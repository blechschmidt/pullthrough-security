package contentscan

import (
	"bufio"
	"bytes"
	"compress/bzip2"
	"compress/gzip"
	"errors"
	"fmt"
	"io"

	"github.com/klauspost/compress/zstd"
	"github.com/ulikunitz/xz/lzma"
)

// Memory bounds on the decompressors.
//
// gzip and bzip2 decode in a fixed, small amount of memory. LZMA (xz, lzma) and
// zstd do not: the stream itself declares how large a history window the
// decoder must hold, up to 4 GiB, and a decoder allocates it before producing a
// byte. That number is chosen by whoever built the archive, so it is bounded
// here, at the values the strongest standard presets produce: `xz -9` uses a
// 64 MiB dictionary and `zstd --ultra -22` a 128 MiB window. A stream asking
// for more is refused before anything is allocated.
const (
	maxLZMADictBytes   = 64 << 20
	maxZstdWindowBytes = 128 << 20
)

// Errors a decompressor reports for a stream it will not decode.
var (
	errDictTooLarge      = errors.New("contentscan: compressed stream requires more decoder memory than allowed")
	errUnsupportedFilter = errors.New("contentscan: xz stream uses a filter chain other than LZMA2")
	errMalformedXZ       = errors.New("contentscan: malformed xz stream")
)

// decompressor opens the compression layer of the given kind over br. The
// returned closer releases the decoder and must be called.
func (w *walker) decompressor(kind container, br *bufio.Reader) (io.Reader, func(), error) {
	return newDecompressor(kind, br)
}

// newDecompressor opens the compression layer of the given kind over br, with
// the decoder's memory bounded (see the constants above). The returned closer
// releases the decoder and must be called.
func newDecompressor(kind container, br *bufio.Reader) (io.Reader, func(), error) {
	noop := func() {}
	switch kind {
	case containerGzip:
		gr, err := gzip.NewReader(br)
		if err != nil {
			return nil, noop, err
		}
		return gr, func() { _ = gr.Close() }, nil
	case containerBzip2:
		return bzip2.NewReader(br), noop, nil
	case containerXz:
		xr, err := newXZReader(br, maxLZMADictBytes)
		if err != nil {
			return nil, noop, err
		}
		return xr, noop, nil
	case containerZstd:
		zr, err := zstd.NewReader(br,
			zstd.WithDecoderConcurrency(1),
			zstd.WithDecoderLowmem(true),
			zstd.WithDecoderMaxWindow(maxZstdWindowBytes),
		)
		if err != nil {
			return nil, noop, err
		}
		return zr, zr.Close, nil
	case containerLzma:
		lr, err := lzma.ReaderConfig{DictCap: maxLZMADictBytes}.NewReader(br)
		if err != nil {
			var tooLarge *lzma.ErrDictSize
			if errors.As(err, &tooLarge) {
				return nil, noop, fmt.Errorf("%w: lzma dictionary of %d bytes", errDictTooLarge, tooLarge.HeaderDictSize)
			}
			return nil, noop, err
		}
		return lr, noop, nil
	}
	return nil, noop, errUnrecognizedArchive
}

// OpenCompressed opens the compression layer a stream begins with — gzip,
// bzip2, xz, zstd or lzma — and returns a reader of what it holds, with the
// decoder's memory bounded exactly as it is for the archive walker (see the
// constants above). compressed is false when the stream does not begin with a
// compression signature this package decodes; the reader is then nil and br is
// untouched. The returned function releases the decoder and must be called.
//
// It is for callers outside this package that have to look inside a compressed
// artifact without unpacking it — a backend checking the digest of an archive's
// uncompressed content — and must not inherit a decoder that allocates whatever
// window the stream asks for.
func OpenCompressed(br *bufio.Reader) (r io.Reader, release func(), compressed bool, err error) {
	head, _ := br.Peek(peekBytes)
	kind := sniffContainer(head)
	if !kind.compression() {
		return nil, func() {}, false, nil
	}
	r, release, err = newDecompressor(kind, br)
	return r, release, true, err
}

// xzReader decodes the .xz container.
//
// It parses the container itself — stream headers, block headers, the index
// and the footer — and hands only the LZMA2 payload of each block to the LZMA
// decoder. Doing the framing here is what makes the memory bound enforceable:
// every block header names its own dictionary size, and each one is checked
// against the cap before a decoder is created for that block. (A general xz
// reader honours whatever the header says, up to 4 GiB per block.)
//
// Integrity checks (CRC32, CRC64, SHA-256) are skipped, not verified: the
// artifact's integrity is established by its content digest, and the purpose
// here is to see what an installer would unpack, not to vouch for the stream.
// Only the LZMA2 filter is supported, which is what every packaging tool
// produces; a stream using a branch/call/jump or delta filter is refused.
type xzReader struct {
	src     *bufio.Reader
	maxDict int64

	inStream  bool // between a stream header and its footer
	seen      bool // at least one stream was read
	checkSize int  // size of the per-block check field of the current stream

	block   io.Reader    // LZMA2 decoder of the current block, nil between blocks
	counted *byteCounter // compressed bytes the current block has consumed
	err     error

	// produced is the number of bytes decoded so far; allocated the dictionary
	// bytes allocated so far. See dictionaryFor.
	produced  int64
	allocated int64
}

// byteCounter counts the bytes read through it. It reads from a bufio.Reader,
// so the one-byte reads the LZMA decoder makes are cheap. It deliberately does
// not offer ReadByte: every byte the decoder takes must pass through Read to be
// counted, because the count is what locates the end of the block.
type byteCounter struct {
	r *bufio.Reader
	n int64
}

func (c *byteCounter) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n += int64(n)
	return n, err
}

// xzCheckSizes maps a stream's check type (the low nibble of its flags) to the
// size of the check field that follows each block.
var xzCheckSizes = [16]int{0, 4, 4, 4, 8, 8, 8, 16, 16, 16, 32, 32, 32, 64, 64, 64}

// LZMA2's filter ID in an xz block header.
const xzFilterLZMA2 = 0x21

// newXZReader starts decoding an xz stream, refusing any block whose dictionary
// is larger than maxDict. It reads and checks the first stream header.
func newXZReader(src *bufio.Reader, maxDict int64) (*xzReader, error) {
	x := &xzReader{src: src, maxDict: maxDict}
	if err := x.streamHeader(); err != nil {
		return nil, err
	}
	return x, nil
}

func (x *xzReader) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	for {
		if x.err != nil {
			return 0, x.err
		}
		if x.block == nil {
			if err := x.nextBlock(); err != nil {
				x.err = err
				return 0, err
			}
			continue
		}
		n, err := x.block.Read(p)
		x.produced += int64(n)
		if err == io.EOF {
			x.block = nil
			if ferr := x.finishBlock(); ferr != nil {
				x.err = ferr
				return n, ferr
			}
			if n > 0 {
				return n, nil
			}
			continue
		}
		if err != nil {
			x.err = err
		}
		return n, err
	}
}

// streamHeader reads the 12-byte stream header.
func (x *xzReader) streamHeader() error {
	var hdr [12]byte
	if _, err := io.ReadFull(x.src, hdr[:]); err != nil {
		return fmt.Errorf("%w: stream header: %v", errMalformedXZ, err)
	}
	if string(hdr[:6]) != "\xfd7zXZ\x00" || hdr[6] != 0 || hdr[7]&0xf0 != 0 {
		return fmt.Errorf("%w: bad stream header", errMalformedXZ)
	}
	x.checkSize = xzCheckSizes[hdr[7]&0x0f]
	x.inStream = true
	x.seen = true
	return nil
}

// nextBlock positions the reader at the next block's payload, crossing the
// index, the footer and any following stream on the way. It returns io.EOF at
// the end of the last stream.
func (x *xzReader) nextBlock() error {
	for {
		if !x.inStream {
			// Stream padding (zero bytes) may follow a stream; then either the
			// input ends or another stream begins.
			for {
				b, err := x.src.Peek(1)
				if err != nil {
					if errors.Is(err, io.EOF) {
						return io.EOF
					}
					return err
				}
				if b[0] != 0 {
					break
				}
				_, _ = x.src.Discard(1)
			}
			if err := x.streamHeader(); err != nil {
				return err
			}
		}
		first, err := x.src.ReadByte()
		if err != nil {
			return fmt.Errorf("%w: truncated before the index", errMalformedXZ)
		}
		if first == 0 {
			if err := x.skipIndexAndFooter(); err != nil {
				return err
			}
			x.inStream = false
			continue
		}
		return x.blockHeader(first)
	}
}

// blockHeader parses a block header whose size byte was already read and
// creates the LZMA2 decoder for the block.
func (x *xzReader) blockHeader(sizeByte byte) error {
	// The header is (sizeByte+1)*4 bytes including the size byte and a CRC32.
	rest := make([]byte, (int(sizeByte)+1)*4-1)
	if _, err := io.ReadFull(x.src, rest); err != nil {
		return fmt.Errorf("%w: truncated block header", errMalformedXZ)
	}
	body := rest[:len(rest)-4] // without the CRC32
	if len(body) < 1 {
		return fmt.Errorf("%w: short block header", errMalformedXZ)
	}
	flags := body[0]
	if flags&0x3c != 0 {
		return fmt.Errorf("%w: reserved block flags set", errMalformedXZ)
	}
	pos := 1
	// Optional fields: the block's compressed size, then its uncompressed size.
	uncompressed := int64(-1)
	for i, present := range []bool{flags&0x40 != 0, flags&0x80 != 0} {
		if !present {
			continue
		}
		v, n, ok := xzVarint(body[pos:])
		if !ok {
			return fmt.Errorf("%w: bad size field in block header", errMalformedXZ)
		}
		pos += n
		if i == 1 && v < 1<<62 {
			uncompressed = int64(v)
		}
	}
	filters := int(flags&0x03) + 1
	if filters != 1 {
		return errUnsupportedFilter
	}
	id, n, ok := xzVarint(body[pos:])
	if !ok {
		return fmt.Errorf("%w: bad filter id", errMalformedXZ)
	}
	pos += n
	propSize, n, ok := xzVarint(body[pos:])
	if !ok {
		return fmt.Errorf("%w: bad filter properties size", errMalformedXZ)
	}
	pos += n
	if id != xzFilterLZMA2 {
		return errUnsupportedFilter
	}
	if propSize != 1 || pos >= len(body) {
		return fmt.Errorf("%w: bad LZMA2 filter properties", errMalformedXZ)
	}
	dict, ok := lzma2DictSize(body[pos])
	if !ok {
		return fmt.Errorf("%w: bad LZMA2 dictionary size", errMalformedXZ)
	}
	if dict > x.maxDict {
		return fmt.Errorf("%w: xz block dictionary of %d bytes", errDictTooLarge, dict)
	}
	dict, err := x.dictionaryFor(dict, uncompressed)
	if err != nil {
		return err
	}
	x.counted = &byteCounter{r: x.src}
	block, err := lzma.Reader2Config{DictCap: int(dict)}.NewReader2(x.counted)
	if err != nil {
		return err
	}
	x.block = block
	return nil
}

// xzFreeDictionaries is how many maximum-size dictionaries a stream may have
// allocated before further ones must be paid for with decoded output, and
// xzDictPerOutput how many dictionary bytes each decoded byte pays for.
const (
	xzFreeDictionaries = 4
	xzDictPerOutput    = 8
)

// dictionaryFor decides how large a dictionary to allocate for a block that
// declares the given dictionary size and (when not negative) uncompressed size.
//
// The decoder allocates a block's dictionary up front, and a stream may consist
// of any number of blocks: a few kilobytes of input can name thousands of
// blocks that each ask for the largest dictionary allowed, and allocating them
// one after another is work no real archive causes. Two rules remove it without
// refusing anything a packaging tool writes:
//
//   - A block that states its uncompressed size (multi-threaded xz always does)
//     gets a dictionary no larger than that size. A dictionary only has to
//     reach back over what the block itself has produced, so this is exact; a
//     block that lied about its size simply fails to decode.
//   - The total allocated is bounded by a fixed allowance plus a multiple of
//     the bytes decoded so far. Real streams produce on the order of the
//     dictionary size per block and never come near the bound; a stream of
//     empty blocks runs into it at once.
func (x *xzReader) dictionaryFor(dict, uncompressed int64) (int64, error) {
	if uncompressed >= 0 && uncompressed < dict {
		dict = uncompressed
	}
	if dict < lzma.MinDictCap {
		dict = lzma.MinDictCap
	}
	if x.allocated+dict > xzFreeDictionaries*x.maxDict+xzDictPerOutput*x.produced {
		return 0, fmt.Errorf("%w: xz stream of many blocks asks for dictionaries out of proportion to its content", errDictTooLarge)
	}
	x.allocated += dict
	return dict, nil
}

// finishBlock consumes what follows a block's payload: padding to a multiple
// of four bytes, then the check field.
func (x *xzReader) finishBlock() error {
	skip := int((4-x.counted.n%4)%4) + x.checkSize
	if _, err := x.src.Discard(skip); err != nil {
		return fmt.Errorf("%w: truncated after a block", errMalformedXZ)
	}
	return nil
}

// skipIndexAndFooter consumes the stream's index (whose indicator byte was
// already read) and footer.
func (x *xzReader) skipIndexAndFooter() error {
	consumed := int64(1) // the index indicator
	readVarint := func() (uint64, error) {
		var v uint64
		for i := 0; i < 9; i++ {
			b, err := x.src.ReadByte()
			if err != nil {
				return 0, fmt.Errorf("%w: truncated index", errMalformedXZ)
			}
			consumed++
			v |= uint64(b&0x7f) << (7 * i)
			if b&0x80 == 0 {
				return v, nil
			}
		}
		return 0, fmt.Errorf("%w: bad index field", errMalformedXZ)
	}
	records, err := readVarint()
	if err != nil {
		return err
	}
	// Each record is at least two bytes of input, so this loop is bounded by the
	// stream's own length; it allocates nothing.
	for i := uint64(0); i < records; i++ {
		if _, err := readVarint(); err != nil {
			return err
		}
		if _, err := readVarint(); err != nil {
			return err
		}
	}
	skip := int((4-consumed%4)%4) + 4 /* index CRC32 */ + 12 /* stream footer */
	if _, err := x.src.Discard(skip); err != nil {
		return fmt.Errorf("%w: truncated index or footer", errMalformedXZ)
	}
	return nil
}

// xzVarint decodes the xz format's multibyte integer: seven bits per byte,
// least significant group first, at most nine bytes.
func xzVarint(b []byte) (v uint64, n int, ok bool) {
	for i := 0; i < 9 && i < len(b); i++ {
		v |= uint64(b[i]&0x7f) << (7 * i)
		if b[i]&0x80 == 0 {
			return v, i + 1, true
		}
	}
	return 0, 0, false
}

// lzma2DictSize decodes the LZMA2 filter's one property byte into a dictionary
// size in bytes.
func lzma2DictSize(prop byte) (int64, bool) {
	bits := int(prop & 0x3f)
	if prop&0xc0 != 0 || bits > 40 {
		return 0, false
	}
	if bits == 40 {
		return 1<<32 - 1, true
	}
	return int64(2|bits&1) << (bits/2 + 11), true
}

// decoderMemoryError reports whether a read error is a decoder refusing a
// stream for the memory it would need.
func decoderMemoryError(err error) bool {
	return errors.Is(err, errDictTooLarge) || errors.Is(err, zstd.ErrWindowSizeExceeded) || errors.Is(err, zstd.ErrDecoderSizeExceeded)
}

// PeelBytes is how much of the start of a stream PeelCompression wants in order
// to see through its compression: enough to hold the first block of a bzip2
// stream, the one format that decodes nothing until a whole block is in hand.
const PeelBytes = 1 << 20

// PeelCompression looks through the compression at the start of a stream: it
// decodes just far enough to return the first bytes (at most one 512-byte tar
// block) of what the stream holds once every compression layer is removed.
// prefix is the beginning of the stream — the whole stream if it is shorter
// than PeelBytes. layers is the number of compression layers removed; a stream
// that is not compressed comes back unchanged with layers 0.
//
// ok is false when the answer could not be established from the prefix: a layer
// is corrupt or cut off before it yields a full block, asks for more decoder
// memory than is allowed, or the layers are nested deeper than the walker
// follows. That is a statement about the stream, and a caller deciding whether
// content needs examining must read it as "cannot tell", never as "nothing
// there": a compressed stream can be built to produce no output for an
// arbitrarily long prefix.
//
// It exists so a caller can tell a compressed index (text, a database) from a
// compressed archive without unpacking either.
func PeelCompression(prefix []byte) (head []byte, layers int, ok bool) {
	cur := prefix
	for {
		kind := sniffContainer(cur)
		if !kind.compression() {
			if len(cur) > peekBytes {
				cur = cur[:peekBytes]
			}
			return cur, layers, true
		}
		if layers == maxCompressionLayers {
			return nil, layers, false
		}
		dr, closer, err := newDecompressor(kind, bufio.NewReaderSize(bytes.NewReader(cur), 4*peekBytes))
		if err != nil {
			return nil, layers, false
		}
		out := make([]byte, peekBytes)
		n, rerr := io.ReadFull(dr, out)
		closer()
		// A full block, or a stream that ended cleanly before filling one, shows
		// what the layer holds. Anything else — an error, or running out of prefix
		// first — does not. (A short read reports the same error whether the
		// stream ended or the prefix did, hence the second look.)
		if rerr != nil && !errors.Is(rerr, io.EOF) && !(errors.Is(rerr, io.ErrUnexpectedEOF) && streamEnded(kind, cur)) {
			return nil, layers, false
		}
		cur = out[:n]
		layers++
	}
}

// streamEnded reports whether a short read from a decoder was the compressed
// stream genuinely ending (as opposed to the prefix being cut off): it decodes
// the layer again to its end and requires that to succeed.
func streamEnded(kind container, data []byte) bool {
	dr, closer, err := newDecompressor(kind, bufio.NewReaderSize(bytes.NewReader(data), 4*peekBytes))
	if err != nil {
		return false
	}
	defer closer()
	_, err = io.Copy(io.Discard, io.LimitReader(dr, peekBytes+1))
	return err == nil
}
