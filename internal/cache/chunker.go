package cache

import (
	"io"
	"math/rand"
)

// Content-defined chunking (CDC) splits a byte stream into variable-length
// chunks whose boundaries are determined by the content itself rather than by a
// fixed offset. Because a boundary depends only on a small rolling window of
// surrounding bytes, inserting or removing bytes early in a stream re-aligns at
// the next natural cut point instead of shifting every subsequent boundary — so
// two artifacts that share long byte runs (a common tarball embedded under two
// coordinates, two releases of a package that differ in a few files) produce
// identical chunks for the shared regions and deduplicate against each other.
//
// The implementation is a FastCDC-style gear hash with normalized chunking: a
// stricter boundary mask is used while the current chunk is below the target
// size and a laxer one once it is above, which tightens the chunk-size
// distribution around the average and improves the dedup ratio versus a plain
// rolling-hash cut. The gear table is seeded deterministically so that every
// process and every replica computes identical boundaries for identical content
// — a hard requirement for cross-artifact and cross-restart deduplication.

const (
	// chunkMin / chunkAvg / chunkMax bound the chunk size. A boundary is never
	// emitted before chunkMin bytes (avoids a storm of tiny chunks and their
	// per-chunk metadata overhead) and is forced at chunkMax (bounds the working
	// buffer and the memory held per in-flight chunk).
	chunkMin = 16 * 1024
	chunkAvg = 64 * 1024
	chunkMax = 256 * 1024
)

// gearTable maps each byte value to a pseudo-random 64-bit word. It is built
// once from a fixed seed so boundaries are stable and reproducible everywhere.
var gearTable = buildGearTable(0x7063_6463_6763_0001)

func buildGearTable(seed int64) [256]uint64 {
	var t [256]uint64
	// math/rand with a fixed seed is deterministic across platforms and Go
	// versions for the same sequence of calls, which is exactly what CDC needs.
	rng := rand.New(rand.NewSource(seed))
	for i := range t {
		t[i] = rng.Uint64()
	}
	return t
}

// Normalized-chunking masks. The number of set bits controls the expected
// run length before a boundary: ~2^bits bytes. maskS (more bits set) applies
// below the average size so short chunks are cut less eagerly; maskL (fewer
// bits) applies above it so the stream is cut sooner, pulling the distribution
// toward chunkAvg. The bit counts correspond to a 64 KiB average.
const (
	maskS = 0x0003_5903_5300_0000 // ~18 bits set: boundary probability 2^-18
	maskL = 0x0000_d903_5300_0000 // ~16 bits set: boundary probability 2^-16
)

// chunker splits the bytes read from an underlying reader into content-defined
// chunks. It buffers at most chunkMax+readBlock bytes at a time so memory stays
// bounded regardless of the total stream length.
type chunker struct {
	r       io.Reader
	buf     []byte
	err     error // sticky read error (other than io.EOF)
	drained bool  // underlying reader returned io.EOF
}

// readBlock is how much the chunker pulls from the reader per refill.
const readBlock = 64 * 1024

func newChunker(r io.Reader) *chunker {
	return &chunker{r: r, buf: make([]byte, 0, chunkMax+readBlock)}
}

// next returns the next content-defined chunk. It returns (nil, io.EOF) once the
// stream is fully consumed, or (nil, err) on a read error. The returned slice is
// only valid until the next call to next; callers that retain it must copy.
func (c *chunker) next() ([]byte, error) {
	for {
		// Emit as soon as we either have a full max-size chunk buffered or have
		// drained the reader and still hold bytes.
		if len(c.buf) >= chunkMax || (c.drained && len(c.buf) > 0) {
			cut := c.boundary(c.buf)
			chunk := c.buf[:cut]
			c.buf = c.buf[cut:]
			// Compact the retained tail to the front so the backing array is
			// reused rather than growing without bound.
			if len(c.buf) > 0 {
				c.buf = append(c.buf[:0:cap(c.buf)], c.buf...)
			}
			return chunk, nil
		}
		if c.drained {
			if c.err != nil {
				return nil, c.err
			}
			return nil, io.EOF
		}
		if err := c.fill(); err != nil && err != io.EOF {
			c.err = err
			c.drained = true
		}
	}
}

// fill pulls one readBlock from the underlying reader onto the buffer.
func (c *chunker) fill() error {
	start := len(c.buf)
	c.buf = append(c.buf, make([]byte, readBlock)...)
	n, err := io.ReadFull(c.r, c.buf[start:])
	c.buf = c.buf[:start+n]
	if err == io.EOF || err == io.ErrUnexpectedEOF {
		c.drained = true
		return io.EOF
	}
	return err
}

// boundary returns the cut offset within data using normalized gear-hash
// chunking. data is guaranteed non-empty.
func (c *chunker) boundary(data []byte) int {
	n := len(data)
	if n <= chunkMin {
		return n
	}
	if n > chunkMax {
		n = chunkMax
	}
	var fp uint64
	i := chunkMin
	// Strict mask region: [chunkMin, chunkAvg).
	normal := chunkAvg
	if normal > n {
		normal = n
	}
	for ; i < normal; i++ {
		fp = (fp << 1) + gearTable[data[i]]
		if fp&maskS == 0 {
			return i + 1
		}
	}
	// Lax mask region: [chunkAvg, n).
	for ; i < n; i++ {
		fp = (fp << 1) + gearTable[data[i]]
		if fp&maskL == 0 {
			return i + 1
		}
	}
	return n
}
