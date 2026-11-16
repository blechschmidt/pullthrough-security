package yum

import (
	"bufio"
	"bytes"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"

	"github.com/blechschmidt/pullthrough-security/internal/contentscan"
)

// This file reads a primary.xml as a stream: the decompression layer the file
// is published in, and the package list itself, one <package> at a time.
//
// A primary.xml is large — Fedora's updates repository publishes 94 MB of it,
// Rocky Linux 9's BaseOS 331 MB, most of it the <format> subtree of every
// package (what it provides, requires and contains) — and it is read on the
// pull path, from an upstream that may be hostile. Reading it whole and
// decoding every <package> into a struct took the proxy 1.3 GB of memory for a
// 30 MB document. StreamPrimary instead walks the document's tokens, keeps the
// few fields that locate and identify each package's file, and skips the rest
// without keeping it, so its memory is bounded by its token, start-tag and
// nesting bounds rather than by the document. OpenPrimary decompresses gzip,
// xz, zstd and bzip2 with the decoder's memory bounded as it is for the
// content scan.

// Bounds of the streaming primary.xml parser.
const (
	// maxPrimaryToken bounds one token of the document: a tag with its
	// attributes, the text between two tags, a comment. The largest in real
	// repositories are package descriptions of a few KB. A longer token is
	// refused rather than buffered (the XML decoder holds a whole token in
	// memory) once the decoder has been handed more than maxPrimaryToken and
	// its read-ahead since the token began.
	maxPrimaryToken = 4 << 20
	// primaryReadAhead is the buffer the decoder reads through: what it may
	// have read beyond the token it is decoding.
	primaryReadAhead = 64 << 10
	// maxPrimaryTag bounds a start tag with its attributes, and
	// maxPrimaryAttrs the attributes it carries. The decoder keeps what the
	// start tag of every open element declares — its name, its namespace
	// declarations, several times their size — until the element ends, so
	// these bound what nesting holds, where maxPrimaryToken would let 66 open
	// elements hold gigabytes. The largest in real repositories are tags of
	// under 1 KB with 6 attributes (an <rpm:entry>).
	maxPrimaryTag   = 64 << 10
	maxPrimaryAttrs = 64
	// maxPrimaryDepth bounds how deeply elements nest below a <package> (its
	// <format> subtree is two levels deep). Skipping is iterative, but the
	// decoder keeps a record per open element.
	maxPrimaryDepth = 64
	// maxPrimaryField bounds a field the parser keeps (a name, a location, a
	// checksum): a longer one makes the package's entry malformed.
	maxPrimaryField = 4 << 10
)

// ErrMalformedPrimary marks a document StreamPrimary refuses: not XML, not a
// primary.xml (its root element is not <metadata>), a token or a nesting past
// the parser's bounds. An error of the reader it reads from is returned as it
// is, not marked.
var ErrMalformedPrimary = errors.New("yum: malformed primary.xml")

// errPrimaryTooLarge marks a decompressed primary.xml past the limit its reader
// was opened with.
var errPrimaryTooLarge = errors.New("yum: primary.xml exceeds the size the proxy reads")

// PrimaryEntry is one package of a primary.xml, reduced to what identifies its
// file and locates it in the repository.
type PrimaryEntry struct {
	// Name and Arch are the package's name and architecture, trimmed.
	Name string
	Arch string
	// Epoch, Version and Release are the package's epoch, version and release
	// as the <version> element's attributes spell them, trimmed (Epoch is
	// empty when the element states none).
	Epoch   string
	Version string
	Release string
	// ChecksumType and Checksum are the package file's digest as the document
	// declares it: the algorithm ("sha256") and its hex value, trimmed.
	ChecksumType string
	Checksum     string
	// Location is the file's location href, trimmed. LocationBase is the
	// location's xml:base, set when the file is served from another base URL
	// than the repository's.
	Location     string
	LocationBase string
	// Size is the package file's size in bytes (<size package="…">) and Time
	// when the file was added to the repository (<time file="…">, Unix
	// seconds); zero when the document states no number.
	Size int64
	Time int64
}

// StreamPrimary reads a decompressed primary.xml from r and calls fn with each
// package entry, in document order, holding one entry at a time. An entry is
// passed only when it names a package and a location; one whose identifying
// fields (name, version, checksum, location) repeat, or run past the field
// bound, is malformed and left out, so one bad entry does not fail the
// document. fn's error stops the walk and is returned. A document that is not a
// primary.xml, or that breaks the parser's bounds, is an error wrapping
// ErrMalformedPrimary; an error of r is returned as it is.
func StreamPrimary(r io.Reader, fn func(PrimaryEntry) error) error {
	src := &tokenBound{r: r, max: maxPrimaryToken + primaryReadAhead}
	// The decoder reads through a buffer of a known size (a ByteReader is
	// used as it is): src can tell how far past its current token it read.
	p := &primaryStream{dec: xml.NewDecoder(bufio.NewReaderSize(src, primaryReadAhead)), src: src}
	return p.run(fn)
}

// primaryStream is one walk of a primary.xml.
type primaryStream struct {
	dec *xml.Decoder
	src *tokenBound
}

// token reads the next token, telling a failure of the reader (returned as it
// is) from a fault of the document (wrapped in ErrMalformedPrimary).
func (p *primaryStream) token() (xml.Token, error) {
	// The token begins where the decoder stands: src bounds what the decoder
	// is handed from here until it returns.
	start := p.dec.InputOffset()
	p.src.start = start
	tok, err := p.dec.Token()
	switch {
	case err == nil || err == io.EOF:
		if t, ok := tok.(xml.StartElement); ok {
			if n := p.dec.InputOffset() - start; n > maxPrimaryTag || len(t.Attr) > maxPrimaryAttrs {
				return nil, fmt.Errorf("%w: a <%s> start tag of %d bytes with %d attributes (the parser takes at most %d bytes and %d attributes)",
					ErrMalformedPrimary, clip(t.Name.Local), n, len(t.Attr), maxPrimaryTag, maxPrimaryAttrs)
			}
		}
		return tok, err
	case p.src.err != nil:
		return nil, p.src.err
	case errors.Is(err, ErrMalformedPrimary):
		return nil, err
	}
	return nil, fmt.Errorf("%w: %v", ErrMalformedPrimary, err)
}

func (p *primaryStream) run(fn func(PrimaryEntry) error) error {
	inRoot, rootDone := false, false
	for {
		tok, err := p.token()
		if err == io.EOF {
			if !rootDone {
				return fmt.Errorf("%w: the document ends before its <metadata> element does", ErrMalformedPrimary)
			}
			return nil
		}
		if err != nil {
			return err
		}
		switch t := tok.(type) {
		case xml.StartElement:
			switch {
			case rootDone:
				return fmt.Errorf("%w: an element follows the <metadata> element", ErrMalformedPrimary)
			case !inRoot:
				if t.Name.Local != "metadata" {
					return fmt.Errorf("%w: its root element is <%s>, not <metadata>", ErrMalformedPrimary, clip(t.Name.Local))
				}
				inRoot = true
			case t.Name.Local == "package":
				e, ok, err := p.readPackage()
				if err != nil {
					return err
				}
				if ok {
					if err := fn(e); err != nil {
						return err
					}
				}
			default:
				if err := p.skip(); err != nil {
					return err
				}
			}
		case xml.EndElement:
			// Strict decoding pairs every end tag with its start: at this
			// level it closes the root.
			inRoot, rootDone = false, true
		}
	}
}

// readPackage reads a <package> element whose start tag was just read.
func (p *primaryStream) readPackage() (PrimaryEntry, bool, error) {
	var e PrimaryEntry
	bad := false
	seen := map[string]bool{}
	once := func(field string) {
		if seen[field] {
			bad = true
		}
		seen[field] = true
	}
	for {
		tok, err := p.token()
		if err != nil {
			if err == io.EOF {
				err = fmt.Errorf("%w: the document ends inside a <package>", ErrMalformedPrimary)
			}
			return e, false, err
		}
		switch t := tok.(type) {
		case xml.EndElement:
			ok := !bad && e.Name != "" && e.Location != ""
			return e, ok, nil
		case xml.StartElement:
			var err error
			switch t.Name.Local {
			case "name":
				once("name")
				e.Name, err = p.text(&bad)
			case "arch":
				once("arch")
				e.Arch, err = p.text(&bad)
			case "version":
				once("version")
				e.Epoch = attr(t, "", "epoch", &bad)
				e.Version = attr(t, "", "ver", &bad)
				e.Release = attr(t, "", "rel", &bad)
				err = p.skip()
			case "checksum":
				once("checksum")
				e.ChecksumType = attr(t, "", "type", &bad)
				e.Checksum, err = p.text(&bad)
			case "location":
				once("location")
				e.Location = attr(t, "", "href", &bad)
				e.LocationBase = attr(t, "xml", "base", &bad)
				err = p.skip()
			case "size":
				e.Size = number(attr(t, "", "package", &bad))
				err = p.skip()
			case "time":
				e.Time = number(attr(t, "", "file", &bad))
				err = p.skip()
			default:
				// summary, description, packager, url, and the <format>
				// subtree: not kept.
				err = p.skip()
			}
			if err != nil {
				return e, false, err
			}
		}
	}
}

// text reads the text of an element whose start tag was just read, up to its
// end tag (the text of nested elements is not part of it). Text past the field
// bound marks the entry bad.
func (p *primaryStream) text(bad *bool) (string, error) {
	var b strings.Builder
	depth := 0
	for {
		tok, err := p.token()
		if err != nil {
			if err == io.EOF {
				err = fmt.Errorf("%w: the document ends inside an element", ErrMalformedPrimary)
			}
			return "", err
		}
		switch t := tok.(type) {
		case xml.CharData:
			if depth == 0 {
				if b.Len()+len(t) > maxPrimaryField {
					*bad = true
				} else {
					b.Write(t)
				}
			}
		case xml.StartElement:
			if depth++; depth > maxPrimaryDepth {
				return "", errTooDeep
			}
		case xml.EndElement:
			if depth == 0 {
				return strings.TrimSpace(b.String()), nil
			}
			depth--
		}
	}
}

// errTooDeep marks elements nested past maxPrimaryDepth.
var errTooDeep = fmt.Errorf("%w: elements nest more than %d levels deep", ErrMalformedPrimary, maxPrimaryDepth)

// skip reads past the end of the element whose start tag was just read,
// iteratively (xml.Decoder.Skip recurses once per level of nesting).
func (p *primaryStream) skip() error {
	depth := 0
	for {
		tok, err := p.token()
		if err != nil {
			if err == io.EOF {
				err = fmt.Errorf("%w: the document ends inside an element", ErrMalformedPrimary)
			}
			return err
		}
		switch tok.(type) {
		case xml.StartElement:
			if depth++; depth > maxPrimaryDepth {
				return errTooDeep
			}
		case xml.EndElement:
			if depth == 0 {
				return nil
			}
			depth--
		}
	}
}

// attr returns an attribute's value, trimmed: space "xml" matches the xml
// prefix whether or not the decoder translated it to its namespace. A value
// past the field bound marks the entry bad.
func attr(t xml.StartElement, space, local string, bad *bool) string {
	for _, a := range t.Attr {
		if a.Name.Local != local {
			continue
		}
		switch {
		case space == "" && a.Name.Space != "":
			continue
		case space == "xml" && a.Name.Space != "xml" && a.Name.Space != "http://www.w3.org/XML/1998/namespace":
			continue
		}
		if len(a.Value) > maxPrimaryField {
			*bad = true
			return ""
		}
		return strings.TrimSpace(a.Value)
	}
	return ""
}

// number reads a non-negative decimal integer; anything else is zero.
func number(s string) int64 {
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil || n < 0 {
		return 0
	}
	return n
}

// clip shortens a name for a message.
func clip(s string) string {
	if len(s) > 64 {
		return s[:64] + "…"
	}
	return s
}

// tokenBound fails a read once the decoder has been handed more than max bytes
// since the token it is decoding began (start, its input offset then): the
// token, and the read-ahead behind it. A bound on the bytes between two '<'
// or '>' would not do: '>' is legal in text and attribute values, and a
// comment may hold '<'. It also keeps the first error of the reader it wraps,
// so that StreamPrimary returns a failed read as what it is.
type tokenBound struct {
	r     io.Reader
	max   int64
	start int64
	read  int64
	// err is the wrapped reader's first error (not io.EOF), fault the
	// document's: a token past the bound.
	err   error
	fault error
}

func (t *tokenBound) Read(p []byte) (int, error) {
	switch {
	case t.fault != nil:
		return 0, t.fault
	case t.err != nil:
		return 0, t.err
	}
	n, err := t.r.Read(p)
	t.read += int64(n)
	if t.read-t.start > t.max {
		// Not the reader's failure: the document's.
		t.fault = fmt.Errorf("%w: a token longer than %d bytes", ErrMalformedPrimary, maxPrimaryToken)
		return n, t.fault
	}
	if err != nil && err != io.EOF {
		t.err = err
	}
	return n, err
}

// OpenPrimary returns a reader of a primary.xml's XML, decompressed as the
// file's name and its first bytes say: gzip (".gz"), xz (".xz"), zstd (".zst")
// or bzip2 (".bz2"), each with the decoder's memory bounded as it is for the
// content scan (contentscan.OpenCompressed: an xz dictionary or a zstd window
// larger than the strongest presets use is refused), or plain XML. name is the
// file's name or its location; a name that declares one compression over bytes
// of another, or of none, is refused, and a zchunk file (".zck") is reported
// unsupported (errUnsupportedCompression): zchunk is not zstd, and repomd.xml
// lists a zstd primary beside it. Reading more than limit bytes of XML fails.
// The returned function releases the decoder and must be called.
func OpenPrimary(r io.Reader, name string, limit int64) (io.Reader, func(), error) {
	noop := func() {}
	want := compressionOf(name)
	if want == "zck" {
		return nil, noop, fmt.Errorf("yum: %w: zchunk primary.xml %q", errUnsupportedCompression, clip(name))
	}
	br := bufio.NewReaderSize(r, 64<<10)
	head, _ := br.Peek(6)
	if got := magicOf(head); want != "" && got != want {
		if got == "" {
			got = "not compressed"
		}
		return nil, noop, fmt.Errorf("yum: %q is named %s but its content is %s", clip(name), want, got)
	}
	dec, release, compressed, err := contentscan.OpenCompressed(br)
	if err != nil {
		release()
		return nil, noop, fmt.Errorf("yum: %q does not decompress: %w", clip(name), err)
	}
	var out io.Reader = br
	if compressed {
		out = dec
	}
	return &limitReader{r: out, left: limit}, release, nil
}

// compressionOf reads the compression a primary.xml's name declares.
func compressionOf(name string) string {
	switch {
	case strings.HasSuffix(name, ".gz"):
		return "gz"
	case strings.HasSuffix(name, ".xz"):
		return "xz"
	case strings.HasSuffix(name, ".zst"):
		return "zst"
	case strings.HasSuffix(name, ".bz2"):
		return "bz2"
	case strings.HasSuffix(name, ".zck"):
		return "zck"
	}
	return ""
}

// magicOf names the compression a stream's first bytes are the signature of.
func magicOf(head []byte) string {
	switch {
	case bytes.HasPrefix(head, []byte("\x1f\x8b")):
		return "gz"
	case bytes.HasPrefix(head, []byte("\xfd7zXZ\x00")):
		return "xz"
	case bytes.HasPrefix(head, []byte("\x28\xb5\x2f\xfd")):
		return "zst"
	case len(head) >= 4 && head[0]&0xf0 == 0x50 && head[1] == 0x2a && head[2] == 0x4d && head[3] == 0x18:
		// A zstd skippable frame, with which a zstd stream may begin.
		return "zst"
	case len(head) >= 4 && bytes.HasPrefix(head, []byte("BZh")) && head[3] >= '1' && head[3] <= '9':
		return "bz2"
	}
	return ""
}

// limitReader fails a read past its limit: a document larger than the proxy
// reads is refused, not cut short.
type limitReader struct {
	r    io.Reader
	left int64
}

func (l *limitReader) Read(p []byte) (int, error) {
	if l.left <= 0 {
		var one [1]byte
		if n, err := l.r.Read(one[:]); n > 0 {
			return 0, errPrimaryTooLarge
		} else if err != nil {
			return 0, err
		}
		return 0, nil
	}
	if int64(len(p)) > l.left {
		p = p[:l.left]
	}
	n, err := l.r.Read(p)
	l.left -= int64(n)
	return n, err
}
