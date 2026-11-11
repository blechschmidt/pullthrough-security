package llmpkgscan

import (
	"io"

	"github.com/blechschmidt/pullthrough-security/internal/contentscan"
)

// Class is what the backend that served a resource says it is. It decides how
// much the bytes have to prove before the gate examines them.
type Class uint8

const (
	// ClassUnknown: the backend made no statement — a pass-through path, a file
	// kind its protocol does not name. The resource is examined when its bytes
	// are something a machine unpacks or runs (an archive, an executable, a
	// script, a pickle), or when it is named like a package archive.
	ClassUnknown Class = iota
	// ClassMetadata: the backend identified an index, a listing or a sidecar. It
	// is examined only when its bytes turn out to be a package archive or an
	// executable after all — which is how a hostile repository would route a
	// package past a gate that trusted the path.
	ClassMetadata
	// ClassPayload: the backend identified something a client installs, builds,
	// imports or executes. It is always examined; bytes that are not an archive
	// are examined as a single file.
	ClassPayload
)

// String returns the class's stable label.
func (c Class) String() string {
	switch c {
	case ClassMetadata:
		return "metadata"
	case ClassPayload:
		return "payload"
	default:
		return "unclassified"
	}
}

// ReadProbePrefix reads from r what Applicable needs to see: the first tar
// block, and — only when that shows a compression signature, which has to be
// looked through — up to ProbeBytes.
func ReadProbePrefix(r io.Reader) ([]byte, error) {
	head := make([]byte, SniffBytes)
	n, err := io.ReadFull(r, head)
	head = head[:n]
	if err == io.EOF || err == io.ErrUnexpectedEOF {
		return head, nil // the whole content is shorter than one block
	}
	if err != nil {
		return nil, err
	}
	if !NeedsLongProbe(head) {
		return head, nil
	}
	rest, err := io.ReadAll(io.LimitReader(r, ProbeBytes-int64(n)))
	if err != nil {
		return nil, err
	}
	return append(head, rest...), nil
}

// NeedsLongProbe reports whether content starting with head is compressed, so
// that telling what it holds takes up to contentscan.PeelBytes of it rather
// than the first SniffBytes.
func NeedsLongProbe(head []byte) bool {
	_, layers, ok := contentscan.PeelCompression(head)
	return layers > 0 || !ok
}

// ProbeBytes is the most Applicable ever needs to see of a resource.
const ProbeBytes = contentscan.PeelBytes

// Probe is what the beginning of a resource's content shows it to be. It is a
// property of the bytes alone; what follows from it depends on what the
// resource was served as (Applies).
type Probe struct {
	// Undetermined reports a compressed stream that would not show what it holds
	// within the probe: corrupt, cut off, asking for too much decoder memory, or
	// built to emit nothing for a megabyte.
	Undetermined bool
	// Compressed reports that at least one compression layer was looked through.
	Compressed bool
	// Container reports a package container the scanner opens — tar, zip,
	// ar/.deb, RPM, cpio, NAR — once any compression is removed. TarLike narrows
	// that to a tar or cpio archive.
	Container bool
	TarLike   bool
	// Executable reports something a machine or an interpreter runs: a native
	// executable or library, WebAssembly, JVM bytecode, a script with an
	// interpreter line, a pickle.
	Executable bool
	// Unsupported reports the signature of an archive or compression format the
	// scanner does not open (7-zip, rar, lz4, …).
	Unsupported bool
}

// ProbeContent examines the beginning of a resource's content (see
// ReadProbePrefix). The content is looked at, not its name: compression is
// peeled off first, so a compressed index — text, a database — and a compressed
// archive are told apart by what is inside.
func ProbeContent(prefix []byte) Probe {
	head, layers, ok := contentscan.PeelCompression(prefix)
	if !ok {
		return Probe{Undetermined: true, Compressed: true}
	}
	p := Probe{
		Compressed:  layers > 0,
		Container:   contentscan.Recognizes(head),
		Executable:  executableMagic(head),
		Unsupported: unsupportedArchiveMagic(head) || (layers == 0 && unsupportedArchiveMagic(prefix)),
	}
	p.TarLike = p.Container && tarLike(head)
	return p
}

// Applies reports whether a resource whose content probed as p holds something
// this gate examines, given what it was served as.
//
//   - A payload always does; its content is not asked.
//   - A package container is examined under any class. So is an executable, a
//     script with an interpreter line, or a pickle.
//   - A compressed stream that will not show what it holds is examined: "cannot
//     tell" is never read as "nothing there".
//   - Metadata whose expected shape is an archive of data files (indexArchive: a
//     registry tarball, a package index shipped as a tar) is left alone when it
//     is exactly that.
//   - For an unclassified resource two more things count: the signature of an
//     archive format the scanner cannot open (it is then reported as a package
//     that went unexamined), and — for content that is no recognizable format at
//     all — a file name that claims to be a package archive.
//
// Metadata is deliberately held to less than an unclassified resource: a
// compressed index is named like an archive ("Packages.gz") and may use a
// compression the scanner lacks ("Packages.lz4") without being one. What it is
// never excused from is being a package: a repository's own index is what tells
// a client where to fetch each package from, so a hostile repository can route
// one through a path that reads as an index.
func (p Probe) Applies(class Class, indexArchive bool, filename string) bool {
	switch {
	case class == ClassPayload, p.Undetermined:
		return true
	case class == ClassMetadata:
		if indexArchive && p.TarLike {
			return false
		}
		return p.Container || p.Executable
	case p.Container, p.Executable, p.Unsupported:
		return true
	case p.Compressed:
		// Compressed text or data: it was looked into, and there is nothing in it
		// to unpack or run.
		return false
	}
	return claimsArchive(filename)
}

// Applicable is ProbeContent(prefix).Applies(…): whether a resource holds
// something this gate examines, from the beginning of its content and what it
// was served as.
func Applicable(class Class, indexArchive bool, prefix []byte, filename string) bool {
	return ProbeContent(prefix).Applies(class, indexArchive, filename)
}

// tarLike reports whether content is a tar or cpio archive: the shape of an
// index that is an archive of data files. head has had its compression peeled.
func tarLike(head []byte) bool {
	return contentscan.Recognizes(head) &&
		!hasPrefixAny(head, "PK\x03\x04", "PK\x05\x06", "PK\x07\x08", "!<arch>\n", "\xed\xab\xee\xdb", "\x0d\x00\x00\x00\x00\x00\x00\x00nix-archive-1")
}

func hasPrefixAny(b []byte, prefixes ...string) bool {
	for _, p := range prefixes {
		if len(b) >= len(p) && string(b[:len(p)]) == p {
			return true
		}
	}
	return false
}
