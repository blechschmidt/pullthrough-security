package contentscan

import (
	"bufio"
	"encoding/binary"
	"errors"
	"io"
)

// The Nix archive (NAR): the serialization of one store path that a Nix binary
// cache serves. It is a tree written as a sequence of length-prefixed strings,
// each padded with zeros to a multiple of eight bytes:
//
//	"nix-archive-1" node
//	node      = "(" "type" "regular" ["executable" ""] "contents" <bytes> ")"
//	          | "(" "type" "symlink" "target" <string> ")"
//	          | "(" "type" "directory" { "entry" "(" "name" <string> "node" node ")" } ")"
//
// A NAR holds no ownership, timestamps or permissions beyond the executable
// bit, so that bit is the only mode it yields.

const (
	// maxNARToken bounds a structural string (a keyword, a file name, a link
	// target). File contents are streamed and are not subject to it.
	maxNARToken = 8192
	// maxNARDepth bounds directory nesting; the parser recurses once per level.
	maxNARDepth = 256
)

var errNAR = errors.New("contentscan: malformed NAR")

// narReader reads NAR tokens.
type narReader struct {
	br *bufio.Reader
}

// length reads a 64-bit little-endian length.
func (n *narReader) length() (uint64, error) {
	var b [8]byte
	if _, err := io.ReadFull(n.br, b[:]); err != nil {
		return 0, err
	}
	return binary.LittleEndian.Uint64(b[:]), nil
}

// pad consumes the zero padding after l bytes of string data.
func (n *narReader) pad(l uint64) error {
	if rem := l % 8; rem != 0 {
		if _, err := n.br.Discard(int(8 - rem)); err != nil {
			return err
		}
	}
	return nil
}

// token reads one structural string.
func (n *narReader) token() (string, error) {
	l, err := n.length()
	if err != nil {
		return "", err
	}
	if l > maxNARToken {
		return "", errNAR
	}
	buf := make([]byte, l)
	if _, err := io.ReadFull(n.br, buf); err != nil {
		return "", err
	}
	if err := n.pad(l); err != nil {
		return "", err
	}
	return string(buf), nil
}

// expect reads one token and requires it to be want.
func (n *narReader) expect(want string) error {
	got, err := n.token()
	if err != nil {
		return err
	}
	if got != want {
		return errNAR
	}
	return nil
}

// walkNAR walks a Nix archive whose members are reported under prefix.
func (w *walker) walkNAR(r io.Reader, prefix string, depth int) error {
	n := &narReader{br: bufio.NewReaderSize(r, 4*peekBytes)}
	if err := n.expect("nix-archive-1"); err != nil {
		if depth == 0 && !w.done() {
			return errUnrecognizedArchive
		}
		return nil
	}
	before := w.entries
	err := w.narNode(n, prefix, "", depth, 0)
	if err == nil || errors.Is(err, errWalkLimit) || w.done() {
		// Complete, or cut short by a limit the statistics already name.
		return nil
	}
	if w.entries == before && depth == 0 {
		return errUnrecognizedArchive
	}
	w.broke()
	return nil
}

// narNode parses one node. rel is the node's path inside the archive ("" for
// the root, which for a store path that is a single file is that file).
func (w *walker) narNode(n *narReader, prefix, rel string, depth, level int) error {
	if level > maxNARDepth {
		return errNAR
	}
	if err := n.expect("("); err != nil {
		return err
	}
	if err := n.expect("type"); err != nil {
		return err
	}
	kind, err := n.token()
	if err != nil {
		return err
	}
	name := rel
	if name == "" {
		name = "content"
	}
	switch kind {
	case "regular":
		tok, err := n.token()
		if err != nil {
			return err
		}
		mode := uint32(0o444)
		if tok == "executable" {
			mode = 0o555
			if err := n.expect(""); err != nil {
				return err
			}
			if tok, err = n.token(); err != nil {
				return err
			}
		}
		if tok != "contents" {
			return errNAR
		}
		size, err := n.length()
		if err != nil {
			return err
		}
		if size > 1<<62 {
			return errNAR
		}
		if !w.countEntry() {
			return errWalkLimit
		}
		data := io.LimitReader(n.br, int64(size))
		if !w.member(containerNAR, depth, name, prefix+name, int64(size), mode, data) {
			return errNAR
		}
		if _, err := io.Copy(io.Discard, data); err != nil {
			return err
		}
		if err := n.pad(size); err != nil {
			return err
		}
		return n.expect(")")
	case "symlink":
		if err := n.expect("target"); err != nil {
			return err
		}
		target, err := n.token()
		if err != nil {
			return err
		}
		if !w.countEntry() {
			return errWalkLimit
		}
		w.link(prefix+name, target, false)
		return n.expect(")")
	case "directory":
		for !w.done() {
			tok, err := n.token()
			if err != nil {
				return err
			}
			if tok == ")" {
				return nil
			}
			if tok != "entry" {
				return errNAR
			}
			if err := n.expect("("); err != nil {
				return err
			}
			if err := n.expect("name"); err != nil {
				return err
			}
			child, err := n.token()
			if err != nil {
				return err
			}
			// A NAR entry name is one path component. Nix refuses ".", ".." and
			// names with a slash; such a name is the mark of a crafted archive, and
			// it is passed on verbatim so the consumer sees the attempt.
			if child == "" {
				child = "_unnamed"
			}
			childRel := child
			if rel != "" {
				childRel = rel + "/" + child
			}
			if err := n.expect("node"); err != nil {
				return err
			}
			if err := w.narNode(n, prefix, childRel, depth, level+1); err != nil {
				return err
			}
			if err := n.expect(")"); err != nil {
				return err
			}
		}
		return errWalkLimit
	default:
		return errNAR
	}
}
