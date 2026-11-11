package contentscan

import (
	"bufio"
	"io"
	"path"
	"strconv"
	"strings"
)

// The Unix ar archive: the container of a Debian package (.deb, .udeb) and of
// static libraries. After the 8-byte global magic it is a sequence of members,
// each a 60-byte ASCII header followed by the data, padded to an even length.

const (
	arMagic      = "!<arch>\n"
	arHeaderSize = 60
	// maxArNameTable bounds the GNU extended file-name table (the "//" member).
	maxArNameTable = 1 << 20
	// maxArLongName bounds a BSD long name stored in front of a member's data.
	maxArLongName = 4096
)

// cleanName normalizes a member name the way every walker does: a leading "./"
// is dropped and redundant separators are removed. The result is NOT made
// safe — an absolute or escaping name is passed on for the consumer to judge.
func cleanName(name string) string {
	return path.Clean(strings.TrimPrefix(name, "./"))
}

// walkAr walks an ar archive whose members are reported under prefix.
//
// A .deb is an ar holding "debian-binary", "control.tar.*" (the package's
// control file and its maintainer scripts — preinst, postinst, prerm, postrm —
// which dpkg runs as root) and "data.tar.*" (the files it installs). Those two
// archives are opened in place: the control members appear under DEBIAN/, the
// data members under their install paths.
func (w *walker) walkAr(r io.Reader, prefix string, depth int) error {
	br := bufio.NewReaderSize(r, 4*peekBytes)
	var magic [len(arMagic)]byte
	if _, err := io.ReadFull(br, magic[:]); err != nil || string(magic[:]) != arMagic {
		if depth == 0 && !w.done() {
			return errUnrecognizedArchive
		}
		return nil
	}

	parent := containerAr
	var names []byte // GNU extended file-name table
	first := true
	for !w.done() {
		var hdr [arHeaderSize]byte
		n, err := io.ReadFull(br, hdr[:])
		if n == 0 {
			return nil // the end of the archive
		}
		if err != nil || hdr[58] != '`' || hdr[59] != '\n' {
			w.broke()
			return nil
		}
		declared, perr := strconv.ParseInt(strings.TrimSpace(string(hdr[48:58])), 10, 64)
		if perr != nil || declared < 0 {
			w.broke()
			return nil
		}
		rawName := strings.TrimRight(string(hdr[0:16]), " ")
		mode, _ := strconv.ParseUint(strings.TrimSpace(string(hdr[40:48])), 8, 32)
		data := io.LimitReader(br, declared)
		size := declared

		name, special := "", false
		switch {
		case rawName == "/" || rawName == "/SYM64/" || rawName == "__.SYMDEF" || rawName == "__.SYMDEF SORTED":
			special = true // a symbol table: an index, not a member
		case rawName == "//":
			// The GNU extended file-name table: long names referenced as "/<offset>".
			special = true
			names, _ = io.ReadAll(io.LimitReader(data, maxArNameTable))
		case strings.HasPrefix(rawName, "#1/"):
			// BSD long name: the name is stored in front of the data and counted in
			// the declared size.
			l, lerr := strconv.Atoi(strings.TrimPrefix(rawName, "#1/"))
			if lerr != nil || l < 0 || int64(l) > declared || l > maxArLongName {
				w.broke()
				return nil
			}
			buf := make([]byte, l)
			if _, rerr := io.ReadFull(data, buf); rerr != nil {
				w.broke()
				return nil
			}
			name = strings.TrimRight(string(buf), "\x00")
			size -= int64(l)
		case strings.HasPrefix(rawName, "/") && len(rawName) > 1:
			off, oerr := strconv.Atoi(rawName[1:])
			if oerr != nil || off < 0 || off >= len(names) {
				w.broke()
				return nil
			}
			end := off
			for end < len(names) && end-off < maxArLongName && names[end] != '\n' {
				end++
			}
			name = strings.TrimSuffix(string(names[off:end]), "/")
		default:
			name = strings.TrimSuffix(rawName, "/")
		}

		if !special {
			if first && name == "debian-binary" {
				parent = containerDeb
				if depth == 0 {
					w.stats.format = "deb"
				}
			}
			first = false
			if !w.countEntry() {
				return nil
			}
			inner := cleanName(name)
			if !w.member(parent, depth, inner, prefix+inner, size, uint32(mode)&0o7777, data) {
				w.broke()
				return nil
			}
		}

		// Skip whatever the member's consumer left unread, then the pad byte: ar
		// pads every member to an even length.
		if _, err := io.Copy(io.Discard, data); err != nil {
			return nil
		}
		if declared%2 != 0 {
			if _, err := br.Discard(1); err != nil {
				return nil
			}
		}
	}
	return nil
}
