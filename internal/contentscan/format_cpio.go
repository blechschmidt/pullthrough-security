package contentscan

import (
	"bufio"
	"io"
	"strconv"
)

// The cpio archive, in the ASCII dialects that occur in packages:
//
//   - "newc" (magic 070701, and 070702 with checksums): the payload of an RPM
//     in the v4 package format;
//   - the older portable "odc" (070707);
//   - rpm's "stripped" variant (07070X): the payload of an RPM in the v6
//     package format, and of any RPM carrying a file of 4 GiB or more. Its
//     entries hold no name, mode or size — only an index into the file table of
//     the package header, which the caller supplies.
//
// All are a sequence of header, name, data; the archive ends with a member
// named "TRAILER!!!".

const (
	cpioNewcHeader = 110
	cpioOdcHeader  = 76
	cpioTrailer    = "TRAILER!!!"
	// maxCpioName bounds a member name; PATH_MAX is 4096.
	maxCpioName = 8192

	cpioTypeMask = 0o170000
	cpioTypeReg  = 0o100000
	cpioTypeDir  = 0o040000
	cpioTypeLink = 0o120000
)

// cpioIndexed is one entry of the file table a stripped cpio's members index:
// what the member's own header would have said.
type cpioIndexed struct {
	path string
	mode int64 // the full st_mode: type and permission bits
	// size is the number of payload bytes the member carries: the file's size
	// for a regular file or a symbolic link (whose data is its target), zero for
	// everything else — including every hard link of a set but the last, which
	// alone carries the set's data.
	size int64
}

// walkCpio walks a cpio archive whose members are reported under prefix. table
// resolves the members of a stripped cpio; it is nil for a self-describing one.
func (w *walker) walkCpio(r io.Reader, prefix string, depth int, table []cpioIndexed) error {
	br := bufio.NewReaderSize(r, 4*peekBytes)
	seen := 0
	for !w.done() {
		var magic [6]byte
		n, err := io.ReadFull(br, magic[:])
		if n == 0 {
			return nil
		}
		if err != nil {
			w.malformed(seen)
			return nil
		}
		var (
			mode, fileSize int64
			rawName        string
			// pad reports a dialect whose headers and data are padded to a
			// multiple of four bytes.
			pad bool
		)
		switch string(magic[:]) {
		case "070701", "070702":
			pad = true
			var hdr [cpioNewcHeader - 6]byte
			if _, err := io.ReadFull(br, hdr[:]); err != nil {
				w.malformed(seen)
				return nil
			}
			// Thirteen 8-digit hexadecimal fields: ino, mode, uid, gid, nlink,
			// mtime, filesize, devmajor, devminor, rdevmajor, rdevminor, namesize,
			// check.
			field := func(i int) (int64, bool) {
				v, perr := strconv.ParseUint(string(hdr[i*8:i*8+8]), 16, 32)
				return int64(v), perr == nil
			}
			var nameSize int64
			var ok1, ok2, ok3 bool
			mode, ok1 = field(1)
			fileSize, ok2 = field(6)
			nameSize, ok3 = field(11)
			if !ok1 || !ok2 || !ok3 {
				w.malformed(seen)
				return nil
			}
			name, ok := readCpioName(br, nameSize)
			if !ok {
				w.malformed(seen)
				return nil
			}
			// Header plus name is padded to a multiple of four bytes.
			if p := (4 - (cpioNewcHeader+nameSize)%4) % 4; p > 0 {
				if _, err := br.Discard(int(p)); err != nil {
					return nil
				}
			}
			rawName = name
		case "070707":
			var hdr [cpioOdcHeader - 6]byte
			if _, err := io.ReadFull(br, hdr[:]); err != nil {
				w.malformed(seen)
				return nil
			}
			// Octal fields: dev[6] ino[6] mode[6] uid[6] gid[6] nlink[6] rdev[6]
			// mtime[11] namesize[6] filesize[11].
			oct := func(from, to int) (int64, bool) {
				v, perr := strconv.ParseUint(string(hdr[from:to]), 8, 63)
				return int64(v), perr == nil
			}
			var nameSize int64
			var ok1, ok2, ok3 bool
			mode, ok1 = oct(12, 18)
			nameSize, ok2 = oct(53, 59)
			fileSize, ok3 = oct(59, 70)
			if !ok1 || !ok2 || !ok3 {
				w.malformed(seen)
				return nil
			}
			name, ok := readCpioName(br, nameSize)
			if !ok {
				w.malformed(seen)
				return nil
			}
			rawName = name
		case "07070X":
			// rpm's stripped header: eight hexadecimal digits indexing the package
			// header's file table, padded (with the magic) to sixteen bytes.
			pad = true
			var hdr [8 + 2]byte
			if _, err := io.ReadFull(br, hdr[:]); err != nil {
				w.malformed(seen)
				return nil
			}
			if table == nil {
				// Without the package header there is nothing to resolve the index
				// against: a stripped cpio on its own is not a readable archive.
				if seen == 0 && depth == 0 {
					return errUnrecognizedArchive
				}
				w.malformed(seen)
				return nil
			}
			fx, perr := strconv.ParseUint(string(hdr[:8]), 16, 32)
			if perr != nil || fx >= uint64(len(table)) {
				// An index the header does not know: without the table entry there
				// is no telling how long the member is, so the walk cannot go on.
				w.broke()
				return nil
			}
			ent := table[fx]
			mode, fileSize, rawName = ent.mode, ent.size, ent.path
		default:
			if seen == 0 && depth == 0 {
				return errUnrecognizedArchive
			}
			w.malformed(seen)
			return nil
		}
		if rawName == cpioTrailer {
			return nil
		}
		seen++
		if !w.countEntry() {
			return nil
		}

		data := io.LimitReader(br, fileSize)
		inner := cleanName(rawName)
		name := prefix + inner
		switch mode & cpioTypeMask {
		case cpioTypeDir:
			// nothing to read
		case cpioTypeLink:
			// A symbolic link stores its target as the member's data.
			target, _, _ := readBounded(data, 4096)
			w.link(name, string(target), false)
		case cpioTypeReg, 0:
			if !w.member(containerCpio, depth, inner, name, fileSize, uint32(mode)&0o7777, data) {
				w.malformed(seen)
				return nil
			}
		default:
			w.stats.others++ // device nodes, fifos, sockets
		}
		if _, err := io.Copy(io.Discard, data); err != nil {
			return nil
		}
		if pad {
			if p := (4 - fileSize%4) % 4; p > 0 {
				if _, err := br.Discard(int(p)); err != nil {
					return nil
				}
			}
		}
	}
	return nil
}

// readCpioName reads a member name of the declared size (which counts the
// terminating NUL) and returns it without the terminator.
func readCpioName(br *bufio.Reader, size int64) (string, bool) {
	if size < 1 || size > maxCpioName {
		return "", false
	}
	buf := make([]byte, size)
	if _, err := io.ReadFull(br, buf); err != nil {
		return "", false
	}
	for i, c := range buf {
		if c == 0 {
			buf = buf[:i]
			break
		}
	}
	return string(buf), true
}

// malformed records a break in a container's structure once at least one
// member was read. A container that never yielded a member is the caller's to
// report (at the top level it is simply not an archive).
func (w *walker) malformed(seen int) {
	if seen > 0 {
		w.broke()
	}
}
