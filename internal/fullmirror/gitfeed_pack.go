package fullmirror

import (
	"bytes"
	"compress/zlib"
	"context"
	"crypto/sha1" //nolint:gosec // Git object ids are SHA-1; this is Git's own integrity check, not a security primitive of the proxy's.
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strconv"
	"time"
)

// This file reads a Git pack (format version 2) as a fetch returns it: every
// object is inflated, deltas are applied to their bases, and each object is
// indexed by the SHA-1 of its content — the id is computed here, never taken
// from the pack, so a tree is only ever found under the id its parent names.

// Git object types as a pack encodes them.
const (
	gitCommit   = 1
	gitTree     = 2
	gitBlob     = 3
	gitTag      = 4
	gitOfsDelta = 6
	gitRefDelta = 7
)

// Limits on a pack.
const (
	// maxPackObjects bounds the objects of one pack.
	maxPackObjects = 4 << 20
	// maxGitObject bounds one object (and one delta's result).
	maxGitObject = 64 << 20
	// maxPackInflated bounds what a pack inflates to, deltas applied: a
	// compressed object can stand for a thousand times its size. The trees
	// of the crates.io index inflate to about 30 MB.
	maxPackInflated = 512 << 20
)

// gitOID is a Git object id.
type gitOID [20]byte

func (id gitOID) String() string { return hex.EncodeToString(id[:]) }

// parseOID reads a hex object id.
func parseOID(s string) (gitOID, error) {
	var id gitOID
	if !isHexOID(s) {
		return id, fmt.Errorf("%q is not a Git object id", truncate(s, 64))
	}
	_, err := hex.Decode(id[:], []byte(s))
	return id, err
}

// gitObject is an object of a pack, resolved.
type gitObject struct {
	typ  int
	data []byte
}

// gitObjects are the objects of a pack, by id.
type gitObjects struct {
	objs map[gitOID]gitObject
}

func (o *gitObjects) get(id gitOID) (gitObject, bool) {
	if o == nil {
		return gitObject{}, false
	}
	obj, ok := o.objs[id]
	return obj, ok
}

func gitTypeName(t int) string {
	switch t {
	case gitCommit:
		return "commit"
	case gitTree:
		return "tree"
	case gitBlob:
		return "blob"
	case gitTag:
		return "tag"
	}
	return ""
}

// hashObject computes an object's id.
func hashObject(typ int, data []byte) gitOID {
	h := sha1.New() //nolint:gosec // see the import
	h.Write([]byte(gitTypeName(typ) + " " + strconv.Itoa(len(data)) + "\x00"))
	h.Write(data)
	var id gitOID
	copy(id[:], h.Sum(nil))
	return id
}

// packEntry is an object as the pack stores it, before deltas are applied.
type packEntry struct {
	offset  int
	typ     int
	data    []byte
	baseOff int    // for an offset delta: the base's offset
	baseID  gitOID // for a reference delta: the base's id
	done    bool
}

// errPackBound reports a pack past one of the reader's bounds (its object
// count, an object's size, what it inflates to).
var errPackBound = errors.New("the pack is past the reader's bounds")

// parsePack reads a pack and returns its objects, within the default bounds.
func parsePack(pack []byte) (*gitObjects, error) {
	return parsePackBounded(context.Background(), pack, maxPackInflated)
}

// parsePackBounded reads a pack whose objects inflate to at most maxInflated
// bytes, deltas applied. ctx is checked as it goes: a pack takes time to
// inflate, and a poll's timeout must hold.
func parsePackBounded(ctx context.Context, pack []byte, maxInflated uint64) (*gitObjects, error) {
	if len(pack) < 32 || !bytes.Equal(pack[:4], []byte("PACK")) {
		return nil, errors.New("not a Git pack")
	}
	if v := binary.BigEndian.Uint32(pack[4:8]); v != 2 && v != 3 {
		return nil, fmt.Errorf("pack version %d is not read", v)
	}
	count := binary.BigEndian.Uint32(pack[8:12])
	if count > maxPackObjects || int(count) > len(pack) {
		return nil, fmt.Errorf("%w: the pack claims %d objects", errPackBound, count)
	}
	sum := sha1.Sum(pack[:len(pack)-20]) //nolint:gosec // see the import
	if !bytes.Equal(sum[:], pack[len(pack)-20:]) {
		return nil, errors.New("the pack's checksum does not match")
	}
	body := pack[:len(pack)-20]
	entries := make([]packEntry, 0, count)
	var inflated uint64
	byOffset := make(map[int]int, count)
	pos := 12
	var zr io.ReadCloser
	for i := uint32(0); i < count; i++ {
		e := packEntry{offset: pos}
		if pos >= len(body) {
			return nil, fmt.Errorf("the pack ends after %d of %d objects", i, count)
		}
		c := body[pos]
		pos++
		e.typ = int(c>>4) & 7
		size := uint64(c & 15)
		for shift := 4; c&0x80 != 0; shift += 7 {
			if pos >= len(body) || shift > 56 {
				return nil, fmt.Errorf("object %d: a malformed size", i)
			}
			c = body[pos]
			pos++
			size |= uint64(c&0x7f) << shift
		}
		if size > maxGitObject {
			return nil, fmt.Errorf("%w: object %d is %d bytes, more than %d", errPackBound, i, size, maxGitObject)
		}
		if inflated += size; inflated > maxInflated {
			return nil, fmt.Errorf("%w: the pack inflates to more than %d bytes", errPackBound, maxInflated)
		}
		if i%1024 == 0 {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
		}
		switch e.typ {
		case gitCommit, gitTree, gitBlob, gitTag:
			e.done = true
		case gitOfsDelta:
			if pos >= len(body) {
				return nil, fmt.Errorf("object %d: a truncated delta offset", i)
			}
			c = body[pos]
			pos++
			off := uint64(c & 0x7f)
			for c&0x80 != 0 {
				if pos >= len(body) || off > 1<<56 {
					return nil, fmt.Errorf("object %d: a malformed delta offset", i)
				}
				c = body[pos]
				pos++
				off = ((off + 1) << 7) | uint64(c&0x7f)
			}
			if off == 0 || off > uint64(e.offset-12) {
				return nil, fmt.Errorf("object %d: a delta base outside the pack", i)
			}
			e.baseOff = e.offset - int(off)
			if _, ok := byOffset[e.baseOff]; !ok {
				return nil, fmt.Errorf("object %d: no object starts at its base's offset", i)
			}
		case gitRefDelta:
			if pos+20 > len(body) {
				return nil, fmt.Errorf("object %d: a truncated delta base", i)
			}
			copy(e.baseID[:], body[pos:pos+20])
			pos += 20
		default:
			return nil, fmt.Errorf("object %d has unknown type %d", i, e.typ)
		}
		// Inflate exactly the object's stream: a bytes.Reader is an
		// io.ByteReader, so the decompressor reads no further than its end.
		br := bytes.NewReader(body[pos:])
		var err error
		if zr == nil {
			zr, err = zlib.NewReader(br)
		} else {
			err = zr.(zlib.Resetter).Reset(br, nil)
		}
		if err != nil {
			return nil, fmt.Errorf("object %d: %w", i, err)
		}
		data, err := io.ReadAll(io.LimitReader(zr, int64(size)+1))
		if err != nil {
			return nil, fmt.Errorf("object %d: %w", i, err)
		}
		if uint64(len(data)) != size {
			return nil, fmt.Errorf("object %d inflates to %d bytes, not the %d stated", i, len(data), size)
		}
		e.data = data
		pos += len(body[pos:]) - br.Len()
		byOffset[e.offset] = len(entries)
		entries = append(entries, e)
	}
	if pos != len(body) {
		return nil, fmt.Errorf("%d bytes follow the last object", len(body)-pos)
	}
	// Resolve the deltas from their bases outwards: every object is
	// resolved once, when its base is — an offset delta by the base's
	// offset, a reference delta by the base's id — so a pack resolves in
	// time proportional to its size whatever the order of its deltas.
	objs := &gitObjects{objs: make(map[gitOID]gitObject, len(entries))}
	byBaseOffset := map[int][]int{}
	byBaseID := map[gitOID][]int{}
	var queue []int
	for i, e := range entries {
		switch {
		case e.done:
			queue = append(queue, i)
		case e.typ == gitOfsDelta:
			byBaseOffset[e.baseOff] = append(byBaseOffset[e.baseOff], i)
		default:
			byBaseID[e.baseID] = append(byBaseID[e.baseID], i)
		}
	}
	resolved := 0
	for len(queue) > 0 {
		i := queue[len(queue)-1]
		queue = queue[:len(queue)-1]
		if resolved++; resolved%1024 == 0 {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
		}
		e := &entries[i]
		id := hashObject(e.typ, e.data)
		if _, dup := objs.objs[id]; !dup {
			objs.objs[id] = gitObject{typ: e.typ, data: e.data}
		}
		children := append(byBaseOffset[e.offset], byBaseID[id]...)
		delete(byBaseOffset, e.offset)
		delete(byBaseID, id)
		for _, c := range children {
			ce := &entries[c]
			if ce.done {
				continue
			}
			data, err := applyDelta(e.data, ce.data)
			if err != nil {
				return nil, fmt.Errorf("the delta at offset %d: %w", ce.offset, err)
			}
			if inflated += uint64(len(data)); inflated > maxInflated {
				return nil, fmt.Errorf("%w: the pack inflates to more than %d bytes", errPackBound, maxInflated)
			}
			ce.typ, ce.data, ce.done = e.typ, data, true
			queue = append(queue, c)
		}
	}
	for _, e := range entries {
		if !e.done {
			return nil, fmt.Errorf("the delta at offset %d names a base the pack does not hold", e.offset)
		}
	}
	return objs, nil
}

// deltaSize reads one of a delta's size fields (little-endian base 128).
func deltaSize(d []byte) (uint64, int, error) {
	var v uint64
	for i := 0; i < len(d) && i < 10; i++ {
		v |= uint64(d[i]&0x7f) << (7 * i)
		if d[i]&0x80 == 0 {
			return v, i + 1, nil
		}
	}
	return 0, 0, errors.New("a malformed size")
}

// applyDelta rebuilds an object from its base and a delta.
func applyDelta(base, delta []byte) ([]byte, error) {
	src, n, err := deltaSize(delta)
	if err != nil {
		return nil, err
	}
	delta = delta[n:]
	if src != uint64(len(base)) {
		return nil, fmt.Errorf("the delta expects a base of %d bytes, not %d", src, len(base))
	}
	dst, n, err := deltaSize(delta)
	if err != nil {
		return nil, err
	}
	delta = delta[n:]
	if dst > maxGitObject {
		return nil, fmt.Errorf("the delta builds an object of %d bytes", dst)
	}
	out := make([]byte, 0, dst)
	for len(delta) > 0 {
		op := delta[0]
		delta = delta[1:]
		switch {
		case op&0x80 != 0:
			var off, size uint64
			for i := uint(0); i < 4; i++ {
				if op&(1<<i) != 0 {
					if len(delta) == 0 {
						return nil, errors.New("a truncated copy")
					}
					off |= uint64(delta[0]) << (8 * i)
					delta = delta[1:]
				}
			}
			for i := uint(0); i < 3; i++ {
				if op&(1<<(4+i)) != 0 {
					if len(delta) == 0 {
						return nil, errors.New("a truncated copy")
					}
					size |= uint64(delta[0]) << (8 * i)
					delta = delta[1:]
				}
			}
			if size == 0 {
				size = 0x10000
			}
			if off+size > uint64(len(base)) {
				return nil, errors.New("a copy beyond the base")
			}
			out = append(out, base[off:off+size]...)
		case op != 0:
			if int(op) > len(delta) {
				return nil, errors.New("a truncated insert")
			}
			out = append(out, delta[:op]...)
			delta = delta[op:]
		default:
			return nil, errors.New("the reserved delta opcode 0")
		}
		if uint64(len(out)) > dst {
			return nil, errors.New("the delta builds more than it states")
		}
	}
	if uint64(len(out)) != dst {
		return nil, fmt.Errorf("the delta builds %d bytes, not the %d it states", len(out), dst)
	}
	return out, nil
}

// gitCommitInfo is what the feed reads from a commit.
type gitCommitInfo struct {
	tree      gitOID
	committed time.Time
}

// parseGitCommit reads a commit's tree and committer time.
func parseGitCommit(data []byte) (gitCommitInfo, error) {
	var ci gitCommitInfo
	sawTree := false
	for len(data) > 0 {
		line := data
		if i := bytes.IndexByte(data, '\n'); i >= 0 {
			line, data = data[:i], data[i+1:]
		} else {
			data = nil
		}
		if len(line) == 0 {
			break // the end of the headers
		}
		switch {
		case bytes.HasPrefix(line, []byte("tree ")) && !sawTree:
			id, err := parseOID(string(line[5:]))
			if err != nil {
				return ci, fmt.Errorf("the commit's tree: %w", err)
			}
			ci.tree, sawTree = id, true
		case bytes.HasPrefix(line, []byte("committer ")):
			// "committer Name <email> <unix seconds> <zone>"
			f := bytes.Fields(line)
			if len(f) >= 3 {
				if secs, err := strconv.ParseInt(string(f[len(f)-2]), 10, 64); err == nil && secs > 0 && secs < 1<<40 {
					ci.committed = time.Unix(secs, 0).UTC()
				}
			}
		}
	}
	if !sawTree {
		return ci, errors.New("the commit names no tree")
	}
	return ci, nil
}

// gitTreeEntry is one entry of a tree.
type gitTreeEntry struct {
	mode uint32
	name string
	id   gitOID
}

// Tree entry modes.
const (
	gitModeTree   = 0o40000
	gitModeGitlnk = 0o160000
)

func (e gitTreeEntry) isTree() bool { return e.mode == gitModeTree }

// parseGitTree reads a tree's entries, in their stored order.
func parseGitTree(data []byte) ([]gitTreeEntry, error) {
	var out []gitTreeEntry
	for len(data) > 0 {
		sp := bytes.IndexByte(data, ' ')
		if sp <= 0 || sp > 7 {
			return nil, errors.New("a tree entry without a mode")
		}
		mode, err := strconv.ParseUint(string(data[:sp]), 8, 32)
		if err != nil {
			return nil, fmt.Errorf("a tree entry's mode: %w", err)
		}
		data = data[sp+1:]
		nul := bytes.IndexByte(data, 0)
		if nul <= 0 || nul+21 > len(data) {
			return nil, errors.New("a truncated tree entry")
		}
		name := string(data[:nul])
		if name == "." || name == ".." || bytes.ContainsAny(data[:nul], "/") {
			return nil, fmt.Errorf("a tree entry named %q", truncate(name, 80))
		}
		var id gitOID
		copy(id[:], data[nul+1:nul+21])
		data = data[nul+21:]
		out = append(out, gitTreeEntry{mode: uint32(mode), name: name, id: id})
	}
	return out, nil
}
