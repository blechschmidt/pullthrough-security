package julia

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha1"
	"fmt"
	"io"
	"sort"
	"strings"
)

// Julia's integrity record is the git-tree-sha1 named in every content-addressed
// URL: the SHA-1 Git tree object hash of the decompressed tarball's contents.
// The Pkg client verifies downloads this way "without git, by independently
// implementing the same algorithm git uses"; the proxy does the same, refusing
// to cache or serve any tarball whose recomputed tree hash does not match the
// hash in its URL. Verification is streaming — the gzip-compressed tarball is
// tee'd through the Git tree-hasher as it is written to the cache, so a mismatch
// aborts the cache write and the client stream at end-of-stream, and only the
// per-entry tree metadata (not the archive body) is ever held in memory.

// maxTreeEntries bounds the number of filesystem entries the tree-hasher will
// track, so a malicious upstream tarball with an unbounded number of tiny
// entries cannot exhaust memory. Real Julia package/registry trees are far
// smaller; the cap is generous.
const maxTreeEntries = 1 << 20 // 1,048,576 entries

// emptyTreeSHA1 is the git hash of the empty tree (sha1("tree 0\x00")). It is the
// hash of a tree with no tracked entries, matching git's behavior of not
// representing empty directories.
const emptyTreeSHA1 = "4b825dc642cb6eb9a060e54bf8d69288fbee4904"

// TreeHashMismatchError reports that a fetched tarball's recomputed git-tree-sha1
// did not match the hash named in its URL. It is returned by a treeHashVerifier
// at end-of-stream so the cache rejects the write — the partial blob is never
// committed — and the proxy surfaces the integrity failure instead of serving
// poisoned content.
type TreeHashMismatchError struct {
	Filename string
	Expected string
	Actual   string
	URL      string
}

func (e *TreeHashMismatchError) Error() string {
	return fmt.Sprintf("julia: git-tree-sha1 mismatch for %s (%s): expected %s, got %s",
		e.URL, e.Filename, e.Expected, e.Actual)
}

// treeHashVerifier wraps a gzip-compressed tarball body and verifies, at
// end-of-stream, that its decompressed contents hash to the expected
// git-tree-sha1. The body is tee'd into a pipe consumed by a Git tree-hasher
// running concurrently; on mismatch (or any decode/hash error) a
// *TreeHashMismatchError is returned in place of io.EOF, which propagates through
// io.Copy so the caching layer aborts the store and never commits unverified
// bytes.
type treeHashVerifier struct {
	src      io.ReadCloser
	pw       *io.PipeWriter
	result   chan hashResult
	expected string
	filename string
	url      string
	verified bool
	teeErr   error
	onResult func(ok bool)
}

type hashResult struct {
	hash string
	err  error
}

// newTreeHashVerifier wraps src so its decompressed contents are checked against
// the expected git-tree-sha1. The returned ReadCloser takes ownership of src and
// closes it on Close. onResult, when non-nil, fires once at end-of-stream with
// the outcome.
func newTreeHashVerifier(src io.ReadCloser, expected, filename, url string, onResult func(ok bool)) *treeHashVerifier {
	pr, pw := io.Pipe()
	v := &treeHashVerifier{
		src:      src,
		pw:       pw,
		result:   make(chan hashResult, 1),
		expected: expected,
		filename: filename,
		url:      url,
		onResult: onResult,
	}
	go func() {
		h, err := gitTreeHashGzip(pr)
		if err != nil {
			// Unblock the producer's next Write and signal the failure.
			pr.CloseWithError(err)
		} else {
			// Drain any bytes trailing the gzip stream so the producer's final
			// Writes never block, then close cleanly.
			_, _ = io.Copy(io.Discard, pr)
			_ = pr.Close()
		}
		v.result <- hashResult{hash: h, err: err}
	}()
	return v
}

func (v *treeHashVerifier) Read(p []byte) (int, error) {
	n, err := v.src.Read(p)
	if n > 0 && v.teeErr == nil {
		if _, werr := v.pw.Write(p[:n]); werr != nil {
			// The hashing pipeline failed (corrupt gzip/tar, or over the entry
			// cap); stop teeing and finalize as a verification failure.
			v.teeErr = werr
		}
	}

	switch {
	case err == io.EOF && !v.verified:
		v.verified = true
		_ = v.pw.Close()
		return n, v.finalize(err)
	case v.teeErr != nil && !v.verified:
		v.verified = true
		return n, v.finalize(err)
	}
	return n, err
}

// finalize awaits the hasher result and returns a *TreeHashMismatchError when the
// content did not verify, or passthroughErr otherwise (io.EOF on a clean EOF).
func (v *treeHashVerifier) finalize(passthroughErr error) error {
	res := <-v.result
	got := res.hash
	ok := res.err == nil && strings.EqualFold(got, v.expected)
	if v.onResult != nil {
		v.onResult(ok)
	}
	if ok {
		return passthroughErr
	}
	if got == "" {
		got = "unknown"
	}
	return &TreeHashMismatchError{
		Filename: v.filename,
		Expected: "git-tree-sha1:" + v.expected,
		Actual:   "git-tree-sha1:" + got,
		URL:      v.url,
	}
}

func (v *treeHashVerifier) Close() error {
	// Unblock the hasher goroutine if the consumer abandoned the stream early.
	if v.pw != nil && !v.verified {
		_ = v.pw.CloseWithError(io.ErrClosedPipe)
		select {
		case <-v.result:
		default:
		}
	}
	return v.src.Close()
}

// gitTreeHashGzip decompresses r (a gzip stream) and computes the SHA-1 Git tree
// object hash of the tar archive's contents, exactly as git would for the
// equivalent working tree. It streams: file contents flow through a SHA-1 blob
// hasher and are not retained; only per-entry tree metadata is accumulated.
func gitTreeHashGzip(r io.Reader) (string, error) {
	gzr, err := gzip.NewReader(r)
	if err != nil {
		return "", fmt.Errorf("julia: gunzip tarball: %w", err)
	}
	defer gzr.Close()

	root := newTreeNode()
	entries := 0
	tr := tar.NewReader(gzr)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return "", fmt.Errorf("julia: read tar entry: %w", err)
		}

		name, ok := normalizeEntryName(hdr.Name)
		if !ok {
			return "", fmt.Errorf("julia: unsafe tar entry name %q", hdr.Name)
		}
		if name == "" {
			continue // the archive root ("." / "./")
		}

		switch hdr.Typeflag {
		case tar.TypeXGlobalHeader, tar.TypeXHeader:
			continue // pax metadata, not a filesystem entry
		case tar.TypeDir:
			if err := root.ensureDir(name); err != nil {
				return "", err
			}
		case tar.TypeReg, tar.TypeRegA:
			mode := "100644"
			if hdr.Mode&0o111 != 0 {
				mode = "100755"
			}
			sum, err := blobHashReader(tr, hdr.Size)
			if err != nil {
				return "", err
			}
			entries++
			if entries > maxTreeEntries {
				return "", fmt.Errorf("julia: tarball exceeds %d entries", maxTreeEntries)
			}
			if err := root.addLeaf(name, mode, sum); err != nil {
				return "", err
			}
		case tar.TypeSymlink:
			sum := blobHashBytes([]byte(hdr.Linkname))
			entries++
			if entries > maxTreeEntries {
				return "", fmt.Errorf("julia: tarball exceeds %d entries", maxTreeEntries)
			}
			if err := root.addLeaf(name, "120000", sum); err != nil {
				return "", err
			}
		default:
			// Hardlinks, char/block devices, FIFOs, etc. do not occur in a Git
			// tree; refuse rather than silently diverge from git's hash.
			return "", fmt.Errorf("julia: unsupported tar entry type %d for %q", hdr.Typeflag, name)
		}
	}

	sum, nonEmpty := root.treeHash()
	if !nonEmpty {
		return emptyTreeSHA1, nil
	}
	return toHex(sum), nil
}

// blobHashReader computes the SHA-1 Git blob hash of size bytes read from r.
// The content streams through the hasher and is never buffered.
func blobHashReader(r io.Reader, size int64) ([]byte, error) {
	h := sha1.New()
	fmt.Fprintf(h, "blob %d\x00", size)
	n, err := io.Copy(h, r)
	if err != nil {
		return nil, fmt.Errorf("julia: read tar entry body: %w", err)
	}
	if n != size {
		return nil, fmt.Errorf("julia: tar entry body short read (%d of %d)", n, size)
	}
	return h.Sum(nil), nil
}

// blobHashBytes computes the SHA-1 Git blob hash of a small in-memory byte slice
// (used for symlink targets).
func blobHashBytes(b []byte) []byte {
	h := sha1.New()
	fmt.Fprintf(h, "blob %d\x00", len(b))
	h.Write(b)
	return h.Sum(nil)
}

// treeNode is a directory in the reconstructed tree. Files and subdirectories
// are kept separate; a name present as both is a malformed tree and surfaces as
// a verification mismatch rather than a panic.
type treeNode struct {
	dirs  map[string]*treeNode
	files map[string]fileLeaf
}

type fileLeaf struct {
	mode string
	sha  []byte // raw 20-byte SHA-1
}

func newTreeNode() *treeNode {
	return &treeNode{dirs: map[string]*treeNode{}, files: map[string]fileLeaf{}}
}

// ensureDir creates the directory chain for name (slash-separated) without a
// leaf. Git does not track empty directories, so such a node contributes nothing
// to the hash unless a file is later added beneath it.
func (n *treeNode) ensureDir(name string) error {
	cur := n
	for _, comp := range strings.Split(name, "/") {
		next, ok := cur.dirs[comp]
		if !ok {
			next = newTreeNode()
			cur.dirs[comp] = next
		}
		cur = next
	}
	return nil
}

// addLeaf inserts a file/symlink leaf at name (slash-separated), creating any
// intermediate directories.
func (n *treeNode) addLeaf(name, mode string, sha []byte) error {
	comps := strings.Split(name, "/")
	cur := n
	for _, comp := range comps[:len(comps)-1] {
		next, ok := cur.dirs[comp]
		if !ok {
			next = newTreeNode()
			cur.dirs[comp] = next
		}
		cur = next
	}
	cur.files[comps[len(comps)-1]] = fileLeaf{mode: mode, sha: sha}
	return nil
}

// treeEntry is one child in a tree object, used only for sorting/encoding.
type treeEntry struct {
	name  string
	mode  string
	sha   []byte
	isDir bool
}

// treeHash computes the SHA-1 Git tree object hash of this directory. It returns
// nonEmpty=false when the directory (recursively) tracks no files, so the parent
// omits it — matching git, which never stores an empty tree as a child entry.
func (n *treeNode) treeHash() (sum []byte, nonEmpty bool) {
	entries := make([]treeEntry, 0, len(n.files)+len(n.dirs))
	for name, leaf := range n.files {
		entries = append(entries, treeEntry{name: name, mode: leaf.mode, sha: leaf.sha})
	}
	for name, d := range n.dirs {
		childSum, childNonEmpty := d.treeHash()
		if !childNonEmpty {
			continue
		}
		entries = append(entries, treeEntry{name: name, mode: "40000", sha: childSum, isDir: true})
	}
	if len(entries) == 0 {
		return nil, false
	}

	// Git orders tree entries by name, comparing a directory as though its name
	// had a trailing '/'. Sorting by that key reproduces the ordering for siblings.
	sort.Slice(entries, func(i, j int) bool {
		return sortKey(entries[i]) < sortKey(entries[j])
	})

	var buf bytes.Buffer
	for _, e := range entries {
		buf.WriteString(e.mode)
		buf.WriteByte(' ')
		buf.WriteString(e.name)
		buf.WriteByte(0)
		buf.Write(e.sha)
	}
	h := sha1.New()
	fmt.Fprintf(h, "tree %d\x00", buf.Len())
	h.Write(buf.Bytes())
	return h.Sum(nil), true
}

func sortKey(e treeEntry) string {
	if e.isDir {
		return e.name + "/"
	}
	return e.name
}

// normalizeEntryName cleans a tar entry path to a slash-separated relative path,
// rejecting absolute paths and any traversal. It returns ("", true) for the
// archive root itself.
func normalizeEntryName(name string) (string, bool) {
	name = strings.TrimPrefix(name, "./")
	name = strings.Trim(name, "/")
	if name == "" || name == "." {
		return "", true
	}
	for _, comp := range strings.Split(name, "/") {
		if comp == "" || comp == "." || comp == ".." {
			return "", false
		}
	}
	return name, true
}

const hexDigits = "0123456789abcdef"

// toHex lowercase-hex-encodes b without allocating via fmt.
func toHex(b []byte) string {
	out := make([]byte, len(b)*2)
	for i, c := range b {
		out[i*2] = hexDigits[c>>4]
		out[i*2+1] = hexDigits[c&0x0f]
	}
	return string(out)
}
