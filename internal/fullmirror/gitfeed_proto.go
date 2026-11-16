package fullmirror

import (
	"bufio"
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
)

// The Git-backed registries (the crates.io index, the Bazel Central Registry,
// conan-center-index, homebrew-core) are followed by diffing the trees of
// their repository's head commits. This file speaks the client side of Git's
// smart HTTP protocol, version 2, just far enough for that: ls-refs to learn
// the head, and a shallow, blob-less fetch of the head's commit and trees.
// It goes through the adapter's HTTP client — the upstream's egress policy,
// TLS pins and pacing — rather than a git binary, which would bypass all three.
// Every object is checked against its hash as it is read (gitfeed_pack.go), so
// the trees the diff walks are the ones the head commit names.

// Limits on what a Git feed reads.
const (
	// maxGitPack bounds a fetch's pack: the crates.io index's trees, all of
	// them, come to about 14 MB.
	maxGitPack = 256 << 20
	// maxGitRefs bounds the ref advertisement.
	maxGitRefs = 4 << 20
	// maxPktLine is the largest pkt-line payload (the format's own bound).
	maxPktLine = 65516
)

// errNotGitV2 reports a server that does not speak protocol version 2.
var errNotGitV2 = errors.New("the server does not speak Git protocol version 2")

// pktLine renders one pkt-line.
func pktLine(s string) []byte {
	return []byte(fmt.Sprintf("%04x%s", len(s)+4, s))
}

// Special pkt-lines.
var (
	pktFlush = []byte("0000")
	pktDelim = []byte("0001")
)

// pktReader reads pkt-lines.
type pktReader struct {
	r   *bufio.Reader
	buf []byte
}

func newPktReader(r io.Reader) *pktReader {
	return &pktReader{r: bufio.NewReaderSize(r, 64<<10), buf: make([]byte, maxPktLine)}
}

// pkt kinds besides data.
const (
	pktData = iota
	pktKindFlush
	pktKindDelim
	pktKindEnd
)

// next reads one pkt-line. The payload is valid until the next call.
func (p *pktReader) next() (kind int, payload []byte, err error) {
	var hdr [4]byte
	if _, err := io.ReadFull(p.r, hdr[:]); err != nil {
		if err == io.EOF {
			return 0, nil, io.ErrUnexpectedEOF
		}
		return 0, nil, err
	}
	n, err := strconv.ParseUint(string(hdr[:]), 16, 16)
	if err != nil {
		return 0, nil, fmt.Errorf("not a pkt-line: %q", hdr[:])
	}
	switch n {
	case 0:
		return pktKindFlush, nil, nil
	case 1:
		return pktKindDelim, nil, nil
	case 2:
		return pktKindEnd, nil, nil
	case 3:
		return 0, nil, fmt.Errorf("invalid pkt-line length 3")
	}
	size := int(n) - 4
	if size > maxPktLine {
		return 0, nil, fmt.Errorf("pkt-line of %d bytes", size)
	}
	if _, err := io.ReadFull(p.r, p.buf[:size]); err != nil {
		return 0, nil, err
	}
	return pktData, p.buf[:size], nil
}

// gitRemote is a Git repository read over smart HTTP.
type gitRemote struct {
	k    kit
	repo *url.URL

	mu   sync.Mutex
	caps map[string]string
}

func newGitRemote(k kit, repo *url.URL) *gitRemote { return &gitRemote{k: k, repo: repo} }

// capabilities reads (once) the server's protocol v2 capability
// advertisement.
func (g *gitRemote) capabilities(ctx context.Context) (map[string]string, error) {
	g.mu.Lock()
	caps := g.caps
	g.mu.Unlock()
	if caps != nil {
		return caps, nil
	}
	body, _, err := g.k.get(ctx, join(g.repo, "info/refs")+"?service=git-upload-pack",
		http.Header{"Git-Protocol": {"version=2"}}, maxGitRefs)
	if err != nil {
		return nil, fmt.Errorf("reading the capabilities of %s: %w", g.repo.Redacted(), err)
	}
	caps, err = parseGitCapabilities(body)
	if err != nil {
		return nil, Permanent(fmt.Errorf("the capabilities of %s: %w", g.repo.Redacted(), err))
	}
	g.mu.Lock()
	g.caps = caps
	g.mu.Unlock()
	return caps, nil
}

// parseGitCapabilities reads a protocol v2 capability advertisement: an
// optional "# service=git-upload-pack" section, then "version 2" and one
// capability per line.
func parseGitCapabilities(body []byte) (map[string]string, error) {
	pr := newPktReader(bytes.NewReader(body))
	caps := map[string]string{}
	sawVersion := false
	for {
		kind, payload, err := pr.next()
		if err != nil {
			if !sawVersion {
				return nil, errNotGitV2
			}
			return nil, err
		}
		if kind == pktKindFlush {
			if sawVersion {
				return caps, nil
			}
			continue // the end of the "# service=" section
		}
		if kind != pktData {
			continue
		}
		line := strings.TrimSuffix(string(payload), "\n")
		switch {
		case strings.HasPrefix(line, "# service="):
		case line == "version 2":
			sawVersion = true
		case !sawVersion:
			return nil, errNotGitV2
		default:
			k, v, _ := strings.Cut(line, "=")
			caps[k] = v
		}
	}
}

// command runs one protocol v2 command and returns the response body (the
// caller closes it).
func (g *gitRemote) command(ctx context.Context, cmd string, args []string) (io.ReadCloser, error) {
	caps, err := g.capabilities(ctx)
	if err != nil {
		return nil, err
	}
	if _, ok := caps[cmd]; !ok {
		return nil, Permanent(fmt.Errorf("%s does not offer the Git %s command", g.repo.Redacted(), cmd))
	}
	var req bytes.Buffer
	req.Write(pktLine("command=" + cmd + "\n"))
	if f, ok := caps["object-format"]; ok {
		if f != "sha1" {
			return nil, Permanent(fmt.Errorf("%s uses object format %q; only sha1 is read", g.repo.Redacted(), f))
		}
		req.Write(pktLine("object-format=sha1\n"))
	}
	req.Write(pktDelim)
	for _, a := range args {
		req.Write(pktLine(a + "\n"))
	}
	req.Write(pktFlush)
	resp, err := g.k.do(ctx, http.MethodPost, join(g.repo, "git-upload-pack"), &req, http.Header{
		"Content-Type": {"application/x-git-upload-pack-request"},
		"Accept":       {"application/x-git-upload-pack-result"},
		"Git-Protocol": {"version=2"},
	})
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		defer drain(resp.Body)
		return nil, httpStatusError(g.repo.Redacted()+" "+cmd, resp)
	}
	return resp.Body, nil
}

// head returns the commit a branch points at — the remote's HEAD when branch
// is empty.
func (g *gitRemote) head(ctx context.Context, branch string) (string, error) {
	ref := "HEAD"
	if branch != "" {
		ref = "refs/heads/" + branch
	}
	body, err := g.command(ctx, "ls-refs", []string{"symrefs", "ref-prefix " + ref})
	if err != nil {
		return "", fmt.Errorf("reading the refs of %s: %w", g.repo.Redacted(), err)
	}
	defer drain(body)
	refs, err := parseLsRefs(io.LimitReader(body, maxGitRefs))
	if err != nil {
		return "", Permanent(fmt.Errorf("the refs of %s: %w", g.repo.Redacted(), err))
	}
	oid, ok := refs[ref]
	if !ok {
		return "", Permanent(fmt.Errorf("%s has no %s", g.repo.Redacted(), ref))
	}
	return oid, nil
}

// parseLsRefs reads an ls-refs response: "<oid> <ref>[ attributes]" lines.
func parseLsRefs(r io.Reader) (map[string]string, error) {
	pr := newPktReader(r)
	refs := map[string]string{}
	for {
		kind, payload, err := pr.next()
		if err != nil {
			return nil, err
		}
		if kind == pktKindFlush {
			return refs, nil
		}
		if kind != pktData {
			return nil, fmt.Errorf("unexpected section marker in the ref list")
		}
		fields := strings.Fields(string(payload))
		if len(fields) < 2 {
			return nil, fmt.Errorf("malformed ref line %q", truncate(string(payload), 80))
		}
		if fields[0] == "unborn" {
			continue
		}
		if !isHexOID(fields[0]) {
			return nil, fmt.Errorf("ref %q names no object id", truncate(fields[1], 80))
		}
		refs[fields[1]] = fields[0]
	}
}

// isHexOID reports whether s is a lower-case hex SHA-1.
func isHexOID(s string) bool {
	if len(s) != 40 {
		return false
	}
	_, err := hex.DecodeString(s)
	return err == nil && strings.ToLower(s) == s
}

// errGitIncrementalTooLarge reports an incremental fetch past its bound.
var errGitIncrementalTooLarge = errors.New("the incremental fetch is larger than a fresh snapshot is worth")

// maxGitIncremental and maxGitIncrementalInflated bound an incremental fetch:
// past either, a fresh snapshot of the head's trees is cheaper (the crates.io
// index's comes to about 14 MB, inflating to about 30 MB, while a day of its
// commits sent incrementally inflates to some 400 MB).
var (
	maxGitIncremental         = 64 << 20
	maxGitIncrementalInflated = uint64(64 << 20)
)

// fetchTrees fetches the commit want and its trees — never blobs. Without
// have it asks for a snapshot: the commit alone (depth 1) and all its trees.
// With have — the commit whose trees the follower holds — it asks for what
// lies between the two: the server sends the commits since have and the trees
// they changed, nothing have's trees hold already. (A depth limit would make
// the server send the whole snapshot again, haves notwithstanding.) Should
// have not be an ancestor of want — the branch was squashed or force-pushed —
// the server sends want's history down to its root; the read is cut off at
// maxGitIncremental and reported with errGitIncrementalTooLarge, so that the
// caller asks for a snapshot instead.
func (g *gitRemote) fetchTrees(ctx context.Context, want, have string) (*gitObjects, error) {
	caps, err := g.capabilities(ctx)
	if err != nil {
		return nil, err
	}
	features := " " + caps["fetch"] + " "
	if !strings.Contains(features, " shallow ") || !strings.Contains(features, " filter ") {
		return nil, Permanent(fmt.Errorf("%s does not offer shallow, filtered fetches (fetch=%s)", g.repo.Redacted(), caps["fetch"]))
	}
	args := []string{"no-progress", "ofs-delta", "filter blob:none"}
	limit := int64(maxGitPack)
	if have == "" {
		args = append(args, "deepen 1", "want "+want)
	} else {
		args = append(args, "want "+want, "have "+have)
		limit = int64(maxGitIncremental)
	}
	args = append(args, "done")
	body, err := g.command(ctx, "fetch", args)
	if err != nil {
		return nil, fmt.Errorf("fetching %s from %s: %w", want, g.repo.Redacted(), err)
	}
	defer drain(body)
	pack, err := readFetchResponse(body, limit)
	if errors.Is(err, errGitPackTooLarge) && have != "" {
		return nil, errGitIncrementalTooLarge
	}
	if err != nil {
		return nil, fmt.Errorf("fetching %s from %s: %w", want, g.repo.Redacted(), err)
	}
	inflate := uint64(maxPackInflated)
	if have != "" {
		inflate = maxGitIncrementalInflated
	}
	objs, err := parsePackBounded(ctx, pack, inflate)
	switch {
	case err == nil:
		return objs, nil
	case ctx.Err() != nil:
		return nil, ctx.Err()
	case errors.Is(err, errPackBound) && have != "":
		return nil, errGitIncrementalTooLarge
	}
	return nil, Permanent(fmt.Errorf("the pack %s sent for %s: %w", g.repo.Redacted(), want, err))
}

// errGitPackTooLarge reports a pack past the read's bound.
var errGitPackTooLarge = errors.New("the pack is larger than the read allows")

// readFetchResponse reads a protocol v2 fetch response and returns the pack
// its packfile section carries (side-band channel 1), at most limit bytes.
func readFetchResponse(r io.Reader, limit int64) ([]byte, error) {
	pr := newPktReader(r)
	section := ""
	var pack bytes.Buffer
	for {
		kind, payload, err := pr.next()
		if err != nil {
			return nil, err
		}
		switch kind {
		case pktKindFlush, pktKindEnd:
			if section != "packfile" {
				return nil, fmt.Errorf("the response ended without a pack")
			}
			return pack.Bytes(), nil
		case pktKindDelim:
			section = ""
			continue
		}
		if section == "" {
			section = strings.TrimSuffix(string(payload), "\n")
			switch section {
			case "acknowledgments", "shallow-info", "wanted-refs", "packfile-uris", "packfile":
			default:
				return nil, fmt.Errorf("unknown response section %q", truncate(section, 40))
			}
			if section == "packfile-uris" {
				return nil, fmt.Errorf("the server offered packfile URIs, which are not fetched")
			}
			continue
		}
		if section != "packfile" {
			continue
		}
		if len(payload) == 0 {
			continue
		}
		switch payload[0] {
		case 1:
			if int64(pack.Len()+len(payload)-1) > limit {
				return nil, fmt.Errorf("%w (%d bytes)", errGitPackTooLarge, limit)
			}
			pack.Write(payload[1:])
		case 2:
			// Progress messages: not asked for, ignored.
		case 3:
			return nil, fmt.Errorf("the server reported: %s", truncate(cleanMessage(string(payload[1:])), 200))
		default:
			return nil, fmt.Errorf("unknown side-band channel %d", payload[0])
		}
	}
}
