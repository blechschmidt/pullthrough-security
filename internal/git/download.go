package git

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/blechschmidt/pullthrough-security/internal/backends"
)

// This file tells the download log (internal/downloadlog, Task 176) which Git
// requests transfer content. A clone or fetch is, for the question "who has
// this code", the same thing as a package download; the protocol chatter around
// it — capability and ref advertisements, ref listings, LFS batch negotiations —
// is not.
//
// What separates the two is in the request, not in the path: both a ref listing
// and a fetch are a POST to "<repo>/git-upload-pack" in protocol v2.
//
// The log is what an operator reads to learn who fetched a repository, so the
// question is asked the cautious way round. A request is left out only when it
// can be shown to be a ref listing (or to ask for nothing at all); every other
// upload-pack request is recorded — one that asks for objects, and equally one
// this code cannot read: an encoding it does not know, a body that is not what
// the protocol describes, a command hidden behind more preamble than is
// examined. The server may well reject such a request; then the entry says so.
// What must not exist is a way to phrase a fetch that the server understands
// and the log does not see.

// sniffLimit is how much of an upload-pack request is examined. A ref listing
// is a few hundred bytes; anything that has not shown itself to be one within
// this window is treated as a fetch.
const sniffLimit = 16 << 10

var _ backends.DownloadDescriber = (*Backend)(nil)

// DescribeDownload implements backends.DownloadDescriber. It reports a request
// that, if served, hands the client repository content:
//
//   - "POST <repo>/git-upload-pack", unless its body shows it to be a ref
//     listing or to ask for nothing (see above);
//   - "GET <repo>/info/lfs/objects/<oid>", a Git LFS object — and the HEAD for
//     it, which the content gates answer like the GET.
//
// The request body is left intact for ServeBackendHTTP: the bytes examined are
// peeked through a buffer that then stands in for the body.
func (b *Backend) DescribeDownload(r *http.Request, repoPath string) (backends.Download, bool) {
	if rawRepo, endpoint, oid, ok := splitLFSEndpoint(repoPath); ok && b.lfsEnabled() {
		if endpoint != lfsEndpointObject || (r.Method != http.MethodGet && r.Method != http.MethodHead) {
			return backends.Download{}, false
		}
		repo, err := sanitizeRepoPath(rawRepo)
		if err != nil {
			return backends.Download{}, false
		}
		d := backends.Download{Name: repo, Artifact: oid}
		if isSHA256Hex(oid) {
			d.Digest = "sha256:" + strings.ToLower(oid)
		}
		return d, true
	}

	rawRepo, endpoint, ok := splitRepoEndpoint(repoPath)
	if !ok || endpoint != endpointUploadPack || r.Method != http.MethodPost {
		return backends.Download{}, false
	}
	repo, err := sanitizeRepoPath(rawRepo)
	if err != nil {
		return backends.Download{}, false
	}
	if !requestsObjects(r) {
		return backends.Download{}, false
	}
	return backends.Download{Name: repo}, true
}

// requestsObjects reports whether an upload-pack request may hand the client
// objects: true unless the body shows it to be a ref listing or to ask for
// nothing. It peeks at the start of the body and puts a reader in its place
// that yields the body unchanged.
func requestsObjects(r *http.Request) bool {
	if r.Body == nil || r.Body == http.NoBody {
		return false
	}
	br := bufio.NewReaderSize(r.Body, sniffLimit)
	r.Body = peekedBody{Reader: br, Closer: r.Body}
	// Peek returns what there is when the body is shorter than the limit; the
	// accompanying error says why it stopped. Only a clean end of the body means
	// that what was examined is all there is.
	head, err := br.Peek(sniffLimit)
	whole := errors.Is(err, io.EOF)

	switch encoding := contentEncoding(r); encoding {
	case "", "identity":
	case "gzip", "x-gzip":
		head, whole = gunzipPrefix(head, whole)
	default:
		return true // an encoding this code cannot read
	}
	return !asksForNothingButRefs(head, whole)
}

// contentEncoding returns the request's content encoding in lower case. More
// than one encoding — repeated headers, a list — is returned as it is, which no
// caller recognizes.
func contentEncoding(r *http.Request) string {
	return strings.ToLower(strings.TrimSpace(strings.Join(r.Header.Values("Content-Encoding"), ",")))
}

// gunzipPrefix decodes as much of a gzip stream as its first bytes allow. whole
// reports whether data is the entire stream; the result is the decoded text and
// whether that is the entire decoded body. Input that cannot be decoded yields
// nothing, and not the entire body — which the caller takes for a fetch.
func gunzipPrefix(data []byte, whole bool) (plain []byte, plainWhole bool) {
	zr, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, false
	}
	// One more byte than is kept, to tell "ends here" from "goes on".
	plain, err = io.ReadAll(io.LimitReader(zr, sniffLimit+1))
	if len(plain) > sniffLimit {
		return plain[:sniffLimit], false
	}
	// ReadAll reports a clean end as no error; a stream cut off by the window —
	// or a damaged one — as an error, with what was decoded before it.
	return plain, err == nil && whole
}

// peekedBody is a request body whose first bytes have been peeked.
type peekedBody struct {
	io.Reader
	io.Closer
}

// The protocol v2 commands that hand the client no objects. "fetch" is the one
// that does; a command this list does not name is treated like it.
var refOnlyCommands = map[string]bool{
	"ls-refs":     true, // the ref listing every clone, fetch and ls-remote starts with
	"object-info": true, // object sizes
	"bundle-uri":  true, // where bundles could be downloaded — from somewhere else
}

// asksForNothingButRefs reports whether the start of an upload-pack request
// body shows the request to transfer no objects. data is the start of the
// (decoded) body and whole whether it is all of it. It answers true for
//
//   - an empty body, or one that is a lone flush-pkt: a protocol v0 request that
//     wants nothing;
//   - a protocol v2 request whose every line up to the first delimiter or flush
//     was examined, and which names exactly one command, a ref-only one.
//
// The reading is the server's: Git accepts the lines before the delimiter in
// any order (the command need not come first), strips one line feed, compares
// the command exactly, and refuses a request that names two. Anything else —
// a "want" line, a line that is not a pkt-line, a section that runs past what
// was examined — answers false.
func asksForNothingButRefs(data []byte, whole bool) bool {
	if len(data) == 0 {
		return whole
	}
	command, lines := "", 0
	for {
		if len(data) < 4 {
			return false // cut off, or not a pkt-line
		}
		var header [4]byte
		copy(header[:], data)
		length, ok := pktLength(header)
		if !ok {
			return false
		}
		switch length {
		case 0: // flush-pkt: the end of the request
			if command != "" {
				return refOnlyCommands[command]
			}
			return lines == 0 && whole && len(data) == 4
		case 1: // delim-pkt: the end of a v2 request's command and capabilities
			return command != "" && refOnlyCommands[command]
		case 2, 3: // response-end, or a length no pkt-line has
			return false
		}
		if len(data) < length {
			return false // the line runs past what was examined
		}
		payload := bytes.TrimSuffix(data[4:length], []byte("\n"))
		data = data[length:]
		lines++
		if bytes.HasPrefix(payload, []byte("want ")) {
			return false
		}
		if name, ok := bytes.CutPrefix(payload, []byte("command=")); ok {
			if command != "" {
				return false // two commands: nothing a server serves, nothing to vouch for
			}
			command = string(name)
		}
	}
}

// fetchCommand is the protocol v2 command that asks for objects.
const fetchCommand = "command=fetch"

// pktPayloadIsFetch reports whether a pkt-line payload opens a fetch: a v0/v1
// want line, or exactly the v2 fetch command (with or without its line feed) —
// not merely something that starts like it.
func pktPayloadIsFetch(payload []byte) bool {
	if bytes.HasPrefix(payload, []byte("want ")) {
		return true
	}
	return string(bytes.TrimSuffix(payload, []byte("\n"))) == fetchCommand
}

func isSHA256Hex(s string) bool {
	if len(s) != 64 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F') {
			return false
		}
	}
	return true
}

// FetchEvent describes one fetch session served over Git-over-SSH, for the
// download log. Over SSH there is no HTTP request for the gateway to observe,
// so the server reports the session itself.
type FetchEvent struct {
	// Upstream is the configured upstream name; Repo the repository path within
	// it ("octocat/Hello-World").
	Upstream string
	Repo     string
	// RemoteAddr is the SSH client's address ("host:port").
	RemoteAddr string
	// KeyFingerprint is the SHA-256 fingerprint of the public key the client
	// authenticated with; empty when client authentication is disabled.
	KeyFingerprint string
	// Bytes is how many bytes were sent to the client.
	Bytes int64
	// Duration is how long the session took.
	Duration time.Duration
	// Err is the failure, if the session did not complete.
	Err error
}

// fetchSniffer watches the client's side of a stateful upload-pack session and
// notes whether the client asked for objects. The client's stream consists of
// pkt-lines only (the pack travels the other way), so it is parsed as such;
// the moment a fetch is seen, or the stream stops looking like pkt-lines, the
// sniffer stops looking and merely passes bytes through.
//
// In protocol v2 one session carries several commands — typically a ref listing
// followed by a fetch — so every pkt-line is examined, not only the first.
type fetchSniffer struct {
	r io.Reader

	fetch bool
	done  bool
	// header collects the 4-byte length prefix of the current pkt-line.
	header [4]byte
	have   int
	// remaining is how many payload bytes of the current pkt-line are still to
	// come and size its total payload length; prefix collects its first bytes.
	remaining int
	size      int
	prefix    []byte
}

// maxFetchPrefix is how much of a payload has to be kept to recognize a fetch:
// the v2 command with its line feed. (A want line is recognized by its first
// five bytes.)
const maxFetchPrefix = len(fetchCommand) + 1

func (s *fetchSniffer) Read(p []byte) (int, error) {
	n, err := s.r.Read(p)
	if n > 0 && !s.done {
		s.scan(p[:n])
	}
	return n, err
}

func (s *fetchSniffer) scan(data []byte) {
	for len(data) > 0 && !s.done {
		if s.remaining == 0 {
			// Reading a length prefix.
			take := min(4-s.have, len(data))
			copy(s.header[s.have:], data[:take])
			s.have += take
			data = data[take:]
			if s.have < 4 {
				return
			}
			s.have = 0
			length, ok := pktLength(s.header)
			switch {
			case !ok:
				s.done = true // not a pkt-line stream after all
			case length <= 4:
				// flush / delim / response-end: no payload.
			default:
				s.remaining = length - 4
				s.size = s.remaining
				s.prefix = s.prefix[:0]
			}
			continue
		}
		take := min(s.remaining, len(data))
		if room := maxFetchPrefix - len(s.prefix); room > 0 {
			s.prefix = append(s.prefix, data[:min(room, take)]...)
		}
		s.remaining -= take
		data = data[take:]
		if s.remaining > 0 {
			continue
		}
		// The payload is complete. prefix holds all of it when it is short
		// enough to be the fetch command; a want line is judged by its start.
		if bytes.HasPrefix(s.prefix, []byte("want ")) || (s.size <= maxFetchPrefix && pktPayloadIsFetch(s.prefix)) {
			s.fetch = true
			s.done = true
		}
	}
}

// pktLength decodes a pkt-line length prefix (four hex digits).
func pktLength(header [4]byte) (int, bool) {
	n := 0
	for _, c := range header {
		var v int
		switch {
		case c >= '0' && c <= '9':
			v = int(c - '0')
		case c >= 'a' && c <= 'f':
			v = int(c-'a') + 10
		case c >= 'A' && c <= 'F':
			v = int(c-'A') + 10
		default:
			return 0, false
		}
		n = n<<4 | v
	}
	return n, true
}

// countingWriter counts the bytes written through it.
type countingWriter struct {
	w io.Writer
	n int64
}

func (c *countingWriter) Write(p []byte) (int, error) {
	n, err := c.w.Write(p)
	c.n += int64(n)
	return n, err
}
