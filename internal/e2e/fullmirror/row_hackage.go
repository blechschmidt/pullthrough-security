//go:build integration
// +build integration

package fullmirror

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"html"
	"io"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"
)

// Hackage: the adapter follows the repository's incremental index,
// 01-index.tar — a tar archive of every package description ever uploaded,
// appended in upload order and never rewritten — the way hackage-security
// updates cabal-install's copy. Bootstrap takes the index's end (a HEAD for
// its length, a Range request for its last bytes) and lists every package
// name from /packages/ (JSON); Changes asks, with a Range request, for the
// index from the last entry it read on, checks that entry's header against the
// hash it stored, and reports each package.json entry after it as an upload.
// Each package's versions come from /package/<name>/preferred (JSON), read
// from the repository, and each version is mirrored as its sdist,
// /package/<name>-<version>.tar.gz.
//
// The LLM package-scan suite's registry serves the index compressed only
// (01-index.tar.gz, what `cabal update` downloads first) — no file a client can
// follow by Range — with every entry dated alike. So the stub serves, in front
// of it, the index as hackage-server writes it: for each upload, in the order
// of publication, its package.json — byte for byte the TUF target metadata the
// registry serves at /package/<name>-<version>/package.json, against which the
// proxy verifies the sdist — and then its .cabal file, both dated with the
// time of the upload, followed by the two zero blocks that end a tar archive
// and that the next upload's entries overwrite. 01-index.tar.gz is the same
// archive compressed. Beside them, /packages/ and /package/<name>/preferred
// answer in JSON when asked for it, in HTML otherwise (hackage-server
// negotiates both), and name exactly the packages published.

func init() {
	register(row{
		Type:    "hackage",
		Feed:    "the incremental index `01-index.tar` (appended per upload; HEAD, Range), `/packages/`, `/package/<name>/preferred`",
		Start:   hackageFeedStart,
		Options: func(*feedEnv) map[string]string { return nil },
		Resumed: hackageResumed,
	})
}

// The owner of the index's entries: hackage-server writes a package.json as
// its own user, a .cabal file as the user who uploaded it.
const (
	hackageServerUser = "Hackage"
	hackageUploader   = "pte2e"
	hackageUploaderID = 4900
)

// hackageIndexReads keeps, for the row's Resumed, the reads of 01-index.tar.
type hackageIndexReads struct {
	mu    sync.Mutex
	reads []hackageIndexRead
}

// hackageIndexRead is one read of the index: its method and Range, and how
// many packages were published when it came.
type hackageIndexRead struct {
	published           int
	method, rangeHeader string
}

func hackageFeedStart(env *feedEnv) error {
	reads := &hackageIndexReads{}
	env.set("index-reads", reads)
	if _, _, err := hackageIndex(env, env.Publications()); err != nil {
		return err
	}
	env.Stub.Handle("/01-index.tar", func(w http.ResponseWriter, r *http.Request) {
		pubs := env.Publications()
		index, _, err := hackageIndex(env, pubs)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		reads.mu.Lock()
		reads.reads = append(reads.reads, hackageIndexRead{published: len(pubs), method: r.Method, rangeHeader: r.Header.Get("Range")})
		reads.mu.Unlock()
		hackageServeIndex(w, r, pubs, index, "application/x-tar")
	})
	env.Stub.Handle("/01-index.tar.gz", func(w http.ResponseWriter, r *http.Request) {
		pubs := env.Publications()
		index, _, err := hackageIndex(env, pubs)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		var gz bytes.Buffer
		zw := gzip.NewWriter(&gz)
		_, _ = zw.Write(index)
		_ = zw.Close()
		hackageServeIndex(w, r, pubs, gz.Bytes(), "application/gzip")
	})
	env.Stub.Handle("/packages/", func(w http.ResponseWriter, r *http.Request) {
		var names []string
		for _, p := range env.Publications() {
			names = append(names, p.Pkg.Name)
		}
		sort.Strings(names)
		if !hackageWantsJSON(r) {
			var b strings.Builder
			b.WriteString("<!DOCTYPE html>\n<html><head><title>Packages | Hackage</title></head><body><ul>\n")
			for _, n := range names {
				fmt.Fprintf(&b, "<li><a href=\"/package/%s\">%s</a></li>\n", html.EscapeString(n), html.EscapeString(n))
			}
			b.WriteString("</ul></body></html>\n")
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			_, _ = io.WriteString(w, b.String())
			return
		}
		list := make([]map[string]string, 0, len(names))
		for _, n := range names {
			list = append(list, map[string]string{"packageName": n})
		}
		writeJSON(w, list)
	})
	env.Stub.Fallback(func(w http.ResponseWriter, r *http.Request) bool {
		rest, ok := strings.CutPrefix(r.URL.Path, "/package/")
		if !ok {
			return false
		}
		name, ok := strings.CutSuffix(rest, "/preferred")
		if !ok || name == "" || strings.Contains(name, "/") {
			return false
		}
		var versions []string
		for _, p := range env.Publications() {
			if p.Pkg.Name == name {
				versions = append(versions, p.Pkg.Version)
			}
		}
		if len(versions) == 0 {
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			w.WriteHeader(http.StatusNotFound)
			_, _ = io.WriteString(w, "Package not found: No such package in package index")
			return true
		}
		if !hackageWantsJSON(r) {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			fmt.Fprintf(w, "<!DOCTYPE html>\n<html><head><title>Preferred versions | Hackage</title></head><body><h2>%s</h2><p>Normal versions: %s</p></body></html>\n",
				html.EscapeString(name), html.EscapeString(strings.Join(versions, ", ")))
			return true
		}
		// Hackage lists a package's versions newest first, the deprecated
		// ones under "deprecated-version" when there are any; each fixture
		// package has one version, which is not deprecated.
		writeJSON(w, map[string][]string{"normal-version": versions})
		return true
	})
	return nil
}

// hackageWantsJSON reports whether a request asks for JSON: hackage-server
// answers its HTML page otherwise.
func hackageWantsJSON(r *http.Request) bool {
	return strings.Contains(r.Header.Get("Accept"), "application/json")
}

// hackageServeIndex serves the index as a file: HEAD, Range (a range beyond
// its end is answered 416), conditional requests, dated by the newest upload.
func hackageServeIndex(w http.ResponseWriter, r *http.Request, pubs []publication, body []byte, contentType string) {
	var modTime time.Time
	for _, p := range pubs {
		if p.Time.After(modTime) {
			modTime = p.Time
		}
	}
	sum := sha256.Sum256(body)
	w.Header().Set("Content-Type", contentType)
	w.Header().Set("ETag", `"`+hex.EncodeToString(sum[:12])+`"`)
	http.ServeContent(w, r, "", modTime.UTC().Truncate(time.Second), bytes.NewReader(body))
}

// hackageIndex builds 01-index.tar for the packages published, in the order
// of publication, and returns it with the offsets of its entries' headers.
// The index of more packages begins with the index of fewer: every entry is
// derived from its own package, dated with its own publication.
func hackageIndex(env *feedEnv, pubs []publication) ([]byte, []int64, error) {
	cabals, err := hackageCabals(env)
	if err != nil {
		return nil, nil, err
	}
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	var headers []int64
	for _, p := range pubs {
		name, version := p.Pkg.Name, p.Pkg.Version
		targets, err := env.fetch("/package/" + name + "-" + version + "/package.json")
		if err != nil {
			return nil, nil, err
		}
		cabalPath := name + "/" + version + "/" + name + ".cabal"
		cabal, ok := cabals[cabalPath]
		if !ok {
			return nil, nil, fmt.Errorf("the stub registry's 01-index.tar.gz has no %s", cabalPath)
		}
		for _, e := range []struct {
			path  string
			body  []byte
			user  string
			uid   int
			mtime time.Time
		}{
			{name + "/" + version + "/package.json", targets, hackageServerUser, 0, p.Time},
			{cabalPath, cabal, hackageUploader, hackageUploaderID, p.Time},
		} {
			if err := tw.Flush(); err != nil {
				return nil, nil, err
			}
			headers = append(headers, int64(buf.Len()))
			hdr := &tar.Header{
				Typeflag: tar.TypeReg, Name: e.path, Mode: 0o644, Size: int64(len(e.body)),
				ModTime: e.mtime.UTC().Truncate(time.Second), Uid: e.uid, Uname: e.user, Gname: hackageServerUser,
				Format: tar.FormatUSTAR,
			}
			if err := tw.WriteHeader(hdr); err != nil {
				return nil, nil, err
			}
			if _, err := tw.Write(e.body); err != nil {
				return nil, nil, err
			}
		}
	}
	if err := tw.Close(); err != nil { // the two zero blocks that end the archive
		return nil, nil, err
	}
	return buf.Bytes(), headers, nil
}

// hackageCabals reads the .cabal files of the stub registry's own index,
// 01-index.tar.gz, by their paths in it ("<name>/<version>/<name>.cabal").
func hackageCabals(env *feedEnv) (map[string][]byte, error) {
	gz, err := env.fetch("/01-index.tar.gz")
	if err != nil {
		return nil, err
	}
	zr, err := gzip.NewReader(bytes.NewReader(gz))
	if err != nil {
		return nil, fmt.Errorf("the stub registry's 01-index.tar.gz: %w", err)
	}
	out := map[string][]byte{}
	tr := tar.NewReader(zr)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			return out, nil
		}
		if err != nil {
			return nil, fmt.Errorf("the stub registry's 01-index.tar.gz: %w", err)
		}
		if !strings.HasSuffix(hdr.Name, ".cabal") {
			continue
		}
		body, err := io.ReadAll(tr)
		if err != nil {
			return nil, err
		}
		out[hdr.Name] = body
	}
}

// hackageResumed: the restarted mirror asked for the index from the header of
// the last entry it had read — the malicious package's .cabal file, where the
// index ended before the late upload — and neither took the index's end again
// (a HEAD) nor listed the packages.
func hackageResumed(env *feedEnv, requests []string) error {
	for _, line := range requests {
		if requestPath(line) == "/packages/" {
			return fmt.Errorf("the packages were listed again: %s", line)
		}
	}
	pubs := env.Publications()
	if len(pubs) != 4 {
		return fmt.Errorf("%d packages published, want 4", len(pubs))
	}
	_, headers, err := hackageIndex(env, pubs[:3])
	if err != nil {
		return err
	}
	want := fmt.Sprintf("bytes=%d-", headers[len(headers)-1])
	reads := env.get("index-reads").(*hackageIndexReads)
	reads.mu.Lock()
	defer reads.mu.Unlock()
	for _, rd := range reads.reads {
		// The late package was published while the proxy was stopped: a read
		// that came after it came from the restarted proxy.
		if rd.published < len(pubs) {
			continue
		}
		if rd.method != http.MethodGet || !strings.HasPrefix(rd.rangeHeader, want) {
			return fmt.Errorf("the first read of 01-index.tar after the restart was %s with Range %q, want a GET with Range %s… (the header of the last entry read before the restart)", rd.method, rd.rangeHeader, want)
		}
		return nil
	}
	return fmt.Errorf("01-index.tar was not read after the restart")
}
