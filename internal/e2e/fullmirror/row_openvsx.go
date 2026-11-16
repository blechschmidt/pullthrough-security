//go:build integration
// +build integration

package fullmirror

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"
)

// Open VSX: the adapter follows openvsx-server's sitemap, /sitemap.xml — a
// <url> per extension, "…/extension/<namespace>/<name>", with the UTC date of
// its newest version as <lastmod> — and the search listing of extensions by
// the time their newest version was published, newest first
// (/api/-/search?sortBy=timestamp&sortOrder=desc), read at every poll; it
// diffs the extensions against a stored copy and reports each one that is new
// or whose date (or time in the listing) moved. Each extension's newest
// version and the platforms it is built for come from its document,
// /api/<namespace>/<name>, read through the proxy; its versions from each
// such platform's version listing, /api/<namespace>/<name>/<platform>/versions;
// each version is mirrored as one .vsix per platform.
//
// The LLM package-scan suite's registry serves a version's document and its
// archive (with the .sha256 the backend verifies it against). The stub serves
// the rest in front, as openvsx-server answers: the sitemap — without
// validators, as open-vsx.org sends none (every poll reads it whole), and
// compressed with gzip when the client accepts it; the search listing; the
// version listings; and the extension's document, which is its newest
// version's: the registry's document of the version with the downloads by
// platform and the downloadable flag openvsx-server adds. The registry's
// document is dated with the suite's fixed date; the stub dates the document —
// at /api/<namespace>/<name>, /api/<namespace>/<name>/<version> and
// /api/<namespace>/<name>/universal/<version>, where the version listing
// points — with the publication, as the listing and the sitemap date it. Each
// fixture extension is built for every platform (universal), so its one
// version has one archive.

func init() {
	register(row{
		Type:    "openvsx",
		Feed:    "`/sitemap.xml` (no validators, gzip), the search listing by time, the extension's document and its platforms' version listings",
		Start:   openvsxFeedStart,
		Options: func(*feedEnv) map[string]string { return nil },
		Resumed: openvsxResumed,
	})
}

// openvsxDocument is the document of an extension's version as openvsx-server
// serves it: the stub registry's, dated with the publication, with the
// archive by platform and the downloadable flag.
func openvsxDocument(env *feedEnv, p publication) (map[string]any, error) {
	ns, ext, ok := strings.Cut(p.Pkg.Name, ".")
	if !ok {
		return nil, fmt.Errorf("%q is not an extension's identifier (<namespace>.<name>)", p.Pkg.Name)
	}
	raw, err := env.fetch("/api/" + ns + "/" + ext + "/" + p.Pkg.Version)
	if err != nil {
		return nil, err
	}
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("the stub registry's document of %s %s: %w", p.Pkg.Name, p.Pkg.Version, err)
	}
	files, _ := doc["files"].(map[string]any)
	download, _ := files["download"].(string)
	if download == "" || doc["targetPlatform"] != "universal" {
		return nil, fmt.Errorf("the stub registry's document of %s %s names no universal archive", p.Pkg.Name, p.Pkg.Version)
	}
	doc["timestamp"] = openvsxTimestamp(p)
	doc["downloads"] = map[string]any{"universal": download}
	doc["downloadable"] = true
	return doc, nil
}

// openvsxTimestamp is a version's time as openvsx-server writes it: UTC, to
// the microsecond.
func openvsxTimestamp(p publication) string {
	return p.Time.UTC().Format("2006-01-02T15:04:05.000000Z")
}

// openvsxPublished returns the publication of the extension ns.ext (with
// version, when not empty).
func openvsxPublished(env *feedEnv, ns, ext, version string) (publication, bool) {
	for _, p := range env.Publications() {
		if p.Pkg.Name == ns+"."+ext && (version == "" || p.Pkg.Version == version) {
			return p, true
		}
	}
	return publication{}, false
}

// openvsxError answers as openvsx-server does when it refuses a request or
// has no such extension.
func openvsxError(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	body, _ := json.Marshal(map[string]string{"error": msg})
	_, _ = w.Write(body)
}

// openvsxPaging reads a listing's size and offset.
func openvsxPaging(r *http.Request, defaultSize int) (size, offset int, ok bool) {
	size, offset = defaultSize, 0
	q := r.URL.Query()
	if v := q.Get("size"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 0 {
			return 0, 0, false
		}
		size = n
	}
	if v := q.Get("offset"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 0 {
			return 0, 0, false
		}
		offset = n
	}
	return size, offset, true
}

func openvsxFeedStart(env *feedEnv) error {
	for _, p := range env.Publications() {
		if _, err := openvsxDocument(env, p); err != nil {
			return err
		}
	}
	env.Stub.Handle("/sitemap.xml", func(w http.ResponseWriter, r *http.Request) {
		var b bytes.Buffer
		b.WriteString(`<?xml version="1.0" encoding="UTF-8"?><urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">` + "\n")
		for _, p := range env.Publications() {
			ns, ext, _ := strings.Cut(p.Pkg.Name, ".")
			b.WriteString("  <url>\n    <loc>")
			_ = xml.EscapeText(&b, []byte(env.URL()+"/extension/"+ns+"/"+ext))
			b.WriteString("</loc>\n    <lastmod>" + p.Time.UTC().Format("2006-01-02") + "</lastmod>\n  </url>\n")
		}
		b.WriteString("</urlset>\n")
		body := b.Bytes()
		w.Header().Set("Content-Type", "application/xml")
		w.Header().Set("Cache-Control", "public, max-age=600")
		w.Header().Set("Vary", "Accept-Encoding")
		if strings.Contains(r.Header.Get("Accept-Encoding"), "gzip") {
			var gz bytes.Buffer
			zw := gzip.NewWriter(&gz)
			_, _ = zw.Write(body)
			_ = zw.Close()
			body = gz.Bytes()
			w.Header().Set("Content-Encoding", "gzip")
		}
		w.Header().Set("Content-Length", strconv.Itoa(len(body)))
		if r.Method != http.MethodHead {
			_, _ = w.Write(body)
		}
	})
	env.Stub.Handle("/api/-/search", func(w http.ResponseWriter, r *http.Request) {
		// The stub orders the listing by time only, the order the adapter
		// reads: another order is refused rather than answered wrongly.
		q := r.URL.Query()
		if q.Get("sortBy") != "timestamp" || (q.Get("sortOrder") != "" && q.Get("sortOrder") != "desc" && q.Get("sortOrder") != "asc") ||
			q.Get("query") != "" || q.Get("category") != "" || q.Get("targetPlatform") != "" {
			openvsxError(w, http.StatusBadRequest, "the stub registry lists extensions by timestamp only")
			return
		}
		size, offset, ok := openvsxPaging(r, 18)
		if !ok {
			openvsxError(w, http.StatusBadRequest, "The parameters 'size' and 'offset' must not be negative.")
			return
		}
		pubs := env.Publications()
		// Newest first; of two published at one instant, the one published
		// later.
		sort.SliceStable(pubs, func(i, j int) bool {
			if !pubs[i].Time.Equal(pubs[j].Time) {
				return pubs[i].Time.After(pubs[j].Time)
			}
			return pubs[i].Seq > pubs[j].Seq
		})
		if q.Get("sortOrder") == "asc" {
			for i, j := 0, len(pubs)-1; i < j; i, j = i+1, j-1 {
				pubs[i], pubs[j] = pubs[j], pubs[i]
			}
		}
		entries := []map[string]any{}
		for i, p := range pubs {
			if i < offset || len(entries) >= size {
				continue
			}
			doc, err := openvsxDocument(env, p)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			ns, ext, _ := strings.Cut(p.Pkg.Name, ".")
			files, _ := doc["files"].(map[string]any)
			entries = append(entries, map[string]any{
				"url":   env.URL() + "/api/" + ns + "/" + ext,
				"files": map[string]any{"download": files["download"], "sha256": files["sha256"]},
				"name":  ext, "namespace": ns, "version": p.Pkg.Version, "timestamp": doc["timestamp"],
				"verified": false, "downloadCount": 0, "displayName": doc["displayName"], "description": doc["description"], "deprecated": false,
			})
		}
		writeJSON(w, map[string]any{"offset": offset, "totalSize": len(pubs), "extensions": entries})
	})
	env.Stub.Fallback(func(w http.ResponseWriter, r *http.Request) bool {
		rest, ok := strings.CutPrefix(r.URL.Path, "/api/")
		if !ok || strings.HasPrefix(rest, "-/") {
			return false
		}
		segs := strings.Split(rest, "/")
		switch {
		case len(segs) == 2:
			// The extension's document: its newest (here: only) version's.
			return openvsxServeDocument(env, w, segs[0], segs[1], "")
		case len(segs) == 3:
			return openvsxServeDocument(env, w, segs[0], segs[1], segs[2])
		case len(segs) == 4 && segs[3] == "versions":
			p, ok := openvsxPublished(env, segs[0], segs[1], "")
			if !ok {
				openvsxError(w, http.StatusNotFound, "Extension not found: "+segs[0]+"."+segs[1])
				return true
			}
			size, offset, ok := openvsxPaging(r, 100)
			if !ok {
				openvsxError(w, http.StatusBadRequest, "The parameters 'size' and 'offset' must not be negative.")
				return true
			}
			// Built for every platform, the extension has its versions
			// under universal and none under a single platform.
			versions := map[string]string{}
			total := 0
			if segs[2] == "universal" {
				total = 1
				if offset == 0 && size > 0 {
					versions[p.Pkg.Version] = env.URL() + "/api/" + segs[0] + "/" + segs[1] + "/universal/" + p.Pkg.Version
				}
			}
			writeJSON(w, map[string]any{"offset": offset, "totalSize": total, "versions": versions})
			return true
		case len(segs) == 4 && segs[2] == "universal":
			return openvsxServeDocument(env, w, segs[0], segs[1], segs[3])
		}
		return false
	})
	return nil
}

// openvsxServeDocument answers with the document of an extension's version
// (its newest for version ""). A version the stub has not published is left
// to the registry.
func openvsxServeDocument(env *feedEnv, w http.ResponseWriter, ns, ext, version string) bool {
	p, ok := openvsxPublished(env, ns, ext, version)
	if !ok {
		if version != "" {
			return false
		}
		openvsxError(w, http.StatusNotFound, "Extension not found: "+ns+"."+ext)
		return true
	}
	doc, err := openvsxDocument(env, p)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return true
	}
	writeJSON(w, doc)
	return true
}

// openvsxResumed: the restarted mirror diffed the sitemap against the copy it
// had stored. The adapter reads an extension's version listings for every
// extension it is told of — every one when it enumerates the registry — so
// after the restart it read the late extension's alone.
//
// It also read the search listing by time, as it does at every poll, and was
// answered with it. The adapter swallows a listing it cannot read (the
// sitemap alone then tells it what changed, a day's second publication
// excepted), so nothing else would show the listing going unread: the stub
// answers a listing in another order than the adapter's with 400.
func openvsxResumed(env *feedEnv, requests []string) error {
	late, ok := env.Publication(pkgLate)
	if !ok {
		return fmt.Errorf("the late extension was not published")
	}
	ns, ext, _ := strings.Cut(late.Pkg.Name, ".")
	want := "/api/" + ns + "/" + ext + "/universal/versions"
	sitemap, listed, searched := false, false, false
	for _, line := range requests {
		path := requestPath(line)
		switch {
		case path == "/sitemap.xml":
			sitemap = true
		case path == want:
			listed = true
		case path == "/api/-/search":
			if !strings.HasSuffix(line, "-> 200") {
				return fmt.Errorf("the restarted mirror's read of the search listing by time was not answered with it: %s", line)
			}
			searched = true
		case strings.HasPrefix(path, "/api/") && strings.HasSuffix(path, "/versions"):
			return fmt.Errorf("the restarted mirror read the version listing of an extension it had mirrored: %s", line)
		}
	}
	switch {
	case !sitemap:
		return fmt.Errorf("the sitemap was not read after the restart")
	case !searched:
		return fmt.Errorf("the search listing by time (/api/-/search) was not read after the restart")
	case !listed:
		return fmt.Errorf("the late extension's version listing (%s) was not read after the restart", want)
	}
	return nil
}
