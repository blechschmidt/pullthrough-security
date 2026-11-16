//go:build integration
// +build integration

package fullmirror

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/xml"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Dart: the adapter follows pub.dev's Atom feed of the newest versions,
// /feed.atom, down to its high-water mark (listfeed.go), and reports the
// package of every version it has not seen; where the feed does not reach
// back to ten minutes below the mark, the pass goes on through the live
// listing of packages by last publication, /packages.json?page=N, reporting
// what the feed does not name. Bootstrap takes the mark from the feed, then
// lists every name of /api/package-names and of the feed. A package's versions
// come from its document, /api/packages/<name>, read through the proxy.
//
// The stub serves all three as pub.dev does: the feed lists every version the
// registry published (pub.dev's holds the newest hundred; the registry has
// four), newest first, each entry "v<version> of <package>" with the time of
// its publication; the listing names every package, 50 a page, most recently
// published first, by the URL of its JSON document; the name list is gzip-
// compressed, and refused (406) to a client that does not accept gzip. The
// package documents and archives are the LLM package-scan suite's registry's.
// (Those documents state an older publication time; the mirror decides
// nothing on it: the listing pass reads a document's time only for a package
// the feed does not name.) The upstream is not pub.dev, so feed option url
// names the stub as the site whose feed and listings are read; settle zero.
//
// The feed dates the seed's version two days back (dartSeedAge), the way
// pub.dev's feed reaches back hours: it then covers the 35 minutes in which
// pub.dev's instances may list a package in different places, and the adapter
// reads the registry in its normal state, not as a burst. The enumeration and
// the first poll, whose mark is the seed's own time, look in the listing (one
// page) for what the feed might not reach; after the restart the pass ends
// inside the feed, at the seed, more than ten minutes below the stored mark,
// and reads no listing — which dartResumed requires. Two days back, the seed
// also lies below the window in which the versions the adapter has seen are
// remembered whatever its mark says: a restarted adapter that lost its mark
// would report it again — reading the listing and the seed's document, which
// dartResumed refuses, and finding its archive cached (skipped), which the
// suite counts.
// A registry younger than those 35 minutes, whose feed covers none of them,
// is followed through the listing's one page instead: the unit test
// TestDartYoungRegistryIsNotABurst (internal/fullmirror) covers that.

func init() {
	register(row{
		Type:  "dart",
		Feed:  "pub.dev's `/feed.atom` (newest versions), `/packages.json?page=N` (by last publication) and `/api/package-names` (gzip only)",
		Start: dartFeedStart,
		Options: func(env *feedEnv) map[string]string {
			return map[string]string{"url": env.URL(), "settle": "0s"}
		},
		Resumed: dartResumed,
		Notes: []string{
			"a registry younger than the 35 minutes the feed must cover (read through a one-page listing) is not this row's: the unit test TestDartYoungRegistryIsNotABurst covers it",
			"the listing is read on its one page, by the enumeration and the first poll, and names nothing the feed does not: later pages, the checks of their boundaries and the boundaries kept for a second look are not covered",
			"settle is zero, and every package has one version, none retracted: holding back young versions, the yanked mark and a new version of a known package are not covered",
		},
	})
}

// dartSeedAge is how long before its publication the feed dates the seed's
// version: beyond the 35 minutes the feed must cover (dartListingSettle) and
// the ten minutes below the mark the adapter looks back over
// (listingLookback), both in internal/fullmirror.
const dartSeedAge = 48 * time.Hour

// dartListedAt is when the feed says a version was published: when it was,
// the seed two days earlier.
func dartListedAt(p publication) time.Time {
	if p.Variant == pkgSeed {
		return p.Time.Add(-dartSeedAge)
	}
	return p.Time
}

// dartNewestFirst sorts publications by the time the feed states, newest
// first; of two of one instant, the one published later first.
func dartNewestFirst(pubs []publication) {
	sort.SliceStable(pubs, func(i, j int) bool {
		if ti, tj := dartListedAt(pubs[i]), dartListedAt(pubs[j]); !ti.Equal(tj) {
			return ti.After(tj)
		}
		return pubs[i].Seq > pubs[j].Seq
	})
}

// dartTime spells the time the feed states for a version the way pub.dev's
// feed does.
func dartTime(p publication) string {
	return dartListedAt(p).UTC().Format("2006-01-02T15:04:05.000000Z07:00")
}

// dartEntryID is the UUID of a version's entry in the feed.
func dartEntryID(p publication) string {
	sum := sha256.Sum256([]byte("pte2e-feed\x00" + p.Pkg.Name + "@" + p.Pkg.Version))
	h := fmt.Sprintf("%x", sum[:16])
	return "urn:uuid:" + h[:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:32]
}

// dartEscape escapes text for the feed's markup.
func dartEscape(s string) string {
	var b bytes.Buffer
	_ = xml.EscapeText(&b, []byte(s))
	return b.String()
}

func dartFeedStart(env *feedEnv) error {
	base := env.URL()
	env.Stub.Handle("/feed.atom", func(w http.ResponseWriter, r *http.Request) {
		pubs := env.Publications()
		dartNewestFirst(pubs)
		if len(pubs) > 100 {
			pubs = pubs[:100]
		}
		var b strings.Builder
		b.WriteString(`<?xml version="1.0" encoding="UTF-8"?>` + "\n")
		b.WriteString(`<feed xmlns="http://www.w3.org/2005/Atom"><id>` + dartEscape(base+"/feed.atom") + `</id><title>Recently published packages on pub.dev</title>`)
		if len(pubs) > 0 {
			b.WriteString(`<updated>` + dartTime(pubs[0]) + `</updated>`)
		}
		b.WriteString(`<link href="` + dartEscape(base+"/") + `" rel="alternate"/><link href="` + dartEscape(base+"/feed.atom") + `" rel="self"/><generator version="0.1.0">Pub Feed Generator</generator>`)
		for _, p := range pubs {
			name := dartEscape(p.Pkg.Name)
			b.WriteString(`<entry><id>` + dartEntryID(p) + `</id><title>v` + dartEscape(p.Pkg.Version) + ` of ` + name + `</title><updated>` + dartTime(p) + `</updated>`)
			b.WriteString(`<author><name>pte2e.example</name></author><content>pkgscan e2e fixture package.</content>`)
			b.WriteString(`<link href="` + dartEscape(base+"/packages/"+p.Pkg.Name) + `" rel="alternate" title="` + name + `"/></entry>`)
		}
		b.WriteString(`</feed>`)
		w.Header().Set("Content-Type", "application/atom+xml; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		_, _ = w.Write([]byte(b.String()))
	})
	env.Stub.Handle("/packages.json", func(w http.ResponseWriter, r *http.Request) {
		page := 1
		if v := r.URL.Query().Get("page"); v != "" {
			n, err := strconv.Atoi(v)
			if err != nil || n < 1 {
				http.Error(w, `{"error":{"code":"InvalidInput","message":"page must be a positive integer"}}`, http.StatusBadRequest)
				return
			}
			page = n
		}
		const size = 50
		pubs := env.Publications()
		dartNewestFirst(pubs)
		// One entry a package, at its newest publication.
		var names []string
		seen := map[string]bool{}
		for _, p := range pubs {
			if !seen[p.Pkg.Name] {
				seen[p.Pkg.Name] = true
				names = append(names, p.Pkg.Name)
			}
		}
		urls := []string{}
		for i := (page - 1) * size; i < len(names) && i < page*size; i++ {
			urls = append(urls, base+"/packages/"+names[i]+".json")
		}
		var next any
		if page*size < len(names) {
			next = base + "/packages.json?page=" + strconv.Itoa(page+1)
		}
		writeJSON(w, map[string]any{"packages": urls, "next": next})
	})
	env.Stub.Handle("/api/package-names", func(w http.ResponseWriter, r *http.Request) {
		if !strings.Contains(r.Header.Get("Accept-Encoding"), "gzip") {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusNotAcceptable)
			_, _ = w.Write([]byte(`{"error":{"code":"NotAcceptable","message":"Client must accept gzip content."}}`))
			return
		}
		names := []string{}
		seen := map[string]bool{}
		for _, p := range env.Publications() {
			if !seen[p.Pkg.Name] {
				seen[p.Pkg.Name] = true
				names = append(names, p.Pkg.Name)
			}
		}
		sort.Strings(names)
		var raw bytes.Buffer
		zw := gzip.NewWriter(&raw)
		_, _ = fmt.Fprintf(zw, `{"packages":%s,"nextUrl":null}`, dartJSONList(names))
		_ = zw.Close()
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.Header().Set("Content-Encoding", "gzip")
		_, _ = w.Write(raw.Bytes())
	})
	return nil
}

// dartJSONList renders names as a JSON array of strings (the names are
// letters, digits and underscores).
func dartJSONList(names []string) string {
	quoted := make([]string, len(names))
	for i, n := range names {
		quoted[i] = strconv.Quote(n)
	}
	return "[" + strings.Join(quoted, ",") + "]"
}

// dartResumed: the restarted mirror continued from the stored mark through
// the feed alone — the feed reaches below the mark's ten minutes, so the pass
// ends inside it, reading neither the listing nor the name list — and read
// the document of the late package alone: the versions it had seen before the
// restart were remembered with the mark.
func dartResumed(env *feedEnv, requests []string) error {
	late, _ := env.Publication(pkgLate)
	read := false
	for _, line := range requests {
		u, err := url.Parse(requestURI(line))
		if err != nil {
			return err
		}
		switch {
		case u.Path == "/api/package-names":
			return fmt.Errorf("the registry was enumerated again: %s", line)
		case u.Path == "/packages.json":
			return fmt.Errorf("the pass read the listing, though the feed reaches below the stored mark: %s", line)
		case u.Path == "/feed.atom":
			read = true
		case strings.HasPrefix(u.Path, "/api/packages/") && u.Path != "/api/packages/"+late.Pkg.Name:
			return fmt.Errorf("a package mirrored before the restart was reported again: %s", line)
		}
	}
	if !read {
		return fmt.Errorf("the feed was not read")
	}
	return nil
}
