//go:build integration
// +build integration

package fullmirror

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strconv"
)

// Composer: the adapter follows Packagist's metadata change log,
// `metadata/changes.json?since=<t>` with t in 1/10000 s: Bootstrap asks it
// without since — Packagist answers 400 with the position to start from —
// then lists every package with `packages/list.json` and continues the log
// from a little before that position; every poll after that reads the
// actions since the position the last answer named. Each package's versions
// come from its v2 metadata, `/p2/<vendor>/<package>.json`, read through the
// proxy once a HEAD request shows a Last-Modified no older than the update
// the log named.
//
// The stub serves the log and the list at its root, as packagist.org does
// (feed option url: a Packagist-compatible site), computed from the
// publications at request time the way Packagist answers from its sorted
// sets of metadata dumps: a package's dump is an `update` action at the time
// it was published, `since` is inclusive, `timestamp` is one past the newest
// dump, a request without a valid since is answered 400 with that timestamp,
// and one more than 24 hours old with a `resync`.
//
// Packagist's metadata files are served with the time they were dumped as
// their Last-Modified — the time the log's update action names. The LLM
// package-scan suite's registry serves every file with one fixed date in
// 2024, which would tell a mirror the document predates its update: the
// adapter takes it for a CDN copy that has not caught up yet and retries the
// read, backing the upstream off, until after three rounds the engine gives
// the package up as a package error. So the stub serves each package's /p2/
// document in front of the registry, the registry's bytes with the dump's
// Last-Modified. The dist archives are the registry's own.

func init() {
	register(row{
		Type:  "composer",
		Feed:  "Packagist's `metadata/changes.json?since=` and `packages/list.json`; `/p2/` documents with the dump's Last-Modified",
		Start: composerFeedStart,
		Options: func(env *feedEnv) map[string]string {
			return map[string]string{"url": env.URL()}
		},
		Resumed:    composerResumed,
		Rereported: []string{pkgSeed},
		Notes: []string{
			"the adapter continues the change log from 15 minutes before the position it enumerated at (composerStartMargin): " +
				"its first poll reports the seed again, which the mirror finds in the cache (skipped: cached)",
			"no `~dev` documents: the fixture packages have no dev branches",
		},
	})
}

// composerMinSince is the lowest since Packagist accepts (its log began in
// 2020): anything lower is answered as a request without since.
const composerMinSince = 15850612240000

// composerLogKept is how far back Packagist's change log reaches, in its
// units: 24 hours.
const composerLogKept = 24 * 3600 * 10000

// composerPosition is a time as a position in the change log: 1/10000 s.
func composerPosition(p publication) int64 { return p.Time.UnixNano() / 100_000 }

func composerFeedStart(env *feedEnv) error {
	env.Stub.Handle("/metadata/changes.json", func(w http.ResponseWriter, r *http.Request) {
		pubs := env.Publications()
		now := int64(0)
		for _, p := range pubs {
			if pos := composerPosition(p) + 1; pos > now {
				now = pos
			}
		}
		since, err := strconv.ParseInt(r.URL.Query().Get("since"), 10, 64)
		if err != nil || since < composerMinSince {
			body := map[string]any{
				"error": fmt.Sprintf(`Invalid or missing "since" query parameter, make sure you store the timestamp at the initial point you started mirroring, `+
					`then send that to begin receiving changes, e.g. %s/metadata/changes.json?since=%d for example.`, env.URL(), now),
				"timestamp": now,
			}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			writeJSON(w, body)
			return
		}
		if since < now-composerLogKept {
			writeJSON(w, map[string]any{
				"actions":   []map[string]any{{"type": "resync", "time": now / 10000, "package": "*"}},
				"timestamp": now,
			})
			return
		}
		actions := []map[string]any{}
		for _, p := range pubs {
			if pos := composerPosition(p); pos >= since && pos < now {
				actions = append(actions, map[string]any{"type": "update", "package": p.Pkg.Name, "time": pos / 10000})
			}
		}
		writeJSON(w, map[string]any{"actions": actions, "timestamp": now})
	})
	env.Stub.Handle("/packages/list.json", func(w http.ResponseWriter, r *http.Request) {
		names := []string{}
		for _, p := range env.Publications() {
			names = append(names, p.Pkg.Name)
		}
		sort.Strings(names)
		writeJSON(w, map[string]any{"packageNames": names})
	})
	// A package's /p2/ document, with the time of its dump as Last-Modified:
	// looked up among the publications at request time, as the change log
	// is, so that the log never names an update the document does not show.
	env.Stub.Fallback(func(w http.ResponseWriter, r *http.Request) bool {
		for _, p := range env.Publications() {
			if r.URL.Path != "/p2/"+p.Pkg.Name+".json" {
				continue
			}
			body, err := env.fetch(r.URL.Path)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return true
			}
			sum := sha256.Sum256(body)
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("ETag", `"`+hex.EncodeToString(sum[:12])+`"`)
			http.ServeContent(w, r, "", p.Time, bytes.NewReader(body))
			return true
		}
		return false
	})
	return nil
}

// composerResumed: the restarted mirror's first read of the change log asked
// for the actions since the position the log named last before the restart —
// one past the benign and malicious packages' dump — none asked from before
// it, and the package list was not read again.
func composerResumed(env *feedEnv, requests []string) error {
	mal, _ := env.Publication(pkgMalicious)
	stored := composerPosition(mal) + 1
	read := false
	for _, line := range requests {
		switch requestPath(line) {
		case "/packages/list.json":
			return fmt.Errorf("the package list was read again: %s", line)
		case "/metadata/changes.json":
			u, err := url.Parse(requestURI(line))
			if err != nil {
				return err
			}
			raw := u.Query().Get("since")
			since, err := strconv.ParseInt(raw, 10, 64)
			switch {
			case raw == "":
				return fmt.Errorf("the change log was asked for a position to start from again: %s", line)
			case err != nil:
				return fmt.Errorf("the change log was read with since=%q: %s", raw, line)
			case since < stored:
				return fmt.Errorf("after the restart the change log was read from since=%d, before the stored position %d", since, stored)
			case !read && since != stored:
				return fmt.Errorf("the first read of the change log continued from since=%d, want the stored position %d", since, stored)
			}
			read = true
		}
	}
	if !read {
		return fmt.Errorf("the change log was not read after the restart")
	}
	return nil
}
