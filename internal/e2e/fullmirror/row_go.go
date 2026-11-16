//go:build integration
// +build integration

package fullmirror

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Go: the adapter replays the module index — index.golang.org's format,
// `index?since=<RFC 3339>&limit=<n>`: one JSON record {Path, Version,
// Timestamp} per line, in chronological order, from since on (inclusive) —
// from its beginning, then follows it from the timestamp of the last record it
// read, dropping the records of that instant it has reported already. Each
// module's versions come from its @v/list, read through the proxy, and each
// version is mirrored as the three files the go command fetches: its .info,
// its .mod and its .zip.
//
// The stub serves the index at /index, where Athens serves its own and where
// the adapter looks for it on any upstream but proxy.golang.org, so the row
// sets no feed option. It holds one record per publication, stamped with the
// time of publication to the microsecond, as index.golang.org stamps a version
// with when the mirror first fetched it. The benign and the malicious module
// are published together and share their timestamp: two records at one
// instant, which the next page — since repeats the instant — lists again.
//
// The .info and the .mod are metadata to the backend (pkgmgr goClassify), and
// the download log keeps a request for metadata only when a gate refused it
// (downloadLog.includeMetadata is off by default): the mirror's fetches of
// them have no entry, which the row's file list says (Metadata).

func init() {
	register(row{
		Type:    "go",
		Feed:    "the module index (`/index?since=&limit=`, Athens' location), one record per publication",
		Start:   goFeedStart,
		Options: func(*feedEnv) map[string]string { return nil },
		Files: func(env *feedEnv, p publication) []file {
			base := strings.TrimSuffix(p.Pkg.Path, ".zip")
			return []file{{Path: p.Pkg.Path}, {Path: base + ".info", Metadata: true}, {Path: base + ".mod", Metadata: true}}
		},
		Resumed: goResumed,
	})
}

// goIndexCap is the most records a page of the index holds, and its default
// page size: index.golang.org refuses a larger limit (400).
const goIndexCap = 2000

// goIndexRecord is one line of the module index.
type goIndexRecord struct {
	Path      string `json:"Path"`
	Version   string `json:"Version"`
	Timestamp string `json:"Timestamp"`
}

// goIndexTime is the instant the index records a publication at: the index's
// resolution is a microsecond.
func goIndexTime(p publication) time.Time { return p.Time.UTC().Truncate(time.Microsecond) }

func goFeedStart(env *feedEnv) error {
	env.Stub.Handle("/index", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		limit := goIndexCap
		if raw := q.Get("limit"); raw != "" {
			n, err := strconv.Atoi(raw)
			if err != nil || n < 1 || n > goIndexCap {
				goIndexBadRequest(w)
				return
			}
			limit = n
		}
		var since time.Time
		if raw := q.Get("since"); raw != "" {
			t, err := time.Parse(time.RFC3339Nano, raw)
			if err != nil {
				goIndexBadRequest(w)
				return
			}
			since = t
		}
		pubs := env.Publications()
		sort.SliceStable(pubs, func(i, j int) bool { return goIndexTime(pubs[i]).Before(goIndexTime(pubs[j])) })
		var b bytes.Buffer
		n := 0
		for _, p := range pubs {
			at := goIndexTime(p)
			if at.Before(since) || n >= limit {
				continue
			}
			line, err := json.Marshal(goIndexRecord{Path: p.Pkg.Name, Version: p.Pkg.Version, Timestamp: at.Format(time.RFC3339Nano)})
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			b.Write(line)
			b.WriteByte('\n')
			n++
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(b.Bytes())
	})
	return nil
}

// goIndexBadRequest answers a since or a limit the index cannot read, in
// index.golang.org's words.
func goIndexBadRequest(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusBadRequest)
	_, _ = w.Write([]byte("400 bad request"))
}

// goResumed: the restarted mirror read the index from the timestamp it stored
// — the benign and the malicious module's, the newest it had read — and did
// not replay it from its beginning.
func goResumed(env *feedEnv, requests []string) error {
	mal, ok := env.Publication(pkgMalicious)
	if !ok {
		return fmt.Errorf("the malicious module was not published")
	}
	want := goIndexTime(mal)
	for _, line := range requests {
		if requestPath(line) != "/index" {
			continue
		}
		u, err := url.Parse(requestURI(line))
		if err != nil {
			return err
		}
		raw := u.Query().Get("since")
		if raw == "" {
			return fmt.Errorf("the index was read from its beginning again: %s", line)
		}
		since, err := time.Parse(time.RFC3339Nano, raw)
		if err != nil {
			return fmt.Errorf("the first read of the index asked for since %q: %v", raw, err)
		}
		if !since.Equal(want) {
			return fmt.Errorf("the first read of the index continued from %s, want the stored timestamp %s", raw, want.Format(time.RFC3339Nano))
		}
		return nil
	}
	return fmt.Errorf("the index was not read after the restart")
}
