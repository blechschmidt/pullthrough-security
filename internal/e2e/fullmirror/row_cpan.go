//go:build integration
// +build integration

package fullmirror

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"path"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// CPAN: the adapter follows a CPAN mirror's RECENT files
// (File::Rsync::Mirror::Recent): RECENT-1h.json lists the mirror's events of
// the last hour — {epoch, path, type}, newest first — and the longer interval
// files (6h, 1d, …) are read when the stored epoch is older than the hour
// file's oldest event. An upload in an author directory is reported once a
// later event shows the directory's CHECKSUMS rewritten. Bootstrap lists
// every distribution 02packages.details.txt.gz indexes, read through the
// proxy, and continues from two hours before the hour file's newest event.
// Each distribution's versions come from its author directory's CHECKSUMS,
// read through the proxy.
//
// The stub serves the RECENT files at the mirror's root (no feed option:
// the adapter reads them there, as on cpan.metacpan.org), computed at request
// time the way PAUSE and the mirror write them: epochs unique and spelt with
// up to five decimals; a file lists a path once, at its latest event, and
// holds the events of its interval, minmax stating its oldest and newest. A
// mirror's RECENT files are never empty: besides the uploads they record the
// stamp and index files PAUSE and the mirror rewrite around the clock. The
// stub's mirror has such files, last written in the hours before the seed's
// upload, so that each interval file spans its interval as one of a running
// mirror does — the six-hour file reaching back past the two hours Bootstrap
// continues from.
//
// An upload is three events: the archive appears in the author's directory;
// PAUSE rewrites the directory's CHECKSUMS to list it some minutes later (4 to
// 45 in the recorded RECENT files) — until then CHECKSUMS does not list it,
// and the adapter, which lists versions from CHECKSUMS, holds the upload
// back; the indexer rewrites 02packages.details.txt.gz after that. The seed's
// three events lie minutes apart, before the proxy starts. A row cannot wait
// minutes for every later upload (its waits are three minutes), so the stub
// compresses PAUSE's delay but keeps its order and its consequence: an
// upload's CHECKSUMS is rewritten two seconds after the first read of the
// RECENT files that showed the upload — every upload is seen unconfirmed by
// one poll, held back, and reported by a later one — and the CHECKSUMS the
// stub serves in front of the registry lists an archive only from its
// rewrite on (the registry's own lists every published archive at once). The
// archives and 02packages.details.txt.gz are the registry's own; the adapter
// reads the index only to enumerate, before which the seed was indexed.

func init() {
	register(row{
		Type:       "cpan",
		Feed:       "`RECENT-<interval>.json` (1h … Z) at the mirror's root: upload, CHECKSUMS rewrite and index rewrite events among the mirror's stamp files",
		Start:      cpanFeedStart,
		Options:    func(*feedEnv) map[string]string { return nil },
		Resumed:    cpanResumed,
		Rereported: []string{pkgSeed},
		Notes: []string{
			"Bootstrap continues the RECENT files from two hours before their newest event (cpanHold): " +
				"the first poll reports the seed again, which the mirror finds in the cache (skipped: cached)",
			"a RECENT producer whose whole history spans less than two hours cannot be followed: no RECENT file the adapter reads " +
				"(it never reads RECENT-Z) reaches back to the position Bootstrap continues from, so every poll enumerates the registry again; " +
				"the stub's mirror has hours of history",
			"PAUSE's delay between an upload and its CHECKSUMS rewrite (minutes) is compressed to two seconds after a read showed the upload",
			"no `.meta` or `.readme` events: the stub registry publishes the archives alone",
		},
	})
}

// cpanIntervalSpans are the stub mirror's RECENT files: their intervals,
// shortest first, and the span of events each holds.
var cpanIntervalSpans = []struct {
	name string
	span time.Duration // 0: everything (Z)
}{
	{"1h", time.Hour}, {"6h", 6 * time.Hour}, {"1d", 24 * time.Hour}, {"1W", 7 * 24 * time.Hour},
	{"1M", 30 * 24 * time.Hour}, {"1Q", 91 * 24 * time.Hour}, {"1Y", 365 * 24 * time.Hour}, {"Z", 0},
}

// cpanDirtymark is the dirtymark of the stub mirror's history: the epoch it was
// last rebuilt at, which never changes while a row runs.
const cpanDirtymark = "1704164645.12345"

// cpanStampFiles are files the mirror rewrote before the seed's upload, with
// how long before it each was last written.
var cpanStampFiles = []struct {
	path   string
	before time.Duration
}{
	{"indices/ls-lR.gz", 5*time.Hour + 30*time.Minute},
	{"indices/find-ls.gz", 4*time.Hour + 10*time.Minute},
	{"MIRRORING.FROM", 2*time.Hour + 50*time.Minute},
	{"indices/cpan-stats.json", time.Hour + 35*time.Minute},
	{"authors/00whois.xml", 40 * time.Minute},
	{"modules/02STAMP", 12 * time.Minute},
	{"authors/02STAMP", 6 * time.Minute},
}

// cpanRecentEvent is one event of the mirror: its epoch in units of 10 µs (the
// five decimals the stub spells) and its path below the mirror's root.
type cpanRecentEvent struct {
	at   int64
	path string
}

// cpanUnit is a time in the stub's epoch units.
func cpanUnit(t time.Time) int64 { return t.UnixNano() / 10_000 }

// cpanEpoch spells an epoch as the RECENT files do: seconds, and the fraction
// without trailing zeros.
func cpanEpoch(at int64) string {
	frac := strings.TrimRight(fmt.Sprintf("%05d", at%100_000), "0")
	if frac == "" {
		return strconv.FormatInt(at/100_000, 10)
	}
	return strconv.FormatInt(at/100_000, 10) + "." + frac
}

// The seed's upload, its CHECKSUMS rewrite and its indexing happened this long
// before its publication: before the proxy started.
const (
	cpanSeedUpload  = 5 * time.Minute
	cpanSeedRewrite = 90 * time.Second
	cpanSeedIndexed = 30 * time.Second
)

// cpanRewriteDelay is how long after the first read of the RECENT files that
// showed an upload the stub rewrites the upload's CHECKSUMS.
const cpanRewriteDelay = 2 * time.Second

// cpanMirror is the stub mirror's state: when a read of the RECENT files
// first showed each upload (by variant).
type cpanMirror struct {
	mu    sync.Mutex
	shown map[string]time.Time
}

// rewritten is when the CHECKSUMS of a publication's directory is rewritten
// to list it (zero: not yet scheduled).
func (m *cpanMirror) rewritten(p publication) time.Time {
	if p.Variant == pkgSeed {
		return p.Time.Add(-cpanSeedRewrite)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if at, ok := m.shown[p.Variant]; ok {
		return at.Add(cpanRewriteDelay)
	}
	return time.Time{}
}

// listed reports whether a publication's CHECKSUMS rewrite has happened at now.
func (m *cpanMirror) listed(p publication, now time.Time) bool {
	at := m.rewritten(p)
	return !at.IsZero() && !at.After(now)
}

// show records that a read at now showed uploads not listed yet: their
// CHECKSUMS is rewritten cpanRewriteDelay later.
func (m *cpanMirror) show(pubs []publication, now time.Time) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, p := range pubs {
		if _, ok := m.shown[p.Variant]; !ok {
			m.shown[p.Variant] = now
		}
	}
}

// events are the mirror's events at now, newest first, each path once at its
// latest event, and the uploads among them their CHECKSUMS does not list yet.
func (m *cpanMirror) events(pubs []publication, now time.Time) ([]cpanRecentEvent, []publication) {
	if len(pubs) == 0 {
		return nil, nil
	}
	var all []cpanRecentEvent
	for _, f := range cpanStampFiles {
		all = append(all, cpanRecentEvent{at: cpanUnit(pubs[0].Time.Add(-f.before)), path: f.path})
	}
	var unlisted []publication
	// Packages published together are one batch of uploads, their archives
	// in one directory: one CHECKSUMS rewrite lists them all.
	for i := 0; i < len(pubs); {
		j := i
		for j < len(pubs) && pubs[j].Time.Equal(pubs[i].Time) {
			j++
		}
		at := cpanUnit(pubs[i].Time)
		if pubs[i].Variant == pkgSeed {
			at = cpanUnit(pubs[i].Time.Add(-cpanSeedUpload))
		}
		for _, p := range pubs[i:j] {
			all = append(all, cpanRecentEvent{at: at, path: strings.TrimPrefix(p.Pkg.Path, "/")})
			at++
		}
		if m.listed(pubs[i], now) {
			rewrite := cpanUnit(m.rewritten(pubs[i]))
			indexed := rewrite + 1
			if pubs[i].Variant == pkgSeed {
				indexed = cpanUnit(pubs[i].Time.Add(-cpanSeedIndexed))
			}
			all = append(all,
				cpanRecentEvent{at: rewrite, path: strings.TrimPrefix(path.Dir(pubs[i].Pkg.Path), "/") + "/CHECKSUMS"},
				cpanRecentEvent{at: indexed, path: "modules/02packages.details.txt.gz"})
		} else {
			unlisted = append(unlisted, pubs[i:j]...)
		}
		i = j
	}
	latest := map[string]int64{}
	for _, e := range all {
		if e.at > latest[e.path] {
			latest[e.path] = e.at
		}
	}
	out := make([]cpanRecentEvent, 0, len(latest))
	for p, at := range latest {
		out = append(out, cpanRecentEvent{at: at, path: p})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].at > out[j].at })
	return out, unlisted
}

// cpanChecksumsWithout returns a CHECKSUMS document without the entries of
// files, as CPAN::Checksums writes it before the files are listed.
func cpanChecksumsWithout(doc []byte, files map[string]bool) []byte {
	var b strings.Builder
	skip := false
	for _, line := range strings.SplitAfter(string(doc), "\n") {
		trimmed := strings.TrimSpace(line)
		switch {
		case skip:
			skip = trimmed != "}," && trimmed != "}"
		case strings.HasSuffix(trimmed, "' => {") && files[strings.TrimSuffix(strings.TrimPrefix(trimmed, "'"), "' => {")]:
			skip = true
		default:
			b.WriteString(line)
		}
	}
	return []byte(b.String())
}

// cpanFeedStart serves the RECENT files, one route per interval, and the
// author directory's CHECKSUMS as the rewrites so far left it.
func cpanFeedStart(env *feedEnv) error {
	m := &cpanMirror{shown: map[string]time.Time{}}
	aggregator := make([]string, 0, len(cpanIntervalSpans))
	for _, iv := range cpanIntervalSpans {
		aggregator = append(aggregator, iv.name)
	}
	for k, iv := range cpanIntervalSpans {
		env.Stub.Handle("/RECENT-"+iv.name+".json", func(w http.ResponseWriter, r *http.Request) {
			now := time.Now()
			from := int64(0)
			if iv.span > 0 {
				from = cpanUnit(now.Add(-iv.span))
			}
			events, unlisted := m.events(env.Publications(), now)
			recent := []map[string]any{}
			var newest, oldest int64
			for _, e := range events {
				if e.at < from {
					continue
				}
				recent = append(recent, map[string]any{"epoch": json.Number(cpanEpoch(e.at)), "path": e.path, "type": "new"})
				if newest == 0 {
					newest = e.at
				}
				oldest = e.at
			}
			meta := map[string]any{
				"aggregator": aggregator, "dirtymark": json.Number(cpanDirtymark), "filenameroot": "RECENT",
				"interval": iv.name, "protocol": 1, "serializer_suffix": ".json",
			}
			if len(recent) > 0 {
				meta["minmax"] = map[string]any{"max": json.Number(cpanEpoch(newest)), "min": json.Number(cpanEpoch(oldest)), "mtime": newest / 100_000}
				if k+1 < len(cpanIntervalSpans) {
					meta["merged"] = map[string]any{"epoch": json.Number(cpanEpoch(newest)), "into_interval": cpanIntervalSpans[k+1].name}
				}
			}
			writeJSON(w, map[string]any{"meta": meta, "recent": recent})
			// PAUSE gets round to the uploads this read showed unlisted.
			m.show(unlisted, now)
		})
	}
	pubs := env.Publications()
	if len(pubs) == 0 {
		return fmt.Errorf("the stub registry published no seed")
	}
	checksums := path.Dir(pubs[0].Pkg.Path) + "/CHECKSUMS"
	env.Stub.Handle(checksums, func(w http.ResponseWriter, r *http.Request) {
		now := time.Now()
		doc, err := env.fetch(checksums)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		unlisted := map[string]bool{}
		var modified time.Time
		for _, p := range env.Publications() {
			if !m.listed(p, now) {
				unlisted[path.Base(p.Pkg.Path)] = true
			} else if at := m.rewritten(p); at.After(modified) {
				modified = at
			}
		}
		body := cpanChecksumsWithout(doc, unlisted)
		sum := sha256.Sum256(body)
		w.Header().Set("Content-Type", "text/plain")
		w.Header().Set("ETag", `"`+hex.EncodeToString(sum[:12])+`"`)
		http.ServeContent(w, r, "", modified, bytes.NewReader(body))
	})
	return nil
}

// cpanResumed: the restarted mirror read the hour file alone — the epoch it
// stored, the newest event before the restart, is within the hour (a mirror
// that had started over from Bootstrap's position, two hours back, would read
// the six-hour file too) — and did not list the index again.
func cpanResumed(env *feedEnv, requests []string) error {
	read := false
	for _, line := range requests {
		switch p := requestPath(line); {
		case p == "/modules/02packages.details.txt.gz":
			return fmt.Errorf("the index was listed again: %s", line)
		case p == "/RECENT-1h.json":
			read = true
		case strings.HasPrefix(p, "/RECENT-"):
			return fmt.Errorf("the restarted mirror read %s: the epoch it continued from is not the one it stored after the poll", line)
		}
	}
	if !read {
		return fmt.Errorf("RECENT-1h.json was not read after the restart")
	}
	return nil
}
