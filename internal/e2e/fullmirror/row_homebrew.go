//go:build integration
// +build integration

package fullmirror

import (
	"bytes"
	"compress/gzip"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"
)

// Homebrew: the adapter has two modes. For formulae.brew.sh, or with the feed
// option url naming a clone of homebrew-core, it diffs homebrew-core's Git
// history (mode git); for any other upstream — a mirror of the JSON API, which
// has no history — mode auto, the default, follows the JSON API's formula
// index instead (mode index), and that is the mode this row covers: the stub
// plays such a mirror. The adapter reads <upstream>/api/formula.json
// conditionally (If-None-Match, If-Modified-Since), as a stream, keeps a
// record per bottle it follows — the synthetic bottle path the backend
// rewrites the bottle's URL to — and reports each formula whose version or
// bottles changed; Releases answers from that copy, and each version is
// mirrored as its bottles. Mode index reports a change at the first poll that
// sees it: the option settle belongs to the Git history, and the adapter
// refuses it here.
//
// The LLM package-scan suite's registry serves each formula's document
// (/api/formula/<name>.json) but not the index. The stub serves it in front,
// as formulae.brew.sh does: a JSON array of the formula documents, one per
// line, sorted by name, each carrying the homebrew-core commit the index was
// generated from (tap_git_head; the stub has no homebrew-core, so it is a
// digest of the formulae listed) — compressed with gzip when the client
// accepts it, with an ETag and a Last-Modified that change with every
// publication. Each fixture formula has one bottle, "all" (it holds no
// compiled code), which the adapter keeps whatever platforms are chosen; the
// row chooses one, as an operator mirroring for Linux would.

func init() {
	register(row{
		Type:  "homebrew",
		Feed:  "the JSON API's formula index `/api/formula.json` (mode auto → index), polled conditionally, gzip",
		Start: homebrewFeedStart,
		Options: func(*feedEnv) map[string]string {
			return map[string]string{"platforms": "x86_64_linux"}
		},
		Resumed: homebrewResumed,
		Notes: []string{
			"mode git (homebrew-core's history, for formulae.brew.sh or feed option url) is not covered: auto chooses mode index for a mirror of the JSON API, which the stub plays",
		},
	})
}

// homebrewIndexReads keeps, for the row's Resumed, the reads of the formula
// index.
type homebrewIndexReads struct {
	mu    sync.Mutex
	reads []homebrewIndexRead
}

// homebrewIndexRead is one read of the formula index: the validators it was
// conditioned on, the ETag it was answered with, and how many formulae were
// published when it came.
type homebrewIndexRead struct {
	published               int
	ifNoneMatch, ifModified string
	etag                    string
}

func homebrewFeedStart(env *feedEnv) error {
	reads := &homebrewIndexReads{}
	env.set("index-reads", reads)
	if _, err := homebrewIndex(env, env.Publications()); err != nil {
		return err
	}
	env.Stub.Handle("/api/formula.json", func(w http.ResponseWriter, r *http.Request) {
		pubs := env.Publications()
		doc, err := homebrewIndex(env, pubs)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		sum := sha256.Sum256(doc)
		etag := `"` + hex.EncodeToString(sum[:12]) + `"`
		body := doc
		w.Header().Set("Vary", "Accept-Encoding")
		if strings.Contains(r.Header.Get("Accept-Encoding"), "gzip") {
			var gz bytes.Buffer
			zw := gzip.NewWriter(&gz)
			_, _ = zw.Write(doc)
			_ = zw.Close()
			body, etag = gz.Bytes(), "W/"+etag
			w.Header().Set("Content-Encoding", "gzip")
		}
		reads.mu.Lock()
		reads.reads = append(reads.reads, homebrewIndexRead{
			published: len(pubs), ifNoneMatch: r.Header.Get("If-None-Match"), ifModified: r.Header.Get("If-Modified-Since"), etag: etag,
		})
		reads.mu.Unlock()
		var modTime time.Time
		for _, p := range pubs {
			if p.Time.After(modTime) {
				modTime = p.Time
			}
		}
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.Header().Set("ETag", etag)
		http.ServeContent(w, r, "", modTime.UTC().Truncate(time.Second), bytes.NewReader(body))
	})
	return nil
}

// homebrewIndex builds /api/formula.json from the documents of the formulae
// published: "[", a formula a line, "]".
func homebrewIndex(env *feedEnv, pubs []publication) ([]byte, error) {
	names := make([]string, 0, len(pubs))
	for _, p := range pubs {
		names = append(names, p.Pkg.Name)
	}
	sort.Strings(names)
	formulae := make([]map[string]any, 0, len(names))
	head := sha1.New()
	for _, name := range names {
		raw, err := env.fetch("/api/formula/" + name + ".json")
		if err != nil {
			return nil, err
		}
		var f map[string]any
		if err := json.Unmarshal(raw, &f); err != nil {
			return nil, fmt.Errorf("the stub registry's formula document of %s: %w", name, err)
		}
		formulae = append(formulae, f)
		head.Write(raw)
	}
	commit := hex.EncodeToString(head.Sum(nil))
	var b bytes.Buffer
	b.WriteString("[\n")
	for i, f := range formulae {
		f["tap_git_head"] = commit
		line, err := json.Marshal(f)
		if err != nil {
			return nil, err
		}
		b.WriteString("  ")
		b.Write(line)
		if i < len(formulae)-1 {
			b.WriteByte(',')
		}
		b.WriteByte('\n')
	}
	b.WriteString("]\n")
	return b.Bytes(), nil
}

// homebrewResumed: the restarted mirror read the formula index conditionally,
// with the ETag of the copy it had read before the restart, rather than read
// it afresh (a new enumeration starts with an unconditional read).
func homebrewResumed(env *feedEnv, _ []string) error {
	reads := env.get("index-reads").(*homebrewIndexReads)
	reads.mu.Lock()
	defer reads.mu.Unlock()
	stored := ""
	for _, rd := range reads.reads {
		// The late formula was published while the proxy was stopped: a
		// read that came after it came from the restarted proxy.
		if rd.published < 4 {
			stored = rd.etag
			continue
		}
		switch {
		case stored == "":
			return fmt.Errorf("the formula index was not read before the restart")
		case rd.ifNoneMatch != stored:
			return fmt.Errorf("the first read of the formula index after the restart carried If-None-Match %q (If-Modified-Since %q), want the ETag of the copy read before the restart, %s",
				rd.ifNoneMatch, rd.ifModified, stored)
		}
		return nil
	}
	return fmt.Errorf("the formula index was not read after the restart")
}
