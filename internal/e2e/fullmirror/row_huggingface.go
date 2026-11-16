//go:build integration
// +build integration

package fullmirror

import (
	"bytes"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Hugging Face: the adapter follows the Hub's listing of repositories by last
// modification, newest first — /api/models?author=<a>&sort=lastModified
// &direction=-1&limit=100&expand=lastModified&expand=sha, each further page
// named by a keyset cursor in the Link header — for the scope feed option
// author names, from its first page down to its high-water mark (listfeed.go),
// and reports every repository modified since; Bootstrap takes the mark from
// that listing, then lists the scope's repositories. A repository's files are
// those of the commit its main branch is at, from its revision metadata
// (/api/models/<repo>/revision/main, read through the proxy), each mirrored
// pinned to the commit (/<repo>/resolve/<commit>/<file>).
//
// The stub serves the listing as the Hub does: the repositories the registry
// published whose owner is the author asked for (and whose name holds the
// search, when one is given), newest first, each with its _id, its commit and
// the time it was last modified — when it was published, in whole seconds, as
// the Hub states it. Every repository is one commit, and the listing ends
// within its first page. (The revision metadata the LLM package-scan suite's
// registry serves states an older lastModified; the mirror decides nothing on
// it.) That registry lists .gitattributes among each repository's files but
// does not serve it: the stub serves it in front, the Hub's default for a new
// repository, with the commit and the Git blob ID the Hub sends for a file
// held in Git — so the mirror fetches all three files of a repository, the
// model code (the payload the gate reads), config.json and .gitattributes.
// The upstream is not huggingface.co, so feed option url names the stub as
// the API whose listing is read.
//
// The listing dates the seed's repository two days back (huggingfaceSeedAge):
// modified within seconds of the others, it would lie in the ten minutes
// below the mark the adapter looks back over, where the repositories it has
// seen are remembered whatever its mark says — and an adapter restarted
// without its mark would go unnoticed. Two days back, the seed lies below the
// window of the mark the follow-up poll stores: a restarted adapter that
// continues from that mark stops at it, one that lost the mark finds it unseen
// and reports it again, which huggingfaceResumed refuses (its revision
// metadata read) and the suite counts (its files skipped, cached).

func init() {
	register(row{
		Type:  "huggingface",
		Feed:  "the Hub's `/api/models?author=…` listing by `lastModified`, newest first (one page); revision metadata",
		Start: huggingfaceFeedStart,
		Options: func(env *feedEnv) map[string]string {
			return map[string]string{"url": env.URL(), "author": "pte2e"}
		},
		Files:   huggingfaceFiles,
		Resumed: huggingfaceResumed,
		Notes: []string{
			"one author's models: feed options search, kind (datasets, spaces), files and restricted keep their defaults, and the listing ends within its first page (no Link cursor followed)",
			"`.gitattributes` is served in front of the LLM package-scan registry, which lists it among each repository's files but does not serve it",
			"every publication is a new repository: a new commit to a known repository, which moves its lastModified, is not covered",
			"no gated, private or disabled repository is published: skipping them (gated and private ones unless feed option restricted is include) is not covered",
		},
	})
}

// huggingfaceGitattributes is the .gitattributes the Hub commits into a new
// model repository (its first lines: which files Git LFS holds).
const huggingfaceGitattributes = "*.7z filter=lfs diff=lfs merge=lfs -text\n" +
	"*.arrow filter=lfs diff=lfs merge=lfs -text\n" +
	"*.bin filter=lfs diff=lfs merge=lfs -text\n" +
	"*.gguf filter=lfs diff=lfs merge=lfs -text\n" +
	"*.h5 filter=lfs diff=lfs merge=lfs -text\n" +
	"*.onnx filter=lfs diff=lfs merge=lfs -text\n" +
	"*.pt filter=lfs diff=lfs merge=lfs -text\n" +
	"*.safetensors filter=lfs diff=lfs merge=lfs -text\n" +
	"*.zip filter=lfs diff=lfs merge=lfs -text\n"

// huggingfaceRevision is what the stub reads of a repository's revision
// metadata, as the registry serves it.
type huggingfaceRevision struct {
	SHA      string `json:"sha"`
	Siblings []struct {
		RFilename string `json:"rfilename"`
	} `json:"siblings"`
}

// huggingfaceSeedAge is how long before its publication the listing dates the
// seed's repository: beyond the ten minutes below the mark the adapter looks
// back over (listingLookback in internal/fullmirror/listfeed.go).
const huggingfaceSeedAge = 48 * time.Hour

// huggingfaceListedAt is when the listing says a repository was last
// modified: when it was published, the seed two days earlier, in whole
// seconds as the Hub states it.
func huggingfaceListedAt(p publication) time.Time {
	t := p.Time
	if p.Variant == pkgSeed {
		t = t.Add(-huggingfaceSeedAge)
	}
	return t.UTC().Truncate(time.Second)
}

// huggingfaceRepo is a publication's repository id ("pte2e/seed").
func huggingfaceRepo(p publication) string { return p.Pkg.Name }

// huggingfaceInfo reads a publication's revision metadata from the registry.
func huggingfaceInfo(env *feedEnv, p publication) (huggingfaceRevision, error) {
	var rev huggingfaceRevision
	body, err := env.fetch("/api/models/" + huggingfaceRepo(p) + "/revision/main")
	if err != nil {
		return rev, err
	}
	if err := json.Unmarshal(body, &rev); err != nil {
		return rev, fmt.Errorf("the revision metadata of %s: %w", huggingfaceRepo(p), err)
	}
	return rev, nil
}

// huggingfaceObjectID is a repository's _id: 24 hex digits, derived from its
// id.
func huggingfaceObjectID(repo string) string {
	sum := sha256.Sum256([]byte("pte2e-repository\x00" + repo))
	return hex.EncodeToString(sum[:12])
}

// huggingfaceBlobID is the Git object ID of a file's content, the ETag the
// Hub sends for a file held in Git.
func huggingfaceBlobID(content []byte) string {
	h := sha1.New()
	h.Write([]byte("blob " + strconv.Itoa(len(content)) + "\x00"))
	h.Write(content)
	return hex.EncodeToString(h.Sum(nil))
}

func huggingfaceFeedStart(env *feedEnv) error {
	env.Stub.Handle("/api/models", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		limit := 1000
		if v := q.Get("limit"); v != "" {
			n, err := strconv.Atoi(v)
			if err != nil || n < 1 {
				http.Error(w, `{"error":"limit must be a positive integer"}`, http.StatusBadRequest)
				return
			}
			limit = n
		}
		if q.Get("sort") != "lastModified" || q.Get("direction") != "-1" {
			http.Error(w, `{"error":"the stub lists repositories by lastModified, newest first, only"}`, http.StatusBadRequest)
			return
		}
		if q.Get("cursor") != "" {
			// The stub hands out no cursor: every listing ends within its first
			// page.
			http.Error(w, `{"error":"Invalid cursor"}`, http.StatusBadRequest)
			return
		}
		author, search := q.Get("author"), strings.ToLower(q.Get("search"))
		var pubs []publication
		for _, p := range env.Publications() {
			owner, name, _ := strings.Cut(huggingfaceRepo(p), "/")
			if (author == "" || owner == author) && (search == "" || strings.Contains(strings.ToLower(name), search)) {
				pubs = append(pubs, p)
			}
		}
		// The Hub's keyset: lastModified, newest first, then _id ascending.
		sort.SliceStable(pubs, func(i, j int) bool {
			ti, tj := huggingfaceListedAt(pubs[i]), huggingfaceListedAt(pubs[j])
			if !ti.Equal(tj) {
				return ti.After(tj)
			}
			return huggingfaceObjectID(huggingfaceRepo(pubs[i])) < huggingfaceObjectID(huggingfaceRepo(pubs[j]))
		})
		out := []map[string]any{}
		for _, p := range pubs {
			if len(out) == limit {
				http.Error(w, "the stub lists at most one page", http.StatusInternalServerError)
				return
			}
			rev, err := huggingfaceInfo(env, p)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			out = append(out, map[string]any{
				"_id": huggingfaceObjectID(huggingfaceRepo(p)), "id": huggingfaceRepo(p),
				"lastModified": huggingfaceListedAt(p).Format("2006-01-02T15:04:05.000Z"), "sha": rev.SHA,
			})
		}
		writeJSON(w, out)
	})
	gitattributes := []byte(huggingfaceGitattributes)
	env.Stub.Fallback(func(w http.ResponseWriter, r *http.Request) bool {
		for _, p := range env.Publications() {
			prefix := "/" + huggingfaceRepo(p) + "/resolve/"
			commit, ok := strings.CutSuffix(strings.TrimPrefix(r.URL.Path, prefix), "/.gitattributes")
			if !strings.HasPrefix(r.URL.Path, prefix) || !ok {
				continue
			}
			rev, err := huggingfaceInfo(env, p)
			if err != nil || commit != rev.SHA {
				return false
			}
			w.Header().Set("X-Repo-Commit", rev.SHA)
			w.Header().Set("ETag", `"`+huggingfaceBlobID(gitattributes)+`"`)
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			http.ServeContent(w, r, "", huggingfaceListedAt(p), bytes.NewReader(gitattributes))
			return true
		}
		return false
	})
	return nil
}

// huggingfaceFiles lists a repository's files at its commit, from the
// revision metadata: the model code, the payload, first.
func huggingfaceFiles(env *feedEnv, p publication) []file {
	out := []file{{Path: p.Pkg.Path}}
	rev, err := huggingfaceInfo(env, p)
	if err != nil {
		return out
	}
	var rest []string
	for _, s := range rev.Siblings {
		if path := "/" + huggingfaceRepo(p) + "/resolve/" + rev.SHA + "/" + s.RFilename; path != p.Pkg.Path {
			rest = append(rest, path)
		}
	}
	sort.Strings(rest)
	for _, path := range rest {
		out = append(out, file{Path: path})
	}
	return out
}

// huggingfaceResumed: the restarted mirror read the author's listing from its
// first page and read the revision metadata of the late repository alone —
// the repositories it had seen before the restart were remembered with the
// mark.
func huggingfaceResumed(env *feedEnv, requests []string) error {
	late, _ := env.Publication(pkgLate)
	read := false
	for _, line := range requests {
		u, err := url.Parse(requestURI(line))
		if err != nil {
			return err
		}
		switch {
		case u.Path == "/api/models":
			if !read && u.Query().Get("cursor") != "" {
				return fmt.Errorf("the first read of the listing did not start at its first page: %s", line)
			}
			read = true
		case strings.HasPrefix(u.Path, "/api/models/") && u.Path != "/api/models/"+huggingfaceRepo(late)+"/revision/main":
			return fmt.Errorf("a repository mirrored before the restart was reported again: %s", line)
		}
	}
	if !read {
		return fmt.Errorf("the listing was not read")
	}
	return nil
}
