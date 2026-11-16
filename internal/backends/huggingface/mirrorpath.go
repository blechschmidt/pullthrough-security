package huggingface

import (
	"net/url"
	"strings"
)

// This file exports the path builders the full-mirror feed adapter (Task 191)
// lists a repository's files with: it must name exactly the paths a Hub
// client requests, and the backend caches, for them.

// Repository kinds, as the backend labels them (MetaRepoType).
const (
	RepoModel   = "model"
	RepoDataset = "dataset"
	RepoSpace   = "space"
)

// repoPrefix is the path prefix of a repository kind's resolve paths and its
// segment of the /api tree.
func repoPrefix(kind string) (resolve, api string, ok bool) {
	switch kind {
	case RepoModel:
		return "", "models", true
	case RepoDataset:
		return "/datasets", "datasets", true
	case RepoSpace:
		return "/spaces", "spaces", true
	}
	return "", "", false
}

// escapeSegments escapes each segment of a slash-separated path, refusing an
// empty or dot segment and a control character.
func escapeSegments(p string) (string, bool) {
	if p == "" {
		return "", false
	}
	for i := 0; i < len(p); i++ {
		if c := p[i]; c < 0x20 || c == 0x7f {
			return "", false
		}
	}
	segs := strings.Split(p, "/")
	for i, s := range segs {
		if s == "" || s == "." || s == ".." {
			return "", false
		}
		segs[i] = url.PathEscape(s)
	}
	return strings.Join(segs, "/"), true
}

// InfoPath returns the path of a repository's metadata document at a
// revision, "/api/models/<repo>/revision/<revision>" ("/api/datasets/…",
// "/api/spaces/…" for the other kinds), escaped for a request. ok is false
// unless the backend reads it back as that repository's metadata document at
// that revision.
func InfoPath(kind, repoID, revision string) (string, bool) {
	_, api, ok := repoPrefix(kind)
	if !ok || strings.Contains(revision, "/") {
		return "", false
	}
	repo, ok1 := escapeSegments(repoID)
	rev, ok2 := escapeSegments(revision)
	if !ok1 || !ok2 {
		return "", false
	}
	r, ok := classify("/api/" + api + "/" + repoID + "/revision/" + revision)
	if !ok || !r.infoDocument || r.repoType.label() != kind || r.repoID != repoID || r.revision != revision {
		return "", false
	}
	return "/api/" + api + "/" + repo + "/revision/" + rev, true
}

// ResolvePath returns the request path of a repository file at a commit,
// "/<repo>/resolve/<commit>/<file>" ("/datasets/…", "/spaces/…" for the other
// kinds), with each segment escaped for a request. commit must be a full
// commit SHA: only a resolve pinned to one is immutable. ok is false unless
// the backend resolves the path back to that repository, commit and file and
// caches it.
func ResolvePath(kind, repoID, commit, file string) (string, bool) {
	prefix, _, ok := repoPrefix(kind)
	if !ok || !isCommitRevision(commit) {
		return "", false
	}
	repo, ok1 := escapeSegments(repoID)
	f, ok2 := escapeSegments(file)
	if !ok1 || !ok2 {
		return "", false
	}
	r, ok := classify(prefix + "/" + repoID + "/resolve/" + commit + "/" + file)
	if !ok || r.kind != kindResolve || r.repoType.label() != kind || r.repoID != repoID || r.revision != commit || r.filepath != file || !r.cacheable() {
		return "", false
	}
	return prefix + "/" + repo + "/resolve/" + commit + "/" + f, true
}
