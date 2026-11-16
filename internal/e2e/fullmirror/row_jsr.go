//go:build integration
// +build integration

package fullmirror

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
)

// JSR: the adapter reads the management API's package list — GET
// <api>/packages?limit=100&page=N, alphabetical, page after page to the first
// empty one — at every poll into a copy it diffs against the copy of the poll
// before (pollfeed.go): a publish moves a package's version count. Each
// changed package's versions come from its meta.json, and each version's
// module files from its "<version>_meta.json" manifest, both read through the
// proxy; every module file of a version is mirrored.
//
// The stub serves the list at /api/packages as api.jsr.io serves it (the
// upstream is not jsr.io, so feed option url names the stub's /api as the
// management API): every package the registry published, sorted by name, each
// with its scope, name, version count, latest version and the times it was
// created and last updated — when it was published — paged by limit and page,
// past the last package an empty page, under the total of packages. The
// versions and files come from the LLM package-scan suite's registry, whose
// version manifests list two module files a version: mod.ts, the payload the
// gate scans, and jsr.json.

func init() {
	register(row{
		Type:  "jsr",
		Feed:  "the management API's package list (`/packages?limit=100&page=N`, alphabetical, to the first empty page), read whole at every poll",
		Start: jsrFeedStart,
		Options: func(env *feedEnv) map[string]string {
			return map[string]string{"url": env.URL() + "/api"}
		},
		Files:   jsrFiles,
		Resumed: jsrResumed,
		Notes: []string{
			"every publication is a new package with one version: the change signal of a publish to a known package — its version count moving — never fires; the diff reports packages that appeared",
			"no package has a second version: the file lists kept per package (a publish reads only the new version's manifest) and a yanked version are not covered",
			"the list fits its first page (then the empty page that ends it): a list of several pages is not covered",
		},
	})
}

// jsrTime spells a time the way the management API does.
func jsrTime(p publication) string { return p.Time.UTC().Format("2006-01-02T15:04:05.000000Z07:00") }

func jsrFeedStart(env *feedEnv) error {
	env.Stub.Handle("/api/packages", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		limit, page := 20, 1
		if v := q.Get("limit"); v != "" {
			n, err := strconv.Atoi(v)
			if err != nil || n < 1 || n > 100 {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusBadRequest)
				_, _ = w.Write([]byte(`{"code":"invalidQuery","message":"limit must be between 1 and 100"}`))
				return
			}
			limit = n
		}
		if v := q.Get("page"); v != "" {
			n, err := strconv.Atoi(v)
			if err != nil || n < 1 {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusBadRequest)
				_, _ = w.Write([]byte(`{"code":"invalidQuery","message":"page must be a positive integer"}`))
				return
			}
			page = n
		}
		pubs := env.Publications()
		sort.SliceStable(pubs, func(i, j int) bool { return pubs[i].Pkg.Name < pubs[j].Pkg.Name })
		items := []map[string]any{}
		for i := (page - 1) * limit; i < len(pubs) && i < page*limit; i++ {
			p := pubs[i]
			scope, name, _ := strings.Cut(strings.TrimPrefix(p.Pkg.Name, "@"), "/")
			items = append(items, map[string]any{
				"scope": scope, "name": name, "description": "", "githubRepository": nil, "runtimeCompat": map[string]any{},
				"updatedAt": jsrTime(p), "createdAt": jsrTime(p), "versionCount": 1, "dependencyCount": 0, "dependentCount": 0,
				"score": nil, "latestVersion": p.Pkg.Version, "whenFeatured": nil, "isArchived": false, "readmeSource": "jsdoc", "symbolCount": nil,
			})
		}
		writeJSON(w, map[string]any{"items": items, "total": len(pubs)})
	})
	return nil
}

// jsrFiles lists a version's module files, from the manifest the registry
// serves: the payload, mod.ts, first.
func jsrFiles(env *feedEnv, p publication) []file {
	out := []file{{Path: p.Pkg.Path}}
	body, err := env.fetch("/" + p.Pkg.Name + "/" + p.Pkg.Version + "_meta.json")
	if err != nil {
		return out
	}
	var doc struct {
		Manifest map[string]json.RawMessage `json:"manifest"`
	}
	if json.Unmarshal(body, &doc) != nil {
		return out
	}
	var rest []string
	for name := range doc.Manifest {
		if path := "/" + p.Pkg.Name + "/" + p.Pkg.Version + name; path != p.Pkg.Path {
			rest = append(rest, path)
		}
	}
	sort.Strings(rest)
	for _, path := range rest {
		out = append(out, file{Path: path})
	}
	return out
}

// jsrResumed: the restarted mirror read the package list from its first page
// and diffed it against the copy it had stored: of the packages, it read the
// late package's meta.json alone.
func jsrResumed(env *feedEnv, requests []string) error {
	late, _ := env.Publication(pkgLate)
	read := false
	for _, line := range requests {
		u, err := url.Parse(requestURI(line))
		if err != nil {
			return err
		}
		switch {
		case u.Path == "/api/packages":
			if !read && u.Query().Get("page") != "1" {
				return fmt.Errorf("the first read of the package list did not start at its first page: %s", line)
			}
			read = true
		case strings.HasSuffix(u.Path, "/meta.json") && u.Path != "/"+late.Pkg.Name+"/meta.json":
			return fmt.Errorf("a package mirrored before the restart was reported again: %s", line)
		}
	}
	if !read {
		return fmt.Errorf("the package list was not read")
	}
	return nil
}
