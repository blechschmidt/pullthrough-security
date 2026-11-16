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
	"time"
)

// Puppet: the adapter follows the Forge's release listing — /v3/releases
// sorted by release_date, newest first, offset-paged — from its first page
// down to its high-water mark and a day below it (listfeed.go), and reports
// the module of every release it has not seen there. Bootstrap takes the mark
// from that listing, then enumerates the modules from the same listing sorted
// by module. A module's releases come from its module document,
// /v3/modules/<owner>-<name>, read through the proxy.
//
// The stub serves both listings at /v3/releases as the Forge does: every
// release the registry published, each its release document less the fields
// the request's exclude_fields names, its created_at the time of the
// publication in the Forge's spelling (Pacific time, "2026-11-16 03:04:05
// -0800"), paged by limit and offset under the Forge's pagination block. It
// also serves the module documents, which the LLM package-scan suite's
// registry has no need of — a client installing an exact version reads the
// release document alone — each listing the module's releases with their
// times, file_uri and file_size, as the Forge's do. (The release documents
// that registry serves state an older creation time; the mirror reads none of
// them for a time: the backend verifies a tarball against its file_sha256.)
// The upstream is not forgeapi.puppet.com, so feed option url names the stub
// as the Forge whose listing is read; settle zero.
//
// The listings, and the module documents with them, date the seed's release
// two days back (puppetSeedAge): published within seconds of the others, it
// would lie in the day below the mark the adapter looks back over, where the
// releases it has seen are remembered whatever its mark says — and an adapter
// restarted without its mark would go unnoticed. Two days back, the seed lies
// below the window of the mark the follow-up poll stores: a restarted adapter
// that continues from that mark stops at it, one that lost the mark finds it
// unseen and reports it again, which puppetResumed refuses (its module
// document read) and the suite counts (its tarball skipped, cached).

func init() {
	register(row{
		Type:  "puppet",
		Feed:  "`/v3/releases` sorted by `release_date` (and by `module` to enumerate), offset-paged; module documents",
		Start: puppetFeedStart,
		Options: func(env *feedEnv) map[string]string {
			return map[string]string{"url": env.URL(), "settle": "0s"}
		},
		Resumed: puppetResumed,
		Notes: []string{
			"settle is zero: holding back releases younger than the settle period (90 minutes by default) is not covered",
			"no deleted release (listed as yanked) and no premium or login-required module (skipped without credentials) is published",
			"the four releases fit the listing's first page: later pages, their overlap and a pass continued in a later poll are not covered",
		},
	})
}

// puppetForgeZone is the zone the Forge states its times in (US Pacific; in
// November, standard time).
var puppetForgeZone = time.FixedZone("PST", -8*60*60)

// puppetForgeTime spells a time the way the Forge does.
func puppetForgeTime(t time.Time) string {
	return t.In(puppetForgeZone).Format("2006-01-02 15:04:05 -0700")
}

// puppetSeedAge is how long before its publication the listings date the
// seed's release: beyond the day below the mark the adapter looks back over
// (puppetLookback in internal/fullmirror/feed_puppet.go).
const puppetSeedAge = 48 * time.Hour

// puppetListedAt is when the listings and the module documents say a release
// was created: when it was published, the seed two days earlier.
func puppetListedAt(p publication) time.Time {
	if p.Variant == pkgSeed {
		return p.Time.Add(-puppetSeedAge)
	}
	return p.Time
}

// puppetRelease returns the release document of a publication as the Forge's
// listings and module documents carry it: the document the registry serves,
// created when the listings say (puppetListedAt).
func puppetRelease(env *feedEnv, p publication) (map[string]any, error) {
	body, err := env.fetch("/v3/releases/" + p.Pkg.Name + "-" + p.Pkg.Version)
	if err != nil {
		return nil, err
	}
	var doc map[string]any
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, fmt.Errorf("the release document of %s: %w", p.Pkg.Name, err)
	}
	at := puppetForgeTime(puppetListedAt(p))
	doc["created_at"], doc["updated_at"] = at, at
	return doc, nil
}

func puppetFeedStart(env *feedEnv) error {
	env.Stub.Handle("/v3/releases", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		limit, offset := 20, 0
		if v := q.Get("limit"); v != "" {
			n, err := strconv.Atoi(v)
			if err != nil || n < 1 || n > 100 {
				http.Error(w, `{"message":"400 Bad Request","errors":["limit must be between 1 and 100"]}`, http.StatusBadRequest)
				return
			}
			limit = n
		}
		if v := q.Get("offset"); v != "" {
			n, err := strconv.Atoi(v)
			if err != nil || n < 0 {
				http.Error(w, `{"message":"400 Bad Request","errors":["offset must be a non-negative integer"]}`, http.StatusBadRequest)
				return
			}
			offset = n
		}
		pubs := env.Publications()
		switch q.Get("sort_by") {
		case "release_date":
			// Newest first; of two releases of one second, the one published
			// later first.
			sort.SliceStable(pubs, func(i, j int) bool {
				ti, tj := puppetListedAt(pubs[i]).Truncate(time.Second), puppetListedAt(pubs[j]).Truncate(time.Second)
				if !ti.Equal(tj) {
					return ti.After(tj)
				}
				return pubs[i].Seq > pubs[j].Seq
			})
		case "module":
			// By module; a module's releases newest first.
			sort.SliceStable(pubs, func(i, j int) bool {
				if pubs[i].Pkg.Name != pubs[j].Pkg.Name {
					return pubs[i].Pkg.Name < pubs[j].Pkg.Name
				}
				return pubs[i].Seq > pubs[j].Seq
			})
		default:
			http.Error(w, `{"message":"400 Bad Request","errors":["the stub sorts releases by release_date or module only"]}`, http.StatusBadRequest)
			return
		}
		excluded := strings.Fields(q.Get("exclude_fields"))
		results := []map[string]any{}
		for i := offset; i < len(pubs) && i < offset+limit; i++ {
			doc, err := puppetRelease(env, pubs[i])
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			for _, f := range excluded {
				delete(doc, f)
			}
			results = append(results, doc)
		}
		link := func(off int) string {
			l := url.Values{}
			for k, v := range q {
				l[k] = v
			}
			l.Set("limit", strconv.Itoa(limit))
			l.Set("offset", strconv.Itoa(off))
			return "/v3/releases?" + l.Encode()
		}
		pagination := map[string]any{
			"limit": limit, "offset": offset, "first": link(0), "previous": nil, "current": link(offset), "next": nil, "total": len(pubs),
		}
		if offset > 0 {
			pagination["previous"] = link(max(0, offset-limit))
		}
		if offset+limit < len(pubs) {
			pagination["next"] = link(offset + limit)
		}
		writeJSON(w, map[string]any{"pagination": pagination, "results": results})
	})
	env.Stub.Fallback(func(w http.ResponseWriter, r *http.Request) bool {
		slug, ok := strings.CutPrefix(r.URL.Path, "/v3/modules/")
		if !ok {
			return false
		}
		var rels []publication
		for _, p := range env.Publications() {
			if p.Pkg.Name == slug {
				rels = append(rels, p)
			}
		}
		if len(rels) == 0 {
			return false
		}
		doc, err := puppetModuleDocument(env, rels)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return true
		}
		writeJSON(w, doc)
		return true
	})
	return nil
}

// puppetModuleDocument is the module document of a module's releases (in the
// order of publication): the module, its newest release in full, and every
// release in brief, newest first.
func puppetModuleDocument(env *feedEnv, rels []publication) (map[string]any, error) {
	newest, err := puppetRelease(env, rels[len(rels)-1])
	if err != nil {
		return nil, err
	}
	module, _ := newest["module"].(map[string]any)
	if module == nil {
		return nil, fmt.Errorf("the release document of %s names no module", rels[0].Pkg.Name)
	}
	var brief []map[string]any
	for i := len(rels) - 1; i >= 0; i-- {
		doc, err := puppetRelease(env, rels[i])
		if err != nil {
			return nil, err
		}
		brief = append(brief, map[string]any{
			"uri": doc["uri"], "slug": doc["slug"], "version": doc["version"], "supported": doc["supported"],
			"created_at": doc["created_at"], "deleted_at": nil, "file_uri": doc["file_uri"], "file_size": doc["file_size"],
		})
	}
	return map[string]any{
		"uri": module["uri"], "slug": module["slug"], "name": module["name"], "downloads": 0,
		"created_at": puppetForgeTime(puppetListedAt(rels[0])), "updated_at": newest["updated_at"],
		"deprecated_at": nil, "deprecated_for": nil, "superseded_by": nil, "supported": false, "endorsement": nil,
		"module_group": "base", "owner": module["owner"], "premium": false, "login_required": false,
		"followers_count": 0, "followed": false, "current_release": newest, "releases": brief,
		"feedback_score": nil, "homepage_url": nil, "issues_url": nil,
	}, nil
}

// puppetResumed: the restarted mirror read the newest-first listing from its
// top, did not enumerate the modules again, and read the module document of
// the late release's module alone — the releases it had seen before the
// restart were remembered with the mark.
func puppetResumed(env *feedEnv, requests []string) error {
	late, _ := env.Publication(pkgLate)
	read := false
	for _, line := range requests {
		u, err := url.Parse(requestURI(line))
		if err != nil {
			return err
		}
		switch {
		case u.Path == "/v3/releases" && u.Query().Get("sort_by") == "module":
			return fmt.Errorf("the modules were enumerated again: %s", line)
		case u.Path == "/v3/releases":
			if !read && u.Query().Get("offset") != "0" {
				return fmt.Errorf("the first read of the listing did not start at its top: %s", line)
			}
			read = true
		case strings.HasPrefix(u.Path, "/v3/modules/") && u.Path != "/v3/modules/"+late.Pkg.Name:
			return fmt.Errorf("a module mirrored before the restart was reported again: %s", line)
		}
	}
	if !read {
		return fmt.Errorf("the release listing was not read")
	}
	return nil
}
