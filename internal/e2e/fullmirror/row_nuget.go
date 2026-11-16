//go:build integration
// +build integration

package fullmirror

import (
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// NuGet: the adapter follows a v3 feed's catalog — the `Catalog/3.0.0`
// resource of the service index: an index of pages, each page a set of leaves
// (PackageDetails, PackageDelete), every page and leaf stamped with the commit
// that wrote it — by commit timestamp: the pages committed after the stored
// timestamp, their newer leaves in commit order. Bootstrap replays the catalog
// from its first page. Each package's versions come from the flat container
// (`PackageBaseAddress/3.0.0`), read through the proxy.
//
// The stub registry plays nuget.org, whose service index names the catalog;
// the LLM package-scan suite's service index names only the flat container and
// the registrations, so the stub serves that document in front of the
// registry with the Catalog/3.0.0 resource added, the way nuget.org lists it.
// The catalog itself is computed from the publications at request time, as
// NuGet's append-only catalog writer builds it: one commit per batch of
// packages published together (one commit id and timestamp, the time of the
// push to 100 ns), its leaves all on one page — the newest page when they fit,
// else a new one. How many leaves a page holds is the writer's choice
// (nuget.org's hold thousands); the stub's hold two, so that the catalog has a
// page per batch and the pages a poll reads show where the mirror continued.
// The flat container and the .nupkg are the stub registry's own. Feed option
// settle zero: the stub's flat container lists a version before the catalog
// commits it.

func init() {
	register(row{
		Type:  "nuget",
		Feed:  "the service index's `Catalog/3.0.0`: catalog index and pages (append-only, commit timestamps, two leaves a page)",
		Start: nugetFeedStart,
		Options: func(*feedEnv) map[string]string {
			return map[string]string{"settle": "0s"}
		},
		Resumed: nugetResumed,
		Notes: []string{
			"the catalog's leaf documents (`/v3/catalog0/data/…`) are not served: the adapter reads the index and the pages only",
		},
	})
}

// nugetPageSize is how many leaves the stub's catalog writer puts on a page.
const nugetPageSize = 2

// nugetCatalogContext is the JSON-LD context of nuget.org's catalog index and
// pages.
var nugetCatalogContext = map[string]any{
	"@vocab":            "http://schema.nuget.org/catalog#",
	"nuget":             "http://schema.nuget.org/schema#",
	"items":             map[string]any{"@id": "item", "@container": "@set"},
	"parent":            map[string]any{"@type": "@id"},
	"commitTimeStamp":   map[string]any{"@type": "http://www.w3.org/2001/XMLSchema#dateTime"},
	"nuget:lastCreated": map[string]any{"@type": "http://www.w3.org/2001/XMLSchema#dateTime"},
	"nuget:lastEdited":  map[string]any{"@type": "http://www.w3.org/2001/XMLSchema#dateTime"},
	"nuget:lastDeleted": map[string]any{"@type": "http://www.w3.org/2001/XMLSchema#dateTime"},
}

// nugetCommit is one commit of the catalog: the packages pushed together.
type nugetCommit struct {
	id   string
	ts   time.Time
	pubs []publication
}

// nugetCatalogPage is one page of the catalog, its leaves' commits in order.
type nugetCatalogPage struct {
	commits []nugetCommit
	leaves  int
}

// last is the newest commit on the page: the page's commitId and
// commitTimeStamp.
func (p nugetCatalogPage) last() nugetCommit { return p.commits[len(p.commits)-1] }

// nugetCatalog lays out the catalog of the packages published so far.
func nugetCatalog(pubs []publication) []nugetCatalogPage {
	var commits []nugetCommit
	for _, p := range pubs {
		if n := len(commits); n > 0 && commits[n-1].pubs[0].Time.Equal(p.Time) {
			commits[n-1].pubs = append(commits[n-1].pubs, p)
			continue
		}
		// The commit timestamp is a .NET DateTime: 100 ns ticks.
		ts := p.Time.UTC().Truncate(100 * time.Nanosecond)
		sum := sha1.Sum([]byte("pullthrough fullmirror e2e catalog commit " + ts.Format(time.RFC3339Nano)))
		h := hex.EncodeToString(sum[:16])
		id := h[0:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:32]
		commits = append(commits, nugetCommit{id: id, ts: ts, pubs: []publication{p}})
	}
	var pages []nugetCatalogPage
	for _, c := range commits {
		if n := len(pages); n == 0 || pages[n-1].leaves+len(c.pubs) > nugetPageSize {
			pages = append(pages, nugetCatalogPage{})
		}
		page := &pages[len(pages)-1]
		page.commits = append(page.commits, c)
		page.leaves += len(c.pubs)
	}
	return pages
}

// nugetStamp spells a commit timestamp as nuget.org does: up to seven
// fractional digits, trailing zeros dropped.
func nugetStamp(t time.Time) string { return t.UTC().Format("2006-01-02T15:04:05.9999999Z07:00") }

func nugetPageURL(env *feedEnv, n int) string {
	return fmt.Sprintf("%s/v3/catalog0/page%d.json", env.URL(), n)
}

func nugetFeedStart(env *feedEnv) error {
	// nuget.org's service index: the stub registry's resources and the catalog.
	raw, err := env.fetch("/v3/index.json")
	if err != nil {
		return err
	}
	var index map[string]any
	if err := json.Unmarshal(raw, &index); err != nil {
		return fmt.Errorf("the stub registry's service index: %w", err)
	}
	resources, _ := index["resources"].([]any)
	index["resources"] = append(resources, map[string]any{
		"@id": env.URL() + "/v3/catalog0/index.json", "@type": "Catalog/3.0.0", "comment": "Index of the NuGet package catalog.",
	})
	body, err := json.Marshal(index)
	if err != nil {
		return err
	}
	env.Stub.File("/v3/index.json", body, "application/json")

	indexURL := env.URL() + "/v3/catalog0/index.json"
	env.Stub.Handle("/v3/catalog0/index.json", func(w http.ResponseWriter, r *http.Request) {
		pages := nugetCatalog(env.Publications())
		if len(pages) == 0 {
			http.NotFound(w, r)
			return
		}
		items := make([]map[string]any, 0, len(pages))
		for i, p := range pages {
			items = append(items, map[string]any{
				"@id": nugetPageURL(env, i), "@type": "CatalogPage",
				"commitId": p.last().id, "commitTimeStamp": nugetStamp(p.last().ts), "count": p.leaves,
			})
		}
		last := pages[len(pages)-1].last()
		writeJSON(w, map[string]any{
			"@id": indexURL, "@type": []string{"CatalogRoot", "AppendOnlyCatalog", "Permalink"},
			"commitId": last.id, "commitTimeStamp": nugetStamp(last.ts), "count": len(pages),
			"nuget:lastCreated": nugetStamp(last.ts), "nuget:lastEdited": nugetStamp(last.ts),
			"items": items, "@context": nugetCatalogContext,
		})
	})
	env.Stub.Fallback(func(w http.ResponseWriter, r *http.Request) bool {
		var n int
		if _, err := fmt.Sscanf(r.URL.Path, "/v3/catalog0/page%d.json", &n); err != nil || nugetPageURL(env, n) != env.URL()+r.URL.Path {
			return false
		}
		pages := nugetCatalog(env.Publications())
		if n < 0 || n >= len(pages) {
			return false
		}
		p := pages[n]
		var items []map[string]any
		for _, c := range p.commits {
			for _, pub := range c.pubs {
				items = append(items, map[string]any{
					"@id": fmt.Sprintf("%s/v3/catalog0/data/%s/%s.%s.json", env.URL(), c.ts.Format("2006.01.02.15.04.05"),
						strings.ToLower(pub.Pkg.Name), strings.ToLower(pub.Pkg.Version)),
					"@type": "nuget:PackageDetails", "commitId": c.id, "commitTimeStamp": nugetStamp(c.ts),
					"nuget:id": pub.Pkg.Name, "nuget:version": pub.Pkg.Version,
				})
			}
		}
		writeJSON(w, map[string]any{
			"@id": nugetPageURL(env, n), "@type": "CatalogPage",
			"commitId": p.last().id, "commitTimeStamp": nugetStamp(p.last().ts), "count": p.leaves,
			"parent": indexURL, "items": items, "@context": nugetCatalogContext,
		})
		return true
	})
	return nil
}

// nugetResumed: the restarted mirror read the catalog index and, of its pages,
// only the one committed after the stored timestamp — the late package's —
// not the pages it had read before the restart (a replay begins with page0).
func nugetResumed(env *feedEnv, requests []string) error {
	want := ""
	for i, p := range nugetCatalog(env.Publications()) {
		for _, c := range p.commits {
			for _, pub := range c.pubs {
				if pub.Variant == pkgLate {
					want = strings.TrimPrefix(nugetPageURL(env, i), env.URL())
				}
			}
		}
	}
	index, read := false, false
	for _, line := range requests {
		switch path := requestPath(line); {
		case path == "/v3/catalog0/index.json":
			index = true
		case strings.HasPrefix(path, "/v3/catalog0/page"):
			if path != want {
				return fmt.Errorf("the restarted mirror read %s, a page committed before the stored timestamp (want %s alone)", path, want)
			}
			read = true
		}
	}
	if !index || !read {
		return fmt.Errorf("the restarted mirror did not read the catalog index and %s (index read %v, page read %v)", want, index, read)
	}
	return nil
}
