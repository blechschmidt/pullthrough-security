//go:build integration
// +build integration

package fullmirror

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Ansible: the adapter follows Galaxy NG's search of collection versions —
// /api/v3/plugin/ansible/search/collection-versions/ ordered by
// -pulp_created and filtered by distribution_base_path (the upstream's
// repository setting, "published"), offset-paged — from its first page down
// to its high-water mark and a day below it (listfeed.go), and reports every
// version it has not seen there. Bootstrap takes the mark from the search,
// then enumerates the repository's collection index. A collection's versions
// come from its versions list, read from the registry directly (the gated
// pipeline takes no query).
//
// The stub serves both lists as galaxy_ng does, in front of the LLM package-
// scan suite's registry (which serves the versions lists, the version details
// and the artifacts a client reads): the search lists every version the
// registry published, newest first by pulp_created — the time of the
// publication — with its repository and the collection version's fields from
// the version's detail document; the collection index lists every collection,
// most recently created first. Both are paged by limit and offset under
// Galaxy's meta and links blocks, and the search lists nothing for another
// distribution. (The versions lists and details that registry serves state an
// older creation time; the mirror decides nothing on it.) The upstream is the
// Galaxy the feed reads, so it needs no feed option url; settle zero.
//
// Both lists date the seed two days back (ansibleSeedAge): published within
// seconds of the others, it would lie in the day below the mark the adapter
// looks back over, where the versions it has seen are remembered whatever its
// mark says — and an adapter restarted without its mark would go unnoticed.
// Two days back, the seed lies below the window of the mark the follow-up
// poll stores: a restarted adapter that continues from that mark stops at it,
// one that lost the mark finds it unseen and reports it again, which
// ansibleResumed refuses (its versions list read) and the suite counts (its
// artifact skipped, cached).

func init() {
	register(row{
		Type:  "ansible",
		Feed:  "Galaxy NG's collection-version search by `-pulp_created` (filtered by distribution) and the collection index, offset-paged",
		Start: ansibleFeedStart,
		Options: func(*feedEnv) map[string]string {
			return map[string]string{"settle": "0s"}
		},
		Resumed: ansibleResumed,
		Notes: []string{
			"settle is zero: holding back versions younger than the settle period (10 minutes by default) is not covered",
			"one version per collection, and the four fit the search's first page: later pages, their overlap, a pass continued in a later poll and a versions list longer than a page are not covered",
			"the refusal of a search that lists nothing while the collection index lists collections (a Galaxy that does not filter by distribution) is not covered",
		},
	})
}

// The lists the stub serves, for the repository "published".
const (
	ansibleSearchPath = "/api/v3/plugin/ansible/search/collection-versions/"
	ansibleIndexPath  = "/api/v3/plugin/ansible/content/published/collections/index/"
)

// ansibleCollectionPath is a collection's path below the index,
// "<namespace>/<name>/".
func ansibleCollectionPath(fqcn string) string { return strings.Replace(fqcn, ".", "/", 1) + "/" }

// ansibleSeedAge is how long before its publication the lists date the seed:
// beyond the day below the mark the adapter looks back over (ansibleLookback
// in internal/fullmirror/feed_ansible.go).
const ansibleSeedAge = 48 * time.Hour

// ansibleListedAt is when the lists say a version's content was created: when
// it was published, the seed two days earlier.
func ansibleListedAt(p publication) time.Time {
	if p.Variant == pkgSeed {
		return p.Time.Add(-ansibleSeedAge)
	}
	return p.Time
}

// ansiblePulpTime spells the time the lists state for a publication the way
// Pulp does.
func ansiblePulpTime(p publication) string {
	return ansibleListedAt(p).UTC().Format("2006-01-02T15:04:05.000000Z07:00")
}

// ansibleHref is a Pulp href of the stub's: a resource named by a UUID
// derived from what it stands for.
func ansibleHref(kind, of string) string {
	sum := sha256.Sum256([]byte(kind + "\x00" + of))
	h := fmt.Sprintf("%x", sum[:16])
	return "/api/pulp/api/v3/" + kind + "/" + h[:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:32] + "/"
}

// ansiblePaging reads limit (Galaxy's default 10) and offset; false when it
// answered the request with an error.
func ansiblePaging(w http.ResponseWriter, q url.Values) (int, int, bool) {
	limit, offset := 10, 0
	for _, f := range []struct {
		name string
		dst  *int
	}{{"limit", &limit}, {"offset", &offset}} {
		name, v := f.name, q.Get(f.name)
		if v == "" {
			continue
		}
		n, err := strconv.Atoi(v)
		if err != nil || n < 0 || (name == "limit" && n == 0) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			_, _ = fmt.Fprintf(w, `{"errors":[{"status":"400","code":"invalid","title":"Invalid input.","detail":"%s must be a positive integer"}]}`, name)
			return 0, 0, false
		}
		*f.dst = n
	}
	return limit, offset, true
}

// ansibleLinks is the links block of a page of a list at path.
func ansibleLinks(path string, q url.Values, limit, offset, count int) map[string]any {
	link := func(off int) string {
		l := url.Values{}
		for k, v := range q {
			l[k] = v
		}
		l.Set("limit", strconv.Itoa(limit))
		l.Set("offset", strconv.Itoa(off))
		return path + "?" + l.Encode()
	}
	links := map[string]any{"first": link(0), "previous": nil, "next": nil, "last": link(max(0, count-limit))}
	if offset > 0 {
		links["previous"] = link(max(0, offset-limit))
	}
	if offset+limit < count {
		links["next"] = link(offset + limit)
	}
	return links
}

// ansibleDetail reads the detail document the registry serves for a
// publication's version.
func ansibleDetail(env *feedEnv, p publication) (map[string]any, error) {
	body, err := env.fetch(ansibleIndexPath + ansibleCollectionPath(p.Pkg.Name) + "versions/" + p.Pkg.Version + "/")
	if err != nil {
		return nil, err
	}
	var doc map[string]any
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, fmt.Errorf("the version detail of %s: %w", p.Pkg.Name, err)
	}
	return doc, nil
}

// ansibleSearchEntry is a publication's version as the search lists it.
func ansibleSearchEntry(env *feedEnv, p publication) (map[string]any, error) {
	detail, err := ansibleDetail(env, p)
	if err != nil {
		return nil, err
	}
	meta, _ := detail["metadata"].(map[string]any)
	ns, name, _ := strings.Cut(p.Pkg.Name, ".")
	var tags []map[string]string
	if list, ok := meta["tags"].([]any); ok {
		for _, t := range list {
			if s, ok := t.(string); ok {
				tags = append(tags, map[string]string{"name": s})
			}
		}
	}
	return map[string]any{
		"repository": map[string]any{
			"pulp_href": ansibleHref("repositories/ansible/ansible", "published"), "name": "published",
			"description": "Certified content repository", "retain_repo_versions": 1, "pulp_labels": map[string]string{"pipeline": "approved"},
		},
		"collection_version": map[string]any{
			"pulp_href": ansibleHref("content/ansible/collection_versions", p.Pkg.Name+"-"+p.Pkg.Version),
			"namespace": ns, "name": name, "version": p.Pkg.Version, "requires_ansible": detail["requires_ansible"],
			"pulp_created": ansiblePulpTime(p), "contents": []any{}, "dependencies": meta["dependencies"],
			"description": meta["description"], "tags": tags,
		},
		"repository_version": "latest", "namespace_metadata": nil, "is_highest": true, "is_deprecated": false, "is_signed": false,
	}, nil
}

// ansibleByCreation sorts publications by the time the lists state, newest
// first or oldest first; of two of one instant, the one published later is
// the newer.
func ansibleByCreation(pubs []publication, newestFirst bool) {
	sort.SliceStable(pubs, func(i, j int) bool {
		a, b := pubs[i], pubs[j]
		if newestFirst {
			a, b = b, a
		}
		if ta, tb := ansibleListedAt(a), ansibleListedAt(b); !ta.Equal(tb) {
			return ta.Before(tb)
		}
		return a.Seq < b.Seq
	})
}

func ansibleFeedStart(env *feedEnv) error {
	env.Stub.Handle(ansibleSearchPath, func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		limit, offset, ok := ansiblePaging(w, q)
		if !ok {
			return
		}
		pubs := env.Publications()
		if base := q.Get("distribution_base_path"); base != "" && base != "published" {
			pubs = nil
		}
		if repo := q.Get("repository_name"); repo != "" && repo != "published" {
			pubs = nil
		}
		switch q.Get("order_by") {
		case "-pulp_created":
			ansibleByCreation(pubs, true)
		case "pulp_created", "":
			ansibleByCreation(pubs, false)
		default:
			http.Error(w, `{"errors":[{"status":"400","code":"invalid","detail":"the stub orders by pulp_created only"}]}`, http.StatusBadRequest)
			return
		}
		data := []map[string]any{}
		for i := offset; i < len(pubs) && i < offset+limit; i++ {
			e, err := ansibleSearchEntry(env, pubs[i])
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			data = append(data, e)
		}
		writeJSON(w, map[string]any{"meta": map[string]int{"count": len(pubs)}, "links": ansibleLinks(ansibleSearchPath, q, limit, offset, len(pubs)), "data": data})
	})
	env.Stub.Handle(ansibleIndexPath, func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		limit, offset, ok := ansiblePaging(w, q)
		if !ok {
			return
		}
		// Every publication is a collection of its own: the most recently
		// created first.
		pubs := env.Publications()
		ansibleByCreation(pubs, true)
		data := []map[string]any{}
		for i := offset; i < len(pubs) && i < offset+limit; i++ {
			p := pubs[i]
			ns, name, _ := strings.Cut(p.Pkg.Name, ".")
			coll := ansibleIndexPath + ansibleCollectionPath(p.Pkg.Name)
			highest := map[string]string{"href": coll + "versions/" + p.Pkg.Version + "/", "version": p.Pkg.Version}
			data = append(data, map[string]any{
				"href": coll, "namespace": ns, "name": name, "deprecated": false, "versions_url": coll + "versions/",
				"highest_version": highest, "created_at": ansiblePulpTime(p), "updated_at": ansiblePulpTime(p), "download_count": 0,
			})
		}
		writeJSON(w, map[string]any{"meta": map[string]int{"count": len(pubs)}, "links": ansibleLinks(ansibleIndexPath, q, limit, offset, len(pubs)), "data": data})
	})
	return nil
}

// ansibleResumed: the restarted mirror read the search from its top, did not
// enumerate the collection index again, and read the versions of the late
// collection alone — the versions it had seen before the restart were
// remembered with the mark.
func ansibleResumed(env *feedEnv, requests []string) error {
	late, _ := env.Publication(pkgLate)
	own := ansibleIndexPath + ansibleCollectionPath(late.Pkg.Name)
	read := false
	for _, line := range requests {
		u, err := url.Parse(requestURI(line))
		if err != nil {
			return err
		}
		switch {
		case u.Path == ansibleIndexPath:
			return fmt.Errorf("the collection index was enumerated again: %s", line)
		case u.Path == ansibleSearchPath:
			if !read && u.Query().Get("offset") != "0" {
				return fmt.Errorf("the first read of the search did not start at its top: %s", line)
			}
			read = true
		case strings.HasPrefix(u.Path, ansibleIndexPath) && !strings.HasPrefix(u.Path, own):
			return fmt.Errorf("a collection mirrored before the restart was reported again: %s", line)
		}
	}
	if !read {
		return fmt.Errorf("the search was not read")
	}
	return nil
}
