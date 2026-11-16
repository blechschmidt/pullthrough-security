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

// npm: the adapter follows a CouchDB-style replication feed — the root's
// update_seq, `_changes?since=<seq>` and, to enumerate, `_all_docs` — and
// reads each package's packument through the proxy. The stub serves the feed
// at /replicate (feed option url, the way a private registry names its
// replica), one sequence number per publication.

func init() {
	register(row{
		Type:  "npm",
		Feed:  "CouchDB replication feed: root update_seq, `_changes`, `_all_docs`",
		Start: npmFeedStart,
		Options: func(env *feedEnv) map[string]string {
			return map[string]string{"url": env.URL() + "/replicate"}
		},
		Resumed: npmResumed,
	})
}

func npmFeedStart(env *feedEnv) error {
	env.Stub.Handle("/replicate/", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, map[string]any{"db_name": "registry", "update_seq": len(env.Publications())})
	})
	env.Stub.Handle("/replicate/_changes", func(w http.ResponseWriter, r *http.Request) {
		since, err := strconv.Atoi(r.URL.Query().Get("since"))
		if err != nil {
			http.Error(w, "since must be a sequence", http.StatusBadRequest)
			return
		}
		limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
		results := []map[string]any{}
		last := since
		for _, p := range env.Publications() {
			if p.Seq <= since || (limit > 0 && len(results) >= limit) {
				continue
			}
			results = append(results, map[string]any{"seq": p.Seq, "id": p.Pkg.Name, "changes": []map[string]string{{"rev": "1-" + p.Variant}}})
			last = p.Seq
		}
		writeJSON(w, map[string]any{"results": results, "last_seq": last})
	})
	env.Stub.Handle("/replicate/_all_docs", func(w http.ResponseWriter, r *http.Request) {
		var after string
		if raw := r.URL.Query().Get("startkey"); raw != "" {
			if err := json.Unmarshal([]byte(raw), &after); err != nil {
				http.Error(w, "startkey must be a JSON string", http.StatusBadRequest)
				return
			}
		}
		var ids []string
		for _, p := range env.Publications() {
			if p.Pkg.Name >= after {
				ids = append(ids, p.Pkg.Name)
			}
		}
		sort.Strings(ids)
		rows := []map[string]any{}
		for _, id := range ids {
			rows = append(rows, map[string]any{"id": id, "key": id, "value": map[string]string{"rev": "1-x"}})
		}
		writeJSON(w, map[string]any{"total_rows": len(rows), "offset": 0, "rows": rows})
	})
	return nil
}

// npmResumed: the restarted mirror read _changes from the sequence it stored
// (the malicious package's, 3) and did not list the registry again.
func npmResumed(env *feedEnv, requests []string) error {
	read := false
	for _, line := range requests {
		uri := requestURI(line)
		switch {
		case strings.HasPrefix(uri, "/replicate/_all_docs"):
			return fmt.Errorf("the registry was listed again: %s", line)
		case strings.HasPrefix(uri, "/replicate/_changes"):
			u, err := url.Parse(uri)
			if err != nil {
				return err
			}
			if !read && u.Query().Get("since") != "3" {
				return fmt.Errorf("the first read of _changes continued from %q, want the stored sequence 3", u.Query().Get("since"))
			}
			read = true
		}
	}
	if !read {
		return fmt.Errorf("_changes was not read")
	}
	return nil
}
