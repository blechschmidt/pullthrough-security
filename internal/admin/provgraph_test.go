package admin

import (
	"net/http"
	"testing"

	"github.com/blechschmidt/pullthrough-security/internal/provgraph"
)

func seededGraph(t *testing.T) *provgraph.Service {
	t.Helper()
	svc := provgraph.New(provgraph.Options{})
	svc.Ingest(provgraph.Event{
		Artifact:     provgraph.ArtifactRef{Ecosystem: "npm", Name: "app", Version: "1.0.0"},
		Commit:       &provgraph.CommitRef{SHA: "abcdef1234567890", RepositoryURL: "https://github.com/acme/app"},
		Dependencies: []provgraph.ArtifactRef{{Ecosystem: "npm", Name: "lib", Version: "2.0.0"}},
	})
	svc.Ingest(provgraph.Event{
		Artifact: provgraph.ArtifactRef{Ecosystem: "npm", Name: "lib", Version: "2.0.0"},
		CVEs:     []provgraph.CVERef{{ID: "CVE-2024-9999", Severity: "critical"}},
	})
	return svc
}

func TestProvgraphStatsAndExport(t *testing.T) {
	srv := newTestServer(t, Options{Provgraph: seededGraph(t)})

	var stats struct {
		Enabled bool `json:"enabled"`
		Stats   struct {
			Nodes int `json:"nodes"`
			Edges int `json:"edges"`
		} `json:"stats"`
	}
	if code := getJSON(t, srv, "/admin/api/provgraph", "", &stats); code != http.StatusOK {
		t.Fatalf("stats status = %d", code)
	}
	if !stats.Enabled || stats.Stats.Nodes == 0 || stats.Stats.Edges == 0 {
		t.Fatalf("unexpected stats: %+v", stats)
	}

	var doc struct {
		Nodes []struct {
			ID   string `json:"id"`
			Kind string `json:"kind"`
		} `json:"nodes"`
		Edges []struct {
			Kind string `json:"kind"`
		} `json:"edges"`
		Stats struct {
			Nodes int `json:"nodes"`
		} `json:"stats"`
	}
	if code := getJSON(t, srv, "/admin/api/provgraph/export", "", &doc); code != http.StatusOK {
		t.Fatalf("export status = %d", code)
	}
	if len(doc.Nodes) != doc.Stats.Nodes || len(doc.Nodes) == 0 {
		t.Fatalf("export node count mismatch: %d vs stats %d", len(doc.Nodes), doc.Stats.Nodes)
	}
	if len(doc.Edges) == 0 {
		t.Fatal("export returned no edges")
	}
}

func TestProvgraphBlastEndpoint(t *testing.T) {
	srv := newTestServer(t, Options{Provgraph: seededGraph(t)})

	var res struct {
		Found     bool `json:"found"`
		Total     int  `json:"total"`
		Direct    int  `json:"direct"`
		Artifacts []struct {
			Name   string `json:"name"`
			Direct bool   `json:"direct"`
		} `json:"artifacts"`
	}
	// CVE affects lib directly and app transitively; type inferred from the id.
	if code := getJSON(t, srv, "/admin/api/provgraph/blast?id=CVE-2024-9999", "", &res); code != http.StatusOK {
		t.Fatalf("blast status = %d", code)
	}
	if !res.Found || res.Total != 2 || res.Direct != 1 {
		t.Fatalf("blast result = %+v", res)
	}

	// An unknown seed is a successful empty result, not an error.
	var empty struct {
		Found bool `json:"found"`
	}
	if code := getJSON(t, srv, "/admin/api/provgraph/blast?id=CVE-0000-0000", "", &empty); code != http.StatusOK {
		t.Fatalf("unknown-seed status = %d", code)
	}
	if empty.Found {
		t.Error("unknown CVE should report found=false")
	}
}

func TestProvgraphPathAndReverseEndpoints(t *testing.T) {
	srv := newTestServer(t, Options{Provgraph: seededGraph(t)})

	var path struct {
		Found     bool   `json:"found"`
		CommitSHA string `json:"commitSha"`
	}
	if code := getJSON(t, srv, "/admin/api/provgraph/path?ecosystem=npm&name=app&version=1.0.0", "", &path); code != http.StatusOK {
		t.Fatalf("path status = %d", code)
	}
	if !path.Found || path.CommitSHA != "abcdef1234567890" {
		t.Fatalf("path result = %+v", path)
	}

	var rev struct {
		Total      int `json:"total"`
		Dependents []struct {
			Name string `json:"name"`
		} `json:"dependents"`
	}
	if code := getJSON(t, srv, "/admin/api/provgraph/reverse?ecosystem=npm&name=lib&version=2.0.0", "", &rev); code != http.StatusOK {
		t.Fatalf("reverse status = %d", code)
	}
	if rev.Total != 1 || rev.Dependents[0].Name != "app" {
		t.Fatalf("reverse result = %+v", rev)
	}
}

func TestProvgraphDisabled(t *testing.T) {
	srv := newTestServer(t, Options{})
	var resp struct {
		Enabled bool `json:"enabled"`
	}
	if code := getJSON(t, srv, "/admin/api/provgraph", "", &resp); code != http.StatusOK {
		t.Fatalf("status = %d", code)
	}
	if resp.Enabled {
		t.Error("provgraph should report disabled when no inspector is wired")
	}
	// The query endpoints 404 when the subsystem is absent.
	if code := getJSON(t, srv, "/admin/api/provgraph/export", "", nil); code != http.StatusNotFound {
		t.Errorf("export status = %d, want 404", code)
	}
}
