package provgraph

import "testing"

// "Shipped in release X" (Task 180): a release node with shipped-in edges from
// the versions it pins, visible per tenant, reached by a blast radius.
func TestReleasesShipVersions(t *testing.T) {
	s := New(Options{})
	s.Ingest(Event{Artifact: ArtifactRef{Ecosystem: "npm", Name: "left-pad", Version: "1.0.0"}, CVEs: []CVERef{{ID: "CVE-2026-1"}}})
	s.IngestRelease(ReleaseEvent{Repo: "widgets", Commit: "aaaa", Tenant: "team-a", Tags: []string{"v1.0"}, State: "current", Status: "pinned",
		Dependencies: []ArtifactRef{{Ecosystem: "npm", Name: "left-pad", Version: "1.0.0"}}, Statuses: []string{"pinned"}})
	s.IngestRelease(ReleaseEvent{Repo: "gadgets", Commit: "cccc", Tenant: "team-b", State: "current", Status: "pinned",
		Dependencies: []ArtifactRef{{Ecosystem: "npm", Name: "left-pad", Version: "1.0.0"}}})

	all := s.ReleasesOf("", "npm", "left-pad", "1.0.0")
	if len(all) != 2 {
		t.Fatalf("releases: %+v", all)
	}
	a := s.ReleasesOf("team-a", "npm", "left-pad", "")
	if len(a) != 1 || a[0].Repo != "widgets" || a[0].Tags[0] != "v1.0" || a[0].DependencyStatus != "pinned" {
		t.Fatalf("team-a: %+v", a)
	}

	// The tag moves away: the release becomes historical, its tags empty.
	s.IngestRelease(ReleaseEvent{Repo: "widgets", Commit: "aaaa", Tenant: "team-a", State: "historical", Status: "pinned"})
	if r := s.ReleasesOf("team-a", "npm", "left-pad", "1.0.0"); len(r) != 1 || r[0].State != "historical" || len(r[0].Tags) != 0 {
		t.Fatalf("historical: %+v", r)
	}

	blast, err := s.BlastRadius(SeedCVE, "CVE-2026-1")
	if err != nil || len(blast.Releases) != 2 {
		t.Fatalf("blast radius: %v %+v", err, blast.Releases)
	}
	if scoped := blast.ScopeReleases("team-b"); len(scoped.Releases) != 1 || scoped.Releases[0].Repo != "gadgets" {
		t.Fatalf("scoped blast radius: %+v", scoped.Releases)
	}
	doc := s.Export().ScopeReleases("team-b")
	for _, n := range doc.Nodes {
		if n.Kind == NodeRelease && n.Attrs["tenant"] != "team-b" {
			t.Fatalf("team-b sees %s", n.ID)
		}
	}
	for _, e := range doc.Edges {
		if e.To == releaseID("widgets", "aaaa") {
			t.Fatal("an edge to another tenant's release survived scoping")
		}
	}
}
