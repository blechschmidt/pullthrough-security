package provgraph

import (
	"testing"
	"time"
)

// newTestService builds a Service with a fixed clock for deterministic tests.
func newTestService(t *testing.T) *Service {
	t.Helper()
	s := New(Options{})
	clock := time.Unix(1_700_000_000, 0).UTC()
	s.now = func() time.Time { clock = clock.Add(time.Second); return clock }
	return s
}

// ingestChain builds a small supply chain:
//
//	app@1.0.0 (built from commit abc, signed by ci, affected by CVE-APP)
//	  depends-on lib@2.0.0 (affected by CVE-LIB)
//	    depends-on leaf@3.0.0
func ingestChain(s *Service) {
	s.Ingest(Event{
		Artifact: ArtifactRef{Ecosystem: "npm", Name: "app", Version: "1.0.0", Digest: "sha256:app"},
		Commit:   &CommitRef{SHA: "abcdef1234567890", RepositoryURL: "https://github.com/acme/app", Confidence: "attested", RiskScore: 10},
		Dependencies: []ArtifactRef{
			{Ecosystem: "npm", Name: "lib", Version: "2.0.0"},
		},
		CVEs:    []CVERef{{ID: "CVE-APP", Severity: "high", CVSS: 7.5}},
		Signers: []SignerRef{{Identity: "https://github.com/acme/app/.github/workflows/release.yml@refs/heads/main", Verified: true, Keyless: true}},
	})
	s.Ingest(Event{
		Artifact: ArtifactRef{Ecosystem: "npm", Name: "lib", Version: "2.0.0"},
		Dependencies: []ArtifactRef{
			{Ecosystem: "npm", Name: "leaf", Version: "3.0.0"},
		},
		CVEs: []CVERef{{ID: "CVE-LIB", Severity: "critical", CVSS: 9.8}},
	})
	s.Ingest(Event{
		Artifact: ArtifactRef{Ecosystem: "npm", Name: "leaf", Version: "3.0.0"},
	})
}

func TestIngest_BuildsNodesAndEdges(t *testing.T) {
	s := newTestService(t)
	ingestChain(s)

	snap := s.Snapshot()
	// packages: app, lib, leaf ; versions: app@1, lib@2, leaf@3 ; commit: abc ;
	// cves: CVE-APP, CVE-LIB ; signer: ci => 3+3+1+2+1 = 10 nodes.
	if snap.NodesByKind[string(NodePackage)] != 3 {
		t.Errorf("packages = %d, want 3", snap.NodesByKind[string(NodePackage)])
	}
	if snap.NodesByKind[string(NodeVersion)] != 3 {
		t.Errorf("versions = %d, want 3", snap.NodesByKind[string(NodeVersion)])
	}
	if snap.NodesByKind[string(NodeCommit)] != 1 {
		t.Errorf("commits = %d, want 1", snap.NodesByKind[string(NodeCommit)])
	}
	if snap.NodesByKind[string(NodeCVE)] != 2 {
		t.Errorf("cves = %d, want 2", snap.NodesByKind[string(NodeCVE)])
	}
	if snap.NodesByKind[string(NodeSigner)] != 1 {
		t.Errorf("signers = %d, want 1", snap.NodesByKind[string(NodeSigner)])
	}
	if snap.EventsIngested != 3 {
		t.Errorf("eventsIngested = %d, want 3", snap.EventsIngested)
	}
	// depends-on: app->lib, lib->leaf => 2.
	if snap.EdgesByKind[string(EdgeDependsOn)] != 2 {
		t.Errorf("depends-on edges = %d, want 2", snap.EdgesByKind[string(EdgeDependsOn)])
	}
	if snap.EdgesByKind[string(EdgeBuiltFromCommit)] != 1 {
		t.Errorf("built-from-commit edges = %d, want 1", snap.EdgesByKind[string(EdgeBuiltFromCommit)])
	}
	if snap.EdgesByKind[string(EdgeAffectedByCVE)] != 2 {
		t.Errorf("affected-by-cve edges = %d, want 2", snap.EdgesByKind[string(EdgeAffectedByCVE)])
	}
}

func TestIngest_Idempotent(t *testing.T) {
	s := newTestService(t)
	ingestChain(s)
	before := s.Snapshot()
	ingestChain(s) // re-ingest identical events
	after := s.Snapshot()
	if before.Nodes != after.Nodes {
		t.Errorf("node count changed on re-ingest: %d -> %d", before.Nodes, after.Nodes)
	}
	if before.Edges != after.Edges {
		t.Errorf("edge count changed on re-ingest: %d -> %d", before.Edges, after.Edges)
	}
}

func TestIngest_DropsArtifactWithoutName(t *testing.T) {
	s := newTestService(t)
	s.Ingest(Event{Artifact: ArtifactRef{Ecosystem: "npm", Version: "1.0.0"}})
	if got := s.Snapshot().Nodes; got != 0 {
		t.Errorf("expected no nodes for nameless artifact, got %d", got)
	}
}

func TestBlastRadius_CVE_TransitiveDependents(t *testing.T) {
	s := newTestService(t)
	ingestChain(s)

	// CVE-LIB directly affects lib@2.0.0; app@1.0.0 depends on it transitively.
	res, err := s.BlastRadius(SeedCVE, "CVE-LIB")
	if err != nil {
		t.Fatalf("BlastRadius: %v", err)
	}
	if !res.Found {
		t.Fatal("expected CVE-LIB to be found")
	}
	if res.Total != 2 {
		t.Fatalf("total affected = %d, want 2 (lib direct, app transitive)", res.Total)
	}
	if res.Direct != 1 {
		t.Errorf("direct = %d, want 1", res.Direct)
	}
	// First entry is the direct one (lib), second the transitive consumer (app).
	if res.Artifacts[0].Name != "lib" || !res.Artifacts[0].Direct {
		t.Errorf("first affected = %+v, want lib (direct)", res.Artifacts[0])
	}
	if res.Artifacts[1].Name != "app" || res.Artifacts[1].Direct || res.Artifacts[1].Distance != 1 {
		t.Errorf("second affected = %+v, want app (transitive, distance 1)", res.Artifacts[1])
	}
}

func TestBlastRadius_Commit(t *testing.T) {
	s := newTestService(t)
	ingestChain(s)

	res, err := s.BlastRadius(SeedCommit, "abcdef1234567890")
	if err != nil {
		t.Fatalf("BlastRadius: %v", err)
	}
	if res.Total != 1 || res.Artifacts[0].Name != "app" {
		t.Errorf("commit blast = %+v, want only app", res.Artifacts)
	}
}

func TestBlastRadius_UnknownSeed(t *testing.T) {
	s := newTestService(t)
	ingestChain(s)
	_, err := s.BlastRadius(SeedCVE, "CVE-DOES-NOT-EXIST")
	if err != ErrNotFound {
		t.Errorf("err = %v, want ErrNotFound", err)
	}
}

func TestReverseDependencies(t *testing.T) {
	s := newTestService(t)
	ingestChain(s)

	// leaf@3.0.0 is depended on by lib (direct) and app (transitive).
	res, err := s.ReverseDependencies("npm", "leaf", "3.0.0")
	if err != nil {
		t.Fatalf("ReverseDependencies: %v", err)
	}
	if res.Total != 2 {
		t.Fatalf("total dependents = %d, want 2", res.Total)
	}
	if res.Dependents[0].Name != "lib" || !res.Dependents[0].Direct {
		t.Errorf("first dependent = %+v, want lib (direct)", res.Dependents[0])
	}
	if res.Dependents[1].Name != "app" || res.Dependents[1].Distance != 2 {
		t.Errorf("second dependent = %+v, want app (distance 2)", res.Dependents[1])
	}
}

func TestForwardDependencies(t *testing.T) {
	s := newTestService(t)
	ingestChain(s)

	// app@1.0.0 directly depends on lib@2.0.0.
	res, err := s.ForwardDependencies("npm", "app", "1.0.0")
	if err != nil {
		t.Fatalf("ForwardDependencies: %v", err)
	}
	if !res.Found {
		t.Fatal("expected app to be found")
	}
	if res.Total != 1 || res.Direct != 1 {
		t.Fatalf("total=%d direct=%d, want 1/1", res.Total, res.Direct)
	}
	d := res.Dependents[0]
	if d.Name != "lib" || d.Version != "2.0.0" || d.Ecosystem != "npm" || !d.Direct {
		t.Errorf("dependency = %+v, want lib@2.0.0 (direct)", d)
	}

	// leaf is a leaf node: no forward dependencies.
	leaf, err := s.ForwardDependencies("npm", "leaf", "3.0.0")
	if err != nil {
		t.Fatalf("ForwardDependencies(leaf): %v", err)
	}
	if leaf.Total != 0 {
		t.Errorf("leaf should have no dependencies, got %d", leaf.Total)
	}

	// An unknown artifact returns ErrNotFound.
	if _, err := s.ForwardDependencies("npm", "ghost", "9.9.9"); err != ErrNotFound {
		t.Errorf("unknown artifact err = %v, want ErrNotFound", err)
	}
}

func TestPathToCommit_Direct(t *testing.T) {
	s := newTestService(t)
	ingestChain(s)

	res, err := s.PathToCommit("npm", "app", "1.0.0")
	if err != nil {
		t.Fatalf("PathToCommit: %v", err)
	}
	if !res.Found {
		t.Fatal("expected a path to commit for app")
	}
	if res.CommitSHA != "abcdef1234567890" {
		t.Errorf("commitSha = %q, want abcdef1234567890", res.CommitSHA)
	}
	if len(res.Steps) != 1 || res.Steps[0].Kind != EdgeBuiltFromCommit {
		t.Errorf("steps = %+v, want one built-from-commit step", res.Steps)
	}
}

func TestPathToCommit_ThroughDependency(t *testing.T) {
	s := newTestService(t)
	// lib has no provenance of its own but depends on app, which does.
	s.Ingest(Event{
		Artifact:     ArtifactRef{Ecosystem: "npm", Name: "lib", Version: "2.0.0"},
		Dependencies: []ArtifactRef{{Ecosystem: "npm", Name: "app", Version: "1.0.0"}},
	})
	s.Ingest(Event{
		Artifact: ArtifactRef{Ecosystem: "npm", Name: "app", Version: "1.0.0"},
		Commit:   &CommitRef{SHA: "deadbeefcafebabe"},
	})

	res, err := s.PathToCommit("npm", "lib", "2.0.0")
	if err != nil {
		t.Fatalf("PathToCommit: %v", err)
	}
	if !res.Found || res.CommitSHA != "deadbeefcafebabe" {
		t.Fatalf("path = %+v, want path to deadbeefcafebabe", res)
	}
	if len(res.Steps) != 2 {
		t.Fatalf("steps = %d, want 2 (depends-on then built-from-commit)", len(res.Steps))
	}
	if res.Steps[0].Kind != EdgeDependsOn || res.Steps[1].Kind != EdgeBuiltFromCommit {
		t.Errorf("step kinds = %s,%s; want depends-on,built-from-commit", res.Steps[0].Kind, res.Steps[1].Kind)
	}
}

func TestPathToCommit_NoCommit(t *testing.T) {
	s := newTestService(t)
	s.Ingest(Event{Artifact: ArtifactRef{Ecosystem: "npm", Name: "lonely", Version: "1.0.0"}})
	res, err := s.PathToCommit("npm", "lonely", "1.0.0")
	if err != nil {
		t.Fatalf("PathToCommit: %v", err)
	}
	if res.Found {
		t.Errorf("expected no path, got %+v", res)
	}
}

func TestPathToCommit_UnknownArtifact(t *testing.T) {
	s := newTestService(t)
	_, err := s.PathToCommit("npm", "ghost", "9.9.9")
	if err != ErrNotFound {
		t.Errorf("err = %v, want ErrNotFound", err)
	}
}

func TestExport_FormatAndDetachment(t *testing.T) {
	s := newTestService(t)
	ingestChain(s)

	doc := s.Export()
	if len(doc.Nodes) != doc.Stats.Nodes {
		t.Errorf("exported %d nodes but stats says %d", len(doc.Nodes), doc.Stats.Nodes)
	}
	if len(doc.Edges) != doc.Stats.Edges {
		t.Errorf("exported %d edges but stats says %d", len(doc.Edges), doc.Stats.Edges)
	}
	// Nodes must be sorted by id for deterministic output.
	for i := 1; i < len(doc.Nodes); i++ {
		if doc.Nodes[i-1].ID > doc.Nodes[i].ID {
			t.Fatalf("nodes not sorted: %q before %q", doc.Nodes[i-1].ID, doc.Nodes[i].ID)
		}
	}
	// Mutating the exported document must not affect the live graph.
	if len(doc.Nodes) > 0 {
		doc.Nodes[0].Attrs["tampered"] = "yes"
	}
	again := s.Export()
	for _, n := range again.Nodes {
		if _, ok := n.Attrs["tampered"]; ok {
			t.Fatal("export is not detached from the live graph")
		}
	}
}

func TestCVE_AttributedToTransitiveComponent(t *testing.T) {
	s := newTestService(t)
	// The scanned artifact is app@1.0.0 but the finding names a different
	// component (a transitive dependency); the CVE must attach to that component.
	s.Ingest(Event{
		Artifact: ArtifactRef{Ecosystem: "npm", Name: "app", Version: "1.0.0"},
		Dependencies: []ArtifactRef{
			{Ecosystem: "npm", Name: "transitive", Version: "0.1.0"},
		},
		CVEs: []CVERef{{ID: "CVE-T", Severity: "high", Package: "transitive", Version: "0.1.0"}},
	})

	res, err := s.BlastRadius(SeedCVE, "CVE-T")
	if err != nil {
		t.Fatalf("BlastRadius: %v", err)
	}
	// transitive is directly affected; app is a transitive consumer.
	names := map[string]bool{}
	for _, a := range res.Artifacts {
		names[a.Name] = true
	}
	if !names["transitive"] || !names["app"] {
		t.Errorf("blast = %+v, want both transitive (direct) and app (consumer)", res.Artifacts)
	}
}
