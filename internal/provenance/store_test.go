package provenance

import (
	"context"
	"errors"
	"testing"
)

func testLink() *Link {
	return &Link{
		Artifact:      Artifact{Ecosystem: "npm", Name: "lodash", Version: "4.17.21", Digest: "sha512:abc"},
		RepositoryURL: "https://github.com/lodash/lodash",
		CommitSHA:     "f299b52f39486275a9e6483b60a936091f6a82f3",
		Confidence:    ConfidenceAttested,
		ResolverName:  "npm-metadata",
		Attestation:   []byte(`{"dsse":true}`),
	}
}

func runStoreContract(t *testing.T, s LinkStore) {
	t.Helper()
	ctx := context.Background()
	l := testLink()

	if _, err := s.Get(ctx, l.Artifact); !errors.Is(err, ErrNoProvenance) {
		t.Fatalf("Get on empty store = %v, want ErrNoProvenance", err)
	}
	if err := s.Put(ctx, l); err != nil {
		t.Fatalf("Put: %v", err)
	}
	got, err := s.Get(ctx, l.Artifact)
	if err != nil {
		t.Fatalf("Get after Put: %v", err)
	}
	if got.CommitSHA != l.CommitSHA || got.RepositoryURL != l.RepositoryURL {
		t.Errorf("round-trip mismatch: %+v", got)
	}
	if string(got.Attestation) != string(l.Attestation) {
		t.Errorf("attestation not preserved: %q", got.Attestation)
	}

	// Identity falls back to digest: a different coordinate but same digest hits.
	byDigest := Artifact{Ecosystem: "other", Name: "x", Digest: "sha512:abc"}
	if _, err := s.Get(ctx, byDigest); err != nil {
		t.Errorf("Get by digest identity: %v", err)
	}

	list, err := s.List(ctx)
	if err != nil || len(list) != 1 {
		t.Fatalf("List = %d items, %v; want 1", len(list), err)
	}
}

func TestMemoryLinkStore(t *testing.T) { runStoreContract(t, NewMemoryLinkStore()) }

func TestFileLinkStore(t *testing.T) {
	s, err := NewFileLinkStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	runStoreContract(t, s)
}

func TestArtifactKey(t *testing.T) {
	withDigest := ArtifactKey(Artifact{Ecosystem: "npm", Name: "a", Version: "1", Digest: "sha256:AA"})
	if withDigest != "digest:sha256:aa" {
		t.Errorf("digest key = %q", withDigest)
	}
	coord := ArtifactKey(Artifact{Ecosystem: "PyPI", Name: "Requests", Version: "2.0"})
	if coord != "coord:pypi|requests|2.0" {
		t.Errorf("coord key = %q", coord)
	}
}

func TestFileLinkStore_RejectsEmptyArtifact(t *testing.T) {
	s, _ := NewFileLinkStore(t.TempDir())
	if err := s.Put(context.Background(), &Link{}); err == nil {
		t.Error("expected error storing a link for an empty artifact")
	}
}
