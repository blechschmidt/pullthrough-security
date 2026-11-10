package provenance

import (
	"context"
	"errors"
	"testing"
)

// fixedResolver returns a preset link (or ErrNoProvenance) and counts calls.
type fixedResolver struct {
	name  string
	link  *Link
	err   error
	calls int
	// onResolve lets a test inspect the (possibly hint-enriched) artifact.
	onResolve func(Artifact)
}

func (r *fixedResolver) Name() string { return r.name }
func (r *fixedResolver) Resolve(_ context.Context, art Artifact) (*Link, error) {
	r.calls++
	if r.onResolve != nil {
		r.onResolve(art)
	}
	if r.err != nil {
		return nil, r.err
	}
	cp := *r.link
	cp.Artifact = art
	return &cp, nil
}

func TestService_PrefersAttested(t *testing.T) {
	claimed := &fixedResolver{name: "meta", link: &Link{RepositoryURL: "https://github.com/o/r", Confidence: ConfidenceClaimed}}
	attested := &fixedResolver{name: "att", link: &Link{RepositoryURL: "https://github.com/o/r", CommitSHA: "deadbeef", Confidence: ConfidenceAttested}}

	svc := NewService(ServiceOptions{Resolvers: []Resolver{claimed, attested}})
	link, err := svc.Resolve(context.Background(), Artifact{Ecosystem: "npm", Name: "x", Version: "1"})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if link.Confidence != ConfidenceAttested {
		t.Errorf("confidence = %q, want attested (strongest wins)", link.Confidence)
	}
}

func TestService_ThreadsRepositoryHint(t *testing.T) {
	meta := &fixedResolver{name: "meta", link: &Link{RepositoryURL: "https://github.com/o/r", Confidence: ConfidenceClaimed}}
	var sawHint string
	enricher := &fixedResolver{
		name: "github", err: ErrNoProvenance,
		onResolve: func(a Artifact) { sawHint = a.RepositoryURL },
	}
	svc := NewService(ServiceOptions{Resolvers: []Resolver{meta, enricher}})
	if _, err := svc.Resolve(context.Background(), Artifact{Ecosystem: "npm", Name: "x"}); err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if sawHint != "https://github.com/o/r" {
		t.Errorf("enricher saw repo hint %q, want it threaded from the metadata resolver", sawHint)
	}
}

func TestService_CachesInStore(t *testing.T) {
	res := &fixedResolver{name: "att", link: &Link{RepositoryURL: "https://github.com/o/r", CommitSHA: "c", Confidence: ConfidenceAttested}}
	store := NewMemoryLinkStore()
	svc := NewService(ServiceOptions{Resolvers: []Resolver{res}, Store: store})

	art := Artifact{Ecosystem: "npm", Name: "x", Version: "1", Digest: "sha256:aa"}
	if _, err := svc.Resolve(context.Background(), art); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Resolve(context.Background(), art); err != nil {
		t.Fatal(err)
	}
	if res.calls != 1 {
		t.Errorf("resolver called %d times, want 1 (second Resolve should hit the store)", res.calls)
	}
}

func TestService_NoProvenance(t *testing.T) {
	res := &fixedResolver{name: "none", err: ErrNoProvenance}
	svc := NewService(ServiceOptions{Resolvers: []Resolver{res}})
	if _, err := svc.Resolve(context.Background(), Artifact{Ecosystem: "npm", Name: "x"}); !errors.Is(err, ErrNoProvenance) {
		t.Errorf("err = %v, want ErrNoProvenance", err)
	}
}

// stubVerdicts implements VerdictLookup.
type stubVerdicts struct{ verdicts map[string]*CommitVerdict }

func (s stubVerdicts) VerdictFor(_ context.Context, sha string) (*CommitVerdict, bool) {
	v, ok := s.verdicts[sha]
	return v, ok
}

func TestService_ResolveEnrichedJoinsVerdict(t *testing.T) {
	res := &fixedResolver{name: "att", link: &Link{RepositoryURL: "https://github.com/o/r", CommitSHA: "deadbeef", Confidence: ConfidenceAttested}}
	verdicts := stubVerdicts{verdicts: map[string]*CommitVerdict{
		"deadbeef": {SHA: "deadbeef", RiskScore: 90, Malicious: true, HighestSeverity: "critical", Findings: 2},
	}}
	svc := NewService(ServiceOptions{Resolvers: []Resolver{res}, Verdicts: verdicts, Store: NewMemoryLinkStore()})

	enriched, err := svc.ResolveEnriched(context.Background(), Artifact{Ecosystem: "oci", Name: "img", Digest: "sha256:aa"})
	if err != nil {
		t.Fatalf("ResolveEnriched: %v", err)
	}
	if enriched.Verdict == nil || !enriched.Verdict.Malicious {
		t.Fatalf("expected the malicious source-commit verdict to be surfaced, got %+v", enriched.Verdict)
	}

	// And the consumed-packages listing carries the same join.
	all, err := svc.LinksWithVerdicts(context.Background())
	if err != nil || len(all) != 1 {
		t.Fatalf("LinksWithVerdicts = %d, %v", len(all), err)
	}
	if all[0].Verdict == nil || all[0].Verdict.RiskScore != 90 {
		t.Errorf("listing verdict = %+v", all[0].Verdict)
	}
}

func TestForEcosystems(t *testing.T) {
	res := &fixedResolver{name: "npm", link: &Link{Confidence: ConfidenceClaimed}}
	gated := ForEcosystems(res, "npm")
	if _, err := gated.Resolve(context.Background(), Artifact{Ecosystem: "pip"}); !errors.Is(err, ErrNoProvenance) {
		t.Error("gated resolver should reject a non-matching ecosystem")
	}
	if res.calls != 0 {
		t.Error("inner resolver should not be called for a non-matching ecosystem")
	}
	if _, err := gated.Resolve(context.Background(), Artifact{Ecosystem: "npm"}); err != nil {
		t.Errorf("gated resolver should pass through a matching ecosystem: %v", err)
	}
}
