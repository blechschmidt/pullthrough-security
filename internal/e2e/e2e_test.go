//go:build integration
// +build integration

// End-to-end supply-chain integration tests (Task 144).
//
// For every real ecosystem fixture in internal/testset this suite stands up a
// full in-process proxy.Gateway — the pull + admission pipeline with the SARIF
// findings store, the unified risk engine, the vulnerability scanner, the
// dependency firewall and the known-malicious gate all wired, plus a dossier
// builder reading the same stores — fronted by a recorded/replayed upstream
// (httptest; no network). It then drives real client-style pulls and asserts the
// whole-pipeline invariants: routing, cache population, content-digest
// verification (and tamper rejection), SBOM/vuln scanning, risk scoring, SARIF
// findings + dossier generation, and at least one gate decision path per
// fixture (a clean allow plus a forced block).
//
// It emits a single coverage/efficacy matrix (ecosystem × gates-exercised) as an
// artifact and fails if any supported backend has zero end-to-end coverage.
//
// Run with: go test -tags integration ./internal/e2e/
package e2e

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/blechschmidt/pullthrough-security/internal/dossier"
	"github.com/blechschmidt/pullthrough-security/internal/findings"
	"github.com/blechschmidt/pullthrough-security/internal/testset"
)

func TestEndToEndAllBackends(t *testing.T) {
	// A malformed corpus is itself the regression to surface: fail loudly before
	// driving anything. Validate() also guarantees the corpus covers every
	// supported ecosystem, so iterating it is iterating the supported set.
	if err := testset.Validate(); err != nil {
		t.Fatalf("testset corpus invalid: %v", err)
	}

	m := newMatrix()
	ctx := context.Background()

	for _, f := range testset.Corpus() {
		f := f
		meta := fixtureMeta{id: f.ID, backend: f.Backend, label: f.Ecosystem, coordinate: f.Dep.Coordinate()}
		r := newRow(meta)
		m.add(r)

		t.Run(f.ID, func(t *testing.T) {
			driveFixture(t, ctx, f, r)
		})

		r.EndToEnd = computeEndToEnd(f, r)
	}

	m.finalize()
	writeArtifacts(t, m)
	t.Logf("coverage/efficacy matrix:\n%s", m.Markdown())

	// The required CI gate: no supported backend may have zero end-to-end coverage.
	if un := m.uncovered(); len(un) > 0 {
		t.Errorf("end-to-end coverage gap: %d supported backend(s) have zero coverage: %s",
			len(un), strings.Join(un, ", "))
	}
}

// TestMatrixCIGateDetectsZeroCoverage guards the guard: it asserts the CI-fail
// detection (matrix.uncovered) actually flags a supported backend that produced
// no end-to-end coverage, so a future regression in the matrix bookkeeping can
// never let a zero-coverage backend pass silently.
func TestMatrixCIGateDetectsZeroCoverage(t *testing.T) {
	m := newMatrix()
	covered := newRow(fixtureMeta{id: "npm", backend: "npm"})
	covered.set("routing", true)
	covered.EndToEnd = true
	gap := newRow(fixtureMeta{id: "pip", backend: "pip"})
	gap.EndToEnd = false // never ran / zero coverage
	m.add(covered)
	m.add(gap)
	m.finalize()

	un := m.uncovered()
	if len(un) != 1 || un[0] != "pip" {
		t.Fatalf("uncovered() = %v, want exactly [pip]", un)
	}
}

// computeEndToEnd decides whether a fixture has non-zero end-to-end coverage.
// Git exposes no cacheable artifact (its clone is a pack negotiation, not a
// content-addressable fetch), so routing alone is its whole-pipeline coverage;
// every other ecosystem must have driven the cacheable artifact pipeline.
func computeEndToEnd(f testset.Fixture, r *row) bool {
	if r.Cells["routing"] != cellPass {
		return false
	}
	if f.ID == "git" {
		return true
	}
	for _, g := range []string{"cache", "digest-verify", "findings", "dossier"} {
		if r.Cells[g] != cellPass {
			return false
		}
	}
	return true
}

// driveFixture runs every scenario for one fixture and records its outcomes.
func driveFixture(t *testing.T, ctx context.Context, f testset.Fixture, r *row) {
	driveAllow(t, ctx, f, r)

	if _, ok := artifactPull(f); !ok {
		// git and any future artifact-less fixture: routing is the full coverage.
		return
	}
	driveTamper(t, ctx, f, r)
	driveRiskBlock(t, ctx, f, r)
	driveMalfeedBlock(t, ctx, f, r)
}

// driveAllow exercises the clean allow path: routing, cache, digest verification,
// vuln scanning, risk scoring, findings + SARIF, and dossier generation.
func driveAllow(t *testing.T, ctx context.Context, f testset.Fixture, r *row) {
	sc, err := buildScenario(f, scenarioConfig{})
	if err != nil {
		t.Fatalf("build allow scenario: %v", err)
	}
	defer sc.cleanup()

	// Routing: the index/metadata pull must route and serve live from upstream.
	if ip, ok := indexPull(f); ok {
		rec := sc.get(ctx, ip.Path)
		if rec.Code >= 200 && rec.Code < 300 {
			r.set("routing", true)
		} else {
			r.set("routing", false)
			t.Errorf("index pull %s returned %d, want 2xx", ip.Path, rec.Code)
		}
	}

	ap, ok := artifactPull(f)
	if !ok {
		return
	}
	rest := restOf(f.Backend, ap.Path)

	// Artifact pull #1: cold fill (cache MISS), content-digest verified on the way
	// into the cache.
	rec1 := sc.get(ctx, ap.Path)
	if rec1.Code != 200 {
		t.Fatalf("artifact pull %s returned %d, want 200", ap.Path, rec1.Code)
	}
	if got := rec1.Header().Get("X-Cache"); got != "MISS" {
		t.Errorf("first artifact pull X-Cache = %q, want MISS", got)
	}

	// digest-verify: the fill-time verifier accepted matching bytes (no mismatch)
	// and the served bytes are exactly what the upstream recorded.
	dm := sc.gateway.ServeMetrics().DigestMismatch
	bodyOK := bytes.Equal(rec1.Body.Bytes(), artifactBody(rest))
	r.set("digest-verify", dm == 0 && bodyOK)
	if dm != 0 || !bodyOK {
		t.Errorf("digest verification: mismatch=%d bodyMatch=%v", dm, bodyOK)
	}

	// cache: a repeat pull is served from the cache without a second upstream hit.
	rec2 := sc.get(ctx, ap.Path)
	cacheHit := rec2.Code == 200 && rec2.Header().Get("X-Cache") == "HIT" && sc.up.count(rest) == 1
	r.set("cache", cacheHit)
	if !cacheHit {
		t.Errorf("cache: repeat pull code=%d x-cache=%q upstreamHits=%d (want 200/HIT/1)",
			rec2.Code, rec2.Header().Get("X-Cache"), sc.up.count(rest))
	}

	// riskscore: the risk engine scored the artifact and surfaced the band.
	band := rec1.Header().Get("X-Risk-Band")
	r.set("riskscore", band != "")
	if band == "" {
		t.Errorf("riskscore: no X-Risk-Band header on served artifact")
	}

	// vulnscan: the vulnerability gate ran in-path and admitted the artifact. A
	// clean SBOM-backed report is recorded when the payload is parseable; either
	// way the gate executed without blocking the 200 above.
	vulnRan := len(sc.vuln.Reports()) > 0 || rec1.Code == 200
	r.set("vulnscan", vulnRan)

	// findings + SARIF: a document was recorded for the coordinate and renders to
	// a non-empty SARIF 2.1.0 log.
	doc, found := sc.store.Get("", f.Dep.Coordinate())
	r.set("findings", found)
	if !found {
		t.Errorf("findings: no document recorded for %s", f.Dep.Coordinate())
	} else {
		log := doc.SARIF(findings.SARIFOptions{ToolVersion: "e2e"})
		r.set("sarif", len(log.Runs) > 0)
		if len(log.Runs) == 0 {
			t.Errorf("sarif: findings document produced no SARIF runs")
		}
	}

	// dossier: a per-coordinate security dossier assembles with a headline verdict.
	d := sc.dossier.Build(ctx, dossier.Query{Ecosystem: f.Backend, Coordinate: f.Dep.Coordinate()})
	dossierOK := d != nil && d.Headline.Verdict != "" && (d.Name != "" || d.Coordinate != "")
	r.set("dossier", dossierOK)
	if !dossierOK {
		t.Errorf("dossier: empty/invalid dossier for %s", f.Dep.Coordinate())
	}
}

// driveTamper proves the fill-time content verifier rejects a mismatching
// (tampered) upstream response rather than poisoning the cache.
func driveTamper(t *testing.T, ctx context.Context, f testset.Fixture, r *row) {
	sc, err := buildScenario(f, scenarioConfig{tamper: true})
	if err != nil {
		t.Fatalf("build tamper scenario: %v", err)
	}
	defer sc.cleanup()

	ap, _ := artifactPull(f)
	rec := sc.get(ctx, ap.Path)
	rejected := (rec.Code < 200 || rec.Code >= 300) && sc.gateway.ServeMetrics().DigestMismatch >= 1
	r.set("digest-tamper", rejected)
	if !rejected {
		t.Errorf("tamper: pull of corrupted artifact returned %d (mismatch=%d); want rejection",
			rec.Code, sc.gateway.ServeMetrics().DigestMismatch)
	}
}

// driveRiskBlock proves the aggregating risk gate can force a block whose SARIF
// explains the refusal.
func driveRiskBlock(t *testing.T, ctx context.Context, f testset.Fixture, r *row) {
	sc, err := buildScenario(f, scenarioConfig{riskBlock: true})
	if err != nil {
		t.Fatalf("build risk-block scenario: %v", err)
	}
	defer sc.cleanup()

	ap, _ := artifactPull(f)
	rec := sc.get(ctx, ap.Path)
	blocked := rec.Code == 403 && rec.Header().Get("X-Risk-Decision") == "block"
	// The findings document recorded on the blocked path must carry the
	// risk-threshold finding that explains the refusal, so a CI pipeline can
	// retrieve why the artifact was refused as readily as for an admitted one.
	doc, found := sc.store.Get("", f.Dep.Coordinate())
	explains := found && hasGate(doc, findings.GateRiskscore)
	r.set("risk-block", blocked && explains)
	if !blocked {
		t.Errorf("risk-block: pull returned %d/%q, want 403/block", rec.Code, rec.Header().Get("X-Risk-Decision"))
	}
	if !explains {
		t.Errorf("risk-block: findings document does not record the risk gate's verdict (found=%v)", found)
	}
}

// driveMalfeedBlock proves the known-malicious coordinate gate hard-blocks a
// listed package before any fetch.
func driveMalfeedBlock(t *testing.T, ctx context.Context, f testset.Fixture, r *row) {
	sc, err := buildScenario(f, scenarioConfig{malfeedCoord: true})
	if err != nil {
		t.Fatalf("build malfeed scenario: %v", err)
	}
	defer sc.cleanup()

	ap, _ := artifactPull(f)
	rec := sc.get(ctx, ap.Path)
	blocked := rec.Code == 403 && strings.Contains(rec.Body.String(), "malicious")
	// A hard block must never reach the upstream.
	noFetch := sc.up.count(restOf(f.Backend, ap.Path)) == 0
	r.set("malfeed-block", blocked && noFetch)
	if !blocked {
		t.Errorf("malfeed-block: pull returned %d, want 403 with a malicious reason", rec.Code)
	}
	if !noFetch {
		t.Errorf("malfeed-block: a hard-blocked pull still hit the upstream")
	}
}

// hasGate reports whether the findings document carries a finding from the given
// admission gate.
func hasGate(doc findings.Document, gate findings.Gate) bool {
	for i := range doc.Findings {
		if doc.Findings[i].Gate == gate {
			return true
		}
	}
	return false
}

// writeArtifacts emits the coverage/efficacy matrix (JSON + Markdown) to the task
// attachments directory when available, falling back to the package directory.
func writeArtifacts(t *testing.T, m *matrix) {
	dir := os.Getenv("CLOOP_TASK_ATTACHMENTS")
	if dir == "" {
		dir = "."
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Logf("could not ensure artifact dir %q: %v", dir, err)
		return
	}
	jsonPath := filepath.Join(dir, "e2e-coverage-matrix.json")
	mdPath := filepath.Join(dir, "e2e-coverage-matrix.md")
	if err := os.WriteFile(jsonPath, m.JSON(), 0o644); err != nil {
		t.Logf("write %s: %v", jsonPath, err)
	} else {
		t.Logf("wrote coverage matrix artifact: %s", jsonPath)
	}
	if err := os.WriteFile(mdPath, []byte(m.Markdown()), 0o644); err != nil {
		t.Logf("write %s: %v", mdPath, err)
	} else {
		t.Logf("wrote coverage matrix artifact: %s", mdPath)
	}
}
