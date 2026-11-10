package policy

import (
	"context"
	"io"
	"log/slog"
	"testing"
)

// Benchmarks for the admission policy engine's per-request hot path,
// Engine.Evaluate. Evaluate runs on every resolved artifact before it is served,
// so its constant cost (glob matching, confidence ordering, decision assembly)
// directly bounds gated request throughput. The AssessmentSource is a fixed
// in-memory stub so the benchmark measures the engine, not provenance I/O.
//
// stubSource is defined in policy_test.go.

func benchEngine(rule Rule, asmt Assessment) *Engine {
	return New(Config{Default: rule}, stubSource{asmt: asmt},
		slog.New(slog.NewTextHandler(io.Discard, nil)))
}

func BenchmarkEvaluate(b *testing.B) {
	art := Artifact{Ecosystem: "npm", Backend: "npm", Name: "@acme/widget", Version: "1.2.3", Digest: "sha256:abc"}

	cases := []struct {
		name string
		eng  *Engine
		art  Artifact
	}{
		{
			// Cheapest accept: provenance found, fully attested, no thresholds tripped.
			name: "allow_attested",
			eng: benchEngine(
				Rule{WarnAtRiskScore: 80, BlockAtRiskScore: 95, BlockMalicious: true},
				Assessment{Found: true, SignatureVerified: true, ChainTrusted: true,
					Confidence: "attested", HasVerdict: true, RiskScore: 10},
			),
			art: art,
		},
		{
			// Hard block on a verified-malicious source commit.
			name: "block_malicious",
			eng: benchEngine(
				Rule{BlockMalicious: true},
				Assessment{Found: true, SignatureVerified: true, ChainTrusted: true,
					Confidence: "attested", HasVerdict: true, Malicious: true, RiskScore: 90},
			),
			art: art,
		},
		{
			// Missing-provenance terminal path (no external assessment value usable).
			name: "missing_provenance",
			eng: benchEngine(
				Rule{OnMissingProvenance: ActionBlock},
				Assessment{Found: false},
			),
			art: art,
		},
		{
			// Glob-heavy allow/deny matching, the most CPU-bound branch.
			name: "allowlist_globs",
			eng: benchEngine(
				Rule{
					Denylist:  []string{"evil-*", "*-malware", "left?pad"},
					Allowlist: []string{"@acme/*", "@corp/*", "lodash", "react*"},
				},
				Assessment{Found: true, SignatureVerified: true, ChainTrusted: true, Confidence: "attested"},
			),
			art: art,
		},
	}

	for _, c := range cases {
		b.Run(c.name, func(b *testing.B) {
			b.ReportAllocs()
			b.ResetTimer()
			var d Decision
			for i := 0; i < b.N; i++ {
				d = c.eng.Evaluate(context.Background(), c.art)
			}
			_ = d
		})
	}
}

// BenchmarkEvaluateParallel measures the engine under concurrent load; it is
// safe for concurrent use, so this should scale near-linearly with -cpu.
func BenchmarkEvaluateParallel(b *testing.B) {
	eng := benchEngine(
		Rule{WarnAtRiskScore: 80, BlockAtRiskScore: 95, BlockMalicious: true,
			Denylist: []string{"evil-*"}, Allowlist: []string{"@acme/*", "lodash"}},
		Assessment{Found: true, SignatureVerified: true, ChainTrusted: true,
			Confidence: "attested", HasVerdict: true, RiskScore: 10},
	)
	art := Artifact{Ecosystem: "npm", Name: "@acme/widget", Version: "1.2.3"}
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_ = eng.Evaluate(context.Background(), art)
		}
	})
}
