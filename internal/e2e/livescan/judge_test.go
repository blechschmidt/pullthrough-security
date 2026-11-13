//go:build integration

package livescan

import (
	"strings"
	"testing"
)

// How the suite judges a commit's verdict: what passes, what passes with a
// note, and what fails.
func TestJudgeCommit(t *testing.T) {
	refused := "deep analysis failed: commit: analyzing abc chunk 1/1 with claude-opus-4-8: commit: claude: request refused by safety system (category \"cyber\")"
	// A verdict a model gave.
	model := func(v commitVerdict) commitVerdict {
		v.Provider, v.Models, v.InputTokens = "claude", []string{"claude-haiku-4-5"}, 1234
		return v
	}
	cases := []struct {
		name      string
		variant   Variant
		v         commitVerdict
		pass      bool
		stage     string
		wantNote  bool
		wantProbs []string
	}{
		{"attacker commit flagged by triage and deep", Malicious, model(commitVerdict{Malicious: true, RiskScore: 99, Escalated: true}), true, "ok", false, nil},
		{"attacker commit flagged, deep refused", Malicious, model(commitVerdict{Malicious: true, RiskScore: 99, Error: refused}), true, "refused", true, nil},
		{"attacker commit flagged, deep failed for another reason", Malicious, model(commitVerdict{Malicious: true, RiskScore: 99, Error: "deep analysis failed: timeout"}), false, "failed", false, []string{"did not complete"}},
		{"attacker commit not flagged", Malicious, model(commitVerdict{Malicious: false, RiskScore: 12}), false, "not needed", false, []string{"not judged malicious"}},
		{"attacker commit not flagged and deep refused", Malicious, model(commitVerdict{Malicious: false, RiskScore: 60, Error: refused}), false, "refused", false, []string{"not judged malicious"}},
		{"attacker commit flagged but the triage itself failed", Malicious, model(commitVerdict{Malicious: true, RiskScore: 90, Error: "llm triage failed: boom"}), false, "not needed", false, []string{"did not complete"}},
		{"control commit clean", Benign, model(commitVerdict{Malicious: false, RiskScore: 3}), true, "not needed", false, nil},
		{"control commit flagged", Benign, model(commitVerdict{Malicious: true, RiskScore: 95, Escalated: true, Rationale: "looks bad"}), false, "ok", false, []string{"false positive"}},
		{"control commit with a failed scan", Benign, model(commitVerdict{Malicious: false, RiskScore: 3, Error: refused}), false, "refused", false, []string{"did not complete"}},

		// A verdict no model gave must not pass as a clean scan.
		{"deterministic fallback on a control", Benign, commitVerdict{Provider: "none", Models: []string{"deterministic-scan"}}, false, "not needed", false, []string{"no model judged"}},
		{"no tokens were spent", Benign, commitVerdict{Provider: "claude", Models: []string{"m"}}, false, "not needed", false, []string{"no model judged"}},
		{"truncated diff", Benign, model(commitVerdict{Truncated: true}), false, "not needed", false, []string{"truncated"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res := CommitResult{Variant: tc.variant}
			v := tc.v
			judgeCommit(&res, &v)
			res.Pass = len(res.Problems) == 0
			if res.Pass != tc.pass {
				t.Errorf("pass = %v (problems %v), want %v", res.Pass, res.Problems, tc.pass)
			}
			if res.DeepStage != tc.stage {
				t.Errorf("deep stage = %q, want %q", res.DeepStage, tc.stage)
			}
			if (len(res.Notes) > 0) != tc.wantNote {
				t.Errorf("notes = %v, want a note: %v", res.Notes, tc.wantNote)
			}
			for _, want := range tc.wantProbs {
				found := false
				for _, p := range res.Problems {
					found = found || strings.Contains(p, want)
				}
				if !found {
					t.Errorf("problems %v lack %q", res.Problems, want)
				}
			}
		})
	}
}

// How the suite judges a package pull.
func TestJudgePackage(t *testing.T) {
	const model = "claude-test-model"
	malicious := func(status int, code, scanCode string, rp *Repull) PackageResult {
		return PackageResult{Status: status, PolicyCode: code, ScanCode: scanCode, Served: status == 200, Repull: rp}
	}
	held := &Repull{Status: 403, PolicyCode: policyMalicious, ModelCalls: 0}
	declined := &Repull{Status: 403, PolicyCode: policyUnscanned, ModelCalls: 0}
	cases := []struct {
		name     string
		variant  Variant
		res      PackageResult
		verdict  string   // the stored verdict; empty = none recorded
		refuses  []string // the sample's modelsMayRefuse
		pass     bool
		outcome  string
		wantProb string
		wantNote string
	}{
		{"refused as malicious, block holds", Malicious, malicious(403, policyMalicious, "", held), "malicious", nil, true, OutcomeDetected, "", ""},
		{"refused as malicious, no second pull recorded", Malicious, malicious(403, policyMalicious, "", nil), "malicious", nil, true, OutcomeDetected, "", ""},
		{"refused as malicious, the API route counts no calls", Malicious, malicious(403, policyMalicious, "", &Repull{Status: 403, PolicyCode: policyMalicious, ModelCalls: -1}), "malicious", nil, true, OutcomeDetected, "", ""},
		{"served", Malicious, malicious(200, "", "", nil), "benign", nil, false, OutcomeServed, "served", ""},
		{"refused as malicious but the verdict says otherwise", Malicious, malicious(403, policyMalicious, "", nil), "suspicious", nil, false, OutcomeDetected, "want malicious", ""},
		{"the block does not hold", Malicious, malicious(403, policyMalicious, "", &Repull{Status: 200}), "malicious", nil, false, OutcomeDetected, "did not hold", ""},
		{"the second pull costs a model call", Malicious, malicious(403, policyMalicious, "", &Repull{Status: 403, PolicyCode: policyMalicious, ModelCalls: 1}), "malicious", nil, false, OutcomeDetected, "cost 1 model call", ""},

		// The provider's safeguards declined to judge the package.
		{"declined by a model that may decline", Malicious, malicious(403, policyUnscanned, "provider-refusal", declined), "", []string{model}, true, OutcomeNoVerdict, "", "declined to judge it"},
		{"declined by a model the sample does not list", Malicious, malicious(403, policyUnscanned, "provider-refusal", declined), "", []string{"another-model"}, false, OutcomeNoVerdict, "detection gap", ""},
		{"declined, nothing listed", Malicious, malicious(403, policyUnscanned, "provider-refusal", declined), "", nil, false, OutcomeNoVerdict, "modelsMayRefuse", ""},
		{"unscanned for a reason that is not the sample's", Malicious, malicious(403, policyUnscanned, "timeout", declined), "", []string{model}, false, OutcomeNoVerdict, "\"timeout\"", ""},
		{"detected although the sample lists the model", Malicious, malicious(403, policyMalicious, "", held), "malicious", []string{model}, true, OutcomeDetected, "", "may no longer decline"},

		{"clean release served unchanged", Benign, PackageResult{Status: 200, Served: true, SameBytes: true}, "benign", nil, true, "", "", ""},
		{"clean release served but altered", Benign, PackageResult{Status: 200, Served: true}, "benign", nil, false, "", "not byte for byte", ""},
		{"clean release refused", Benign, PackageResult{Status: 403, PolicyCode: policyMalicious}, "malicious", nil, false, "", "was not served", ""},
		{"clean release judged malicious", Benign, PackageResult{Status: 200, Served: true, SameBytes: true}, "malicious", nil, false, "", "false positive", ""},
		{"clean release the model doubts", Benign, PackageResult{Status: 200, Served: true, SameBytes: true}, "suspicious", nil, true, "", "", "near false positive"},
		{"clean release without a verdict", Benign, PackageResult{Status: 200, Served: true, SameBytes: true}, "", nil, false, "", "no verdict was recorded", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res := tc.res
			p := &pull{Variant: tc.variant, Digest: "sha256:aa", Sample: &Sample{ModelsMayRefuse: tc.refuses}}
			verdicts := map[string]verdictRow{}
			if tc.verdict != "" {
				verdicts[p.Digest] = verdictRow{Digest: p.Digest, Verdict: tc.verdict, Confidence: 0.9}
			}
			judgePackage(&res, p, verdicts, model)
			if res.Pass != tc.pass {
				t.Errorf("pass = %v (problems %v), want %v", res.Pass, res.Problems, tc.pass)
			}
			if res.Outcome != tc.outcome {
				t.Errorf("outcome = %q, want %q", res.Outcome, tc.outcome)
			}
			if tc.wantProb != "" && !strings.Contains(strings.Join(res.Problems, "; "), tc.wantProb) {
				t.Errorf("problems %v lack %q", res.Problems, tc.wantProb)
			}
			if tc.wantNote != "" && !strings.Contains(strings.Join(res.Notes, "; "), tc.wantNote) {
				t.Errorf("notes %v lack %q", res.Notes, tc.wantNote)
			}
			if tc.wantNote == "" && len(res.Notes) > 0 {
				t.Errorf("unexpected notes %v", res.Notes)
			}
		})
	}
}
