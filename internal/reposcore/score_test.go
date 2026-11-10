package reposcore

import "testing"

func TestScoreFacts_PerfectRepo(t *testing.T) {
	f := RepoFacts{
		CommitsAnalyzed:   100,
		SignedCommits:     100,
		GoodSignedCommits: 100,
		Tags:              10,
		SignedTags:        10,
		DistinctAuthors:   8,
		BusFactor:         5,
		TopAuthorShare:    0.3,
		LastCommitUnix:    1,
		LastCommitAgeDays: 3,
		ActiveDays:        25,
		HasCI:             true,
		HasSecurityPolicy: true,
		HasDepAutomation:  true,
		// Authoritative branch protection from an enricher.
		BranchProtectionKnown: true,
		BranchProtected:       true,
	}
	health, signals, weak, grade := scoreFacts(f, DefaultWeights())
	if health < 95 {
		t.Errorf("expected near-perfect health, got %d", health)
	}
	if grade != "A" {
		t.Errorf("expected grade A, got %s", grade)
	}
	if len(weak) != 0 {
		t.Errorf("expected no weak signals, got %v", weak)
	}
	if len(signals) != len(allSignals) {
		t.Fatalf("expected %d signals, got %d", len(allSignals), len(signals))
	}
	// Branch protection should be authoritative (not a hint) and full health.
	for _, s := range signals {
		if s.Kind == SignalBranchProtection {
			if s.Hint {
				t.Error("branch protection should not be a hint when enriched")
			}
			if s.Health != 1 {
				t.Errorf("branch protection health should be 1, got %v", s.Health)
			}
		}
	}
}

func TestScoreFacts_WorstRepo(t *testing.T) {
	f := RepoFacts{
		CommitsAnalyzed:   50,
		SignedCommits:     0,
		DistinctAuthors:   1,
		BusFactor:         1,
		TopAuthorShare:    1.0,
		LastCommitUnix:    1,
		LastCommitAgeDays: 1000, // > 2 years
		ActiveDays:        1,
	}
	health, _, weak, grade := scoreFacts(f, DefaultWeights())
	if health > 15 {
		t.Errorf("expected very low health, got %d", health)
	}
	if grade != "F" {
		t.Errorf("expected grade F, got %s", grade)
	}
	// Every signal except (vacuously) none should be weak here.
	if len(weak) < 5 {
		t.Errorf("expected most signals weak, got %v", weak)
	}
}

func TestBranchProtectionScored_HintVsVerified(t *testing.T) {
	// Offline with CODEOWNERS → partial-credit hint.
	e := branchProtectionScored(RepoFacts{HasCodeowners: true})
	if !e.hint || e.health != 0.5 {
		t.Errorf("expected codeowners hint at 0.5, got hint=%v health=%v", e.hint, e.health)
	}
	// Offline without CODEOWNERS → zero, still a hint.
	e = branchProtectionScored(RepoFacts{})
	if !e.hint || e.health != 0 {
		t.Errorf("expected no-signal hint at 0, got hint=%v health=%v", e.hint, e.health)
	}
	// Enriched, protected → authoritative full health.
	e = branchProtectionScored(RepoFacts{BranchProtectionKnown: true, BranchProtected: true})
	if e.hint || e.health != 1 {
		t.Errorf("expected verified protection at 1, got hint=%v health=%v", e.hint, e.health)
	}
	// Enriched, NOT protected → authoritative zero (worse than the unknown hint,
	// which is also zero but flagged as a hint).
	e = branchProtectionScored(RepoFacts{BranchProtectionKnown: true, BranchProtected: false})
	if e.hint || e.health != 0 {
		t.Errorf("expected verified-unprotected at 0, got hint=%v health=%v", e.hint, e.health)
	}
}

func TestSignedCommitsScored_PartialCreditForUnverifiable(t *testing.T) {
	// All commits signed but none verifiable offline (key absent): 60% credit.
	e := signedCommitsScored(RepoFacts{CommitsAnalyzed: 10, SignedCommits: 10, GoodSignedCommits: 0})
	if e.health < 0.59 || e.health > 0.61 {
		t.Errorf("expected ~0.6 for present-but-unverifiable signatures, got %v", e.health)
	}
	// All commits validly signed: full credit.
	e = signedCommitsScored(RepoFacts{CommitsAnalyzed: 10, SignedCommits: 10, GoodSignedCommits: 10})
	if e.health < 0.99 {
		t.Errorf("expected ~1.0 for valid signatures, got %v", e.health)
	}
}

func TestMaintainersScored_BusFactor(t *testing.T) {
	cases := []struct {
		bus  int
		want float64
	}{{1, 0.2}, {2, 0.55}, {3, 0.8}, {4, 1.0}, {7, 1.0}}
	for _, c := range cases {
		e := maintainersScored(RepoFacts{CommitsAnalyzed: 10, BusFactor: c.bus, DistinctAuthors: c.bus})
		if e.health != c.want {
			t.Errorf("bus factor %d: expected health %v, got %v", c.bus, c.want, e.health)
		}
	}
	// Heavy single-author concentration caps health even with several authors.
	e := maintainersScored(RepoFacts{CommitsAnalyzed: 100, BusFactor: 3, DistinctAuthors: 5, TopAuthorShare: 0.95})
	if e.health != 0.2 {
		t.Errorf("expected concentration penalty to cap health at 0.2, got %v", e.health)
	}
}

func TestActivityScored_Recency(t *testing.T) {
	fresh := activityScored(RepoFacts{LastCommitUnix: 1, LastCommitAgeDays: 10, ActiveDays: 20, CommitsAnalyzed: 50})
	stale := activityScored(RepoFacts{LastCommitUnix: 1, LastCommitAgeDays: 800, ActiveDays: 20, CommitsAnalyzed: 50})
	if fresh.health <= stale.health {
		t.Errorf("fresh repo should score higher than stale: fresh=%v stale=%v", fresh.health, stale.health)
	}
	if stale.health != 0.3*1.0 { // recency 0, cadence saturated at 1 → 0.3 weight
		t.Errorf("expected stale health 0.3 (cadence only), got %v", stale.health)
	}
}
