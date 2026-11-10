package vulnscan

import "testing"

func TestParseCVSSBaseScore(t *testing.T) {
	cases := []struct {
		vector string
		want   float64
		ok     bool
	}{
		// Canonical v3.1 examples (from the CVSS specification and common CVEs).
		{"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8, true},
		{"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H", 7.5, true},
		{"CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:L/A:N", 2.9, true},
		{"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", 6.1, true}, // scope changed
		{"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8, true},
		{"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N", 0.0, true}, // no impact
		// Unparseable / unknown.
		{"CVSS:2.0/AV:N/AC:L/Au:N/C:P/I:P/A:P", 0, false},
		{"garbage", 0, false},
		{"", 0, false},
	}
	for _, c := range cases {
		got, ok := ParseCVSSBaseScore(c.vector)
		if ok != c.ok {
			t.Errorf("%s: ok=%v want %v", c.vector, ok, c.ok)
			continue
		}
		if ok && got != c.want {
			t.Errorf("%s: score=%.1f want %.1f", c.vector, got, c.want)
		}
	}
}

func TestParseCVSSv4Approx(t *testing.T) {
	// v4.0 uses an approximation; assert it lands in the expected qualitative band
	// rather than an exact score.
	score, ok := ParseCVSSBaseScore("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N")
	if !ok {
		t.Fatal("expected v4.0 vector to parse")
	}
	if SeverityFromCVSS(score) != SeverityCritical && SeverityFromCVSS(score) != SeverityHigh {
		t.Errorf("v4.0 full-impact vector scored %.1f (%s), expected high/critical", score, SeverityFromCVSS(score))
	}
}

func TestSeverityFromCVSS(t *testing.T) {
	cases := []struct {
		score float64
		want  Severity
	}{
		{0, SeverityNone},
		{3.9, SeverityLow},
		{4.0, SeverityMedium},
		{6.9, SeverityMedium},
		{7.0, SeverityHigh},
		{8.9, SeverityHigh},
		{9.0, SeverityCritical},
		{10.0, SeverityCritical},
	}
	for _, c := range cases {
		if got := SeverityFromCVSS(c.score); got != c.want {
			t.Errorf("score %.1f: got %s want %s", c.score, got, c.want)
		}
	}
}

func TestSeverityOrdering(t *testing.T) {
	if !SeverityCritical.AtLeast(SeverityHigh) {
		t.Error("critical should be >= high")
	}
	if SeverityLow.AtLeast(SeverityHigh) {
		t.Error("low should not be >= high")
	}
	if !SeverityUnknown.AtLeast(SeverityNone) {
		t.Error("unknown should rank above none")
	}
	if SeverityUnknown.AtLeast(SeverityLow) {
		t.Error("unknown should rank below low")
	}
}

func TestNormalizeSeverity(t *testing.T) {
	cases := map[string]Severity{
		"MODERATE": SeverityMedium,
		"moderate": SeverityMedium,
		"HIGH":     SeverityHigh,
		"Critical": SeverityCritical,
		"":         SeverityUnknown,
		"weird":    SeverityUnknown,
		"NONE":     SeverityNone,
	}
	for in, want := range cases {
		if got := NormalizeSeverity(in); got != want {
			t.Errorf("%q: got %s want %s", in, got, want)
		}
	}
}
