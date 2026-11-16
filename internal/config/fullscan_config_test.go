package config

import (
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const fullScanGate = "\nllmPackageScan: {enabled: true, provider: claude, apiKey: x}\n"

// A full scan needs the gate, a budget and a state directory; an upstream the
// gate excludes cannot be fully scanned.
func TestFullScanConfiguration(t *testing.T) {
	upstream := "    fullMirror: {fullScan: true}\n"
	for _, tc := range []struct {
		name, upstream, extra, want string
	}{
		{"without the gate", upstream, "\nfullScan: {budget: {dailyUsd: 5}}\n", "llmPackageScan.enabled"},
		{"without a budget", upstream, fullScanGate, "needs a cost budget"},
		{"the global switch without a budget", "", fullScanGate + "fullScan: {enabled: true}\n", "fullScan.enabled needs a cost budget"},
		{"an excluded upstream", upstream, "\nllmPackageScan: {enabled: true, provider: claude, apiKey: x, excludeUpstreams: [npm]}\nfullScan: {budget: {monthlyUsd: 50}}\n", "excludeUpstreams excludes"},
		{"a negative budget", upstream, fullScanGate + "fullScan: {budget: {dailyUsd: -1}}\n", "non-negative"},
		{"too many workers", upstream, fullScanGate + "fullScan: {concurrency: 99, budget: {dailyUsd: 1}}\n", "concurrency"},
		{"a sweep too often", upstream, fullScanGate + "fullScan: {sweepInterval: 5s, budget: {dailyUsd: 1}}\n", "sweepInterval"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := loadFullMirrorYAML(t, tc.upstream, tc.extra)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want one mentioning %q", err, tc.want)
			}
		})
	}

	cfg, err := loadFullMirrorYAML(t, upstream, fullScanGate+"fullScan: {concurrency: 3, sweepInterval: 2h, budget: {dailyUsd: 5, monthlyUsd: 100}}\n")
	if err != nil {
		t.Fatal(err)
	}
	if got := cfg.FullScanUpstreams(); len(got) != 1 || got[0] != "npm" || !cfg.FullScanRequested() {
		t.Fatalf("FullScanUpstreams = %v", got)
	}
	if want := filepath.Join(cfg.Cache.Dir, "fullmirror", "fullscan"); cfg.FullScanStateDir() != want {
		t.Fatalf("FullScanStateDir = %q, want %q", cfg.FullScanStateDir(), want)
	}
	if fs := cfg.FullScan; fs.Concurrency != 3 || fs.SweepInterval != 2*time.Hour || fs.Budget.DailyUSD != 5 || fs.Budget.MonthlyUSD != 100 {
		t.Fatalf("fullScan = %+v", fs)
	}
	// Nothing requested: nothing required.
	cfg, err = loadFullMirrorYAML(t, "", "")
	if err != nil || cfg.FullScanRequested() {
		t.Fatalf("a configuration without a full scan: %v (requested %v)", err, cfg.FullScanRequested())
	}
}
