package main

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/blechschmidt/pullthrough-security/internal/audit"
	"github.com/blechschmidt/pullthrough-security/internal/config"
	"github.com/blechschmidt/pullthrough-security/internal/findings"
	"github.com/blechschmidt/pullthrough-security/internal/metrics"
	"github.com/blechschmidt/pullthrough-security/internal/notify"
	"github.com/blechschmidt/pullthrough-security/internal/scan"
	"github.com/blechschmidt/pullthrough-security/internal/scan/commit"
	"github.com/blechschmidt/pullthrough-security/internal/scan/watch"
)

// buildCommitWatch constructs the continuous webhook/polling-driven incremental
// Git commit scanner (Task 108). It drives the existing commit-scanning pipeline
// (reached through the scanner) over a configured set of watched repositories,
// detecting new commits via a push webhook and/or polling and persisting a
// per-repo cursor. It returns a nil service (and no-op closer) when the watcher
// is disabled or the commit pipeline is unavailable.
//
// The observer wires each scanned commit into the unified findings store
// (keyed by repo+commit) and the tamper-evident audit log; notifications flow
// through the pipeline's existing per-verdict hook so a flagged commit alerts
// exactly once regardless of what triggered the scan.
func buildCommitWatch(
	cfg *config.Config,
	scanner scan.Scanner,
	findingsStore *findings.Store,
	auditLog *audit.Logger,
	notifier *notify.Notifier,
	logger *slog.Logger,
) (*watch.Service, func() error, error) {
	noop := func() error { return nil }
	wc := cfg.Scanning.Watch
	if !wc.Enabled {
		return nil, noop, nil
	}

	// The watcher needs the concrete commit pipeline (Scan + Signature). When
	// scanning produced no commit pipeline (disabled / unsupported provider), the
	// watcher cannot run.
	cs, ok := scanner.(*commit.Scanner)
	if !ok || cs.Pipeline() == nil {
		logger.Warn("commit watcher enabled but no commit-scanning pipeline is available; watcher disabled " +
			"(enable scanning with an LLM provider and/or deterministic secret detection)")
		return nil, noop, nil
	}
	pipeline := cs.Pipeline()

	source, err := watch.NewGitSource(watch.GitSourceOptions{
		Root:   wc.MirrorDir,
		Logger: logger,
	})
	if err != nil {
		return nil, noop, fmt.Errorf("building commit-watch git source: %w", err)
	}

	state, closeState, err := buildWatchState(wc, logger)
	if err != nil {
		return nil, noop, err
	}

	repos := make([]watch.RepoRef, 0, len(wc.Repos))
	for _, r := range wc.Repos {
		repos = append(repos, watch.RepoRef{
			Name:     r.Name,
			URL:      r.URL,
			Branches: r.Branches,
			FullName: r.FullName,
			Username: r.Username,
			Token:    r.Token,
		})
	}

	obs := &commitWatchObserver{
		findings: findingsStore,
		audit:    auditLog,
		failOn:   scan.Severity(cfg.Scanning.FailOn),
		logger:   logger,
	}

	svc, err := watch.NewService(pipeline, source, state, obs, watch.Config{
		Repos:                     repos,
		PollInterval:              wc.PollInterval,
		MaxCommitsPerScan:         wc.MaxCommitsPerScan,
		Backfill:                  wc.Backfill,
		WebhookSecret:             wc.WebhookSecret,
		AllowUnconfiguredWebhooks: wc.AllowUnconfiguredWebhooks,
		Logger:                    logger,
	})
	if err != nil {
		_ = closeState()
		return nil, noop, fmt.Errorf("building commit watcher: %w", err)
	}

	closer := func() error {
		err := svc.Close()
		if cerr := closeState(); cerr != nil && err == nil {
			err = cerr
		}
		return err
	}
	logger.Info("continuous commit scanning enabled",
		"repos", len(repos), "pollInterval", wc.PollInterval,
		"webhookPath", watchWebhookPath(cfg), "backfill", wc.Backfill,
		"signatureVerification", wc.WebhookSecret != "")
	return svc, closer, nil
}

// buildWatchState constructs the per-repo cursor store (filesystem when a
// directory is configured, otherwise in-memory).
func buildWatchState(wc config.GitScanConfig, logger *slog.Logger) (watch.StateStore, func() error, error) {
	if dir := wc.StateDir; dir != "" {
		st, err := watch.NewFileStateStore(dir)
		if err != nil {
			return nil, nil, fmt.Errorf("building commit-watch cursor store: %w", err)
		}
		logger.Info("commit-watch cursor store: filesystem", "dir", dir)
		return st, st.Close, nil
	}
	logger.Warn("commit-watch cursor store: in-memory (cursors are lost on restart; set scanning.watch.stateDir for durability)")
	st := watch.NewMemoryStateStore()
	return st, st.Close, nil
}

// bindCommitWatchMetrics registers the continuous commit scanner's counters on
// the shared metrics registry and binds live gauges (watched repos, cumulative
// commits scanned). It is a no-op when metrics are disabled (nil collector) or
// the watcher is not running. It must be called before svc.Start.
func bindCommitWatchMetrics(c *metrics.Collector, svc *watch.Service) {
	if c == nil || svc == nil {
		return
	}
	svc.SetMetrics(watch.NewMetrics(c.Registry()))
	c.BindGauge("pullthrough_commitwatch_repos_watched",
		"Number of repositories the continuous commit scanner is watching.",
		func() float64 { return float64(svc.Snapshot().ReposWatched) })
	c.BindGauge("pullthrough_commitwatch_commits_scanned",
		"Cumulative commits scanned by the continuous commit scanner since start.",
		func() float64 { return float64(svc.Snapshot().CommitsScanned) })
}

// watchWebhookPath returns the configured webhook path or the default.
func watchWebhookPath(cfg *config.Config) string {
	if p := cfg.Scanning.Watch.WebhookPath; p != "" {
		return p
	}
	return "/webhooks/git"
}

// commitWatchObserver persists each watcher-scanned commit into the unified
// findings store (keyed by repo+commit) and records a tamper-evident audit
// event. Notifications are emitted by the pipeline's own per-verdict hook, so
// this observer does not re-emit them (avoiding duplicate alerts).
type commitWatchObserver struct {
	findings *findings.Store
	audit    *audit.Logger
	failOn   scan.Severity
	logger   *slog.Logger
}

func (o *commitWatchObserver) ObserveScan(ctx context.Context, ev watch.ScanEvent) {
	v := ev.Verdict
	if v == nil {
		return
	}

	flagged := v.Malicious || len(commitFindings(v)) > 0
	coordinate := "git/" + ev.Repo.Name + "@" + v.SHA

	// Record findings for a flagged commit so they surface in the SARIF export,
	// the admin findings view, and the tenant portal. Clean commits are not
	// recorded (the findings store is bounded and keyed per coordinate; recording
	// every clean commit would evict package findings).
	if o.findings != nil && flagged {
		o.findings.Record(buildCommitDocument(ev, coordinate))
	}

	// Audit every scanned commit (allow/deny mirrors whether the verdict would
	// fail admission at the configured severity floor).
	decision := audit.DecisionAllow
	if v.Malicious || severityAtLeast(v.HighestSeverity(), string(o.failOn)) {
		decision = audit.DecisionDeny
	}
	if err := o.audit.Log(ctx, audit.Event{
		Type:      audit.EventScanVerdict,
		Ecosystem: "git",
		Resource:  coordinate,
		Decision:  decision,
		Reason:    v.Rationale,
		Detail: map[string]any{
			"repository": ev.Repo.URL,
			"commit":     v.SHA,
			"riskScore":  v.RiskScore,
			"malicious":  v.Malicious,
			"severity":   v.HighestSeverity(),
			"findings":   len(v.Findings),
			"fresh":      ev.Fresh,
			"backfill":   ev.Backfill,
			"trigger":    "commit-watch",
		},
	}); err != nil {
		o.logger.Error("commit-watch audit log failed", "repo", ev.Repo.Name, "sha", v.SHA, "error", err)
	}
}

// buildCommitDocument maps a scanned commit's verdict onto a findings.Document
// keyed by repo+commit.
func buildCommitDocument(ev watch.ScanEvent, coordinate string) findings.Document {
	v := ev.Verdict
	doc := findings.Document{
		Artifact: findings.Artifact{
			Ecosystem:     "git",
			Name:          ev.Repo.Name,
			Coordinate:    coordinate,
			CommitSHA:     v.SHA,
			RepositoryURL: ev.Repo.URL,
		},
		GeneratedAt: time.Now().UTC(),
	}
	base := findings.Location{
		Coordinate:    coordinate,
		CommitSHA:     v.SHA,
		RepositoryURL: ev.Repo.URL,
	}

	for _, f := range commitFindings(v) {
		ruleID := findings.RuleSuspiciousCommit
		gate := findings.GateCommitScan
		switch f.Category {
		case commit.CategorySecret:
			ruleID = findings.RuleExposedSecret
			gate = findings.GateSecretscan
		case commit.CategoryActionPinning:
			// The deterministic GitHub Actions pinning gate (Task 115) sets a
			// disallowed-owner finding at high severity and pinning (mutable/unpinned)
			// findings at medium; route each to its SARIF rule accordingly.
			gate = findings.GateActionPin
			if severityAtLeast(f.Severity, "high") {
				ruleID = findings.RuleDisallowedActionOwner
			} else {
				ruleID = findings.RuleUnpinnedAction
			}
		}
		sev := findings.Severity(normalizeFindingSeverity(f.Severity))
		loc := base
		loc.File = f.File
		loc.Line = f.Line
		doc.Findings = append(doc.Findings, findings.Finding{
			RuleID:     ruleID,
			Gate:       gate,
			Severity:   sev,
			Level:      findingLevel(sev),
			Identifier: string(f.Category),
			Title:      f.Title,
			Message:    f.Detail,
			Location:   loc,
			Properties: map[string]any{
				"category":   string(f.Category),
				"riskScore":  v.RiskScore,
				"malicious":  v.Malicious,
				"confidence": f.Confidence,
			},
		})
	}

	// A commit the model itself called malicious always yields at least one
	// critical finding, even if it enumerated no per-item findings.
	if v.Malicious && len(doc.Findings) == 0 {
		doc.Findings = append(doc.Findings, findings.Finding{
			RuleID:     findings.RuleSuspiciousCommit,
			Gate:       findings.GateCommitScan,
			Severity:   findings.SeverityCritical,
			Level:      findings.LevelError,
			Identifier: "malicious",
			Title:      "Commit assessed malicious",
			Message:    firstNonEmpty(v.Rationale, "the commit-scanning pipeline assessed this commit as malicious"),
			Location:   base,
			Properties: map[string]any{"riskScore": v.RiskScore, "malicious": true},
		})
	}
	return doc
}

// commitFindings returns the verdict's findings (helper kept for a single place
// to adjust filtering).
func commitFindings(v *commit.Verdict) []commit.Finding { return v.Findings }

// normalizeFindingSeverity coerces a commit-finding severity onto the findings
// vocabulary.
func normalizeFindingSeverity(s string) string {
	switch s {
	case "critical", "high", "medium", "low", "info":
		return s
	default:
		return "info"
	}
}

// findingLevel maps a findings severity to its SARIF level (mirrors the findings
// package's internal mapping, which is not exported).
func findingLevel(s findings.Severity) findings.Level {
	switch s {
	case findings.SeverityCritical, findings.SeverityHigh:
		return findings.LevelError
	case findings.SeverityMedium:
		return findings.LevelWarning
	case findings.SeverityLow, findings.SeverityInfo:
		return findings.LevelNote
	default:
		return findings.LevelWarning
	}
}

// severityAtLeast reports whether got is at least as severe as want, using the
// commit-scan severity vocabulary.
func severityAtLeast(got, want string) bool {
	order := map[string]int{"": 0, "info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
	w, ok := order[want]
	if !ok {
		w = order["high"]
	}
	return order[got] >= w
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}
