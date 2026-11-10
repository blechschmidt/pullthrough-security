package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"

	"github.com/blechschmidt/pullthrough-security/internal/audit"
	"github.com/blechschmidt/pullthrough-security/internal/config"
	"github.com/blechschmidt/pullthrough-security/internal/findings"
	"github.com/blechschmidt/pullthrough-security/internal/policyengine"
)

// buildFindingsStore constructs the unified findings-aggregation store (Task 42)
// when enabled. It returns nil when disabled, in which case the gateway records
// nothing and the admin SARIF surface reports itself absent.
func buildFindingsStore(cfg *config.Config, logger *slog.Logger) *findings.Store {
	fc := cfg.Findings
	if !fc.Enabled {
		logger.Info("findings aggregation disabled (set findings.enabled to retain normalized gate findings and export SARIF for CI)")
		return nil
	}
	store := findings.NewStore(findings.StoreOptions{MaxEntries: fc.MaxEntries})
	logger.Info("findings aggregation enabled (SARIF export at {admin}/api/findings/sarif)", "maxEntries", fc.MaxEntries)
	return store
}

// buildFindingsDedup constructs the de-duplication metrics accumulator and the
// immutable suppression audit trail (Task 165). Both are gated by their own
// config flags (default on). The ledger mirrors each newly-recorded suppression
// into the tamper-evident audit log via auditSuppressionSink, so the "who/what
// suppressed and why" trail is both queryable per coordinate and hash-chained.
// Either return value may be nil (disabled); the gateway tolerates nil for both.
func buildFindingsDedup(cfg *config.Config, auditLog *audit.Logger, logger *slog.Logger) (*findings.Metrics, *findings.SuppressionLedger) {
	fc := cfg.Findings
	if !fc.Enabled {
		return nil, nil
	}
	var metrics *findings.Metrics
	if fc.DedupEnabled() {
		metrics = findings.NewMetrics()
		logger.Info("findings de-duplication enabled (overlapping gate findings collapsed before risk/SARIF/dossier; metrics: pullthrough_findings_dedup_*)")
	} else {
		logger.Info("findings de-duplication disabled (set findings.dedup to collapse overlapping gate findings)")
	}
	var ledger *findings.SuppressionLedger
	if fc.SuppressionTrailEnabled() {
		ledger = findings.NewSuppressionLedger(findings.SuppressionLedgerOptions{
			MaxEntries: fc.MaxSuppressions,
			Sink:       auditSuppressionSink{log: auditLog},
		})
		logger.Info("findings suppression audit trail enabled (who/what/why per suppressed finding, queryable per coordinate, mirrored to the audit log)")
	} else {
		logger.Info("findings suppression audit trail disabled (set findings.suppressionTrail to record VEX/reachability/policy suppressions)")
	}
	return metrics, ledger
}

// auditSuppressionSink mirrors a newly-recorded suppression into the
// tamper-evident audit log as an EventSuppression record. It satisfies
// findings.AuditSink. A nil logger is a safe no-op (audit.Logger.Log tolerates a
// nil receiver), so suppression recording never depends on the audit log being
// configured.
type auditSuppressionSink struct {
	log *audit.Logger
}

func (s auditSuppressionSink) RecordSuppression(ctx context.Context, rec findings.SuppressionRecord) error {
	if s.log == nil {
		return nil
	}
	detail := map[string]any{
		"mechanism":  string(rec.Mechanism),
		"actor":      rec.Actor,
		"category":   string(rec.Category),
		"coordinate": rec.Coordinate,
	}
	if rec.Digest != "" {
		detail["digest"] = rec.Digest
	}
	if rec.RuleID != "" {
		detail["ruleId"] = rec.RuleID
	}
	if rec.Identifier != "" {
		detail["identifier"] = rec.Identifier
	}
	if rec.Gate != "" {
		detail["gate"] = string(rec.Gate)
	}
	return s.log.Log(ctx, audit.Event{
		Type:     audit.EventSuppression,
		Team:     rec.Tenant,
		Resource: rec.Coordinate,
		Decision: audit.DecisionAllow,
		Reason:   rec.Justification,
		Detail:   detail,
	})
}

// findingsInspector adapts the findings.Store to the admin FindingsInspector,
// supplying the build version stamped into exported SARIF (which the store does
// not itself retain).
type findingsInspector struct {
	store   *findings.Store
	version string
}

func (f findingsInspector) Get(tenant, pkg string) (findings.Document, bool) {
	return f.store.Get(tenant, pkg)
}

func (f findingsInspector) Documents(tenant, q string) []findings.Document {
	return f.store.Documents(tenant, q)
}

func (f findingsInspector) ToolVersion() string { return f.version }

// runFindingsCommand dispatches the `findings` CLI subcommand. Today it offers a
// single action, `sarif`, which renders SARIF 2.1.0 from a batch of aggregated
// admission documents — the air-gapped import-preflight path. It owns its own
// flag set so the live server's global flags stay uncluttered.
func runFindingsCommand(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("findings: a subcommand is required (sarif)")
	}
	switch args[0] {
	case "sarif":
		return runFindingsSARIF(args[1:])
	default:
		return fmt.Errorf("findings: unknown subcommand %q (want: sarif)", args[0])
	}
}

// runFindingsSARIF reads one or more aggregated admission documents
// (policyengine.Input — the same self-describing signal model the policy and
// risk engines evaluate) from a file or stdin and writes a single SARIF 2.1.0 log
// fusing every artifact's findings. This lets a CI pipeline (or an air-gapped
// import preflight) produce CI-ingestible SARIF from exported gate signals
// without a live proxy.
//
// The input is either a single JSON object or a JSON array of objects, each:
//
//	{ "artifact": {...}, "vuln": {...}, "license": {...}, ... }
//
// matching the documented admission-input schema. Unknown fields are tolerated.
func runFindingsSARIF(args []string) error {
	fs := flag.NewFlagSet("findings sarif", flag.ContinueOnError)
	var (
		inPath  = fs.String("input", "", "path to a JSON file of admission input document(s); '-' or empty reads stdin")
		outPath = fs.String("output", "", "path to write the SARIF log (default stdout)")
		toolVer = fs.String("tool-version", version, "tool version recorded in the SARIF driver")
	)
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "Usage: pullthrough findings sarif [-input <file>] [-output <file>] [-tool-version <v>]")
		fmt.Fprintln(os.Stderr, "Reads aggregated admission input document(s) (JSON object or array) and writes SARIF 2.1.0.")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return err
	}

	raw, err := readInput(*inPath)
	if err != nil {
		return fmt.Errorf("findings sarif: reading input: %w", err)
	}

	inputs, err := decodeInputs(raw)
	if err != nil {
		return fmt.Errorf("findings sarif: parsing input: %w", err)
	}

	docs := make([]findings.Document, 0, len(inputs))
	for _, in := range inputs {
		doc := findings.FromInput(in, findings.Options{})
		// Collapse overlapping gate findings before export so the SARIF a CI
		// pipeline ingests does not double-count the same issue (Task 165).
		doc.Deduplicate()
		docs = append(docs, doc)
	}
	log := findings.SARIFFromDocuments(docs, findings.SARIFOptions{ToolVersion: *toolVer})

	out := os.Stdout
	if *outPath != "" {
		f, ferr := os.Create(*outPath)
		if ferr != nil {
			return fmt.Errorf("findings sarif: creating output: %w", ferr)
		}
		defer f.Close()
		out = f
	}
	enc := json.NewEncoder(out)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	if err := enc.Encode(log); err != nil {
		return fmt.Errorf("findings sarif: encoding SARIF: %w", err)
	}
	if *outPath != "" {
		fmt.Fprintf(os.Stderr, "findings sarif: wrote %d artifact(s), %d finding(s) to %s\n",
			len(docs), totalFindings(docs), *outPath)
	}
	return nil
}

// decodeInputs parses raw JSON that is either a single admission input object or
// a JSON array of them, tolerating leading whitespace.
func decodeInputs(raw []byte) ([]policyengine.Input, error) {
	trimmed := skipSpace(raw)
	if len(trimmed) == 0 {
		return nil, fmt.Errorf("input is empty")
	}
	if trimmed[0] == '[' {
		var arr []policyengine.Input
		if err := json.Unmarshal(raw, &arr); err != nil {
			return nil, err
		}
		return arr, nil
	}
	var one policyengine.Input
	if err := json.Unmarshal(raw, &one); err != nil {
		return nil, err
	}
	return []policyengine.Input{one}, nil
}

func skipSpace(b []byte) []byte {
	for i, c := range b {
		switch c {
		case ' ', '\t', '\r', '\n':
			continue
		default:
			return b[i:]
		}
	}
	return nil
}

// readInput reads from path, or from stdin when path is empty or "-".
func readInput(path string) ([]byte, error) {
	if path == "" || path == "-" {
		return io.ReadAll(os.Stdin)
	}
	return os.ReadFile(path)
}

func totalFindings(docs []findings.Document) int {
	n := 0
	for i := range docs {
		n += len(docs[i].Findings)
	}
	return n
}
