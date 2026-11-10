// Package covguard implements statement-coverage measurement, a committed
// coverage baseline, and a coverage-regression gate for CI. It is the coverage
// analogue of internal/loadbench's performance-regression guard (Task 112):
// `ptctl covguard` runs `go test ./... -coverprofile`, aggregates per-package
// and total statement coverage, and either records a baseline or compares a
// fresh run against the committed baseline and fails when total coverage drops
// beyond a threshold or a critical package falls under its floor.
//
// Coverage is parsed directly from Go's coverprofile format, so the numbers are
// identical to `go tool cover -func` and independent of the cover mode
// (set/count/atomic) — the percentage is always covered-statements over
// total-statements.
package covguard

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// BaselineSchemaVersion is the on-disk schema version of a stored coverage
// baseline. It is bumped if the file layout changes in a way that makes an
// older baseline incomparable, so a stale file is rejected with a clear message
// rather than silently mis-compared.
const BaselineSchemaVersion = 1

// Coverage is the statement-coverage tally for one package (or the whole run).
type Coverage struct {
	// Covered is the number of statements executed at least once.
	Covered int `json:"coveredStatements"`
	// Total is the number of statements instrumented.
	Total int `json:"totalStatements"`
	// Pct is the derived coverage percentage, carried in the file for
	// human-readability; it is always recomputed from Covered/Total on load so a
	// hand-edited percentage cannot desync from the counts.
	Pct float64 `json:"coveragePct"`
}

// percent returns covered/total as a percentage, treating a zero-statement
// package as 100% (a package with no executable statements cannot regress).
func percent(covered, total int) float64 {
	if total <= 0 {
		return 100
	}
	return float64(covered) / float64(total) * 100
}

// recompute refreshes the derived percentage from the counts.
func (c *Coverage) recompute() { c.Pct = percent(c.Covered, c.Total) }

// Baseline is a committed snapshot of per-package and total statement coverage
// for the whole module, produced by `ptctl covguard -update-baseline` and
// checked into the repo at coverage/coverage-baseline.json. A later run is
// compared against it by the regression gate.
type Baseline struct {
	// SchemaVersion guards against comparing against an incompatible layout.
	SchemaVersion int `json:"schemaVersion"`
	// CapturedAt is when the baseline run completed (RFC 3339).
	CapturedAt time.Time `json:"capturedAt"`
	// Tool is the version of the harness that produced the baseline.
	Tool string `json:"tool,omitempty"`
	// Mode is the cover mode the profile was produced with (set/count/atomic),
	// recorded for traceability only — it does not affect the percentages.
	Mode string `json:"mode,omitempty"`
	// Total is the module-wide coverage over every package in the profile.
	Total Coverage `json:"total"`
	// Packages holds one tally per package, keyed by full import path.
	Packages map[string]Coverage `json:"packages"`
	// CriticalFloors is the committed floor (minimum coverage %) for packages
	// whose coverage must not fall below a hard minimum. It is persisted in the
	// baseline so the critical-package gate is repeatable without re-specifying
	// floors on every run; a `-critical` flag overrides it per invocation.
	CriticalFloors map[string]float64 `json:"criticalFloors,omitempty"`
}

// ParseProfile reads a Go coverprofile and aggregates it into a Baseline with
// per-package and total tallies. It does not set CapturedAt/Tool/CriticalFloors;
// the caller fills those in. Lines that do not match the coverprofile grammar
// are rejected so a truncated or wrong-format file fails loudly.
func ParseProfile(r io.Reader) (*Baseline, error) {
	b := &Baseline{
		SchemaVersion: BaselineSchemaVersion,
		Packages:      map[string]Coverage{},
	}
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	lineNo := 0
	sawMode := false
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		lineNo++
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "mode:") {
			b.Mode = strings.TrimSpace(strings.TrimPrefix(line, "mode:"))
			sawMode = true
			continue
		}
		pkg, numStmts, count, err := parseProfileLine(line)
		if err != nil {
			return nil, fmt.Errorf("coverprofile line %d: %w", lineNo, err)
		}
		cov := b.Packages[pkg]
		cov.Total += numStmts
		if count > 0 {
			cov.Covered += numStmts
		}
		b.Packages[pkg] = cov
		b.Total.Total += numStmts
		if count > 0 {
			b.Total.Covered += numStmts
		}
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("reading coverprofile: %w", err)
	}
	if !sawMode {
		return nil, fmt.Errorf("coverprofile has no 'mode:' header — is this a valid profile?")
	}
	if len(b.Packages) == 0 {
		return nil, fmt.Errorf("coverprofile contains no coverage data (did any tests run with coverage?)")
	}
	b.Total.recompute()
	for name, cov := range b.Packages {
		cov.recompute()
		b.Packages[name] = cov
	}
	return b, nil
}

// parseProfileLine parses one coverprofile block line of the form:
//
//	import/path/file.go:startLine.startCol,endLine.endCol numStmts count
//
// and returns the owning package import path, statement count, and hit count.
func parseProfileLine(line string) (pkg string, numStmts, count int, err error) {
	fields := strings.Fields(line)
	if len(fields) != 3 {
		return "", 0, 0, fmt.Errorf("expected 3 fields, got %d: %q", len(fields), line)
	}
	numStmts, err = strconv.Atoi(fields[1])
	if err != nil {
		return "", 0, 0, fmt.Errorf("invalid statement count %q: %w", fields[1], err)
	}
	count, err = strconv.Atoi(fields[2])
	if err != nil {
		return "", 0, 0, fmt.Errorf("invalid hit count %q: %w", fields[2], err)
	}
	// fields[0] is "file:startLine.startCol,endLine.endCol"; the position block
	// is after the final colon, so the file path is everything before it.
	colon := strings.LastIndex(fields[0], ":")
	if colon <= 0 {
		return "", 0, 0, fmt.Errorf("malformed block position %q", fields[0])
	}
	file := fields[0][:colon]
	// Import paths use forward slashes regardless of host OS, so use path.Dir.
	return path.Dir(file), numStmts, count, nil
}

// LoadBaseline reads and validates a baseline JSON file.
func LoadBaseline(pathname string) (*Baseline, error) {
	f, err := os.Open(pathname)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return DecodeBaseline(f)
}

// DecodeBaseline reads a baseline from r, validates its schema version, and
// recomputes derived percentages so a hand-edited file stays self-consistent.
func DecodeBaseline(r io.Reader) (*Baseline, error) {
	var b Baseline
	dec := json.NewDecoder(r)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&b); err != nil {
		return nil, fmt.Errorf("decode baseline: %w", err)
	}
	if b.SchemaVersion != BaselineSchemaVersion {
		return nil, fmt.Errorf("baseline schema version %d is not supported (this build expects %d); regenerate with -update-baseline",
			b.SchemaVersion, BaselineSchemaVersion)
	}
	if len(b.Packages) == 0 {
		return nil, fmt.Errorf("baseline contains no packages")
	}
	b.Total.recompute()
	for name, cov := range b.Packages {
		cov.recompute()
		b.Packages[name] = cov
	}
	return &b, nil
}

// Save writes the baseline to path as indented JSON, creating parent
// directories as needed. The write is atomic (temp file + rename) so a crash
// mid-write cannot leave a truncated, un-parseable baseline checked out.
func (b *Baseline) Save(pathname string) error {
	if err := os.MkdirAll(filepath.Dir(pathname), 0o755); err != nil {
		return err
	}
	data, err := json.MarshalIndent(b, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')

	tmp, err := os.CreateTemp(filepath.Dir(pathname), ".coverage-baseline-*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName) // no-op once the rename succeeds
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, pathname)
}
