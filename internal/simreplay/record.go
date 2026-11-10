// Package simreplay provides a deterministic policy & risk "what-if" simulation
// and replay harness (Task 47). It lets operators test candidate policyengine
// bundles, riskscore weights, and admission-gate changes against historical
// traffic BEFORE rolling them out.
//
// The flow has three stages:
//
//  1. Capture. A bounded, sampled, redacted ring buffer (Recorder) records the
//     canonical admission document (policyengine.Input) and the baseline verdict
//     each pull produced live, keyed by tenant/coordinate. The recorder is wired
//     into the pull path and exports its buffer as a self-describing Capture.
//
//  2. Persist. A Capture is a versioned, self-describing JSON envelope (Save /
//     Load) so a buffer captured on one replica can be replayed elsewhere — in
//     CI, on a laptop, or in an air-gapped environment.
//
//  3. Replay. Run evaluates every captured record through a candidate Evaluator
//     (a policy engine + risk engine built from the candidate config) and diffs
//     the candidate verdict against the baseline, producing a DiffReport: which
//     pulls would flip admit<->block, risk-band shifts, new policy violations,
//     and per-tenant blast radius.
//
// Every stage is deterministic: capture sampling is counter-based (not random),
// the engines evaluate purely (no clock, no state mutation), and the report
// orders records by capture sequence and tenants lexicographically. The same
// capture replayed through the same candidate always yields the same report.
package simreplay

import (
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/blechschmidt/pullthrough-security/internal/policyengine"
	"github.com/blechschmidt/pullthrough-security/internal/riskscore"
)

// CaptureVersion is the schema version stamped into persisted Capture files. It
// is bumped only on incompatible changes to the on-disk record shape.
const CaptureVersion = 1

// Record is one captured admission event: the canonical, redacted signal
// document plus the baseline verdict the live configuration produced for it. It
// is the unit of replay.
type Record struct {
	// Seq is the monotonic capture sequence number assigned by the recorder. It
	// gives every record a stable identity and a deterministic replay order.
	Seq int64 `json:"seq"`
	// CapturedAt is the wall-clock time the record was captured.
	CapturedAt time.Time `json:"capturedAt"`
	// Tenant is the team/tenant the pull was attributed to ("" when anonymous).
	Tenant string `json:"tenant,omitempty"`
	// Coordinate is the artifact identity (name@version) for human-readable diffs.
	Coordinate string `json:"coordinate,omitempty"`
	// Input is the canonical admission document (redacted) the gates evaluated.
	Input policyengine.Input `json:"input"`
	// Baseline is the verdict the live configuration produced at capture time. It
	// is the reference the candidate is diffed against unless Run is given an
	// explicit baseline Evaluator to recompute it.
	Baseline Verdict `json:"baseline"`
}

// VerdictMatch records one policy rule that fired during evaluation.
type VerdictMatch struct {
	RuleID string              `json:"ruleId"`
	Action policyengine.Action `json:"action,omitempty"`
}

// Verdict is the admission outcome a configuration produces for one input. It
// fuses the policy-as-code decision and the unified risk score into the single
// admit/block result the pull path enforces, while retaining the per-gate detail
// needed to explain a diff.
type Verdict struct {
	// PolicyEnabled reports whether a policy engine contributed to this verdict.
	PolicyEnabled bool `json:"policyEnabled"`
	// PolicyAction is the effective policy action after the engine's mode
	// (enforce/audit) is applied — the action the pull path would actually honor.
	PolicyAction policyengine.Action `json:"policyAction,omitempty"`
	// PolicyReason is the human-readable explanation for the policy decision.
	PolicyReason string `json:"policyReason,omitempty"`
	// PolicyMatches lists the rules that fired, in evaluation order.
	PolicyMatches []VerdictMatch `json:"policyMatches,omitempty"`

	// RiskEnabled reports whether a risk engine contributed to this verdict.
	RiskEnabled bool `json:"riskEnabled"`
	// RiskScore is the composite 0..100 risk score.
	RiskScore int `json:"riskScore"`
	// RiskBand is the coarse risk band (low|medium|high|critical).
	RiskBand riskscore.Band `json:"riskBand,omitempty"`
	// RiskAction is the threshold action the risk band triggered (off|warn|block).
	RiskAction riskscore.ThresholdAction `json:"riskAction,omitempty"`
	// RiskExceeds reports whether the band met/exceeded the admission threshold.
	RiskExceeds bool `json:"riskExceeds"`

	// Admitted is the overall outcome: true when no gate blocked the pull. It is
	// the canonical field flips are computed from.
	Admitted bool `json:"admitted"`
}

// Blocked reports whether any gate blocked the pull (policy deny or risk block).
func (v Verdict) Blocked() bool {
	if v.PolicyEnabled && v.PolicyAction == policyengine.ActionDeny {
		return true
	}
	if v.RiskEnabled && v.RiskAction == riskscore.ThresholdBlock {
		return true
	}
	return false
}

// finalize recomputes the derived Admitted field from the per-gate fields so a
// hand-constructed or deserialized Verdict is always self-consistent.
func (v Verdict) finalize() Verdict {
	v.Admitted = !v.Blocked()
	return v
}

// DenyRuleIDs returns the IDs of the rules whose action denies admission.
func (v Verdict) DenyRuleIDs() []string {
	var out []string
	for _, m := range v.PolicyMatches {
		if m.Action == policyengine.ActionDeny {
			out = append(out, m.RuleID)
		}
	}
	return out
}

// ruleIDSet returns the set of all matched rule IDs for diffing.
func (v Verdict) ruleIDSet() map[string]struct{} {
	s := make(map[string]struct{}, len(v.PolicyMatches))
	for _, m := range v.PolicyMatches {
		s[m.RuleID] = struct{}{}
	}
	return s
}

// Capture is the self-describing, versioned envelope persisted to disk and
// returned by the recorder's export. It is the wire/file format both the CLI and
// the admin endpoint accept as the captured-traffic input.
type Capture struct {
	// Version is the schema version (CaptureVersion). Load rejects unknown ones.
	Version int `json:"version"`
	// ExportedAt is when the buffer was exported (informational).
	ExportedAt time.Time `json:"exportedAt"`
	// Sampling describes how the buffer was sampled, for provenance.
	Sampling SamplingInfo `json:"sampling"`
	// Records are the captured admission events, oldest-first.
	Records []Record `json:"records"`
}

// SamplingInfo documents how a capture buffer was sampled so a reader can judge
// how representative it is of live traffic.
type SamplingInfo struct {
	// Capacity is the ring-buffer size the records were drawn from.
	Capacity int `json:"capacity"`
	// SampleRate is the 1-in-N capture rate (1 = every pull captured).
	SampleRate int `json:"sampleRate"`
	// Observed is the total number of pulls the recorder saw.
	Observed int64 `json:"observed"`
	// Captured is the number of pulls actually recorded (after sampling).
	Captured int64 `json:"captured"`
	// Redacted reports whether sensitive fields were stripped on capture.
	Redacted bool `json:"redacted"`
}

// Save writes the capture as indented JSON to path. HTML escaping is disabled so
// identifiers containing <, >, or & round-trip verbatim.
func (c Capture) Save(path string) error {
	f, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("simreplay: creating capture file: %w", err)
	}
	defer f.Close()
	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	if err := enc.Encode(c); err != nil {
		return fmt.Errorf("simreplay: encoding capture: %w", err)
	}
	return nil
}

// LoadCapture reads and validates a capture file written by Save (or exported by
// the admin endpoint). It tolerates a bare JSON array of Records (an unwrapped
// capture) for convenience.
func LoadCapture(path string) (Capture, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return Capture{}, fmt.Errorf("simreplay: reading capture file: %w", err)
	}
	return ParseCapture(raw)
}

// ParseCapture parses a capture from raw JSON, accepting either the versioned
// envelope or a bare array of records.
func ParseCapture(raw []byte) (Capture, error) {
	trimmed := skipLeadingSpace(raw)
	if len(trimmed) == 0 {
		return Capture{}, fmt.Errorf("simreplay: capture is empty")
	}
	if trimmed[0] == '[' {
		var recs []Record
		if err := json.Unmarshal(raw, &recs); err != nil {
			return Capture{}, fmt.Errorf("simreplay: parsing capture records: %w", err)
		}
		return Capture{Version: CaptureVersion, Records: normalizeRecords(recs)}, nil
	}
	var c Capture
	if err := json.Unmarshal(raw, &c); err != nil {
		return Capture{}, fmt.Errorf("simreplay: parsing capture: %w", err)
	}
	if c.Version == 0 {
		// An envelope without a version is tolerated as the current schema; an
		// explicit unknown future version is rejected.
		c.Version = CaptureVersion
	}
	if c.Version != CaptureVersion {
		return Capture{}, fmt.Errorf("simreplay: unsupported capture version %d (want %d)", c.Version, CaptureVersion)
	}
	c.Records = normalizeRecords(c.Records)
	return c, nil
}

// normalizeRecords ensures every record has a self-consistent baseline verdict
// and a coordinate, so externally-authored captures (which may omit the derived
// fields) replay correctly.
func normalizeRecords(recs []Record) []Record {
	for i := range recs {
		recs[i].Baseline = recs[i].Baseline.finalize()
		if recs[i].Coordinate == "" {
			recs[i].Coordinate = coordinate(recs[i].Input.Artifact.Name, recs[i].Input.Artifact.Version)
		}
	}
	return recs
}

func skipLeadingSpace(b []byte) []byte {
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

func coordinate(name, version string) string {
	if name == "" {
		return ""
	}
	if version == "" {
		return name
	}
	return name + "@" + version
}
