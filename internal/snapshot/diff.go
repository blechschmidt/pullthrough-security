package snapshot

import (
	"fmt"
	"sort"
	"time"

	"github.com/blechschmidt/pullthrough-security/internal/sbomdiff"
)

// Diff is the structured comparison of two snapshots. It reuses the sbomdiff
// drift-scoring concept (an explainable, weighted, clamped 0..100 score with a
// per-factor contribution breakdown) applied to coordinate-level deltas instead
// of dependency-level ones.
type Diff struct {
	From SnapshotRef `json:"from"`
	To   SnapshotRef `json:"to"`

	// Added are coordinates present in To but not in From (newly served).
	Added []Entry `json:"added"`
	// Removed are coordinates present in From but not in To (no longer served).
	Removed []Entry `json:"removed"`
	// DigestChanges are coordinates served at the same (name, version) but with a
	// different content digest — the strongest tamper / re-publish signal.
	DigestChanges []DigestChange `json:"digestChanges"`
	// VerdictChanges are coordinates whose admission verdict changed.
	VerdictChanges []FieldChange `json:"verdictChanges"`
	// BandChanges are coordinates whose risk band changed.
	BandChanges []FieldChange `json:"bandChanges"`
	// CommitChanges are coordinates whose source commit changed for the same
	// version (a provenance discontinuity).
	CommitChanges []FieldChange `json:"commitChanges"`

	DriftScore    float64                 `json:"driftScore"`
	Contributions []sbomdiff.Contribution `json:"contributions,omitempty"`
	Significant   bool                    `json:"significant"`
}

// SnapshotRef identifies a side of the diff.
type SnapshotRef struct {
	ID         string    `json:"id"`
	Name       string    `json:"name,omitempty"`
	CreatedAt  time.Time `json:"createdAt"`
	EntryCount int       `json:"entryCount"`
}

// DigestChange is one coordinate served with two different digests.
type DigestChange struct {
	Coordinate string `json:"coordinate"`
	Ecosystem  string `json:"ecosystem"`
	Name       string `json:"name"`
	Version    string `json:"version"`
	FromDigest string `json:"fromDigest"`
	ToDigest   string `json:"toDigest"`
}

// FieldChange is a generic from->to change of a single field on a coordinate.
type FieldChange struct {
	Coordinate string `json:"coordinate"`
	From       string `json:"from"`
	To         string `json:"to"`
}

// Empty reports whether the diff found no material change.
func (d *Diff) Empty() bool {
	return len(d.Added) == 0 && len(d.Removed) == 0 && len(d.DigestChanges) == 0 &&
		len(d.VerdictChanges) == 0 && len(d.BandChanges) == 0 && len(d.CommitChanges) == 0
}

// diffWeights mirrors the sbomdiff weighting model, tuned for snapshot-level
// deltas: digest changes and band escalations dominate because they signal
// tampering or a security regression rather than normal churn.
type diffWeights struct {
	perAdded         float64
	perRemoved       float64
	perDigestChange  float64
	perVerdictChange float64
	perBandChange    float64
	perCommitChange  float64
}

func defaultDiffWeights() diffWeights {
	return diffWeights{
		perAdded:         2,
		perRemoved:       1,
		perDigestChange:  30,
		perVerdictChange: 10,
		perBandChange:    12,
		perCommitChange:  15,
	}
}

const significantDrift = 25

// Diff computes the comparison between two snapshots by id. It is pure and
// deterministic. Returns ok=false when either id is unknown.
func (s *Service) Diff(fromID, toID string) (*Diff, bool) {
	from, ok := s.Get(fromID)
	if !ok {
		return nil, false
	}
	to, ok := s.Get(toID)
	if !ok {
		return nil, false
	}
	return computeDiff(from, to), true
}

// computeDiff is the pure comparison core, exported-adjacent for testing.
func computeDiff(from, to *Manifest) *Diff {
	d := &Diff{
		From: SnapshotRef{ID: from.ID, Name: from.Name, CreatedAt: from.CreatedAt, EntryCount: from.EntryCount},
		To:   SnapshotRef{ID: to.ID, Name: to.Name, CreatedAt: to.CreatedAt, EntryCount: to.EntryCount},
	}
	fromByKey := indexByKey(from.Entries)
	toByKey := indexByKey(to.Entries)

	// Removed and changed: iterate the From side.
	for _, fe := range from.Entries {
		te, ok := toByKey[fe.key()]
		if !ok {
			d.Removed = append(d.Removed, fe)
			continue
		}
		if fe.Digest != "" && te.Digest != "" && !digestEqual(fe.Digest, te.Digest) {
			d.DigestChanges = append(d.DigestChanges, DigestChange{
				Coordinate: te.Coordinate, Ecosystem: te.Ecosystem, Name: te.Name, Version: te.Version,
				FromDigest: fe.Digest, ToDigest: te.Digest,
			})
		}
		if fe.Verdict != te.Verdict {
			d.VerdictChanges = append(d.VerdictChanges, FieldChange{Coordinate: te.Coordinate, From: fe.Verdict, To: te.Verdict})
		}
		if fe.RiskBand != te.RiskBand {
			d.BandChanges = append(d.BandChanges, FieldChange{Coordinate: te.Coordinate, From: fe.RiskBand, To: te.RiskBand})
		}
		if fe.SourceCommit != "" && te.SourceCommit != "" && fe.SourceCommit != te.SourceCommit {
			d.CommitChanges = append(d.CommitChanges, FieldChange{Coordinate: te.Coordinate, From: fe.SourceCommit, To: te.SourceCommit})
		}
	}
	// Added: iterate the To side for coordinates absent from From.
	for _, te := range to.Entries {
		if _, ok := fromByKey[te.key()]; !ok {
			d.Added = append(d.Added, te)
		}
	}

	sortEntries(d.Added)
	sortEntries(d.Removed)
	sort.Slice(d.DigestChanges, func(i, j int) bool { return d.DigestChanges[i].Coordinate < d.DigestChanges[j].Coordinate })
	sortFieldChanges(d.VerdictChanges)
	sortFieldChanges(d.BandChanges)
	sortFieldChanges(d.CommitChanges)

	d.scoreDrift(defaultDiffWeights())
	d.Significant = d.DriftScore >= significantDrift
	return d
}

// scoreDrift computes the explainable composite drift score, clamped to [0,100].
func (d *Diff) scoreDrift(w diffWeights) {
	add := func(factor string, count int, per float64) {
		if count <= 0 || per == 0 {
			return
		}
		d.Contributions = append(d.Contributions, sbomdiff.Contribution{
			Factor: factor, Count: count, Points: float64(count) * per,
		})
	}
	add("digest-changes", len(d.DigestChanges), w.perDigestChange)
	add("commit-changes", len(d.CommitChanges), w.perCommitChange)
	add("band-changes", len(d.BandChanges), w.perBandChange)
	add("verdict-changes", len(d.VerdictChanges), w.perVerdictChange)
	add("added-coordinates", len(d.Added), w.perAdded)
	add("removed-coordinates", len(d.Removed), w.perRemoved)

	var total float64
	for _, c := range d.Contributions {
		total += c.Points
	}
	if total > 100 {
		total = 100
	}
	d.DriftScore = float64(int(total*10+0.5)) / 10
}

// Markdown renders a human-readable diff report.
func (d *Diff) Markdown() string {
	var b []byte
	w := func(format string, args ...any) { b = append(b, []byte(fmt.Sprintf(format, args...))...) }
	w("# Snapshot diff\n\n")
	w("- **From:** `%s` %s (%d entries, %s)\n", shortDigest(d.From.ID), d.From.Name, d.From.EntryCount, d.From.CreatedAt.Format(time.RFC3339))
	w("- **To:** `%s` %s (%d entries, %s)\n", shortDigest(d.To.ID), d.To.Name, d.To.EntryCount, d.To.CreatedAt.Format(time.RFC3339))
	w("- **Drift score:** %.1f%s\n\n", d.DriftScore, significanceTag(d.Significant))
	if d.Empty() {
		w("No material change.\n")
		return string(b)
	}
	if len(d.DigestChanges) > 0 {
		w("## Digest changes (%d) — possible tamper / re-publish\n\n", len(d.DigestChanges))
		for _, c := range d.DigestChanges {
			w("- `%s`: %s → %s\n", c.Coordinate, shortDigest(c.FromDigest), shortDigest(c.ToDigest))
		}
		w("\n")
	}
	if len(d.BandChanges) > 0 {
		w("## Risk-band changes (%d)\n\n", len(d.BandChanges))
		for _, c := range d.BandChanges {
			w("- `%s`: %s → %s\n", c.Coordinate, orDash(c.From), orDash(c.To))
		}
		w("\n")
	}
	if len(d.VerdictChanges) > 0 {
		w("## Verdict changes (%d)\n\n", len(d.VerdictChanges))
		for _, c := range d.VerdictChanges {
			w("- `%s`: %s → %s\n", c.Coordinate, orDash(c.From), orDash(c.To))
		}
		w("\n")
	}
	if len(d.CommitChanges) > 0 {
		w("## Source-commit changes (%d)\n\n", len(d.CommitChanges))
		for _, c := range d.CommitChanges {
			w("- `%s`: %s → %s\n", c.Coordinate, shortCommit(c.From), shortCommit(c.To))
		}
		w("\n")
	}
	if len(d.Added) > 0 {
		w("## Added coordinates (%d)\n\n", len(d.Added))
		for _, e := range d.Added {
			w("- `%s` %s\n", e.Coordinate, shortDigest(e.Digest))
		}
		w("\n")
	}
	if len(d.Removed) > 0 {
		w("## Removed coordinates (%d)\n\n", len(d.Removed))
		for _, e := range d.Removed {
			w("- `%s`\n", e.Coordinate)
		}
		w("\n")
	}
	return string(b)
}

func indexByKey(entries []Entry) map[string]Entry {
	m := make(map[string]Entry, len(entries))
	for _, e := range entries {
		m[e.key()] = e
	}
	return m
}

func sortFieldChanges(c []FieldChange) {
	sort.Slice(c, func(i, j int) bool { return c[i].Coordinate < c[j].Coordinate })
}

func significanceTag(sig bool) string {
	if sig {
		return " (significant)"
	}
	return ""
}

func orDash(s string) string {
	if s == "" {
		return "—"
	}
	return s
}

func shortCommit(c string) string {
	if len(c) > 12 {
		return c[:12]
	}
	if c == "" {
		return "—"
	}
	return c
}
