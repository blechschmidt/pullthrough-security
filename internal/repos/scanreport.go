package repos

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/blechschmidt/pullthrough-security/internal/findings"
	"github.com/blechschmidt/pullthrough-security/internal/lockfiles"
)

// The read side of the dependency scans (Task 181): the stored reports, their
// findings documents (SARIF located at the lock file's line), and the views the
// admin API, the dossier and the query API take of them.

// RepoScanEcosystem is the findings "ecosystem" of a repository scan's
// document: the document describes a repository revision, not a package.
const RepoScanEcosystem = "repository"

// RepoScanName is the findings name of a repository's scan documents.
func RepoScanName(repo string) string { return "repo:" + repo }

// FindingsDocument renders the report as a findings document: one finding per
// lock-file location of each dependency that is not benign — malicious,
// suspicious, or unscanned (which is never benign) — so a SARIF consumer
// annotates the line of the lock file that pins it. A dependency a break-glass
// grant releases is reported suppressed, with the grant.
//
// Messages are the proxy's own sentences. What the model said (its reasons) is
// carried in the result properties, labeled as model output; the excerpts it
// quoted from the package are not carried at all (they are on the admin
// surface, rendered inertly).
func (r *ScanReport) FindingsDocument() findings.Document {
	version := r.Commit
	if r.Kind == ScanHead && r.Ref != "" {
		version = r.Ref
	}
	return r.document(version)
}

// headDocument is the document under the default branch's name: the head's
// findings, replaced by each scan of the head.
func (r *ScanReport) headDocument() findings.Document {
	return r.document(firstNonEmpty(r.Branch, firstNonEmpty(r.Ref, r.Commit)))
}

// Bounds on a scan's findings document: every finding is a SARIF result and a
// SIEM event.
const (
	maxLocationsPerDependency = 20
	maxFindingsPerDocument    = 10000
)

func (r *ScanReport) document(version string) findings.Document {
	doc := findings.Document{
		Tenant: r.Tenant,
		Artifact: findings.Artifact{
			Ecosystem: RepoScanEcosystem, Backend: "repos", Name: RepoScanName(r.Repo), Version: version,
			Coordinate: RepoScanName(r.Repo) + "@" + version, CommitSHA: r.Commit, RepositoryURL: r.URL,
		},
		GeneratedAt: r.FinishedAt,
	}
	for _, d := range r.Dependencies {
		if d.Verdict == VerdictBenign {
			continue
		}
		rule, sev, ident := findings.RuleLLMUnscannedDependency, findings.SeverityLow, "unscanned"
		switch d.Verdict {
		case VerdictMalicious:
			rule, sev = findings.RuleLLMMaliciousDependency, findings.SeverityCritical
		case VerdictSuspicious:
			rule, sev = findings.RuleLLMSuspiciousDependency, findings.SeverityMedium
			if d.Detail != nil && d.Detail.ModelVerdict == VerdictMalicious {
				sev = findings.SeverityHigh // called malicious, held as suspicious by the threshold
			}
		}
		props := map[string]any{
			"verdict":    d.Verdict,
			"repository": r.Repo,
			"commit":     r.Commit,
			"scanKind":   r.Kind,
			"dependency": d.Coordinate(),
		}
		if r.Ref != "" {
			props["ref"] = r.Ref
		}
		if d.Pinned {
			props["pinned"] = true
		}
		if d.Refused {
			props["refused"] = true
		}
		if v := d.Detail; v != nil {
			ident = v.Digest
			props["digest"] = v.Digest
			props["modelVerdict"] = v.ModelVerdict
			props["confidence"] = v.Confidence
			props["model"] = v.Model
			props["provider"] = v.Provider
			props["promptVersion"] = v.PromptVersion
			if !v.ScannedAt.IsZero() {
				props["scannedAt"] = v.ScannedAt.UTC().Format(time.RFC3339)
			}
			if v.Scope != "" {
				props["scope"] = v.Scope
			}
			// Only the places the proxy found the model's quote at: a path the
			// model named and the proxy did not find is the model's text, and
			// a document travels to CI, the SIEM and AI agents. The model's
			// reasons and the excerpts are on the admin surface only.
			var cited []any
			for _, ev := range v.Evidence {
				if ev.Verified {
					cited = append(cited, map[string]any{"path": ev.Path, "line": ev.Line})
				}
			}
			if len(cited) > 0 {
				props["verifiedEvidence"] = cited
			}
		}
		if u := d.Unscanned; u != nil {
			ident = "unscanned:" + u.Code
			props["unscannedCode"] = u.Code
			props["unscannedReason"] = u.Reason
			if u.Retryable {
				props["retryable"] = true
			}
		}
		title := fmt.Sprintf("Dependency %s judged %s by the LLM package-content scan", d.Coordinate(), d.Verdict)
		message := scanSentence(r, d)
		if d.Verdict == VerdictUnscanned {
			title = fmt.Sprintf("Dependency %s could not be examined by the LLM package-content scan", d.Coordinate())
			reason := "no reason recorded"
			if d.Unscanned != nil {
				reason = d.Unscanned.Code + ": " + d.Unscanned.Reason
			}
			message = capitalize(fmt.Sprintf("%s of %s pins %s, which the LLM package-content scan could not examine (%s). An unscanned dependency is not a clean one.",
				scanWhere(r), r.Repo, plainText(d.Coordinate()), reason))
		}
		locs := lockLocations(d.Files)
		if len(locs) == 0 {
			locs = []lockLocation{{}}
		}
		if len(locs) > maxLocationsPerDependency {
			props["moreLocations"] = len(locs) - maxLocationsPerDependency
			locs = locs[:maxLocationsPerDependency]
		}
		for _, loc := range locs {
			if len(doc.Findings) >= maxFindingsPerDocument {
				break
			}
			f := findings.Finding{
				RuleID: rule, Gate: findings.GateLLMPkgScan, Severity: sev, Identifier: ident,
				Title: title, Message: message,
				Location:   findings.Location{Coordinate: d.Coordinate(), File: loc.path, Line: loc.line},
				Properties: copyProps(props),
			}
			if d.Released != "" {
				f.Suppressed = true
				f.Justification = "released by break-glass approval " + d.Released
				f.Properties[findings.PropSuppressionMechanism] = string(findings.MechanismBreakGlass)
				f.Properties[findings.PropSuppressedBy] = d.Released
			}
			doc.Add(f)
		}
	}
	// A lock file that was found and not read: whatever it pins is unscanned.
	unread := map[string]string{}
	var order []string
	for _, lf := range r.LockFiles {
		if lf.Error != "" {
			unread[lf.Path] = "it could not be read: " + lf.Error
			order = append(order, lf.Path)
		}
	}
	for _, sk := range r.Skipped {
		if strings.HasSuffix(sk.Path, "/") {
			continue // a directory passed over on purpose
		}
		if _, dup := unread[sk.Path]; !dup {
			unread[sk.Path] = "it was not read: " + sk.Reason
			order = append(order, sk.Path)
		}
	}
	for _, path := range order {
		if len(doc.Findings) >= maxFindingsPerDocument {
			break
		}
		doc.Add(findings.Finding{
			RuleID: findings.RuleLLMUnscannedDependency, Gate: findings.GateLLMPkgScan, Severity: findings.SeverityLow,
			Identifier: "unscanned:lockfile-unread",
			Title:      "Lock file " + plainText(path) + " was not read: its dependencies were not scanned",
			Message: capitalize(fmt.Sprintf("%s of %s has the lock file %s, and %s. The dependencies it pins were not examined by the LLM package-content scan; an unscanned dependency is not a clean one.",
				scanWhere(r), r.Repo, plainText(path), unread[path])),
			Location: findings.Location{File: path},
			Properties: map[string]any{"verdict": VerdictUnscanned, "unscannedCode": "lockfile-unread", "repository": r.Repo,
				"commit": r.Commit, "scanKind": r.Kind, "lockFile": path},
		})
	}
	if total := r.findingCount(); total > len(doc.Findings) {
		// What did not fit is in the report (admin API, ptctl repos report):
		// the document says so rather than looking complete.
		doc.Findings[len(doc.Findings)-1].Properties["omittedResults"] = total - len(doc.Findings)
	}
	return doc
}

// findingCount is how many findings the report would make without bounds.
func (r *ScanReport) findingCount() int {
	n := 0
	for _, d := range r.Dependencies {
		if d.Verdict == VerdictBenign {
			continue
		}
		locs := len(lockLocations(d.Files))
		switch {
		case locs == 0:
			locs = 1
		case locs > maxLocationsPerDependency:
			locs = maxLocationsPerDependency
		}
		n += locs
	}
	for _, lf := range r.LockFiles {
		if lf.Error != "" {
			n++
		}
	}
	for _, sk := range r.Skipped {
		if !strings.HasSuffix(sk.Path, "/") {
			n++
		}
	}
	return n
}

func copyProps(in map[string]any) map[string]any {
	out := make(map[string]any, len(in)+2)
	for k, v := range in {
		out[k] = v
	}
	return out
}

// lockLocation is one "path:line" of a dependency.
type lockLocation struct {
	path string
	line int
}

// lockLocations splits a dependency's lock-file locations.
func lockLocations(files []string) []lockLocation {
	var out []lockLocation
	seen := map[string]bool{}
	for _, f := range files {
		if seen[f] {
			continue
		}
		seen[f] = true
		loc := lockLocation{path: f}
		if i := strings.LastIndexByte(f, ':'); i > 0 {
			if n, err := strconv.Atoi(f[i+1:]); err == nil {
				loc.path, loc.line = f[:i], n
			}
		}
		out = append(out, loc)
	}
	return out
}

// --- queries ------------------------------------------------------------------

// ScanReportView is a stored report with what the API adds: whether its commit
// is still the default branch's head.
type ScanReportView struct {
	ScanReport
	// Current reports, for a head scan, that the commit is still the head.
	Current bool `json:"current,omitempty"`
}

// ScanOverview is a repository's scans at a glance.
type ScanOverview struct {
	Enabled bool          `json:"enabled"`
	Gate    ScannerStatus `json:"gate"`
	Head    HeadState     `json:"head"`
	// Latest is the newest head scan's header; Releases the releases' scan
	// headers, newest first.
	Latest   *ScanReport  `json:"latest,omitempty"`
	Releases []ScanReport `json:"releases,omitempty"`
	Others   []ScanReport `json:"others,omitempty"`
	// Queued and Running list the commits waiting for or being scanned.
	Queued  []string `json:"queued,omitempty"`
	Running []string `json:"running,omitempty"`
}

// ScanReport returns a repository's report of a revision: rev empty returns
// the newest scan of the default branch's head; otherwise rev is a tag, a
// branch or a commit (prefix) and the report of the commit it names is
// returned. ErrNotFound when there is none.
func (s *Service) ScanReport(ctx context.Context, tenant, name, rev string) (*ScanReportView, error) {
	reg, ok := s.registration(tenant, name)
	if !ok {
		return nil, ErrNotFound
	}
	rev = strings.TrimSpace(rev)
	commit := ""
	switch {
	case rev == "" || rev == "HEAD":
		commit = s.headReportCommit(ctx, name)
		if commit == "" {
			return nil, ErrNotFound
		}
	default:
		if !revRE.MatchString(rev) || strings.Contains(rev, "..") {
			return nil, &ValidationError{Err: fmt.Errorf("%q is not a tag, branch or commit", rev)}
		}
		lower := strings.ToLower(rev)
		if commitPrefixRE.MatchString(lower) {
			// A commit prefix of a stored report.
			var match []string
			for _, h := range s.scanHeaders(name) {
				if strings.HasPrefix(h.Commit, lower) {
					match = append(match, h.Commit)
				}
			}
			if len(match) == 1 {
				commit = match[0]
			} else if len(match) > 1 {
				return nil, &ValidationError{Err: fmt.Errorf("commit prefix %q is ambiguous", rev)}
			}
		}
		if commit == "" {
			c, err := s.resolveRev(ctx, reg.Repo, rev)
			if err != nil {
				return nil, err
			}
			commit = c
		}
	}
	rep, err := s.readScanReport(ctx, name, commit)
	if err != nil {
		return nil, err
	}
	if tenant != "" && rep.Tenant != tenant {
		return nil, ErrNotFound
	}
	v := &ScanReportView{ScanReport: *rep}
	if rep.Kind == ScanHead || rep.Branch != "" {
		v.Current = s.headState(ctx, name).Commit == rep.Commit
	}
	return v, nil
}

// headReportCommit returns the commit of a repository's newest scan of its
// default branch's head: the head scanned last, or else the newest head scan.
func (s *Service) headReportCommit(ctx context.Context, name string) string {
	if hs := s.headState(ctx, name); validCommit(hs.ScannedCommit) {
		s.mu.RLock()
		_, ok := s.scanHeads[scanObject(name, hs.ScannedCommit)]
		s.mu.RUnlock()
		if ok {
			return hs.ScannedCommit
		}
	}
	for _, h := range s.scanHeaders(name) {
		if h.Kind == ScanHead || h.Branch != "" {
			return h.Commit
		}
	}
	return ""
}

// ScanReportOf returns the stored report of a commit, exactly.
func (s *Service) ScanReportOf(ctx context.Context, tenant, name, commit string) (*ScanReport, error) {
	if _, ok := s.registration(tenant, name); !ok {
		return nil, ErrNotFound
	}
	commit = strings.ToLower(strings.TrimSpace(commit))
	if !validCommit(commit) {
		return nil, &ValidationError{Err: errors.New("a full commit ID is needed")}
	}
	rep, err := s.readScanReport(ctx, name, commit)
	if err != nil {
		return nil, err
	}
	if tenant != "" && rep.Tenant != tenant {
		return nil, ErrNotFound
	}
	return rep, nil
}

// ScanOverview returns a repository's scans at a glance.
func (s *Service) ScanOverview(ctx context.Context, tenant, name string) (*ScanOverview, error) {
	if _, ok := s.registration(tenant, name); !ok {
		return nil, ErrNotFound
	}
	gate, enabled := s.ScanStatus()
	ov := &ScanOverview{Enabled: enabled, Gate: gate, Head: s.headState(ctx, name)}
	ov.Head.Notified = nil
	headCommit := s.headReportCommit(ctx, name)
	for _, h := range s.scanHeaders(name) {
		if tenant != "" && h.Tenant != tenant {
			continue
		}
		h := h
		if h.Commit == headCommit && ov.Latest == nil {
			ov.Latest = &h
		}
		switch h.Kind {
		case ScanHead:
		case ScanRelease:
			ov.Releases = append(ov.Releases, h)
		default:
			ov.Others = append(ov.Others, h)
		}
	}
	s.scanQMu.Lock()
	for k := range s.scanQueued {
		if r, c, ok := strings.Cut(k, "/"); ok && r == name {
			ov.Queued = append(ov.Queued, c)
		}
	}
	for k := range s.scanRunning {
		if r, c, ok := strings.Cut(k, "/"); ok && r == name {
			ov.Running = append(ov.Running, c)
		}
	}
	s.scanQMu.Unlock()
	sort.Strings(ov.Queued)
	sort.Strings(ov.Running)
	return ov, nil
}

// DependencyScanRef is one scanned revision whose lock files pin a coordinate,
// and what the scan read in it (the dossier's view).
type DependencyScanRef struct {
	Repo   string   `json:"repo"`
	Commit string   `json:"commit"`
	Kind   string   `json:"kind"`
	Ref    string   `json:"ref,omitempty"`
	Tags   []string `json:"tags,omitempty"`
	// Current reports, for a head scan, that the commit is still the head.
	Current bool `json:"current,omitempty"`
	// The dependency's result in that scan.
	Version   string         `json:"version"`
	Verdict   string         `json:"verdict"`
	Reason    string         `json:"reason,omitempty"`
	Unscanned *UnscannedInfo `json:"unscanned,omitempty"`
	Detail    *VerdictDetail `json:"detail,omitempty"`
	Files     []string       `json:"files"`
	Pinned    bool           `json:"pinned,omitempty"`
	Released  string         `json:"released,omitempty"`
	ScanAt    time.Time      `json:"scanAt"`
}

// maxDossierReports bounds the reports one coordinate lookup reads.
const maxDossierReports = 64

// ScansOf returns the scans whose lock files pin a coordinate (every version
// when version is empty), visible to tenant: the releases that pin it, and the
// newest head scan of each repository.
func (s *Service) ScansOf(ctx context.Context, tenant, ecosystem, name, version string) ([]DependencyScanRef, error) {
	ecosystem = lockfiles.CanonicalType(ecosystem)
	if ecosystem == "" || strings.TrimSpace(name) == "" {
		return nil, &ValidationError{Err: errors.New("an ecosystem and a name are needed")}
	}
	type target struct{ repo, commit string }
	var targets []target
	seen := map[string]bool{}
	add := func(repo, commit string) {
		k := repo + "/" + commit
		if !seen[k] && len(targets) < maxDossierReports {
			seen[k] = true
			targets = append(targets, target{repo, commit})
		}
	}
	for _, id := range s.idx.lookup(tenant, ecosystem, name, version, "") {
		repo, commit := splitManifestID(id)
		add(repo, commit)
	}
	for _, r := range s.tracked() {
		if tenant != "" && r.Tenant != tenant {
			continue
		}
		if c := s.headReportCommit(ctx, r.Name); c != "" {
			add(r.Name, c)
		}
	}
	var out []DependencyScanRef
	for _, t := range targets {
		if ctx.Err() != nil {
			return out, ctx.Err()
		}
		rep, err := s.readScanReport(ctx, t.repo, t.commit)
		if err != nil || (tenant != "" && rep.Tenant != tenant) {
			continue
		}
		if _, ok := s.registration(tenant, rep.Repo); !ok {
			continue
		}
		current := (rep.Kind == ScanHead || rep.Branch != "") && s.headState(ctx, rep.Repo).Commit == rep.Commit
		for _, d := range rep.Dependencies {
			if lockfiles.CanonicalType(d.Type) != ecosystem || !strings.EqualFold(d.Name, name) || (version != "" && d.Version != version) {
				continue
			}
			out = append(out, DependencyScanRef{
				Repo: rep.Repo, Commit: rep.Commit, Kind: rep.Kind, Ref: rep.Ref, Tags: rep.Tags, Current: current,
				Version: d.Version, Verdict: d.Verdict, Reason: d.Reason, Unscanned: d.Unscanned, Detail: d.Detail,
				Files: d.Files, Pinned: d.Pinned, Released: d.Released, ScanAt: rep.FinishedAt,
			})
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		if r1, r2 := verdictRank(out[i].Verdict), verdictRank(out[j].Verdict); r1 != r2 {
			return r1 > r2
		}
		return out[i].ScanAt.After(out[j].ScanAt)
	})
	return out, nil
}

// ScanFact is one dependency of a current scan that the scan flagged or could
// not examine, as the query API joins it: from the newest scan of each
// repository's default-branch head, and from every release scan.
type ScanFact struct {
	Tenant    string    `json:"tenant,omitempty"`
	Ecosystem string    `json:"ecosystem"`
	Name      string    `json:"name"`
	Version   string    `json:"version"`
	Digest    string    `json:"digest,omitempty"`
	Repo      string    `json:"repo"`
	Commit    string    `json:"commit"`
	Kind      string    `json:"kind"`
	Verdict   string    `json:"verdict"`
	Model     string    `json:"model,omitempty"`
	ScannedAt time.Time `json:"scannedAt"`
}

// ScanFacts lists the flagged and unscanned dependencies of the current scans
// visible to tenant ("" sees all). It reads no report: the facts are indexed
// when a report is stored or loaded.
func (s *Service) ScanFacts(ctx context.Context, tenant string) []ScanFact {
	heads := map[string]string{}
	for _, r := range s.tracked() {
		heads[r.Name] = s.headReportCommit(ctx, r.Name)
	}
	var out []ScanFact
	for _, h := range s.scanHeaders("") {
		if tenant != "" && h.Tenant != tenant {
			continue
		}
		if h.Kind != ScanRelease && heads[h.Repo] != h.Commit {
			continue // an older head, or a revision scanned on request
		}
		s.mu.RLock()
		out = append(out, s.scanFacts[scanObject(h.Repo, h.Commit)]...)
		s.mu.RUnlock()
	}
	return out
}

// ScanDocuments returns the findings documents of a repository's current
// scans: the newest head scan and every release scan.
func (s *Service) ScanDocuments(ctx context.Context, tenant, name string) ([]findings.Document, error) {
	if _, ok := s.registration(tenant, name); !ok {
		return nil, ErrNotFound
	}
	var docs []findings.Document
	headCommit := s.headReportCommit(ctx, name)
	for _, h := range s.scanHeaders(name) {
		if tenant != "" && h.Tenant != tenant {
			continue
		}
		if h.Kind != ScanRelease && h.Commit != headCommit {
			continue
		}
		rep, err := s.readScanReport(ctx, h.Repo, h.Commit)
		if err != nil {
			continue
		}
		docs = append(docs, rep.FindingsDocument())
	}
	return docs, nil
}
