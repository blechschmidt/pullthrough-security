package dossier

import (
	"context"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/blechschmidt/pullthrough-security/internal/approvals"
	"github.com/blechschmidt/pullthrough-security/internal/findings"
	"github.com/blechschmidt/pullthrough-security/internal/llmpkgscan"
	"github.com/blechschmidt/pullthrough-security/internal/rebuildverify"
	"github.com/blechschmidt/pullthrough-security/internal/remediation"
	"github.com/blechschmidt/pullthrough-security/internal/timeline"
)

// maxFindingItems bounds the findings list embedded on the card.
const maxFindingItems = 25

// setIdentity backfills the dossier's content identity from a richer source. It
// locks mu, so callers must not already hold it.
func setIdentity(mu *sync.Mutex, d *Dossier, digest, backend, name, version string) {
	mu.Lock()
	defer mu.Unlock()
	if d.Digest == "" && digest != "" {
		d.Digest = digest
	}
	if d.Backend == "" && backend != "" {
		d.Backend = backend
	}
	if d.Name == "" && name != "" {
		d.Name = strings.TrimSpace(name)
	}
	if d.Version == "" && version != "" {
		d.Version = strings.TrimSpace(version)
	}
}

// fillFindings aggregates the unified admission findings (the spine) and derives
// the license disposition from the license-gate findings.
func (b *Builder) fillFindings(id ident, tenant string, mu *sync.Mutex, d *Dossier) (string, string) {
	docs := b.providers.Findings.Documents(strings.TrimSpace(tenant), "")
	sec := &FindingsSection{ByGate: map[string]int{}}
	lic := &LicenseSection{}
	var items []FindingItem
	var matched bool
	var licenses []string

	for di := range docs {
		doc := &docs[di]
		a := doc.Artifact
		if !id.matches(a.Ecosystem, a.Name, a.Version, a.Coordinate) {
			continue
		}
		matched = true
		setIdentity(mu, d, a.Digest, a.Backend, a.Name, a.Version)
		for fi := range doc.Findings {
			f := &doc.Findings[fi]
			if f.Gate == findings.GateLicense {
				accumulateLicense(lic, &licenses, f)
			}
			if f.Suppressed {
				items = appendFinding(items, f)
				continue
			}
			sec.Total++
			sec.ByGate[string(f.Gate)]++
			if f.Level == findings.LevelError {
				sec.Blocking++
			}
			sec.Worst = worseSeverity(sec.Worst, string(f.Severity))
			items = appendFinding(items, f)
		}
	}

	if !matched {
		return StatusEmpty, ""
	}

	sortFindingItems(items)
	if len(items) > maxFindingItems {
		items = items[:maxFindingItems]
	}
	sec.Items = items

	mu.Lock()
	d.Findings = sec
	if len(licenses) > 0 || lic.Disposition != "" {
		lic.Licenses = dedupeSorted(licenses)
		if lic.Disposition == "" {
			lic.Disposition = "allowed"
		}
		d.License = lic
	}
	mu.Unlock()
	return StatusOK, ""
}

// accumulateLicense folds a license-gate finding into the license section. The
// finding level encodes the policy disposition (error => denied, warning =>
// review); the identifier is the offending SPDX expression.
func accumulateLicense(lic *LicenseSection, licenses *[]string, f *findings.Finding) {
	switch f.Level {
	case findings.LevelError:
		lic.Disposition = "denied"
	case findings.LevelWarning:
		if lic.Disposition != "denied" {
			lic.Disposition = "review"
		}
	}
	if f.Identifier != "" {
		*licenses = append(*licenses, f.Identifier)
	}
	if f.Title != "" {
		lic.Notes = appendUnique(lic.Notes, f.Title)
	}
}

func appendFinding(items []FindingItem, f *findings.Finding) []FindingItem {
	return append(items, FindingItem{
		RuleID:     f.RuleID,
		Gate:       string(f.Gate),
		Severity:   string(f.Severity),
		Title:      f.Title,
		Identifier: f.Identifier,
		Suppressed: f.Suppressed,
	})
}

func sortFindingItems(items []FindingItem) {
	sort.SliceStable(items, func(i, j int) bool {
		ri, rj := severityRank[strings.ToLower(items[i].Severity)], severityRank[strings.ToLower(items[j].Severity)]
		if ri != rj {
			return ri > rj
		}
		if items[i].Suppressed != items[j].Suppressed {
			return !items[i].Suppressed // active before suppressed
		}
		return items[i].Gate < items[j].Gate
	})
}

// fillRisk projects the highest-scoring recent risk assessment for the coordinate.
func (b *Builder) fillRisk(id ident, tenant string, mu *sync.Mutex, d *Dossier) (string, string) {
	var best *RiskSection
	for _, a := range b.providers.Risk.Recent(0) {
		if tenant != "" && a.Tenant != "" && !strings.EqualFold(a.Tenant, tenant) {
			continue
		}
		ar := a.Artifact
		if !id.matches(ar.Ecosystem, ar.Name, ar.Version, ar.Coordinate) {
			continue
		}
		if best != nil && a.Score <= best.Score {
			continue
		}
		sec := &RiskSection{
			Score:    a.Score,
			Band:     string(a.Band),
			Block:    a.Block,
			Warn:     a.Warn,
			Summary:  a.Summary,
			ScoredAt: a.ScoredAt,
		}
		for _, c := range a.Contributions {
			sec.Contributions = append(sec.Contributions, RiskDriver{
				Signal:       string(c.Signal),
				Contribution: c.Points,
				Detail:       c.Raw,
			})
		}
		best = sec
	}
	if best == nil {
		return StatusEmpty, ""
	}
	mu.Lock()
	d.Risk = best
	mu.Unlock()
	return StatusOK, ""
}

// fillVuln matches a cached vulnerability report by digest (preferred) or
// coordinate and rolls up the headline figures and quarantine state.
func (b *Builder) fillVuln(id ident, mu *sync.Mutex, d *Dossier) (string, string) {
	sec := &VulnSection{}
	var matched bool
	var cves []string
	for _, rep := range b.providers.Vuln.Reports() {
		if rep == nil {
			continue
		}
		a := rep.Artifact
		if !id.matches(a.Ecosystem, a.Name, a.Version, "") {
			continue
		}
		matched = true
		setIdentity(mu, d, rep.Digest, "", a.Name, a.Version)
		sec.Critical += rep.Counts.Critical
		sec.High += rep.Counts.High
		sec.Medium += rep.Counts.Medium
		sec.Low += rep.Counts.Low
		sec.Total += rep.Counts.Total()
		sec.VEXSuppress += rep.VEXSuppressed
		if rep.MaxCVSS > sec.MaxCVSS {
			sec.MaxCVSS = rep.MaxCVSS
		}
		sec.MaxSeverity = worseSeverity(sec.MaxSeverity, string(rep.MaxSeverity))
		for vi := range rep.Vulnerabilities {
			v := &rep.Vulnerabilities[vi]
			if v.Withdrawn || v.Suppressed || v.ID == "" {
				continue
			}
			cves = append(cves, v.ID)
		}
		if rep.Digest != "" && b.providers.Vuln.IsQuarantined(rep.Digest) {
			sec.Quarantined = true
		}
	}
	if !matched {
		return StatusEmpty, ""
	}
	sec.CVEs = dedupeSorted(cves)
	mu.Lock()
	d.Vulns = sec
	mu.Unlock()
	return StatusOK, ""
}

// fillSigverify owns the signature section. It reads the dedicated sigverify
// reports when wired, and always falls back to the unified findings so a
// sigverify-gate finding still marks the signature unverified.
func (b *Builder) fillSigverify(id ident, mu *sync.Mutex, d *Dossier) (string, string) {
	sec := &SignatureSection{Verified: true, Status: "verified"}
	var found bool

	if b.providers.Sigverify != nil {
		for _, rep := range b.providers.Sigverify.Reports() {
			if rep == nil {
				continue
			}
			a := rep.Artifact
			if !id.matches(a.Ecosystem, a.Name, a.Version, "") {
				continue
			}
			found = true
			setIdentity(mu, d, a.Digest, a.Backend, a.Name, a.Version)
			sec.VerifiedSignature = sec.VerifiedSignature || rep.VerifiedSignature
			sec.VerifiedAttestation = sec.VerifiedAttestation || rep.VerifiedAttestation
			if rep.Source != "" {
				sec.Source = rep.Source
			}
			if rep.VerifiedAt.After(sec.VerifiedAt) {
				sec.VerifiedAt = rep.VerifiedAt
			}
			if !rep.VerifiedSignature && !rep.VerifiedAttestation {
				sec.Verified = false
			}
		}
	}

	// The findings store is authoritative for the "unverified" verdict even when
	// the report cache has been pruned.
	if b.providers.Findings != nil {
		for _, doc := range b.providers.Findings.Documents("", "") {
			a := doc.Artifact
			if !id.matches(a.Ecosystem, a.Name, a.Version, a.Coordinate) {
				continue
			}
			for fi := range doc.Findings {
				if doc.Findings[fi].Gate == findings.GateSigverify {
					found = true
					sec.Verified = false
				}
			}
		}
	}

	if !found {
		return StatusEmpty, ""
	}
	if !sec.Verified {
		sec.Status = "unverified"
	}
	mu.Lock()
	d.Signature = sec
	mu.Unlock()
	return StatusOK, ""
}

// fillProvenance resolves the source commit/repository and the inbound
// build-provenance signals, plus the downstream blast radius from the graph.
func (b *Builder) fillProvenance(id ident, mu *sync.Mutex, d *Dossier) (string, string) {
	sec := &ProvenanceSection{}
	var found bool

	// Inbound build provenance (Task 72): the strongest signal for source identity.
	if bp := b.providers.BuildProv; bp != nil && bp.Enabled() {
		for _, rep := range bp.Reports() {
			if rep == nil {
				continue
			}
			a := rep.Artifact
			if !id.matches(a.Ecosystem, a.Name, a.Version, "") {
				continue
			}
			found = true
			sec.HasProvenance = sec.HasProvenance || rep.Present
			sec.ProvenanceVerified = sec.ProvenanceVerified || rep.Verified
			sec.SourceVerified = sec.SourceVerified || rep.SourceVerified
			sec.ProvenanceMismatch = sec.ProvenanceMismatch || rep.Mismatch
			if rep.CommitSHA != "" {
				sec.SourceCommit = rep.CommitSHA
			}
			if rep.RepositoryURL != "" {
				sec.RepositoryURL = rep.RepositoryURL
			}
			if rep.BuilderID != "" {
				sec.BuilderID = rep.BuilderID
			}
			if rep.WorkflowRef != "" {
				sec.WorkflowRef = rep.WorkflowRef
			}
		}
	}

	// Inbound PyPI PEP 740 attestations (Task 146): the publisher-authenticated
	// digest binding for a served wheel/sdist.
	if pa := b.providers.PyPIAttest; pa != nil && pa.Enabled() {
		for _, rep := range pa.Reports() {
			if rep == nil {
				continue
			}
			a := rep.Artifact
			if !id.matches(a.Ecosystem, a.Name, a.Version, "") {
				continue
			}
			found = true
			sec.HasProvenance = sec.HasProvenance || rep.Present
			sec.HasPyPIAttestation = sec.HasPyPIAttestation || rep.Present
			sec.PyPIAttestationVerified = sec.PyPIAttestationVerified || rep.Verified
			sec.PyPIPublisherTrusted = sec.PyPIPublisherTrusted || rep.PublisherTrusted
			sec.PyPIDigestMismatch = sec.PyPIDigestMismatch || rep.DigestMismatch
			if rep.Verified {
				sec.ProvenanceVerified = true
			}
			if rep.PublisherTrusted {
				sec.SourceVerified = true
			}
			if rep.Publisher.Identity != "" {
				sec.PyPIPublisher = rep.Publisher.Identity
				if sec.WorkflowRef == "" {
					sec.WorkflowRef = rep.Publisher.Identity
				}
			}
			if rep.RepositoryURL != "" && sec.RepositoryURL == "" {
				sec.RepositoryURL = rep.RepositoryURL
			}
		}
	}

	// Provenance graph (Task 33): source commit via the package->commit
	// association and the reverse-dependency blast radius.
	if pg := b.providers.Provgraph; pg != nil && id.name != "" {
		if path, err := pg.PathToCommit(id.eco, id.name, id.version); err == nil && path.Found {
			found = true
			if sec.SourceCommit == "" {
				sec.SourceCommit = firstNonEmpty(path.CommitSHA, path.CommitID)
				sec.CommitFromGraph = true
			}
		}
		if dep, err := pg.ReverseDependencies(id.eco, id.name, id.version); err == nil && dep.Found {
			found = true
			sec.DownstreamPaths = dep.Total
			sec.DirectDependents = dep.Direct
		}
	}

	// Findings fallback: the unified store carries the claimed source commit/repo.
	if (sec.SourceCommit == "" || sec.RepositoryURL == "") && b.providers.Findings != nil {
		for _, doc := range b.providers.Findings.Documents("", "") {
			a := doc.Artifact
			if !id.matches(a.Ecosystem, a.Name, a.Version, a.Coordinate) {
				continue
			}
			if sec.SourceCommit == "" && a.CommitSHA != "" {
				sec.SourceCommit = a.CommitSHA
				found = true
			}
			if sec.RepositoryURL == "" && a.RepositoryURL != "" {
				sec.RepositoryURL = a.RepositoryURL
				found = true
			}
		}
	}

	if !found {
		return StatusEmpty, ""
	}
	mu.Lock()
	d.Provenance = sec
	mu.Unlock()
	return StatusOK, ""
}

// fillRebuild projects the most recent reproducible-build verdict for the coordinate.
func (b *Builder) fillRebuild(id ident, mu *sync.Mutex, d *Dossier) (string, string) {
	var best *rebuildverify.Result
	for _, r := range b.providers.Rebuild.Recent(0) {
		res := r
		if !id.matches(res.Ecosystem, res.Name, res.Version, res.Coordinate) {
			continue
		}
		if best == nil || res.ComputedAt.After(best.ComputedAt) {
			best = &res
		}
	}
	if best == nil {
		return StatusEmpty, ""
	}
	mu.Lock()
	d.Reproduce = &ReproSection{
		Verdict:       string(best.Verdict),
		Reproducible:  best.Reproducible,
		Mismatch:      best.Mismatch,
		Pending:       best.Pending,
		CommitSHA:     best.CommitSHA,
		RepositoryURL: best.RepositoryURL,
		Reason:        best.Reason,
		ComputedAt:    best.ComputedAt,
	}
	mu.Unlock()
	return StatusOK, ""
}

// fillSbomDrift projects the latest dependency-drift diff for the coordinate.
func (b *Builder) fillSbomDrift(id ident, tenant string, mu *sync.Mutex, d *Dossier) (string, string) {
	diff, ok := b.providers.SbomDrift.DiffLatest(strings.TrimSpace(tenant), id.eco, id.name)
	if !ok || diff == nil {
		return StatusEmpty, ""
	}
	mu.Lock()
	d.SbomDrift = &SbomDriftSection{
		FromVersion: diff.From.Version,
		ToVersion:   diff.To.Version,
		DriftScore:  diff.DriftScore,
		Significant: diff.Significant,
		AddedDeps:   len(diff.AddedDeps),
		RemovedDeps: len(diff.RemovedDeps),
		NewVulns:    len(diff.NewVulnerabilities),
	}
	mu.Unlock()
	return StatusOK, ""
}

// fillApprovals projects the break-glass / quarantine-review history for the coordinate.
func (b *Builder) fillApprovals(id ident, tenant string, now time.Time, mu *sync.Mutex, d *Dossier) (string, string) {
	sec := &ApprovalsSection{}
	var matched bool
	for _, req := range b.providers.Approvals.List("", 0) {
		if tenant != "" && req.Tenant != "" && !strings.EqualFold(req.Tenant, tenant) {
			continue
		}
		if !id.matches(req.Ecosystem, "", "", req.Coordinate) {
			continue
		}
		matched = true
		switch req.Status {
		case approvals.StatusApproved:
			if req.ExpiresAt.After(now) {
				sec.Active++
			}
		case approvals.StatusPending:
			sec.Pending++
		}
		sec.History = append(sec.History, ApprovalItem{
			Gate:      req.Gate,
			Status:    string(req.Status),
			Reason:    req.Reason,
			Requester: req.Requester,
			GrantedAt: req.GrantedAt,
			ExpiresAt: req.ExpiresAt,
		})
	}
	if !matched {
		return StatusEmpty, ""
	}
	mu.Lock()
	d.Approvals = sec
	mu.Unlock()
	return StatusOK, ""
}

// fillAttest projects the proxy's own outbound attestation bundle for the artifact.
func (b *Builder) fillAttest(id ident, tenant string, mu *sync.Mutex, d *Dossier) (string, string) {
	bundle, ok := b.providers.Attest.Get(strings.TrimSpace(tenant), id.coord)
	if !ok || bundle == nil {
		return StatusEmpty, ""
	}
	mu.Lock()
	d.Attest = &AttestSection{
		Present:       true,
		BundleDigest:  bundle.Digest,
		PredicateType: bundle.PredicateType,
		SubjectDigest: bundle.SubjectDigest,
		KeyID:         bundle.KeyID,
		CreatedAt:     bundle.CreatedAt,
	}
	if p := bundle.Rekor; p != nil {
		d.Attest.Rekor = &RekorSection{
			LogIndex:               p.LogIndex,
			LogID:                  p.LogID,
			UUID:                   p.UUID,
			URL:                    p.URL,
			IntegratedTime:         p.IntegratedTime,
			InclusionProofVerified: p.InclusionProofVerified,
			SETVerified:            p.SETVerified,
		}
	}
	if d.Digest == "" && bundle.SubjectDigest != "" {
		d.Digest = bundle.SubjectDigest
	}
	mu.Unlock()
	return StatusOK, ""
}

// fillTimeline embeds the correlated forensic event chain for the coordinate.
func (b *Builder) fillTimeline(ctx context.Context, id ident, tenant string, mu *sync.Mutex, d *Dossier) (string, string) {
	q := timeline.Query{Coordinate: id.coord, Tenant: strings.TrimSpace(tenant), Limit: b.tlLimit}
	res, err := b.providers.Timeline.Query(ctx, q)
	if err != nil {
		if _, ok := err.(*timeline.QueryError); ok {
			return StatusEmpty, err.Error()
		}
		return StatusError, err.Error()
	}
	if len(res.Events) == 0 {
		return StatusEmpty, ""
	}
	sec := &TimelineSection{Total: res.Total, Returned: res.Returned, Truncated: res.Truncated}
	for _, ev := range res.Events {
		te := TimelineEvent{
			Time:     ev.Time,
			Source:   string(ev.Source),
			Category: string(ev.Category),
			Decision: ev.Decision,
			Actor:    ev.Actor,
			Summary:  firstNonEmpty(ev.Summary, ev.Kind),
		}
		if ev.Proof != nil && ev.Proof.AuditSeq != 0 {
			te.AuditSeq = ev.Proof.AuditSeq
			sec.Provable = true
		}
		sec.Events = append(sec.Events, te)
	}
	mu.Lock()
	d.Timeline = sec
	mu.Unlock()
	return StatusOK, ""
}

// --- small helpers ----------------------------------------------------------

func firstNonEmpty(vs ...string) string {
	for _, v := range vs {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

func appendUnique(dst []string, v string) []string {
	v = strings.TrimSpace(v)
	if v == "" {
		return dst
	}
	for _, e := range dst {
		if e == v {
			return dst
		}
	}
	return append(dst, v)
}

func dedupeSorted(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	for _, v := range in {
		v = strings.TrimSpace(v)
		if v == "" {
			continue
		}
		if _, ok := seen[v]; ok {
			continue
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}
	sort.Strings(out)
	return out
}

// fillSuggestedFix runs the automated dependency-remediation advisor for the
// coordinate and projects its verdict onto the dossier's "suggested fix" panel
// (Task 121). It needs a concrete version and ecosystem to pivot on; without
// them there is nothing to remediate, so the source reports empty. Because the
// advisor makes live upstream and scan calls it is bounded, like every other
// leg, by the per-source timeout — a slow advisory degrades to an absent panel
// rather than stalling the whole dossier. An already-safe coordinate (no
// blocking finding) also reports empty: there is no fix to suggest.
func (b *Builder) fillSuggestedFix(ctx context.Context, id ident, tenant string, mu *sync.Mutex, d *Dossier) (string, string) {
	if !id.versioned || strings.TrimSpace(id.eco) == "" {
		return StatusEmpty, "a concrete ecosystem and version are required"
	}
	advice, err := b.providers.Remediation.Advise(ctx, remediation.Request{
		Tenant:    strings.TrimSpace(tenant),
		Ecosystem: id.eco,
		Name:      id.name,
		Version:   id.version,
	})
	if err != nil {
		return StatusError, err.Error()
	}
	if advice == nil || advice.Status == remediation.StatusAlreadySafe {
		return StatusEmpty, ""
	}
	sec := &SuggestedFixSection{
		Status:             string(advice.Status),
		FixDescription:     advice.Summary,
		VersionsConsidered: advice.VersionsConsidered,
	}
	if rec := advice.Recommendation; rec != nil {
		sec.RecommendedVersion = rec.Version
		sec.FixDescription = rec.FixDescription
		sec.Resolved = len(rec.ResolvedFindings)
		sec.Residual = len(rec.ResidualFindings)
		sec.Introduced = len(rec.IntroducedFindings)
		for _, f := range rec.ResolvedFindings {
			label := f.ID
			if label == "" {
				label = f.Title
			}
			sec.ResolvedFindings = append(sec.ResolvedFindings, string(f.Gate)+":"+label)
		}
	}
	mu.Lock()
	d.SuggestedFix = sec
	mu.Unlock()
	return StatusOK, ""
}

// maxSuppressionItems bounds the suppression entries surfaced on the card.
const maxSuppressionItems = 50

// fillSuppression populates the immutable suppression audit trail for the
// coordinate (Task 165): every finding a gate suppressed or downgraded, with
// who/what/why. It queries the suppression ledger by the dossier coordinate
// (exact "name@version" when versioned, else the bare name to match any
// version) and reports an absent section when nothing was suppressed.
func (b *Builder) fillSuppression(id ident, tenant string, mu *sync.Mutex, d *Dossier) (string, string) {
	key := id.name
	if id.versioned {
		key = id.coord
	}
	if strings.TrimSpace(key) == "" {
		return StatusEmpty, "no coordinate to query"
	}
	recs := b.providers.Suppressions.ByCoordinate(strings.TrimSpace(tenant), key)
	if len(recs) == 0 {
		return StatusEmpty, ""
	}
	sec := &SuppressionSection{Total: len(recs), ByMechanism: map[string]int{}}
	for i := range recs {
		r := &recs[i]
		sec.ByMechanism[string(r.Mechanism)]++
		if len(sec.Items) < maxSuppressionItems {
			sec.Items = append(sec.Items, SuppressionEntry{
				Mechanism:     string(r.Mechanism),
				Actor:         r.Actor,
				Category:      string(r.Category),
				RuleID:        r.RuleID,
				Identifier:    r.Identifier,
				Gate:          string(r.Gate),
				Justification: r.Justification,
				Time:          r.Time,
				LastSeen:      r.LastSeen,
				Count:         r.Count,
			})
		}
	}
	mu.Lock()
	d.Suppression = sec
	mu.Unlock()
	return StatusOK, ""
}

// maxLLMEvidence bounds the cited locations embedded on the card.
const maxLLMEvidence = 12

// fillLLMPackageScan projects the LLM package-content scan verdict (Task 173)
// for the coordinate. A coordinate can cover several artifacts (a wheel and an
// sdist, or every version when the query is unversioned); the card shows the
// one the gate reads worst — that is the one a responder has to act on — and
// counts the rest.
func (b *Builder) fillLLMPackageScan(id ident, tenant string, mu *sync.Mutex, d *Dossier) (string, string) {
	p := b.providers.LLMPackageScan
	verdicts := p.ForCoordinate(strings.TrimSpace(tenant), id.eco, id.name, id.version)
	if len(verdicts) == 0 {
		return StatusEmpty, ""
	}

	var (
		worst   *llmpkgscan.Verdict
		worstSt llmpkgscan.Standing
		flagged int
	)
	for _, v := range verdicts { // newest first: a tie keeps the most recent
		st := p.Standing(v)
		if st.Disposition == llmpkgscan.DispositionMalicious || st.Disposition == llmpkgscan.DispositionSuspicious {
			flagged++
		}
		if worst == nil || llmStandingRank(st) > llmStandingRank(worstSt) {
			worst, worstSt = v, st
		}
	}

	sec := &LLMPackageScanSection{
		Verdict:        worst.Verdict,
		Confidence:     worst.Confidence,
		Disposition:    string(worstSt.Disposition),
		Reason:         worstSt.Reason,
		Action:         string(worstSt.Action),
		Refused:        worstSt.Refused,
		Reasons:        append([]string(nil), worst.Reasons...),
		StructuralRisk: worst.StructuralRisk,
		Anomalies:      append([]string(nil), worst.Anomalies...),
		Truncated:      worst.Truncated,
		Coverage:       append([]string(nil), worst.Coverage...),
		Format:         worst.Format,
		ReadAs:         llmpkgscan.DescribeVariant(worst),
		Digest:         worst.Digest,
		Provider:       worst.Provider,
		Model:          worst.Model,
		PromptVersion:  worst.PromptVersion,
		Mode:           worst.Mode,
		FilesScanned:   worst.Files,
		ScannedAt:      worst.ScannedAt,
		Artifacts:      len(verdicts),
		Flagged:        flagged,
	}
	for _, ev := range worst.Evidence {
		if len(sec.Evidence) >= maxLLMEvidence {
			break
		}
		sec.Evidence = append(sec.Evidence, LLMEvidence{Path: ev.Path, Line: ev.Line, Excerpt: ev.Excerpt, Verified: ev.Verified})
	}
	seen := make(map[string]bool)
	for _, hit := range worst.Injection {
		if !hit.Strong {
			continue
		}
		sec.PromptInjection = true
		if !seen[hit.Rule] {
			seen[hit.Rule] = true
			sec.InjectionRules = append(sec.InjectionRules, hit.Rule)
		}
	}
	sort.Strings(sec.InjectionRules)

	mu.Lock()
	d.LLMPackageScan = sec
	mu.Unlock()
	return StatusOK, ""
}

// llmStandingRank orders gate readings worst-last for "worst of" selection.
func llmStandingRank(st llmpkgscan.Standing) int {
	rank := 0
	switch st.Disposition {
	case llmpkgscan.DispositionMalicious:
		rank = 4
	case llmpkgscan.DispositionSuspicious:
		rank = 2
	case llmpkgscan.DispositionBenign:
		rank = 1
	}
	if st.Refused {
		rank++
	}
	return rank
}

// fillReleases lists the releases that ship the coordinate (Task 180).
func (b *Builder) fillReleases(ctx context.Context, id ident, tenant string, mu *sync.Mutex, d *Dossier) (string, string) {
	if id.eco == "" {
		// A release pins a dependency of a given type; without the ecosystem
		// the name could be anyone's.
		return StatusEmpty, "the ecosystem is needed to find releases"
	}
	refs, err := b.providers.Releases.ReleasesShipping(ctx, strings.TrimSpace(tenant), id.eco, id.name, id.version)
	if err != nil {
		return StatusError, err.Error()
	}
	if len(refs) == 0 {
		return StatusEmpty, ""
	}
	sec := &ReleasesSection{Total: len(refs), Releases: refs}
	for _, r := range refs {
		if r.State == "current" {
			sec.Current++
		}
		if r.Status == "pinned" {
			sec.Pinned++
		}
	}
	mu.Lock()
	d.Releases = sec
	mu.Unlock()
	return StatusOK, ""
}
