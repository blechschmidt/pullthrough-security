package grpcapi

import (
	"github.com/blechschmidt/pullthrough-security/internal/dossier"
	securityv1 "github.com/blechschmidt/pullthrough-security/internal/grpcapi/gen/securityv1"
)

// mapDossier projects a dossier.Dossier (the admin "360 view" assembly, Task 87)
// onto the proto Dossier. Each section is nil in the source when its subsystem
// was disabled or had nothing for the coordinate; the mapping preserves that by
// leaving the corresponding proto field unset.
func (s *Server) mapDossier(d *dossier.Dossier) *securityv1.Dossier {
	if d == nil {
		return &securityv1.Dossier{}
	}
	out := &securityv1.Dossier{
		Tenant:      d.Tenant,
		Ecosystem:   d.Ecosystem,
		Name:        d.Name,
		Version:     d.Version,
		Coordinate:  d.Coordinate,
		Digest:      d.Digest,
		GeneratedAt: rfc3339(d.GeneratedAt),
		Partial:     d.Partial,
		Found:       !d.Partial && (d.Risk != nil || d.Findings != nil || d.Vulns != nil || d.Provenance != nil),
		Headline: &securityv1.Headline{
			Verdict:   d.Headline.Verdict,
			Blocking:  d.Headline.Blocking,
			RiskScore: int32(d.Headline.RiskScore),
			RiskBand:  d.Headline.RiskBand,
			Reasons:   d.Headline.Reasons,
			Summary:   d.Headline.Summary,
		},
	}

	for _, src := range d.Sources {
		out.Sources = append(out.Sources, &securityv1.SourceStatus{
			Source: src.Source,
			Status: src.Status,
			Detail: src.Detail,
		})
	}

	if r := d.Risk; r != nil {
		rv := &securityv1.RiskVerdict{
			Coordinate:    d.Coordinate,
			Ecosystem:     d.Ecosystem,
			Name:          d.Name,
			Version:       d.Version,
			Tenant:        d.Tenant,
			Found:         true,
			HasAssessment: true,
			Score:         int32(r.Score),
			Band:          r.Band,
			Block:         r.Block,
			Warn:          r.Warn,
			Summary:       r.Summary,
		}
		switch {
		case r.Block:
			rv.Verdict = "block"
		case r.Warn:
			rv.Verdict = "warn"
		default:
			rv.Verdict = "allow"
		}
		for i, drv := range r.Contributions {
			if i >= s.maxDetail {
				break
			}
			rv.Contributions = append(rv.Contributions, &securityv1.RiskContribution{
				Signal: drv.Signal,
				Points: drv.Contribution,
				Detail: drv.Detail,
			})
		}
		out.Risk = rv
	}

	if f := d.Findings; f != nil {
		fr := &securityv1.FindingsResponse{
			Coordinate:    d.Coordinate,
			Tenant:        d.Tenant,
			Found:         true,
			Total:         int32(f.Total),
			Blocking:      int32(f.Blocking),
			WorstSeverity: f.Worst,
		}
		for g := range f.ByGate {
			fr.Gates = append(fr.Gates, g)
		}
		for i, it := range f.Items {
			if i >= s.maxDetail {
				break
			}
			fr.Findings = append(fr.Findings, &securityv1.Finding{
				RuleId:     it.RuleID,
				Gate:       it.Gate,
				Severity:   it.Severity,
				Identifier: it.Identifier,
				Title:      it.Title,
				Suppressed: it.Suppressed,
			})
		}
		out.Findings = fr
	}

	if v := d.Vulns; v != nil {
		vs := &securityv1.VulnerabilitySummary{
			HasReport:     true,
			Total:         int32(v.Total),
			Critical:      int32(v.Critical),
			High:          int32(v.High),
			Medium:        int32(v.Medium),
			Low:           int32(v.Low),
			MaxCvss:       v.MaxCVSS,
			MaxSeverity:   v.MaxSeverity,
			Cves:          v.CVEs,
			Quarantined:   v.Quarantined,
			VexSuppressed: int32(v.VEXSuppress),
		}
		out.Vulnerabilities = vs
	}

	if p := d.Provenance; p != nil {
		pr := &securityv1.ProvenanceResponse{
			Coordinate:       d.Coordinate,
			Tenant:           d.Tenant,
			Found:            true,
			DirectDependents: int32(p.DirectDependents),
			DownstreamPaths:  int32(p.DownstreamPaths),
		}
		if p.SourceCommit != "" {
			pr.SourceCommit = &securityv1.SourceCommit{
				Found:    true,
				CommitId: p.SourceCommit,
			}
		}
		out.Provenance = pr
	}

	// Fold the outbound attestation (a separate dossier section) into the
	// provenance response so the proto keeps a single provenance block.
	if a := d.Attest; a != nil {
		if out.Provenance == nil {
			out.Provenance = &securityv1.ProvenanceResponse{
				Coordinate: d.Coordinate,
				Tenant:     d.Tenant,
			}
		}
		out.Provenance.Attestation = &securityv1.Attestation{
			Present:       a.Present,
			Digest:        a.BundleDigest,
			PredicateType: a.PredicateType,
			SubjectDigest: a.SubjectDigest,
			KeyId:         a.KeyID,
			CreatedAt:     rfc3339(a.CreatedAt),
		}
	}

	return out
}
