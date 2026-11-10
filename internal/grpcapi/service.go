package grpcapi

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	connect "connectrpc.com/connect"
	"google.golang.org/protobuf/types/known/structpb"

	"github.com/blechschmidt/pullthrough-security/internal/dossier"
	"github.com/blechschmidt/pullthrough-security/internal/findings"
	securityv1 "github.com/blechschmidt/pullthrough-security/internal/grpcapi/gen/securityv1"
	"github.com/blechschmidt/pullthrough-security/internal/queryapi"
)

// rpc method names used as metric labels (the trailing segment of the Connect
// procedure path).
const (
	rpcGetDossier             = "GetDossier"
	rpcGetRiskVerdict         = "GetRiskVerdict"
	rpcGetFindings            = "GetFindings"
	rpcGetProvenance          = "GetProvenance"
	rpcGetComplianceScorecard = "GetComplianceScorecard"
	rpcQueryCorpus            = "QueryCorpus"
	rpcStreamQueryCorpus      = "StreamQueryCorpus"
)

// rfc3339 renders a timestamp in UTC RFC3339, or "" for the zero time.
func rfc3339(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}

// mapQueryError maps a federated-query validation failure to the appropriate
// Connect code (invalid argument), and anything else to internal.
func mapQueryError(err error) error {
	var qe *queryapi.QueryError
	if asQueryError(err, &qe) {
		return connect.NewError(connect.CodeInvalidArgument, fmt.Errorf("query rejected (%s): %s", qe.Code, qe.Msg))
	}
	return connect.NewError(connect.CodeInternal, err)
}

// asQueryError is a tiny errors.As helper kept local to avoid importing errors
// solely for one call; queryapi.QueryError is returned concretely by the engine.
func asQueryError(err error, target **queryapi.QueryError) bool {
	if qe, ok := err.(*queryapi.QueryError); ok {
		*target = qe
		return true
	}
	return false
}

// GetRiskVerdict returns the explainable supply-chain risk verdict for a
// coordinate, projected over the federated query engine and enriched with the
// risk provider's contribution breakdown when wired.
func (s *Server) GetRiskVerdict(ctx context.Context, req *connect.Request[securityv1.CoordinateRequest]) (*connect.Response[securityv1.RiskVerdict], error) {
	m := req.Msg
	if strings.TrimSpace(m.GetName()) == "" {
		err := connect.NewError(connect.CodeInvalidArgument, fmt.Errorf("the 'name' field is required"))
		s.metrics.recordRPC(rpcGetRiskVerdict, true)
		return nil, err
	}
	tenant := tenantScope(ctx, m.GetTenant())
	c, err := s.resolve(tenant, m.GetEcosystem(), m.GetName(), m.GetVersion())
	if err != nil {
		s.metrics.recordRPC(rpcGetRiskVerdict, true)
		return nil, mapQueryError(err)
	}

	verdict := "allow"
	switch {
	case rowBool(c.Row, "riskBlock"):
		verdict = "block"
	case rowBool(c.Row, "riskWarn"):
		verdict = "warn"
	}

	out := &securityv1.RiskVerdict{
		Coordinate:    c.Coordinate,
		Ecosystem:     c.Ecosystem,
		Name:          c.Name,
		Version:       c.Version,
		Tenant:        tenant,
		Found:         c.Found,
		HasAssessment: rowBool(c.Row, "hasRisk"),
		Score:         int32(rowInt(c.Row, "riskScore")),
		Band:          rowStr(c.Row, "riskBand"),
		Verdict:       verdict,
		Block:         rowBool(c.Row, "riskBlock"),
		Warn:          rowBool(c.Row, "riskWarn"),
	}
	if !c.Found {
		out.Summary = fmt.Sprintf("No risk assessment is on record for %s; the proxy has not yet evaluated it for this tenant.", c.pkgKey())
	} else {
		out.Summary = fmt.Sprintf("%s has risk band %q (score %d). Recommended admission action: %s.",
			c.Coordinate, out.Band, out.Score, verdict)
		out.Contributions = s.riskContributions(c)
	}
	s.metrics.recordRPC(rpcGetRiskVerdict, false)
	return connect.NewResponse(out), nil
}

// riskContributions returns the explainable contribution breakdown from the
// most recent matching risk assessment, when the risk provider is wired.
func (s *Server) riskContributions(c coord) []*securityv1.RiskContribution {
	if s.risk == nil {
		return nil
	}
	for _, a := range s.risk.Recent(s.maxDetail) {
		if !coordinateMatches(a.Artifact.Coordinate, a.Artifact.Name, a.Artifact.Version, c) {
			continue
		}
		out := make([]*securityv1.RiskContribution, 0, len(a.Contributions))
		for i, ct := range a.Contributions {
			if i >= s.maxDetail {
				break
			}
			out = append(out, &securityv1.RiskContribution{
				Signal: string(ct.Signal),
				Points: ct.Points,
				Detail: ct.Raw,
			})
		}
		return out
	}
	return nil
}

// GetFindings returns the aggregated admission-gate findings for a coordinate.
func (s *Server) GetFindings(ctx context.Context, req *connect.Request[securityv1.CoordinateRequest]) (*connect.Response[securityv1.FindingsResponse], error) {
	m := req.Msg
	if strings.TrimSpace(m.GetName()) == "" {
		s.metrics.recordRPC(rpcGetFindings, true)
		return nil, connect.NewError(connect.CodeInvalidArgument, fmt.Errorf("the 'name' field is required"))
	}
	tenant := tenantScope(ctx, m.GetTenant())
	c, err := s.resolve(tenant, m.GetEcosystem(), m.GetName(), m.GetVersion())
	if err != nil {
		s.metrics.recordRPC(rpcGetFindings, true)
		return nil, mapQueryError(err)
	}

	out := &securityv1.FindingsResponse{
		Coordinate: c.Coordinate,
		Tenant:     tenant,
		Found:      c.Found,
	}

	if s.findings != nil {
		if doc, ok := s.findings.Get(tenant, c.pkgKey()); ok {
			out.Found = true
			out.Total = int32(len(doc.Findings))
			out.Findings = s.summarizeFindings(doc)
			out.Blocking = int32(countBlocking(doc))
			out.WorstSeverity = worstSeverity(doc)
			out.Gates = gatesOf(doc)
			s.metrics.recordRPC(rpcGetFindings, false)
			return connect.NewResponse(out), nil
		}
	}

	// Fall back to the query summary (counts only) when no detail provider is
	// wired or the artifact has no recorded findings document.
	out.Total = int32(rowInt(c.Row, "findings"))
	out.Blocking = int32(rowInt(c.Row, "blockingFindings"))
	out.Gates = rowList(c.Row, "findingGates")
	out.WorstSeverity = rowStr(c.Row, "worstSeverity")
	s.metrics.recordRPC(rpcGetFindings, false)
	return connect.NewResponse(out), nil
}

// summarizeFindings renders a bounded, compact view of a findings document.
func (s *Server) summarizeFindings(doc findings.Document) []*securityv1.Finding {
	out := make([]*securityv1.Finding, 0, len(doc.Findings))
	for i := range doc.Findings {
		if i >= s.maxDetail {
			break
		}
		f := doc.Findings[i]
		out = append(out, &securityv1.Finding{
			RuleId:     f.RuleID,
			Gate:       string(f.Gate),
			Severity:   string(f.Severity),
			Level:      string(f.Level),
			Identifier: f.Identifier,
			Title:      f.Title,
			Suppressed: f.Suppressed,
		})
	}
	return out
}

// GetProvenance returns the provenance-graph edges for a coordinate.
func (s *Server) GetProvenance(ctx context.Context, req *connect.Request[securityv1.CoordinateRequest]) (*connect.Response[securityv1.ProvenanceResponse], error) {
	m := req.Msg
	if strings.TrimSpace(m.GetName()) == "" {
		s.metrics.recordRPC(rpcGetProvenance, true)
		return nil, connect.NewError(connect.CodeInvalidArgument, fmt.Errorf("the 'name' field is required"))
	}
	tenant := tenantScope(ctx, m.GetTenant())
	c, err := s.resolve(tenant, m.GetEcosystem(), m.GetName(), m.GetVersion())
	if err != nil {
		s.metrics.recordRPC(rpcGetProvenance, true)
		return nil, mapQueryError(err)
	}

	out := &securityv1.ProvenanceResponse{
		Coordinate:       c.Coordinate,
		Tenant:           tenant,
		Found:            c.Found,
		DirectDependents: int32(rowInt(c.Row, "directDependents")),
		DownstreamPaths:  int32(rowInt(c.Row, "downstreamPaths")),
	}

	// Source-commit path and reverse-dependency blast radius require a version to
	// key the graph node; only query when we have one.
	if s.provgraph != nil && c.Ecosystem != "" && c.Version != "" {
		if path, perr := s.provgraph.PathToCommit(c.Ecosystem, c.Name, c.Version); perr == nil && path.Found {
			out.SourceCommit = &securityv1.SourceCommit{
				Found:     true,
				CommitId:  path.CommitID,
				CommitSha: path.CommitSHA,
				Nodes:     path.Nodes,
			}
		}
		if dep, derr := s.provgraph.ReverseDependencies(c.Ecosystem, c.Name, c.Version); derr == nil && dep.Found {
			rd := &securityv1.ReverseDependencies{
				Found:  true,
				Total:  int32(dep.Total),
				Direct: int32(dep.Direct),
			}
			for i := range dep.Dependents {
				if i >= s.maxDetail {
					break
				}
				d := dep.Dependents[i]
				rd.Dependents = append(rd.Dependents, &securityv1.Dependent{
					Ecosystem: d.Ecosystem,
					Name:      d.Name,
					Version:   d.Version,
					Direct:    d.Direct,
					Distance:  int32(d.Distance),
				})
			}
			out.ReverseDependencies = rd
		}
	}

	if s.attest != nil {
		if b, ok := s.attest.Get(tenant, c.pkgKey()); ok && b != nil {
			out.Attestation = &securityv1.Attestation{
				Present:       true,
				Digest:        b.Digest,
				PredicateType: b.PredicateType,
				SubjectDigest: b.SubjectDigest,
				KeyId:         b.KeyID,
				CreatedAt:     rfc3339(b.CreatedAt),
			}
		} else {
			out.Attestation = &securityv1.Attestation{Present: false}
		}
	}
	s.metrics.recordRPC(rpcGetProvenance, false)
	return connect.NewResponse(out), nil
}

// GetComplianceScorecard returns the continuous-compliance scorecard.
func (s *Server) GetComplianceScorecard(ctx context.Context, req *connect.Request[securityv1.ComplianceScorecardRequest]) (*connect.Response[securityv1.ComplianceScorecard], error) {
	if s.compliance == nil {
		s.metrics.recordRPC(rpcGetComplianceScorecard, false)
		return connect.NewResponse(&securityv1.ComplianceScorecard{Enabled: false}), nil
	}
	card := s.compliance.Latest()
	if req.Msg.GetRefresh() {
		card = s.compliance.Recompute()
	}
	out := &securityv1.ComplianceScorecard{
		Enabled:     true,
		GeneratedAt: rfc3339(card.GeneratedAt),
		Version:     card.Version,
		Score:       card.Score,
		Grade:       card.Grade,
		Status:      string(card.Status),
		Summary: &securityv1.StatusCounts{
			Pass: int32(card.Summary.Pass),
			Warn: int32(card.Summary.Warn),
			Fail: int32(card.Summary.Fail),
			Na:   int32(card.Summary.NA),
		},
		Slsa: &securityv1.SLSASummary{
			BuildLevel: int32(card.SLSA.BuildLevel),
			Track:      card.SLSA.Track,
			Rationale:  card.SLSA.Rationale,
			Estimated:  card.SLSA.Estimated,
		},
	}
	for _, ctl := range card.Controls {
		out.Controls = append(out.Controls, &securityv1.Control{
			Id:         ctl.ID,
			Title:      ctl.Title,
			Category:   ctl.Category,
			Frameworks: ctl.Frameworks,
			Status:     string(ctl.Status),
			Score:      ctl.Score,
			Weight:     ctl.Weight,
			Required:   ctl.Required,
			Detail:     ctl.Detail,
			Observed:   ctl.Observed,
			Threshold:  ctl.Threshold,
		})
	}
	s.metrics.recordRPC(rpcGetComplianceScorecard, false)
	return connect.NewResponse(out), nil
}

// buildQuery translates a QueryRequest into a federated-query engine Query,
// forcing the tenant scope so a caller cannot read another tenant's data.
func (s *Server) buildQuery(ctx context.Context, m *securityv1.QueryRequest) (queryapi.Query, error) {
	q := queryapi.Query{
		Select: m.GetSelect(),
		Limit:  int(m.GetLimit()),
		Offset: int(m.GetOffset()),
	}
	for _, o := range m.GetOrderBy() {
		q.OrderBy = append(q.OrderBy, queryapi.Order{Field: o.GetField(), Desc: o.GetDesc()})
	}
	if wj := strings.TrimSpace(m.GetWhereJson()); wj != "" {
		var f queryapi.Filter
		if err := json.Unmarshal([]byte(wj), &f); err != nil {
			return q, connect.NewError(connect.CodeInvalidArgument, fmt.Errorf("invalid where_json: %w", err))
		}
		q.Where = &f
	}
	// Hard-scope: the authenticated tenant always wins over any client-supplied
	// value. An empty tenant (a global admin / trusted-network call) queries
	// across tenants, matching the GraphQL/MCP semantics.
	q.Tenant = tenantScope(ctx, m.GetTenant())
	return q, nil
}

// QueryCorpus runs an ad-hoc federated query and returns the full page.
func (s *Server) QueryCorpus(ctx context.Context, req *connect.Request[securityv1.QueryRequest]) (*connect.Response[securityv1.QueryResponse], error) {
	q, err := s.buildQuery(ctx, req.Msg)
	if err != nil {
		s.metrics.recordRPC(rpcQueryCorpus, true)
		return nil, err
	}
	res, err := s.backend.Query(q)
	if err != nil {
		s.metrics.recordRPC(rpcQueryCorpus, true)
		return nil, mapQueryError(err)
	}

	out := &securityv1.QueryResponse{
		Fields:      res.Fields,
		Total:       int32(res.Total),
		Returned:    int32(res.Returned),
		Offset:      int32(res.Offset),
		Limit:       int32(res.Limit),
		Truncated:   res.Truncated,
		Scanned:     int32(res.Scanned),
		Cost:        int32(res.Cost),
		GeneratedAt: rfc3339(res.GeneratedAt),
	}
	for _, row := range res.Rows {
		st, cerr := rowToStruct(row)
		if cerr != nil {
			s.metrics.recordRPC(rpcQueryCorpus, true)
			return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("encoding row: %w", cerr))
		}
		out.Rows = append(out.Rows, st)
	}
	s.metrics.recordRPC(rpcQueryCorpus, false)
	return connect.NewResponse(out), nil
}

// StreamQueryCorpus runs the same federated query but streams each matched row
// as its own message, then a terminal summary. It exercises the Connect
// server-streaming protocol over the shared read-access layer.
func (s *Server) StreamQueryCorpus(ctx context.Context, req *connect.Request[securityv1.QueryRequest], stream *connect.ServerStream[securityv1.QueryRowOrSummary]) error {
	q, err := s.buildQuery(ctx, req.Msg)
	if err != nil {
		s.metrics.recordRPC(rpcStreamQueryCorpus, true)
		return err
	}
	res, err := s.backend.Query(q)
	if err != nil {
		s.metrics.recordRPC(rpcStreamQueryCorpus, true)
		return mapQueryError(err)
	}

	sent := 0
	for _, row := range res.Rows {
		// Honor client cancellation promptly on long streams.
		if ctx.Err() != nil {
			s.metrics.recordRPC(rpcStreamQueryCorpus, true)
			s.metrics.recordStream(sent)
			return connect.NewError(connect.CodeCanceled, ctx.Err())
		}
		st, cerr := rowToStruct(row)
		if cerr != nil {
			s.metrics.recordRPC(rpcStreamQueryCorpus, true)
			s.metrics.recordStream(sent)
			return connect.NewError(connect.CodeInternal, fmt.Errorf("encoding row: %w", cerr))
		}
		msg := &securityv1.QueryRowOrSummary{
			Kind: &securityv1.QueryRowOrSummary_Row{Row: st},
		}
		if serr := stream.Send(msg); serr != nil {
			s.metrics.recordRPC(rpcStreamQueryCorpus, true)
			s.metrics.recordStream(sent)
			return serr
		}
		sent++
	}

	summary := &securityv1.QueryRowOrSummary{
		Kind: &securityv1.QueryRowOrSummary_Summary{
			Summary: &securityv1.QuerySummary{
				Fields:      res.Fields,
				Total:       int32(res.Total),
				Returned:    int32(res.Returned),
				Offset:      int32(res.Offset),
				Limit:       int32(res.Limit),
				Truncated:   res.Truncated,
				Scanned:     int32(res.Scanned),
				Cost:        int32(res.Cost),
				GeneratedAt: rfc3339(res.GeneratedAt),
			},
		},
	}
	if serr := stream.Send(summary); serr != nil {
		s.metrics.recordRPC(rpcStreamQueryCorpus, true)
		s.metrics.recordStream(sent)
		return serr
	}
	sent++
	s.metrics.recordRPC(rpcStreamQueryCorpus, false)
	s.metrics.recordStream(sent)
	return nil
}

// rowToStruct converts a projected query row (whose values are the int/float/
// bool/string/[]string/[]any boxings the projector emits) into a protobuf
// Struct. It normalizes through JSON so every value lands on a structpb-
// compatible type (e.g. []string becomes a list of strings) regardless of the
// Go type the projector chose.
func rowToStruct(row map[string]any) (*structpb.Struct, error) {
	if row == nil {
		return &structpb.Struct{}, nil
	}
	b, err := json.Marshal(row)
	if err != nil {
		return nil, err
	}
	var normalized map[string]any
	if err := json.Unmarshal(b, &normalized); err != nil {
		return nil, err
	}
	return structpb.NewStruct(normalized)
}

// GetDossier returns the unified per-coordinate "360 view". It reuses the
// dossier builder (Task 87) when wired — the identical assembly the admin
// /api/dossier endpoint uses — and otherwise synthesizes a minimal card from the
// federated query model so the RPC still answers.
func (s *Server) GetDossier(ctx context.Context, req *connect.Request[securityv1.GetDossierRequest]) (*connect.Response[securityv1.Dossier], error) {
	m := req.Msg
	coordStr := strings.TrimSpace(m.GetCoordinate())
	if coordStr == "" {
		coordStr = strings.TrimSpace(m.GetName())
	}
	if coordStr == "" {
		s.metrics.recordRPC(rpcGetDossier, true)
		return nil, connect.NewError(connect.CodeInvalidArgument, fmt.Errorf("a coordinate or name is required"))
	}
	tenant := tenantScope(ctx, m.GetTenant())

	if s.dossier != nil {
		d := s.dossier.Build(ctx, dossier.Query{
			Tenant:     tenant,
			Ecosystem:  strings.TrimSpace(m.GetEcosystem()),
			Coordinate: coordStr,
			Version:    strings.TrimSpace(m.GetVersion()),
		})
		out := s.mapDossier(d)
		s.metrics.recordRPC(rpcGetDossier, false)
		return connect.NewResponse(out), nil
	}

	// No dossier builder wired: fall back to a minimal card from the query model.
	name := strings.TrimSpace(m.GetName())
	if name == "" {
		name = coordinateName(coordStr)
	}
	c, err := s.resolve(tenant, m.GetEcosystem(), name, m.GetVersion())
	if err != nil {
		s.metrics.recordRPC(rpcGetDossier, true)
		return nil, mapQueryError(err)
	}
	out := &securityv1.Dossier{
		Tenant:      tenant,
		Ecosystem:   c.Ecosystem,
		Name:        c.Name,
		Version:     c.Version,
		Coordinate:  c.Coordinate,
		Digest:      c.Digest,
		GeneratedAt: rfc3339(time.Now()),
		Found:       c.Found,
		Headline: &securityv1.Headline{
			Verdict:   "unknown",
			RiskScore: int32(rowInt(c.Row, "riskScore")),
			RiskBand:  rowStr(c.Row, "riskBand"),
			Summary:   "dossier builder not enabled; minimal projection from the query model",
		},
	}
	s.metrics.recordRPC(rpcGetDossier, false)
	return connect.NewResponse(out), nil
}

// coordinateName strips a trailing @version from a coordinate string.
func coordinateName(coordinate string) string {
	if i := strings.LastIndexByte(coordinate, '@'); i > 0 {
		return coordinate[:i]
	}
	return coordinate
}
