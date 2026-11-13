package mcpserver

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/blechschmidt/pullthrough-security/internal/findings"
	"github.com/blechschmidt/pullthrough-security/internal/provgraph"
	"github.com/blechschmidt/pullthrough-security/internal/queryapi"
	"github.com/blechschmidt/pullthrough-security/internal/repos"
	"github.com/blechschmidt/pullthrough-security/internal/timeline"
)

// tool is one MCP tool: its name, human/agent-facing description, JSON Schema for
// arguments, and the handler that executes it scoped to a tenant.
type tool struct {
	Name        string
	Description string
	InputSchema map[string]any
	Handler     func(ctx context.Context, tenant string, args json.RawMessage) (any, error)
}

// toolDescriptor is the wire shape returned by tools/list.
type toolDescriptor struct {
	Name        string         `json:"name"`
	Description string         `json:"description"`
	InputSchema map[string]any `json:"inputSchema"`
}

func (s *Server) toolDescriptors() []toolDescriptor {
	out := make([]toolDescriptor, 0, len(s.tools))
	for _, t := range s.tools {
		out = append(out, toolDescriptor{Name: t.Name, Description: t.Description, InputSchema: t.InputSchema})
	}
	return out
}

// coordArgs is the shared argument shape for the per-coordinate tools.
type coordArgs struct {
	Ecosystem string `json:"ecosystem"`
	Name      string `json:"name"`
	Version   string `json:"version"`
}

// coordSchema builds the JSON Schema for the per-coordinate tools, with optional
// extra properties merged in.
func coordSchema(extra map[string]any) map[string]any {
	props := map[string]any{
		"ecosystem": map[string]any{
			"type":        "string",
			"description": "Package ecosystem (npm, pypi, go, cargo, maven, nuget, docker, ...). Optional; narrows the match.",
		},
		"name": map[string]any{
			"type":        "string",
			"description": "Package name. Required.",
		},
		"version": map[string]any{
			"type":        "string",
			"description": "Package version. Optional; the most-recently-seen version is used when omitted.",
		},
	}
	for k, v := range extra {
		props[k] = v
	}
	return map[string]any{
		"type":       "object",
		"properties": props,
		"required":   []string{"name"},
	}
}

func (s *Server) buildTools() []tool {
	return []tool{
		{
			Name: "get_risk_verdict",
			Description: "Return the proxy's authoritative, explainable supply-chain risk verdict for a " +
				"package coordinate: a 0-100 score, a band (low|medium|high|critical), the recommended " +
				"admission action (allow|warn|block), and the contributing signals. Use this to answer " +
				"'is this package safe to add?'.",
			InputSchema: coordSchema(nil),
			Handler:     s.toolRiskVerdict,
		},
		{
			Name: "get_findings",
			Description: "Return the aggregated admission-gate findings for a coordinate (vulnerabilities, " +
				"license issues, exposed secrets, unverified signatures, typosquatting, ...). Set format to " +
				"'sarif' for a SARIF 2.1.0 log suitable for CI/PR decoration; the default 'summary' returns a " +
				"compact finding list.",
			InputSchema: coordSchema(map[string]any{
				"format": map[string]any{
					"type":        "string",
					"enum":        []string{"summary", "sarif"},
					"description": "Output format: 'summary' (default) or 'sarif'.",
				},
			}),
			Handler: s.toolFindings,
		},
		{
			Name: "get_provenance",
			Description: "Return the supply-chain provenance for a coordinate: the path from the artifact to " +
				"its source commit, the reverse-dependency blast radius, and whether the proxy issued a signed " +
				"attestation bundle for the served artifact.",
			InputSchema: coordSchema(nil),
			Handler:     s.toolProvenance,
		},
		{
			Name: "get_timeline",
			Description: "Reconstruct the forensic incident timeline for a coordinate (or, with only an " +
				"incidentId, for an incident): the chronologically-ordered, de-duplicated chain of pulls, " +
				"verdicts, overrides, anomalies, and lockdowns correlated across subsystems.",
			InputSchema: coordSchema(map[string]any{
				"incidentId": map[string]any{
					"type":        "string",
					"description": "Restrict to a specific incident identifier. Optional.",
				},
				"limit": map[string]any{
					"type":        "integer",
					"description": "Maximum events to return (bounded by the server's detail cap).",
				},
			}),
			Handler: s.toolTimeline,
		},
		{
			Name: "get_vulnerabilities",
			Description: "Return the known vulnerabilities affecting a coordinate after VEX adjudication: " +
				"per-severity counts, the headline CVSS, and the per-CVE detail (advisory id, severity, fixed " +
				"versions, VEX suppression status).",
			InputSchema: coordSchema(nil),
			Handler:     s.toolVulnerabilities,
		},
		{
			Name: "get_repository_scan",
			Description: "Return the LLM malicious-behaviour scan of every dependency a tracked repository's lock " +
				"files pin, for one revision: a tag, a branch or a commit (default: the default branch's head). " +
				"Each dependency carries its verdict (malicious|suspicious|benign|unscanned — unscanned is never " +
				"benign, and says why), the model and when it judged, the artifact digest, and the lock-file " +
				"lines that pin it. The model's reasons and the excerpts it quoted are left out: they are text " +
				"from the untrusted package. Set format to 'sarif' for a SARIF 2.1.0 log located at the lock-file lines.",
			InputSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"repo": map[string]any{"type": "string", "description": "Registered repository name. Required."},
					"rev":  map[string]any{"type": "string", "description": "Tag, branch or commit. Optional; the default branch's head when omitted."},
					"verdicts": map[string]any{
						"type":        "string",
						"enum":        []string{"all", "flagged", "unscanned", "not-benign"},
						"description": "Which dependencies to list: all (default), flagged (malicious or suspicious), unscanned, or not-benign.",
					},
					"format": map[string]any{
						"type":        "string",
						"enum":        []string{"summary", "sarif"},
						"description": "Output format: 'summary' (default) or 'sarif'.",
					},
				},
				"required": []string{"repo"},
			},
			Handler: s.toolRepositoryScan,
		},
		{
			Name: "run_query",
			Description: "Run an ad-hoc read-only query over the proxy's federated security data model using " +
				"the same projection DSL as the admin query API (select/where/orderBy/limit/offset). The query " +
				"is always hard-scoped to your tenant. Call get_query_schema-style introspection via the admin " +
				"schema endpoint for the field registry.",
			InputSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"select":  map[string]any{"type": "array", "items": map[string]any{"type": "string"}, "description": "Fields to project. Omit for the default projection; use [\"*\"] for all fields."},
					"where":   map[string]any{"type": "object", "description": "Boolean predicate tree (and/or/not + field/op/value leaves)."},
					"orderBy": map[string]any{"type": "array", "items": map[string]any{"type": "object"}, "description": "Sort keys: [{\"field\":\"riskScore\",\"desc\":true}]."},
					"limit":   map[string]any{"type": "integer", "description": "Page size (clamped to the engine maximum)."},
					"offset":  map[string]any{"type": "integer", "description": "Pagination offset."},
				},
			},
			Handler: s.toolRunQuery,
		},
	}
}

// decodeArgs unmarshals tool arguments, tolerating absent arguments (treated as
// an empty object).
func decodeArgs(raw json.RawMessage, into any) error {
	if len(raw) == 0 || strings.TrimSpace(string(raw)) == "null" {
		return nil
	}
	if err := json.Unmarshal(raw, into); err != nil {
		return fmt.Errorf("invalid arguments: %w", err)
	}
	return nil
}

// toolRiskVerdict implements get_risk_verdict.
func (s *Server) toolRiskVerdict(ctx context.Context, tenant string, raw json.RawMessage) (any, error) {
	var a coordArgs
	if err := decodeArgs(raw, &a); err != nil {
		return nil, err
	}
	if strings.TrimSpace(a.Name) == "" {
		return nil, fmt.Errorf("the 'name' argument is required")
	}
	c, err := s.resolve(tenant, a.Ecosystem, a.Name, a.Version)
	if err != nil {
		return nil, err
	}

	out := map[string]any{
		"coordinate":        c.Coordinate,
		"ecosystem":         c.Ecosystem,
		"name":              c.Name,
		"version":           c.Version,
		"tenant":            tenant,
		"found":             c.Found,
		"hasAssessment":     rowBool(c.Row, "hasRisk"),
		"score":             rowInt(c.Row, "riskScore"),
		"band":              rowStr(c.Row, "riskBand"),
		"block":             rowBool(c.Row, "riskBlock"),
		"warn":              rowBool(c.Row, "riskWarn"),
		"blockAdjacent":     rowBool(c.Row, "blockAdjacent"),
		"signatureVerified": rowBool(c.Row, "signatureVerified"),
	}

	verdict := "allow"
	switch {
	case rowBool(c.Row, "riskBlock"):
		verdict = "block"
	case rowBool(c.Row, "riskWarn"):
		verdict = "warn"
	}
	out["verdict"] = verdict

	if !c.Found {
		out["summary"] = fmt.Sprintf("No risk assessment is on record for %s; the proxy has not yet evaluated it for this tenant.", c.pkgKey())
	} else {
		out["summary"] = fmt.Sprintf("%s has risk band %q (score %d). Recommended admission action: %s.",
			c.Coordinate, rowStr(c.Row, "riskBand"), rowInt(c.Row, "riskScore"), verdict)
		if d, ok := s.riskDetail(c); ok {
			out["contributions"] = d["contributions"]
			if sum, ok := d["assessmentSummary"]; ok {
				out["assessmentSummary"] = sum
			}
		}
	}
	return out, nil
}

// riskDetail enriches the verdict with the explainable contribution breakdown
// from the most recent matching risk assessment, when the risk provider is wired.
func (s *Server) riskDetail(c coord) (map[string]any, bool) {
	if s.risk == nil {
		return nil, false
	}
	for _, a := range s.risk.Recent(s.maxDetail) {
		if !coordinateMatches(a.Artifact.Coordinate, a.Artifact.Name, a.Artifact.Version, c) {
			continue
		}
		contribs := make([]map[string]any, 0, len(a.Contributions))
		for i, ct := range a.Contributions {
			if i >= s.maxDetail {
				break
			}
			contribs = append(contribs, map[string]any{
				"signal": string(ct.Signal),
				"points": ct.Points,
				"raw":    ct.Raw,
			})
		}
		return map[string]any{
			"contributions":     contribs,
			"assessmentSummary": a.Summary,
		}, true
	}
	return nil, false
}

// coordinateMatches reports whether an assessment/document identity addresses c.
func coordinateMatches(coordinate, name, version string, c coord) bool {
	if c.Coordinate != "" && strings.EqualFold(coordinate, c.Coordinate) {
		return true
	}
	if c.Name != "" && strings.EqualFold(name, c.Name) {
		return c.Version == "" || strings.EqualFold(version, c.Version)
	}
	return false
}

// toolFindings implements get_findings.
func (s *Server) toolFindings(ctx context.Context, tenant string, raw json.RawMessage) (any, error) {
	var a struct {
		coordArgs
		Format string `json:"format"`
	}
	if err := decodeArgs(raw, &a); err != nil {
		return nil, err
	}
	if strings.TrimSpace(a.Name) == "" {
		return nil, fmt.Errorf("the 'name' argument is required")
	}
	c, err := s.resolve(tenant, a.Ecosystem, a.Name, a.Version)
	if err != nil {
		return nil, err
	}

	out := map[string]any{
		"coordinate": c.Coordinate,
		"tenant":     tenant,
		"found":      c.Found,
	}

	if s.findings != nil {
		if doc, ok := s.findings.Get(tenant, c.pkgKey()); ok {
			out["found"] = true
			if strings.EqualFold(strings.TrimSpace(a.Format), "sarif") {
				out["format"] = "sarif"
				out["sarif"] = doc.SARIF(findings.SARIFOptions{ToolVersion: s.version})
			} else {
				out["format"] = "summary"
				out["findings"] = s.summarizeFindings(doc)
				out["count"] = len(doc.Findings)
			}
			return out, nil
		}
	}

	// Fall back to the query summary (counts only) when no detail provider is
	// wired or the artifact has no recorded findings document.
	out["format"] = "summary"
	out["findings"] = []any{}
	out["count"] = rowInt(c.Row, "findings")
	out["blocking"] = rowInt(c.Row, "blockingFindings")
	out["gates"] = rowList(c.Row, "findingGates")
	out["rules"] = rowList(c.Row, "findingRules")
	out["worstSeverity"] = rowStr(c.Row, "worstSeverity")
	return out, nil
}

// summarizeFindings renders a bounded, compact view of a findings document.
func (s *Server) summarizeFindings(doc findings.Document) []map[string]any {
	out := make([]map[string]any, 0, len(doc.Findings))
	for i := range doc.Findings {
		if i >= s.maxDetail {
			break
		}
		f := doc.Findings[i]
		out = append(out, map[string]any{
			"ruleId":     f.RuleID,
			"gate":       string(f.Gate),
			"severity":   string(f.Severity),
			"level":      string(f.Level),
			"identifier": f.Identifier,
			"title":      f.Title,
			"suppressed": f.Suppressed,
		})
	}
	return out
}

// toolProvenance implements get_provenance.
func (s *Server) toolProvenance(ctx context.Context, tenant string, raw json.RawMessage) (any, error) {
	var a coordArgs
	if err := decodeArgs(raw, &a); err != nil {
		return nil, err
	}
	if strings.TrimSpace(a.Name) == "" {
		return nil, fmt.Errorf("the 'name' argument is required")
	}
	c, err := s.resolve(tenant, a.Ecosystem, a.Name, a.Version)
	if err != nil {
		return nil, err
	}

	out := map[string]any{
		"coordinate":       c.Coordinate,
		"tenant":           tenant,
		"found":            c.Found,
		"downstreamPaths":  rowInt(c.Row, "downstreamPaths"),
		"directDependents": rowInt(c.Row, "directDependents"),
	}

	// Source-commit path and reverse-dependency blast radius require a version to
	// key the graph node; only query when we have one.
	if s.provgraph != nil && c.Ecosystem != "" && c.Version != "" {
		if path, perr := s.provgraph.PathToCommit(c.Ecosystem, c.Name, c.Version); perr == nil && path.Found {
			out["sourceCommit"] = map[string]any{
				"commitId":  path.CommitID,
				"commitSha": path.CommitSHA,
				"nodes":     path.Nodes,
			}
		}
		if dep, derr := s.provgraph.ReverseDependencies(c.Ecosystem, c.Name, c.Version); derr == nil && dep.Found {
			out["reverseDependencies"] = map[string]any{
				"total":      dep.Total,
				"direct":     dep.Direct,
				"dependents": s.boundedDependents(dep.Dependents),
			}
		}
	}

	if s.attest != nil {
		if b, ok := s.attest.Get(tenant, c.pkgKey()); ok && b != nil {
			out["attestation"] = map[string]any{
				"present":       true,
				"digest":        b.Digest,
				"predicateType": b.PredicateType,
				"subjectDigest": b.SubjectDigest,
				"keyId":         b.KeyID,
				"createdAt":     b.CreatedAt,
			}
		} else {
			out["attestation"] = map[string]any{"present": false}
		}
	}
	return out, nil
}

// boundedDependents trims the reverse-dependency list to the detail cap and
// renders a compact view of each entry.
func (s *Server) boundedDependents(deps []provgraph.Dependent) []map[string]any {
	out := make([]map[string]any, 0, len(deps))
	for i := range deps {
		if i >= s.maxDetail {
			break
		}
		d := deps[i]
		out = append(out, map[string]any{
			"ecosystem": d.Ecosystem,
			"name":      d.Name,
			"version":   d.Version,
			"direct":    d.Direct,
			"distance":  d.Distance,
		})
	}
	return out
}

// toolTimeline implements get_timeline.
func (s *Server) toolTimeline(ctx context.Context, tenant string, raw json.RawMessage) (any, error) {
	var a struct {
		coordArgs
		IncidentID string `json:"incidentId"`
		Limit      int    `json:"limit"`
	}
	if err := decodeArgs(raw, &a); err != nil {
		return nil, err
	}
	if s.timeline == nil {
		return map[string]any{"enabled": false, "events": []any{}, "note": "the forensic timeline subsystem is not enabled"}, nil
	}

	var c coord
	var err error
	if strings.TrimSpace(a.Name) != "" {
		if c, err = s.resolve(tenant, a.Ecosystem, a.Name, a.Version); err != nil {
			return nil, err
		}
	}

	limit := a.Limit
	if limit <= 0 || limit > s.maxDetail {
		limit = s.maxDetail
	}
	// Tenant is always set, which satisfies the timeline engine's requirement for
	// a scoping selector and enforces hard tenant isolation.
	q := timeline.Query{
		Tenant:     tenant,
		Coordinate: c.Coordinate,
		IncidentID: strings.TrimSpace(a.IncidentID),
		Limit:      limit,
	}
	res, qerr := s.timeline.Query(ctx, q)
	if qerr != nil {
		return nil, qerr
	}

	events := make([]map[string]any, 0, len(res.Events))
	for i := range res.Events {
		if i >= s.maxDetail {
			break
		}
		ev := res.Events[i]
		m := map[string]any{
			"time":       ev.Time,
			"source":     string(ev.Source),
			"category":   string(ev.Category),
			"kind":       ev.Kind,
			"actor":      ev.Actor,
			"coordinate": ev.Coordinate,
			"decision":   ev.Decision,
			"summary":    ev.Summary,
			"incidentId": ev.IncidentID,
		}
		if ev.Proof != nil {
			m["provable"] = true
		}
		events = append(events, m)
	}
	return map[string]any{
		"enabled":   true,
		"tenant":    tenant,
		"events":    events,
		"total":     res.Total,
		"returned":  res.Returned,
		"truncated": res.Truncated,
		"sources":   res.Sources,
	}, nil
}

// toolVulnerabilities implements get_vulnerabilities.
func (s *Server) toolVulnerabilities(ctx context.Context, tenant string, raw json.RawMessage) (any, error) {
	var a coordArgs
	if err := decodeArgs(raw, &a); err != nil {
		return nil, err
	}
	if strings.TrimSpace(a.Name) == "" {
		return nil, fmt.Errorf("the 'name' argument is required")
	}
	c, err := s.resolve(tenant, a.Ecosystem, a.Name, a.Version)
	if err != nil {
		return nil, err
	}

	out := map[string]any{
		"coordinate":    c.Coordinate,
		"tenant":        tenant,
		"found":         c.Found,
		"hasReport":     rowBool(c.Row, "hasVuln"),
		"total":         rowInt(c.Row, "vulnTotal"),
		"critical":      rowInt(c.Row, "vulnCritical"),
		"high":          rowInt(c.Row, "vulnHigh"),
		"medium":        rowInt(c.Row, "vulnMedium"),
		"low":           rowInt(c.Row, "vulnLow"),
		"maxCvss":       rowNum(c.Row, "maxCvss"),
		"maxSeverity":   rowStr(c.Row, "maxSeverity"),
		"cves":          rowList(c.Row, "cves"),
		"quarantined":   rowBool(c.Row, "quarantined"),
		"vexSuppressed": rowInt(c.Row, "vexSuppressed"),
	}

	if s.vuln != nil && c.Digest != "" {
		if rep, ok := s.vuln.Report(c.Digest); ok && rep != nil {
			out["scanner"] = rep.Scanner
			out["scannedAt"] = rep.ScannedAt
			vulns := make([]map[string]any, 0, len(rep.Vulnerabilities))
			for i := range rep.Vulnerabilities {
				if i >= s.maxDetail {
					break
				}
				v := rep.Vulnerabilities[i]
				vulns = append(vulns, map[string]any{
					"id":            v.ID,
					"severity":      string(v.Severity),
					"cvss":          v.CVSS,
					"component":     v.Component,
					"package":       v.Package,
					"version":       v.Version,
					"fixedVersions": v.FixedVersions,
					"suppressed":    v.Suppressed,
					"vexStatus":     string(v.VEXStatus),
				})
			}
			out["vulnerabilities"] = vulns
		}
	}
	return out, nil
}

// toolRunQuery implements run_query: a passthrough to the federated query engine,
// forcing the tenant scope so a client cannot read another tenant's data.
func (s *Server) toolRunQuery(ctx context.Context, tenant string, raw json.RawMessage) (any, error) {
	var q queryapi.Query
	if err := decodeArgs(raw, &q); err != nil {
		return nil, err
	}
	// Hard-scope: the authenticated tenant always wins over any client-supplied
	// value. An empty tenant (a global admin / unauthenticated trusted-network
	// call) queries across tenants, matching the admin query API's semantics.
	q.Tenant = tenant
	res, err := s.backend.Query(q)
	if err != nil {
		if qe, ok := err.(*queryapi.QueryError); ok {
			return nil, fmt.Errorf("query rejected (%s): %s", qe.Code, qe.Msg)
		}
		return nil, err
	}
	return res, nil
}

// toolRepositoryScan returns a repository revision's dependency scan (Task
// 181), hard-scoped to the caller's tenant.
func (s *Server) toolRepositoryScan(ctx context.Context, tenant string, raw json.RawMessage) (any, error) {
	var a struct {
		Repo     string `json:"repo"`
		Rev      string `json:"rev"`
		Verdicts string `json:"verdicts"`
		Format   string `json:"format"`
	}
	if err := decodeArgs(raw, &a); err != nil {
		return nil, err
	}
	if strings.TrimSpace(a.Repo) == "" {
		return nil, fmt.Errorf("the 'repo' argument is required")
	}
	if s.repoScans == nil {
		return nil, fmt.Errorf("repository dependency scans are not available (repositories.enabled)")
	}
	rep, err := s.repoScans.ScanReport(ctx, tenant, strings.TrimSpace(a.Repo), strings.TrimSpace(a.Rev))
	if err != nil {
		if errors.Is(err, repos.ErrNotFound) {
			return nil, fmt.Errorf("no scan of that repository revision is visible to you")
		}
		return nil, err
	}
	if strings.EqualFold(strings.TrimSpace(a.Format), "sarif") {
		doc := rep.FindingsDocument()
		return map[string]any{"format": "sarif", "repo": rep.Repo, "commit": rep.Commit,
			"sarif": doc.SARIF(findings.SARIFOptions{ToolVersion: s.version})}, nil
	}
	keep := func(v string) bool { return true }
	switch strings.ToLower(strings.TrimSpace(a.Verdicts)) {
	case "flagged":
		keep = func(v string) bool { return v == repos.VerdictMalicious || v == repos.VerdictSuspicious }
	case "unscanned":
		keep = func(v string) bool { return v == repos.VerdictUnscanned }
	case "not-benign":
		keep = func(v string) bool { return v != repos.VerdictBenign }
	}
	// Flagged first, then unscanned, then benign; bounded.
	deps := append([]repos.DependencyScan(nil), rep.Dependencies...)
	sort.SliceStable(deps, func(i, j int) bool { return verdictOrder(deps[i].Verdict) > verdictOrder(deps[j].Verdict) })
	list := make([]map[string]any, 0, len(deps))
	for _, d := range deps {
		if !keep(d.Verdict) {
			continue
		}
		if len(list) >= s.maxDetail {
			break
		}
		item := map[string]any{
			"dependency": d.Coordinate(),
			"verdict":    d.Verdict,
			"files":      d.Files,
		}
		if d.Pinned {
			item["pinned"] = true
		}
		if d.Refused {
			item["refusedToClients"] = true
		}
		if d.Released != "" {
			item["releasedByBreakGlass"] = d.Released
		}
		if u := d.Unscanned; u != nil {
			item["unscannedCode"] = u.Code
			item["unscannedReason"] = u.Reason
			item["retryable"] = u.Retryable
		}
		if v := d.Detail; v != nil {
			item["model"] = v.Model
			item["modelVerdict"] = v.ModelVerdict
			item["confidence"] = v.Confidence
			item["digest"] = v.Digest
			item["scannedAt"] = v.ScannedAt
			// Only the places the proxy confirmed: a path the model named
			// and the proxy did not find is the model's text.
			var cited []map[string]any
			for _, ev := range v.Evidence {
				if ev.Verified {
					cited = append(cited, map[string]any{"path": ev.Path, "line": ev.Line})
				}
			}
			if len(cited) > 0 {
				item["verifiedEvidence"] = cited
			}
		}
		list = append(list, item)
	}
	return map[string]any{
		"format":                      "summary",
		"repo":                        rep.Repo,
		"commit":                      rep.Commit,
		"kind":                        rep.Kind,
		"ref":                         rep.Ref,
		"tags":                        rep.Tags,
		"current":                     rep.Current,
		"status":                      rep.Status,
		"result":                      rep.Result,
		"containsMaliciousDependency": rep.ContainsMaliciousDependency,
		"reason":                      rep.Reason,
		"summary":                     rep.Summary,
		"gate":                        rep.Gate,
		"finishedAt":                  rep.FinishedAt,
		"dependencies":                list,
	}, nil
}

func verdictOrder(v string) int {
	switch v {
	case repos.VerdictMalicious:
		return 4
	case repos.VerdictSuspicious:
		return 3
	case repos.VerdictUnscanned:
		return 2
	}
	return 1
}
