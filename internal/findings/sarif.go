package findings

import (
	"crypto/sha256"
	"encoding/hex"
	"sort"
)

// This file renders the canonical findings model as a SARIF 2.1.0 log. The types
// model the subset of the SARIF object model the proxy emits; field names and
// the omitempty choices follow the SARIF 2.1.0 schema so the output validates
// against it and is ingestible by GitHub code scanning and GitLab.

// SARIFSchema is the canonical $schema URI for SARIF 2.1.0.
const SARIFSchema = "https://json.schemastore.org/sarif-2.1.0.json"

// SARIFVersion is the SARIF specification version this package emits.
const SARIFVersion = "2.1.0"

// toolInformationURI points consumers at the producing tool.
const toolInformationURI = "https://github.com/blechschmidt/pullthrough-security"

// Log is the root SARIF document.
type Log struct {
	Schema  string `json:"$schema"`
	Version string `json:"version"`
	Runs    []Run  `json:"runs"`
}

// Run is a single analysis run: the tool that produced it and its results.
type Run struct {
	Tool    Tool     `json:"tool"`
	Results []Result `json:"results"`
}

// Tool describes the analysis tool (its driver component).
type Tool struct {
	Driver Driver `json:"driver"`
}

// Driver is the primary tool component: its identity and rule catalog.
type Driver struct {
	Name           string          `json:"name"`
	InformationURI string          `json:"informationUri,omitempty"`
	Version        string          `json:"version,omitempty"`
	Rules          []ReportingRule `json:"rules"`
}

// ReportingRule is a SARIF reportingDescriptor (a rule definition).
type ReportingRule struct {
	ID                   string                  `json:"id"`
	Name                 string                  `json:"name,omitempty"`
	ShortDescription     *MultiformatMessage     `json:"shortDescription,omitempty"`
	FullDescription      *MultiformatMessage     `json:"fullDescription,omitempty"`
	Help                 *MultiformatMessage     `json:"help,omitempty"`
	HelpURI              string                  `json:"helpUri,omitempty"`
	DefaultConfiguration *ReportingConfiguration `json:"defaultConfiguration,omitempty"`
	Properties           map[string]any          `json:"properties,omitempty"`
}

// ReportingConfiguration carries a rule's default level.
type ReportingConfiguration struct {
	Level string `json:"level"`
}

// MultiformatMessage is a SARIF multiformatMessageString (text, optional
// markdown).
type MultiformatMessage struct {
	Text string `json:"text"`
}

// Result is a single finding occurrence.
type Result struct {
	RuleID              string            `json:"ruleId"`
	RuleIndex           int               `json:"ruleIndex"`
	Level               string            `json:"level"`
	Message             Message           `json:"message"`
	Locations           []ResultLoc       `json:"locations,omitempty"`
	PartialFingerprints map[string]string `json:"partialFingerprints,omitempty"`
	Suppressions        []Suppression     `json:"suppressions,omitempty"`
	Fixes               []Fix             `json:"fixes,omitempty"`
	Properties          map[string]any    `json:"properties,omitempty"`
}

// Fix is a SARIF fix object: a proposed change that would resolve the result.
// The proxy emits the description only (a suggested dependency upgrade), which
// is the portion GitHub code scanning and GitLab surface in a PR annotation; the
// optional artifactChanges array is intentionally omitted because the fix is a
// coordinate-level upgrade, not a concrete source-file edit.
type Fix struct {
	Description *Message `json:"description,omitempty"`
}

// Message is a SARIF message object.
type Message struct {
	Text string `json:"text"`
}

// ResultLoc is a SARIF location: a physical location (artifact/region) and/or
// logical locations (the package coordinate, the source commit).
type ResultLoc struct {
	PhysicalLocation *PhysicalLocation `json:"physicalLocation,omitempty"`
	LogicalLocations []LogicalLocation `json:"logicalLocations,omitempty"`
}

// PhysicalLocation points at an artifact and (optionally) a region within it.
type PhysicalLocation struct {
	ArtifactLocation ArtifactLocation `json:"artifactLocation"`
	Region           *Region          `json:"region,omitempty"`
}

// ArtifactLocation is a URI identifying an artifact.
type ArtifactLocation struct {
	URI string `json:"uri"`
}

// Region is a span within an artifact (a line for secret findings).
type Region struct {
	StartLine int `json:"startLine,omitempty"`
}

// LogicalLocation names a logical place: the package coordinate or the source
// commit, with a SARIF "kind" so consumers can distinguish them.
type LogicalLocation struct {
	Name               string `json:"name,omitempty"`
	FullyQualifiedName string `json:"fullyQualifiedName,omitempty"`
	Kind               string `json:"kind,omitempty"`
}

// Suppression marks a result as suppressed (VEX adjudication), so CI does not
// fail on it but the finding remains visible for transparency.
type Suppression struct {
	Kind          string `json:"kind"`
	Justification string `json:"justification,omitempty"`
}

// SARIFOptions tunes SARIF rendering.
type SARIFOptions struct {
	// ToolVersion is recorded as the driver version (the proxy build version).
	ToolVersion string
}

// SARIF renders one document as a complete SARIF 2.1.0 log (a single run). It is
// a convenience over SARIFFromDocuments for the common single-artifact case.
func (d *Document) SARIF(opts SARIFOptions) Log {
	return SARIFFromDocuments([]Document{*d}, opts)
}

// SARIFFromDocuments renders a batch of documents as a single SARIF run, fusing
// every artifact's findings into one log — the shape a CI pipeline ingests for a
// whole dependency set or an air-gapped import preflight. The rule catalog is
// the union of rules any finding references, emitted in canonical order; results
// are ordered by document, then by the finding order within each document, so
// output is fully deterministic.
func SARIFFromDocuments(docs []Document, opts SARIFOptions) Log {
	// Collect the set of referenced rule ids, then emit them in canonical order.
	referenced := map[string]bool{}
	for i := range docs {
		for j := range docs[i].Findings {
			referenced[docs[i].Findings[j].RuleID] = true
		}
	}
	rules := make([]ReportingRule, 0, len(referenced))
	ruleIndex := make(map[string]int, len(referenced))
	emit := func(id string) {
		if _, done := ruleIndex[id]; done {
			return
		}
		ruleIndex[id] = len(rules)
		rules = append(rules, toReportingRule(ruleFor(id)))
	}
	for _, id := range catalogOrder {
		if referenced[id] {
			emit(id)
		}
	}
	// Any referenced id not in the canonical order (defensive) is appended in a
	// stable, sorted order so output stays deterministic.
	var extra []string
	for id := range referenced {
		if _, done := ruleIndex[id]; !done {
			extra = append(extra, id)
		}
	}
	sort.Strings(extra)
	for _, id := range extra {
		emit(id)
	}

	results := make([]Result, 0)
	for i := range docs {
		for j := range docs[i].Findings {
			results = append(results, toResult(&docs[i], &docs[i].Findings[j], ruleIndex))
		}
	}

	return Log{
		Schema:  SARIFSchema,
		Version: SARIFVersion,
		Runs: []Run{{
			Tool: Tool{Driver: Driver{
				Name:           "pullthrough-security",
				InformationURI: toolInformationURI,
				Version:        fallback(opts.ToolVersion, "dev"),
				Rules:          rules,
			}},
			Results: results,
		}},
	}
}

// toReportingRule projects a catalog Rule to a SARIF reportingDescriptor.
func toReportingRule(r Rule) ReportingRule {
	rr := ReportingRule{
		ID:                   r.ID,
		Name:                 r.Name,
		HelpURI:              r.HelpURI,
		DefaultConfiguration: &ReportingConfiguration{Level: string(r.Default)},
		Properties:           map[string]any{"gate": string(r.Gate)},
	}
	if r.Short != "" {
		rr.ShortDescription = &MultiformatMessage{Text: r.Short}
	}
	if r.Full != "" {
		rr.FullDescription = &MultiformatMessage{Text: r.Full}
	}
	if r.HelpText != "" {
		rr.Help = &MultiformatMessage{Text: r.HelpText}
	}
	if len(r.Tags) > 0 {
		rr.Properties["tags"] = toAnySlice(r.Tags)
	}
	if r.External != "" {
		rr.Properties["externalReference"] = r.External
	}
	return rr
}

// toResult projects a normalized Finding to a SARIF result, keyed to its rule by
// index and located against the package coordinate / file / commit.
func toResult(d *Document, f *Finding, ruleIndex map[string]int) Result {
	res := Result{
		RuleID:     f.RuleID,
		RuleIndex:  ruleIndex[f.RuleID],
		Level:      string(f.Level),
		Message:    Message{Text: resultMessage(f)},
		Locations:  []ResultLoc{toLocation(d, f)},
		Properties: resultProperties(d, f),
	}
	res.PartialFingerprints = map[string]string{"primary": fingerprint(d, f)}
	if f.Suppressed {
		res.Suppressions = []Suppression{{Kind: "external", Justification: f.Justification}}
	}
	if f.Fix != nil && f.Fix.Description != "" {
		res.Fixes = []Fix{{Description: &Message{Text: f.Fix.Description}}}
	}
	return res
}

// resultMessage prefers the full message, falling back to the title.
func resultMessage(f *Finding) string {
	if f.Message != "" {
		return f.Message
	}
	return f.Title
}

// toLocation builds the SARIF location for a finding. The package coordinate is
// the physical artifact URI (so CI shows a path), with logical locations for the
// coordinate and — when known — the source commit and the file.
func toLocation(d *Document, f *Finding) ResultLoc {
	coord := f.Location.Coordinate
	if coord == "" {
		coord = d.Artifact.Coordinate
	}
	uri := coord
	if f.Location.File != "" {
		uri = f.Location.File
	}
	if uri == "" {
		uri = fallback(d.Artifact.Name, "artifact")
	}
	loc := ResultLoc{
		PhysicalLocation: &PhysicalLocation{ArtifactLocation: ArtifactLocation{URI: uri}},
	}
	if f.Location.Line > 0 {
		loc.PhysicalLocation.Region = &Region{StartLine: f.Location.Line}
	}
	if coord != "" {
		loc.LogicalLocations = append(loc.LogicalLocations, LogicalLocation{
			Name: coord, FullyQualifiedName: coord, Kind: "package",
		})
	}
	if f.Location.CommitSHA != "" {
		fqn := f.Location.CommitSHA
		if f.Location.RepositoryURL != "" {
			fqn = f.Location.RepositoryURL + "@" + f.Location.CommitSHA
		}
		loc.LogicalLocations = append(loc.LogicalLocations, LogicalLocation{
			Name: f.Location.CommitSHA, FullyQualifiedName: fqn, Kind: "module",
		})
	}
	return loc
}

// resultProperties assembles the result property bag: the originating gate,
// canonical severity, the stable identifier, plus any gate-specific detail.
func resultProperties(d *Document, f *Finding) map[string]any {
	props := map[string]any{
		"gate":     string(f.Gate),
		"severity": string(f.Severity),
	}
	if f.Identifier != "" {
		props["identifier"] = f.Identifier
	}
	// When de-duplication merged two or more gates' reports of the same issue,
	// surface every contributing gate so a SARIF consumer can see the finding was
	// corroborated by more than one gate (Task 165). A single-gate finding is left
	// unannotated to keep the common case compact.
	if len(f.Sources) > 1 {
		srcs := make([]any, 0, len(f.Sources))
		for _, s := range f.Sources {
			srcs = append(srcs, map[string]any{
				"gate":       string(s.Gate),
				"ruleId":     s.RuleID,
				"severity":   string(s.Severity),
				"identifier": s.Identifier,
				"suppressed": s.Suppressed,
			})
		}
		props["sources"] = srcs
	}
	if d.Tenant != "" {
		props["tenant"] = d.Tenant
	}
	if d.Artifact.Ecosystem != "" {
		props["ecosystem"] = d.Artifact.Ecosystem
	}
	for k, v := range f.Properties {
		if v == nil {
			continue
		}
		if s, ok := v.(string); ok && s == "" {
			continue
		}
		props[k] = v
	}
	return props
}

// fingerprint computes a stable partial fingerprint so SARIF consumers recognize
// the same logical finding across scans (deduplication / resolved-tracking). It
// keys on the rule, the artifact coordinate, the gate identifier, and the file —
// the identity of the issue, independent of message wording.
func fingerprint(d *Document, f *Finding) string {
	coord := f.Location.Coordinate
	if coord == "" {
		coord = d.Artifact.Coordinate
	}
	h := sha256.New()
	for _, part := range []string{f.RuleID, coord, f.Identifier, f.Location.File, f.Location.CommitSHA} {
		h.Write([]byte(part))
		h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil))[:32]
}

func toAnySlice(in []string) []any {
	out := make([]any, len(in))
	for i, s := range in {
		out[i] = s
	}
	return out
}
