package siem

import (
	"fmt"
	"strings"
)

// DefaultOCSFSchemaVersion is the Open Cybersecurity Schema Framework schema
// version the encoder targets when an operator does not override it. OCSF-aware
// platforms (AWS Security Lake, Snowflake, ...) select a parser/table from the
// metadata.version field, so it is emitted on every record.
const DefaultOCSFSchemaVersion = "1.1.0"

// OCSF category and class identifiers used by the encoder. These are the stable
// numeric ids defined by the Open Cybersecurity Schema Framework; the encoder
// emits both the uid and the human-readable name for each so downstream
// platforms can route on either.
const (
	ocsfCategoryFindings    = 2 // Findings
	ocsfCategoryIAM         = 3 // Identity & Access Management
	ocsfCategoryApplication = 6 // Application Activity

	ocsfClassVulnerabilityFinding = 2002
	ocsfClassComplianceFinding    = 2003
	ocsfClassDetectionFinding     = 2004
	ocsfClassAuthentication       = 3002
	ocsfClassAPIActivity          = 6003
)

// ocsfClass describes one OCSF event class: its numeric class uid and the
// category it belongs to, with both human-readable names.
type ocsfClass struct {
	categoryUID  int
	categoryName string
	classUID     int
	className    string
}

// ocsfClasses is the registry of the event classes this encoder can emit,
// keyed by class uid.
var ocsfClasses = map[int]ocsfClass{
	ocsfClassVulnerabilityFinding: {ocsfCategoryFindings, "Findings", ocsfClassVulnerabilityFinding, "Vulnerability Finding"},
	ocsfClassComplianceFinding:    {ocsfCategoryFindings, "Findings", ocsfClassComplianceFinding, "Compliance Finding"},
	ocsfClassDetectionFinding:     {ocsfCategoryFindings, "Findings", ocsfClassDetectionFinding, "Detection Finding"},
	ocsfClassAuthentication:       {ocsfCategoryIAM, "Identity & Access Management", ocsfClassAuthentication, "Authentication"},
	ocsfClassAPIActivity:          {ocsfCategoryApplication, "Application Activity", ocsfClassAPIActivity, "API Activity"},
}

// ocsfClassAliases maps the operator-facing class names (accepted in the
// siem.ocsf.classMap overrides) onto the class uid. Both the canonical
// snake_case token and the OCSF display name are accepted.
var ocsfClassAliases = map[string]int{
	"vulnerability_finding": ocsfClassVulnerabilityFinding,
	"vulnerability finding": ocsfClassVulnerabilityFinding,
	"compliance_finding":    ocsfClassComplianceFinding,
	"compliance finding":    ocsfClassComplianceFinding,
	"detection_finding":     ocsfClassDetectionFinding,
	"detection finding":     ocsfClassDetectionFinding,
	"authentication":        ocsfClassAuthentication,
	"api_activity":          ocsfClassAPIActivity,
	"api activity":          ocsfClassAPIActivity,
	"application_activity":  ocsfClassAPIActivity,
	"application activity":  ocsfClassAPIActivity,
}

// lookupOCSFClass resolves an operator-supplied class name to its definition.
func lookupOCSFClass(name string) (ocsfClass, bool) {
	uid, ok := ocsfClassAliases[strings.ToLower(strings.TrimSpace(name))]
	if !ok {
		return ocsfClass{}, false
	}
	return ocsfClasses[uid], true
}

// ValidOCSFClass reports whether name is a recognized OCSF class name for a
// classMap override. It is used by both the config validator and the encoder
// constructor.
func ValidOCSFClass(name string) bool {
	_, ok := ocsfClassAliases[strings.ToLower(strings.TrimSpace(name))]
	return ok
}

// OCSFConfig configures the OCSF output encoder (siem.ocsf.*). The zero value
// encodes against DefaultOCSFSchemaVersion with the built-in category->class
// routing and no overrides.
type OCSFConfig struct {
	// SchemaVersion is the OCSF schema version stamped into metadata.version
	// (default DefaultOCSFSchemaVersion).
	SchemaVersion string
	// ClassMap overrides the default category->class routing. Each key is an
	// event Category (the gate name for findings, the audit EventType for audit
	// records); each value names an OCSF class ("detection_finding",
	// "vulnerability_finding", "compliance_finding", "authentication", or
	// "api_activity").
	ClassMap map[string]string
	// ProductName and VendorName populate metadata.product (defaults
	// "pullthrough-security" / "Blechschmidt").
	ProductName string
	VendorName  string
}

// ocsfEncoder renders a normalized Event into an OCSF-conformant object.
type ocsfEncoder struct {
	schemaVersion string
	classMap      map[string]ocsfClass // keyed by lowercased event category
	productName   string
	vendorName    string
}

// newOCSFEncoder builds an encoder from config, validating any classMap
// overrides.
func newOCSFEncoder(cfg OCSFConfig) (*ocsfEncoder, error) {
	version := strings.TrimSpace(cfg.SchemaVersion)
	if version == "" {
		version = DefaultOCSFSchemaVersion
	}
	e := &ocsfEncoder{
		schemaVersion: version,
		classMap:      make(map[string]ocsfClass, len(cfg.ClassMap)),
		productName:   firstNonEmpty(cfg.ProductName, "pullthrough-security"),
		vendorName:    firstNonEmpty(cfg.VendorName, "Blechschmidt"),
	}
	for category, className := range cfg.ClassMap {
		cls, ok := lookupOCSFClass(className)
		if !ok {
			return nil, fmt.Errorf("siem: unknown ocsf class %q for category %q (want detection_finding, vulnerability_finding, compliance_finding, authentication, or api_activity)", className, category)
		}
		key := strings.ToLower(strings.TrimSpace(category))
		if key == "" {
			return nil, fmt.Errorf("siem: ocsf classMap has an empty category key")
		}
		e.classMap[key] = cls
	}
	return e, nil
}

// classFor selects the OCSF class for an event: an explicit classMap override
// wins, otherwise the built-in routing applies.
func (e *ocsfEncoder) classFor(ev Event) ocsfClass {
	if cls, ok := e.classMap[strings.ToLower(ev.Category)]; ok {
		return cls
	}
	return defaultOCSFClass(ev)
}

// defaultOCSFClass is the built-in category->class routing. Gate findings map
// to the matching Findings-category class; audit records map to Authentication,
// Detection Finding, or API Activity depending on the audited event type.
func defaultOCSFClass(ev Event) ocsfClass {
	if ev.Source == SourceFinding {
		switch ev.Category {
		case "vulnscan", "vex":
			return ocsfClasses[ocsfClassVulnerabilityFinding]
		case "license":
			return ocsfClasses[ocsfClassComplianceFinding]
		default:
			return ocsfClasses[ocsfClassDetectionFinding]
		}
	}
	switch ev.Category {
	case "auth":
		return ocsfClasses[ocsfClassAuthentication]
	case "scan_verdict", "policy_decision", "egress_blocked", "tls_pin":
		return ocsfClasses[ocsfClassDetectionFinding]
	default:
		return ocsfClasses[ocsfClassAPIActivity]
	}
}

// encode renders an Event into an OCSF object. The returned map is a fresh
// allocation safe for the caller to JSON-encode; map iteration order does not
// matter because encoding/json sorts keys.
func (e *ocsfEncoder) encode(ev Event) map[string]any {
	cls := e.classFor(ev)
	activityID, activityName := e.activity(ev, cls)
	sevID := ocsfSeverityID(ev.Severity)

	obj := map[string]any{
		"activity_id":   activityID,
		"activity_name": activityName,
		"category_uid":  cls.categoryUID,
		"category_name": cls.categoryName,
		"class_uid":     cls.classUID,
		"class_name":    cls.className,
		"type_uid":      cls.classUID*100 + activityID,
		"type_name":     fmt.Sprintf("%s: %s", cls.className, activityName),
		"severity_id":   sevID,
		"severity":      ocsfSeverityName(sevID),
		"time":          ev.Time.UTC().UnixMilli(),
		"metadata": map[string]any{
			"version":      e.schemaVersion,
			"log_provider": "pullthrough-security",
			"log_name":     string(ev.Source),
			"product": map[string]any{
				"name":        e.productName,
				"vendor_name": e.vendorName,
			},
			"uid": ocsfRecordUID(ev),
		},
	}
	if ev.Message != "" {
		obj["message"] = ev.Message
	}

	// Carry every structured field through the OCSF-reserved "unmapped" object
	// so no detail (seq/hash correlation keys, coordinates, trace ids) is lost
	// even when it has no first-class OCSF home.
	if len(ev.Fields) > 0 {
		unmapped := make(map[string]any, len(ev.Fields))
		for k, v := range ev.Fields {
			unmapped[k] = v
		}
		obj["unmapped"] = unmapped
	}

	switch cls.categoryUID {
	case ocsfCategoryFindings:
		e.decorateFinding(obj, ev, cls)
	case ocsfCategoryIAM:
		e.decorateAuthentication(obj, ev)
	default:
		e.decorateAPIActivity(obj, ev)
	}
	return obj
}

// decorateFinding adds the finding-class-specific objects: finding_info, a New
// status, and (for Vulnerability Finding) the vulnerabilities array.
func (e *ocsfEncoder) decorateFinding(obj map[string]any, ev Event, cls ocsfClass) {
	fi := map[string]any{
		"title": nonEmpty(ev.Name, ev.Category),
		"uid":   ocsfRecordUID(ev),
	}
	if ev.Message != "" {
		fi["desc"] = ev.Message
	}
	if id := ev.Fields["identifier"]; id != "" {
		fi["types"] = []any{id}
	}
	if rule := ev.Fields["ruleId"]; rule != "" {
		fi["product_uid"] = rule
	}
	obj["finding_info"] = fi
	// A forwarded finding is a newly-observed detection; OCSF status_id 1 = New.
	obj["status"] = "New"
	obj["status_id"] = 1

	if cls.classUID == ocsfClassVulnerabilityFinding {
		obj["vulnerabilities"] = []any{e.vulnerability(ev)}
	}
}

// vulnerability builds a single OCSF Vulnerability object from an event's
// fields.
func (e *ocsfEncoder) vulnerability(ev Event) map[string]any {
	v := map[string]any{
		"severity": ocsfSeverityName(ocsfSeverityID(ev.Severity)),
	}
	if ev.Message != "" {
		v["desc"] = ev.Message
	}
	if title := nonEmpty(ev.Name, ev.Category); title != "" {
		v["title"] = title
	}
	if id := ev.Fields["identifier"]; isVulnID(id) {
		v["cve"] = map[string]any{"uid": id}
	}
	if pkg := e.affectedPackage(ev); pkg != nil {
		v["affected_packages"] = []any{pkg}
	}
	return v
}

// affectedPackage projects an event's artifact coordinate onto an OCSF
// affected-package object, or nil when nothing is known.
func (e *ocsfEncoder) affectedPackage(ev Event) map[string]any {
	name := ev.Fields["artifact"]
	if name == "" {
		return nil
	}
	pkg := map[string]any{"name": name}
	if v := ev.Fields["version"]; v != "" {
		pkg["version"] = v
	}
	if eco := ev.Fields["ecosystem"]; eco != "" {
		pkg["purl"] = fmt.Sprintf("pkg:%s/%s@%s", eco, name, ev.Fields["version"])
	}
	return pkg
}

// decorateAuthentication adds Authentication-class detail: the subject user and
// a success/failure status derived from the audit decision.
func (e *ocsfEncoder) decorateAuthentication(obj map[string]any, ev Event) {
	if ev.Subject != "" {
		obj["user"] = map[string]any{"name": ev.Subject}
	}
	if addr := ev.Fields["remoteAddr"]; addr != "" {
		obj["src_endpoint"] = map[string]any{"ip": addr}
	}
	statusID, status := ocsfStatus(ev.Outcome)
	obj["status_id"] = statusID
	obj["status"] = status
	if ev.Outcome != "" {
		obj["status_detail"] = ev.Outcome
	}
}

// decorateAPIActivity adds API-Activity-class detail: the api operation/service
// and a success/failure status derived from the audit decision.
func (e *ocsfEncoder) decorateAPIActivity(obj map[string]any, ev Event) {
	api := map[string]any{
		"operation": nonEmpty(ev.Fields["method"], ev.Category),
	}
	if svc := ev.Fields["backend"]; svc != "" {
		api["service"] = map[string]any{"name": svc}
	}
	obj["api"] = api
	if res := nonEmpty(ev.Fields["resource"], ev.Fields["coordinate"]); res != "" {
		obj["resources"] = []any{map[string]any{"name": res, "type": ev.Fields["ecosystem"]}}
	}
	if addr := ev.Fields["remoteAddr"]; addr != "" {
		obj["src_endpoint"] = map[string]any{"ip": addr}
	}
	if ev.Subject != "" {
		obj["actor"] = map[string]any{"user": map[string]any{"name": ev.Subject}}
	}
	statusID, status := ocsfStatus(ev.Outcome)
	obj["status_id"] = statusID
	obj["status"] = status
	if ev.Outcome != "" {
		obj["status_detail"] = ev.Outcome
	}
}

// activity returns the OCSF activity_id/activity_name for an event within its
// class. Findings are always a Create; authentication a Logon; API activity is
// inferred from the HTTP-ish method when present and otherwise Unknown.
func (e *ocsfEncoder) activity(ev Event, cls ocsfClass) (int, string) {
	switch cls.categoryUID {
	case ocsfCategoryFindings:
		return 1, "Create"
	case ocsfCategoryIAM:
		return 1, "Logon"
	default:
		return apiActivity(ev.Fields["method"])
	}
}

// apiActivity maps an HTTP method onto the OCSF API Activity activity id/name.
// A non-HTTP or absent method yields the Unknown activity (id 0), which is a
// valid OCSF value.
func apiActivity(method string) (int, string) {
	switch strings.ToUpper(strings.TrimSpace(method)) {
	case "POST":
		return 1, "Create"
	case "GET", "HEAD":
		return 2, "Read"
	case "PUT", "PATCH":
		return 3, "Update"
	case "DELETE":
		return 4, "Delete"
	default:
		return 0, "Unknown"
	}
}

// ocsfStatus maps an audit decision/outcome onto the OCSF status id/name scale
// (1 Success, 2 Failure, 0 Unknown).
func ocsfStatus(outcome string) (int, string) {
	switch strings.ToLower(strings.TrimSpace(outcome)) {
	case "allow":
		return 1, "Success"
	case "deny", "error":
		return 2, "Failure"
	default:
		return 0, "Unknown"
	}
}

// ocsfSeverityID maps the canonical severity onto the OCSF severity_id scale:
// 1 Informational, 2 Low, 3 Medium, 4 High, 5 Critical.
func ocsfSeverityID(sev Severity) int {
	switch sev {
	case SeverityLow:
		return 2
	case SeverityMedium:
		return 3
	case SeverityHigh:
		return 4
	case SeverityCritical:
		return 5
	default:
		return 1
	}
}

// ocsfSeverityName renders the OCSF severity caption for a severity_id.
func ocsfSeverityName(id int) string {
	switch id {
	case 2:
		return "Low"
	case 3:
		return "Medium"
	case 4:
		return "High"
	case 5:
		return "Critical"
	default:
		return "Informational"
	}
}

// ocsfRecordUID derives a stable, correlatable record uid from the event: the
// audit log sequence number when present, otherwise the gate rule/identifier,
// falling back to the category.
func ocsfRecordUID(ev Event) string {
	if seq := ev.Fields["seq"]; seq != "" {
		return "audit:" + seq
	}
	rule := ev.Fields["ruleId"]
	id := ev.Fields["identifier"]
	switch {
	case rule != "" && id != "":
		return rule + ":" + id
	case rule != "":
		return rule
	case id != "":
		return id
	default:
		return ev.Category
	}
}

// isVulnID reports whether id looks like a vulnerability identifier the OCSF
// cve.uid field should carry (a CVE or GHSA advisory id).
func isVulnID(id string) bool {
	u := strings.ToUpper(strings.TrimSpace(id))
	return strings.HasPrefix(u, "CVE-") || strings.HasPrefix(u, "GHSA-")
}
