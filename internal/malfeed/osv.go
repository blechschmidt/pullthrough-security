package malfeed

import (
	"encoding/json"
	"fmt"
	"strings"
)

// osvRecord is the subset of the OSV schema (https://ossf.github.io/osv-schema/)
// the malicious-packages dataset and the GitHub Advisory malware entries use.
// Only the fields needed to derive a known-malicious (ecosystem, name, version)
// record are decoded; everything else is ignored.
type osvRecord struct {
	ID        string          `json:"id"`
	Aliases   []string        `json:"aliases"`
	Summary   string          `json:"summary"`
	Details   string          `json:"details"`
	Published string          `json:"published"`
	Affected  []osvAffected   `json:"affected"`
	Database  osvDatabase     `json:"database_specific"`
	Severity  json.RawMessage `json:"severity"`
}

type osvDatabase struct {
	// The OSV malicious-packages dataset tags the malware class here; GHSA uses a
	// "type": "malware" marker. Both are best-effort and optional.
	MalwareCategories []string `json:"malicious-packages-origins"`
	Categories        []string `json:"categories"`
	Type              string   `json:"type"`
}

type osvAffected struct {
	Package  osvPackage    `json:"package"`
	Versions []string      `json:"versions"`
	Ranges   []osvRange    `json:"ranges"`
	Database osvAffectedDB `json:"database_specific"`
}

type osvAffectedDB struct {
	Categories []string `json:"categories"`
}

type osvPackage struct {
	Ecosystem string `json:"ecosystem"`
	Name      string `json:"name"`
	PURL      string `json:"purl"`
}

type osvRange struct {
	Type   string     `json:"type"`
	Events []osvEvent `json:"events"`
}

type osvEvent struct {
	Introduced   string `json:"introduced"`
	Fixed        string `json:"fixed"`
	LastAffected string `json:"last_affected"`
	Limit        string `json:"limit"`
}

// ParseOSVRecord decodes a single OSV/GHSA JSON document into zero or more
// Entries — one per affected package. The OSV malicious-packages dataset stores
// one record per file with a single affected package; GHSA malware advisories
// can list several. source labels the originating feed for provenance. A record
// with no affected packages yields no entries (not an error).
func ParseOSVRecord(data []byte, source string) ([]Entry, error) {
	var rec osvRecord
	if err := json.Unmarshal(data, &rec); err != nil {
		return nil, fmt.Errorf("malfeed: parse OSV record: %w", err)
	}
	return rec.toEntries(source), nil
}

// ParseOSVStream decodes either a single OSV record or a JSON array of OSV
// records (the export shapes the malicious-packages tooling and GHSA bulk
// exports both produce). It returns the accumulated entries.
func ParseOSVStream(data []byte, source string) ([]Entry, error) {
	trimmed := strings.TrimSpace(string(data))
	if strings.HasPrefix(trimmed, "[") {
		var recs []osvRecord
		if err := json.Unmarshal(data, &recs); err != nil {
			return nil, fmt.Errorf("malfeed: parse OSV array: %w", err)
		}
		var out []Entry
		for i := range recs {
			out = append(out, recs[i].toEntries(source)...)
		}
		return out, nil
	}
	return ParseOSVRecord(data, source)
}

// toEntries converts an OSV record to per-affected-package Entries.
func (rec osvRecord) toEntries(source string) []Entry {
	id := strings.TrimSpace(rec.ID)
	summary := strings.TrimSpace(rec.Summary)
	if summary == "" {
		summary = firstLine(rec.Details)
	}
	baseCats := append([]string(nil), rec.Database.Categories...)
	baseCats = append(baseCats, rec.Database.MalwareCategories...)

	var out []Entry
	for _, aff := range rec.Affected {
		name := strings.TrimSpace(aff.Package.Name)
		eco := strings.TrimSpace(aff.Package.Ecosystem)
		if name == "" || eco == "" {
			// Fall back to the purl when the package block is sparse.
			if e, ok := splitPURL(aff.Package.PURL); ok {
				if name == "" {
					name = e.name
				}
				if eco == "" {
					eco = e.ecosystem
				}
			}
		}
		if name == "" || eco == "" {
			continue
		}

		e := Entry{
			ID:         id,
			Ecosystem:  eco,
			Name:       name,
			Aliases:    rec.Aliases,
			Summary:    summary,
			Categories: append(append([]string(nil), baseCats...), aff.Database.Categories...),
			Versions:   dedupeStrings(aff.Versions),
			Source:     source,
			Published:  strings.TrimSpace(rec.Published),
		}
		for _, r := range aff.Ranges {
			e.Ranges = append(e.Ranges, convertRange(r)...)
		}
		// The malicious-packages convention: the whole package is malicious when
		// the affected block names neither explicit versions nor a bounded range.
		if len(e.Versions) == 0 && !hasBoundedRange(e.Ranges) {
			e.AllVersions = true
			e.Ranges = nil
		}
		out = append(out, e)
	}
	return out
}

// convertRange turns an OSV range's event list into VersionRanges. OSV events
// are ordered along a number line: each "introduced" opens an interval that the
// next "fixed"/"last_affected" closes. A bare "introduced: 0" with no closing
// event denotes the entire version history.
func convertRange(r osvRange) []VersionRange {
	var out []VersionRange
	var cur *VersionRange
	for _, ev := range r.Events {
		switch {
		case ev.Introduced != "":
			if cur != nil {
				out = append(out, *cur)
			}
			cur = &VersionRange{Introduced: ev.Introduced}
		case ev.Fixed != "":
			if cur == nil {
				cur = &VersionRange{}
			}
			cur.Fixed = ev.Fixed
			out = append(out, *cur)
			cur = nil
		case ev.LastAffected != "":
			if cur == nil {
				cur = &VersionRange{}
			}
			cur.LastAffected = ev.LastAffected
			out = append(out, *cur)
			cur = nil
		}
	}
	if cur != nil {
		out = append(out, *cur)
	}
	return out
}

// hasBoundedRange reports whether any range constrains the affected set (i.e. it
// is not the "introduced: 0, no upper bound" whole-history sentinel).
func hasBoundedRange(ranges []VersionRange) bool {
	for _, r := range ranges {
		intro := normalizeVersion(r.Introduced)
		if (intro != "" && intro != "0") || normalizeVersion(r.Fixed) != "" || normalizeVersion(r.LastAffected) != "" {
			return true
		}
	}
	return false
}

// purlParts holds an ecosystem/name pair recovered from a Package URL.
type purlParts struct {
	ecosystem string
	name      string
}

// splitPURL recovers an (ecosystem, name) pair from a minimal Package URL of the
// form "pkg:TYPE/NAME@VERSION". Only the type and name are needed; the version
// (if present) is dropped. It tolerates namespaced names (pkg:npm/@scope/name,
// pkg:maven/group/artifact).
func splitPURL(purl string) (purlParts, bool) {
	purl = strings.TrimSpace(purl)
	if !strings.HasPrefix(purl, "pkg:") {
		return purlParts{}, false
	}
	rest := strings.TrimPrefix(purl, "pkg:")
	if i := strings.IndexByte(rest, '?'); i >= 0 {
		rest = rest[:i]
	}
	if i := strings.IndexByte(rest, '@'); i >= 0 {
		rest = rest[:i]
	}
	slash := strings.IndexByte(rest, '/')
	if slash <= 0 || slash == len(rest)-1 {
		return purlParts{}, false
	}
	typ := rest[:slash]
	name := rest[slash+1:]
	// Maven separates group/artifact with '/': fold to the canonical "group:artifact".
	if CanonicalEcosystem(typ) == "maven" {
		name = strings.ReplaceAll(name, "/", ":")
	}
	return purlParts{ecosystem: typ, name: name}, name != ""
}

// firstLine returns the first non-empty line of s, trimmed, for a compact
// summary when the record has only a details body.
func firstLine(s string) string {
	for _, line := range strings.Split(s, "\n") {
		if t := strings.TrimSpace(line); t != "" {
			return t
		}
	}
	return ""
}
