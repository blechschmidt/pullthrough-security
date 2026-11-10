package vulnscan

import (
	"encoding/json"
	"strings"
)

// npmLicenseExpression derives an SPDX license expression from an npm
// package.json's "license" and/or legacy "licenses" fields. The modern "license"
// field is an SPDX expression string (e.g. "MIT" or "(MIT OR Apache-2.0)"); the
// deprecated object form ({"type": "...", "url": "..."}) and the legacy
// "licenses" array (of strings or {type} objects) are also handled. Multiple
// legacy entries are combined with OR (their historical "choose one" meaning).
func npmLicenseExpression(license, licenses json.RawMessage) string {
	if expr := npmLicenseField(license); expr != "" {
		return expr
	}
	return npmLicensesField(licenses)
}

// npmLicenseField reads the singular "license" field (string or {type} object).
func npmLicenseField(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}
	var s string
	if json.Unmarshal(raw, &s) == nil {
		return strings.TrimSpace(s)
	}
	var obj struct {
		Type string `json:"type"`
	}
	if json.Unmarshal(raw, &obj) == nil {
		return strings.TrimSpace(obj.Type)
	}
	return ""
}

// npmLicensesField reads the legacy plural "licenses" array (of strings or
// {type} objects) and OR-joins the distinct entries.
func npmLicensesField(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}
	var arrStr []string
	if json.Unmarshal(raw, &arrStr) == nil && len(arrStr) > 0 {
		return joinLicensesOr(arrStr)
	}
	var arrObj []struct {
		Type string `json:"type"`
	}
	if json.Unmarshal(raw, &arrObj) == nil && len(arrObj) > 0 {
		types := make([]string, 0, len(arrObj))
		for _, o := range arrObj {
			types = append(types, o.Type)
		}
		return joinLicensesOr(types)
	}
	return ""
}

// joinLicensesOr trims, de-duplicates and OR-joins license tokens, parenthesizing
// only when more than one distinct token remains.
func joinLicensesOr(tokens []string) string {
	seen := make(map[string]bool)
	var out []string
	for _, t := range tokens {
		t = strings.TrimSpace(t)
		if t == "" || seen[strings.ToLower(t)] {
			continue
		}
		seen[strings.ToLower(t)] = true
		out = append(out, t)
	}
	switch len(out) {
	case 0:
		return ""
	case 1:
		return out[0]
	default:
		return strings.Join(out, " OR ")
	}
}

// extractPyPI derives the primary component's license from a Python distribution:
// a wheel (a zip carrying "<dist>.dist-info/METADATA") or an sdist (a gzip tar
// carrying "<dir>/PKG-INFO"). Both embed RFC822-style metadata from which the
// license is read.
func extractPyPI(sbom *SBOM, data []byte) {
	if sbom.Metadata == nil || sbom.Metadata.Component == nil {
		return
	}
	// Wheel: METADATA inside a *.dist-info directory.
	meta, ok := readZipFile(data, func(name string) bool {
		return strings.HasSuffix(name, ".dist-info/METADATA")
	})
	if !ok {
		// sdist: PKG-INFO at the archive root (one directory deep) or top-level.
		meta, ok = readTarGzFile(data, func(name string) bool {
			return name == "PKG-INFO" || (strings.HasSuffix(name, "/PKG-INFO") && strings.Count(name, "/") == 1)
		})
	}
	if !ok {
		return
	}
	if expr := pythonMetadataLicense(meta); expr != "" {
		setLicenseExpression(sbom.Metadata.Component, expr)
	}
}

// pythonMetadataLicense parses Python core-metadata (PEP 566 / PEP 639) headers
// and returns an SPDX-style license expression. Precedence: the explicit
// "License-Expression" (PEP 639) header, then mapped "License ::" trove
// classifiers, then the free-text "License" field (used only when it looks like a
// short identifier rather than embedded license text).
func pythonMetadataLicense(meta []byte) string {
	var licenseExpr, licenseField string
	var classifiers []string

	for _, raw := range strings.Split(string(meta), "\n") {
		line := strings.TrimRight(raw, "\r")
		// Headers end at the first blank line (the long description follows).
		if strings.TrimSpace(line) == "" {
			break
		}
		key, val, ok := strings.Cut(line, ":")
		if !ok {
			continue // continuation line of a folded header; not needed here
		}
		val = strings.TrimSpace(val)
		switch strings.ToLower(strings.TrimSpace(key)) {
		case "license-expression":
			if val != "" {
				licenseExpr = val
			}
		case "license":
			if val != "" {
				licenseField = val
			}
		case "classifier":
			if strings.HasPrefix(val, "License ::") {
				classifiers = append(classifiers, val)
			}
		}
	}

	if licenseExpr != "" {
		return licenseExpr
	}
	if expr := classifiersToSPDX(classifiers); expr != "" {
		return expr
	}
	// The free-text License field frequently holds a short id ("MIT", "BSD"); use
	// it only when it is a single short token, not embedded full license text.
	if licenseField != "" && len(licenseField) <= 40 && !strings.Contains(licenseField, "  ") {
		return licenseField
	}
	return ""
}

// pyClassifierSPDX maps the common Python trove "License ::" classifiers to SPDX
// identifiers. The mapping is intentionally curated to the classifiers that occur
// in practice; an unmapped classifier is ignored (leaving the license undeclared
// rather than guessed).
var pyClassifierSPDX = map[string]string{
	"License :: OSI Approved :: MIT License":                                             "MIT",
	"License :: OSI Approved :: MIT No Attribution License (MIT-0)":                      "MIT-0",
	"License :: OSI Approved :: Apache Software License":                                 "Apache-2.0",
	"License :: OSI Approved :: BSD License":                                             "BSD-3-Clause",
	"License :: OSI Approved :: ISC License (ISCL)":                                      "ISC",
	"License :: OSI Approved :: The Unlicense (Unlicense)":                               "Unlicense",
	"License :: OSI Approved :: Mozilla Public License 2.0 (MPL 2.0)":                    "MPL-2.0",
	"License :: OSI Approved :: Python Software Foundation License":                      "PSF-2.0",
	"License :: OSI Approved :: GNU General Public License v2 (GPLv2)":                   "GPL-2.0-only",
	"License :: OSI Approved :: GNU General Public License v2 or later (GPLv2+)":         "GPL-2.0-or-later",
	"License :: OSI Approved :: GNU General Public License v3 (GPLv3)":                   "GPL-3.0-only",
	"License :: OSI Approved :: GNU General Public License v3 or later (GPLv3+)":         "GPL-3.0-or-later",
	"License :: OSI Approved :: GNU Lesser General Public License v2 (LGPLv2)":           "LGPL-2.0-only",
	"License :: OSI Approved :: GNU Lesser General Public License v2 or later (LGPLv2+)": "LGPL-2.0-or-later",
	"License :: OSI Approved :: GNU Lesser General Public License v3 (LGPLv3)":           "LGPL-3.0-only",
	"License :: OSI Approved :: GNU Lesser General Public License v3 or later (LGPLv3+)": "LGPL-3.0-or-later",
	"License :: OSI Approved :: GNU Affero General Public License v3":                    "AGPL-3.0-only",
	"License :: OSI Approved :: GNU Affero General Public License v3 or later (AGPLv3+)": "AGPL-3.0-or-later",
}

// classifiersToSPDX maps recognized trove classifiers to SPDX ids and OR-joins
// the distinct results (multiple license classifiers historically denote a
// choice).
func classifiersToSPDX(classifiers []string) string {
	var ids []string
	for _, c := range classifiers {
		if id, ok := pyClassifierSPDX[strings.TrimSpace(c)]; ok {
			ids = append(ids, id)
		}
	}
	return joinLicensesOr(ids)
}
