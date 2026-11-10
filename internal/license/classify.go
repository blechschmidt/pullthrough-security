package license

import "strings"

// Category buckets SPDX licenses by their copyleft/obligation strength so an
// operator can express policy in families ("deny all strong copyleft") rather
// than enumerating every identifier. The categories are referenced from policy
// entries with an "@" prefix (e.g. "@strong-copyleft").
type Category string

const (
	// CategoryPermissive covers licenses with minimal obligations beyond
	// attribution (MIT, Apache-2.0, BSD, ISC, ...).
	CategoryPermissive Category = "permissive"
	// CategoryWeakCopyleft covers file-/library-scoped copyleft (LGPL, MPL, EPL,
	// CDDL, ...): obligations attach to the licensed files, not the whole work.
	CategoryWeakCopyleft Category = "weak-copyleft"
	// CategoryStrongCopyleft covers whole-work copyleft distributed as software
	// (the GPL family).
	CategoryStrongCopyleft Category = "strong-copyleft"
	// CategoryNetworkCopyleft covers copyleft whose trigger includes network use
	// (the AGPL family) — the highest-risk family for SaaS/proprietary tenants.
	CategoryNetworkCopyleft Category = "network-copyleft"
	// CategoryPublicDomain covers public-domain dedications / equivalents.
	CategoryPublicDomain Category = "public-domain"
	// CategoryProprietary covers commercial / proprietary identifiers.
	CategoryProprietary Category = "proprietary"
	// CategoryUnknown is returned for identifiers absent from the built-in catalog.
	CategoryUnknown Category = "unknown"
)

// catalogEntry is a catalog record: the canonical-case SPDX id and its category.
type catalogEntry struct {
	id  string
	cat Category
}

// licenseCatalog maps a lower-cased SPDX identifier to its canonical form and
// category. It is intentionally a curated subset covering the licenses that
// dominate package-ecosystem metadata; an identifier absent here classifies as
// CategoryUnknown (and the policy's unknown disposition applies). Deprecated
// short forms (e.g. "GPL-3.0") are included alongside their current "-only" /
// "-or-later" replacements so real-world manifests classify correctly.
var licenseCatalog = buildCatalog(map[Category][]string{
	CategoryPermissive: {
		"MIT", "MIT-0", "X11", "ISC", "0BSD", "BSD-1-Clause",
		"BSD-2-Clause", "BSD-3-Clause", "BSD-3-Clause-Clear", "BSD-4-Clause",
		"Apache-1.1", "Apache-2.0", "Zlib", "libpng-2.0", "BSL-1.0",
		"PostgreSQL", "Python-2.0", "Python-2.0.1", "PSF-2.0", "Ruby",
		"Unicode-DFS-2016", "NCSA", "WTFPL", "Beerware",
	},
	CategoryWeakCopyleft: {
		"LGPL-2.0-only", "LGPL-2.0-or-later", "LGPL-2.0",
		"LGPL-2.1-only", "LGPL-2.1-or-later", "LGPL-2.1",
		"LGPL-3.0-only", "LGPL-3.0-or-later", "LGPL-3.0",
		"MPL-1.0", "MPL-1.1", "MPL-2.0", "MPL-2.0-no-copyleft-exception",
		"EPL-1.0", "EPL-2.0", "CDDL-1.0", "CDDL-1.1",
		"EUPL-1.1", "EUPL-1.2", "Artistic-1.0", "Artistic-2.0",
		"OSL-1.0", "OSL-2.0", "OSL-2.1", "OSL-3.0", "CC-BY-4.0", "CC-BY-3.0",
	},
	CategoryStrongCopyleft: {
		"GPL-1.0-only", "GPL-1.0-or-later", "GPL-1.0",
		"GPL-2.0-only", "GPL-2.0-or-later", "GPL-2.0",
		"GPL-3.0-only", "GPL-3.0-or-later", "GPL-3.0",
		"CC-BY-SA-4.0", "CC-BY-SA-3.0", "GFDL-1.3-only", "GFDL-1.3-or-later",
	},
	CategoryNetworkCopyleft: {
		"AGPL-1.0-only", "AGPL-1.0-or-later", "AGPL-1.0",
		"AGPL-3.0-only", "AGPL-3.0-or-later", "AGPL-3.0",
	},
	CategoryPublicDomain: {
		"CC0-1.0", "Unlicense", "0BSD-1.0",
	},
	CategoryProprietary: {
		"LicenseRef-Proprietary", "Commercial", "Nonstandard",
	},
})

// buildCatalog flattens a category->ids map into the lookup table keyed by
// lower-cased id. The first category an id appears under wins (the input is
// already partitioned, so collisions do not occur in practice).
func buildCatalog(byCat map[Category][]string) map[string]catalogEntry {
	out := make(map[string]catalogEntry)
	for cat, ids := range byCat {
		for _, id := range ids {
			key := strings.ToLower(id)
			if _, exists := out[key]; exists {
				continue
			}
			out[key] = catalogEntry{id: id, cat: cat}
		}
	}
	return out
}

// Classify returns the category of an SPDX license id and whether it is known to
// the built-in catalog. The "+" suffix is not significant to classification and
// must already be stripped by the caller (the parser does this). A custom
// LicenseRef-* identifier is reported as unknown (recognized=false) so the
// policy's unknown disposition governs it unless explicitly listed.
func Classify(id string) (Category, bool) {
	if e, ok := licenseCatalog[strings.ToLower(strings.TrimSpace(id))]; ok {
		return e.cat, true
	}
	return CategoryUnknown, false
}

// CanonicalID returns the catalog's canonical-case spelling of an id, or the
// trimmed input unchanged when the id is not in the catalog.
func CanonicalID(id string) string {
	id = strings.TrimSpace(id)
	if e, ok := licenseCatalog[strings.ToLower(id)]; ok {
		return e.id
	}
	return id
}

// categoryExpansions maps a policy "@" family keyword to the concrete categories
// it covers. "@copyleft" is a convenience union of every copyleft family.
var categoryExpansions = map[string][]Category{
	"@permissive":       {CategoryPermissive},
	"@weak-copyleft":    {CategoryWeakCopyleft},
	"@strong-copyleft":  {CategoryStrongCopyleft},
	"@network-copyleft": {CategoryNetworkCopyleft},
	"@public-domain":    {CategoryPublicDomain},
	"@proprietary":      {CategoryProprietary},
	"@unknown":          {CategoryUnknown},
	"@copyleft":         {CategoryWeakCopyleft, CategoryStrongCopyleft, CategoryNetworkCopyleft},
}

// categoryKeyword resolves a policy "@family" keyword to its categories, or
// (nil, false) when the token is not a recognized family keyword.
func categoryKeyword(token string) ([]Category, bool) {
	cats, ok := categoryExpansions[strings.ToLower(strings.TrimSpace(token))]
	return cats, ok
}
