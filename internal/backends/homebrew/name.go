package homebrew

import "strings"

// A bottle's OCI repository is "{org}/{tap}/{image}": the tap's GitHub Packages
// namespace followed by the formula's image name. brew derives the image name
// from the formula name with GitHubPackages.image_formula_name, which replaces
// the two characters a container name cannot carry:
//
//	formula_name.tr("@", "/").tr("+", "x")
//
// so "openssl@3" lives at "homebrew/core/openssl/3", "python@3.12" at
// "homebrew/core/python/3.12", and "gtk+3" at "homebrew/core/gtkx3".
//
// The admission gates key on the formula name an operator knows ("openssl@3",
// "gtk+3"), so the backend maps a repository back to it. "/" -> "@" inverts
// exactly (a formula name never contains "/", and has at most one "@"). The
// "+" -> "x" step is lossy — "gtkx3" could be "gtkx3" or "gtk+3" — so the path
// alone yields the image spelling, and the true name is taken from upstream
// metadata when available: the image index's title annotation, or the formula
// JSON document. A name taken from metadata is accepted only if brew's forward
// mapping turns it back into the repository's image name, so metadata can
// disambiguate the spelling but never substitute a different formula for the
// repository the request actually names.

// coreTap is the bottle-registry namespace of Homebrew's core tap, whose
// formulae brew addresses by bare name and whose metadata formulae.brew.sh
// serves. A formula from any other tap is addressed tap-qualified
// ("{org}/{tap}/{name}"), which keeps a third-party tap's "wget" distinct from
// core's in every name-keyed gate.
const coreTap = "homebrew/core"

// maxPlusCandidates bounds how many trailing "x" characters are tried as "+"
// when asking the formula API about an image name (see formulaNameCandidates).
const maxPlusCandidates = 3

// imageFormulaName mirrors brew's GitHubPackages.image_formula_name: the image
// name a formula's bottles are stored under.
func imageFormulaName(name string) string {
	return strings.NewReplacer("@", "/", "+", "x").Replace(name)
}

// splitRepo splits a validated bottle repository "{org}/{tap}/{image...}" into
// its tap namespace ("{org}/{tap}") and image name. A repository with fewer than
// three segments has no image and yields an empty one.
func splitRepo(repo string) (tap, image string) {
	segs := strings.SplitN(repo, "/", 3)
	if len(segs) < 3 {
		return repo, ""
	}
	return segs[0] + "/" + segs[1], segs[2]
}

// qualifyFormula renders a formula name as brew addresses it: bare for the core
// tap, "{org}/{tap}/{name}" otherwise.
func qualifyFormula(tap, formula string) string {
	if tap == coreTap {
		return formula
	}
	return tap + "/" + formula
}

// pathFormulaName derives a formula name from the repository path alone: the
// image name with "/" mapped back to "@". It is deterministic and needs no
// upstream data, which makes it the name of last resort; it differs from the
// true formula name only for the few formulae spelled with "+".
func pathFormulaName(tap, image string) string {
	return qualifyFormula(tap, strings.ReplaceAll(image, "/", "@"))
}

// formulaNameFromTitle validates the formula name an OCI document's
// "org.opencontainers.image.title" annotation carries against the repository it
// was fetched from, returning the gate-facing name. brew sets the title to the
// formula's full name on an image index ("hello", "openssl@3", "gtk+3", or
// "{org}/{tap}/{name}" for a non-core tap) and to "{full name} {tag}" on a
// per-platform image manifest.
func formulaNameFromTitle(tap, image, title string) (string, bool) {
	title = strings.TrimSpace(title)
	if i := strings.IndexByte(title, ' '); i >= 0 {
		title = title[:i]
	}
	bare := title
	if i := strings.LastIndexByte(title, '/'); i >= 0 {
		// A tap-qualified title must name the tap the repository belongs to (brew
		// lowercases the organisation in the registry path, so compare loosely).
		if !strings.EqualFold(title[:i], tap) {
			return "", false
		}
		bare = title[i+1:]
	}
	if bare == "" || imageFormulaName(bare) != image {
		return "", false
	}
	return qualifyFormula(tap, bare), true
}

// formulaNameCandidates lists the formula names an image name may stand for, in
// the order they are tried against the formula API: the direct "/" -> "@"
// mapping first, then variants with the last one, two and three "x" characters
// read as "+". Every "+"-spelled formula in homebrew-core has a single "+" or a
// trailing "++" ("gtk+3", "dvd+rw-tools", "libsigc++@2", "libxml++"), which
// these suffix runs cover; the list is bounded so an arbitrary image name costs
// at most 1+maxPlusCandidates lookups.
func formulaNameCandidates(image string) []string {
	base := []byte(strings.ReplaceAll(image, "/", "@"))
	out := []string{string(base)}
	replaced := 0
	for i := len(base) - 1; i >= 0 && replaced < maxPlusCandidates; i-- {
		if base[i] != 'x' {
			continue
		}
		base[i] = '+'
		replaced++
		out = append(out, string(base))
	}
	return out
}
