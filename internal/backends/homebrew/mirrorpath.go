package homebrew

// This file exports the backend's own request path for the full-mirror feed
// adapter (internal/fullmirror, Task 190), which reads a formula's metadata
// through the proxy and takes the bottles' paths from the URLs this backend
// rewrote in it.

// FormulaDocumentPath is one formula's JSON document,
// "/api/formula/<name>.json": the document the backend serves with its
// bottle URLs rewritten to the synthetic "/bottle/{name}/{version}/v2/…"
// endpoint. ok is false for a name the backend would not classify as that
// formula's document (an empty name, one with a character outside the plain
// formula alphabet or not starting with a letter or digit, one ending in
// ".jws" whose path would name the signed index form instead).
func FormulaDocumentPath(name string) (string, bool) {
	if !isPlainSegment(name) || !isFormulaStart(name[0]) {
		return "", false
	}
	p := "/api/formula/" + name + ".json"
	res, ok := classify(p)
	if !ok || res.kind != kindFormula || res.name != name || !res.jsonDocument {
		return "", false
	}
	return p, true
}

// isFormulaStart reports whether c may begin a formula name: an ASCII letter
// or digit.
func isFormulaStart(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9'
}
