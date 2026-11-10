package main

import (
	"encoding/json"
	"io"
)

// writeJSONIndented encodes v as indented JSON to w without HTML-escaping, the
// shared rendering for raw-document output (SARIF, DSSE envelopes).
func writeJSONIndented(w io.Writer, v any) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	return enc.Encode(v)
}
