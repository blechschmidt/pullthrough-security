package lockfiles

import "testing"

// TestNoParserEntriesHaveNoParsers: an upstream type with a parser must not
// keep its "why there is none" entry (coverage hides the reason of a type
// with parsers, so the stale entry would otherwise go unnoticed).
func TestNoParserEntriesHaveNoParsers(t *testing.T) {
	for typ := range noParser {
		if ps := DefaultRegistry().Parsers(typ); len(ps) > 0 {
			t.Errorf("%s has %d parsers and still a no-parser entry; delete it", typ, len(ps))
		}
	}
	for typ := range unparsedFormats {
		if len(DefaultRegistry().Parsers(typ)) == 0 {
			t.Errorf("%s lists unparsed formats but has no parser; say why in noParser", typ)
		}
	}
}
