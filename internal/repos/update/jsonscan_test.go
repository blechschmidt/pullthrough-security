package update

import (
	"encoding/json"
	"strings"
	"testing"
)

// bs is a backslash, for JSON escapes spelled out in the cases.
const bs = "\\"

// jsonScannerCases are documents at the edges of the JSON grammar.
var jsonScannerCases = []string{
	`{}`, `[]`, `""`, `0`, `-0`, `-0.5e+10`, `1E5`, `1e-0`, `true`, `false`, `null`, " \t\r\n{} \n",
	`{"a":[1,{"b":null}],"c":"d"}`, `[[[[]]]]`, `"` + bs + `"` + bs + bs + bs + `/` + bs + `b` + bs + `f` + bs + `n` + bs + `r` + bs + `t"`,
	`"` + bs + `u00e9` + bs + `uD83D` + bs + `uDE00"`, "\"\xff\xfe\"", "\"\x7f\"", `{"a":1,"a":2}`,
	// Not JSON.
	``, ` `, `{`, `}`, `[1,]`, `{"a":1,}`, `{"a" 1}`, `{"a":1 "b":2}`, `{a:1}`, `[1 2]`, `01`, `-`, `1.`, `.5`, `1e`, `1e+`,
	`+1`, `tru`, `nul`, `nullx`, `truefalse`, `"abc`, `"` + bs + `x"`, `"` + bs + `u12"`, `"` + bs + `u12G4"`, "\"a\nb\"", "\"\x00\"",
	`{}{}`, `{} x`, `[}`, `{]`, `{"a":}`, `{,}`, `[,]`, "\xef\xbb\xbf{}", "0\x00", "{}\x00", "\x00",
}

// TestJSONScannerAgreesWithEncodingJSON: the scanner accepts exactly what
// encoding/json accepts, and reads strings as it decodes them.
func TestJSONScannerAgreesWithEncodingJSON(t *testing.T) {
	for _, c := range jsonScannerCases {
		s := &jsonScanner{data: []byte(c)}
		err := s.skip()
		if err == nil {
			err = s.end()
		}
		if ok := err == nil; ok != json.Valid([]byte(c)) {
			t.Errorf("%q: the scanner says %v (%v), encoding/json %v", c, ok, err, !ok)
		}
	}
	deep := strings.Repeat("[", maxJSONNesting) + strings.Repeat("]", maxJSONNesting)
	for _, c := range []string{deep, "[" + deep + "]"} {
		s := &jsonScanner{data: []byte(c)}
		if ok := s.skip() == nil; ok != json.Valid([]byte(c)) {
			t.Errorf("nesting %d: the scanner says %v", strings.Count(c, "["), ok)
		}
	}
	for _, c := range []string{`"plain"`, `"` + bs + `u00e9t` + bs + `u00e9"`, "\"\xff\"", `"a` + bs + `/b"`, `"` + bs + `uD800"`} {
		s := &jsonScanner{data: []byte(c)}
		sp, err := s.str()
		if err != nil {
			t.Fatalf("%q: %v", c, err)
		}
		got, err := s.text(sp)
		var want string
		if err != nil || json.Unmarshal([]byte(c), &want) != nil || got != want {
			t.Errorf("%q: read %q (%v), encoding/json %q", c, got, err, want)
		}
	}
	for _, v := range []string{"1.2.3", "https://r.example/a/-/a-1.0.0.tgz", "a\"b\\c\nd\x01é\u2028"} {
		var back string
		if err := json.Unmarshal([]byte(jsonString(v)), &back); err != nil || back != v {
			t.Errorf("jsonString(%q) = %s, reads back as %q (%v)", v, jsonString(v), back, err)
		}
	}
	if got := jsonString("a/b<c>&\u2028"); got != `"a/b<c>&`+"\u2028"+`"` {
		t.Errorf("jsonString escapes what JSON.stringify does not: %s", got)
	}
}
