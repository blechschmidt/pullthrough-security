package lockfiles

import (
	"strings"
	"testing"
)

func TestTOMLDocument(t *testing.T) {
	src := `# a comment
title = "x" # trailing
"quoted key" = 'literal \n'
dotted.key.path = 1_000
multi = """
first\
   second
  "quoted" ""
"""
lit = '''
raw \n
'''
escapes = "tab\tnl\nuni\u00e9\U0001F600"
nums = [ +1, -2, 0x1F, 0o7, 0b1, 3.14, -1e-3, inf, nan ]
when = 1979-05-27T07:32:00Z
local = 1979-05-27 07:32:00
date = 1979-05-27
time = 07:32:00.5
inline = { a = 1, b.c = "d", e = [1, [2, 3]] }
multi_inline = {
  a = 1,
  b = 2,
}

[table]
k = true

[[package]]
name = "first"

[package.source]
url = "https://example"

[[package]]
name = "second"
files = [
  {file = "a.whl", hash = "sha256:00"},  # comment inside
  {file = "b.tar.gz", hash = "sha256:11"},
]

[a.b.c]
x = 1
[a]
y = 2
`
	doc, err := parseTOML([]byte(src))
	if err != nil {
		t.Fatal(err)
	}
	if doc.str("title") != "x" || doc.str("quoted key") != `literal \n` {
		t.Errorf("strings: %q %q", doc.str("title"), doc.str("quoted key"))
	}
	if v := doc.table("dotted").table("key").get("path"); v == nil || v.kind != tkInteger || v.str != "1_000" {
		t.Errorf("dotted key: %+v", v)
	}
	// A line-ending backslash joins the lines without a space.
	if got := doc.str("multi"); got != "firstsecond\n  \"quoted\" \"\"\n" {
		t.Errorf("multi-line basic string = %q", got)
	}
	if got := doc.str("lit"); got != "raw \\n\n" {
		t.Errorf("multi-line literal string = %q", got)
	}
	if got := doc.str("escapes"); got != "tab\tnl\nuni\u00e9\U0001F600" {
		t.Errorf("escapes = %q", got)
	}
	if v := doc.get("nums"); v == nil || len(v.arr) != 9 {
		t.Errorf("numbers: %+v", v)
	}
	for _, k := range []string{"when", "local", "date", "time"} {
		if v := doc.get(k); v == nil || v.kind != tkDatetime {
			t.Errorf("%s is not a date-time: %+v", k, v)
		}
	}
	if doc.table("inline").table("b").str("c") != "d" || doc.table("multi_inline").get("b") == nil {
		t.Error("inline tables")
	}
	pkgs := doc.tables("package")
	if len(pkgs) != 2 || pkgs[0].str("name") != "first" || pkgs[0].table("source").str("url") != "https://example" {
		t.Fatalf("array of tables: %+v", pkgs)
	}
	headers := linesOf(src, "[[package]]")
	if pkgs[0].line != headers[0] || pkgs[1].line != headers[1] {
		t.Errorf("table lines %d, %d; want %v", pkgs[0].line, pkgs[1].line, headers)
	}
	files := pkgs[1].tables("files")
	if len(files) != 2 || files[1].str("hash") != "sha256:11" || files[1].line != linesOf(src, `{file = "b.tar.gz"`)[0] {
		t.Errorf("files %+v", files)
	}
	if doc.table("a").get("y") == nil || doc.table("a").table("b").table("c").get("x") == nil {
		t.Error("implicit table defined later")
	}
}

// linesOf returns the 1-based lines of src that contain s.
func linesOf(src, s string) []int {
	var out []int
	for i, line := range strings.Split(src, "\n") {
		if strings.Contains(line, s) {
			out = append(out, i+1)
		}
	}
	return out
}

func TestTOMLRejects(t *testing.T) {
	bad := map[string]string{
		"duplicate key":           "a = 1\na = 2\n",
		"table defined twice":     "[a]\n[a]\n",
		"table over a value":      "a = 1\n[a]\n",
		"array of tables clash":   "a = 1\n[[a]]\n",
		"inline table extended":   "a = {b = 1}\n[a.c]\n",
		"dotted then header":      "[f]\napple.color = 1\n[f.apple]\n",
		"unterminated string":     "a = \"x\n",
		"unterminated multi":      "a = \"\"\"x\n",
		"bad escape":              "a = \"\\q\"\n",
		"surrogate escape":        "a = \"\\uD800\"\n",
		"text after value":        "a = 1 b\n",
		"no value":                "a =\n",
		"leading zero":            "a = 01\n",
		"double underscore":       "a = 1__0\n",
		"unclosed array":          "a = [1, 2\n",
		"unclosed inline":         "a = {b = 1\n",
		"missing equals":          "a 1\n",
		"control char":            "a = \"\x01\"\n",
		"invalid UTF-8":           "a = \"\xff\"\n",
		"empty key":               " = 1\n",
		"bare word value":         "a = yes\n",
		"header not closed":       "[a\n",
		"multi-line key":          "\"\"\"a\"\"\" = 1\n",
		"array too deep":          "a = " + strings.Repeat("[", 100) + strings.Repeat("]", 100) + "\n",
		"inline too deep":         "a = " + strings.Repeat("{b=", 100) + "1" + strings.Repeat("}", 100) + "\n",
		"key with too many parts": strings.Repeat("a.", 100) + "a = 1\n",
	}
	for name, src := range bad {
		if _, err := parseTOML([]byte(src)); err == nil {
			t.Errorf("%s: accepted %q", name, src)
		}
	}
}

func TestTOMLErrorsNameTheLineNotTheText(t *testing.T) {
	_, err := parseTOML([]byte("ok = 1\nsecret = \"https://u:ptl1zzzz@x\" junk\n"))
	if err == nil || !strings.Contains(err.Error(), "line 2") || strings.Contains(err.Error(), "ptl1") {
		t.Fatalf("err = %v", err)
	}
}
