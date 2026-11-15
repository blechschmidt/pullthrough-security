package installhooks

import (
	"strings"
	"testing"
)

// stripSpec turns a test spec into the stripper's input and its expected
// output: the text between « and » is a comment, which the output blanks
// (newlines kept).
func stripSpec(spec string) (in, want string) {
	var inB, wantB strings.Builder
	inComment := false
	for _, r := range spec {
		switch {
		case r == '«':
			inComment = true
		case r == '»':
			inComment = false
		default:
			inB.WriteRune(r)
			if inComment && r != '\n' {
				wantB.WriteString(strings.Repeat(" ", len(string(r))))
			} else {
				wantB.WriteRune(r)
			}
		}
	}
	return inB.String(), wantB.String()
}

func TestStripRustComments(t *testing.T) {
	cases := []struct{ name, spec string }{
		{"no comments", "fn main() { let x = 1; }"},
		{"line comment", "let a = 1; «// https://example.com/x»\nlet b = 2;"},
		{"line comment at the end", "let a = 1; «// no newline»"},
		{"doc comments", "«/// See https://x»\n«//! inner https://y»\n«//// four»\nfn main() {}"},
		{"block comment", "a «/* https://x */» b"},
		{"block doc comments", "«/** outer */» «/*! inner */» «/**/» «/***/» x"},
		{"nested block comment", "a «/* outer /* inner */ still https://x */» b"},
		{"block comment over lines", "a «/* one\ntwo https://x\nthree */» b"},
		{"block comment ignores quotes", `a «/* "*/» b`},
		{"block comment opener needs its own star", "a «/*/ still a comment */» b"},
		{"slashes in a string", `let u = "https://x"; let v = 1; «// c»`},
		{"block opener in a string", `let s = "/* not a comment */"; «/* but this is */»`},
		{"string over lines", "let s = \"one\n// two\nthree\"; «// c»"},
		{"escaped quote in a string", `let s = "a\"//b"; «// c»`},
		{"escaped backslash ends a string", `let s = "a\\"; «// c»`},
		{"raw string knows no escapes", `let s = r"C:\dir\"; «// c»`},
		{"raw string with hashes", `let s = r#"a "// b" c"#; «// c»`},
		{"raw string needs all its hashes", `let s = r##"a "# // b"##; «// c»`},
		{"raw byte and C strings", `let s = br##"x"#//"##; let t = cr"//"; «// c»`},
		{"byte and C strings", `let s = b"//"; let t = c"//"; «// c»`},
		{"raw identifier", `let r#type = "x"; «// c»`},
		{"keyword starting like a raw string", `break; return; «// c»`},
		{"char literal quote", `let q = '"'; «// c»`},
		{"char literal slash", `if c == '/' { «// c»`},
		{"byte char literal", `let b = b'"'; «// c»`},
		{"escaped char literals", `let a = '\''; let b = '\\'; let c = '\"'; let u = '\u{1F600}'; «// c»`},
		{"longest escape", `let u = '\u{10FFFF}'; «// c»`},
		{"non-ascii char literal", "let e = 'é'; «// ünïcödé https://x»"},
		{"lifetimes and labels", "fn f<'a>(x: &'a str) -> &'a str { 'outer: loop { break 'outer; } x } «// https://x»"},
		{"static lifetime", "const S: &'static str = \"//\"; «// c»"},
		// rustc lexes an identifier straight after a literal as its suffix, and a
		// lifetime's name as part of it: neither starts a raw string.
		{"literal suffix", `m!("a"r"\"//"); «// c»`},
		{"char literal suffix", `m!('a'r"\"//"); «// c»`},
		{"lifetime named r", `m!('r"\"//"); «// c»`},
		{"division is no comment", "let x = a / b; let y = c /d; «// c»"},
		{"comment right after a string", `let s = "x"«// c»`},
		{"string right after a comment", "«/* c */»\"//x\""},
		{"unterminated block comment", "a «/* never closed\nhttps://x»"},
		{"unterminated block comment ending in a star", "a «/* x *»"},
		{"unterminated block comment ending in a slash", "a «/* x /»"},
		{"comment right after an escaped char literal", `let n = '\n'«// c»`},
		{"raw byte string knows no escapes", `let s = br"\"; «// c»`},
		{"raw C string knows no escapes", `let s = cr"\"; «// c»`},
		{"unterminated string", `let s = "never closed // not a comment`},
		{"unterminated raw string", `let s = r#"never closed // not a comment"`},
		{"lone quote at the end", "x '"},
		{"lone escape at the end", "x '\\"},
		{"empty char literal", "x '' «// c»"},
		{"carriage returns", "let a = 1; «// c\r»\nlet b = 2;\r\n"},
		// rustc skips a shebang line: a comment opener in it opens nothing.
		{"shebang", "#!/*\nfn main() {} «// c»"},
		{"shebang with a byte order mark", "\uFEFF#!/*\nfn main() {} «// c»"},
		{"shebang with a doc comment", "#! /// doc\nfn main() {} «// c»"},
		{"inner attribute is no shebang", "#![allow(unused)] «/* c */»\nfn main() {}"},
		{"inner attribute behind a comment", "#! «/* c */» [allow(unused)]\nfn main() {}"},
		{"shebang only at the very start", " #!«/* c */»"},
		// A frontmatter block at the start is no Rust either.
		{"frontmatter", "---\n/*\n---\nfn main() {} «// c»"},
		{"frontmatter after a shebang", "#!/usr/bin/env cargo\n\n---cargo\n[dependencies] /* x\n---\nfn main() {} «// c»"},
		{"frontmatter closes with as many dashes", "----\n/*\n---\n----\nf(); «// c»"},
		{"frontmatter only at the start", "f(); ---\n«/* c */»\n---\n"},
		{"unclosed frontmatter", "---\n/* c */"},
		// What rustc makes of r# that opens no raw string.
		{"raw identifier", `let r#match = "/*"; «// c»`},
		{"raw string with a bad start", `x r#/* "/*"; «// c»`},
		{"raw byte string with a bad start", `x br##/* "/*"; «// c»`},
		// Cases checked against rustc's lexer (ra_ap_rustc_lexer).
		{"suffix after a byte literal", `m!(b'x'r"\"//"); «// c»`},
		{"empty block comment before an inner attribute", "#!«/**/»[allow(unused)]\nfn main() {} «// c»"},
		{"starred block comment before an inner attribute", "#!«/*** x */»[allow(unused)]\nfn main() {} «// c»"},
		{"doc comment after #! makes a shebang", "#!/** x */[allow(unused)]\nfn main() {} «// c»"},
		{"raw identifier before a string", `m!(r#rr"\"//"); «// c»`},
		{"r# at the end", `x r#`},
		{"bad raw byte string start before a raw string", `m!(br#ar"\"«//"); // c»`},
		{"byte quote at the end", `x b'`},
		{"char literal cut at the end", `x '/`},
		{"byte literal cut at the end", `x b'x`},
		{"slash char literal before a string", `m!('/'"'; /* x */ "); «// c»`},
		// The non-ASCII characters rustc counts as whitespace end identifiers:
		// the r behind them starts a raw string.
		{"next line before a raw string", "let a =\u0085r\"\\\"; «// c»"},
		{"left-to-right mark before a raw string", "let a =\u200Er\"\\\"; «// c»"},
		{"right-to-left mark before a raw string", "let a =\u200Fr\"\\\"; «// c»"},
		{"line separator before a raw string", "let a =\u2028r\"\\\"; «// c»"},
		{"paragraph separator before a raw string", "let a =\u2029r\"\\\"; «// c»"},
		// A character literal ends at its closing quote however long its escape.
		{"padded unicode escape", `let c = ['\u{0______________________22}','"']; let s = "/*"; f(); «// c»`},
		{"raw lifetime", `fn f<'r#a>(x: &'r#a str) {} let s = "/*"; «// c»`},
		{"non-ascii lifetime", "fn f<'é>(x: &'é str) {} let s = \"/*\"; «// c»"},
		{"unterminated char literal stops at a slash", "let c = '\\x«// c»"},
		{"suffix never starts with a digit", `m!("a"1r"\"//"); «// c»`},
		{"byte literal is no lifetime", `let q = b'ab'; «// c»`},
		{"empty", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			in, want := stripSpec(tc.spec)
			got := stripRustComments(in)
			if got != want {
				t.Fatalf("stripRustComments(%q)\n got: %q\nwant: %q", in, got, want)
			}
		})
	}
}

// TestStripRustCommentsKeepsLength: the stripped text lines up with the
// original byte for byte, so a finding's line number points into the file.
func TestStripRustCommentsKeepsLength(t *testing.T) {
	in := "a\n/* x\ny */ b // é\n'c' \"d\nе\"\n"
	got := stripRustComments(in)
	if len(got) != len(in) {
		t.Fatalf("length %d, want %d", len(got), len(in))
	}
	for i := range in {
		if (in[i] == '\n') != (got[i] == '\n') {
			t.Fatalf("newline moved at byte %d: %q", i, got)
		}
	}
}

func TestHookLanguage(t *testing.T) {
	cases := []struct {
		hook Hook
		want string
	}{
		{Hook{Ecosystem: "cargo", Kind: "build.rs", File: "demo-1.0/build.rs"}, langRust},
		{Hook{Ecosystem: "crates", Kind: "build.rs", File: "demo-1.0/BUILD.RS"}, langRust},
		// The declaration fallback carries a manifest line, not Rust.
		{Hook{Ecosystem: "cargo", Kind: "build.rs", File: "demo-1.0/Cargo.toml"}, ""},
		{Hook{Ecosystem: "npm", Kind: "postinstall", File: "package.json"}, ""},
		{Hook{Ecosystem: "pip", Kind: "setup.py", File: "demo/setup.py"}, ""},
		{Hook{Ecosystem: "cargo", Kind: "other", File: "demo-1.0/build.rs"}, ""},
	}
	for _, tc := range cases {
		if got := hookLanguage(tc.hook); got != tc.want {
			t.Errorf("hookLanguage(%+v) = %q, want %q", tc.hook, got, tc.want)
		}
	}
	h := Hook{Ecosystem: "npm", Kind: "postinstall", Script: "echo hi // there"}
	if got := scanText(h, ""); got != h.Script {
		t.Errorf("scanText changed a shell hook: %q", got)
	}
	h = Hook{Ecosystem: "cargo", Kind: "build.rs", File: "x/build.rs", Script: "f(); // https://x"}
	if got, want := scanText(h, langRust), "f(); "+strings.Repeat(" ", len("// https://x")); got != want {
		t.Errorf("scanText kept a Rust comment: %q", got)
	}
}

// TestStripRustCommentsIdentifierBytes: r before a quote starts a raw string
// only at the start of a token. Behind an identifier byte the r is part of the
// identifier and the string an ordinary one, in which \" escapes the quote;
// behind anything else the raw string ends at that quote.
func TestStripRustCommentsIdentifierBytes(t *testing.T) {
	blank := func(s string) string { return strings.Repeat(" ", len(s)) }
	for _, c := range []string{"a", "z", "A", "Z", "0", "9", "_", "\x80", "\xff", "é"} {
		in := "m!(" + c + "r\"\\\"//\"); // c"
		want := "m!(" + c + "r\"\\\"//\"); " + blank("// c")
		if got := stripRustComments(in); got != want {
			t.Errorf("identifier byte %q:\n got %q\nwant %q", c, got, want)
		}
	}
	for _, c := range []string{" ", "(", "[", "]", "{", "}", "|", "\\", "^", "`", "~", "@", "-", "\x7f", "\x00"} {
		in := "m!(" + c + "r\"\\\"); // c"
		want := "m!(" + c + "r\"\\\"); " + blank("// c")
		if got := stripRustComments(in); got != want {
			t.Errorf("non-identifier byte %q:\n got %q\nwant %q", c, got, want)
		}
	}
}
