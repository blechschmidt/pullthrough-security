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
