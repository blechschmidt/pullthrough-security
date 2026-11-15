package installhooks

import (
	"bytes"
	"strings"
	"unicode/utf8"
)

// langRust names the language of a Cargo build script. Most hooks are shell
// command lines, manifests or metadata, which the rules read as they are. A
// build script is a Rust program: its comments are not code, and some of the
// generic patterns misread ordinary Rust (a URL in a comment or an error
// message is not network egress; `.spawn()` runs a compiler probe as often as
// anything else). The rules therefore run over the program with its comments
// removed, and a rule may carry a pattern for Rust in place of its generic one.
const langRust = "rust"

// hookLanguage reports the programming language of a hook's text, or "" for
// text the rules read as it is.
func hookLanguage(h Hook) string {
	if canonEco(h.Ecosystem) == "cargo" && h.Kind == "build.rs" && strings.HasSuffix(strings.ToLower(h.File), ".rs") {
		return langRust
	}
	return ""
}

// scanText returns the text of a hook the rules run over: a Rust build script
// without its comments, anything else unchanged.
func scanText(h Hook, lang string) string {
	if lang == langRust {
		return stripRustComments(h.Script)
	}
	return h.Script
}

// stripRustComments blanks out the comments of Rust source — line comments,
// block comments (which nest) and doc comments — and keeps everything else,
// string and character literals included, byte for byte. A removed byte becomes
// a space and a newline stays a newline, so the result has the length and the
// line numbers of the input.
//
// The lexing follows rustc's lexer (rustc_lexer): it starts after a shebang
// line and a frontmatter block; a comment cannot start inside a string, raw
// string or character
// literal; a block comment ends at its matching "*/" whatever it contains; a
// quote starts a character literal or a lifetime by rustc's rule, and a
// character literal ends where rustc ends it; an identifier straight after a
// literal is that literal's suffix; and the non-ASCII characters rustc counts as
// whitespace end an identifier. Getting any of this wrong could hide code from
// the rules — a "//" or "/*" inside a literal must not swallow what follows —
// so the cases are rustc's own. Text that is not valid Rust is handled
// best-effort: rustc refuses it, so a build script made of it never runs.
func stripRustComments(src string) string {
	b := []byte(src)
	out := []byte(src)
	n := len(b)
	for i := rustFrontmatterEnd(b, rustShebangEnd(b)); i < n; {
		c := b[i]
		switch {
		case c == '/' && i+1 < n && b[i+1] == '/':
			end := rustLineCommentEnd(b, i)
			blankRange(out, i, end)
			i = end
		case c == '/' && i+1 < n && b[i+1] == '*':
			end := rustBlockCommentEnd(b, i)
			blankRange(out, i, end)
			i = end
		case c == '"':
			i = skipRustSuffix(b, skipRustString(b, i))
		case c == '\'':
			i = skipRustQuote(b, i)
		case c == 'b' && i+1 < n && b[i+1] == '\'':
			// A byte literal (b'x') is never a lifetime.
			end, terminated := rustSingleQuotedEnd(b, i+1)
			if terminated {
				end = skipRustSuffix(b, end)
			}
			i = end
		case rustIdentLen(b, i) > 0:
			if hashes, quote, ok := rustRawStringStart(b, i); ok {
				i = skipRustSuffix(b, skipRustRawString(b, quote, hashes))
				continue
			}
			if end, ok := rustRawPrefixEnd(b, i); ok {
				i = end
				continue
			}
			i = skipRustIdent(b, i)
		default:
			i += runeLen(b, i)
		}
	}
	return string(out)
}

// blankRange replaces out[from:to] with spaces, keeping newlines.
func blankRange(out []byte, from, to int) {
	for k := from; k < to; k++ {
		if out[k] != '\n' {
			out[k] = ' '
		}
	}
}

// rustShebangEnd returns where rustc starts to lex: past a leading byte order
// mark, and past the first line when it is a shebang. A first line starting
// with "#!" is one unless the next token, past whitespace and comments that are
// not doc comments, is "[" (then it is an inner attribute, #![...]). rustc
// ignores a shebang line, so a "/*" in it opens no comment.
func rustShebangEnd(b []byte) int {
	start := 0
	if bytes.HasPrefix(b, []byte("\uFEFF")) {
		start = len("\uFEFF")
	}
	if !bytes.HasPrefix(b[start:], []byte("#!")) {
		return start
	}
	n := len(b)
	j := start + 2
	for j < n {
		if w := rustWhitespaceLen(b, j); w > 0 {
			j += w
			continue
		}
		if b[j] == '/' && j+1 < n && b[j+1] == '/' && !rustDocLineComment(b, j) {
			j = rustLineCommentEnd(b, j)
			continue
		}
		if b[j] == '/' && j+1 < n && b[j+1] == '*' && !rustDocBlockComment(b, j) {
			j = rustBlockCommentEnd(b, j)
			continue
		}
		break
	}
	if j < n && b[j] == '[' {
		return start
	}
	if k := bytes.IndexByte(b[start:], '\n'); k >= 0 {
		return start + k
	}
	return n
}

// rustFrontmatterEnd returns where lexing continues past a frontmatter block
// starting at b[i] (after a shebang, and whitespace): a line of three or more
// dashes, up to the end of the next line that starts with as many dashes.
// rustc lexes it there (cargo-script's front matter; nightly compiles it with
// feature(frontmatter)), and its text is not Rust: a "/*" in it opens no
// comment. Without a closing fence rustc rejects the file; the rest of it is
// left as it is.
func rustFrontmatterEnd(b []byte, i int) int {
	n := len(b)
	j := i
	for j < n {
		w := rustWhitespaceLen(b, j)
		if w == 0 {
			break
		}
		j += w
	}
	k := j
	for k < n && b[k] == '-' {
		k++
	}
	if k-j < 3 {
		return i
	}
	fence := append([]byte{'\n'}, b[j:k]...)
	c := bytes.Index(b[k:], fence)
	if c < 0 {
		return n
	}
	end := k + c + len(fence)
	if e := bytes.IndexByte(b[end:], '\n'); e >= 0 {
		return end + e
	}
	return n
}

// rustDocLineComment reports whether the line comment at b[i] ("//") is a doc
// comment: "//!" or "///" but not "////".
func rustDocLineComment(b []byte, i int) bool {
	n := len(b)
	if i+2 >= n {
		return false
	}
	return b[i+2] == '!' || (b[i+2] == '/' && (i+3 >= n || b[i+3] != '/'))
}

// rustDocBlockComment reports whether the block comment at b[i] ("/*") is a doc
// comment: "/*!" or "/**" but not "/***" or "/**/".
func rustDocBlockComment(b []byte, i int) bool {
	n := len(b)
	if i+2 >= n {
		return false
	}
	return b[i+2] == '!' || (b[i+2] == '*' && (i+3 >= n || (b[i+3] != '*' && b[i+3] != '/')))
}

// rustLineCommentEnd returns the index of the newline ending the line comment
// at b[start] (or the end of the text).
func rustLineCommentEnd(b []byte, start int) int {
	if k := bytes.IndexByte(b[start:], '\n'); k >= 0 {
		return start + k
	}
	return len(b)
}

// rustBlockCommentEnd returns the index just past the block comment opening at
// b[start] ("/*"), counting nested "/*" … "*/" pairs. An unterminated comment
// runs to the end of the text.
func rustBlockCommentEnd(b []byte, start int) int {
	n := len(b)
	depth := 1
	j := start + 2
	for j < n {
		switch {
		case b[j] == '/' && j+1 < n && b[j+1] == '*':
			depth++
			j += 2
		case b[j] == '*' && j+1 < n && b[j+1] == '/':
			depth--
			j += 2
			if depth == 0 {
				return j
			}
		default:
			j++
		}
	}
	return n
}

// skipRustString returns the index just past the string literal opening at
// b[start] ('"'). A backslash escapes the byte after it.
func skipRustString(b []byte, start int) int {
	n := len(b)
	for j := start + 1; j < n; {
		switch b[j] {
		case '\\':
			j += 2
		case '"':
			return j + 1
		default:
			j++
		}
	}
	return n
}

// rustRawStringStart reports whether a raw string literal starts at b[i]: r,
// br or cr, then zero or more '#', then '"'. It returns the number of '#' and
// the index of the opening quote. The caller checks that b[i] starts a token.
func rustRawStringStart(b []byte, i int) (hashes, quote int, ok bool) {
	n := len(b)
	j := i
	if (b[j] == 'b' || b[j] == 'c') && j+1 < n && b[j+1] == 'r' {
		j++
	}
	if b[j] != 'r' {
		return 0, 0, false
	}
	j++
	first := j
	for j < n && b[j] == '#' {
		j++
	}
	if j < n && b[j] == '"' {
		return j - first, j, true
	}
	return 0, 0, false
}

// rustRawPrefixEnd handles r# (or br#, cr#) at a token start that does not
// open a raw string, as rustc does: r# and an identifier is a raw identifier;
// anything else after the hashes is consumed as the bad character of a raw
// string that rustc rejects. It reports false where none of this applies.
func rustRawPrefixEnd(b []byte, i int) (int, bool) {
	n := len(b)
	j := i
	if (b[j] == 'b' || b[j] == 'c') && j+1 < n && b[j+1] == 'r' {
		j++
	}
	if b[j] != 'r' || j+1 >= n || b[j+1] != '#' {
		return 0, false
	}
	if j == i && j+2 < n && rustIdentStartLen(b, j+2) > 0 {
		return skipRustIdent(b, j+2), true // r#name
	}
	k := j + 1
	for k < n && b[k] == '#' {
		k++
	}
	if k < n {
		k += runeLen(b, k)
	}
	return k, true
}

// skipRustRawString returns the index just past the raw string whose opening
// quote is b[quote]: it ends at the first '"' followed by as many '#' as opened
// it. A raw string knows no escapes.
func skipRustRawString(b []byte, quote, hashes int) int {
	n := len(b)
	for j := quote + 1; j < n; j++ {
		if b[j] != '"' {
			continue
		}
		k := j + 1
		for k < n && k-(j+1) < hashes && b[k] == '#' {
			k++
		}
		if k-(j+1) == hashes {
			return k
		}
	}
	return n
}

// skipRustQuote lexes what a single quote at b[start] begins, as rustc does: a
// lifetime or label ('a, 'static, 'r#raw) when the next character can start
// one and the one after it is not a quote, else a character literal ('x', '"',
// '/', '\n', '\u{…}' however long), which ends at its closing quote — or, never
// closed, before a slash or a line break, where rustc stops it too.
func skipRustQuote(b []byte, start int) int {
	n := len(b)
	j := start + 1
	if j >= n {
		return n
	}
	first, size := utf8.DecodeRune(b[j:])
	k := j + size
	second := rune(-1)
	if k < n {
		second, _ = utf8.DecodeRune(b[k:])
	}
	canBeLifetime := second != '\'' && (rustIdentStartLen(b, j) > 0 || ('0' <= first && first <= '9'))
	if !canBeLifetime {
		end, terminated := rustSingleQuotedEnd(b, start)
		if terminated {
			end = skipRustSuffix(b, end)
		}
		return end
	}
	if first == 'r' && second == '#' && k+1 < n && rustIdentStartLen(b, k+1) > 0 {
		return skipRustIdent(b, k+1) // a raw lifetime, 'r#name
	}
	// A lifetime, or with a closing quote a character literal of more than one
	// character (which rustc rejects).
	end := skipRustIdent(b, k)
	if end < n && b[end] == '\'' {
		return end + 1
	}
	return end
}

// rustSingleQuotedEnd scans the character (or byte) literal whose opening
// quote is b[quote], as rustc's single_quoted_string does. It returns the index
// just past the closing quote and true, or — the literal never closes — the
// index of the slash or line break (or the end of the text) where rustc stops,
// and false.
func rustSingleQuotedEnd(b []byte, quote int) (int, bool) {
	n := len(b)
	j := quote + 1
	if j < n && b[j] != '\\' {
		if _, size := utf8.DecodeRune(b[j:]); j+size < n && b[j+size] == '\'' {
			return j + size + 1, true
		}
	}
	for j < n {
		switch b[j] {
		case '\'':
			return j + 1, true
		case '/':
			return j, false
		case '\n':
			if j+1 < n && b[j+1] == '\'' {
				j++
				continue
			}
			return j, false
		case '\\':
			j++
			if j < n {
				j += runeLen(b, j)
			}
		default:
			j += runeLen(b, j)
		}
	}
	return n, false
}

// skipRustSuffix skips the suffix rustc reads straight after a literal
// ("x"suffix, 'c'u8): an identifier, never a raw string's start.
func skipRustSuffix(b []byte, i int) int {
	if i < len(b) && rustIdentStartLen(b, i) > 0 {
		return skipRustIdent(b, i)
	}
	return i
}

// skipRustIdent returns the index just past the identifier characters at b[i]
// (none: i itself).
func skipRustIdent(b []byte, i int) int {
	for i < len(b) {
		l := rustIdentLen(b, i)
		if l == 0 {
			break
		}
		i += l
	}
	return i
}

// rustIdentLen returns the length of the identifier character (letter, digit,
// "_", or a non-ASCII character that is not whitespace) at b[i], or 0 when
// there is none. Outside literals and comments, valid Rust has no other
// non-ASCII characters (rustc rejects the rest), so the exact Unicode
// identifier classes do not matter here; its whitespace does.
func rustIdentLen(b []byte, i int) int {
	c := b[i]
	if c < utf8.RuneSelf {
		if c == '_' || ('a' <= c && c <= 'z') || ('A' <= c && c <= 'Z') || ('0' <= c && c <= '9') {
			return 1
		}
		return 0
	}
	if rustWhitespaceLen(b, i) > 0 {
		return 0
	}
	return runeLen(b, i)
}

// rustIdentStartLen is rustIdentLen without the digits, which cannot start an
// identifier.
func rustIdentStartLen(b []byte, i int) int {
	if c := b[i]; '0' <= c && c <= '9' {
		return 0
	}
	return rustIdentLen(b, i)
}

// rustWhitespaceLen returns the length of the whitespace character at b[i], or
// 0: rustc's whitespace is Unicode Pattern_White_Space, which besides ASCII's
// takes NEXT LINE, the two direction marks and the line and paragraph
// separators.
func rustWhitespaceLen(b []byte, i int) int {
	switch c := b[i]; c {
	case '\t', '\n', '\v', '\f', '\r', ' ':
		return 1
	}
	if b[i] < utf8.RuneSelf {
		return 0
	}
	r, size := utf8.DecodeRune(b[i:])
	switch r {
	case '\u0085', '\u200E', '\u200F', '\u2028', '\u2029':
		return size
	}
	return 0
}

// runeLen returns the length of the UTF-8 sequence at b[i] (1 for a byte that
// does not start one).
func runeLen(b []byte, i int) int {
	if b[i] < utf8.RuneSelf {
		return 1
	}
	_, size := utf8.DecodeRune(b[i:])
	return size
}
