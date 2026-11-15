package installhooks

import (
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
// The lexing follows rustc: a comment cannot start inside a string, raw string
// or character literal, a block comment ends at its matching "*/" whatever it
// contains, and an identifier straight after a literal is that literal's suffix.
// Getting this wrong in the other direction would hide code from the rules: a
// "//" inside a string literal must not swallow the rest of its line. Text that
// is not valid Rust is handled best-effort; rustc refuses it, so it never runs.
func stripRustComments(src string) string {
	b := []byte(src)
	out := []byte(src)
	n := len(b)
	for i := 0; i < n; {
		c := b[i]
		switch {
		case c == '/' && i+1 < n && b[i+1] == '/':
			end := i + 2
			for end < n && b[end] != '\n' {
				end++
			}
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
		case isRustIdentByte(c):
			if hashes, quote, ok := rustRawStringStart(b, i); ok {
				i = skipRustSuffix(b, skipRustRawString(b, quote, hashes))
				continue
			}
			i = skipRustIdent(b, i)
		default:
			i++
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

// skipRustQuote handles a single quote at b[start]: a character literal ('x',
// 'é', '"', '\n', '\x7f', '\u{1F600}') is skipped whole with its suffix, so the
// quote characters and slashes inside it never count; anything else is a
// lifetime or a label ('a, 'static, 'outer), skipped with its name.
func skipRustQuote(b []byte, start int) int {
	n := len(b)
	j := start + 1
	if j >= n {
		return n
	}
	if b[j] == '\\' {
		// An escape: the closing quote follows within a few bytes on the same
		// line ('\u{10FFFF}' is the longest that matters: a longer \u{…} can
		// only pad with underscores, and neither they nor hex digits are quotes
		// or slashes, so giving up on it lexes nothing differently).
		for k := j + 2; k < n && k-start <= 11; k++ {
			if b[k] == '\n' {
				break
			}
			if b[k] == '\'' {
				return skipRustSuffix(b, k+1)
			}
		}
		return start + 1
	}
	if b[j] != '\'' && b[j] != '\n' {
		_, size := utf8.DecodeRune(b[j:])
		if j+size < n && b[j+size] == '\'' {
			return skipRustSuffix(b, j+size+1)
		}
	}
	return skipRustIdent(b, j)
}

// skipRustSuffix skips an identifier that directly follows a literal: rustc
// lexes it as the literal's suffix ("x"suffix, 'c'u8), never as the start of a
// raw string.
func skipRustSuffix(b []byte, i int) int {
	return skipRustIdent(b, i)
}

// skipRustIdent returns the index just past the run of identifier bytes at
// b[i] (none: i itself).
func skipRustIdent(b []byte, i int) int {
	for i < len(b) && isRustIdentByte(b[i]) {
		i++
	}
	return i
}

// isRustIdentByte reports whether c can be part of an identifier, a keyword or
// a number. Every byte of a multi-byte UTF-8 sequence counts: outside literals
// and comments non-ASCII text can only be an identifier (or an error).
func isRustIdentByte(c byte) bool {
	return c == '_' || c >= 0x80 ||
		('a' <= c && c <= 'z') || ('A' <= c && c <= 'Z') || ('0' <= c && c <= '9')
}
