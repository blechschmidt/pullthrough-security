package userlinks

import (
	"regexp"
	"strings"
	"testing"
)

func TestNewTokenIsWellFormedAndUnique(t *testing.T) {
	seen := map[string]struct{}{}
	// What documentation tells secret scanners to look for.
	pattern := regexp.MustCompile(`^ptl1[a-z2-7]{39}$`)
	// What a container image reference admits as a repository path component —
	// a link is one, in "<host>/u/<token>/<upstream>/<repository>".
	component := regexp.MustCompile(`^[a-z0-9]+(?:(?:[._]|__|[-]+)[a-z0-9]+)*$`)
	for i := 0; i < 500; i++ {
		tok, err := NewToken()
		if err != nil {
			t.Fatal(err)
		}
		if len(tok) != TokenLen {
			t.Fatalf("token %q has length %d, want %d", tok, len(tok), TokenLen)
		}
		if !WellFormed(tok) {
			t.Fatalf("a fresh token is not well formed: %q", tok)
		}
		if !pattern.MatchString(tok) {
			t.Fatalf("token %q does not match the documented pattern", tok)
		}
		if !component.MatchString(tok) {
			t.Fatalf("token %q is not a valid container repository path component", tok)
		}
		if _, dup := seen[tok]; dup {
			t.Fatalf("token %q was generated twice", tok)
		}
		seen[tok] = struct{}{}
	}
}

// The checksum is there so that a damaged token is recognised without a lookup:
// a wrong character, a missing one, a swapped pair.
func TestWellFormedDetectsDamage(t *testing.T) {
	tok, err := NewToken()
	if err != nil {
		t.Fatal(err)
	}
	// Every single-character substitution, at every position after the prefix.
	for i := len(TokenPrefix); i < len(tok); i++ {
		for _, c := range tokenAlphabet {
			if byte(c) == tok[i] {
				continue
			}
			damaged := tok[:i] + string(c) + tok[i+1:]
			if WellFormed(damaged) {
				t.Fatalf("a token with position %d changed from %q to %q still passes", i, tok[i], c)
			}
		}
	}
	// Every transposition of two adjacent, different characters.
	for i := len(TokenPrefix); i+1 < len(tok); i++ {
		if tok[i] == tok[i+1] {
			continue
		}
		b := []byte(tok)
		b[i], b[i+1] = b[i+1], b[i]
		if WellFormed(string(b)) {
			t.Fatalf("a token with positions %d and %d swapped still passes", i, i+1)
		}
	}
	for name, s := range map[string]string{
		"empty":             "",
		"truncated":         tok[:len(tok)-1],
		"extended":          tok + "a",
		"upper case":        strings.ToUpper(tok),
		"other prefix":      "ptl2" + tok[4:],
		"leading space":     " " + tok[1:],
		"a digit outside":   tok[:10] + "9" + tok[11:],
		"a slash inside":    tok[:10] + "/" + tok[11:],
		"prefix only":       TokenPrefix,
		"all the same char": TokenPrefix + strings.Repeat("a", TokenLen-len(TokenPrefix)),
	} {
		if WellFormed(s) {
			t.Errorf("%s: %q passes as a token", name, s)
		}
	}
}

func TestTokenHashAndID(t *testing.T) {
	tok, _ := NewToken()
	hash := hashToken(tok)
	if !validHex(hash, 64) {
		t.Fatalf("hash %q is not a hex SHA-256", hash)
	}
	id := linkIDFromHash(hash)
	if !ValidLinkID(id) || !strings.HasPrefix(hash, id) {
		t.Fatalf("id %q is not the leading 16 hex digits of the hash %q", id, hash)
	}
	if strings.Contains(hash, tok) || strings.Contains(id, tok[4:12]) {
		t.Fatal("the hash or the id contains token material")
	}
	other, _ := NewToken()
	if hashToken(other) == hash {
		t.Fatal("two tokens hash alike")
	}
	for _, bad := range []string{"", "abc", strings.Repeat("g", 16), strings.Repeat("A", 16), strings.Repeat("a", 17)} {
		if ValidLinkID(bad) {
			t.Errorf("%q passes as a link id", bad)
		}
	}
}
