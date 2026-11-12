//go:build fuzz
// +build fuzz

// Fuzz targets for personal cache links (Task 177).
//
// A link's token arrives in a request path or a credential header, a cookie
// arrives from a browser, and the registry's records are read from a directory
// an operator can edit or a bucket other software can write to. None of the
// three may crash the proxy, and each has a property that must hold for every
// input:
//
//   - whatever passes as a token has exactly the shape the rest of the system
//     relies on — and so is safe to use as a path segment and a hash input;
//   - no cookie that was not signed by this proxy, for that purpose, decodes;
//   - a stored record that is accepted holds together: its identifier belongs
//     to its token hash, its subject is printable, every field is bounded.
//
// Run one with:
//
//	go test -tags fuzz -run='^$' -fuzz='^FuzzLoadLink$' -fuzztime=30s ./internal/userlinks/
package userlinks

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"
	"unicode"
	"unicode/utf8"
)

func FuzzWellFormed(f *testing.F) {
	tok, _ := NewToken()
	f.Add(tok)
	f.Add("")
	f.Add(TokenPrefix)
	f.Add(strings.ToUpper(tok))
	f.Add(tok[:20])
	f.Fuzz(func(t *testing.T, s string) {
		if !WellFormed(s) {
			return
		}
		// Whatever passes has exactly the shape the rest of the system relies
		// on: fixed length, the prefix, lower-case letters and digits only.
		if len(s) != TokenLen || !strings.HasPrefix(s, TokenPrefix) {
			t.Fatalf("%q passes with the wrong length or prefix", s)
		}
		for i := 0; i < len(s); i++ {
			c := s[i]
			if !(c >= 'a' && c <= 'z') && !(c >= '0' && c <= '9') {
				t.Fatalf("%q passes with the character %q", s, c)
			}
		}
	})
}

// printable reports whether s is what cleanText promises: valid UTF-8 without
// control or invisible format characters.
func printable(s string) bool {
	if !utf8.ValidString(s) {
		return false
	}
	for _, r := range s {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) || r == '\u2028' || r == '\u2029' {
			return false
		}
	}
	return true
}

func FuzzCleanText(f *testing.F) {
	f.Add("laptop", 64)
	f.Add("  ci \x00\u202eevil\u200b ", 8)
	f.Add("\xff\xfe", 4)
	f.Add(strings.Repeat("ä", 100), 7)
	f.Fuzz(func(t *testing.T, s string, max int) {
		if max < 0 || max > 4096 {
			return
		}
		got := cleanText(s, max)
		if len(got) > max {
			t.Fatalf("cleanText(%q, %d) is %d bytes long", s, max, len(got))
		}
		if !printable(got) {
			t.Fatalf("cleanText(%q, %d) = %q, which is not printable", s, max, got)
		}
		if got != strings.TrimSpace(got) {
			t.Fatalf("cleanText(%q, %d) = %q, which is not trimmed", s, max, got)
		}
		if again := cleanText(got, max); again != got {
			t.Fatalf("cleaning twice changes the result: %q → %q", got, again)
		}
	})
}

// No cookie decodes unless this proxy signed it, as that kind of cookie.
func FuzzDecodeCookie(f *testing.F) {
	now := func() time.Time { return time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC) }
	codec := newCookieCodec([]byte("0123456789abcdef0123456789abcdef"), now)
	session, _ := codec.encodeSession(Identity{Subject: "alice@example.com", Team: "platform"}, time.Hour)
	flow, _ := codec.encodeFlow(flowClaims{State: "s", Verifier: "v", Nonce: "n"}, time.Minute)
	f.Add(session)
	f.Add(flow)
	f.Add("")
	f.Add("a.b")
	f.Add(base64.RawURLEncoding.EncodeToString([]byte(`{"subject":"admin","exp":99999999999}`)) + ".AAAA")
	f.Fuzz(func(t *testing.T, value string) {
		id, _, err := codec.decodeSession(value)
		if err == nil {
			// Only what the codec itself produced for a session is accepted.
			if value != session {
				body, mac, _ := strings.Cut(value, ".")
				if sign(codec.sessionKey, body) != mac {
					t.Fatalf("a session cookie with a wrong signature decoded: %q", value)
				}
			}
			if id.Subject == "" || !printable(id.Subject) {
				t.Fatalf("a session decoded to the subject %q", id.Subject)
			}
		}
		if _, err := codec.decodeFlow(value); err == nil {
			body, mac, _ := strings.Cut(value, ".")
			if sign(codec.flowKey, body) != mac {
				t.Fatalf("a flow cookie with a wrong signature decoded: %q", value)
			}
		}
	})
}

// A record read from the store is either refused or holds together.
func FuzzLoadLink(f *testing.F) {
	hash := hashToken("ptl1" + strings.Repeat("a", 39))
	good, _ := json.Marshal(Link{ID: linkIDFromHash(hash), TokenHash: hash, Identity: Identity{Subject: "alice@example.com"}, CreatedAt: time.Unix(1, 0)})
	f.Add(string(good), hash)
	f.Add(`{"id":"x","tokenHash":"y"}`, hash)
	f.Add(`{}`, "")
	f.Add(`not json`, hash)
	f.Add(`{"id":"`+linkIDFromHash(hash)+`","tokenHash":"`+hash+`","subject":"a\u202eb","createdAt":"2026-01-01T00:00:00Z"}`, hash)
	f.Fuzz(func(t *testing.T, data, name string) {
		store := NewMemoryStore()
		ctx := context.Background()
		if !validObjectName("link/" + name) {
			return
		}
		if err := store.Put(ctx, "link/"+name, []byte(data)); err != nil {
			return
		}
		r, err := NewRegistry(RegistryConfig{Store: store, LinkTTL: -1})
		if err != nil {
			t.Fatal(err)
		}
		for _, info := range r.List(Filter{}) {
			if info.ID != linkIDFromHash(name) || !validHex(name, 64) {
				t.Fatalf("a record stored as %q was loaded as link %q", name, info.ID)
			}
			if info.Subject == "" || !printable(info.Subject) || len(info.Subject) > maxSubjectLen {
				t.Fatalf("a record with the subject %q was accepted", info.Subject)
			}
			for field, value := range map[string]string{"name": info.Name, "email": info.Email, "team": info.Team, "label": info.Label, "from": info.CreatedFrom} {
				if !printable(value) || len(value) > maxSubjectLen {
					t.Fatalf("a record with the %s %q was accepted", field, value)
				}
			}
			if len(info.Roles) > maxRoles {
				t.Fatalf("a record with %d roles was accepted", len(info.Roles))
			}
		}
	})
}
