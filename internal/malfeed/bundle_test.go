package malfeed

import (
	"bytes"
	"crypto/ed25519"
	"testing"
	"time"
)

// fixedKey returns a deterministic Ed25519 key pair so bundle output and
// signatures are reproducible across test runs.
func fixedKey() (ed25519.PrivateKey, ed25519.PublicKey) {
	seed := bytes.Repeat([]byte{0x42}, ed25519.SeedSize)
	priv := ed25519.NewKeyFromSeed(seed)
	return priv, priv.Public().(ed25519.PublicKey)
}

func TestBundle_RoundTrip(t *testing.T) {
	priv, pub := fixedKey()
	entries, _ := ParseOSVStream([]byte(fixtureFeed), "fixture")
	createdAt := time.Date(2026, 6, 20, 0, 0, 0, 0, time.UTC)

	data, err := ExportBundle(entries, "test-export", createdAt, priv)
	if err != nil {
		t.Fatalf("export: %v", err)
	}

	// Deterministic: a second export of the same input is byte-identical.
	data2, err := ExportBundle(entries, "test-export", createdAt, priv)
	if err != nil {
		t.Fatalf("export2: %v", err)
	}
	if !bytes.Equal(data, data2) {
		t.Fatal("bundle export is not deterministic")
	}

	got, err := ImportBundle(data, pub)
	if err != nil {
		t.Fatalf("import: %v", err)
	}
	if len(got) != len(entries) {
		t.Fatalf("round-trip entry count mismatch: got %d want %d", len(got), len(entries))
	}

	// Imported entries must rebuild into an equivalent matcher.
	m := NewMatcher(got)
	if d := m.Match(Coordinate{Ecosystem: "npm", Name: "evil-stealer", Version: "1.0.0"}); !d.Matched {
		t.Fatal("imported bundle lost the npm entry")
	}
	if d := m.Match(Coordinate{Ecosystem: "cargo", Name: "bad_crate", Version: "1.3.0"}); !d.Matched {
		t.Fatal("imported bundle lost the cargo range entry")
	}
}

func TestBundle_RejectsTamper(t *testing.T) {
	priv, pub := fixedKey()
	entries, _ := ParseOSVStream([]byte(fixtureFeed), "fixture")
	data, err := ExportBundle(entries, "t", time.Unix(0, 0).UTC(), priv)
	if err != nil {
		t.Fatalf("export: %v", err)
	}

	// Flip a byte inside the base64 payload; the digest/signature check must fail.
	marker := []byte(`"payload": "`)
	idx := bytes.Index(data, marker)
	if idx < 0 {
		t.Fatal("test setup: payload field not found")
	}
	tampered := append([]byte(nil), data...)
	pos := idx + len(marker) + 4 // a byte well inside the base64 blob
	if tampered[pos] == 'A' {
		tampered[pos] = 'B'
	} else {
		tampered[pos] = 'A'
	}
	if bytes.Equal(tampered, data) {
		t.Fatal("test setup: payload not modified")
	}
	if _, err := ImportBundle(tampered, pub); err == nil {
		t.Fatal("expected tampered bundle to be rejected")
	}
}

func TestBundle_WrongTrustedKey(t *testing.T) {
	priv, _ := fixedKey()
	entries, _ := ParseOSVStream([]byte(fixtureFeed), "fixture")
	data, err := ExportBundle(entries, "t", time.Unix(0, 0).UTC(), priv)
	if err != nil {
		t.Fatalf("export: %v", err)
	}

	// A different trusted key must reject the bundle.
	otherSeed := bytes.Repeat([]byte{0x07}, ed25519.SeedSize)
	otherPub := ed25519.NewKeyFromSeed(otherSeed).Public().(ed25519.PublicKey)
	if _, err := ImportBundle(data, otherPub); err == nil {
		t.Fatal("expected import to fail against the wrong trusted key")
	}
}

func TestBundle_IntegrityOnlyWhenUnpinned(t *testing.T) {
	priv, _ := fixedKey()
	entries, _ := ParseOSVStream([]byte(fixtureFeed), "fixture")
	data, err := ExportBundle(entries, "t", time.Unix(0, 0).UTC(), priv)
	if err != nil {
		t.Fatalf("export: %v", err)
	}
	// With no pinned key, the embedded key verifies integrity.
	got, err := ImportBundle(data, nil)
	if err != nil {
		t.Fatalf("unpinned import: %v", err)
	}
	if len(got) != len(entries) {
		t.Fatalf("entry count mismatch: %d vs %d", len(got), len(entries))
	}
}
