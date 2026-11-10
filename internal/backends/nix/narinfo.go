package nix

import (
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"path"
	"strconv"
	"strings"
)

// A narinfo is the signed metadata record for a single store path. It is a small
// "Key: value" text document, e.g.:
//
//	StorePath: /nix/store/zzz...-hello-2.12.1
//	URL: nar/1abc....nar.xz
//	Compression: xz
//	FileHash: sha256:1abc...
//	FileSize: 50088
//	NarHash: sha256:0def...
//	NarSize: 226552
//	References: zzz...-glibc zzz...-hello-2.12.1
//	Deriver: www...-hello-2.12.1.drv
//	Sig: cache.nixos.org-1:BASE64SIG==
//
// The ed25519 signature (the "Sig" field, possibly repeated) covers a canonical
// "fingerprint" over the StorePath, NarHash, NarSize and References — NOT the URL
// or FileHash — so the proxy can rewrite the URL field to route NAR downloads
// back through itself without invalidating the signature. The backend verifies
// the signature against the configured trusted public keys before serving the
// narinfo, which is the trust anchor for the whole store path: it authenticates
// the NarHash the Nix client will itself enforce after decompressing the NAR.

// maxNarInfoBytes bounds a narinfo fetch. Real narinfos are a few hundred bytes
// to a few KiB; the cap stops a hostile upstream returning an unbounded body on
// a path the proxy fully buffers to verify and rewrite.
const maxNarInfoBytes = 2 << 20 // 2 MiB

// narInfo is the parsed, order-preserving view of a narinfo document.
type narInfo struct {
	StorePath   string
	URL         string
	Compression string
	FileHash    string
	FileSize    uint64
	NarHash     string
	NarSize     uint64
	References  []string
	Deriver     string
	Sigs        []string
	// lines retains every raw line (including blanks and unknown keys) so the
	// document can be re-emitted byte-for-byte except for the single rewritten
	// URL line.
	lines []rawLine
}

// rawLine is one physical line of a narinfo, split into its key and the raw
// remainder after "Key: " so the value can be rewritten while preserving layout.
type rawLine struct {
	key   string // "" for a blank/malformed line
	value string
}

// parseNarInfo parses a narinfo document. It tolerates unknown keys and blank
// lines (retaining them for faithful re-emission) and returns an error only when
// a known numeric field is malformed.
func parseNarInfo(data []byte) (*narInfo, error) {
	ni := &narInfo{}
	text := string(data)
	for _, line := range strings.Split(text, "\n") {
		trimmed := strings.TrimRight(line, "\r")
		idx := strings.Index(trimmed, ": ")
		if idx < 0 {
			ni.lines = append(ni.lines, rawLine{value: trimmed})
			continue
		}
		key := trimmed[:idx]
		val := trimmed[idx+2:]
		ni.lines = append(ni.lines, rawLine{key: key, value: val})

		switch key {
		case "StorePath":
			ni.StorePath = val
		case "URL":
			ni.URL = val
		case "Compression":
			ni.Compression = val
		case "FileHash":
			ni.FileHash = val
		case "FileSize":
			n, err := strconv.ParseUint(strings.TrimSpace(val), 10, 64)
			if err != nil {
				return nil, fmt.Errorf("nix: malformed FileSize %q: %w", val, err)
			}
			ni.FileSize = n
		case "NarHash":
			ni.NarHash = val
		case "NarSize":
			n, err := strconv.ParseUint(strings.TrimSpace(val), 10, 64)
			if err != nil {
				return nil, fmt.Errorf("nix: malformed NarSize %q: %w", val, err)
			}
			ni.NarSize = n
		case "References":
			ni.References = splitFields(val)
		case "Deriver":
			ni.Deriver = val
		case "Sig":
			ni.Sigs = append(ni.Sigs, val)
		}
	}
	if ni.StorePath == "" {
		return nil, fmt.Errorf("nix: narinfo missing StorePath")
	}
	if ni.URL == "" {
		return nil, fmt.Errorf("nix: narinfo missing URL")
	}
	return ni, nil
}

// splitFields splits a space-separated field value, dropping empties.
func splitFields(v string) []string {
	parts := strings.Fields(v)
	if len(parts) == 0 {
		return nil
	}
	return parts
}

// fingerprint renders the canonical string an ed25519 narinfo signature is
// computed over, exactly as Nix's libstore does:
//
//	1;<storePath>;<narHash>;<narSize>;<ref1>,<ref2>,...
//
// where each reference is its full store path (the store directory — the
// directory component of StorePath — joined with the listed base name). The
// NarHash is used verbatim in the "sha256:<nixbase32>" form the narinfo records,
// which is the form that was signed.
func (ni *narInfo) fingerprint() (string, error) {
	if ni.NarHash == "" {
		return "", fmt.Errorf("nix: narinfo missing NarHash")
	}
	if ni.NarSize == 0 {
		return "", fmt.Errorf("nix: narinfo missing or zero NarSize")
	}
	storeDir := path.Dir(ni.StorePath)
	refs := make([]string, len(ni.References))
	for i, r := range ni.References {
		// A reference may already be a full path in some producers; keep it as-is
		// then, otherwise join it under the store directory.
		if strings.HasPrefix(r, "/") {
			refs[i] = r
		} else {
			refs[i] = storeDir + "/" + r
		}
	}
	var b strings.Builder
	b.WriteString("1;")
	b.WriteString(ni.StorePath)
	b.WriteByte(';')
	b.WriteString(ni.NarHash)
	b.WriteByte(';')
	b.WriteString(strconv.FormatUint(ni.NarSize, 10))
	b.WriteByte(';')
	b.WriteString(strings.Join(refs, ","))
	return b.String(), nil
}

// rewriteURL replaces the narinfo's "URL:" value with newURL in both the parsed
// struct and the retained raw lines, so reemit() produces a document whose only
// change from the upstream bytes is the proxied NAR location.
func (ni *narInfo) rewriteURL(newURL string) {
	ni.URL = newURL
	for i := range ni.lines {
		if ni.lines[i].key == "URL" {
			ni.lines[i].value = newURL
		}
	}
}

// reemit renders the narinfo back to its text form, preserving the original line
// order, blank lines and unknown keys, with only the URL value changed by any
// prior rewriteURL call.
func (ni *narInfo) reemit() string {
	var b strings.Builder
	for i, ln := range ni.lines {
		// A trailing empty final line (from a terminating newline in the source)
		// is reproduced by the join below; avoid emitting a spurious "key: " for it.
		if ln.key == "" {
			b.WriteString(ln.value)
		} else {
			b.WriteString(ln.key)
			b.WriteString(": ")
			b.WriteString(ln.value)
		}
		if i != len(ni.lines)-1 {
			b.WriteByte('\n')
		}
	}
	return b.String()
}

// publicKey is a trusted Nix binary-cache signing key: a name and its ed25519
// public key. Narinfo signatures are "name:base64sig"; a signature verifies when
// its name matches a trusted key and the ed25519 check passes.
type publicKey struct {
	name string
	key  ed25519.PublicKey
}

// parsePublicKey parses a trusted key in Nix's "name:base64" form (e.g.
// "cache.nixos.org-1:6NCHdD59X431o0gWypbMrAURkbJ16ZPMQFGspcDShjY=").
func parsePublicKey(s string) (publicKey, error) {
	name, b64, ok := strings.Cut(strings.TrimSpace(s), ":")
	if !ok || name == "" || b64 == "" {
		return publicKey{}, fmt.Errorf("nix: malformed trusted public key %q (want name:base64)", s)
	}
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return publicKey{}, fmt.Errorf("nix: trusted public key %q: invalid base64: %w", name, err)
	}
	if len(raw) != ed25519.PublicKeySize {
		return publicKey{}, fmt.Errorf("nix: trusted public key %q: want %d-byte ed25519 key, got %d", name, ed25519.PublicKeySize, len(raw))
	}
	return publicKey{name: name, key: ed25519.PublicKey(raw)}, nil
}

// parseTrustedKeys parses a set of trusted keys, keyed by signer name. It accepts
// a slice of "name:base64" strings.
func parseTrustedKeys(keys []string) (map[string]publicKey, error) {
	out := make(map[string]publicKey, len(keys))
	for _, k := range keys {
		if strings.TrimSpace(k) == "" {
			continue
		}
		pk, err := parsePublicKey(k)
		if err != nil {
			return nil, err
		}
		out[pk.name] = pk
	}
	return out, nil
}

// verifySignature checks the narinfo's signatures against the trusted keys. It
// returns the name of the first trusted key whose signature verifies, or ok=false
// if none do. With no trusted keys configured it returns ("", false) and the
// caller decides policy (serve unverified).
func verifySignature(ni *narInfo, trusted map[string]publicKey) (signer string, ok bool) {
	if len(trusted) == 0 {
		return "", false
	}
	fp, err := ni.fingerprint()
	if err != nil {
		return "", false
	}
	msg := []byte(fp)
	for _, sig := range ni.Sigs {
		name, b64, cut := strings.Cut(sig, ":")
		if !cut {
			continue
		}
		pk, known := trusted[name]
		if !known {
			continue
		}
		raw, err := base64.StdEncoding.DecodeString(b64)
		if err != nil || len(raw) != ed25519.SignatureSize {
			continue
		}
		if ed25519.Verify(pk.key, msg, raw) {
			return name, true
		}
	}
	return "", false
}
