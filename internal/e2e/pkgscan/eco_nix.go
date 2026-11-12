//go:build integration
// +build integration

package pkgscan

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"

	"github.com/ulikunitz/xz"
)

// Nix binary cache: a client that wants a store path asks the cache for
// "/<store hash>.narinfo", a signed description of the path — its NAR's hash
// and size and its references, signed (ed25519) by the cache key the client
// trusts — and the location of the NAR, the serialized path, which it then
// downloads. The signature does not cover the location, so the proxy rewrites
// it onto itself; it verifies the signature against the configured
// `trustedPublicKeys` before it serves a narinfo, and a NAR against the
// content address its file name carries.
//
// The stub publishes each NAR as `nix copy` does by default: xz-compressed, at
// "nar/<hash of the compressed file>.nar.xz". A NAR is the store path's tree
// written as a sequence of length-prefixed strings (narWrite); the scanner
// lists its files relative to the store path's root.
//
// The proxy has no name or version for a NAR: it reports the content address
// in the file name as both.

func init() {
	register(eco{
		ID: "nix", Type: "nix", Title: "Nix binary cache",
		Format: "NAR (xz) + signed narinfo",
		Settings: func(string) map[string]string {
			return map[string]string{"trustedPublicKeys": nixKeyName + ":" + base64.StdEncoding.EncodeToString(nixSigningKey().Public().(ed25519.PublicKey))}
		},
		Registry: nixRegistry,
	})
}

// nixKeyName is the name of the stub cache's signing key, as a narinfo's
// "Sig:" and a client's trusted-public-keys spell it ("<name>:<base64>").
const nixKeyName = "pkgscan-e2e-cache-1"

// nixSigningKey is the stub cache's ed25519 key. It is derived from a fixed
// seed, so the proxy configuration (Settings) and the stub (Registry) agree on
// it without sharing state, and a run is reproducible.
func nixSigningKey() ed25519.PrivateKey {
	seed := sha256.Sum256([]byte("pullthrough-pkgscan-e2e nix binary cache signing key"))
	return ed25519.NewKeyFromSeed(seed[:])
}

func nixRegistry(env stubEnv) (*registry, error) {
	reg := newRegistry()
	reg.mux.File("/nix-cache-info", []byte("StoreDir: /nix/store\nWantMassQuery: 1\nPriority: 40\n"), "text/x-nix-cache-info")
	key := nixSigningKey()
	for _, s := range env.Specs {
		name := s.Name() + "-" + fixtureVersion
		nar := narWrite(&narNode{Entries: map[string]*narNode{
			"share": {Entries: map[string]*narNode{
				s.Name(): {Entries: map[string]*narNode{
					"README":   {Contents: "pullthrough pkgscan e2e fixture package\n"},
					markerFile: {Contents: s.Text("")},
				}},
			}},
		}})
		compressed, err := nixXZ(nar)
		if err != nil {
			return nil, fmt.Errorf("compressing the NAR of %s: %w", name, err)
		}
		narHash := sha256.Sum256(nar)
		fileHash := sha256.Sum256(compressed)
		file := nixBase32(fileHash[:]) + ".nar.xz"
		storeHash := nixStoreHash(narHash, name)
		storePath := "/nix/store/" + storeHash + "-" + name
		narHashField := "sha256:" + nixBase32(narHash[:])

		// The signature covers the fingerprint "1;<store path>;<NAR hash>;<NAR
		// size>;<references, comma-separated>" — not the URL, which is why the
		// proxy may rewrite it.
		fingerprint := fmt.Sprintf("1;%s;%s;%d;", storePath, narHashField, len(nar))
		narinfo := strings.Join([]string{
			"StorePath: " + storePath,
			"URL: nar/" + file,
			"Compression: xz",
			"FileHash: sha256:" + nixBase32(fileHash[:]),
			fmt.Sprintf("FileSize: %d", len(compressed)),
			"NarHash: " + narHashField,
			fmt.Sprintf("NarSize: %d", len(nar)),
			"References: ",
			// The path is content-addressed (see nixStoreHash): its NAR hash, recursive.
			"CA: fixed:r:" + narHashField,
			"Sig: " + nixKeyName + ":" + base64.StdEncoding.EncodeToString(ed25519.Sign(key, []byte(fingerprint))),
		}, "\n") + "\n"
		reg.mux.File("/"+storeHash+".narinfo", []byte(narinfo), "text/x-nix-narinfo")
		reg.mux.File("/nar/"+file, compressed, "application/x-nix-nar")

		reg.add(s.Variant, &pkgPull{
			Name: nixBase32(fileHash[:]), Version: nixBase32(fileHash[:]),
			// What a substituter query costs a client: the cache's descriptor, then
			// the store path's narinfo, whose URL must now lead back to the proxy.
			Preamble: []step{
				{Path: "/nix-cache-info", Contains: []string{"StoreDir: /nix/store"}},
				{Path: "/" + storeHash + ".narinfo", Contains: []string{"StorePath: " + storePath + "\n", "URL: " + mountPlaceholder + "/nar/" + file + "\n"}},
			},
			Payload: step{Path: "/nar/" + file},
			Body:    compressed,
			Marker:  "share/" + s.Name() + "/" + markerFile,
		})
	}
	return reg, nil
}

// nixStoreHash returns the hash part of the store path of a tree added to the
// store by its content (`nix-store --add`): the SHA-256 of
// "source:sha256:<NAR hash, hex>:/nix/store:<name>", XOR-folded to 160 bits and
// written in Nix base-32 — 32 characters. The proxy checks only that form.
func nixStoreHash(narHash [32]byte, name string) string {
	h := sha256.Sum256([]byte("source:sha256:" + hex.EncodeToString(narHash[:]) + ":/nix/store:" + name))
	var folded [20]byte
	for i, b := range h {
		folded[i%len(folded)] ^= b
	}
	return nixBase32(folded[:])
}

// nixBase32Alphabet is Nix's base-32 digit set: no "e", "o", "u" or "t".
const nixBase32Alphabet = "0123456789abcdfghijklmnpqrsvwxyz"

// nixBase32 writes a digest in Nix's base-32 encoding, which is not RFC 4648:
// the characters are emitted most significant first, each taking its five
// bits from the digest read least significant first.
func nixBase32(hash []byte) string {
	n := (len(hash)*8-1)/5 + 1
	out := make([]byte, n)
	for i := 0; i < n; i++ {
		bit := (n - 1 - i) * 5
		at, shift := bit/8, uint(bit%8)
		c := uint16(hash[at]) >> shift
		if at+1 < len(hash) {
			c |= uint16(hash[at+1]) << (8 - shift)
		}
		out[i] = nixBase32Alphabet[c&0x1f]
	}
	return string(out)
}

// narNode is one node of a store path's tree: a directory (Entries non-nil),
// a symbolic link (Target set) or a regular file.
type narNode struct {
	Entries    map[string]*narNode
	Target     string
	Contents   string
	Executable bool
}

// narWrite serializes a tree as a Nix archive, as `nix-store --dump` does:
//
//	"nix-archive-1" node
//	node = "(" "type" "regular" ["executable" ""] "contents" <bytes> ")"
//	     | "(" "type" "symlink" "target" <target> ")"
//	     | "(" "type" "directory" { "entry" "(" "name" <name> "node" node ")" } ")"
//
// every string as a 64-bit little-endian length followed by the bytes, padded
// with zeros to a multiple of eight; directory entries sorted by name.
func narWrite(root *narNode) []byte {
	var b bytes.Buffer
	str := func(s string) {
		var n [8]byte
		binary.LittleEndian.PutUint64(n[:], uint64(len(s)))
		b.Write(n[:])
		b.WriteString(s)
		b.Write(make([]byte, (8-len(s)%8)%8))
	}
	var node func(n *narNode)
	node = func(n *narNode) {
		str("(")
		str("type")
		switch {
		case n.Entries != nil:
			str("directory")
			names := make([]string, 0, len(n.Entries))
			for name := range n.Entries {
				names = append(names, name)
			}
			sort.Strings(names)
			for _, name := range names {
				str("entry")
				str("(")
				str("name")
				str(name)
				str("node")
				node(n.Entries[name])
				str(")")
			}
		case n.Target != "":
			str("symlink")
			str("target")
			str(n.Target)
		default:
			str("regular")
			if n.Executable {
				str("executable")
				str("")
			}
			str("contents")
			str(n.Contents)
		}
		str(")")
	}
	str("nix-archive-1")
	node(root)
	return b.Bytes()
}

// nixXZ compresses a NAR with xz, the default compression of a binary cache
// `nix copy` writes.
func nixXZ(nar []byte) ([]byte, error) {
	var buf bytes.Buffer
	w, err := xz.NewWriter(&buf)
	if err != nil {
		return nil, err
	}
	if _, err := w.Write(nar); err != nil {
		return nil, err
	}
	if err := w.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
