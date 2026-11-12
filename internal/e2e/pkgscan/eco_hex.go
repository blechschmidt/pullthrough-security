//go:build integration
// +build integration

package pkgscan

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
)

// Hex (hex.pm, registry v2): `mix deps.get` reads "/packages/<name>" to
// resolve a dependency, then downloads "/tarballs/<name>-<version>.tar".
//
// "/packages/<name>" is a registry resource: a gzip-compressed protobuf
// Signed{payload, signature}, whose payload is a Package{releases, name,
// repository} and whose signature is the repository's RSA signature over the
// payload (PKCS #1 v1.5, SHA-512). Each Release carries its version, the inner
// checksum and the outer checksum — the SHA-256 of the whole tarball. The
// backend reads the resource itself to verify a tarball against its outer
// checksum; it does not check the signature, and passes the resource through
// byte for byte so that a client pinning the repository's key can. The stub
// signs with a key generated for the run, so its resources are what a
// repository serves, not merely what the backend parses.
//
// A tarball (version 3) is an uncompressed tar of VERSION, CHECKSUM,
// metadata.config and contents.tar.gz. The package's files are in
// contents.tar.gz, which the scanner opens in place: they are listed by their
// paths in the package. Nothing is rewritten.

func init() {
	register(eco{
		ID: "hex", Type: "hex", Title: "Hex (Elixir / Erlang)",
		Format:   "release tarball (.tar holding contents.tar.gz)",
		Registry: hexpmRegistry,
	})
}

// hexpmRepository is the repository a registry resource names (Package's
// repository field), which a client checks against the repository it asked.
// The proxy is configured as a mirror of hex.pm (HEX_MIRROR), so the resources
// it serves are those of "hexpm".
const hexpmRepository = "hexpm"

func hexpmRegistry(env stubEnv) (*registry, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("generating the repository key: %w", err)
	}
	reg := newRegistry()
	for _, s := range env.Specs {
		// A Hex package name is lower-case letters, digits and underscores.
		name := "pte2e_" + s.Slug()
		module := "Pte2e" + strings.ToUpper(s.Slug()[:1]) + s.Slug()[1:]
		tarball, inner := hexpmTarball(name, map[string]string{
			"mix.exs": "defmodule " + module + ".MixProject do\n  use Mix.Project\n\n  def project do\n" +
				"    [app: :" + name + ", version: \"" + fixtureVersion + "\", elixir: \"~> 1.14\"]\n  end\nend\n",
			"lib/" + name + ".ex": "defmodule " + module + " do\n  def answer, do: 42\nend\n",
			markerFile:            s.Text(""),
		})
		outer := sha256.Sum256(tarball)
		resource, err := hexpmPackageResource(key, name, fixtureVersion, inner, outer[:])
		if err != nil {
			return nil, err
		}
		path := "/tarballs/" + name + "-" + fixtureVersion + ".tar"
		reg.mux.File(path, tarball, "application/octet-stream")
		reg.mux.File("/packages/"+name, resource, "application/octet-stream")

		reg.add(s.Variant, &pkgPull{
			Name: name, Version: fixtureVersion,
			// The backend passes the signed resource through untouched, so that a
			// client's signature check runs over exactly what the repository signed:
			// it must arrive byte for byte.
			Preamble: []step{{Path: "/packages/" + name, Contains: []string{string(resource)}}},
			Payload:  step{Path: path},
			Body:     tarball,
			Marker:   markerFile,
		})
	}
	return reg, nil
}

// hexpmTarball builds a release tarball as hex_tarball:create/3 writes one
// (tarball version 3) for a package of the given files (path -> content). It
// returns the tarball and its inner checksum: the SHA-256 of VERSION,
// metadata.config and contents.tar.gz concatenated, which the CHECKSUM member
// carries in upper-case hex.
func hexpmTarball(name string, files map[string]string) (tarball, inner []byte) {
	const version = "3"
	contents := tarGz(files)
	metadata := hexpmMetadata(name, files)
	sum := sha256.Sum256([]byte(version + metadata + string(contents)))
	return tarOf(
		member{Name: "VERSION", Data: version},
		member{Name: "CHECKSUM", Data: strings.ToUpper(hex.EncodeToString(sum[:]))},
		member{Name: "metadata.config", Data: metadata},
		member{Name: "contents.tar.gz", Data: string(contents)},
	), sum[:]
}

// hexpmMetadata renders metadata.config: the package's metadata as Erlang terms,
// one "{Key, Value}." per line, keys in term order.
func hexpmMetadata(name string, files map[string]string) string {
	paths := make([]string, 0, len(files))
	for p := range files {
		paths = append(paths, `<<"`+p+`">>`)
	}
	sort.Strings(paths)
	return `{<<"app">>,<<"` + name + `">>}.` + "\n" +
		`{<<"build_tools">>,[<<"mix">>]}.` + "\n" +
		`{<<"description">>,<<"pullthrough llm-package-scan e2e fixture">>}.` + "\n" +
		`{<<"elixir">>,<<"~> 1.14">>}.` + "\n" +
		`{<<"files">>,[` + strings.Join(paths, ",") + `]}.` + "\n" +
		`{<<"licenses">>,[<<"MIT">>]}.` + "\n" +
		`{<<"links">>,[]}.` + "\n" +
		`{<<"name">>,<<"` + name + `">>}.` + "\n" +
		`{<<"requirements">>,[]}.` + "\n" +
		`{<<"version">>,<<"` + fixtureVersion + `">>}.` + "\n"
}

// hexpmPackageResource builds the registry resource "/packages/<name>" for a
// package with one release, signed with key, as hex_registry_server builds it:
// gzip(Signed{payload: Package, signature: RSA-SHA512(payload)}).
//
//	Signed  { bytes payload = 1; bytes signature = 2; }
//	Package { repeated Release releases = 1; string name = 2; string repository = 3; }
//	Release { string version = 1; bytes inner_checksum = 2; ...; bytes outer_checksum = 5; }
func hexpmPackageResource(key *rsa.PrivateKey, name, version string, inner, outer []byte) ([]byte, error) {
	var release []byte
	release = append(release, hexpmField(1, []byte(version))...)
	release = append(release, hexpmField(2, inner)...)
	release = append(release, hexpmField(5, outer)...)
	var payload []byte
	payload = append(payload, hexpmField(1, release)...)
	payload = append(payload, hexpmField(2, []byte(name))...)
	payload = append(payload, hexpmField(3, []byte(hexpmRepository))...)

	digest := sha512.Sum512(payload)
	signature, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA512, digest[:])
	if err != nil {
		return nil, fmt.Errorf("signing the %s registry resource: %w", name, err)
	}
	// What a client pinning the repository's public key does with it.
	if err := rsa.VerifyPKCS1v15(&key.PublicKey, crypto.SHA512, digest[:], signature); err != nil {
		return nil, fmt.Errorf("the %s registry resource does not verify: %w", name, err)
	}
	signed := append(hexpmField(1, payload), hexpmField(2, signature)...)
	return gzipOf(signed), nil
}

// hexpmField encodes one length-delimited protobuf field (wire type 2), the
// only kind the registry messages written here hold.
func hexpmField(number int, value []byte) []byte {
	b := binary.AppendUvarint(nil, uint64(number)<<3|2)
	b = binary.AppendUvarint(b, uint64(len(value)))
	return append(b, value...)
}
