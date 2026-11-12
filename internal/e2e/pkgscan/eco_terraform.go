//go:build integration
// +build integration

package pkgscan

import (
	"archive/zip"
	"bytes"
	"fmt"
	"io"
	"io/fs"

	//lint:ignore SA1019 the frozen openpgp package is what the backend verifies with; the stub signs with it.
	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/armor"
)

// Terraform / OpenTofu provider registry protocol. The client — configured with
// a `host` block that points providers.v1 at the proxy's mount, so it does no
// service discovery against the proxy (docs/clients/terraform.md) — asks:
//
//   - "/v1/providers/<ns>/<type>/versions": the versions and platforms;
//   - ".../<version>/download/<os>/<arch>": the package descriptor, naming the
//     release zip ("download_url"), the SHA256SUMS manifest ("shasums_url"),
//     its detached GPG signature ("shasums_signature_url"), the zip's SHA-256
//     ("shasum") and the keys that sign the manifest ("signing_keys"). The proxy
//     rewrites the three URLs onto synthetic endpoints of its own,
//     ".../<os>/<arch>/zip", "/shasums" and "/shasums.sig";
//   - the manifest and its signature (Terraform fetches both before the zip, to
//     authenticate it), then the zip.
//
// The zip is the payload. On a miss the proxy re-reads the descriptor from the
// registry, verifies the manifest's signature against the advertised key and
// the zip against the manifest, and only then serves it. The release files live
// on a separate release host in the real registry; the stub plays that host
// too, under "/releases/".

// The provider address and platform every fixture is published for.
const (
	tfNamespace = "pte2e"
	tfOS        = "linux"
	tfArch      = "amd64"
)

func init() {
	register(eco{
		ID: "terraform", Type: "terraform", Title: "Terraform / OpenTofu registry",
		Format:   "provider package (.zip)",
		Registry: tfRegistry,
	})
}

func tfRegistry(env stubEnv) (*registry, error) {
	signer, err := tfNewSigner()
	if err != nil {
		return nil, err
	}
	reg := newRegistry()
	for _, s := range env.Specs {
		typ := s.Slug() // the provider address is pte2e/<variant>
		binary := "terraform-provider-" + typ + "_v" + fixtureVersion
		zipName := "terraform-provider-" + typ + "_" + fixtureVersion + "_" + tfOS + "_" + tfArch + ".zip"
		sumsName := "terraform-provider-" + typ + "_" + fixtureVersion + "_SHA256SUMS"
		pkg := tfProviderZip(
			member{Name: binary, Data: "#!/bin/sh\necho \"" + binary + ": pkgscan e2e fixture provider\"\n", Mode: 0o755},
			member{Name: markerFile, Data: s.Text("")},
		)
		// SHA256SUMS lists every platform's zip in `sha256sum` format; this
		// release has one.
		sums := []byte(hexOf(pkg) + "  " + zipName + "\n")
		sig, err := signer.sign(sums)
		if err != nil {
			return nil, fmt.Errorf("signing the %s SHA256SUMS: %w", typ, err)
		}
		release := "/releases/terraform-provider-" + typ + "/" + fixtureVersion + "/"
		reg.mux.File(release+zipName, pkg, "application/zip")
		reg.mux.File(release+sumsName, sums, "text/plain; charset=utf-8")
		reg.mux.File(release+sumsName+".sig", sig, "application/pgp-signature")

		api := "/v1/providers/" + tfNamespace + "/" + typ
		reg.mux.File(api+"/versions", jsonDoc(map[string]any{
			"id": tfNamespace + "/" + typ,
			"versions": []map[string]any{{
				"version":   fixtureVersion,
				"protocols": []string{"5.0"},
				"platforms": []map[string]string{{"os": tfOS, "arch": tfArch}},
			}},
		}), "application/json")
		download := api + "/" + fixtureVersion + "/download/" + tfOS + "/" + tfArch
		reg.mux.File(download, jsonDoc(map[string]any{
			"protocols":             []string{"5.0"},
			"os":                    tfOS,
			"arch":                  tfArch,
			"filename":              zipName,
			"download_url":          env.URL + release + zipName,
			"shasums_url":           env.URL + release + sumsName,
			"shasums_signature_url": env.URL + release + sumsName + ".sig",
			"shasum":                hexOf(pkg),
			"signing_keys": map[string]any{"gpg_public_keys": []map[string]string{{
				"key_id":      signer.keyID,
				"ascii_armor": signer.armoredPublicKey,
				"source":      "pkgscan-e2e",
			}}},
		}), "application/json")

		reg.add(s.Variant, &pkgPull{
			// The coordinate of a provider is its address; the version is the path's.
			Name: tfNamespace + "/" + typ, Version: fixtureVersion,
			Preamble: []step{
				{Path: api + "/versions", Contains: []string{fixtureVersion}},
				// The descriptor must send every artifact fetch back through the proxy
				// (the proxy re-encodes it compactly), and keep what the client
				// verifies with: the digest and the key.
				{Path: download, Contains: []string{
					`"download_url":"` + mountPlaceholder + download + `/zip"`,
					`"shasums_url":"` + mountPlaceholder + download + `/shasums"`,
					`"shasums_signature_url":"` + mountPlaceholder + download + `/shasums.sig"`,
					hexOf(pkg),
					signer.keyID,
				}},
				{Path: download + "/shasums", Contains: []string{hexOf(pkg) + "  " + zipName}},
				{Path: download + "/shasums.sig"},
			},
			Payload: step{Path: download + "/zip"},
			Body:    pkg,
			Marker:  markerFile,
		})
	}
	return reg, nil
}

// tfSigner is the GPG key a stub provider registry signs its SHA256SUMS
// manifests with, as a provider publisher does.
type tfSigner struct {
	entity           *openpgp.Entity
	keyID            string
	armoredPublicKey string
}

// tfNewSigner generates a throwaway signing key.
func tfNewSigner() (*tfSigner, error) {
	ent, err := openpgp.NewEntity("pkgscan e2e provider publisher", "", "pkgscan-e2e@example.invalid", nil)
	if err != nil {
		return nil, fmt.Errorf("generating the provider signing key: %w", err)
	}
	var pub bytes.Buffer
	w, err := armor.Encode(&pub, openpgp.PublicKeyType, nil)
	if err != nil {
		return nil, err
	}
	if err := ent.Serialize(w); err != nil {
		return nil, err
	}
	if err := w.Close(); err != nil {
		return nil, err
	}
	return &tfSigner{
		entity:           ent,
		keyID:            ent.PrimaryKey.KeyIdString(), // 16 upper-case hex digits, as registries list it
		armoredPublicKey: pub.String(),
	}, nil
}

// sign returns a detached binary signature over message, the form
// releases.hashicorp.com publishes as "<name>_SHA256SUMS.sig".
func (s *tfSigner) sign(message []byte) ([]byte, error) {
	var sig bytes.Buffer
	if err := openpgp.DetachSign(&sig, s.entity, bytes.NewReader(message), nil); err != nil {
		return nil, err
	}
	return sig.Bytes(), nil
}

// tfProviderZip builds a provider release zip. A release holds the plugin
// executable Terraform runs, with its executable bit recorded in the zip (which
// zipOf does not write); the fixture's executable is a script that only
// identifies itself.
func tfProviderZip(members ...member) []byte {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for _, m := range members {
		hdr := &zip.FileHeader{Name: m.Name, Method: zip.Deflate, Modified: stubModTime}
		mode := m.Mode
		if mode == 0 {
			mode = 0o644
		}
		hdr.SetMode(fs.FileMode(mode))
		w, _ := zw.CreateHeader(hdr)
		_, _ = io.WriteString(w, m.Data)
	}
	_ = zw.Close()
	return buf.Bytes()
}
