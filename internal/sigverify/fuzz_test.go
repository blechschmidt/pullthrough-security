//go:build fuzz
// +build fuzz

// Fuzz target for OCI/Docker manifest and index ("referrers"/tag-list) JSON
// handling (Task 30, Task 5).
//
// When the signature-verification gate resolves an image it fetches and decodes
// manifest and index documents returned by an upstream registry, then walks the
// referenced descriptors (config, layers, referrer manifests) to find cosign
// signature/attestation artifacts. The registry is untrusted, so this decode +
// descriptor-walk must never panic and must not allocate without bound on a
// hostile manifest.
//
// Build-tag gated (`fuzz`). Run e.g.:
//
//	go test -tags fuzz -run=Fuzz -fuzz=FuzzOCIManifest ./internal/sigverify/
package sigverify

import (
	"encoding/json"
	"testing"
)

func FuzzOCIManifest(f *testing.F) {
	seeds := []string{
		// Image manifest.
		`{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json","config":{"mediaType":"application/vnd.oci.image.config.v1+json","digest":"sha256:aaaa","size":7023},"layers":[{"mediaType":"application/vnd.oci.image.layer.v1.tar+gzip","digest":"sha256:bbbb","size":32654}]}`,
		// Index / referrers response (the "tag-list"-shaped document the gate walks).
		`{"schemaVersion":2,"mediaType":"application/vnd.oci.image.index.v1+json","manifests":[{"mediaType":"application/vnd.oci.image.manifest.v1+json","artifactType":"application/vnd.dev.cosign.artifact.sig.v1+json","digest":"sha256:cccc","size":100},{"mediaType":"application/vnd.in-toto+json","digest":"sha256:dddd","size":200}]}`,
		// Edge cases / malformed.
		`{"manifests":null}`,
		`{"layers":[null,null]}`,
		`{"config":{"digest":""}}`,
		`{"manifests":[{"annotations":{"k":"v"}}]}`,
		`{}`,
		`[]`,
		`null`,
		`not json`,
		``,
		`{"manifests":[{"digest":"notadigest"}]}`,
		`{"manifests":[{"digest":"sha256:"}]}`,
	}
	for _, s := range seeds {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		var m ociManifest
		if err := json.Unmarshal(data, &m); err != nil {
			return // a decode failure is graceful, not a crash
		}
		// Walk the descriptors exactly as the gate does: classify referrer
		// artifacts and derive cosign tags from any config/layer/manifest digest.
		all := append(append([]ociDescriptor{m.Config}, m.Layers...), m.Manifests...)
		for _, d := range all {
			_ = isCosignArtifactType(d)
			for _, tag := range cosignTags(d.Digest) {
				if tag == "" {
					t.Fatalf("cosignTags produced an empty tag for digest %q", d.Digest)
				}
			}
		}
	})
}
