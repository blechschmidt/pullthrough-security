package sigverify

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// HTTPDoer is the minimal HTTP surface the package-registry source needs. The
// standard *http.Client and the proxy's outbound client satisfy it.
type HTTPDoer interface {
	Do(req *http.Request) (*http.Response, error)
}

// maxAttestationBytes bounds the package attestation response read.
const maxAttestationBytes = 8 << 20 // 8 MiB

// PackageSource discovers Sigstore-based publish attestations for a package
// release from its registry. npm exposes them at
// "/-/npm/v1/attestations/<name>@<version>"; PyPI exposes PEP 740 provenance.
// Both return Sigstore bundles (a certificate + a DSSE envelope), which this
// source decodes into attestation material for the common verifier.
type PackageSource struct {
	doer      HTTPDoer
	ecosystem string
	// urlFor builds the attestations URL for an artifact. Pluggable so npm and
	// pip (or a private registry mirror) can share the bundle-parsing core.
	urlFor func(art Artifact) (string, bool)
}

// NewNPMSource constructs a PackageSource for an npm registry rooted at baseURL
// (e.g. "https://registry.npmjs.org").
func NewNPMSource(doer HTTPDoer, baseURL string) *PackageSource {
	base := strings.TrimRight(baseURL, "/")
	return &PackageSource{
		doer:      doer,
		ecosystem: "npm",
		urlFor: func(art Artifact) (string, bool) {
			if art.Name == "" || art.Version == "" {
				return "", false
			}
			return base + "/-/npm/v1/attestations/" + art.Name + "@" + art.Version, true
		},
	}
}

// NewPackageSource constructs a PackageSource with a custom URL builder, for
// registries (e.g. PyPI PEP 740 provenance) whose attestation URL differs.
func NewPackageSource(doer HTTPDoer, ecosystem string, urlFor func(art Artifact) (string, bool)) *PackageSource {
	return &PackageSource{doer: doer, ecosystem: ecosystem, urlFor: urlFor}
}

// Fetch implements Source. It retrieves the registry's attestation document and
// decodes every Sigstore bundle it carries into DSSE attestation material.
func (p *PackageSource) Fetch(ctx context.Context, art Artifact) (*Material, error) {
	if p.urlFor == nil {
		return nil, ErrNotApplicable
	}
	rawURL, ok := p.urlFor(art)
	if !ok {
		return nil, ErrNotApplicable
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := p.doer.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<16))
		_ = resp.Body.Close()
	}()

	// A 404 means the package simply has no published attestations — not an error.
	if resp.StatusCode == http.StatusNotFound {
		return nil, nil
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("sigverify/%s: attestations request returned status %d", p.ecosystem, resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxAttestationBytes))
	if err != nil {
		return nil, err
	}

	atts, err := parseAttestationDocument(body)
	if err != nil {
		return nil, fmt.Errorf("sigverify/%s: %w", p.ecosystem, err)
	}
	if len(atts) == 0 {
		return nil, nil
	}
	return &Material{Source: p.ecosystem + "-attestations", Attestations: atts}, nil
}

// attestationDocument captures the response shapes registries use to expose
// Sigstore attestations: npm's {"attestations":[{"bundle":...}]} and PEP 740's
// {"attestation_bundles":[{"attestations":[{"envelope":...,"verification_material":...}]}]}.
type attestationDocument struct {
	Attestations []struct {
		Bundle json.RawMessage `json:"bundle"`
		// PEP 740 inline form.
		Envelope             *Envelope                   `json:"envelope"`
		VerificationMaterial *bundleVerificationMaterial `json:"verification_material"`
	} `json:"attestations"`
	AttestationBundles []struct {
		Attestations []struct {
			Envelope             *Envelope                   `json:"envelope"`
			VerificationMaterial *bundleVerificationMaterial `json:"verification_material"`
		} `json:"attestations"`
	} `json:"attestation_bundles"`
}

// sigstoreBundle is the Sigstore bundle (protobuf-JSON) carrying the signing
// certificate and the DSSE envelope.
type sigstoreBundle struct {
	MediaType            string                     `json:"mediaType"`
	VerificationMaterial bundleVerificationMaterial `json:"verificationMaterial"`
	DSSEEnvelope         *Envelope                  `json:"dsseEnvelope"`
}

// bundleVerificationMaterial carries the signing certificate (single, v0.3+) or
// chain (older bundles) plus transparency-log entries.
type bundleVerificationMaterial struct {
	Certificate *struct {
		RawBytes string `json:"rawBytes"`
	} `json:"certificate"`
	X509CertificateChain *struct {
		Certificates []struct {
			RawBytes string `json:"rawBytes"`
		} `json:"certificates"`
	} `json:"x509CertificateChain"`
	TlogEntries []json.RawMessage `json:"tlogEntries"`
}

// certificates parses the leaf certificate and chain from verification material.
func (m *bundleVerificationMaterial) certificates() (leaf *x509.Certificate, chain []*x509.Certificate) {
	var raws []string
	if m.Certificate != nil && m.Certificate.RawBytes != "" {
		raws = append(raws, m.Certificate.RawBytes)
	}
	if m.X509CertificateChain != nil {
		for _, c := range m.X509CertificateChain.Certificates {
			if c.RawBytes != "" {
				raws = append(raws, c.RawBytes)
			}
		}
	}
	var certs []*x509.Certificate
	for _, raw := range raws {
		der, err := base64.StdEncoding.DecodeString(raw)
		if err != nil {
			continue
		}
		if cert, err := x509.ParseCertificate(der); err == nil {
			certs = append(certs, cert)
		}
	}
	if len(certs) == 0 {
		return nil, nil
	}
	return certs[0], certs[1:]
}

// parseAttestationDocument decodes a registry attestation response into DSSE
// attestation material, tolerating npm's bundle-wrapped form and PEP 740's
// inline envelope form.
func parseAttestationDocument(body []byte) ([]DSSEAttestation, error) {
	var doc attestationDocument
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, fmt.Errorf("decoding attestation document: %w", err)
	}

	var out []DSSEAttestation
	for _, a := range doc.Attestations {
		if len(a.Bundle) > 0 {
			if att, ok := attestationFromBundle(a.Bundle); ok {
				out = append(out, att)
			}
			continue
		}
		if a.Envelope != nil {
			out = append(out, attestationFromInline(a.Envelope, a.VerificationMaterial))
		}
	}
	for _, b := range doc.AttestationBundles {
		for _, a := range b.Attestations {
			if a.Envelope != nil {
				out = append(out, attestationFromInline(a.Envelope, a.VerificationMaterial))
			}
		}
	}
	return out, nil
}

// attestationFromBundle decodes a Sigstore bundle into attestation material.
func attestationFromBundle(raw json.RawMessage) (DSSEAttestation, bool) {
	var b sigstoreBundle
	if err := json.Unmarshal(raw, &b); err != nil || b.DSSEEnvelope == nil {
		return DSSEAttestation{}, false
	}
	leaf, chain := b.VerificationMaterial.certificates()
	return DSSEAttestation{Envelope: b.DSSEEnvelope, Cert: leaf, Chain: chain}, true
}

// attestationFromInline builds attestation material from a PEP 740 inline
// envelope + verification material.
func attestationFromInline(env *Envelope, vm *bundleVerificationMaterial) DSSEAttestation {
	att := DSSEAttestation{Envelope: env}
	if vm != nil {
		att.Cert, att.Chain = vm.certificates()
	}
	return att
}
