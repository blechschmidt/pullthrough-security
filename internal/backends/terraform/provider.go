package terraform

import (
	"encoding/json"
	"fmt"
)

// The provider registry protocol's "find a provider package" endpoint
//
//	GET /v1/providers/{namespace}/{type}/{version}/download/{os}/{arch}
//
// returns a JSON descriptor naming the release ZIP, its SHA-256, the signed
// SHASUMS manifest and detached signature, and the GPG public keys the registry
// asserts for the provider. The proxy parses it to (a) rewrite the artifact URLs
// so the ZIP and signature material flow through (and are cached by) the proxy,
// and (b) independently verify the ZIP against the signed manifest before it is
// served. See https://developer.hashicorp.com/terraform/internals/provider-registry-protocol.

// gpgPublicKey is one trusted signing key the registry asserts for a provider.
type gpgPublicKey struct {
	KeyID      string `json:"key_id"`
	ASCIIArmor string `json:"ascii_armor"`
	TrustSig   string `json:"trust_signature,omitempty"`
	Source     string `json:"source,omitempty"`
	SourceURL  string `json:"source_url,omitempty"`
}

// providerPackage is the provider-download descriptor. Only the fields the proxy
// reads (or rewrites) are modeled; json.Unmarshal preserves the rest only if the
// caller round-trips through a generic map, so the rewrite path edits a decoded
// map rather than this struct (see rewriteProviderPackage).
type providerPackage struct {
	Protocols           []string `json:"protocols"`
	OS                  string   `json:"os"`
	Arch                string   `json:"arch"`
	Filename            string   `json:"filename"`
	DownloadURL         string   `json:"download_url"`
	ShasumsURL          string   `json:"shasums_url"`
	ShasumsSignatureURL string   `json:"shasums_signature_url"`
	Shasum              string   `json:"shasum"`
	SigningKeys         struct {
		GPGPublicKeys []gpgPublicKey `json:"gpg_public_keys"`
	} `json:"signing_keys"`
}

// parseProviderPackage decodes a provider-download descriptor.
func parseProviderPackage(data []byte) (*providerPackage, error) {
	var p providerPackage
	if err := json.Unmarshal(data, &p); err != nil {
		return nil, fmt.Errorf("terraform: parsing provider descriptor: %w", err)
	}
	if p.Filename == "" {
		return nil, fmt.Errorf("terraform: provider descriptor missing filename")
	}
	if p.DownloadURL == "" {
		return nil, fmt.Errorf("terraform: provider descriptor missing download_url")
	}
	return &p, nil
}

// armoredKeys returns the ASCII-armored public keys for signature verification.
func (p *providerPackage) armoredKeys() []string {
	keys := make([]string, 0, len(p.SigningKeys.GPGPublicKeys))
	for _, k := range p.SigningKeys.GPGPublicKeys {
		if k.ASCIIArmor != "" {
			keys = append(keys, k.ASCIIArmor)
		}
	}
	return keys
}

// primaryKeyID returns the first advertised GPG key id, for diagnostics and the
// admission signal.
func (p *providerPackage) primaryKeyID() string {
	for _, k := range p.SigningKeys.GPGPublicKeys {
		if k.KeyID != "" {
			return k.KeyID
		}
	}
	return ""
}

// rewriteProviderPackage rewrites the artifact-bearing URLs in a decoded
// provider descriptor so a Terraform/OpenTofu client fetches the ZIP and its
// signature material through the proxy (where they are cached and verified)
// rather than directly from the release host. It edits a generic decoded map so
// every other field — protocols, signing_keys, shasum — is preserved byte-for-
// byte for the client's own verification. zipURL/shasumsURL/sigURL are the
// proxy-side endpoints to substitute.
func rewriteProviderPackage(data []byte, zipURL, shasumsURL, sigURL string) ([]byte, error) {
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(data, &obj); err != nil {
		return nil, fmt.Errorf("terraform: re-decoding provider descriptor: %w", err)
	}
	set := func(key, val string) error {
		enc, err := json.Marshal(val)
		if err != nil {
			return err
		}
		obj[key] = enc
		return nil
	}
	if err := set("download_url", zipURL); err != nil {
		return nil, err
	}
	if _, ok := obj["shasums_url"]; ok || shasumsURL != "" {
		if err := set("shasums_url", shasumsURL); err != nil {
			return nil, err
		}
	}
	if _, ok := obj["shasums_signature_url"]; ok || sigURL != "" {
		if err := set("shasums_signature_url", sigURL); err != nil {
			return nil, err
		}
	}
	return json.Marshal(obj)
}
