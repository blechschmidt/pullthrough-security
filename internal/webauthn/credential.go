package webauthn

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// Credential is a registered passkey bound to an admin subject. The public key
// is stored as the raw COSE key bytes exactly as the authenticator emitted it,
// so it round-trips through durable storage without a lossy re-encoding, and is
// re-parsed on load. The signature counter is the replay/clone defense: it must
// never regress across assertions.
type Credential struct {
	// ID is the base64url (no padding) credential id the authenticator reports.
	ID string `json:"id"`
	// Subject is the admin identity that enrolled the credential.
	Subject string `json:"subject"`
	// Label is an operator-supplied display name ("YubiKey 5C", "iCloud").
	Label string `json:"label"`
	// COSEKey is the credential public key, base64url-encoded COSE_Key CBOR.
	COSEKey string `json:"coseKey"`
	// AAGUID identifies the authenticator model (base64url), informational.
	AAGUID string `json:"aaguid,omitempty"`
	// SignCount is the last observed authenticator signature counter.
	SignCount uint32 `json:"signCount"`
	// AttestationFormat and AttestationVerified record the registration-time
	// attestation outcome for audit/display.
	AttestationFormat   string `json:"attestationFormat,omitempty"`
	AttestationVerified bool   `json:"attestationVerified"`
	// Transports are the authenticator transports the client advertised.
	Transports []string `json:"transports,omitempty"`

	CreatedAt time.Time `json:"createdAt"`
	LastUsed  time.Time `json:"lastUsed,omitempty"`
}

// CredentialView is the redacted public projection returned to the admin UI and
// API: it never exposes the raw public key material, only the fields an operator
// needs to recognise and manage a credential.
type CredentialView struct {
	ID                  string    `json:"id"`
	Label               string    `json:"label"`
	AAGUID              string    `json:"aaguid,omitempty"`
	SignCount           uint32    `json:"signCount"`
	AttestationFormat   string    `json:"attestationFormat,omitempty"`
	AttestationVerified bool      `json:"attestationVerified"`
	Transports          []string  `json:"transports,omitempty"`
	CreatedAt           time.Time `json:"createdAt"`
	LastUsed            time.Time `json:"lastUsed,omitempty"`
}

func (c *Credential) view() CredentialView {
	return CredentialView{
		ID:                  c.ID,
		Label:               c.Label,
		AAGUID:              c.AAGUID,
		SignCount:           c.SignCount,
		AttestationFormat:   c.AttestationFormat,
		AttestationVerified: c.AttestationVerified,
		Transports:          c.Transports,
		CreatedAt:           c.CreatedAt,
		LastUsed:            c.LastUsed,
	}
}

// coseKey decodes and parses the stored COSE public key.
func (c *Credential) coseKey() (*coseKey, error) {
	raw, err := b64urlDecode(c.COSEKey)
	if err != nil {
		return nil, fmt.Errorf("webauthn: decoding stored COSE key: %w", err)
	}
	v, err := cborDecode(raw)
	if err != nil {
		return nil, err
	}
	m, ok := v.(map[any]any)
	if !ok {
		return nil, fmt.Errorf("webauthn: stored COSE key is not a CBOR map")
	}
	return parseCOSEKey(m)
}

// store is the subsystem's durable sidecar: the per-subject credential set
// persisted to a private JSON file via atomic temp-file + rename, following the
// continuity/approvals pattern. An empty path means in-memory only.
type store struct {
	path string
}

// persistedState is the on-disk representation of the credential set.
type persistedState struct {
	Version     int           `json:"version"`
	Credentials []*Credential `json:"credentials"`
	UpdatedAt   time.Time     `json:"updatedAt"`
}

const storeVersion = 1

// load reads the credential file into the service's in-memory index. A missing
// file is not an error (first run); a corrupt file is.
func (st *store) load(s *Service) error {
	if st.path == "" {
		return nil
	}
	data, err := os.ReadFile(st.path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	var ps persistedState
	if err := json.Unmarshal(data, &ps); err != nil {
		return fmt.Errorf("webauthn: parsing credential store: %w", err)
	}
	for _, c := range ps.Credentials {
		if c == nil || c.ID == "" || c.Subject == "" {
			continue
		}
		s.creds[c.Subject] = append(s.creds[c.Subject], c)
	}
	return nil
}

// persistLocked atomically writes the credential set. Best-effort: a write
// failure is logged by the caller but never fails the ceremony in progress
// (the in-memory state remains authoritative for the process lifetime). The
// caller must hold s.mu.
func (st *store) persistLocked(s *Service) error {
	if st.path == "" {
		return nil
	}
	ps := persistedState{Version: storeVersion, UpdatedAt: s.now()}
	for _, list := range s.creds {
		ps.Credentials = append(ps.Credentials, list...)
	}
	data, err := json.MarshalIndent(ps, "", "  ")
	if err != nil {
		return err
	}
	return atomicWrite(st.path, data)
}

// atomicWrite writes data to path via a temp file in the same directory followed
// by an atomic rename, creating the directory if needed.
func atomicWrite(path string, data []byte) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".webauthn-*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, path)
}
