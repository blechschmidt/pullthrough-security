package rekor

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// Client submits signed attestations to a Rekor transparency log and returns the
// resulting log entry (log index + inclusion proof + SET). It is the transport
// seam: production wires an HTTPClient; tests inject a FakeLog (fake.go) so the
// submit→verify round trip runs with no network.
type Client interface {
	// Submit adds a signed DSSE/in-toto attestation to the log and returns the
	// resulting entry. The returned *LogEntry is never nil on a nil error.
	Submit(ctx context.Context, req SubmitRequest) (*LogEntry, error)
}

// SubmitRequest is a single transparency-log submission: a signed DSSE envelope
// plus the public key that verifies it.
type SubmitRequest struct {
	// Envelope is the raw signed DSSE envelope JSON (the attestation bundle's
	// envelope bytes). Required.
	Envelope []byte
	// PublicKeyPEM is the PEM-encoded public key (or certificate) that verifies
	// the envelope signature. Rekor records it so the entry is self-describing.
	// Required by the public Rekor instance.
	PublicKeyPEM []byte
}

// Doer is the minimal HTTP surface the client needs; *http.Client satisfies it.
// Abstracting it (rather than taking a concrete *http.Client) lets tests supply
// a fake round-tripper without a listening socket.
type Doer interface {
	Do(*http.Request) (*http.Response, error)
}

// HTTPClient is the production Rekor REST client. It POSTs an intoto proposed
// entry to /api/v1/log/entries and parses the returned LogEntryAnon map.
type HTTPClient struct {
	baseURL string
	doer    Doer
}

// HTTPConfig configures an HTTPClient.
type HTTPConfig struct {
	// URL is the Rekor base URL (e.g. https://rekor.sigstore.dev). Empty uses
	// DefaultPublicURL.
	URL string
	// Doer is the HTTP transport. Nil uses an http.Client with Timeout.
	Doer Doer
	// Timeout bounds a single submission when Doer is nil (default 15s).
	Timeout time.Duration
}

// NewHTTPClient constructs a Rekor HTTP client.
func NewHTTPClient(cfg HTTPConfig) *HTTPClient {
	base := strings.TrimRight(strings.TrimSpace(cfg.URL), "/")
	if base == "" {
		base = DefaultPublicURL
	}
	doer := cfg.Doer
	if doer == nil {
		timeout := cfg.Timeout
		if timeout <= 0 {
			timeout = 15 * time.Second
		}
		doer = &http.Client{Timeout: timeout}
	}
	return &HTTPClient{baseURL: base, doer: doer}
}

// BaseURL returns the configured log base URL.
func (c *HTTPClient) BaseURL() string { return c.baseURL }

// Submit implements Client. It builds an intoto v0.0.1 proposed entry around the
// DSSE envelope, POSTs it, and normalizes the response into a *LogEntry.
func (c *HTTPClient) Submit(ctx context.Context, req SubmitRequest) (*LogEntry, error) {
	if len(req.Envelope) == 0 {
		return nil, fmt.Errorf("rekor: submit requires a DSSE envelope")
	}
	body, err := buildIntotoEntry(req)
	if err != nil {
		return nil, err
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/api/v1/log/entries", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("rekor: building request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Accept", "application/json")

	resp, err := c.doer.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("rekor: submitting entry: %w", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))

	// Rekor returns 201 Created on a new entry and 409 Conflict when the entry
	// already exists; both are success from the proxy's perspective (the claim is
	// in the log). Other statuses are errors.
	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusConflict {
		return nil, fmt.Errorf("rekor: submit returned HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(raw)))
	}

	entry, err := parseEntriesResponse(raw)
	if err != nil {
		return nil, err
	}
	return entry, nil
}

// intotoProposedEntry is the Rekor intoto v0.0.1 proposed-entry envelope. The
// log canonicalizes it, stores hashes of the DSSE envelope + payload, and
// returns a LogEntryAnon.
type intotoProposedEntry struct {
	APIVersion string          `json:"apiVersion"`
	Kind       string          `json:"kind"`
	Spec       intotoEntrySpec `json:"spec"`
}

type intotoEntrySpec struct {
	Content   intotoContent `json:"content"`
	PublicKey string        `json:"publicKey"` // base64(PEM)
}

type intotoContent struct {
	Envelope string     `json:"envelope"` // the raw DSSE envelope JSON
	Hash     *rekorHash `json:"hash,omitempty"`
	Payload  *rekorHash `json:"payloadHash,omitempty"`
}

type rekorHash struct {
	Algorithm string `json:"algorithm"`
	Value     string `json:"value"`
}

func buildIntotoEntry(req SubmitRequest) ([]byte, error) {
	if len(req.PublicKeyPEM) == 0 {
		return nil, fmt.Errorf("rekor: submit requires the signer public key (PEM)")
	}
	// Compute the envelope hash so the proposed entry is well-formed even against
	// a strict log; Rekor recomputes/validates it.
	sum := sha256.Sum256(req.Envelope)
	entry := intotoProposedEntry{
		APIVersion: "0.0.1",
		Kind:       "intoto",
		Spec: intotoEntrySpec{
			Content: intotoContent{
				Envelope: string(req.Envelope),
				Hash:     &rekorHash{Algorithm: "sha256", Value: hex.EncodeToString(sum[:])},
			},
			PublicKey: base64.StdEncoding.EncodeToString(req.PublicKeyPEM),
		},
	}
	out, err := json.Marshal(entry)
	if err != nil {
		return nil, fmt.Errorf("rekor: encoding proposed entry: %w", err)
	}
	return out, nil
}

// logEntryAnon mirrors the subset of Rekor's LogEntryAnon the proxy consumes.
type logEntryAnon struct {
	LogID          string             `json:"logID"`
	LogIndex       int64              `json:"logIndex"`
	Body           string             `json:"body"`
	IntegratedTime int64              `json:"integratedTime"`
	Verification   *entryVerification `json:"verification,omitempty"`
}

type entryVerification struct {
	SignedEntryTimestamp string             `json:"signedEntryTimestamp,omitempty"`
	InclusionProof       *rekorInclusionRaw `json:"inclusionProof,omitempty"`
}

type rekorInclusionRaw struct {
	LogIndex   int64    `json:"logIndex"`
	RootHash   string   `json:"rootHash"`
	TreeSize   int64    `json:"treeSize"`
	Hashes     []string `json:"hashes"`
	Checkpoint string   `json:"checkpoint,omitempty"`
}

// parseEntriesResponse normalizes Rekor's "{ <uuid>: LogEntryAnon }" map into a
// single *LogEntry (the proxy submits one entry at a time).
func parseEntriesResponse(raw []byte) (*LogEntry, error) {
	var m map[string]logEntryAnon
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, fmt.Errorf("rekor: decoding log entry response: %w", err)
	}
	if len(m) == 0 {
		return nil, fmt.Errorf("rekor: log entry response contained no entries")
	}
	for uuid, a := range m {
		entry := &LogEntry{
			UUID:           uuid,
			LogID:          a.LogID,
			LogIndex:       a.LogIndex,
			Body:           a.Body,
			IntegratedTime: a.IntegratedTime,
		}
		if a.Verification != nil {
			entry.SET = a.Verification.SignedEntryTimestamp
			if ip := a.Verification.InclusionProof; ip != nil {
				entry.InclusionProof = &InclusionProof{
					LogIndex:   ip.LogIndex,
					RootHash:   ip.RootHash,
					TreeSize:   ip.TreeSize,
					Hashes:     ip.Hashes,
					Checkpoint: ip.Checkpoint,
				}
			}
		}
		return entry, nil
	}
	return nil, fmt.Errorf("rekor: log entry response contained no entries")
}
