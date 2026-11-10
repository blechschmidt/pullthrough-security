// Package rekor is the proxy's Sigstore Rekor transparency-log client and
// inclusion-proof verifier (Task 142). It gives the supply-chain attestation
// subsystem two capabilities:
//
//   - Outbound (attester): when the proxy signs an attestation — a per-served-
//     artifact in-toto bundle (internal/attestbundle, Task 46) or a self-release
//     signature (internal/selfrelease, Task 135) — it can SUBMIT the signed DSSE
//     envelope to a public Rekor transparency log and record the returned log
//     index + inclusion proof, making the claim publicly discoverable and
//     tamper-evident independent of the proxy.
//   - Inbound (verifier): on the signature-verification gate (internal/sigverify,
//     Task 23) it can VERIFY that a presented signature/attestation carries a
//     valid Rekor inclusion proof (an RFC 6962 Merkle audit path to a signed tree
//     head) and a valid Signed Entry Timestamp (SET), the two cryptographic facts
//     that make keyless/Fulcio-style verification trustworthy: not merely "this
//     cert signed this blob" but "a public, append-only log witnessed it".
//
// Design:
//
//   - The transport is behind the Client interface so the gateway wires a real
//     HTTP client (client.go) in production and tests inject a FakeLog (fake.go)
//     that is a genuine in-memory Merkle log — it signs real SETs and produces
//     real inclusion proofs — so the submit→verify round trip is exercised end to
//     end with NO network.
//   - Verification (verify.go + merkle.go) is a pure, dependency-free re-
//     implementation of the two checks, so it is exhaustively unit-testable
//     against committed golden fixtures and shares no live-network code path.
//
// SECURITY: an inclusion proof only proves the entry is in SOME tree with the
// given root hash; trust in that root comes from the SET being signed by a
// configured Rekor log public key (verify.go). A proof that validates against a
// root nobody vouches for is worthless, so VerifyEntry requires both unless the
// caller explicitly relaxes one.
package rekor

import (
	"strings"
	"time"
)

// DefaultPublicURL is the public Sigstore Rekor instance used when no URL is
// configured. Operators running a private log override it via config.
const DefaultPublicURL = "https://rekor.sigstore.dev"

// InclusionProof is an RFC 6962 Merkle audit path proving a leaf's membership in
// a log tree of a given size, up to a signed root hash. It mirrors the shape
// Rekor returns under a log entry's verification block.
type InclusionProof struct {
	// LogIndex is the 0-based index of the leaf within the log tree.
	LogIndex int64 `json:"logIndex"`
	// RootHash is the hex-encoded Merkle tree root the proof reconstructs to.
	RootHash string `json:"rootHash"`
	// TreeSize is the number of leaves in the tree the root commits to.
	TreeSize int64 `json:"treeSize"`
	// Hashes is the ordered list of sibling hashes (hex) forming the audit path.
	Hashes []string `json:"hashes"`
	// Checkpoint is the signed note (STH) the root came from, when present. It is
	// carried for completeness and auditing; verification keys off RootHash + SET.
	Checkpoint string `json:"checkpoint,omitempty"`
}

// LogEntry is the proxy's normalized view of a Rekor log entry (the subset of
// Rekor's LogEntryAnon the proxy consumes and verifies). It is what Submit
// returns and what VerifyEntry checks.
type LogEntry struct {
	// UUID is the entry's Merkle leaf identifier (the Rekor entry UUID).
	UUID string `json:"uuid,omitempty"`
	// LogID is the hex-encoded public key hash identifying the log (shard) the
	// entry lives in.
	LogID string `json:"logID,omitempty"`
	// LogIndex is the global (cross-shard) log index Rekor assigns the entry.
	LogIndex int64 `json:"logIndex"`
	// Body is the base64-encoded canonicalized log entry (the Merkle leaf
	// preimage): SHA-256(0x00 || base64decode(Body)) is the Merkle leaf hash.
	Body string `json:"body"`
	// IntegratedTime is the unix time (seconds) the entry was integrated.
	IntegratedTime int64 `json:"integratedTime"`
	// SET is the base64-encoded Signed Entry Timestamp: the log's signature over
	// the canonicalized (body, integratedTime, logID, logIndex) tuple.
	SET string `json:"signedEntryTimestamp,omitempty"`
	// InclusionProof is the Merkle audit path, when the log returned one.
	InclusionProof *InclusionProof `json:"inclusionProof,omitempty"`
}

// Pointer is the compact, persistable record of a submitted/verified log entry
// that the proxy stores on a bundle, in the dossier, and in the audit log. It
// never carries the full proof — just enough to locate and re-verify the entry.
type Pointer struct {
	// LogIndex is the global log index (the primary locator).
	LogIndex int64 `json:"logIndex"`
	// LogID identifies the log shard.
	LogID string `json:"logID,omitempty"`
	// UUID is the entry UUID.
	UUID string `json:"uuid,omitempty"`
	// IntegratedTime is when the entry was integrated (UTC).
	IntegratedTime time.Time `json:"integratedTime,omitempty"`
	// URL is a best-effort deep link to the entry in the log's UI/API.
	URL string `json:"url,omitempty"`
	// InclusionProofVerified reports the Merkle audit path validated to a root.
	InclusionProofVerified bool `json:"inclusionProofVerified"`
	// SETVerified reports the Signed Entry Timestamp validated against a trusted
	// Rekor log public key.
	SETVerified bool `json:"setVerified"`
	// TreeSize/RootHash capture the signed tree head the inclusion proof anchored
	// to, for later audit. Omitted when no proof was present.
	TreeSize int64  `json:"treeSize,omitempty"`
	RootHash string `json:"rootHash,omitempty"`
}

// Pointer builds a persistable Pointer from a verified log entry. baseURL, when
// non-empty, is used to synthesize the entry deep link.
func (e *LogEntry) Pointer(baseURL string, v Verification) Pointer {
	p := Pointer{
		LogIndex:               e.LogIndex,
		LogID:                  e.LogID,
		UUID:                   e.UUID,
		InclusionProofVerified: v.InclusionVerified,
		SETVerified:            v.SETVerified,
	}
	if e.IntegratedTime > 0 {
		p.IntegratedTime = time.Unix(e.IntegratedTime, 0).UTC()
	}
	if e.InclusionProof != nil {
		p.TreeSize = e.InclusionProof.TreeSize
		p.RootHash = e.InclusionProof.RootHash
	}
	p.URL = entryURL(baseURL, e.UUID, e.LogIndex)
	return p
}

// entryURL synthesizes a best-effort deep link to a Rekor entry. Rekor's REST
// API exposes an entry by UUID at /api/v1/log/entries/<uuid>; when the UUID is
// unknown the global index is used as a fallback locator.
func entryURL(baseURL, uuid string, logIndex int64) string {
	base := strings.TrimRight(strings.TrimSpace(baseURL), "/")
	if base == "" {
		return ""
	}
	if uuid != "" {
		return base + "/api/v1/log/entries/" + uuid
	}
	return base + "/api/v1/log/entries?logIndex=" + itoa(logIndex)
}

func itoa(n int64) string {
	// Small helper to avoid importing strconv just for one call site in several
	// files; kept local and obvious.
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}
