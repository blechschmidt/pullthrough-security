package sigverify

import (
	"encoding/base64"
	"encoding/json"
	"strings"

	"github.com/blechschmidt/pullthrough-security/internal/rekor"
)

// This file defines the wire formats the gate parses: cosign "simple signing"
// payloads, DSSE envelopes, in-toto statements, SLSA provenance predicates, and
// the cosign Rekor bundle annotation. They are hand-rolled (the project depends
// on no Sigstore libraries) and mirror the equivalent unexported types in the
// provenance subsystem, kept here so the gate is a self-contained, independently
// testable unit.

const (
	// dssePayloadType is the in-toto DSSE payload type cosign uses for
	// attestations.
	dssePayloadType = "application/vnd.in-toto+json"

	// simpleSigningType is the payload type of a cosign image signature.
	simpleSigningType = "cosign container image signature"

	// In-toto / SLSA predicate type identifiers recognized for provenance.
	inTotoStatementV1  = "https://in-toto.io/Statement/v1"
	inTotoStatementV01 = "https://in-toto.io/Statement/v0.1"
	predicateSLSAv1    = "https://slsa.dev/provenance/v1"
	predicateSLSAv02   = "https://slsa.dev/provenance/v0.2"
	predicateSLSAv01   = "https://slsa.dev/provenance/v0.1"
)

// cosign OCI layer annotation keys.
const (
	annoSignature   = "dev.cosignproject.cosign/signature"
	annoCertificate = "dev.sigstore.cosign/certificate"
	annoChain       = "dev.sigstore.cosign/chain"
	annoBundle      = "dev.sigstore.cosign/bundle"
)

// Envelope is a DSSE (Dead Simple Signing Envelope, https://github.com/
// secure-systems-lab/dsse) carrying a base64 payload and one or more
// base64-encoded signatures over the payload's pre-authentication encoding.
type Envelope struct {
	PayloadType string              `json:"payloadType"`
	Payload     string              `json:"payload"`
	Signatures  []EnvelopeSignature `json:"signatures"`
}

// EnvelopeSignature is one signature within a DSSE envelope.
type EnvelopeSignature struct {
	KeyID string `json:"keyid,omitempty"`
	Sig   string `json:"sig"`
}

// decodePayload returns the decoded payload bytes of a DSSE envelope.
func (e *Envelope) decodePayload() ([]byte, error) {
	return base64.StdEncoding.DecodeString(e.Payload)
}

// Statement is an in-toto Statement: the subject(s) an attestation is about and
// the predicate (type + body) asserted over them.
type Statement struct {
	Type          string          `json:"_type"`
	PredicateType string          `json:"predicateType"`
	Subject       []Subject       `json:"subject"`
	Predicate     json.RawMessage `json:"predicate"`
}

// Subject is one artifact an in-toto Statement binds, identified by name and a
// map of digest algorithm to lower-hex digest.
type Subject struct {
	Name   string            `json:"name"`
	Digest map[string]string `json:"digest"`
}

// parseStatement decodes an in-toto Statement from a DSSE payload.
func parseStatement(payload []byte) (*Statement, error) {
	var st Statement
	if err := json.Unmarshal(payload, &st); err != nil {
		return nil, err
	}
	return &st, nil
}

// BindsDigest reports whether any subject of the statement carries the given
// "<algo>:<hex>" content digest. An attestation that does not bind the artifact
// being served is irrelevant and must not be accepted for it.
func (st *Statement) BindsDigest(digest string) bool {
	algo, hex, ok := strings.Cut(strings.ToLower(strings.TrimSpace(digest)), ":")
	if !ok || hex == "" {
		return false
	}
	for _, s := range st.Subject {
		for a, h := range s.Digest {
			if strings.EqualFold(a, algo) && strings.EqualFold(h, hex) {
				return true
			}
		}
	}
	return false
}

// IsSLSAProvenance reports whether the statement's predicate is a SLSA
// provenance predicate of any recognized version.
func (st *Statement) IsSLSAProvenance() bool {
	switch st.PredicateType {
	case predicateSLSAv1, predicateSLSAv02, predicateSLSAv01:
		return true
	default:
		return strings.HasPrefix(st.PredicateType, "https://slsa.dev/provenance/")
	}
}

// slsaProvenance models the fields of a SLSA provenance predicate (v0.x and v1
// layouts) needed to surface the source repository and revision.
type slsaProvenance struct {
	// v1 layout.
	BuildDefinition struct {
		ResolvedDependencies []slsaResource `json:"resolvedDependencies"`
	} `json:"buildDefinition"`
	RunDetails struct {
		Builder struct {
			ID string `json:"id"`
		} `json:"builder"`
	} `json:"runDetails"`
	// v0.x layout.
	Builder struct {
		ID string `json:"id"`
	} `json:"builder"`
	Invocation struct {
		ConfigSource struct {
			URI    string            `json:"uri"`
			Digest map[string]string `json:"digest"`
		} `json:"configSource"`
	} `json:"invocation"`
	Materials []slsaResource `json:"materials"`
}

// slsaResource is a SLSA materials/resolvedDependencies entry (a URI + digest).
type slsaResource struct {
	URI    string            `json:"uri"`
	Digest map[string]string `json:"digest"`
}

// SourceRef summarizes the build provenance of an attested artifact.
type SourceRef struct {
	RepositoryURL string
	CommitSHA     string
	BuilderID     string
}

// SourceRef extracts the source repository, commit, and builder identity from a
// SLSA provenance statement, reconciling the v0.x and v1 layouts. The boolean is
// false when the statement is not SLSA provenance or carries no source.
func (st *Statement) SourceRef() (SourceRef, bool) {
	if !st.IsSLSAProvenance() || len(st.Predicate) == 0 {
		return SourceRef{}, false
	}
	var p slsaProvenance
	if err := json.Unmarshal(st.Predicate, &p); err != nil {
		return SourceRef{}, false
	}

	ref := SourceRef{BuilderID: firstNonEmpty(p.RunDetails.Builder.ID, p.Builder.ID)}

	// v0.x: configSource is the canonical build entry point.
	if uri := p.Invocation.ConfigSource.URI; uri != "" {
		ref.RepositoryURL, ref.CommitSHA = repoAndCommit(uri, p.Invocation.ConfigSource.Digest)
	}
	// Fall back to the first source-control material/dependency.
	if ref.RepositoryURL == "" {
		for _, m := range append(append([]slsaResource{}, p.Materials...), p.BuildDefinition.ResolvedDependencies...) {
			if repo, commit := repoAndCommit(m.URI, m.Digest); repo != "" {
				ref.RepositoryURL, ref.CommitSHA = repo, commit
				break
			}
		}
	}
	if ref.RepositoryURL == "" && ref.CommitSHA == "" && ref.BuilderID == "" {
		return SourceRef{}, false
	}
	return ref, true
}

// repoAndCommit normalizes a source-control URI (git+https://..., a bare repo
// URL, or "https://github.com/o/r@<sha>") and digest map into a repository URL
// and commit SHA.
func repoAndCommit(uri string, digest map[string]string) (repo, commit string) {
	if uri == "" {
		return "", ""
	}
	commit = digest["gitCommit"]
	if commit == "" {
		commit = digest["sha1"]
	}
	u := uri
	u = strings.TrimPrefix(u, "git+")
	// Strip a trailing "@<ref>" pin, capturing it as the commit when no digest
	// was supplied.
	if at := strings.LastIndex(u, "@"); at > strings.Index(u, "://") && at != -1 {
		if commit == "" {
			commit = u[at+1:]
		}
		u = u[:at]
	}
	u = strings.TrimSuffix(u, ".git")
	if !strings.HasPrefix(u, "http://") && !strings.HasPrefix(u, "https://") {
		// Only surface canonical http(s) repository URLs.
		if strings.HasPrefix(u, "github.com/") || strings.HasPrefix(u, "gitlab.com/") || strings.HasPrefix(u, "bitbucket.org/") {
			u = "https://" + u
		} else {
			return "", commit
		}
	}
	return u, commit
}

// simpleSigningPayload is the cosign "simple signing" payload bound by an image
// signature: it pins the manifest digest the signature is over.
type simpleSigningPayload struct {
	Critical struct {
		Identity struct {
			DockerReference string `json:"docker-reference"`
		} `json:"identity"`
		Image struct {
			DockerManifestDigest string `json:"docker-manifest-digest"`
		} `json:"image"`
		Type string `json:"type"`
	} `json:"critical"`
}

// bindsDigest reports whether a cosign simple-signing payload pins the given
// manifest digest.
func (p *simpleSigningPayload) bindsDigest(digest string) bool {
	got := strings.TrimSpace(p.Critical.Image.DockerManifestDigest)
	return got != "" && strings.EqualFold(got, strings.TrimSpace(digest))
}

// rekorBundle is the cosign transparency-log bundle stored in the
// dev.sigstore.cosign/bundle annotation. It carries the Rekor log entry and a
// Signed Entry Timestamp (SET): an ECDSA signature, by the Rekor log key, over
// the canonicalized payload, which is the practical proof of public-log
// inclusion the gate verifies.
type rekorBundle struct {
	SignedEntryTimestamp string         `json:"SignedEntryTimestamp"`
	Payload              rekorBundlePay `json:"Payload"`
	// InclusionProof is the RFC 6962 Merkle audit path, present in newer Rekor
	// bundle/entry formats (Task 142). The classic cosign bundle carries only the
	// SET; when a proof is present the gate can additionally prove public-log
	// inclusion up to a signed tree head.
	InclusionProof *rekorInclusionProof `json:"InclusionProof,omitempty"`
	rawPayload     json.RawMessage      `json:"-"`
}

type rekorBundlePay struct {
	Body           string `json:"body"`
	IntegratedTime int64  `json:"integratedTime"`
	LogIndex       int64  `json:"logIndex"`
	LogID          string `json:"logID"`
}

// rekorInclusionProof mirrors the inclusion-proof block a Rekor entry carries.
type rekorInclusionProof struct {
	LogIndex   int64    `json:"logIndex"`
	RootHash   string   `json:"rootHash"`
	TreeSize   int64    `json:"treeSize"`
	Hashes     []string `json:"hashes"`
	Checkpoint string   `json:"checkpoint,omitempty"`
}

// parseRekorBundle decodes a cosign bundle annotation value.
func parseRekorBundle(raw string) (*rekorBundle, bool) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, false
	}
	var b rekorBundle
	if err := json.Unmarshal([]byte(raw), &b); err != nil {
		return nil, false
	}
	if b.SignedEntryTimestamp == "" {
		return nil, false
	}
	return &b, true
}

// toLogEntry maps a cosign/Rekor bundle onto the shared rekor.LogEntry shape so
// SET and inclusion-proof verification run through the dedicated internal/rekor
// verifier (Task 142) rather than being duplicated here.
func (b *rekorBundle) toLogEntry() *rekor.LogEntry {
	entry := &rekor.LogEntry{
		LogID:          b.Payload.LogID,
		LogIndex:       b.Payload.LogIndex,
		Body:           b.Payload.Body,
		IntegratedTime: b.Payload.IntegratedTime,
		SET:            b.SignedEntryTimestamp,
	}
	if ip := b.InclusionProof; ip != nil {
		entry.InclusionProof = &rekor.InclusionProof{
			LogIndex:   ip.LogIndex,
			RootHash:   ip.RootHash,
			TreeSize:   ip.TreeSize,
			Hashes:     ip.Hashes,
			Checkpoint: ip.Checkpoint,
		}
	}
	return entry
}

// canonicalPayload reproduces the byte sequence the Rekor SET is computed over:
// the bundle payload serialized as canonical JSON with keys sorted
// (body, integratedTime, logID, logIndex). Encoding it by hand avoids depending
// on a canonical-JSON library and matches Rekor's marshaling.
func (b *rekorBundle) canonicalPayload() []byte {
	type canon struct {
		Body           string `json:"body"`
		IntegratedTime int64  `json:"integratedTime"`
		LogID          string `json:"logID"`
		LogIndex       int64  `json:"logIndex"`
	}
	out, _ := json.Marshal(canon{
		Body:           b.Payload.Body,
		IntegratedTime: b.Payload.IntegratedTime,
		LogID:          b.Payload.LogID,
		LogIndex:       b.Payload.LogIndex,
	})
	return out
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}
