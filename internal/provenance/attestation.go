package provenance

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
)

// This file parses the on-the-wire attestation formats the proxy understands and
// extracts, from a *verified* attestation, the (source repository, commit) pair
// it binds an artifact to.
//
// The formats, innermost to outermost:
//
//   - in-toto Statement: the signed payload. It lists one or more subjects (each
//     a name + content digest) and a typed predicate. The SLSA provenance
//     predicate is the one that records where/how the artifact was built.
//   - DSSE envelope (Dead Simple Signing Envelope): wraps the in-toto Statement
//     (as the payload) with a payloadType and one or more signatures. This is
//     what cosign/Sigstore and GitHub sign.
//   - Sigstore bundle: a DSSE envelope plus the verification material (the
//     signing certificate chain) needed to verify it. GitHub's attestation API
//     and `cosign download attestation`/the OCI referrers API serve these.
//
// SECURITY: parsing never establishes trust. A parsed attestation is only
// actionable after (a) its DSSE signature verifies against a certificate that
// chains to a trusted root (verify.go) and (b) one of its subject digests equals
// the digest of the artifact actually being consumed (BindsDigest). Skipping
// either check lets an attacker present a perfectly valid attestation that
// describes a *different*, benign artifact and have it accepted for a malicious
// one.

// inTotoPredicateType values we recognize. Both the SLSA v0.2 and v1 provenance
// predicate shapes are handled; GitHub build provenance emits v1.
const (
	predicateSLSAv1   = "https://slsa.dev/provenance/v1"
	predicateSLSAv02  = "https://slsa.dev/provenance/v0.2"
	predicateSLSAv01  = "https://slsa.dev/provenance/v0.1"
	inTotoStatementV1 = "https://in-toto.io/Statement/v1"
	dssePayloadType   = "application/vnd.in-toto+json"
)

// dsseEnvelope is a Dead Simple Signing Envelope (DSSE). Payload is the
// base64-encoded in-toto Statement; PayloadType is bound into the signature via
// PAE (see verify.go) so it cannot be swapped.
type dsseEnvelope struct {
	PayloadType string          `json:"payloadType"`
	Payload     string          `json:"payload"`
	Signatures  []dsseSignature `json:"signatures"`
}

type dsseSignature struct {
	KeyID string `json:"keyid,omitempty"`
	Sig   string `json:"sig"`
}

// decodedPayload returns the raw in-toto Statement bytes that were signed.
func (e *dsseEnvelope) decodedPayload() ([]byte, error) {
	if e.Payload == "" {
		return nil, fmt.Errorf("provenance: DSSE envelope has empty payload")
	}
	// DSSE mandates standard base64 (RFC 4648 §4) for the payload.
	raw, err := base64.StdEncoding.DecodeString(e.Payload)
	if err != nil {
		return nil, fmt.Errorf("provenance: decoding DSSE payload: %w", err)
	}
	return raw, nil
}

// inTotoStatement is the signed claim: a set of subjects and a typed predicate.
type inTotoStatement struct {
	Type          string            `json:"_type"`
	Subject       []inTotoSubject   `json:"subject"`
	PredicateType string            `json:"predicateType"`
	Predicate     json.RawMessage   `json:"predicate"`
	rawDigests    map[string]string // memoized union of subject digests (lower-hex)
}

type inTotoSubject struct {
	Name   string            `json:"name"`
	Digest map[string]string `json:"digest"`
}

// parseStatement decodes the in-toto Statement from raw payload bytes.
func parseStatement(payload []byte) (*inTotoStatement, error) {
	var stmt inTotoStatement
	if err := json.Unmarshal(payload, &stmt); err != nil {
		return nil, fmt.Errorf("provenance: decoding in-toto statement: %w", err)
	}
	if len(stmt.Subject) == 0 {
		return nil, fmt.Errorf("provenance: in-toto statement has no subjects")
	}
	return &stmt, nil
}

// BindsDigest reports whether any subject of the statement carries the given
// content digest. This is the binding check that ties an attestation to the
// specific artifact bytes the proxy cached: it must pass before the attestation's
// source claim is attributed to that artifact.
//
// want is a content digest in "<algorithm>:<hex>" form (e.g. the OCI manifest or
// blob digest, or a package tarball's sha256). Comparison is case-insensitive on
// the hex and exact on the algorithm.
func (s *inTotoStatement) BindsDigest(want string) bool {
	algo, hex, ok := splitDigest(want)
	if !ok {
		return false
	}
	for _, subj := range s.Subject {
		if got, ok := subj.Digest[algo]; ok && strings.EqualFold(got, hex) {
			return true
		}
	}
	return false
}

// subjectName returns the first subject name, for diagnostics.
func (s *inTotoStatement) subjectName() string {
	if len(s.Subject) > 0 {
		return s.Subject[0].Name
	}
	return ""
}

// slsaProvenance is the subset of the SLSA provenance predicate (v0.1, v0.2 and
// v1) we read to recover the source repository and commit. The two schema
// generations name the fields differently, so both layouts are unmarshaled and
// reconciled in sourceRef.
type slsaProvenance struct {
	// v1 layout.
	BuildDefinition struct {
		ExternalParameters   json.RawMessage `json:"externalParameters"`
		ResolvedDependencies []slsaResource  `json:"resolvedDependencies"`
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

// slsaResource is a SLSA material / resolved dependency: a URI and digest set.
type slsaResource struct {
	URI    string            `json:"uri"`
	Digest map[string]string `json:"digest"`
}

// SourceRef is the source coordinate recovered from a provenance predicate.
type SourceRef struct {
	// RepositoryURL is the canonical https URL of the source repository.
	RepositoryURL string
	// CommitSHA is the git revision the artifact was built from, when present.
	CommitSHA string
	// BuilderID identifies the build platform (e.g. the GitHub Actions runner).
	BuilderID string
}

// gitCommitRE matches a full (40-hex) or sha-256 (64-hex) git object name.
var gitCommitRE = regexp.MustCompile(`\b([0-9a-f]{40}|[0-9a-f]{64})\b`)

// sourceRef extracts the source repository and commit from a SLSA provenance
// predicate. It tolerates the schema differences across SLSA versions and the
// various URI encodings build systems emit (git+https://…@<sha>,
// https://github.com/o/r, scheme-less host/path, …).
func (s *inTotoStatement) sourceRef() (SourceRef, bool) {
	if !isSLSAPredicate(s.PredicateType) {
		return SourceRef{}, false
	}
	var p slsaProvenance
	if err := json.Unmarshal(s.Predicate, &p); err != nil {
		return SourceRef{}, false
	}

	ref := SourceRef{BuilderID: firstNonEmpty(p.RunDetails.Builder.ID, p.Builder.ID)}

	// Preferred source: the v1 externalParameters often carry the workflow ref;
	// the most reliable repo+commit pair is a resolvedDependency / material whose
	// URI is the source repo and whose digest carries gitCommit.
	candidates := append([]slsaResource{}, p.BuildDefinition.ResolvedDependencies...)
	candidates = append(candidates, p.Materials...)
	if cs := p.Invocation.ConfigSource; cs.URI != "" {
		candidates = append(candidates, slsaResource{URI: cs.URI, Digest: cs.Digest})
	}
	// v1 externalParameters frequently embed {"workflow":{"repository":...,"ref":...}}.
	if repo, sha := sourceFromExternalParameters(p.BuildDefinition.ExternalParameters); repo != "" {
		ref.RepositoryURL = normalizeRepoURL(repo)
		if sha != "" {
			ref.CommitSHA = sha
		}
	}

	for _, c := range candidates {
		repo, commit := repoAndCommit(c)
		if repo == "" {
			continue
		}
		// Prefer a candidate that carries an actual commit; otherwise keep the
		// first repo we saw so a repo-only material still yields a repository link.
		if ref.RepositoryURL == "" {
			ref.RepositoryURL = repo
		}
		if commit != "" {
			ref.RepositoryURL = repo
			ref.CommitSHA = commit
			break
		}
	}

	if ref.RepositoryURL == "" && ref.CommitSHA == "" {
		return SourceRef{}, false
	}
	return ref, true
}

// repoAndCommit pulls a normalized repository URL and (when present) a commit SHA
// out of a single SLSA resource.
func repoAndCommit(r slsaResource) (repo, commit string) {
	if c, ok := r.Digest["gitCommit"]; ok && gitCommitRE.MatchString(strings.ToLower(c)) {
		commit = strings.ToLower(c)
	} else if c, ok := r.Digest["sha1"]; ok && gitCommitRE.MatchString(strings.ToLower(c)) {
		commit = strings.ToLower(c)
	}
	uri := r.URI
	if uri == "" {
		return "", commit
	}
	// A URI of the form "git+https://github.com/o/r@<sha>" carries the commit
	// inline; split it out when the digest set did not already provide one.
	if at := strings.LastIndex(uri, "@"); at > 0 {
		tail := uri[at+1:]
		if gitCommitRE.MatchString(strings.ToLower(tail)) && commit == "" {
			commit = strings.ToLower(tail)
		}
		uri = uri[:at]
	}
	repo = normalizeRepoURL(uri)
	if !looksLikeRepoURL(repo) {
		return "", commit
	}
	return repo, commit
}

// sourceFromExternalParameters reads the GitHub-flavored externalParameters that
// embed the source repository and ref.
func sourceFromExternalParameters(raw json.RawMessage) (repo, sha string) {
	if len(raw) == 0 {
		return "", ""
	}
	var ep struct {
		Workflow struct {
			Repository string `json:"repository"`
			Ref        string `json:"ref"`
			Path       string `json:"path"`
		} `json:"workflow"`
		Source struct {
			URI    string            `json:"uri"`
			Digest map[string]string `json:"digest"`
		} `json:"source"`
	}
	if err := json.Unmarshal(raw, &ep); err != nil {
		return "", ""
	}
	if ep.Source.URI != "" {
		r, c := repoAndCommit(slsaResource{URI: ep.Source.URI, Digest: ep.Source.Digest})
		if r != "" {
			return r, c
		}
	}
	return ep.Workflow.Repository, ""
}

// isSLSAPredicate reports whether t is a SLSA provenance predicate type.
func isSLSAPredicate(t string) bool {
	switch t {
	case predicateSLSAv1, predicateSLSAv02, predicateSLSAv01:
		return true
	default:
		// Tolerate minor/patch suffixes like ".../provenance/v1?draft".
		return strings.HasPrefix(t, "https://slsa.dev/provenance/")
	}
}

// normalizeRepoURL canonicalizes a repository locator to an "https://host/path"
// form without VCS scheme prefixes, credentials, ".git" suffixes, or fragments,
// so links from different build systems for the same repo compare equal.
func normalizeRepoURL(u string) string {
	u = strings.TrimSpace(u)
	if u == "" {
		return ""
	}
	// Strip VCS pseudo-schemes: git+https://, git+ssh://, git://.
	for _, p := range []string{"git+https://", "git+ssh://", "git+http://", "git://"} {
		if strings.HasPrefix(u, p) {
			u = "https://" + strings.TrimPrefix(u, p)
			break
		}
	}
	// scp-like syntax: git@github.com:owner/repo(.git)
	if strings.HasPrefix(u, "git@") {
		if i := strings.Index(u, ":"); i > 0 {
			u = "https://" + u[len("git@"):i] + "/" + u[i+1:]
		}
	}
	if strings.HasPrefix(u, "ssh://git@") {
		u = "https://" + strings.TrimPrefix(u, "ssh://git@")
	}
	if !strings.Contains(u, "://") {
		// scheme-less host/path.
		u = "https://" + u
	}
	// Drop any fragment and trailing .git.
	if i := strings.IndexByte(u, '#'); i >= 0 {
		u = u[:i]
	}
	u = strings.TrimSuffix(u, "/")
	u = strings.TrimSuffix(u, ".git")
	return u
}

// looksLikeRepoURL is a coarse sanity check that a normalized URL is an http(s)
// repository locator with a host and a path, so opaque material URIs (OCI refs,
// blob digests) are not mistaken for source repos.
func looksLikeRepoURL(u string) bool {
	if !strings.HasPrefix(u, "https://") && !strings.HasPrefix(u, "http://") {
		return false
	}
	rest := u
	rest = strings.TrimPrefix(rest, "https://")
	rest = strings.TrimPrefix(rest, "http://")
	host, path, ok := strings.Cut(rest, "/")
	return ok && host != "" && path != "" && strings.Contains(host, ".")
}

// splitDigest splits "<algorithm>:<hex>" into its parts, lower-casing the hex.
func splitDigest(d string) (algo, hex string, ok bool) {
	algo, hex, ok = strings.Cut(d, ":")
	if !ok || algo == "" || hex == "" {
		return "", "", false
	}
	return algo, strings.ToLower(hex), true
}

func firstNonEmpty(vs ...string) string {
	for _, v := range vs {
		if v != "" {
			return v
		}
	}
	return ""
}
