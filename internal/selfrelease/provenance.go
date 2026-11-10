package selfrelease

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

// provenanceFileNames / globs name the SLSA provenance attestation. The SLSA
// generic generator emits "<something>.intoto.jsonl"; GitHub's
// attest-build-provenance emits a .sigstore(.json) bundle; a plain in-toto
// statement or DSSE envelope is also accepted.
func findProvenance(dir, binaryBase string) []string {
	return glob(dir,
		binaryBase+".intoto.jsonl",
		binaryBase+".sigstore", binaryBase+".sigstore.json",
		binaryBase+".provenance.json", binaryBase+".build.provenance.json",
		"*.intoto.jsonl",
		"provenance.json", "provenance.intoto.jsonl",
		"multiple.intoto.jsonl",
	)
}

// intotoStatement is the subset of the in-toto v1 Statement we verify.
type intotoStatement struct {
	Type          string `json:"_type"`
	PredicateType string `json:"predicateType"`
	Subject       []struct {
		Name   string            `json:"name"`
		Digest map[string]string `json:"digest"`
	} `json:"subject"`
	// Predicate covers both SLSA v0.2 (builder.id at top) and v1
	// (runDetails.builder.id).
	Predicate struct {
		Builder struct {
			ID string `json:"id"`
		} `json:"builder"`
		RunDetails struct {
			Builder struct {
				ID string `json:"id"`
			} `json:"builder"`
		} `json:"runDetails"`
	} `json:"predicate"`
}

func (s *intotoStatement) builderID() string {
	if id := strings.TrimSpace(s.Predicate.RunDetails.Builder.ID); id != "" {
		return id
	}
	return strings.TrimSpace(s.Predicate.Builder.ID)
}

// envelopeShapes is the union of DSSE / sigstore-bundle shapes a provenance line
// may take.
type envelopeShapes struct {
	// DSSE envelope.
	Payload     string `json:"payload"`
	PayloadType string `json:"payloadType"`
	// Sigstore bundle wrapping a DSSE envelope.
	DSSEEnvelope *struct {
		Payload     string `json:"payload"`
		PayloadType string `json:"payloadType"`
	} `json:"dsseEnvelope"`
	// Bare in-toto statement markers.
	StmtType string          `json:"_type"`
	Subject  json.RawMessage `json:"subject"`
}

// extractStatements pulls every in-toto statement out of a provenance file,
// tolerating DSSE envelopes, sigstore bundles, JSONL, and bare statements.
func extractStatements(data []byte) ([]intotoStatement, error) {
	var out []intotoStatement
	// Try as JSONL first (each non-empty line parsed independently), which also
	// handles the single-object case.
	lines := splitJSONLines(data)
	var parseErr error
	for _, line := range lines {
		stmt, err := extractOne(line)
		if err != nil {
			parseErr = err
			continue
		}
		if stmt != nil {
			out = append(out, *stmt)
		}
	}
	if len(out) == 0 {
		if parseErr != nil {
			return nil, parseErr
		}
		return nil, fmt.Errorf("no in-toto statement found in provenance")
	}
	return out, nil
}

func extractOne(line []byte) (*intotoStatement, error) {
	var env envelopeShapes
	if err := json.Unmarshal(line, &env); err != nil {
		return nil, fmt.Errorf("parsing provenance object: %w", err)
	}
	var payloadB64 string
	switch {
	case env.Payload != "":
		payloadB64 = env.Payload
	case env.DSSEEnvelope != nil && env.DSSEEnvelope.Payload != "":
		payloadB64 = env.DSSEEnvelope.Payload
	case env.StmtType != "" && len(env.Subject) > 0:
		// Bare statement.
		var stmt intotoStatement
		if err := json.Unmarshal(line, &stmt); err != nil {
			return nil, fmt.Errorf("parsing bare in-toto statement: %w", err)
		}
		return &stmt, nil
	default:
		// Not a recognized shape; ignore (e.g. a blank or a bundle verification
		// block with no DSSE envelope).
		return nil, nil
	}

	payload, err := base64.StdEncoding.DecodeString(strings.TrimSpace(payloadB64))
	if err != nil {
		return nil, fmt.Errorf("decoding DSSE payload: %w", err)
	}
	var stmt intotoStatement
	if err := json.Unmarshal(payload, &stmt); err != nil {
		return nil, fmt.Errorf("parsing in-toto statement: %w", err)
	}
	return &stmt, nil
}

// splitJSONLines splits data into candidate JSON objects: one per line for
// JSONL, or the whole blob when it is a single multi-line object.
func splitJSONLines(data []byte) [][]byte {
	trimmed := strings.TrimSpace(string(data))
	if trimmed == "" {
		return nil
	}
	// If the whole thing parses as one JSON value, use it as-is (handles
	// pretty-printed multi-line single objects).
	var probe json.RawMessage
	if err := json.Unmarshal([]byte(trimmed), &probe); err == nil {
		return [][]byte{[]byte(trimmed)}
	}
	var out [][]byte
	for _, ln := range strings.Split(trimmed, "\n") {
		ln = strings.TrimSpace(ln)
		if ln == "" {
			continue
		}
		out = append(out, []byte(ln))
	}
	return out
}

// verifyProvenance checks that some provenance attestation names the binary (by
// digest) as a subject and was produced by the embedded expected builder.
func verifyProvenance(id Identity, dir, binaryBase, binaryDigest string) Check {
	const name = "provenance"

	files := findProvenance(dir, binaryBase)
	if len(files) == 0 {
		return Check{Name: name, Status: StatusFail, Detail: fmt.Sprintf("no SLSA provenance attestation found in %s (expected %s.intoto.jsonl or a .sigstore bundle)", dir, binaryBase)}
	}

	wantHex := bareHex(binaryDigest)
	var lastErr string
	for _, f := range files {
		data, err := os.ReadFile(f)
		if err != nil {
			lastErr = err.Error()
			continue
		}
		stmts, err := extractStatements(data)
		if err != nil {
			lastErr = err.Error()
			continue
		}
		for _, stmt := range stmts {
			if !subjectMatches(stmt, binaryBase, wantHex) {
				continue
			}
			// Subject matched; now the builder must match the embedded identity.
			builder := stmt.builderID()
			if builder == "" {
				return Check{Name: name, Status: StatusFail, Detail: fmt.Sprintf("provenance %s names the binary but records no builder id", baseOf(f))}
			}
			if !id.BuilderID.MatchString(builder) {
				return Check{Name: name, Status: StatusFail, Detail: fmt.Sprintf("provenance builder %q does not match the embedded expected builder %q", builder, id.BuilderIDRaw)}
			}
			return Check{Name: name, Status: StatusPass, Detail: fmt.Sprintf("provenance %s binds this binary's digest to builder %q", baseOf(f), builder)}
		}
	}

	detail := fmt.Sprintf("no provenance subject matches this binary's digest %s", binaryDigest)
	if lastErr != "" {
		detail += " (last parse error: " + lastErr + ")"
	}
	return Check{Name: name, Status: StatusFail, Detail: detail}
}

// subjectMatches reports whether any subject carries the wanted sha256 digest.
// The subject name is matched leniently (basename) and is advisory; the digest
// is authoritative.
func subjectMatches(stmt intotoStatement, binaryBase, wantHex string) bool {
	for _, s := range stmt.Subject {
		for algo, h := range s.Digest {
			if strings.EqualFold(algo, "sha256") && strings.EqualFold(strings.TrimSpace(h), wantHex) {
				return true
			}
		}
	}
	return false
}

func baseOf(p string) string {
	if i := strings.LastIndexByte(p, '/'); i >= 0 {
		return p[i+1:]
	}
	return p
}
