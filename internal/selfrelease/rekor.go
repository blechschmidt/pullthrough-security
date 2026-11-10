package selfrelease

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/blechschmidt/pullthrough-security/internal/rekor"
)

// Transparency-log verification for the proxy's own release (Task 142). The
// release pipeline (scripts/release-*.sh) submits the signed release attestation
// to a Sigstore Rekor log and drops the returned log entry next to the binary as
// a "<binary>.rekor.json" sidecar (plus an optional "rekor-pubkey.pem" for the
// log's Signed Entry Timestamp key). verify-self then re-verifies the recorded
// inclusion proof offline, so an operator can confirm the release is publicly
// logged without contacting the log.
//
// The check is advisory by design:
//
//   - No sidecar present  -> SKIP (keyless cosign verification, handled
//     elsewhere, is the primary transparency check; the sidecar is an extra).
//   - Inclusion proof + SET verify -> PASS.
//   - Inclusion proof verifies but no log key is available for the SET -> WARN
//     (promoted to FAIL under --require-cosign/--strict).
//   - Inclusion proof is invalid -> FAIL (the recorded proof does not hold).

// rekorSidecarNames are the accepted Rekor log-entry sidecar filenames.
func rekorSidecarNames(binaryBase string) []string {
	return []string{
		binaryBase + ".rekor.json",
		binaryBase + ".rekor-entry.json",
		"rekor.json",
		"rekor-log-entry.json",
	}
}

// rekorKeyNames are the accepted Rekor log public-key filenames.
var rekorKeyNames = []string{"rekor-pubkey.pem", "rekor.pub", "rekor-public-key.pem"}

// verifyRekor checks a recorded Rekor log entry's inclusion proof (and SET when a
// log key is present) for the released binary.
func verifyRekor(releaseDir, binaryBase string) Check {
	const name = "rekor-transparency"

	path, ok := firstExisting(releaseDir, rekorSidecarNames(binaryBase)...)
	if !ok {
		return Check{Name: name, Status: StatusSkip, Detail: "no Rekor log-entry sidecar found (release transparency relies on cosign/keyless verification)"}
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return Check{Name: name, Status: StatusFail, Detail: "reading Rekor log entry: " + err.Error()}
	}
	var entry rekor.LogEntry
	if err := json.Unmarshal(data, &entry); err != nil {
		return Check{Name: name, Status: StatusFail, Detail: "parsing Rekor log entry: " + err.Error()}
	}
	if entry.InclusionProof == nil {
		return Check{Name: name, Status: StatusWarn, Detail: fmt.Sprintf("Rekor entry %s carries no inclusion proof (only a log index); cannot prove public-log inclusion offline", baseOf(path))}
	}

	// Load the log key for the SET when one is present; the inclusion proof itself
	// is key-independent (it reconstructs the signed root hash).
	var verifier *rekor.Verifier
	haveKey := false
	if keyPath, ok := firstExisting(releaseDir, rekorKeyNames...); ok {
		pemBytes, kerr := os.ReadFile(keyPath)
		if kerr != nil {
			return Check{Name: name, Status: StatusFail, Detail: "reading Rekor public key: " + kerr.Error()}
		}
		v, verr := rekor.NewVerifierFromPEM(pemBytes)
		if verr != nil {
			return Check{Name: name, Status: StatusFail, Detail: "parsing Rekor public key: " + verr.Error()}
		}
		verifier, haveKey = v, true
	} else {
		verifier = rekor.NewVerifier(nil)
	}

	res := verifier.VerifyEntry(&entry)
	if !res.InclusionVerified {
		detail := "Rekor inclusion proof did not reconstruct the signed root hash"
		if res.Err != "" {
			detail += ": " + res.Err
		}
		return Check{Name: name, Status: StatusFail, Detail: detail}
	}
	if !haveKey {
		return Check{Name: name, Status: StatusWarn, Detail: fmt.Sprintf("Rekor inclusion proof verified (log index %d), but no log public key was available to verify the Signed Entry Timestamp", entry.LogIndex)}
	}
	if !res.SETVerified {
		return Check{Name: name, Status: StatusFail, Detail: "Rekor Signed Entry Timestamp did not verify against the configured log public key"}
	}
	return Check{Name: name, Status: StatusPass, Detail: fmt.Sprintf("Rekor inclusion proof and SET verified (log index %d, tree size %d)", entry.LogIndex, entry.InclusionProof.TreeSize)}
}
