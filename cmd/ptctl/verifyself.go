package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/blechschmidt/pullthrough-security/internal/selfrelease"
)

// runVerifySelf implements `ptctl verify-self [flags]`.
//
// It closes the "trust the tool that enforces trust" loop (Task 135): the proxy
// admits or blocks third-party artifacts on the strength of signatures,
// provenance, and SBOMs, so the proxy's own binary must be verifiable against
// the same class of evidence. verify-self checks the running binary (or a sibling
// named with --binary) against its signed release artifacts:
//
//   - checksums:              the binary's SHA-256 is listed in the signed
//     SHA256SUMS manifest.
//   - signature-identity:     the keyless (Fulcio/OIDC) signature over the
//     manifest verifies and the signer identity + OIDC
//     issuer match the identity embedded in this binary.
//   - signature-transparency: `cosign verify-blob` additionally confirms the
//     Fulcio chain and Rekor inclusion (needs the
//     cosign CLI; a WARN otherwise, FAIL under
//     --require-cosign).
//   - provenance:             a SLSA provenance attestation binds this binary's
//     digest to the embedded expected builder.
//   - sbom:                   a CycloneDX/SPDX SBOM is present and bound to the
//     release.
//
// It is fully self-contained and offline: the expected signer identity travels
// inside the binary, so no network or trust configuration is needed. It exits
// non-zero when verification fails, so it doubles as a deployment-time gate
// (init container, startup probe, or CI smoke test). See docs/self-release.md.
func runVerifySelf(args []string) error {
	fs := flag.NewFlagSet("verify-self", flag.ContinueOnError)
	var (
		binary     = fs.String("binary", "", "path to the binary to verify (default: the running ptctl executable)")
		releaseDir = fs.String("release-dir", os.Getenv("PULLTHROUGH_RELEASE_DIR"), "directory holding the release artifacts: SHA256SUMS, signature, provenance, SBOM (default: the binary's directory; env PULLTHROUGH_RELEASE_DIR)")
		requireCos = fs.Bool("require-cosign", false, "require the cosign CLI for full Fulcio-root + Rekor transparency verification; without it that step is a warning")
		cosignPath = fs.String("cosign", "", "path to the cosign executable (default: 'cosign' on PATH)")
		jsonOut    = fs.Bool("json", false, "emit the verification report as JSON")
		quiet      = fs.Bool("quiet", false, "suppress the report; only set the exit code")
	)
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "Usage: ptctl verify-self [flags]")
		fmt.Fprintln(os.Stderr, "Verify the running binary against its own signed release artifacts (signature, SLSA provenance, SBOM)")
		fmt.Fprintln(os.Stderr, "using the release-signer identity embedded at build time. Exits non-zero if verification fails.")
		fmt.Fprintln(os.Stderr)
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return err
	}

	rep, err := selfrelease.Verify(selfrelease.Options{
		BinaryPath:    *binary,
		ReleaseDir:    *releaseDir,
		RequireCosign: *requireCos,
		CosignPath:    *cosignPath,
	})
	if err != nil {
		return err
	}

	if !*quiet {
		if *jsonOut {
			b, err := json.MarshalIndent(rep, "", "  ")
			if err != nil {
				return fmt.Errorf("rendering JSON: %w", err)
			}
			fmt.Println(string(b))
		} else {
			fmt.Print(rep.Describe())
		}
	}

	if !rep.OK {
		// Signal failure without the generic "ptctl: ..." prefix the top-level
		// error path adds; the report already explains what failed.
		os.Exit(1)
	}
	return nil
}
