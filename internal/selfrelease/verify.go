package selfrelease

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime/debug"
	"strings"
)

// Verify runs full self-verification and returns a Report. The returned error is
// non-nil only for operational problems that prevented verification from running
// at all (e.g. the binary could not be located or hashed); a verification
// *failure* is reported via Report.OK=false with failing checks, not via error.
func Verify(opts Options) (*Report, error) {
	id := EmbeddedIdentity()

	binPath, err := resolveBinary(opts.BinaryPath)
	if err != nil {
		return nil, err
	}
	binDigest, err := hashFile(binPath)
	if err != nil {
		return nil, fmt.Errorf("hashing binary %s: %w", binPath, err)
	}
	binBase := filepath.Base(binPath)

	releaseDir := strings.TrimSpace(opts.ReleaseDir)
	if releaseDir == "" {
		releaseDir = filepath.Dir(binPath)
	}

	report := &Report{
		BinaryPath:   binPath,
		BinaryName:   binBase,
		BinaryDigest: binDigest,
		BuildVariant: detectVariant(opts.BinaryPath, binBase),
		ReleaseDir:   releaseDir,
		Identity: IDView{
			CertIdentityPattern: id.IdentityRaw,
			OIDCIssuer:          id.OIDCIssuer,
			BuilderIDPattern:    id.BuilderIDRaw,
			SourceRepository:    id.SourceRepo,
		},
	}

	// --- checksums manifest --------------------------------------------------
	manifestPath, ok := firstExisting(releaseDir, checksumManifestNames...)
	if !ok {
		report.Checks = append(report.Checks, Check{
			Name:   "checksums",
			Status: StatusFail,
			Detail: fmt.Sprintf("no checksums manifest found in %s (expected one of %s)", releaseDir, strings.Join(checksumManifestNames, ", ")),
		})
		report.finish(opts)
		return report, nil
	}
	manifestData, err := os.ReadFile(manifestPath)
	if err != nil {
		report.Checks = append(report.Checks, Check{Name: "checksums", Status: StatusFail, Detail: "reading checksums manifest: " + err.Error()})
		report.finish(opts)
		return report, nil
	}
	manifestBase := filepath.Base(manifestPath)
	checksums := parseChecksums(manifestData)

	report.Checks = append(report.Checks, checksumCheck(binBase, binDigest, checksums, manifestBase))

	// --- signature over the manifest ----------------------------------------
	report.Checks = append(report.Checks, verifySignature(opts, id, releaseDir, manifestPath, manifestBase, manifestData)...)

	// --- SLSA provenance -----------------------------------------------------
	report.Checks = append(report.Checks, verifyProvenance(id, releaseDir, binBase, binDigest))

	// --- SBOM ----------------------------------------------------------------
	report.Checks = append(report.Checks, verifySBOM(releaseDir, binBase, binDigest, checksums))

	// --- Rekor transparency-log inclusion (Task 142) -------------------------
	report.Checks = append(report.Checks, verifyRekor(releaseDir, binBase))

	report.finish(opts)
	return report, nil
}

// checksumCheck verifies the binary's digest is listed in the manifest.
func checksumCheck(binBase, binDigest string, checksums map[string]checksumEntry, manifestBase string) Check {
	const name = "checksums"
	ent, ok := checksums[binBase]
	if !ok {
		return Check{Name: name, Status: StatusFail, Detail: fmt.Sprintf("%s is not listed in %s", binBase, manifestBase)}
	}
	if ent.Hex != bareHex(binDigest) {
		return Check{Name: name, Status: StatusFail, Detail: fmt.Sprintf("binary digest %s does not match %s entry %s", binDigest, manifestBase, ent.Hex)}
	}
	return Check{Name: name, Status: StatusPass, Detail: fmt.Sprintf("binary digest matches the %s entry for %s", manifestBase, binBase)}
}

// finish computes the overall OK verdict.
func (r *Report) finish(opts Options) {
	ok := true
	for _, c := range r.Checks {
		switch c.Status {
		case StatusFail:
			ok = false
		case StatusWarn:
			if opts.RequireCosign {
				ok = false
			}
		}
	}
	r.OK = ok
}

// resolveBinary returns the absolute, symlink-resolved path of the binary to
// verify. An empty path means the running executable.
func resolveBinary(path string) (string, error) {
	if strings.TrimSpace(path) == "" {
		exe, err := os.Executable()
		if err != nil {
			return "", fmt.Errorf("locating the running executable: %w", err)
		}
		path = exe
	}
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		// Fall back to the path as given if symlink resolution fails (e.g. the
		// path does not exist — surfaced as a hashing error next).
		resolved = path
	}
	abs, err := filepath.Abs(resolved)
	if err != nil {
		return resolved, nil
	}
	return abs, nil
}

// detectVariant reports the crypto build variant of the binary under
// verification. When verifying the running executable it reads the embedded
// build settings (GOFIPS140 ⇒ fips); otherwise it infers from the "-fips"
// filename convention `make build-fips`/`make release-fips` use.
func detectVariant(requestedPath, binBase string) string {
	if strings.TrimSpace(requestedPath) == "" {
		if bi, ok := debug.ReadBuildInfo(); ok {
			for _, s := range bi.Settings {
				if s.Key == "GOFIPS140" {
					if v := strings.TrimSpace(s.Value); v != "" && v != "off" {
						return "fips"
					}
				}
			}
		}
	}
	if strings.Contains(binBase, "-fips") {
		return "fips"
	}
	return "standard"
}
