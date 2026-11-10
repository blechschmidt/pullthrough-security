package selfrelease

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// Status is the outcome of a single verification check.
type Status string

const (
	// StatusPass: the check ran and succeeded.
	StatusPass Status = "pass"
	// StatusFail: the check ran and failed. Any failing check fails verification.
	StatusFail Status = "fail"
	// StatusWarn: the check could not be fully performed but this does not, on its
	// own, mean the binary is untrusted (e.g. cosign is unavailable so the
	// Fulcio-root + Rekor verification was reduced to the offline cert-identity
	// check). Promoted to a failure when the operator passes --require-cosign /
	// --strict.
	StatusWarn Status = "warn"
	// StatusSkip: the check was intentionally not run.
	StatusSkip Status = "skip"
)

// Check is one named verification step and its result.
type Check struct {
	Name   string `json:"name"`
	Status Status `json:"status"`
	Detail string `json:"detail"`
}

// Report is the complete result of self-verification.
type Report struct {
	BinaryPath   string  `json:"binaryPath"`
	BinaryName   string  `json:"binaryName"`
	BinaryDigest string  `json:"binaryDigest"` // sha256:hex
	BuildVariant string  `json:"buildVariant"` // "standard" or "fips"
	ReleaseDir   string  `json:"releaseDir"`
	Identity     IDView  `json:"expectedIdentity"`
	Checks       []Check `json:"checks"`
	OK           bool    `json:"ok"`
}

// IDView is the embedded expected identity, as surfaced in the report.
type IDView struct {
	CertIdentityPattern string `json:"certIdentityPattern"`
	OIDCIssuer          string `json:"oidcIssuer"`
	BuilderIDPattern    string `json:"builderIdPattern"`
	SourceRepository    string `json:"sourceRepository"`
}

// Options controls verification.
type Options struct {
	// BinaryPath is the binary to verify. Empty means the running executable
	// (os.Executable), i.e. verify-self in the literal sense.
	BinaryPath string
	// ReleaseDir is the directory holding the release sidecar artifacts
	// (SHA256SUMS, signature, provenance, SBOM). Empty means the directory of the
	// binary being verified.
	ReleaseDir string
	// RequireCosign promotes a missing/unusable cosign CLI (and any other WARN)
	// to a hard failure, for environments that mandate full transparency-log
	// verification.
	RequireCosign bool
	// CosignPath overrides the cosign executable lookup (default: "cosign" on
	// PATH). An explicit path that does not exist yields a WARN (or FAIL under
	// RequireCosign).
	CosignPath string
	// Now/Exec are injection points for tests; nil means production defaults.
	runCosign cosignRunner
}

// hashFile returns the "sha256:<hex>" digest of a file.
func hashFile(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return "sha256:" + hex.EncodeToString(h.Sum(nil)), nil
}

// hashBytes returns the "sha256:<hex>" digest of a byte slice.
func hashBytes(b []byte) string {
	sum := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// bareHex strips an optional "sha256:" (or other algo) prefix, returning the
// lowercased hex.
func bareHex(digest string) string {
	d := strings.ToLower(strings.TrimSpace(digest))
	if i := strings.IndexByte(d, ':'); i >= 0 {
		d = d[i+1:]
	}
	return d
}

// checksumEntry is one parsed line of a SHA256SUMS manifest.
type checksumEntry struct {
	Hex  string
	Name string
}

// parseChecksums parses a sha256sum-format manifest: "<64-hex><space><space-or-*><name>".
// Lines that do not parse are ignored (the manifest may carry comments). The
// returned map is keyed by file basename.
func parseChecksums(data []byte) map[string]checksumEntry {
	out := make(map[string]checksumEntry)
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		h := strings.ToLower(fields[0])
		if len(h) != 64 || !isHexString(h) {
			continue
		}
		// The name is the remainder; strip a binary-mode "*" marker and any
		// leading "./".
		name := strings.TrimSpace(strings.Join(fields[1:], " "))
		name = strings.TrimPrefix(name, "*")
		name = strings.TrimPrefix(name, "./")
		base := filepath.Base(name)
		out[base] = checksumEntry{Hex: h, Name: name}
	}
	return out
}

func isHexString(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= '0' && c <= '9':
		case c >= 'a' && c <= 'f':
		default:
			return false
		}
	}
	return len(s) > 0
}

// firstExisting returns the first path (joined under dir) that exists, and
// whether any did.
func firstExisting(dir string, names ...string) (string, bool) {
	for _, n := range names {
		p := filepath.Join(dir, n)
		if fileExists(p) {
			return p, true
		}
	}
	return "", false
}

func fileExists(p string) bool {
	st, err := os.Stat(p)
	return err == nil && !st.IsDir()
}

// glob returns files in dir matching any of the shell patterns, sorted for
// determinism.
func glob(dir string, patterns ...string) []string {
	seen := map[string]bool{}
	var out []string
	for _, pat := range patterns {
		matches, _ := filepath.Glob(filepath.Join(dir, pat))
		for _, m := range matches {
			if fileExists(m) && !seen[m] {
				seen[m] = true
				out = append(out, m)
			}
		}
	}
	sort.Strings(out)
	return out
}

// checksumManifestNames are the accepted checksum-manifest filenames.
var checksumManifestNames = []string{"SHA256SUMS", "SHA256SUMS.txt", "checksums.txt", "sha256sums"}

// describe renders a short multi-line human summary of the report.
func (r *Report) describe() string {
	var b strings.Builder
	status := "VERIFIED"
	if !r.OK {
		status = "FAILED"
	}
	fmt.Fprintf(&b, "self-verification: %s\n", status)
	fmt.Fprintf(&b, "  binary:       %s\n", r.BinaryPath)
	fmt.Fprintf(&b, "  digest:       %s\n", r.BinaryDigest)
	fmt.Fprintf(&b, "  build:        %s variant\n", r.BuildVariant)
	fmt.Fprintf(&b, "  release dir:  %s\n", r.ReleaseDir)
	fmt.Fprintf(&b, "  expect id:    %s\n", r.Identity.CertIdentityPattern)
	fmt.Fprintf(&b, "  expect issuer:%s\n", r.Identity.OIDCIssuer)
	b.WriteString("  checks:\n")
	for _, c := range r.Checks {
		mark := map[Status]string{StatusPass: "✓", StatusFail: "✗", StatusWarn: "!", StatusSkip: "-"}[c.Status]
		fmt.Fprintf(&b, "    %s %-26s %s\n", mark, c.Name, c.Detail)
	}
	return b.String()
}

// Describe is the exported human-readable rendering.
func (r *Report) Describe() string { return r.describe() }
