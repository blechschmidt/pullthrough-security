package locate

import (
	"archive/zip"
	"bytes"
	"crypto/md5"  //nolint:gosec // lock files record MD5 digests (conda, CRAN); checked, never trusted alone
	"crypto/sha1" //nolint:gosec // npm/yarn record SHA-1 integrity next to SHA-512; checked, never trusted alone
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"io"
	"os"
	"sort"
	"strings"
)

// Outcomes of checking an artifact against the lock file (CheckResult.Status).
const (
	// CheckVerified: every digest the lock file records for the object was
	// computed over the bytes served, and each matched.
	CheckVerified = "verified"
	// CheckMismatch: a digest the lock file records does not match the bytes
	// served. The object is not pinned for the release.
	CheckMismatch = "mismatch"
	// CheckUnverified: the lock file records no digest of the object; it is
	// pinned as served (trust on first use).
	CheckUnverified = "unverified"
	// CheckUnchecked: the lock file's digests are of something the proxy does
	// not compute (a signature-less NuGet package, Yarn's cache zip, a Git
	// tree); the backend's own verification is what stands.
	CheckUnchecked = "unchecked"
)

// CheckResult is the outcome of checking one artifact.
type CheckResult struct {
	Status string `json:"status"`
	// Checked lists the algorithms computed and compared ("sha512", "h1").
	Checked []string `json:"checked,omitempty"`
	// Unchecked lists the digest kinds that could not be compared.
	Unchecked []string `json:"unchecked,omitempty"`
	// Detail explains a mismatch or an unchecked digest.
	Detail string `json:"detail,omitempty"`
	// SHA256 is "sha256:<hex>" of the bytes served; Size their length.
	SHA256 string `json:"sha256,omitempty"`
	Size   int64  `json:"size"`
	// Computed are the digests Artifact.Compute asked for, by algorithm:
	// lower-case hex, or for "h1" the base64 text. ComputeError says why one
	// asked for could not be computed.
	Computed     map[string]string `json:"computed,omitempty"`
	ComputeError string            `json:"computeError,omitempty"`
}

// streamAlgorithms are the hashes computed while the bytes stream.
var streamAlgorithms = map[string]func() hash.Hash{
	"md5":    md5.New,
	"sha1":   sha1.New,
	"sha256": sha256.New,
	"sha384": sha512.New384,
	"sha512": sha512.New,
}

// Limits of the Go module hash: the bytes a module zip may unpack to, its files,
// and the size of a go.mod held in memory.
const (
	maxGoZipBytes = 1 << 30
	maxGoZipFiles = 200_000
	maxGoModBytes = 16 << 20
)

// Checker hashes an artifact as it streams through it (it is an io.Writer)
// and holds the bytes to the digests the lock file records for it.
type Checker struct {
	art    Artifact
	groups map[string][]string // algorithm -> acceptable values (lower-case hex, or h1 base64)
	hashes map[string]hash.Hash
	all    hash.Hash // SHA-256 of everything, always
	n      int64

	unchecked []string
	h1Zip     bool
	h1Mod     bool
	// compute are the algorithms Artifact.Compute asked for; h1Expected
	// reports whether the lock file's own expectations include h1 (a failure
	// to compute it is then a mismatch, not just a missing value).
	compute    []string
	h1Expected bool
	spool      *os.File
	spoolErr   error
	mod        bytes.Buffer
}

// NewChecker prepares the check of one artifact. spoolDir holds the temporary
// copy a Go module zip needs (its hash is over the files it contains); empty
// is the system's temporary directory.
func NewChecker(a Artifact, spoolDir string) (*Checker, error) {
	c := &Checker{art: a, groups: map[string][]string{}, hashes: map[string]hash.Hash{}, all: sha256.New()}
	for _, d := range a.Expect {
		algo := strings.ToLower(strings.TrimSpace(d.Algorithm))
		val := strings.TrimSpace(d.Value)
		switch {
		case algo == "h1" && d.Of == "go.mod" && a.Role == "go.mod":
			c.h1Mod = true
			c.groups["h1"] = append(c.groups["h1"], val)
		case algo == "h1" && d.Of == "" && a.Role == "package" && strings.HasSuffix(a.Path, ".zip") && strings.Contains(a.Path, "/@v/"):
			c.h1Zip = true
			c.groups["h1"] = append(c.groups["h1"], val)
		case streamAlgorithms[algo] != nil && (d.Of == "" || d.Of == a.File || d.Of == "terraform-zip"):
			c.groups[algo] = append(c.groups[algo], strings.ToLower(val))
			if c.hashes[algo] == nil && algo != "sha256" {
				c.hashes[algo] = streamAlgorithms[algo]()
			}
		default:
			kind := d.Of
			if kind == "" {
				kind = algo
			}
			c.unchecked = appendUnique(c.unchecked, kind)
		}
	}
	c.h1Expected = c.h1Mod || c.h1Zip
	for _, algo := range a.Compute {
		algo = strings.ToLower(strings.TrimSpace(algo))
		switch {
		case algo == "h1" && a.Role == "go.mod":
			c.h1Mod = true
		case algo == "h1" && a.Role == "package" && strings.HasSuffix(a.Path, ".zip") && strings.Contains(a.Path, "/@v/"):
			c.h1Zip = true
		case algo == "h1":
			return nil, fmt.Errorf("locate: the Go module hash applies to a module zip or a go.mod, not to %s", a.Path)
		case streamAlgorithms[algo] != nil:
			if c.hashes[algo] == nil && algo != "sha256" {
				c.hashes[algo] = streamAlgorithms[algo]()
			}
		default:
			return nil, fmt.Errorf("locate: cannot compute %q digests", algo)
		}
		c.compute = appendUnique(c.compute, algo)
	}
	if c.h1Zip {
		f, err := os.CreateTemp(spoolDir, "pt-gomod-*.zip")
		if err != nil {
			return nil, fmt.Errorf("locate: spooling a module zip: %w", err)
		}
		c.spool = f
	}
	return c, nil
}

// Write implements io.Writer.
func (c *Checker) Write(p []byte) (int, error) {
	c.n += int64(len(p))
	c.all.Write(p)
	for _, h := range c.hashes {
		h.Write(p)
	}
	if c.spool != nil && c.spoolErr == nil {
		if _, err := c.spool.Write(p); err != nil {
			c.spoolErr = err
		}
	}
	if c.h1Mod && c.mod.Len() <= maxGoModBytes {
		c.mod.Write(p)
	}
	return len(p), nil
}

// Close removes the temporary copy, if any.
func (c *Checker) Close() error {
	if c.spool == nil {
		return nil
	}
	name := c.spool.Name()
	err := c.spool.Close()
	if rerr := os.Remove(name); rerr != nil && err == nil && !errors.Is(rerr, os.ErrNotExist) {
		err = rerr
	}
	c.spool = nil
	return err
}

// SHA256 returns "sha256:<hex>" of the bytes written so far.
func (c *Checker) SHA256() string {
	return "sha256:" + hex.EncodeToString(c.all.Sum(nil))
}

// Result evaluates the expectations over the bytes written.
func (c *Checker) Result() CheckResult {
	res := CheckResult{SHA256: c.SHA256(), Size: c.n, Unchecked: c.unchecked}
	computed := map[string]string{"sha256": strings.TrimPrefix(res.SHA256, "sha256:")}
	for algo, h := range c.hashes {
		computed[algo] = hex.EncodeToString(h.Sum(nil))
	}
	var h1Err string
	if c.h1Mod {
		if c.mod.Len() > maxGoModBytes {
			h1Err = "the go.mod is larger than the proxy hashes"
		} else {
			computed["h1"] = goHash1([]goFile{{name: "go.mod", data: c.mod.Bytes()}})
		}
	}
	if c.h1Zip {
		if h, err := c.hashModuleZip(); err != nil {
			h1Err = err.Error()
		} else {
			computed["h1"] = h
		}
	}
	if h1Err != "" && c.h1Expected {
		return c.unable(res, "h1", h1Err)
	}
	if len(c.compute) > 0 {
		res.Computed = map[string]string{}
		for _, algo := range c.compute {
			if v, ok := computed[algo]; ok {
				res.Computed[algo] = v
			}
		}
		if h1Err != "" {
			res.ComputeError = "the h1 digest could not be computed over the bytes served: " + h1Err
		}
	}

	algos := make([]string, 0, len(c.groups))
	for a := range c.groups {
		algos = append(algos, a)
	}
	sort.Strings(algos)
	var failed []string
	for _, algo := range algos {
		got := computed[algo]
		ok := false
		for _, want := range c.groups[algo] {
			if (algo == "h1" && want == got) || (algo != "h1" && strings.EqualFold(want, got)) {
				ok = true
				break
			}
		}
		res.Checked = append(res.Checked, algo)
		if !ok {
			failed = append(failed, algo)
		}
	}
	switch {
	case len(failed) > 0:
		res.Status = CheckMismatch
		res.Detail = fmt.Sprintf("the bytes served do not have the %s digest the lock file records", strings.Join(failed, "/"))
	case len(res.Checked) > 0:
		res.Status = CheckVerified
	case len(res.Unchecked) > 0:
		res.Status = CheckUnchecked
		res.Detail = "the lock file's digests are of " + strings.Join(res.Unchecked, ", ") + ", which the proxy does not compute"
	default:
		res.Status = CheckUnverified
	}
	return res
}

// unable reports an expectation the checker could not evaluate: a digest it
// is meant to compute (a Go module hash) over bytes that will not yield one —
// not a zip, too large, a file name the hash cannot represent. That fails
// closed: the bytes are not the module the lock file pins, or cannot be shown
// to be, and are not pinned.
func (c *Checker) unable(res CheckResult, kind, why string) CheckResult {
	res.Checked = append(res.Checked, kind)
	res.Status = CheckMismatch
	res.Detail = "the " + kind + " digest the lock file records could not be computed over the bytes served: " + why
	return res
}

// hashModuleZip computes the Go module hash ("h1:") of the spooled zip: the
// SHA-256 of the sorted "<sha256-hex>  <name>\n" lines of its files, as
// golang.org/x/mod/sumdb/dirhash.HashZip does.
func (c *Checker) hashModuleZip() (string, error) {
	if c.spoolErr != nil {
		return "", fmt.Errorf("spooling the module zip: %w", c.spoolErr)
	}
	if c.spool == nil {
		return "", errors.New("the module zip was not kept")
	}
	if err := c.spool.Sync(); err != nil {
		return "", err
	}
	zr, err := zip.NewReader(c.spool, c.n)
	if err != nil {
		return "", fmt.Errorf("reading the module zip: %w", err)
	}
	if len(zr.File) > maxGoZipFiles {
		return "", fmt.Errorf("the module zip holds %d files, more than the proxy hashes", len(zr.File))
	}
	files := make([]*zip.File, len(zr.File))
	copy(files, zr.File)
	sort.Slice(files, func(i, j int) bool { return files[i].Name < files[j].Name })
	h := sha256.New()
	var total int64
	for _, f := range files {
		if strings.Contains(f.Name, "\n") {
			return "", errors.New("the module zip has a file name with a newline")
		}
		rc, err := f.Open()
		if err != nil {
			return "", fmt.Errorf("reading %s in the module zip: %w", f.Name, err)
		}
		fh := sha256.New()
		n, err := io.Copy(fh, io.LimitReader(rc, maxGoZipBytes-total+1))
		rc.Close()
		if err != nil {
			return "", fmt.Errorf("reading %s in the module zip: %w", f.Name, err)
		}
		total += n
		if total > maxGoZipBytes {
			return "", errors.New("the module zip unpacks to more than the proxy hashes")
		}
		fmt.Fprintf(h, "%x  %s\n", fh.Sum(nil), f.Name)
	}
	return base64.StdEncoding.EncodeToString(h.Sum(nil)), nil
}

type goFile struct {
	name string
	data []byte
}

// goHash1 is dirhash.Hash1 over in-memory files, without the "h1:" prefix (the
// lock file records the base64 text alone).
func goHash1(files []goFile) string {
	sort.Slice(files, func(i, j int) bool { return files[i].name < files[j].name })
	h := sha256.New()
	for _, f := range files {
		sum := sha256.Sum256(f.data)
		fmt.Fprintf(h, "%x  %s\n", sum, f.name)
	}
	return base64.StdEncoding.EncodeToString(h.Sum(nil))
}

func appendUnique(list []string, s string) []string {
	for _, e := range list {
		if e == s {
			return list
		}
	}
	return append(list, s)
}
