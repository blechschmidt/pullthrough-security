//go:build integration
// +build integration

package fullmirror

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/blechschmidt/pullthrough-security/internal/e2e/pkgscan"
)

// Hex: the adapter polls the repository's /versions — every package with its
// versions — with conditional requests, checks its signature and the
// repository it names, keeps a copy and diffs the next one against it, one
// change per version added, retired or gone; it reads /names, every package
// with the time it last changed, for the time of the newest change. Releases
// answers from the copy: each version's tarball, which the backend checks
// against the outer checksum of the package's signed /packages/<name>.
//
// The stub serves /names and /versions in front of the registry as
// repo.hex.pm serves them: static files written again at every publication —
// gzipped protobuf in a signed envelope, the packages sorted by name, naming
// the repository "hexpm" — with an ETag of their content and the time of the
// newest publication as Last-Modified. They are signed with the key the stub
// registry signs /packages/<name> with, which the feed option publicKey names:
// the stub is not hex.pm, whose key the adapter checks with by default. Feed
// option repository: "hexpm", the repository a mirror of hex.pm names.

func init() {
	register(row{
		Type:    "hex",
		Feed:    "the repository's signed `/names` and `/versions` (gzipped protobuf), polled conditionally",
		Start:   hexFeedStart,
		Publish: func(env *feedEnv, added []publication) error { return hexFeed(env).publish(env, added) },
		Options: func(env *feedEnv) map[string]string {
			return map[string]string{"publicKey": hexFeed(env).publicKey, "repository": pkgscan.HexRepositoryName}
		},
		Resumed: func(env *feedEnv, _ []string) error { return hexFeed(env).resumed() },
		Notes: []string{
			"no retired version is published: the yanked mark is not covered",
		},
	})
}

// hexResources are the stub's /names and /versions and what was asked of
// them.
type hexResources struct {
	publicKey string

	mu        sync.Mutex
	names     []byte
	versions  []byte
	modTime   time.Time
	asked     []hexAsk
	mark      int
	heldETag  string
	published bool
}

// hexAsk is one request for /versions: the ETag it was conditional on.
type hexAsk struct{ ifNoneMatch string }

func hexFeed(env *feedEnv) *hexResources { return env.get("hex").(*hexResources) }

func hexFeedStart(env *feedEnv) error {
	pub, err := pkgscan.HexRepositoryKey()
	if err != nil {
		return err
	}
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return err
	}
	// The option holds no line break: the PEM armor and body on one line.
	h := &hexResources{publicKey: "-----BEGIN PUBLIC KEY----- " + base64.StdEncoding.EncodeToString(der) + " -----END PUBLIC KEY-----"}
	env.set("hex", h)
	if err := h.publish(env, nil); err != nil {
		return err
	}
	env.Stub.Handle("/names", func(w http.ResponseWriter, r *http.Request) { h.serve(w, r, false) })
	env.Stub.Handle("/versions", func(w http.ResponseWriter, r *http.Request) { h.serve(w, r, true) })
	return nil
}

// publish writes /names and /versions again, listing every package
// published. For the late package it notes where the restarted mirror's
// requests begin and the ETag of the /versions the first mirror read last.
func (h *hexResources) publish(env *feedEnv, added []publication) error {
	var names []pkgscan.HexNamesEntry
	var versions []pkgscan.HexVersionsEntry
	var newest time.Time
	for _, p := range env.Publications() {
		names = append(names, pkgscan.HexNamesEntry{Name: p.Pkg.Name, Updated: p.Time})
		versions = append(versions, pkgscan.HexVersionsEntry{Name: p.Pkg.Name, Versions: []string{p.Pkg.Version}})
		if p.Time.After(newest) {
			newest = p.Time
		}
	}
	n, err := pkgscan.HexSignedNames(names)
	if err != nil {
		return err
	}
	v, err := pkgscan.HexSignedVersions(versions)
	if err != nil {
		return err
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	for _, p := range added {
		if p.Variant == pkgLate {
			h.mark, h.heldETag, h.published = len(h.asked), hexETag(h.versions), true
		}
	}
	h.names, h.versions, h.modTime = n, v, newest.Truncate(time.Second)
	return nil
}

// serve answers a request for /names or /versions as a static file.
func (h *hexResources) serve(w http.ResponseWriter, r *http.Request, versions bool) {
	h.mu.Lock()
	body, modTime := h.names, h.modTime
	if versions {
		body = h.versions
		h.asked = append(h.asked, hexAsk{ifNoneMatch: r.Header.Get("If-None-Match")})
	}
	h.mu.Unlock()
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("ETag", hexETag(body))
	http.ServeContent(w, r, "", modTime, bytes.NewReader(body))
}

// resumed checks the restarted mirror's first request for /versions: it was
// conditional on the ETag of the /versions the mirror had read before it
// stopped — the copy its cursor names — and so was answered in full only
// because the late package changed it.
func (h *hexResources) resumed() error {
	h.mu.Lock()
	defer h.mu.Unlock()
	if !h.published {
		return fmt.Errorf("the late package was not published")
	}
	if h.mark >= len(h.asked) {
		return fmt.Errorf("the restarted mirror did not read /versions")
	}
	if got := h.asked[h.mark].ifNoneMatch; got != h.heldETag {
		return fmt.Errorf("the restarted mirror's first request for /versions was conditional on %q, want the ETag of the copy it held, %s", got, h.heldETag)
	}
	return nil
}

// hexETag is the ETag the stub serves a resource with.
func hexETag(body []byte) string {
	sum := sha256.Sum256(body)
	return fmt.Sprintf(`"%x"`, sum[:16])
}
