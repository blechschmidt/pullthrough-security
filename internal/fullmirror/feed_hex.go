package fullmirror

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	hexbackend "github.com/blechschmidt/pullthrough-security/internal/backends/hex"
	"github.com/blechschmidt/pullthrough-security/internal/lockfiles"
)

// hex follows a Hex repository's registry index (Task 191).
//
// A Hex repository — repo.hex.pm, an organisation's repository beneath
// repo.hex.pm/repos/<org>, mini_repo, an Artifactory Hex repository —
// publishes two resources that list everything it holds: /versions, every
// package with its versions and which of them are retired, and /names, every
// package with the time it last changed. Both are gzipped protobuf in a
// signed envelope. The feed reads both with conditional requests (an
// unchanged repository costs two 304s) and checks their signatures — an RSA
// signature of the payload's SHA-512 — with hex.pm's key, which signs its
// organisations' repositories too and is the key the Hex client trusts a
// HEX_MIRROR with, unless the option "publicKey" names the repository's own
// (mini_repo and Artifactory sign with their own keys) or "none". A /versions
// that does not verify fails the poll: the feed would otherwise follow
// whatever someone between the proxy and the repository listed. The name of
// the repository the resources state is checked as hex_core checks it, so
// that another repository's validly signed index cannot be passed off as
// this one's: "hexpm" for repo.hex.pm, the organisation's name for
// repo.hex.pm/repos/<org> (also when the option "url" reads the index from a
// mirror of them), "hexpm" for any other repository checked with hex.pm's key
// (a mirror of hex.pm, as HEX_MIRROR clients take one); the option
// "repository" names another ("none" checks none), as for a mirror of an
// organisation's repository or a mini_repo.
//
// The copy of the index holds one record per version /versions lists: the
// tarball's path — repos/locate's hex locator, "/tarballs/<name>-<version>.tar",
// read back through the backend's own classification — and whether the version
// is retired. Changes reports every version added, retired or un-retired
// (name@version), every new package (by name) and what is gone. /names adds no
// records: its update times would make every change to a package a
// package-level difference, which the diff reports by name alone, and the
// engine would look at every version of the package again instead of the one
// published (an update time also moves when nothing a mirror holds changed: an
// owner, the documentation). It gives the time of the newest change, shown as
// the feed's head time; a /names that cannot be read or does not verify costs
// only that. A package one resource lists and the other does not is taken as
// /versions has it: a package without versions has nothing to mirror.
//
// Releases is answered from the copy, without a request: every version with
// its tarball, retired versions marked yanked, oldest first by SemVer (Hex
// versions are SemVer 2.0). The registry states no sizes or dates. Package
// names outside the backend's rule — hex.pm keeps a few dozen early packages
// with upper-case letters ("addressBook") — are not served by the backend and
// not followed.
//
// /names and /versions sit beneath the repository's URL in every kind of Hex
// repository; the option "url" names another repository base to read them
// from.

// hexPublicHost is the public repository's host.
const hexPublicHost = "repo.hex.pm"

// hexPublicKey is hex.pm's repository key, as https://repo.hex.pm/public_key
// serves it and hex_core and the Hex client have it built in (checked against
// both on 2026-11-16).
const hexPublicKey = `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEApqREcFDt5vV21JVe2QNB
Edvzk6w36aNFhVGWN5toNJRjRJ6m4hIuG4KaXtDWVLjnvct6MYMfqhC79HAGwyF+
IqR6Q6a5bbFSsImgBJwz1oadoVKD6ZNetAuCIK84cjMrEFRkELtEIPNHblCzUkkM
3rS9+DPlnfG8hBvGi6tvQIuZmXGCxF/73hU0/MyGhbmEjIKRtG6b0sJYKelRLTPW
XgK7s5pESgiwf2YC/2MGDXjAJfpfCd0RpLdvd4eRiXtVlE9qO9bND94E7PgQ/xqZ
J1i2xWFndWa6nfFnRxZmCStCOZWYYPlaxr+FZceFbpMwzTNs4g3d4tLNUcbKAIH4
0wIDAQAB
-----END PUBLIC KEY-----`

// Bounds of the hex feed.
const (
	// hexMaxResource bounds /names and /versions as served (hex.pm's are
	// 380 KB each); it is the bound the backend reads a registry resource
	// with, beyond which it refuses one.
	hexMaxResource = 16 << 20
	// hexMinKeyBits is the smallest repository key accepted.
	hexMinKeyBits = 2048
	// hexMaxVersion bounds a version string.
	hexMaxVersion = 255
	// hexMaxRepository bounds a repository's name.
	hexMaxRepository = 255
)

type hexFeed struct {
	*indexFeed
}

func newHexFeed(env Env) (Feed, error) {
	opts, err := parseOptions(env, "url", "publicKey", "repository")
	if err != nil {
		return nil, err
	}
	k, err := newKit(env)
	if err != nil {
		return nil, err
	}
	base := k.upstream
	if opts["url"] != "" {
		if base, err = parseBaseURL("the feed option url", opts["url"]); err != nil {
			return nil, err
		}
	}
	key, err := hexParseKey(opts["publicKey"])
	if err != nil {
		return nil, fmt.Errorf("option publicKey: %w", err)
	}
	repo, err := hexExpectedRepository(k.upstream, opts["repository"], opts["publicKey"] == "")
	if err != nil {
		return nil, err
	}
	src := &hexSource{k: k, names: join(base, "names"), versions: join(base, "versions"), key: key, repository: repo}
	return &hexFeed{indexFeed: newIndexFeed("hex", env, src)}, nil
}

// hexExpectedRepository is the name of the repository the upstream's index
// must state ("" when none is known): the option "repository" ("none" checks
// none); else, as hex_core expects them, "hexpm" for repo.hex.pm and the
// organisation's name for repo.hex.pm/repos/<org>; else "hexpm" when the
// resources are checked with hex.pm's key (defaultKey): a repository signed
// by hex.pm that is not repo.hex.pm is a mirror of it, and HEX_MIRROR clients
// expect "hexpm".
func hexExpectedRepository(upstream *url.URL, option string, defaultKey bool) (string, error) {
	switch option = strings.TrimSpace(option); {
	case strings.EqualFold(option, "none"):
		return "", nil
	case option != "":
		if len(option) > hexMaxRepository || !cleanName(option) {
			return "", fmt.Errorf("option repository: %q is not a repository name", truncate(option, 80))
		}
		return option, nil
	}
	if hostIs(upstream, hexPublicHost) {
		switch org, ok := strings.CutPrefix(upstream.Path, "/repos/"); {
		case upstream.Path == "":
			return "hexpm", nil
		case ok && org != "" && !strings.Contains(org, "/") && len(org) <= hexMaxRepository && cleanName(org):
			return org, nil
		}
		return "", nil
	}
	if defaultKey {
		return "hexpm", nil
	}
	return "", nil
}

func init() { Register("hex", newHexFeed) }

// hexParseKey reads the "publicKey" option: an RSA public key, PEM-encoded
// (on one line, as an option holds no line break: the armor, then the base64
// body) or as its base64 body alone, in the PKIX or the PKCS #1 form. "none"
// turns the signature check off (nil); empty is hex.pm's key.
func hexParseKey(v string) (*rsa.PublicKey, error) {
	v = strings.TrimSpace(v)
	switch {
	case v == "":
		v = hexPublicKey
	case strings.EqualFold(v, "none"):
		return nil, nil
	}
	var der []byte
	if blk, _ := pem.Decode([]byte(v)); blk != nil {
		der = blk.Bytes
	} else {
		body := v
		for _, armor := range []string{"-----BEGIN PUBLIC KEY-----", "-----END PUBLIC KEY-----", "-----BEGIN RSA PUBLIC KEY-----", "-----END RSA PUBLIC KEY-----"} {
			body = strings.ReplaceAll(body, armor, "")
		}
		var err error
		if der, err = base64.StdEncoding.DecodeString(strings.Join(strings.Fields(body), "")); err != nil {
			return nil, errors.New("not a PEM-encoded or base64 public key")
		}
	}
	var key *rsa.PublicKey
	if pub, err := x509.ParsePKIXPublicKey(der); err == nil {
		rk, ok := pub.(*rsa.PublicKey)
		if !ok {
			return nil, fmt.Errorf("a %T, not an RSA key: Hex repositories sign with RSA", pub)
		}
		key = rk
	} else if rk, err := x509.ParsePKCS1PublicKey(der); err == nil {
		key = rk
	} else {
		return nil, errors.New("not an RSA public key")
	}
	if key.N.BitLen() < hexMinKeyBits {
		return nil, fmt.Errorf("a %d-bit key; at least %d bits are accepted", key.N.BitLen(), hexMinKeyBits)
	}
	return key, nil
}

// hexSource reads a Hex repository's /versions and /names.
type hexSource struct {
	k        kit
	names    string
	versions string
	// key checks the resources' signatures; nil does not.
	key *rsa.PublicKey
	// repository is the name the resources must state; "" is not checked.
	repository string
}

// hexState is what the next read is conditioned on.
type hexState struct {
	Names    httpValidators `json:"names"`
	Versions httpValidators `json:"versions"`
}

// readIndex reads /versions into the copy, and /names for the time of the
// newest change.
func (s *hexSource) readIndex(ctx context.Context, prev json.RawMessage, old *snapHeader, b *snapBuilder) (indexRead, error) {
	var st hexState
	if old == nil || len(prev) == 0 || json.Unmarshal(prev, &st) != nil || !hexUsable(st.Names) || !hexUsable(st.Versions) {
		// Without a copy to fall back on, or validators to send, both
		// resources are read in full.
		st = hexState{}
	}
	vbody, vval, _, err := s.fetch(ctx, s.versions, st.Versions)
	unchanged := errors.Is(err, errNotModified)
	if err != nil && !unchanged {
		return indexRead{}, fmt.Errorf("reading the Hex repository's /versions: %w", err)
	}
	if unchanged && old == nil {
		return indexRead{}, fmt.Errorf("the Hex repository answered an unconditional request for /versions with 304")
	}
	var rd indexRead
	// /names gives only the head time: a repository that does not serve it,
	// or one that does not read or verify, is followed without one (and
	// read in full again at the next poll).
	nbody, nval, _, err := s.fetch(ctx, s.names, st.Names)
	switch {
	case err == nil:
		if t, err := s.readNames(nbody); err == nil {
			rd.HeadTime, st.Names = t, nval
		} else {
			st.Names = httpValidators{}
		}
	case errors.Is(err, errNotModified):
	case ctx.Err() != nil:
		return indexRead{}, ctx.Err()
	default:
		st.Names = httpValidators{}
	}
	if !unchanged {
		if err := s.readVersions(ctx, vbody, b); err != nil {
			return indexRead{}, err
		}
		st.Versions = vval
	}
	state, err := json.Marshal(st)
	if err != nil {
		return indexRead{}, err
	}
	rd.State = state
	rd.Unchanged = unchanged
	return rd, nil
}

// hexUsable reports whether validators kept in a cursor — which is not
// trusted — can go back into a request header.
func hexUsable(v httpValidators) bool {
	for _, h := range []string{v.ETag, v.LastModified} {
		if len(h) > 512 {
			return false
		}
		for i := 0; i < len(h); i++ {
			if c := h[i]; c < 0x20 && c != '\t' || c == 0x7f {
				return false
			}
		}
	}
	return true
}

// fetch reads a resource, conditionally on val. A 304 is errNotModified.
func (s *hexSource) fetch(ctx context.Context, rawURL string, val httpValidators) ([]byte, httpValidators, *http.Response, error) {
	hdr := http.Header{}
	val.set(hdr)
	resp, body, err := s.k.getStream(ctx, rawURL, hdr, hexMaxResource)
	if err != nil {
		return nil, httpValidators{}, resp, err
	}
	defer body.Close()
	data, err := io.ReadAll(body)
	if err != nil {
		return nil, httpValidators{}, resp, fmt.Errorf("reading %s: %w", rawURL, err)
	}
	return data, validatorsOf(resp), resp, nil
}

// open unwraps a resource's signed envelope and checks its signature.
func (s *hexSource) open(body []byte, what string) ([]byte, error) {
	payload, sig, err := hexbackend.OpenSignedResource(body)
	if err != nil {
		return nil, Permanent(fmt.Errorf("the Hex repository's %s does not read: %w", what, err))
	}
	if s.key != nil {
		if err := hexbackend.VerifyResourceSignature(payload, sig, s.key); err != nil {
			return nil, Permanent(fmt.Errorf("the Hex repository's %s: %w (a repository that signs with another key needs the feed option publicKey)", what, err))
		}
	}
	return payload, nil
}

// checkRepository checks the repository name a resource states.
func (s *hexSource) checkRepository(got, what string) error {
	if s.repository != "" && got != s.repository {
		return Permanent(fmt.Errorf("the Hex repository's %s is the index of repository %q, not %q", what, truncate(got, 80), s.repository))
	}
	return nil
}

// readNames reads /names for the time the newest package changed.
func (s *hexSource) readNames(body []byte) (time.Time, error) {
	payload, err := s.open(body, "/names")
	if err != nil {
		return time.Time{}, err
	}
	newest, repo, err := hexNamesNewest(payload)
	if err != nil {
		return time.Time{}, err
	}
	if err := s.checkRepository(repo, "/names"); err != nil {
		return time.Time{}, err
	}
	return newest, nil
}

// hexNamesNewest reads a /names payload for the time the newest package
// changed (zero when no entry states one) and the repository name.
func hexNamesNewest(payload []byte) (time.Time, string, error) {
	var newest time.Time
	repo, err := hexbackend.ParseNames(payload, func(e hexbackend.NamesEntry) error {
		if e.Updated.After(newest) {
			newest = e.Updated
		}
		return nil
	})
	if err != nil {
		return time.Time{}, "", Permanent(fmt.Errorf("the Hex repository's /names does not read: %w", err))
	}
	return newest, repo, nil
}

// readVersions adds the records of /versions to the copy.
func (s *hexSource) readVersions(ctx context.Context, body []byte, b *snapBuilder) error {
	payload, err := s.open(body, "/versions")
	if err != nil {
		return err
	}
	repo, err := hexAddVersions(ctx, s.k, payload, b)
	if err != nil {
		return err
	}
	return s.checkRepository(repo, "/versions")
}

// hexAddVersions adds a /versions payload's records to the copy: each version
// whose tarball the backend serves, with its path and whether it is retired.
// It returns the repository name the payload states.
func hexAddVersions(ctx context.Context, k kit, payload []byte, b *snapBuilder) (string, error) {
	repo, err := hexbackend.ParseVersions(payload, func(e hexbackend.VersionsEntry) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if !hexbackend.ValidPackageName(e.Name) {
			return nil
		}
		for i, v := range e.Versions {
			if p, ok := hexTarballPath(ctx, k, e.Name, v); ok {
				b.Add(snapRecord{Name: e.Name, Version: v, Path: p, Yanked: e.Retired[i]})
			}
		}
		return nil
	})
	if err != nil {
		if cerr := ctx.Err(); cerr != nil {
			return "", cerr
		}
		return "", Permanent(fmt.Errorf("the Hex repository's /versions does not read: %w", err))
	}
	return repo, nil
}

// hexTarballPath locates a version's tarball with repos/locate's hex locator
// and checks that the backend classifies the path as that very version.
func hexTarballPath(ctx context.Context, k kit, name, version string) (string, bool) {
	if !hexValidVersion(version) {
		return "", false
	}
	arts, err := k.locate(ctx, lockfiles.Dependency{Name: name, Version: version}, nil)
	if err != nil || len(arts) != 1 {
		return "", false
	}
	dec, err := url.PathUnescape(arts[0].Path)
	if err != nil {
		return "", false
	}
	if n, v, ok := hexbackend.TarballCoordinate(dec); !ok || n != name || v != version {
		return "", false
	}
	return arts[0].Path, true
}

// hexValidVersion reports whether s is spelt as a Hex version can be: a
// SemVer 2.0 version's characters ([0-9A-Za-z.+-]), starting with a digit.
func hexValidVersion(s string) bool {
	if s == "" || len(s) > hexMaxVersion || s[0] < '0' || s[0] > '9' {
		return false
	}
	for i := 0; i < len(s); i++ {
		if c := s[i]; !(c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c == '.' || c == '+' || c == '-') {
			return false
		}
	}
	return true
}

// Releases lists a package's versions from the copy of the index.
func (f *hexFeed) Releases(_ context.Context, name string) ([]Release, error) {
	if !hexbackend.ValidPackageName(name) {
		return nil, Permanent(fmt.Errorf("%q is not a Hex package name the proxy serves", truncate(name, 200)))
	}
	recs, err := f.lookup(name)
	if err != nil {
		return nil, err
	}
	rels := snapReleases(recs)
	hexOrderReleases(rels)
	return rels, nil
}

// hexOrderReleases sorts releases oldest first. Hex versions are SemVer 2.0
// (Elixir's Version); internal/versions has no scheme of the type, and npm's
// (node-semver's) is SemVer's precedence.
func hexOrderReleases(rels []Release) { orderReleases("npm", rels) }
