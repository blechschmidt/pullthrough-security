package config

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"github.com/blechschmidt/pullthrough-security/internal/fullmirror"
)

const fullMirrorBaseYAML = `
server:
  httpAddr: ":8080"
cache:
  backend: filesystem
  dir: %CACHE%
upstreams:
  npm:
    type: npm
    url: "https://registry.npmjs.org"
`

func loadFullMirrorYAML(t *testing.T, upstreamBlock, extra string) (*Config, error) {
	t.Helper()
	doc := strings.ReplaceAll(fullMirrorBaseYAML, "%CACHE%", filepath.Join(t.TempDir(), "cache")) + upstreamBlock + extra
	return loadDownloadLogYAML(t, doc)
}

// registerFakeAdapter has a fake feed follow typ for the test, in place of
// the adapter registered for it (if any): the tests check the configuration,
// not an adapter's reading of the upstream.
func registerFakeAdapter(t *testing.T, typ string) {
	t.Helper()
	t.Cleanup(fullmirror.ReplaceAdapter(typ, func(fullmirror.Env) (fullmirror.Feed, error) { return noFeed{}, nil }))
}

type noFeed struct{}

func (noFeed) Bootstrap(context.Context, string) (fullmirror.Batch, error) {
	return fullmirror.Batch{}, errors.New("no feed")
}
func (noFeed) Changes(context.Context, string) (fullmirror.Batch, error) {
	return fullmirror.Batch{}, errors.New("no feed")
}
func (noFeed) Releases(context.Context, string) ([]fullmirror.Release, error) {
	return nil, errors.New("no feed")
}

// Full mirroring is refused, with a pointer to the page that says why, for
// every type with no feed to follow: the tier-(d) registries and Terraform.
func TestFullMirrorIsRefusedWithoutAFeed(t *testing.T) {
	for typ, block := range map[string]string{
		"docker":    `url: "https://registry-1.docker.io"`,
		"terraform": `url: "https://registry.terraform.io"`,
		"swift":     `url: "https://tuist.dev/api/registry/swift"`,
		"nix":       `url: "https://cache.nixos.org"`,
		"git":       `url: "https://github.com"`,
		"generic": `url: "https://repo.example.com"
    generic:
      publicBaseURL: https://proxy.example.com/v1/u
      routes:
        - name: artifact
          match: '^/dist/.+\.tar\.gz$'
          cacheable: true`,
	} {
		_, err := loadDownloadLogYAML(t, `
server:
  httpAddr: ":8080"
cache: {backend: filesystem, dir: `+filepath.Join(t.TempDir(), "c")+`}
upstreams:
  u:
    type: `+typ+`
    `+block+`
    fullMirror: {enabled: true, byteBudget: 1000000}
`)
		if err == nil || !strings.Contains(err.Error(), `upstream "u": fullMirror.enabled: `) ||
			!strings.Contains(err.Error(), "cannot be followed") || !strings.Contains(err.Error(), "docs/full-mirroring.md#"+typ) {
			t.Errorf("%s: %v, want a refusal pointing at docs/full-mirroring.md#%s", typ, err, typ)
		}
	}
	// A disabled block is checked for syntax only.
	cfg, err := loadFullMirrorYAML(t, `
    fullMirror: {enabled: false, include: ["@acme/.*"], versions: latest, latest: 2}
`, "")
	if err != nil {
		t.Fatalf("a disabled block: %v", err)
	}
	if len(cfg.FullMirrorUpstreams()) != 0 {
		t.Errorf("FullMirrorUpstreams = %v", cfg.FullMirrorUpstreams())
	}
}

func TestFullMirrorAcceptedWithAnAdapter(t *testing.T) {
	registerFakeAdapter(t, "npm")
	cfg, err := loadFullMirrorYAML(t, `
    fullMirror:
      enabled: true
      include: ["@acme/.*", "lodash"]
      exclude: ["@acme/internal-.*"]
      versions: latest
      latest: 3
      maxArtifactBytes: 104857600
      byteBudget: 107374182400
      concurrency: 4
      requestsPerSecond: 5
      pollInterval: 2m
      offPeak: {start: "22:00", end: "06:00", timezone: Europe/Berlin}
      dryRun: true
`, "")
	if err != nil {
		t.Fatal(err)
	}
	fm := cfg.Upstreams["npm"].FullMirror
	if fm == nil || !fm.Enabled || fm.Latest != 3 || fm.OffPeak.Timezone != "Europe/Berlin" || !fm.DryRun {
		t.Fatalf("parsed %+v", fm)
	}
	if got := cfg.FullMirrorUpstreams(); len(got) != 1 || got[0] != "npm" {
		t.Errorf("FullMirrorUpstreams = %v", got)
	}
	if got, want := cfg.FullMirrorStateDir(), filepath.Join(cfg.Cache.Dir, "fullmirror"); got != want {
		t.Errorf("state dir %q, want %q", got, want)
	}
}

func TestFullMirrorValidation(t *testing.T) {
	registerFakeAdapter(t, "npm")
	for _, tc := range []struct {
		name, block, extra, want string
	}{
		{"no budget", `{enabled: true}`, "", "fullMirror.byteBudget is required"},
		{"negative budget", `{enabled: false, byteBudget: -1}`, "", "byteBudget must not be negative"},
		{"bad include", `{enabled: true, byteBudget: 10, include: ["("]}`, "", "fullMirror.include: pattern 0"},
		{"empty exclude", `{enabled: true, byteBudget: 10, exclude: [""]}`, "", "fullMirror.exclude: pattern 0 is empty"},
		{"latest without N", `{enabled: true, byteBudget: 10, versions: latest}`, "", "needs latest: N"},
		{"N without latest", `{enabled: true, byteBudget: 10, latest: 2}`, "", "set versions: latest"},
		{"unknown policy", `{enabled: true, byteBudget: 10, versions: newest}`, "", "unknown version policy"},
		{"negative max", `{enabled: true, byteBudget: 10, maxArtifactBytes: -5}`, "", "maxArtifactBytes must not be negative"},
		{"max over budget", `{enabled: true, byteBudget: 10, maxArtifactBytes: 11}`, "", "larger than the byteBudget"},
		{"concurrency", `{enabled: true, byteBudget: 10, concurrency: 33}`, "", "concurrency must be between"},
		{"rate", `{enabled: true, byteBudget: 10, requestsPerSecond: -1}`, "", "requestsPerSecond must be between"},
		{"poll", `{enabled: true, byteBudget: 10, pollInterval: 1s}`, "", "pollInterval must be at least 10s"},
		{"half window", `{enabled: true, byteBudget: 10, offPeak: {start: "22:00"}}`, "", "offPeak: the window needs both"},
		{"bad zone", `{enabled: true, byteBudget: 10, offPeak: {start: "22:00", end: "06:00", timezone: Nowhere/Land}}`, "", "offPeak: window time zone"},
		{"undefined role", `{enabled: true, byteBudget: 10}`, `
auth:
  enabled: true
  tokens: [{name: ci, token: abcdefghijklmnopqrstuvwxyz012345, team: default, roles: [reader]}]
  roles: [{name: reader, upstreams: ["*"]}]
fullMirror: {roles: [nope]}
`, `fullMirror.roles references undefined role "nope"`},
		{"auth without roles", `{enabled: true, byteBudget: 10}`, `
auth:
  enabled: true
  tokens: [{name: ci, token: abcdefghijklmnopqrstuvwxyz012345, team: default, roles: [reader]}]
  roles: [{name: reader, upstreams: ["*"]}]
`, "the full mirror needs roles to fetch with"},
	} {
		_, err := loadFullMirrorYAML(t, "    fullMirror: "+tc.block+"\n", tc.extra)
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: %v, want an error containing %q", tc.name, err, tc.want)
		}
	}

	// Auth with roles that exist is accepted.
	if _, err := loadFullMirrorYAML(t, "    fullMirror: {enabled: true, byteBudget: 10}\n", `
auth:
  enabled: true
  tokens: [{name: ci, token: abcdefghijklmnopqrstuvwxyz012345, team: default, roles: [reader]}]
  roles: [{name: reader, upstreams: ["*"]}]
fullMirror: {roles: [reader], tenant: mirror}
`); err != nil {
		t.Errorf("auth with roles: %v", err)
	}
}

func TestFullMirrorNeedsADurableHome(t *testing.T) {
	registerFakeAdapter(t, "npm")
	memory := `
server:
  httpAddr: ":8080"
cache: {backend: memory}
upstreams:
  npm:
    type: npm
    url: "https://registry.npmjs.org"
    fullMirror: {enabled: true, byteBudget: 10}
`
	if _, err := loadDownloadLogYAML(t, memory); err == nil || !strings.Contains(err.Error(), "fullMirror.stateDir is required") {
		t.Errorf("memory cache without a state dir: %v", err)
	}
	withDir := memory + "fullMirror: {stateDir: " + t.TempDir() + "}\n"
	if _, err := loadDownloadLogYAML(t, withDir); err == nil || !strings.Contains(err.Error(), "needs a durable cache") {
		t.Errorf("memory cache with a state dir: %v", err)
	}
}
