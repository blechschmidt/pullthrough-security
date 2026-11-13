package config

import (
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const repositoriesBaseYAML = `
server:
  httpAddr: ":8080"
cache:
  backend: filesystem
  dir: %CACHE%
upstreams:
  npm: {type: npm, url: "https://registry.npmjs.org"}
  crates: {type: cargo, url: "https://index.crates.io"}
`

func loadRepositoriesYAML(t *testing.T, extra string) (*Config, error) {
	t.Helper()
	doc := strings.ReplaceAll(repositoriesBaseYAML, "%CACHE%", filepath.Join(t.TempDir(), "cache")) + extra
	return loadDownloadLogYAML(t, doc)
}

func TestRepositoriesDefaults(t *testing.T) {
	cfg, err := loadRepositoriesYAML(t, `
repositories:
  enabled: true
  repos:
    - name: widgets
      url: https://github.com/acme/widgets.git
      credentialsRef: env://WIDGETS_TOKEN
      tenant: team-a
      upstreams: {cargo: crates}
`)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := cfg.RepositoriesStateDir(), filepath.Join(cfg.Cache.Dir, "repositories"); got != want {
		t.Errorf("stateDir %q, want %q", got, want)
	}
	if got := cfg.RepositoriesMirrorDir(); got != filepath.Join(cfg.RepositoriesStateDir(), "mirrors") {
		t.Errorf("mirrorDir %q", got)
	}
	if cfg.RepositoriesPollInterval() != 5*time.Minute || cfg.RepositoriesWebhookPath() != "/webhooks/repos" {
		t.Errorf("poll %s webhook %s", cfg.RepositoriesPollInterval(), cfg.RepositoriesWebhookPath())
	}
	// The credentials reference is kept as a reference, resolved at fetch time.
	if cfg.Repositories.Repos[0].CredentialsRef != "env://WIDGETS_TOKEN" {
		t.Errorf("credentialsRef %q", cfg.Repositories.Repos[0].CredentialsRef)
	}
}

func TestRepositoriesValidation(t *testing.T) {
	cases := map[string]string{
		"poll too short": `
repositories: {enabled: true, pollInterval: 1s}`,
		"webhook under /v1": `
repositories: {enabled: true, webhookPath: /v1/hook}`,
		"unknown scheme": `
repositories: {enabled: true, allowedSchemes: [ext]}`,
		"bad platform": `
repositories: {enabled: true, pinning: {platforms: [linux]}}`,
		"negative pinning": `
repositories: {enabled: true, pinning: {workers: -1}}`,
		"duplicate repo": `
repositories:
  enabled: true
  repos:
    - {name: a, url: "https://x/a.git"}
    - {name: a, url: "https://x/b.git"}`,
		"repo without url": `
repositories:
  enabled: true
  repos: [{name: a}]`,
		"unknown upstream": `
repositories:
  enabled: true
  repos: [{name: a, url: "https://x/a.git", upstreams: {npm: nope}}]`,
		"wrong upstream type": `
repositories:
  enabled: true
  repos: [{name: a, url: "https://x/a.git", upstreams: {npm: crates}}]`,
		"backfill below -1": `
repositories: {enabled: true, backfillTags: -2}`,
	}
	for name, extra := range cases {
		if _, err := loadRepositoriesYAML(t, extra); err == nil || !strings.Contains(err.Error(), "repositories") {
			t.Errorf("%s: accepted (%v)", name, err)
		}
	}
}

func TestRepositoriesNeedADurableCache(t *testing.T) {
	cfg := Default()
	cfg.Cache.Backend = "memory"
	cfg.Repositories.Enabled = true
	cfg.Repositories.StateDir = t.TempDir()
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "durable cache") {
		t.Fatalf("memory cache: %v", err)
	}
	cfg.Cache.Backend = "s3"
	cfg.Repositories.StateDir = ""
	if err := cfg.validateRepositories(); err == nil || !strings.Contains(err.Error(), "stateDir") {
		t.Fatalf("s3 without stateDir: %v", err)
	}
}

func TestRepositoriesWebhookSecretIsACredential(t *testing.T) {
	cfg := Default()
	cfg.Repositories.WebhookSecret = "s3cret"
	found := false
	for _, f := range credentialFields(&cfg) {
		if f.name == "repositories.webhookSecret" && f.get() == "s3cret" {
			found = true
		}
	}
	if !found {
		t.Fatal("repositories.webhookSecret is not resolved and redacted like the other secrets")
	}
}

// With client authentication on, the release pinner fetches with roles: each
// configured repository needs some (its own or repositories.roles), and only
// defined ones.
func TestRepositoriesRoles(t *testing.T) {
	const authYAML = `
auth:
  enabled: true
  roles:
    - {name: reader, ecosystems: ["*"], upstreams: ["*"]}
  tokens:
    - {name: ci, token: a-sufficiently-long-token-value, roles: [reader]}
`
	if _, err := loadRepositoriesYAML(t, authYAML+`
repositories:
  enabled: true
  repos: [{name: a, url: "https://x/a.git"}]`); err == nil || !strings.Contains(err.Error(), "needs roles") {
		t.Fatalf("a repository the pinner holds no role for: %v", err)
	}
	for name, extra := range map[string]string{
		"default": `
repositories: {enabled: true, roles: [nope]}`,
		"repository": `
repositories:
  enabled: true
  repos: [{name: a, url: "https://x/a.git", roles: [nope]}]`,
	} {
		if _, err := loadRepositoriesYAML(t, authYAML+extra); err == nil || !strings.Contains(err.Error(), "undefined role") {
			t.Errorf("%s: an undefined role was accepted: %v", name, err)
		}
	}
	for _, extra := range []string{`
repositories:
  enabled: true
  roles: [reader]
  repos: [{name: a, url: "https://x/a.git"}]`, `
repositories:
  enabled: true
  repos: [{name: a, url: "https://x/a.git", roles: [reader]}]`} {
		if _, err := loadRepositoriesYAML(t, authYAML+extra); err != nil {
			t.Errorf("roles given: %v", err)
		}
	}
	// Without client authentication roles are not needed.
	if _, err := loadRepositoriesYAML(t, `
repositories:
  enabled: true
  repos: [{name: a, url: "https://x/a.git"}]`); err != nil {
		t.Fatal(err)
	}
}

// TestRepositoryUpdatesValidation checks the maintenance updater's settings
// (Task 182).
func TestRepositoryUpdatesValidation(t *testing.T) {
	llm := `
llmPackageScan: {enabled: true, provider: claude, apiKey: x}
`
	cfg, err := loadRepositoriesYAML(t, llm+`
repositories:
  enabled: true
  updates:
    enabled: true
    maxBump: patch
    sandbox: {runtime: podman, images: {npm: "node:22-slim"}}
  repos:
    - name: widgets
      url: https://github.com/acme/widgets.git
      updates: {ignore: ["npm/lodash@>=5"], forge: gitlab, forgeTokenRef: "env://GL_TOKEN", branch: deps/maint}
`)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Repositories.Updates.MaxBump != "patch" || cfg.Repositories.Repos[0].Updates.Forge != "gitlab" {
		t.Fatalf("parsed: %+v", cfg.Repositories.Updates)
	}
	cases := map[string]string{
		"no LLM gate": `
repositories: {enabled: true, updates: {enabled: true}}`,
		"maxBump": llm + `
repositories: {enabled: true, updates: {enabled: true, maxBump: major}}`,
		"interval": llm + `
repositories: {enabled: true, updates: {enabled: true, interval: 5s}}`,
		"branch": llm + `
repositories: {enabled: true, updates: {enabled: true, branch: "-x"}}`,
		"runtime": llm + `
repositories: {enabled: true, updates: {enabled: true, sandbox: {runtime: lxc}}}`,
		"image tool": llm + `
repositories: {enabled: true, updates: {enabled: true, sandbox: {runtime: docker, images: {bundler: "ruby:3"}}}}`,
		"author": llm + `
repositories: {enabled: true, updates: {enabled: true, authorEmail: "a <b>"}}`,
		"repo forge": `
repositories: {enabled: true, repos: [{name: w, url: "https://h/w.git", updates: {forge: bitbucket}}]}`,
		"repo token literal": `
repositories: {enabled: true, repos: [{name: w, url: "https://h/w.git", updates: {forgeTokenRef: ghp_x}}]}`,
		"repo ignore": `
repositories: {enabled: true, repos: [{name: w, url: "https://h/w.git", updates: {ignore: [lodash]}}]}`,
	}
	for name, extra := range cases {
		if _, err := loadRepositoriesYAML(t, extra); err == nil || !strings.Contains(err.Error(), "updates") {
			t.Errorf("%s: %v", name, err)
		}
	}
}
