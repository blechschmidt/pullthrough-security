// Command ptctl is the first-class client CLI for the pull-through security
// proxy. It streamlines developer onboarding and self-service against a running
// proxy:
//
//   - `config`     generate per-tenant package-manager config snippets
//     (pip.conf, .npmrc, Cargo config, go env, NuGet.config,
//     Docker/Helm login, Maven settings.xml, …) for the proxy's
//     enabled backends.
//   - `selftest`   run a connectivity/auth self-test against each enabled
//     backend (and the proxy's health endpoints).
//   - `inspect`    surface the admission-gate verdict and findings for a
//     coordinate in human-readable form (reuses the findings/SARIF
//     admin endpoint).
//   - `attest`     fetch (and summarize) the proxy's outbound attestation bundle
//     for a served artifact.
//   - `downloads`  show the download log — which package was downloaded from
//     which client address, and by which user — filtered by address,
//     user, package, outcome or time, as a table, JSON or CSV.
//   - `userlinks`  list, revoke or issue personal cache links: the per-user
//     addresses of the package sources that downloads are tracked by.
//   - `completion` emit a shell-completion script (bash|zsh|fish).
//
// It talks to the proxy over HTTP only; it never needs the proxy's config file
// or filesystem, so a developer can run it from anywhere with just a URL, an
// optional --tenant, and an optional --token.
package main

import (
	"flag"
	"fmt"
	"os"
	"strings"
	"time"
)

// version is overridden at build time via -ldflags "-X main.version=...".
var version = "dev"

// globalFlags are the connection/identity flags every subcommand accepts. Each
// falls back to an environment variable so they can be exported once per shell
// session and omitted from individual invocations.
type globalFlags struct {
	url         string
	tenant      string
	token       string
	adminPrefix string
	insecure    bool
	timeout     time.Duration
}

// registerGlobals wires the global flags onto a subcommand's flag set, seeding
// defaults from the environment so `export PULLTHROUGH_URL=...` works.
func registerGlobals(fs *flag.FlagSet, g *globalFlags) {
	fs.StringVar(&g.url, "url", os.Getenv("PULLTHROUGH_URL"), "base URL of the proxy, e.g. https://proxy.example.com (env PULLTHROUGH_URL)")
	fs.StringVar(&g.tenant, "tenant", os.Getenv("PULLTHROUGH_TENANT"), "tenant/team scope for config and lookups (env PULLTHROUGH_TENANT)")
	fs.StringVar(&g.token, "token", os.Getenv("PULLTHROUGH_TOKEN"), "proxy access token, sent as a bearer credential (env PULLTHROUGH_TOKEN)")
	fs.StringVar(&g.adminPrefix, "admin-prefix", envOr("PULLTHROUGH_ADMIN_PREFIX", "/admin"), "admin API path prefix (env PULLTHROUGH_ADMIN_PREFIX)")
	fs.BoolVar(&g.insecure, "insecure", false, "skip TLS certificate verification (for self-signed dev proxies)")
	fs.DurationVar(&g.timeout, "timeout", 30*time.Second, "per-request timeout")
}

func envOr(key, fallback string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return fallback
}

// command is one ptctl subcommand.
type command struct {
	name    string
	summary string
	run     func(args []string) error
}

func commands() []command {
	return []command{
		{"config", "generate package-manager config snippets for the proxy's backends", runConfig},
		{"selftest", "check connectivity and auth against each enabled backend", runSelftest},
		{"doctor", "run a consolidated read-only health & config self-diagnostic (Task 152)", runDoctor},
		{"inspect", "show admission verdict and findings for a coordinate", runInspect},
		{"attest", "fetch the proxy's outbound attestation bundle for an artifact", runAttest},
		{"sbom-diff", "show dependency drift between two versions of a package", runSbomDiff},
		{"remediate", "compute the nearest safe upgrade for a blocked/flagged artifact (Task 121)", runRemediate},
		{"snapshot", "list/diff/capture snapshots and freeze/rollback the org (Task 70)", runSnapshot},
		{"vex", "export the proxy's VEX posture as a signed OpenVEX/CycloneDX document (Task 137)", runVEX},
		{"lockdown", "engage/clear the emergency lockdown / global kill-switch (Task 74)", runLockdown},
		{"gitops", "show GitOps sync status, force a sync, or roll back to last-known-good (Task 93)", runGitops},
		{"prewarm", "show predictive cache pre-warming status or trigger a cycle (Task 134)", runPrewarm},
		{"sbom-export", "show outbound SBOM/findings federation status or trigger an export sweep (Task 153)", runSBOMExport},
		{"query", "run a federated query over the proxy's security data model", runQuery},
		{"mcp", "query the read-only MCP security endpoint or bridge stdio↔HTTP for AI agents (Task 79)", runMCP},
		{"grpc", "query the read-only gRPC/Connect security API — risk/findings/provenance/dossier/compliance/query (Task 159)", runGRPC},
		{"timeline", "reconstruct the forensic incident timeline for a coordinate/tenant/identity/incident (Task 77)", runTimeline},
		{"dossier", "show the complete per-coordinate security dossier / '360 view' (Task 87)", runDossier},
		{"usage", "show per-tenant usage metering & chargeback report (Task 84)", runUsage},
		{"downloads", "show the download log: which package was downloaded from which client address — and by which user (Task 176)", runDownloads},
		{"userlinks", "list, revoke or issue personal cache links — the per-user addresses downloads are tracked by (Task 177)", runUserLinks},
		{"preset", "list/diff/apply curated compliance policy presets — SLSA/NIST SSDF/hardened (Task 88)", runPreset},
		{"compaction", "report cache compression & cross-artifact dedup space savings (Task 125)", runCompaction},
		{"cache-encryption", "report at-rest cache-encryption status or rotate the key-encryption key (Task 141)", runCacheEncryption},
		{"cache-tiering", "report hot/cold tiered cache storage status or trigger a demotion sweep (Task 154)", runCacheTiering},
		{"keys", "report signing-key/credential expiry status or rotate supported keys (Task 148)", runKeys},
		{"loadtest", "drive concurrent pulls against a running proxy and report latency/throughput/cache behavior (Task 105)", runLoadtest},
		{"perfguard", "run the committed benchmark suite and guard against performance regressions vs a baseline (Task 112)", runPerfguard},
		{"covguard", "measure statement coverage and guard against coverage regressions vs a committed baseline (Task 117)", runCovguard},
		{"mutguard", "measure test fault-detection via mutation testing and guard against regressions vs a committed baseline (Task 157)", runMutguard},
		{"redteam", "run the supply-chain attack red-team / gate-efficacy suite (Task 76)", runRedteam},
		{"testset", "validate and exercise the ecosystem test-set of real minimal builds (Task 99)", runTestset},
		{"verify-self", "verify this binary against its own signed release artifacts (signature/provenance/SBOM) (Task 135)", runVerifySelf},
		{"completion", "emit a shell-completion script (bash|zsh|fish)", runCompletion},
		{"version", "print the ptctl version", runVersionCmd},
		{"help", "show usage", func(args []string) error { usage(os.Stdout); return nil }},
	}
}

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "ptctl: %v\n", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	// A bare -version/--version (or -h/--help) before any subcommand is handled
	// for ergonomics, matching the server binary's behavior.
	if len(args) == 0 {
		usage(os.Stderr)
		return fmt.Errorf("a subcommand is required")
	}
	switch args[0] {
	case "-version", "--version":
		fmt.Println(version)
		return nil
	case "-h", "--help":
		usage(os.Stdout)
		return nil
	}

	for _, c := range commands() {
		if c.name == args[0] {
			return c.run(args[1:])
		}
	}
	usage(os.Stderr)
	return fmt.Errorf("unknown subcommand %q", args[0])
}

func runVersionCmd(args []string) error {
	fmt.Println(version)
	return nil
}

// usage prints the top-level help.
func usage(w *os.File) {
	fmt.Fprintln(w, "ptctl — client CLI for the pull-through security proxy")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Usage: ptctl <command> [flags]")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Commands:")
	for _, c := range commands() {
		fmt.Fprintf(w, "  %-11s %s\n", c.name, c.summary)
	}
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Global flags (accepted by every command):")
	fmt.Fprintln(w, "  --url           proxy base URL            (env PULLTHROUGH_URL)")
	fmt.Fprintln(w, "  --tenant        tenant/team scope         (env PULLTHROUGH_TENANT)")
	fmt.Fprintln(w, "  --token         proxy access token        (env PULLTHROUGH_TOKEN)")
	fmt.Fprintln(w, "  --admin-prefix  admin API prefix (/admin) (env PULLTHROUGH_ADMIN_PREFIX)")
	fmt.Fprintln(w, "  --insecure      skip TLS verification")
	fmt.Fprintln(w, "  --timeout       per-request timeout (default 30s)")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Run 'ptctl <command> -h' for command-specific flags.")
	fmt.Fprintln(w, "Run 'ptctl completion bash|zsh|fish' to enable shell completion.")
}

// commandNames returns the subcommand names, for shell completion.
func commandNames() []string {
	cs := commands()
	out := make([]string, 0, len(cs))
	for _, c := range cs {
		out = append(out, c.name)
	}
	return out
}
