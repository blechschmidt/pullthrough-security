package main

import (
	"flag"
	"fmt"
	"net/http"
	"os"
	"strings"
)

// probeResult is the outcome of one connectivity probe.
type probeResult struct {
	Target  string
	URL     string
	Status  int    // HTTP status, 0 on transport error
	Verdict string // OK | AUTH | ERROR | UNREACHABLE
	Detail  string
}

func (r probeResult) ok() bool { return r.Verdict == "OK" }

// runSelftest implements `ptctl selftest`: it verifies the proxy is reachable
// (health endpoints) and then probes each enabled backend with a representative
// request, classifying the result so a developer can tell connectivity failures
// from auth failures from missing backends at a glance.
func runSelftest(args []string) error {
	fs := flag.NewFlagSet("selftest", flag.ContinueOnError)
	var g globalFlags
	registerGlobals(fs, &g)
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "Usage: ptctl selftest [flags] [name=type ...]")
		fmt.Fprintln(os.Stderr, "Check connectivity and auth against the proxy and each enabled backend.")
		fmt.Fprintln(os.Stderr)
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return err
	}

	c, err := newClient(g)
	if err != nil {
		return err
	}

	var results []probeResult
	// Health first: a failure here explains every subsequent backend failure.
	results = append(results, c.probe("health: /healthz", c.gatewayURL("healthz")))
	results = append(results, c.probe("ready: /readyz", c.gatewayURL("readyz")))

	backends, derr := resolveBackends(c, fs.Args())
	if derr != nil {
		// Discovery failure is informative but not fatal: still report health.
		fmt.Fprintf(os.Stderr, "note: %v\n", derr)
	}
	for _, b := range backends {
		path, _ := probePath(b)
		results = append(results, c.probe(
			fmt.Sprintf("%s (%s)", b.Name, orUnknown(b.Type)),
			c.gatewayURL(path)))
	}

	failed := printProbeTable(os.Stdout, results)
	if failed > 0 {
		return fmt.Errorf("%d of %d checks did not pass", failed, len(results))
	}
	return nil
}

// probe issues a GET and classifies the response into a verdict. It treats any
// HTTP response as "reachable" (network + TLS + routing worked); 401/403 is an
// auth problem; 5xx is a proxy/upstream error; transport errors are unreachable.
func (c *client) probe(target, u string) probeResult {
	req, err := http.NewRequest(http.MethodGet, u, nil)
	if err != nil {
		return probeResult{Target: target, URL: u, Verdict: "ERROR", Detail: err.Error()}
	}
	c.authorize(req)
	resp, err := c.http.Do(req)
	if err != nil {
		return probeResult{Target: target, URL: u, Verdict: "UNREACHABLE", Detail: transportHint(err)}
	}
	defer resp.Body.Close()
	res := probeResult{Target: target, URL: u, Status: resp.StatusCode}
	switch {
	case resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden:
		res.Verdict = "AUTH"
		res.Detail = "authentication required or token rejected"
	case resp.StatusCode >= 500:
		res.Verdict = "ERROR"
		res.Detail = "proxy/upstream error"
	case resp.StatusCode == http.StatusNotFound:
		// The mount answered but this representative path has no content; the
		// backend is wired, so treat it as reachable with a note.
		res.Verdict = "OK"
		res.Detail = "reachable (probe path returned 404)"
	default:
		res.Verdict = "OK"
	}
	return res
}

// probePath returns a representative gateway path for a backend type and whether
// a 200 is expected (for documentation; classification is status-based). The
// path always includes the /v1/<name>/ mount prefix.
func probePath(b backend) (string, bool) {
	mount := "v1/" + b.Name
	switch b.Type {
	case "npm":
		return mount + "/", true
	case "pip", "pypi":
		return mount + "/simple/", true
	case "cargo":
		return mount + "/config.json", true
	case "nuget":
		return mount + "/v3/index.json", true
	case "docker", "oci":
		return mount + "/v2/", true
	case "helm":
		return mount + "/index.yaml", true
	case "rubygems":
		return mount + "/versions", true
	case "composer":
		return mount + "/packages.json", true
	case "terraform":
		return mount + "/.well-known/terraform.json", true
	case "conan":
		// /v2/ping is the Conan capability probe; full servers (Artifactory) answer
		// 200, but ConanCenter's read-only CDN returns 404, so a 200 is not assumed.
		return mount + "/v2/ping", false
	case "conda":
		// The noarch repodata.json index exists for every channel.
		return mount + "/noarch/repodata.json", true
	case "cran":
		// The source-package index exists for every CRAN repository.
		return mount + "/src/contrib/PACKAGES", true
	case "cpan":
		// The master package index exists for every CPAN mirror.
		return mount + "/modules/02packages.details.txt.gz", true
	case "hex":
		// The /versions registry resource exists for every Hex repository.
		return mount + "/versions", true
	case "bazel":
		// bazel_registry.json exists at the root of every Bazel module registry.
		return mount + "/bazel_registry.json", true
	case "julia":
		// /registries lists the server's registries and exists on every Pkg Server.
		return mount + "/registries", true
	case "jsr":
		// A well-known package's meta.json; a bare scope/name has no always-200
		// guarantee across registries, so a 200 is not assumed.
		return mount + "/@std/encoding/meta.json", false
	case "hackage":
		// The incremental package index exists for every Hackage repository.
		return mount + "/01-index.tar.gz", true
	case "nix":
		// /nix-cache-info exists at the root of every Nix binary cache.
		return mount + "/nix-cache-info", true
	case "homebrew":
		// A well-known formula's metadata document; a bare formula name has no
		// always-200 guarantee across mirrors, so a 200 is not assumed.
		return mount + "/api/formula/wget.json", false
	case "ansible":
		// A well-known collection's index document; a bare namespace/name has no
		// always-200 guarantee across Galaxy deployments, so a 200 is not assumed.
		return mount + "/api/v3/plugin/ansible/content/published/collections/index/community/general/", false
	case "puppet":
		// A well-known module's metadata document; a bare owner-name slug has no
		// always-200 guarantee across Forge deployments, so a 200 is not assumed.
		return mount + "/v3/modules/puppetlabs-stdlib", false
	case "openvsx":
		// A well-known extension's metadata document; a bare namespace/extension has
		// no always-200 guarantee across registries, so a 200 is not assumed.
		return mount + "/api/redhat/java", false
	case "swift":
		// Release-list for a well-known package; a bare scope/name has no always-200
		// guarantee across registries, so a 200 is not assumed.
		return mount + "/apple/swift-nio", false
	case "dart", "pub":
		// The list-versions document for a well-known package.
		return mount + "/api/packages/path", false
	default:
		// go, maven, apt, yum, git and unknown types have no single cheap
		// always-200 endpoint; the mount root still exercises routing+auth.
		return mount + "/", false
	}
}

// transportHint adds onboarding-friendly guidance to common transport errors.
func transportHint(err error) string {
	msg := err.Error()
	switch {
	case strings.Contains(msg, "certificate"):
		return msg + " (pass --insecure for a self-signed dev proxy)"
	case strings.Contains(msg, "no such host"):
		return msg + " (check --url)"
	case strings.Contains(msg, "connection refused"):
		return msg + " (is the proxy running and reachable?)"
	case strings.Contains(msg, "context deadline exceeded") || strings.Contains(msg, "Timeout"):
		return msg + " (increase --timeout?)"
	default:
		return msg
	}
}

// printProbeTable renders the results as an aligned table and returns the number
// of non-OK results.
func printProbeTable(w *os.File, results []probeResult) int {
	width := 0
	for _, r := range results {
		if len(r.Target) > width {
			width = len(r.Target)
		}
	}
	failed := 0
	for _, r := range results {
		mark := "✓"
		if !r.ok() {
			mark = "✗"
			failed++
		}
		status := "-"
		if r.Status > 0 {
			status = fmt.Sprintf("%d", r.Status)
		}
		fmt.Fprintf(w, "%s  %-*s  %-11s %-4s %s\n", mark, width, r.Target, r.Verdict, status, r.Detail)
	}
	fmt.Fprintf(w, "\n%d/%d checks passed.\n", len(results)-failed, len(results))
	return failed
}
