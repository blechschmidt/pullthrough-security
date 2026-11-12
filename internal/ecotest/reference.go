package ecotest

import (
	"fmt"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// GenerateReference renders the ecosystem test reference as Markdown: for every
// ecosystem, the real client that is exercised, where it pulls from, the
// packages used, and — verbatim — the script that configures the client to use
// the proxy.
//
// It is generated from the catalog and the embedded client scripts, i.e. from
// exactly what CI runs, so the document cannot drift from the tests:
// `make ecosystem-reference-check` fails CI when the committed
// docs/ecosystem-tests-reference.md no longer matches this output. The output is
// deterministic (ecosystems sorted by ID, maps rendered in key order).
func GenerateReference() string {
	var b strings.Builder
	b.WriteString("# Ecosystem test reference (generated)\n\n")
	b.WriteString("<!-- GENERATED FILE — DO NOT EDIT.\n")
	b.WriteString("     Regenerate with `make ecosystem-reference-gen`.\n")
	b.WriteString("     Source of truth: internal/ecotest (catalog_data.go + clients/*.sh + clients/transparent/*.sh). -->\n\n")
	b.WriteString("This reference is generated from the real-package-manager ecosystem test suite\n")
	b.WriteString("([ecosystem-tests.md](ecosystem-tests.md)). For every supported ecosystem it shows the\n")
	b.WriteString("client that CI runs, the registry it pulls from through the proxy, and the exact\n")
	b.WriteString("script that points that client at the proxy.\n\n")
	b.WriteString("Because CI executes these scripts with the real clients against the real\n")
	b.WriteString("registries on every push, each one is a **continuously verified** client\n")
	b.WriteString("configuration: if a script here stops working, the build is red.\n\n")
	b.WriteString("In every script `$MOUNT` is the ecosystem's package source on the proxy\n")
	b.WriteString("(`https://proxy.example.com/v1/<upstream>`), `$PROXY_URL` is the proxy's base URL,\n")
	b.WriteString("`$PROXY_HOST` its `host:port`, and `$PKG_NAME` / `$PKG_VERSION` the package to\n")
	b.WriteString("install. The test proxy listens on loopback over plain HTTP unless noted.\n\n")
	b.WriteString("Each ecosystem also has an **interception script** — the same client, *not* pointed at\n")
	b.WriteString("the proxy at all ([intercept-mode.md](intercept-mode.md)). It keeps the client's own\n")
	b.WriteString("registry and only makes it trust the proxy's interception CA, `$PT_CA_CERT`. CI runs it\n")
	b.WriteString("twice: in **TLS-interception** mode, with the forward proxy exported as `HTTPS_PROXY`,\n")
	b.WriteString("`HTTP_PROXY` (and their lower-case forms) and as `$PT_INTERCEPT_PROXY` for the clients\n")
	b.WriteString("that need it spelled out; and in **NAT** mode, with nothing at all — the registry's\n")
	b.WriteString("hostnames resolve to the proxy's NAT listeners and nothing else is reachable.\n\n")

	cat := Catalog()

	b.WriteString("## Overview\n\n")
	b.WriteString("| Ecosystem | Client | Runs in | Pulls from | Installs | Refused | Interception | NAT |\n")
	b.WriteString("|---|---|---|---|---|---|:-:|:-:|\n")
	for _, e := range cat {
		bad := "— (no package coordinate)"
		if e.Bad != nil {
			bad = "`" + packageLabel(*e.Bad) + "`"
		}
		mark := func(reason string) string {
			if reason == "" {
				return "✓"
			}
			return "—"
		}
		fmt.Fprintf(&b, "| [%s](#%s) | %s | `%s` | %s | `%s` | %s | %s | %s |\n",
			e.ID, e.ID, e.Client, e.Image, e.Upstream.URL, packageLabel(e.Good), bad, mark(e.NoIntercept), mark(e.NoNAT))
	}
	b.WriteString("\n\"Installs\" is pinned to the benign commit of the test's source repository and must\n")
	b.WriteString("install; \"Refused\" is pinned to the commit the (mock) LLM flags malicious and must be\n")
	b.WriteString("blocked by the proxy. Nothing is wrong with the refused packages themselves.\n\n")

	for _, e := range cat {
		fmt.Fprintf(&b, "## %s\n\n", e.ID)

		fmt.Fprintf(&b, "- **Client:** %s, in `%s`", e.Client, e.Image)
		if e.runner() == RunnerDind {
			b.WriteString(" (a private Docker-in-Docker daemon whose registry mirror is the proxy)")
		}
		b.WriteString("\n")
		fmt.Fprintf(&b, "- **Upstream:** `%s` (type `%s`) → %s\n", e.Upstream.Name, e.Upstream.Type, e.Upstream.URL)
		if len(e.Upstream.Settings) > 0 {
			keys := make([]string, 0, len(e.Upstream.Settings))
			for k := range e.Upstream.Settings {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			for _, k := range keys {
				fmt.Fprintf(&b, "  - setting `%s: %s`\n", k, e.Upstream.Settings[k])
			}
		}
		if len(e.Upstream.Config) > 0 {
			// The configuration beyond type and URL (a generic upstream's route
			// table) is part of what makes the client work: show the entry.
			var doc strings.Builder
			enc := yaml.NewEncoder(&doc)
			enc.SetIndent(2)
			err := enc.Encode(map[string]any{"upstreams": map[string]any{e.Upstream.Name: upstreamEntry(e.Upstream)}})
			if err == nil {
				err = enc.Close()
			}
			if err != nil {
				fmt.Fprintf(&b, "  - _(configuration not renderable: %v)_\n", err)
			} else {
				b.WriteString("\n  ```yaml\n")
				for _, line := range strings.Split(strings.TrimRight(doc.String(), "\n"), "\n") {
					b.WriteString("  " + line + "\n")
				}
				b.WriteString("  ```\n\n")
			}
		}
		for _, u := range e.Extra {
			fmt.Fprintf(&b, "- **Also uses:** upstream `%s` (type `%s`) → %s, for the client's own tooling\n", u.Name, u.Type, u.URL)
		}
		if e.RegistryDefault != "" {
			fmt.Fprintf(&b, "- **Proxy setting:** `server.registry.defaultUpstream: %s`\n", e.RegistryDefault)
		}
		if e.TLS {
			b.WriteString("- **Transport:** HTTPS with a test CA (the client refuses a plain-HTTP source)\n")
		}
		if e.Bad != nil {
			fmt.Fprintf(&b, "- **Installs:** `%s` — pinned as %s\n", packageLabel(e.Good), pinLabel(e.Upstream.Type, e.Good))
		} else {
			// Without a package to refuse, the proxy runs no admission chain and
			// nothing is pinned.
			fmt.Fprintf(&b, "- **Installs:** `%s`\n", packageLabel(e.Good))
		}
		if e.Bad != nil {
			fmt.Fprintf(&b, "- **Refused:** `%s` — pinned as %s\n", packageLabel(*e.Bad), pinLabel(e.Upstream.Type, *e.Bad))
		} else {
			b.WriteString("- **Refused:** not applicable — the ecosystem has no package coordinate for the admission policy to gate\n")
		}
		if e.DownloadLog {
			b.WriteString("- **Download log:** asserted — each client run reaches the proxy from its own address; the log must show " +
				"the installed package for each of them and the refused one as blocked ([download-log.md](download-log.md))\n")
		}
		if e.NoPersonalLink != "" {
			fmt.Fprintf(&b, "- **Personal link:** not asserted here — %s\n", e.NoPersonalLink)
		} else {
			b.WriteString("- **Personal link:** asserted — the install is repeated with `$MOUNT` being a user's personal address " +
				"(`$PROXY_URL/u/<link>/v1/<upstream>`); the client must never leave it, and the download log must name the user " +
				"([user-links.md](user-links.md))\n")
		}
		if e.Notes != "" {
			fmt.Fprintf(&b, "- **Note:** %s\n", e.Notes)
		}

		script, err := e.Script()
		if err != nil {
			// Validate() guarantees every ecosystem has a script; keep the
			// generator total anyway so a broken catalog is visible in the output.
			fmt.Fprintf(&b, "\n_(client script missing: %v)_\n\n", err)
			continue
		}
		b.WriteString("\n```sh\n")
		b.WriteString(strings.TrimRight(string(script), "\n"))
		b.WriteString("\n```\n\n")

		writeTransparentReference(&b, e)
	}
	return b.String()
}

// writeTransparentReference renders an ecosystem's interception and NAT legs:
// what they assert, what the proxy needs beyond its upstreams, and the
// transparent script.
func writeTransparentReference(b *strings.Builder, e Ecosystem) {
	fmt.Fprintf(b, "### %s — interception and NAT\n\n", e.ID)
	if e.NoIntercept != "" {
		fmt.Fprintf(b, "- **TLS interception:** not asserted — %s\n", e.NoIntercept)
	} else {
		// What the leg asserts depends on what the explicit run has: a cache
		// entry to be served from, a package to refuse.
		what := "the package"
		if e.Bad != nil {
			what = "the good package"
		}
		what += " through the forward proxy"
		if e.Artifact != "" {
			what += ", out of the cache entry the explicit install filled"
		}
		if e.Bad != nil {
			what += ", and the bad package is refused"
		}
		fmt.Fprintf(b, "- **TLS interception:** asserted — the client, given only `HTTPS_PROXY` and the CA, installs %s\n", what)
	}
	if e.NoNAT != "" {
		fmt.Fprintf(b, "- **NAT:** not asserted — %s\n", e.NoNAT)
	} else {
		b.WriteString("- **NAT:** asserted — the same with nothing but the CA: the registry's hostnames lead to the proxy's NAT " +
			"listeners, and nothing else (not even the proxy's own address) is reachable\n")
	}
	if len(e.InterceptHosts) > 0 {
		rules := make([]string, 0, len(e.InterceptHosts))
		for rule := range e.InterceptHosts {
			rules = append(rules, rule)
		}
		sort.Strings(rules)
		for _, rule := range rules {
			fmt.Fprintf(b, "- **Proxy setting:** `server.intercept.hosts: {%s: %s}`\n", rule, e.InterceptHosts[rule])
		}
	}
	script, err := e.TransparentScript()
	if err != nil {
		b.WriteString("\n")
		return
	}
	b.WriteString("\n```sh\n")
	b.WriteString(strings.TrimRight(string(script), "\n"))
	b.WriteString("\n```\n\n")
}

// pinLabel renders the provenance pin a package gets, as it appears in the
// proxy configuration.
func pinLabel(ecosystem string, p Package) string {
	label := fmt.Sprintf("`{ecosystem: %s, name: %s", ecosystem, p.pinName())
	if p.CoordinateVersion != "" {
		label += ", version: " + p.CoordinateVersion
	}
	return label + "}`"
}
