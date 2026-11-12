package ecotest

import (
	"fmt"
	"sort"
	"strings"
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
	b.WriteString("     Source of truth: internal/ecotest (catalog_data.go + clients/*.sh). -->\n\n")
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

	cat := Catalog()

	b.WriteString("## Overview\n\n")
	b.WriteString("| Ecosystem | Client | Runs in | Pulls from | Installs | Refused |\n")
	b.WriteString("|---|---|---|---|---|---|\n")
	for _, e := range cat {
		bad := "— (no package coordinate)"
		if e.Bad != nil {
			bad = "`" + packageLabel(*e.Bad) + "`"
		}
		fmt.Fprintf(&b, "| [%s](#%s) | %s | `%s` | %s | `%s` | %s |\n",
			e.ID, e.ID, e.Client, e.Image, e.Upstream.URL, packageLabel(e.Good), bad)
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
		for _, u := range e.Extra {
			fmt.Fprintf(&b, "- **Also uses:** upstream `%s` (type `%s`) → %s, for the client's own tooling\n", u.Name, u.Type, u.URL)
		}
		if e.RegistryDefault != "" {
			fmt.Fprintf(&b, "- **Proxy setting:** `server.registry.defaultUpstream: %s`\n", e.RegistryDefault)
		}
		if e.TLS {
			b.WriteString("- **Transport:** HTTPS with a test CA (the client refuses a plain-HTTP source)\n")
		}
		fmt.Fprintf(&b, "- **Installs:** `%s` — pinned as %s\n", packageLabel(e.Good), pinLabel(e.Upstream.Type, e.Good))
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
	}
	return b.String()
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
