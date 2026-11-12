package scancoverage

import (
	"fmt"
	"sort"
	"strings"
)

// ServePath describes one way bytes reach a client, and where the LLM package
// scan sits on it.
type ServePath struct {
	Path string
	// How says how the gate applies there.
	How string
}

// ServePaths lists every path an artifact's bytes can take to a client. Each
// row is covered by a test in internal/proxy (llmpkgscan_paths_test.go) or
// internal/git.
func ServePaths() []ServePath {
	return []ServePath{
		{"Cacheable artifact, cache miss", "Fetched into the content cache; the gate runs on the cache entry before any byte is written. A refused artifact is evicted."},
		{"Cacheable artifact, cache hit", "The gate runs on every hit as well. Bytes that already have a verdict are answered from the verdict store (no model call); bytes that do not — an entry written before the gate was enabled — are scanned then."},
		{"Non-cacheable response (a snapshot build, an image manifest by tag, a file on a moving branch, a path the adapter does not know)", "The first bytes decide whether there is anything to examine. If there is, the response is held in a spool file until the verdict exists and is served from the spool; a refusal is written before any byte of it. The verdict is stored under the digest of the held bytes."},
		{"Non-cacheable response larger than `limits.maxArtifactBytes`", "Cannot be held whole: reported `oversized`, and `failMode` decides (under fail-open the held prefix and the rest of the stream are served in order)."},
		{"`Range` request", "The cached path cuts the range from the entry after the gate has passed; the non-cacheable path ignores `Range` upstream and serves the gated response whole; Git LFS serves ranges after its serve gate. A range is never a way around a verdict or to a slice of an artifact that has none."},
		{"`HEAD` request", "No body is served. On the cached path the gate still runs (the artifact is fetched); on the non-cacheable path nothing is downloaded or scanned."},
		{"OCI image manifest (by tag or digest)", "The image is examined as a whole — config, history, every layer — and the verdict stored under the manifest digest. The manifest response is held until it exists."},
		{"OCI blob (config or layer)", "Refused when a refusing image verdict implicates it (a layer its confirmed evidence cites; its config, unless an image the gate serves has the same config); served without a scan of its own when an image scan read it in full; examined alone otherwise — a layer the image scan's budget did not reach, or one whose manifest was never pulled here — as a root-filesystem layer, under its own digest."},
		{"Git LFS object", "The Git backend's serve gate: every object request — hit or miss, whole or ranged — passes the gate after the object is cached and before a byte is written. A refused object is evicted."},
		{"Git clone / fetch", "Not this gate, and not gated by any other: the Git backend serves smart-HTTP and SSH itself. The LLM commit scan judges the commits of watched repositories and of the commits packages were built from; its verdicts raise findings and gate those packages, but do not refuse a clone or fetch."},
		{"Cache-federation peer endpoint (a sibling proxy reads this proxy's cache)", "Nothing is scanned there; a stored verdict is enforced: an entry whose bytes have a refusing verdict, or that is a blob implicated by a refused image, is answered 403. The receiving proxy runs its own gates on what it is given."},
		{"Cache miss filled from a sibling proxy", "The filled entry is put before this proxy's own gate like one fetched from the upstream."},
		{"Predictive pre-warm", "Drives the same pipeline as a client pull: the gate runs, and a refused artifact is not left in the cache."},
		{"TLS-intercepted request (forward-proxy or NAT mode)", "Decrypted, mapped onto the upstream's route and served by the same pipeline as a request sent to the proxy directly: every row of this table applies, and the artifact lands in the same cache entry. A host no upstream is configured for is refused, or — only with `passthroughUnmatched` — passed on without being decrypted (a CONNECT tunnel, or a NAT connection relayed to its original destination), which is outside every gate."},
		{"Air-gap import / restored cache", "Entries arrive in the cache without having been pulled; they are gated when served (the cache-hit row). Verdicts travel with the bundle (`pullthrough export` / `import`) and are imported when the bundle's manifest digest was verified out of band, so an air-gapped instance enforces them without reaching a provider."},
	}
}

// Format describes one artifact format the shared unpack layer opens.
type Format struct {
	Format string
	UsedBy string
	// Shown says what the model is given beyond the member listing.
	Shown string
}

// Formats lists the container formats the unpacker (internal/contentscan) opens
// for the scan. Each has a test against an archive written by the real tool, or
// a synthetic one, in internal/contentscan and internal/llmpkgscan.
func Formats() []Format {
	return []Format{
		{"tar, plain or under gzip / bzip2 / xz / zstd / lzma", "npm, sdist, .crate, Helm, conda .tar.bz2, CRAN, CPAN, Hackage, pub, Conan, Bazel, Julia, Ansible, Puppet, Homebrew bottles, Terraform modules, OCI layers", "members; a damaged header is skipped the way lenient extractors skip it"},
		{"zip (also behind a prefix: zipapp, executable jar, self-extractor)", "wheel, Go module, .nupkg, jar / war, .vsix, Composer, Terraform provider, Swift, Bazel", "members; the bytes in front of a prefixed zip as an entry of their own"},
		{".gem (tar holding data.tar.gz)", "RubyGems", "the files of data.tar.gz, metadata, checksums"},
		{"Hex package (tar holding contents.tar.gz)", "Hex", "the files of contents.tar.gz, metadata.config"},
		{".conda (zip holding info-*.tar.zst and pkg-*.tar.zst)", "conda", "the members of both inner archives"},
		{".deb (ar holding control.tar.* and data.tar.*)", "APT", "maintainer scripts and control files under `DEBIAN/`, then the data files"},
		{".rpm (lead, signature, header, compressed cpio payload; RPM 4 and RPM 6)", "YUM / DNF", "scriptlets and triggers from the header as `RPM/scriptlets/*` and `RPM/triggers/*`, a header summary, then the payload files"},
		{"cpio (newc, crc, odc) and ar", "RPM payloads, static libraries", "members"},
		{"NAR, plain or compressed", "Nix", "the store path's files, with their executable bits"},
		{"OCI image (manifest + config + layers)", "Docker / OCI, Helm OCI charts, other OCI artifacts", "`image/run.txt` (user, entrypoint, command, environment, …), `image/history.txt`, the config and manifest, and every layer's files under `layers/NNN-<digest>/`, top-most layer first"},
		{"single file, plain or compressed", "POM, Package.swift, conanfile.py, MODULE.bazel, JSR module files, model repository files, installers, Git LFS objects", "the file; for a binary its kind, a strings view and — for a pickle or a safetensors file — a proxy-written summary of what it imports or declares"},
		{"archive inside an archive (two levels)", "any", "the inner archive's members under `<member>!/`"},
		{"a file that is two archives at once (zip from its end + another format from its start)", "any", "both readings: the second under `_same-file-read-as-zip!/` or `_same-file-read-as-tar!/`"},
	}
}

// GenerateReference renders the coverage record as Markdown. The output is
// deterministic: entries are sorted by type and every list is rendered in a
// fixed order, so `make llmscan-coverage-check` can compare it byte for byte
// with the committed docs/llm-package-scan-coverage.md.
func GenerateReference() string {
	var b strings.Builder
	b.WriteString("# LLM scan coverage (generated)\n\n")
	b.WriteString("<!-- GENERATED FILE — DO NOT EDIT.\n")
	b.WriteString("     Regenerate with `make llmscan-coverage-gen`.\n")
	b.WriteString("     Source of truth: internal/scancoverage (catalog_data.go). -->\n\n")
	b.WriteString("This is the record of which content the LLM scans examine, per upstream type: the\n")
	b.WriteString("request paths that carry something a client installs, unpacks or runs, the format\n")
	b.WriteString("each arrives in, and the serve path it takes — and the documents next to them that\n")
	b.WriteString("the scan leaves alone. See [llm-package-scan.md](llm-package-scan.md) for how the\n")
	b.WriteString("gate works.\n\n")
	b.WriteString("It is generated from a catalog that is checked against the code on every build:\n\n")
	b.WriteString("- every example path below is resolved against the real backend, built the way\n")
	b.WriteString("  the server builds it, and must be classified and cached exactly as stated;\n")
	b.WriteString("- every upstream type the configuration accepts must have an entry, so a backend\n")
	b.WriteString("  added later cannot be left out of the scan without that being a decision;\n")
	b.WriteString("- every ecosystem scanned by default must have a test that unpacks, ranks and\n")
	b.WriteString("  judges an artifact in its real format.\n\n")

	b.WriteString("## How a request is classified\n\n")
	b.WriteString("Each backend states what a resolved request is. The gate acts on that statement,\n")
	b.WriteString("and on the bytes:\n\n")
	b.WriteString("| Class | Meaning | What the gate does |\n|---|---|---|\n")
	b.WriteString("| `payload` | Something a client installs, unpacks, builds, imports or executes. | Always examined. Bytes that do not unpack are reported `unsupported-format` — never read as a harmless file — unless the backend marked the payload as one that may be a single file. |\n")
	b.WriteString("| `metadata` | An index, a listing, a checksum or signature sidecar. | Left alone once its first bytes have shown it is not a package archive, an executable, a script or a pickle after all: a hostile repository names each package's download path in its own index, so a path that reads as an index proves nothing. |\n")
	b.WriteString("| `unclassified` | The backend made no statement (a pass-through path). | Judged from its bytes: an archive, an executable, a script or a pickle is examined; so is content named like a package archive; anything else is left alone. |\n\n")
	b.WriteString("A compressed response that will not show what it holds is examined under every\n")
	b.WriteString("class: \"cannot tell\" is never read as \"nothing there\".\n\n")

	b.WriteString("## Serve paths\n\n")
	b.WriteString("| Path to the client | Where the gate sits |\n|---|---|\n")
	for _, sp := range ServePaths() {
		fmt.Fprintf(&b, "| %s | %s |\n", sp.Path, sp.How)
	}
	b.WriteString("\n")

	b.WriteString("## Artifact formats\n\n")
	b.WriteString("| Format | Used by | What the model is shown |\n|---|---|---|\n")
	for _, f := range Formats() {
		fmt.Fprintf(&b, "| %s | %s | %s |\n", f.Format, f.UsedBy, f.Shown)
	}
	b.WriteString("\nAn artifact larger than `limits.maxArtifactBytes` follows `llmPackageScan.oversize`:\n")
	b.WriteString("`fail` (no verdict; `failMode` decides) or `metadata-only` (the inventory and the\n")
	b.WriteString("scripts within the limit are judged, and the verdict is recorded as partial).\n\n")

	cat := Catalog()
	b.WriteString("## Coverage by upstream type\n\n")
	b.WriteString("| Upstream type | Examined by | Scope key | Payload formats | Serve paths |\n|---|---|---|---|---|\n")
	for _, e := range cat {
		name := "[`" + e.Type + "`](#" + anchor(e) + ")"
		for _, a := range e.Aliases {
			name += " / `" + a + "`"
		}
		scope := "—"
		if e.Ecosystem != "" {
			scope = "`" + e.Ecosystem + "`"
		}
		fmt.Fprintf(&b, "| %s | %s | %s | %s | %s |\n", name, gateName(e.Gate), scope, joinUnique(e.Payloads(), func(p Path) string { return p.Format }), joinUnique(e.Payloads(), func(p Path) string { return p.Serve }))
	}
	b.WriteString("\nThe scope key is what `llmPackageScan.include` / `exclude` name. With `include`\n")
	b.WriteString("empty every key in this table is scanned.\n\n")

	for _, e := range cat {
		fmt.Fprintf(&b, "### %s\n\n", e.Title)
		fmt.Fprintf(&b, "Upstream type `%s`", e.Type)
		if len(e.Aliases) > 0 {
			fmt.Fprintf(&b, " (also `%s`)", strings.Join(e.Aliases, "`, `"))
		}
		fmt.Fprintf(&b, " — examined by the %s", gateName(e.Gate))
		if e.Ecosystem != "" {
			fmt.Fprintf(&b, ", scope key `%s`", e.Ecosystem)
		}
		b.WriteString(".\n\n")
		if len(e.Settings) > 0 {
			keys := make([]string, 0, len(e.Settings))
			for k := range e.Settings {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			b.WriteString("Examples assume the upstream settings")
			for i, k := range keys {
				if i > 0 {
					b.WriteString(",")
				}
				fmt.Fprintf(&b, " `%s: %s`", k, e.Settings[k])
			}
			b.WriteString(".\n\n")
		}
		if len(e.Routes) > 0 {
			b.WriteString("Examples assume these routes:\n\n")
			b.WriteString("| Route | Match | Cacheable | Rewrite | Gates |\n|---|---|---|---|---|\n")
			for _, r := range e.Routes {
				gates := "—"
				if len(r.Gates) > 0 {
					gates = "`" + strings.Join(r.Gates, "`, `") + "`"
				}
				fmt.Fprintf(&b, "| %s | `%s` | %v | %v | %s |\n", r.Name, strings.ReplaceAll(r.Match, "|", "\\|"), r.Cacheable, r.Rewrite, gates)
			}
			b.WriteString("\n")
		}
		b.WriteString("| Request | Example path | Class | Format | Serve path |\n|---|---|---|---|---|\n")
		for _, p := range e.Paths {
			class := "`" + p.Class + "`"
			if p.Kind != "" {
				class += " (`" + p.Kind + "`)"
			}
			format := p.Format
			if format == "" {
				format = "—"
			}
			fmt.Fprintf(&b, "| %s | `%s` | %s | %s | %s |\n", p.What, p.Example, class, format, p.Serve)
		}
		b.WriteString("\n")
		for _, n := range e.Notes {
			fmt.Fprintf(&b, "- %s\n", n)
		}
		if len(e.Notes) > 0 {
			b.WriteString("\n")
		}
	}
	return b.String()
}

func anchor(e Entry) string {
	var b strings.Builder
	for _, r := range strings.ToLower(e.Title) {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '-':
			b.WriteRune(r)
		case r == ' ':
			b.WriteByte('-')
		}
	}
	return b.String()
}

func gateName(gate string) string {
	switch gate {
	case GatePackageScan:
		return "LLM package scan"
	case GateCommitScan:
		// Said wherever the gate is named: "examined by the commit scan" must not
		// read as "gated by it".
		return "LLM commit scan (examines the commits of watched repositories; refuses no clone or fetch)"
	}
	return gate
}

// joinUnique joins the distinct, non-empty values of f over paths, in order of
// first appearance.
func joinUnique(paths []Path, f func(Path) string) string {
	seen := map[string]bool{}
	var out []string
	for _, p := range paths {
		v := f(p)
		if v == "" || seen[v] {
			continue
		}
		seen[v] = true
		out = append(out, v)
	}
	if len(out) == 0 {
		return "—"
	}
	return strings.Join(out, "; ")
}
