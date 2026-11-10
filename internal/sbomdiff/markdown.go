package sbomdiff

import (
	"fmt"
	"strconv"
	"strings"
)

// Markdown renders a diff as a human-readable Markdown report, suitable for the
// admin "what changed?" endpoint, a PR comment, or a CLI dump. The output is
// deterministic (every slice in the diff is already sorted), so it is
// golden-testable.
func (d *Diff) Markdown() string {
	var b strings.Builder
	coord := d.Coordinate
	fmt.Fprintf(&b, "# Dependency drift: %s %s → %s\n\n", coord, d.From.Version, d.To.Version)
	fmt.Fprintf(&b, "- Ecosystem: `%s`\n", d.Ecosystem)
	if d.Tenant != "" {
		fmt.Fprintf(&b, "- Tenant: `%s`\n", d.Tenant)
	}
	fmt.Fprintf(&b, "- Drift score: **%s / 100**%s\n", trimFloat(d.DriftScore), significantSuffix(d.Significant))
	fmt.Fprintf(&b, "- Dependencies: %d → %d\n", d.From.DepCount, d.To.DepCount)
	fmt.Fprintf(&b, "- Vulnerabilities: %d → %d\n\n", d.From.VulnCount, d.To.VulnCount)

	if d.Empty() {
		b.WriteString("_No material change between these versions._\n")
		return b.String()
	}

	section := func(title string, n int) {
		fmt.Fprintf(&b, "## %s (%d)\n\n", title, n)
	}

	if len(d.NewVulnerabilities) > 0 {
		section("Net-new vulnerabilities", len(d.NewVulnerabilities))
		b.WriteString("| Advisory | Severity | Package | CVSS |\n|---|---|---|---|\n")
		for _, v := range d.NewVulnerabilities {
			cvss := ""
			if v.CVSS > 0 {
				cvss = trimFloat(v.CVSS)
			}
			fmt.Fprintf(&b, "| %s | %s | %s | %s |\n", mdCell(v.ID), mdCell(v.Severity), mdCell(v.Package), cvss)
		}
		b.WriteString("\n")
	}

	if len(d.NewLicenses) > 0 {
		section("Newly-introduced licenses", len(d.NewLicenses))
		b.WriteString("| License | Disposition | Component |\n|---|---|---|\n")
		for _, l := range d.NewLicenses {
			disp := l.Disposition
			if disp == "" {
				disp = "—"
			}
			fmt.Fprintf(&b, "| %s | %s | %s |\n", mdCell(l.License), mdCell(disp), mdCell(l.Component))
		}
		b.WriteString("\n")
	}

	if len(d.NewNamespaces) > 0 {
		section("Newly-introduced namespaces / maintainers", len(d.NewNamespaces))
		for _, ns := range d.NewNamespaces {
			fmt.Fprintf(&b, "- `%s`\n", ns)
		}
		b.WriteString("\n")
	}

	if len(d.AddedDeps) > 0 {
		section("Added dependencies", len(d.AddedDeps))
		b.WriteString("| Dependency | Version | Namespace |\n|---|---|---|\n")
		for _, dep := range d.AddedDeps {
			fmt.Fprintf(&b, "| %s | %s | %s |\n", mdCell(dep.Name), mdCell(dep.Version), mdCell(dep.Namespace))
		}
		b.WriteString("\n")
	}

	if len(d.VersionBumps) > 0 {
		section("Version-bumped dependencies", len(d.VersionBumps))
		b.WriteString("| Dependency | From | To | Direction |\n|---|---|---|---|\n")
		for _, vb := range d.VersionBumps {
			fmt.Fprintf(&b, "| %s | %s | %s | %s |\n", mdCell(vb.Name), mdCell(vb.FromVersion), mdCell(vb.ToVersion), mdCell(vb.Direction))
		}
		b.WriteString("\n")
	}

	if len(d.RemovedDeps) > 0 {
		section("Removed dependencies", len(d.RemovedDeps))
		b.WriteString("| Dependency | Version | Namespace |\n|---|---|---|\n")
		for _, dep := range d.RemovedDeps {
			fmt.Fprintf(&b, "| %s | %s | %s |\n", mdCell(dep.Name), mdCell(dep.Version), mdCell(dep.Namespace))
		}
		b.WriteString("\n")
	}

	if len(d.Contributions) > 0 {
		b.WriteString("## Drift-score breakdown\n\n")
		b.WriteString("| Factor | Count | Points |\n|---|---|---|\n")
		for _, c := range d.Contributions {
			fmt.Fprintf(&b, "| %s | %d | %s |\n", mdCell(c.Factor), c.Count, trimFloat(c.Points))
		}
		b.WriteString("\n")
	}

	return b.String()
}

func significantSuffix(sig bool) string {
	if sig {
		return " ⚠️ significant"
	}
	return ""
}

// trimFloat formats a float without a trailing ".0" and at most one decimal.
func trimFloat(f float64) string {
	s := strconv.FormatFloat(f, 'f', 1, 64)
	s = strings.TrimSuffix(s, ".0")
	return s
}

// mdCell escapes a table cell so a pipe in a value cannot break the table, and
// renders an empty value as an em-dash.
func mdCell(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return "—"
	}
	return strings.ReplaceAll(s, "|", "\\|")
}
