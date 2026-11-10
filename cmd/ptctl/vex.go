package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
)

// runVEX implements `ptctl vex export`: a thin client over the proxy's outbound
// VEX authoring endpoint (Task 137). It renders the proxy's current VEX posture
// — the not_affected/fixed suppression corpus, VEX-adjudicated findings, and
// active break-glass grants — as an OpenVEX document or a CycloneDX VEX/VDR BOM,
// scoped to a single coordinate, a captured snapshot, or the whole live set, and
// optionally cosign-signed with a detached signature.
//
// It is HTTP-only and read-only: it calls the admin GET /api/vex/export endpoint.
func runVEX(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("vex: a subcommand is required (export)")
	}
	switch args[0] {
	case "export":
		return runVEXExport(args[1:])
	default:
		return fmt.Errorf("vex: unknown subcommand %q (want: export)", args[0])
	}
}

func runVEXExport(args []string) error {
	fs := flag.NewFlagSet("vex export", flag.ContinueOnError)
	var g globalFlags
	registerGlobals(fs, &g)
	var (
		format    = fs.String("format", "openvex", "output format: openvex | cyclonedx")
		ecosystem = fs.String("ecosystem", "", "artifact ecosystem (npm|pip|cargo|go|nuget|…) for a single-coordinate export")
		coord     = fs.String("coordinate", "", "artifact selector 'name@version' or digest (alternative to positional args)")
		snapshot  = fs.String("snapshot", "", "export the VEX posture for a captured snapshot id (its coordinate set)")
		sign      = fs.Bool("sign", false, "attach a detached cosign-compatible signature (requires a signing key on the proxy)")
		output    = fs.String("output", "", "write the document to this file (default stdout)")
		sigOut    = fs.String("sig-out", "", "write the detached signature JSON to this file (requires --sign)")
	)
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "Usage: ptctl vex export [flags] [--ecosystem <eco>] [<name> [version]]")
		fmt.Fprintln(os.Stderr, "       ptctl vex export [flags] --coordinate <name@version>")
		fmt.Fprintln(os.Stderr, "       ptctl vex export [flags] --snapshot <id>")
		fmt.Fprintln(os.Stderr, "       ptctl vex export [flags]            # whole live posture for --tenant")
		fmt.Fprintln(os.Stderr, "\nGenerate an OpenVEX document or CycloneDX VEX/VDR BOM from the proxy's VEX posture.")
		fmt.Fprintln(os.Stderr, "\nFlags:")
		fs.PrintDefaults()
		fmt.Fprintln(os.Stderr, "\nExamples:")
		fmt.Fprintln(os.Stderr, "  ptctl vex export --ecosystem npm lodash 4.17.21")
		fmt.Fprintln(os.Stderr, "  ptctl vex export --ecosystem pip requests@2.19.0 --format cyclonedx")
		fmt.Fprintln(os.Stderr, "  ptctl vex export --tenant acme --sign --output acme-vex.json --sig-out acme-vex.sig.json")
	}
	if err := fs.Parse(args); err != nil {
		return err
	}

	name := strings.TrimSpace(fs.Arg(0))
	version := strings.TrimSpace(fs.Arg(1))
	if name != "" && version == "" {
		if i := strings.LastIndexByte(name, '@'); i > 0 {
			version = name[i+1:]
			name = name[:i]
		}
	}
	if *sigOut != "" && !*sign {
		return fmt.Errorf("vex export: --sig-out requires --sign")
	}

	c, err := newClient(g)
	if err != nil {
		return err
	}

	query := map[string]string{
		"format":     strings.TrimSpace(*format),
		"tenant":     c.tenant,
		"ecosystem":  strings.TrimSpace(*ecosystem),
		"name":       name,
		"version":    version,
		"coordinate": strings.TrimSpace(*coord),
		"snapshot":   strings.TrimSpace(*snapshot),
	}
	if *sign {
		query["sign"] = "true"
	}

	body, headers, err := c.getRaw(c.adminURL("api/vex/export", query))
	if err != nil {
		if ae, ok := err.(*apiError); ok && ae.Status == 404 {
			return fmt.Errorf("outbound VEX export is not enabled on the proxy (set vulnerabilities.vex.export.enabled)")
		}
		return err
	}

	// Write the document.
	if *output != "" {
		if err := os.WriteFile(*output, body, 0o644); err != nil {
			return fmt.Errorf("vex export: writing %s: %w", *output, err)
		}
		fmt.Fprintf(os.Stderr, "vex export: wrote %s (%s, %s statements, scope %s)\n",
			*output, headers.Get("X-Vex-Statements"), headers.Get("X-Vex-Coordinates"), headers.Get("X-Vex-Scope"))
	} else {
		if _, err := os.Stdout.Write(body); err != nil {
			return err
		}
		if len(body) > 0 && body[len(body)-1] != '\n' {
			fmt.Fprintln(os.Stdout)
		}
	}

	// Surface the detached signature.
	if *sign {
		sig := map[string]string{
			"algorithm": headers.Get("X-Vex-Signature-Algorithm"),
			"keyId":     headers.Get("X-Vex-Signature-Key-Id"),
			"digest":    headers.Get("X-Vex-Digest"),
			"signature": headers.Get("X-Vex-Signature"),
		}
		enc, _ := json.MarshalIndent(sig, "", "  ")
		if *sigOut != "" {
			if err := os.WriteFile(*sigOut, append(enc, '\n'), 0o644); err != nil {
				return fmt.Errorf("vex export: writing signature %s: %w", *sigOut, err)
			}
			fmt.Fprintf(os.Stderr, "vex export: wrote detached signature to %s (keyId %s)\n", *sigOut, sig["keyId"])
		} else if *output != "" {
			fmt.Fprintf(os.Stderr, "vex export: signature keyId=%s algorithm=%s digest=%s\n", sig["keyId"], sig["algorithm"], sig["digest"])
		}
	}
	return nil
}
