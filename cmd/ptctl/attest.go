package main

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/blechschmidt/pullthrough-security/internal/attestbundle"
)

// attestListResp mirrors the admin GET /api/attest envelope (subset).
type attestListResp struct {
	Enabled bool                   `json:"enabled"`
	Items   []*attestbundle.Bundle `json:"items"`
}

// runAttest implements `ptctl attest <coordinate>`: it fetches the proxy's
// outbound, signed attestation bundle for a served artifact and either
// summarizes it (default) or emits the raw, verifiable DSSE envelope (-raw /
// -output) for piping into `pullthrough attest verify` or cosign.
func runAttest(args []string) error {
	fs := flag.NewFlagSet("attest", flag.ContinueOnError)
	var g globalFlags
	registerGlobals(fs, &g)
	var (
		raw    = fs.Bool("raw", false, "emit the raw DSSE envelope (for offline verification) instead of a summary")
		outDir = fs.String("output", "", "write the DSSE envelope to this file instead of stdout")
	)
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "Usage: ptctl attest [flags] <name[@version]>")
		fmt.Fprintln(os.Stderr, "Fetch the proxy's outbound attestation bundle for a served artifact.")
		fmt.Fprintln(os.Stderr)
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return err
	}
	coord := strings.TrimSpace(fs.Arg(0))
	if coord == "" {
		fs.Usage()
		return fmt.Errorf("a coordinate (name[@version]) is required")
	}

	c, err := newClient(g)
	if err != nil {
		return err
	}

	var resp attestListResp
	u := c.adminURL("api/attest", map[string]string{"tenant": c.tenant, "package": coord})
	if err := c.getJSON(u, &resp); err != nil {
		return err
	}
	if !resp.Enabled {
		return fmt.Errorf("outbound attestation is not enabled on the proxy")
	}
	if len(resp.Items) == 0 || resp.Items[0] == nil {
		return fmt.Errorf("no attestation for %q (it may not have been served through the proxy yet)", coord)
	}
	bundle := resp.Items[0]

	if *raw || *outDir != "" {
		envJSON, err := bundle.EnvelopeJSON()
		if err != nil {
			return fmt.Errorf("encoding DSSE envelope: %w", err)
		}
		if *outDir != "" {
			if err := os.WriteFile(*outDir, append(envJSON, '\n'), 0o644); err != nil {
				return fmt.Errorf("writing envelope: %w", err)
			}
			fmt.Fprintf(os.Stderr, "wrote DSSE envelope for %s to %s\n", bundle.Coordinate, *outDir)
			return nil
		}
		_, err = os.Stdout.Write(append(envJSON, '\n'))
		return err
	}

	return printAttestation(os.Stdout, bundle)
}

// printAttestation renders a human-readable summary of a bundle, including the
// signing identity and the admission verdict carried in the in-toto predicate.
func printAttestation(w *os.File, b *attestbundle.Bundle) error {
	fmt.Fprintf(w, "Coordinate:    %s\n", b.Coordinate)
	if b.SubjectDigest != "" {
		fmt.Fprintf(w, "Subject:       %s\n", b.SubjectDigest)
	}
	fmt.Fprintf(w, "Predicate:     %s\n", b.PredicateType)
	fmt.Fprintf(w, "Bundle digest: %s\n", b.Digest)
	if b.KeyID != "" {
		fmt.Fprintf(w, "Signed by key: %s\n", b.KeyID)
	}
	if !b.CreatedAt.IsZero() {
		fmt.Fprintf(w, "Created:       %s\n", b.CreatedAt.Format("2006-01-02 15:04:05 MST"))
	}

	stmt, err := b.Statement()
	if err != nil {
		fmt.Fprintf(w, "\n(could not decode the in-toto statement: %v)\n", err)
		return nil
	}
	p := stmt.Predicate
	if p.Source != nil && (p.Source.CommitSHA != "" || p.Source.RepositoryURL != "") {
		fmt.Fprintf(w, "Source:        %s @ %s\n", p.Source.RepositoryURL, p.Source.CommitSHA)
	}
	if p.Attester.ID != "" {
		fmt.Fprintf(w, "Attester:      %s %s\n", p.Attester.ID, p.Attester.Version)
	}

	adm := p.Admission
	verdict := adm.Verdict
	if verdict == "" {
		verdict = "admitted"
	}
	if adm.Warned {
		verdict += " (with warnings)"
	}
	fmt.Fprintf(w, "Admission:     %s\n", verdict)
	if len(adm.Gates) > 0 {
		fmt.Fprintln(w, "Gates:")
		for _, gate := range adm.Gates {
			mark := "✓"
			if gate.Decision == "warn" {
				mark = "!"
			}
			line := fmt.Sprintf("  %s %s: %s", mark, gate.Gate, gate.Decision)
			if gate.Summary != "" {
				line += " — " + gate.Summary
			}
			fmt.Fprintln(w, line)
		}
	}
	fmt.Fprintln(w, "\nFetch the raw, verifiable envelope with --raw, then verify offline:")
	fmt.Fprintf(w, "  ptctl attest %s --raw | pullthrough attest verify -pubkey <proxy-pubkey.pem>\n", b.Coordinate)
	return nil
}
