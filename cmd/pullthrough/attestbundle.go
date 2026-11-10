package main

import (
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"strings"

	"github.com/blechschmidt/pullthrough-security/internal/attestbundle"
	"github.com/blechschmidt/pullthrough-security/internal/config"
	"github.com/blechschmidt/pullthrough-security/internal/policyengine"
	"github.com/blechschmidt/pullthrough-security/internal/sigverify"
)

// buildAttestor constructs the outbound attestation engine (Task 46) when
// enabled and a signing key is available. The signing key is, in order of
// preference: an attestation-specific key (attest.signingKey[File]), else the
// audit transparency checkpoint signing key (so a signed audit log automatically
// makes the proxy an attester at no extra config). When no key is available the
// engine stays inactive — an unsigned attestation would be worthless — and the
// reason is logged. It returns a nil *Service when disabled/inactive.
func buildAttestor(cfg *config.Config, rekorDeps *rekorDeps, logger *slog.Logger) (*attestbundle.Service, error) {
	ac := cfg.Attest
	if !ac.Enabled {
		logger.Info("outbound attestation disabled (set attest.enabled to sign a supply-chain attestation for every served artifact)")
		return nil, nil
	}

	signer, source, err := loadAttestSigner(cfg)
	if err != nil {
		return nil, err
	}
	if signer == nil {
		logger.Warn("outbound attestation inactive: no signing key available (set attest.signingKey[File] or audit.transparency.signingKey[File] to sign attestations)")
		return nil, nil
	}

	att := attestbundle.Attester{
		ID:       ac.AttesterID,
		Name:     "pullthrough-security",
		Version:  version,
		Instance: ac.Instance,
	}

	// Transparency-log submission (Task 142): when transparency.rekor.submit is on
	// and a client was wired, every signed bundle is submitted to the log and the
	// returned log index + inclusion proof are recorded on the stored bundle.
	rekorCfg, err := attestRekorConfig(cfg, rekorDeps, signer)
	if err != nil {
		return nil, err
	}

	svc, err := attestbundle.NewService(attestbundle.Config{
		Signer:   signer,
		Attester: att,
		Store:    attestbundle.NewStore(attestbundle.StoreOptions{MaxEntries: ac.MaxEntries}),
		Rekor:    rekorCfg,
		Logger:   logger,
	})
	if err != nil {
		return nil, fmt.Errorf("attest: %w", err)
	}
	logger.Info("outbound attestation enabled (signed in-toto/SLSA bundle per served artifact; referrers at {admin}/api/attest/referrers)",
		"keyId", svc.KeyID(), "keySource", source, "predicateType", attestbundle.PredicateType,
		"rekorSubmit", svc.RekorEnabled())
	return svc, nil
}

// attestRekorConfig builds the attestation engine's transparency-log submission
// config from the shared rekor wiring. It returns nil (submission disabled) when
// transparency.rekor.submit is off or no client is available. The signer's
// public key is submitted so the Rekor entry is self-describing.
func attestRekorConfig(cfg *config.Config, deps *rekorDeps, signer *attestbundle.Signer) (*attestbundle.RekorConfig, error) {
	if deps == nil || !deps.submit || deps.client == nil {
		return nil, nil
	}
	der, err := x509.MarshalPKIXPublicKey(signer.PublicKey())
	if err != nil {
		return nil, fmt.Errorf("attest: marshaling signer public key for rekor: %w", err)
	}
	pubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
	return &attestbundle.RekorConfig{
		Client:       deps.client,
		Verifier:     deps.verifier,
		PublicKeyPEM: pubPEM,
		BaseURL:      deps.baseURL,
		Timeout:      cfg.Transparency.Rekor.Timeout,
		Metrics:      deps.metrics,
	}, nil
}

// loadAttestSigner resolves the signing key for outbound attestation, returning
// the signer, a human-readable source label, and any parse error. It returns a
// nil signer (no error) when no key material is configured anywhere.
func loadAttestSigner(cfg *config.Config) (*attestbundle.Signer, string, error) {
	ac := cfg.Attest
	switch {
	case ac.SigningKey != "":
		s, err := attestbundle.LoadSigner([]byte(ac.SigningKey))
		if err != nil {
			return nil, "", fmt.Errorf("attest: loading attest.signingKey: %w", err)
		}
		return s, "attest.signingKey", nil
	case ac.SigningKeyFile != "":
		s, err := attestbundle.LoadSignerFile(ac.SigningKeyFile)
		if err != nil {
			return nil, "", fmt.Errorf("attest: loading attest.signingKeyFile: %w", err)
		}
		return s, "attest.signingKeyFile", nil
	}

	// Fall back to the audit transparency checkpoint signing key.
	tc := cfg.Audit.Transparency
	switch {
	case tc.SigningKey != "":
		s, err := attestbundle.LoadSigner([]byte(tc.SigningKey))
		if err != nil {
			return nil, "", fmt.Errorf("attest: loading audit.transparency.signingKey: %w", err)
		}
		return s, "audit.transparency.signingKey", nil
	case tc.SigningKeyFile != "":
		s, err := attestbundle.LoadSignerFile(tc.SigningKeyFile)
		if err != nil {
			return nil, "", fmt.Errorf("attest: loading audit.transparency.signingKeyFile: %w", err)
		}
		return s, "audit.transparency.signingKeyFile", nil
	}
	return nil, "", nil
}

// attestInspector adapts the attestbundle.Service to the admin AttestInspector.
type attestInspector struct {
	svc *attestbundle.Service
}

func (a attestInspector) Snapshot() attestbundle.Snapshot { return a.svc.Snapshot() }
func (a attestInspector) Get(tenant, pkg string) (*attestbundle.Bundle, bool) {
	return a.svc.Get(tenant, pkg)
}
func (a attestInspector) Documents(tenant, q string) []*attestbundle.Bundle {
	return a.svc.Store().Documents(tenant, q)
}
func (a attestInspector) Referrers(digest string) (attestbundle.ReferrersIndex, bool) {
	return a.svc.Referrers(digest)
}

// runAttestCommand dispatches the `attest` CLI subcommand: `export` builds and
// signs an attestation bundle from an aggregated admission document (the
// air-gapped / offline path), and `verify` checks a bundle against a public key.
// It owns its own flag set so the live server's global flags stay uncluttered.
func runAttestCommand(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("attest: a subcommand is required (export|verify)")
	}
	switch args[0] {
	case "export":
		return runAttestExport(args[1:])
	case "verify":
		return runAttestVerify(args[1:])
	default:
		return fmt.Errorf("attest: unknown subcommand %q (want: export|verify)", args[0])
	}
}

// runAttestExport reads an aggregated admission document (policyengine.Input —
// the same self-describing signal model the policy/risk/findings layers consume)
// from a file or stdin, signs it with the configured key, and writes the DSSE
// attestation bundle. This lets CI (or an air-gapped preflight) produce the
// proxy's attestation from exported gate signals without a live proxy.
//
// Usage:
//
//	pullthrough attest export -key <pem> [-input <file>] [-output <file>] [coordinate]
//
// A trailing positional coordinate ("name@version") overrides the artifact
// coordinate in the input document, matching the `attest export <coordinate>`
// shape in the task.
func runAttestExport(args []string) error {
	fs := flag.NewFlagSet("attest export", flag.ContinueOnError)
	var (
		keyPath   = fs.String("key", "", "PEM private key (PKCS#8 / EC / PKCS#1) used to sign the attestation (required)")
		inPath    = fs.String("input", "", "path to a JSON admission input document; '-' or empty reads stdin")
		outPath   = fs.String("output", "", "path to write the DSSE bundle (default stdout)")
		attesterI = fs.String("attester-id", "pullthrough-proxy", "attester identity recorded in the predicate")
		instance  = fs.String("instance", "", "optional attester instance/host recorded in the predicate")
	)
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "Usage: pullthrough attest export -key <pem> [-input <file>] [-output <file>] [coordinate]")
		fmt.Fprintln(os.Stderr, "Reads an aggregated admission input document and writes a signed DSSE attestation bundle.")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *keyPath == "" {
		return fmt.Errorf("attest export: -key is required")
	}

	signer, err := attestbundle.LoadSignerFile(*keyPath)
	if err != nil {
		return fmt.Errorf("attest export: %w", err)
	}

	raw, err := readInput(*inPath)
	if err != nil {
		return fmt.Errorf("attest export: reading input: %w", err)
	}
	var in policyengine.Input
	if err := json.Unmarshal(raw, &in); err != nil {
		return fmt.Errorf("attest export: parsing admission input: %w", err)
	}
	if coord := strings.TrimSpace(coordinateArg(fs.Args())); coord != "" {
		applyCoordinate(&in, coord)
	}

	svc, err := attestbundle.NewService(attestbundle.Config{
		Signer:   signer,
		Attester: attestbundle.Attester{ID: *attesterI, Name: "pullthrough-security", Version: version, Instance: *instance},
	})
	if err != nil {
		return fmt.Errorf("attest export: %w", err)
	}
	// The offline export path has only the aggregated admission document; the
	// risk/policy verdicts are computed by the live engines, so the bundle built
	// here carries the gate sections present in the input but no separate
	// risk/policy section (kept honest rather than fabricated).
	bundle, err := svc.Attest(in, attestbundle.Options{})
	if err != nil {
		return fmt.Errorf("attest export: signing: %w", err)
	}

	out := os.Stdout
	if *outPath != "" {
		f, ferr := os.Create(*outPath)
		if ferr != nil {
			return fmt.Errorf("attest export: creating output: %w", ferr)
		}
		defer f.Close()
		out = f
	}
	enc := json.NewEncoder(out)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	if err := enc.Encode(bundle); err != nil {
		return fmt.Errorf("attest export: encoding bundle: %w", err)
	}
	if *outPath != "" {
		fmt.Fprintf(os.Stderr, "attest export: wrote bundle for %s (subject %s, digest %s) to %s\n",
			bundle.Coordinate, bundle.SubjectDigest, bundle.Digest, *outPath)
	}
	return nil
}

// runAttestVerify reads a DSSE attestation bundle (or bare envelope) and verifies
// its signature against a PEM public key, printing the authenticated in-toto
// statement on success. This is the downstream-consumer check, runnable offline.
func runAttestVerify(args []string) error {
	fs := flag.NewFlagSet("attest verify", flag.ContinueOnError)
	var (
		pubPath = fs.String("pubkey", "", "PEM public key to verify the attestation signature (required)")
		inPath  = fs.String("input", "", "path to the DSSE bundle/envelope; '-' or empty reads stdin")
	)
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "Usage: pullthrough attest verify -pubkey <pem> [-input <file>]")
		fmt.Fprintln(os.Stderr, "Verifies a proxy attestation bundle's DSSE signature and prints the statement.")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *pubPath == "" {
		return fmt.Errorf("attest verify: -pubkey is required")
	}
	pubPEM, err := os.ReadFile(*pubPath)
	if err != nil {
		return fmt.Errorf("attest verify: reading public key: %w", err)
	}
	pub, err := sigverify.ParsePublicKeyPEM(pubPEM)
	if err != nil {
		return fmt.Errorf("attest verify: parsing public key: %w", err)
	}

	raw, err := readInput(*inPath)
	if err != nil {
		return fmt.Errorf("attest verify: reading input: %w", err)
	}
	env, err := decodeEnvelopeInput(raw)
	if err != nil {
		return fmt.Errorf("attest verify: %w", err)
	}

	stmt, err := attestbundle.VerifyEnvelope(pub, env)
	if err != nil {
		return fmt.Errorf("attest verify: %w", err)
	}
	fmt.Fprintln(os.Stderr, "attest verify: signature OK")
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	return enc.Encode(stmt)
}

// decodeEnvelopeInput accepts either a full Bundle ({"envelope":{...}}) or a bare
// DSSE envelope ({"payloadType":...}) and returns the envelope.
func decodeEnvelopeInput(raw []byte) (attestbundle.Envelope, error) {
	var bundle attestbundle.Bundle
	if err := json.Unmarshal(raw, &bundle); err == nil && bundle.Envelope.Payload != "" {
		return bundle.Envelope, nil
	}
	var env attestbundle.Envelope
	if err := json.Unmarshal(raw, &env); err != nil {
		return attestbundle.Envelope{}, fmt.Errorf("parsing bundle/envelope: %w", err)
	}
	if env.Payload == "" {
		return attestbundle.Envelope{}, fmt.Errorf("input has no DSSE payload")
	}
	return env, nil
}

// coordinateArg returns the first positional argument (the optional coordinate).
func coordinateArg(args []string) string {
	if len(args) > 0 {
		return args[0]
	}
	return ""
}

// applyCoordinate overrides the input's artifact name/version from a
// "name@version" coordinate.
func applyCoordinate(in *policyengine.Input, coord string) {
	if i := strings.LastIndex(coord, "@"); i > 0 {
		in.Artifact.Name = coord[:i]
		in.Artifact.Version = coord[i+1:]
		return
	}
	in.Artifact.Name = coord
}
