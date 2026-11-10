package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/blechschmidt/pullthrough-security/internal/config"
	"github.com/blechschmidt/pullthrough-security/internal/malfeed"
)

// runMalfeedCommand dispatches the offline-bundle subcommands for the
// known-malicious-package gate (Task 48):
//
//	pullthrough malfeed keygen -private priv.pem -public pub.pem
//	pullthrough malfeed export -config cfg.yaml -key priv.pem -out bundle.json
//	pullthrough malfeed import -in bundle.json [-pubkey pub.pem]
//
// keygen produces the Ed25519 signing keypair, export fetches the configured
// feeds and writes a signed bundle for transfer into an air-gapped environment,
// and import verifies + summarizes a bundle (the proxy itself imports one at
// startup via malfeed.bundlePath).
func runMalfeedCommand(args []string) error {
	if len(args) == 0 {
		return errors.New("malfeed: expected a subcommand (keygen|export|import)")
	}
	switch args[0] {
	case "keygen":
		return runMalfeedKeygen(args[1:])
	case "export":
		return runMalfeedExport(args[1:])
	case "import":
		return runMalfeedImport(args[1:])
	default:
		return fmt.Errorf("malfeed: unknown subcommand %q (want keygen|export|import)", args[0])
	}
}

// runMalfeedKeygen generates an Ed25519 keypair and writes the private key
// (PKCS#8) and public key (PKIX) as PEM files.
func runMalfeedKeygen(args []string) error {
	fs := flag.NewFlagSet("malfeed keygen", flag.ContinueOnError)
	privOut := fs.String("private", "", "path to write the PEM-encoded Ed25519 private key (required)")
	pubOut := fs.String("public", "", "path to write the PEM-encoded Ed25519 public key (required)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *privOut == "" || *pubOut == "" {
		return errors.New("malfeed keygen: -private and -public are required")
	}

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return fmt.Errorf("malfeed keygen: generate key: %w", err)
	}
	privDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return fmt.Errorf("malfeed keygen: marshal private key: %w", err)
	}
	pubDER, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return fmt.Errorf("malfeed keygen: marshal public key: %w", err)
	}
	privPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privDER})
	pubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER})
	if err := os.WriteFile(*privOut, privPEM, 0o600); err != nil {
		return fmt.Errorf("malfeed keygen: write private key: %w", err)
	}
	if err := os.WriteFile(*pubOut, pubPEM, 0o644); err != nil {
		return fmt.Errorf("malfeed keygen: write public key: %w", err)
	}
	fmt.Printf("wrote Ed25519 private key to %s and public key to %s\n", *privOut, *pubOut)
	return nil
}

// runMalfeedExport fetches the configured malware feeds and writes a signed
// offline bundle for transfer into an air-gapped environment.
func runMalfeedExport(args []string) error {
	fs := flag.NewFlagSet("malfeed export", flag.ContinueOnError)
	configPath := fs.String("config", "", "path to YAML configuration file (for malfeed.sources)")
	keyPath := fs.String("key", "", "path to the PEM-encoded Ed25519 signing key (required)")
	out := fs.String("out", "", "path to write the signed bundle (required)")
	source := fs.String("source", "malfeed-export", "provenance label recorded in the bundle")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *keyPath == "" || *out == "" {
		return errors.New("malfeed export: -key and -out are required")
	}

	keyPEM, err := os.ReadFile(*keyPath)
	if err != nil {
		return fmt.Errorf("malfeed export: read signing key: %w", err)
	}
	signer, err := malfeed.LoadSignerPEM(keyPEM)
	if err != nil {
		return err
	}

	cfg, err := config.Load(*configPath)
	if err != nil {
		return err
	}
	if len(cfg.Malfeed.Sources) == 0 {
		return errors.New("malfeed export: no malfeed.sources configured to fetch")
	}

	sources := make([]malfeed.FeedSource, 0, len(cfg.Malfeed.Sources))
	for _, s := range cfg.Malfeed.Sources {
		sources = append(sources, malfeed.FeedSource{URL: s.URL, Name: s.Name})
	}
	timeout := cfg.Malfeed.Timeout
	if timeout <= 0 {
		timeout = 60 * time.Second
	}
	svc := malfeed.NewService(malfeed.Config{Sources: sources, Timeout: timeout})
	defer svc.Close()

	ctx, cancel := signalContext()
	defer cancel()
	if err := svc.Refresh(ctx); err != nil {
		return fmt.Errorf("malfeed export: fetch feeds: %w", err)
	}
	entries := svc.Matcher().Entries()

	data, err := malfeed.ExportBundle(entries, *source, time.Now(), signer)
	if err != nil {
		return err
	}
	if err := os.WriteFile(*out, data, 0o644); err != nil {
		return fmt.Errorf("malfeed export: write bundle: %w", err)
	}
	fmt.Printf("exported %d known-malicious entries to signed bundle %s\n", len(entries), *out)
	return nil
}

// runMalfeedImport verifies a signed offline bundle and prints a summary. When a
// public key is supplied the signature must verify against it (authenticity);
// otherwise only integrity against the embedded key is checked.
func runMalfeedImport(args []string) error {
	fs := flag.NewFlagSet("malfeed import", flag.ContinueOnError)
	in := fs.String("in", "", "path to the signed bundle to verify (required)")
	pubPath := fs.String("pubkey", "", "path to the PEM-encoded Ed25519 public key to verify against (optional)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *in == "" {
		return errors.New("malfeed import: -in is required")
	}

	var trusted ed25519.PublicKey
	if *pubPath != "" {
		pemBytes, err := os.ReadFile(*pubPath)
		if err != nil {
			return fmt.Errorf("malfeed import: read public key: %w", err)
		}
		trusted, err = malfeed.LoadVerifierPEM(pemBytes)
		if err != nil {
			return err
		}
	}

	data, err := os.ReadFile(*in)
	if err != nil {
		return fmt.Errorf("malfeed import: read bundle: %w", err)
	}
	entries, err := malfeed.ImportBundle(data, trusted)
	if err != nil {
		return err
	}

	counts := malfeed.NewMatcher(entries).CountsByEcosystem()
	fmt.Printf("bundle verified: %d known-malicious entries\n", len(entries))
	for eco, n := range counts {
		fmt.Printf("  %-10s %d\n", eco, n)
	}
	return nil
}
