//go:build ignore

// Command gen produces the committed golden fixtures for the rekor package's
// inclusion-proof + SET verification tests: a Rekor-shaped log entry
// (entry.json), the log's public key (log_pubkey.pem), and a tampered variant
// (entry_tampered.json) whose root hash was flipped. Regenerate with:
//
//	go run ./internal/rekor/testdata/gen
//
// The fixtures are internally consistent (the SET and inclusion proof validate
// against the embedded public key), so the verification tests need no network
// and no external tooling.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/blechschmidt/pullthrough-security/internal/rekor"
)

func main() {
	log := rekor.NewFakeLog(nil)

	// Seed the log with several unrelated entries so the target entry sits at a
	// non-trivial index with a multi-hash audit path.
	ctx := context.Background()
	for i := 0; i < 5; i++ {
		if _, err := log.Submit(ctx, rekor.SubmitRequest{Envelope: []byte(fmt.Sprintf("seed-%d", i))}); err != nil {
			panic(err)
		}
	}

	envelope := []byte(`{"payloadType":"application/vnd.in-toto+json","payload":"eyJfdHlwZSI6Imh0dHBzOi8vaW4tdG90by5pby9TdGF0ZW1lbnQvdjEifQ==","signatures":[{"sig":"Zm9v"}]}`)
	entry, err := log.Submit(ctx, rekor.SubmitRequest{Envelope: envelope, PublicKeyPEM: log.PublicKeyPEM()})
	if err != nil {
		panic(err)
	}

	dir := filepath.Dir(must(os.Getwd()))
	_ = dir // fixtures are written relative to the gen dir's parent (testdata/)
	outDir := "internal/rekor/testdata"

	writeJSON(filepath.Join(outDir, "entry.json"), entry)

	// Tampered: flip the root hash so inclusion-proof verification must fail.
	tampered := *entry
	ip := *entry.InclusionProof
	ip.RootHash = flipHex(ip.RootHash)
	tampered.InclusionProof = &ip
	writeJSON(filepath.Join(outDir, "entry_tampered.json"), &tampered)

	if err := os.WriteFile(filepath.Join(outDir, "log_pubkey.pem"), log.PublicKeyPEM(), 0o644); err != nil {
		panic(err)
	}
	fmt.Printf("wrote fixtures to %s (logIndex=%d treeSize=%d hashes=%d)\n",
		outDir, entry.LogIndex, entry.InclusionProof.TreeSize, len(entry.InclusionProof.Hashes))
}

func writeJSON(path string, v any) {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		panic(err)
	}
	if err := os.WriteFile(path, append(b, '\n'), 0o644); err != nil {
		panic(err)
	}
}

func flipHex(h string) string {
	if h == "" {
		return h
	}
	b := []byte(h)
	// Flip the first hex nibble to a different value.
	if b[0] == '0' {
		b[0] = '1'
	} else {
		b[0] = '0'
	}
	return string(b)
}

func must[T any](v T, err error) T {
	if err != nil {
		panic(err)
	}
	return v
}
