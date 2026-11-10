// Package ecotest is the real-package-manager ecosystem test suite (Task 170).
//
// Every other suite in this repository drives the proxy with synthetic HTTP
// requests. That proves the proxy implements each protocol as its author read
// the specification — it does not prove that npm, pip, cargo, docker, dnf or
// bazel can actually install anything through it. This suite closes that gap:
// for every supported ecosystem it runs the ecosystem's REAL client, configured
// to use the pull-through proxy instead of the public registry, against the REAL
// proxy binary fronting the REAL upstream registry, and asserts end to end:
//
//  1. good package — the client installs a real package through the proxy, the
//     artifact is served by (and stored in) the proxy's cache, and its admission
//     was decided by the LLM commit scan of the source commit it is built from
//     (a benign verdict), not by the absence of a check;
//  2. cache — a second install from a pristine client is served from the proxy's
//     cache without the artifact being fetched from the upstream again;
//  3. bad package — a package whose source commit the LLM flagged malicious is
//     refused by the proxy, and the real client fails the install.
//
// The LLM is a mock (MockLLM) that speaks the Anthropic Messages and OpenAI Chat
// Completions wire formats, so the proxy's real provider client, prompt
// construction, verdict parsing and scoring all run; only the model is faked.
// The source repository is a small local Git fixture holding one benign and one
// malicious commit, scanned by the proxy's own continuous commit scanner. A
// package is tied to a commit with an operator provenance pin
// (provenance.pins) — the production mechanism for ecosystems that publish no
// attestation.
//
// Layout:
//
//   - catalog.go    one Ecosystem per supported ecosystem: client image, upstream
//     configuration, the good and the bad package
//   - clients/      one POSIX shell script per ecosystem: configure the package
//     manager to use the proxy, then install $PKG_NAME. These are the
//     authoritative, continuously-verified client configurations.
//   - mockllm.go    the mock LLM provider endpoint
//   - config.go     renders the proxy configuration for one ecosystem run
//   - report.go     the ecosystem x outcome matrix (JSON / Markdown)
//   - harness_test.go (build tag `ecosystem`): process, container and assertion
//     orchestration
//
// The suite needs Docker (each client runs in its ecosystem's official image, so
// a developer needs no toolchain beyond Docker and Go) and network access to the
// upstream registries. It is therefore gated behind the `ecosystem` build tag
// and never runs as part of `go test ./...`:
//
//	make test-ecosystems                    # every ecosystem
//	make test-ecosystems ECOSYSTEMS="npm pip"
//	go test -tags ecosystem ./internal/ecotest/ -run 'TestEcosystems/^npm$' -v
//
// The untagged tests in this package keep the catalog, the client scripts, the
// rendered proxy configuration and the mock LLM honest on every `go test ./...`
// without Docker or network access.
package ecotest
