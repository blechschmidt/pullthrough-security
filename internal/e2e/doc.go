// Package e2e holds the end-to-end supply-chain integration test suite (Task
// 144). It drives the full pull + admission pipeline — a real in-process
// proxy.Gateway fronted by a recorded/replayed upstream, with the admission
// gates, SARIF findings store, risk engine, vulnerability scanner and dossier
// builder all wired — once for every real ecosystem fixture in
// internal/testset, with no network access.
//
// The whole suite is gated behind the `integration` build tag, so the default
// `go test ./...` stays hermetic and fast; this untagged file only exists so the
// package directory always contains a buildable Go file (every other file in
// the package carries `//go:build integration`). Run the suite with:
//
//	go test -tags integration ./internal/e2e/
//
// It closes the gap between the per-package unit/integration tests (each backend
// has its own against its live upstream) and whole-pipeline behavior, and guards
// against cross-cutting regressions. Its artifact is a single coverage/efficacy
// matrix (ecosystem × gates-exercised) written to the task attachments dir.
//
// A sibling suite (Task 168, llmscan_test.go) adds a per-ecosystem LLM
// commit-scan admission test: for every package ecosystem it configures the
// proxy instead of the official registry, wires the production provenance →
// policy admission bridge to a MOCK LLM commit scanner, and proves that a "good"
// package (benign source commit) is admitted while a "bad" package (a source
// commit the mock LLM flags malicious) is blocked with a 403 before serving. It
// emits its own ecosystem × {scanned, good-admit, bad-block} efficacy matrix and
// fails CI if any package ecosystem lacks both outcomes.
package e2e
