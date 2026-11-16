// Package fullmirror is the end-to-end suite of full mirroring and the full
// scan (internal/fullmirror and internal/fullscan; Tasks 189-192, this suite
// Task 194).
//
// The engine's and the adapters' own tests prove what each part does with a
// registry it is handed — against fakes in the same process. This suite proves
// what an operator relies on when they write `fullMirror.enabled: true` into
// the configuration of an upstream: that the proxy follows that registry by
// itself, fetches what is published there before any client asks for it, has
// every file judged by the admission gates — the LLM package-content scan
// among them — on the way into the cache, and keeps its place in the feed
// across a restart. It therefore tests the real thing, from the outside:
//
//   - the real `pullthrough` binary, started from a YAML configuration file
//     with full mirroring and the full scan switched on for one upstream — the
//     production wiring (cmd/pullthrough), every default-on gate included;
//   - a stub registry of the upstream's type that serves packages in the
//     ecosystem's own format — the LLM package-scan suite's
//     (internal/e2e/pkgscan), built again whenever a package is published —
//     and, in front of it, the feed the type's adapter follows, in the
//     registry's own format: npm's `_changes`, PyPI's XML-RPC changelog, a Git
//     index served by the real `git http-backend`, an APT Release file and the
//     Packages files it names, an Atom feed, a listing by date;
//   - the LLM package-scan suite's mock LLM, which judges package material
//     malicious when it holds that suite's marker.
//
// No request leaves the machine: the proxy's egress guard allows loopback only,
// and no real LLM API is called.
//
// # What is asserted, per upstream type
//
// For every upstream type a feed adapter follows (the catalog's implemented
// and partial types, docs/full-mirroring.md), one row:
//
//  1. a package published before the proxy starts is fetched by the
//     enumeration that starts the mirror (Bootstrap);
//  2. then a benign and a malicious package are published, and — without any
//     client request — the mirror finds both in the feed and fetches every file
//     of each. The benign one is cached and carries a benign verdict of the LLM
//     package scan; a client's pull of it is then served from the cache (200,
//     byte for byte, X-LLMPkgScan-Verdict: benign) with no further model call.
//     The malicious one is refused by the gate on its way in: it is not kept
//     in the cache (the full scan evicts it), the mirror counts it refused by
//     `llmpkgscan`, the full scan counts it malicious, and a client's pull is
//     refused (403, llm-package-malicious) from the stored verdict. The
//     mirror's counts are exactly the files fetched and refused; the full
//     scan counts exactly one malicious artifact and every benign package; the
//     download log holds an entry with via=system for every file the mirror
//     fetched (metadata aside, which it leaves out) and nothing a client asked
//     for;
//  3. the proxy is stopped, a third package is published, and the proxy is
//     started again: the mirror continues from the cursor it stored — no new
//     enumeration — fetches the new package and nothing it had already.
//
// The suite writes a coverage matrix (upstream type × mirrored / scanned /
// blocked / logged / resumed; JSON and Markdown) to PT_TEST_REPORT_DIR, and
// fails when an upstream type the catalog marks implemented (or partial) has
// no row whose cells all pass — an adapter added later cannot stay outside the
// suite unnoticed. Every type nothing can follow (tier (d), and Terraform) is
// started with `fullMirror.enabled` and must be refused at configuration
// validation.
//
// # Running it
//
// Everything but this file carries the `integration` build tag:
//
//	make test-full-mirror
//	go test -tags integration ./internal/e2e/fullmirror/
//	PT_FULLMIRROR_TYPES="npm cargo" go test -tags integration ./internal/e2e/fullmirror/ -v
//
// The Git-backed feeds (cargo, bazel, conan) drive the real git as the stub's
// Git server; the suite commits with an identity of its own, so it runs where
// git has none configured (CI's runner user). Select types with
// PT_FULLMIRROR_TYPES rather than -run: see the environment variables in
// harness.go for the knobs.
//
// Not covered: a new version of a package already mirrored (every package is
// published once, at one version), and each adapter's rarer paths (a
// registry's rewrite or reset of its feed, deletions, yanks, a burst) — the
// adapters' own tests drive those against recorded documents.
package fullmirror
