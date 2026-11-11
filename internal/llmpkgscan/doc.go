// Package llmpkgscan implements the sandboxed LLM package-content scan gate
// (Task 173): an admission gate that has a language model read the contents of
// a downloaded package and return a malicious / suspicious / benign verdict
// before the artifact is served to a client.
//
// The LLM commit scanner (internal/scan/commit) judges the source commit a
// package is believed to come from. This gate judges the artifact itself — the
// bytes a developer's package manager is about to install — which is the only
// thing that actually runs on their machine, and which need not match any
// commit at all.
//
// # What the model is given, and what it is not
//
// The artifact is unpacked with the contentscan archive walker into a bounded,
// read-only, in-memory tree (tree.go). Nothing is written to disk and nothing
// in the package is ever executed, imported or installed. The model then reads
// that tree one of two ways:
//
//   - With a provider that supports tool use (commit.ToolProvider), it gets
//     three tools — list_files, read_file, grep — implemented here, in-process,
//     over the in-memory tree (tools.go). They are the model's only capability:
//     there is no shell, no interpreter, no network, no filesystem, and no
//     provider-hosted tool is ever declared. A path that is not a key of the
//     tree simply does not resolve.
//   - With a provider that lacks tool use, it gets one prompt: a content bundle
//     of the files most likely to matter, in priority order, with every omission
//     named (buildSeed in prompt.go, runBundle in scan.go). In "auto" mode the
//     same path is taken when a provider's endpoint turns a tool-bearing request
//     down, which is how a gateway without function calling shows itself.
//
// Either way the seed prompt leads with the same prioritized material: install
// scripts, lifecycle hooks, build files and entry points first.
//
// Every dimension of the work is capped: artifact size, unpacked bytes, file
// count, path depth and compression ratio on the way in; prompt bytes, tool
// calls, tool output, conversation turns, tokens and wall-clock time while the
// model works; concurrency and spend across scans.
//
// # Untrusted content
//
// Package content is written by whoever published the package, so the prompt
// treats it as hostile data (prompt.go): it is delimited by markers carrying a
// per-scan random nonce the content cannot predict, rendered with a line-number
// gutter and with invisible characters made visible, and governed by a frozen
// system prompt stating that nothing inside it can change the task. The model's
// answer must be exactly one JSON object of a fixed shape (verdict.go); anything
// else — prose around it, a second object, an unknown field, a missing verdict,
// a truncated reply, a provider refusal — is a scan error. A scan error is
// never read as "benign": what happens to the artifact is then decided solely
// by the configured fail mode.
//
// A deterministic pass (inject.go) additionally looks for text that addresses
// the scanner. A package that contains such text cannot earn a clean verdict by
// talking the model into one.
//
// # Scanning once
//
// A verdict is stored under the artifact's sha256 digest together with the
// model and the prompt version (store.go), so identical bytes are scanned once
// no matter how many coordinates, tenants or requests they arrive under, and a
// model or prompt change re-scans rather than serving a stale answer.
// Concurrent requests for the same digest share one scan. The scan runs on its
// own context, not the first requester's: a client that gives up does not
// throw away work the next client would have to pay for again.
//
// # What counts as a package
//
// The gate is asked about every versioned resource of an ecosystem in scope,
// and some of those are not packages: a wheel's METADATA sidecar, a .nuspec, a
// gemspec. A resource that carries no archive or compression signature and is
// not named like an installable archive is left alone (Assess returns no
// report). Anything that starts like an archive but cannot be unpacked, and
// anything named like a package that turns out not to be one, is a package that
// went unexamined — "unsupported-format", never a silent pass (tree.go).
//
// # Who may read a verdict
//
// A verdict quotes the package: its reasons describe the code and its evidence
// carries excerpts of it. The read side (ForCoordinate, Verdicts) is therefore
// scoped by tenant: a tenant-bound reader is given only verdicts on bytes its
// own tenant has pulled through the gate.
//
// All exported methods are safe for concurrent use and safe on a nil receiver.
package llmpkgscan
