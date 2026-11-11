// Package llmpkgscan implements the sandboxed LLM package-content scan gate
// (Tasks 173, 174): an admission gate that has a language model read the
// contents of a downloaded artifact and return a malicious / suspicious /
// benign verdict before the artifact is served to a client. It covers every
// upstream type the proxy fronts, in the format each ships, on every path the
// bytes take to a client; internal/scancoverage is the checked record of that.
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
// # What is examined
//
// The gate is asked about every resource of an ecosystem in scope, and most of
// those are not packages: indexes, listings, checksum sidecars. Which is which
// is first of all the backend's to say — each classifies what it resolves as a
// payload, as metadata, or not at all (Artifact.Class) — and then a matter of
// the bytes (applicable.go):
//
//   - a payload is always examined;
//   - metadata is left alone only once its first bytes have shown it is not a
//     package archive, an executable, a script or a pickle after all: in
//     several protocols a repository's own index names each package's download
//     path, so a path that reads as an index proves nothing;
//   - an unclassified resource is examined when its bytes are something a
//     machine unpacks or runs, or it is named like a package archive;
//   - a compressed stream that will not show what it holds is examined under
//     every class.
//
// A payload that does not unpack is a package that went unexamined —
// "unsupported-format", never a harmless single file — unless a single file is
// what it may honestly be (singleFileOK in tree.go). Extractors are more
// forgiving than a careful parser, and "the scanner could not open it" must
// never mean "nobody will".
//
// # Formats, images, binaries
//
// The shared unpack layer (internal/contentscan) opens every container format
// in use — tar under five compressions, zip, .deb, .rpm, cpio, ar, NAR, the
// package formats that nest an archive, archives inside archives — and reads a
// file both ways when it is two archives at once. An OCI image is examined as a
// whole when its manifest is pulled (image.go): what it runs, how it says it
// was built, and the files of every layer, top-most first; its blobs then
// follow the image's verdict (blobs.go) — the ones the scan read in full. A
// layer its budget did not reach is examined on its own when it is pulled, as
// the piece of a root filesystem it is (Artifact.RootFS), under a verdict of
// its own. A binary member is shown to the model as a description of its
// header and a view of its strings (binary.go).
//
// An artifact above the size limit is either not scanned at all, or — under
// OversizeMetadataOnly — judged on its inventory and the scripts within the
// limit, with a verdict stored as a variant of its own so that it can never be
// served as a verdict on the whole (Verdict.Scope).
//
// # Verdicts enforced without a scan
//
// A verdict is keyed by the digest of the bytes, so it can be enforced wherever
// those bytes turn up: on a blob of a refused image, on an entry a sibling
// proxy asks for (StoredVerdict, BlobStatus, ReportFor), and on an instance
// that cannot reach a provider at all — verdicts are exported with the
// artifacts of an air-gap bundle and imported on the other side (bundle.go).
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
