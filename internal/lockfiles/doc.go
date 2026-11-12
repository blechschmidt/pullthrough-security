// Package lockfiles finds the lock files in a Git tree and turns each into the
// exact dependencies it pins: for every dependency the upstream type it is
// fetched through, its name, its exact version, the integrity digests the lock
// file records for it, the registry it comes from, and the lock file path and
// line it was read from.
//
// # Reading a tree
//
// Scan walks one commit's tree through the object access of internal/git (an
// ObjectReader over a mirror, a clone made for the scan, or any local
// repository). It reads objects, never a working tree: what is scanned is
// what the commit holds. The walk
//
//   - skips directories (and files) matching the configured globs — vendored
//     code and test fixtures by default (DefaultSkip): their lock files pin
//     somebody else's dependencies, or none at all;
//   - stops descending at MaxDepth, reads no lock file larger than
//     MaxFileBytes (its size is asked for before its content), and gives up
//     after MaxFiles lock files, MaxTotalBytes read or MaxTreeEntries tree
//     entries — each limit reached is recorded in the report, never silent;
//   - finds every lock file in the tree, not one per repository: a monorepo
//     has one per package, often for several ecosystems.
//
// # Parsers
//
// A Parser handles one format: Detect decides from a path alone whether a file
// is in that format, Parse turns the file's bytes into dependencies. Parsers
// are kept in a Registry keyed by upstream type ("npm" has four formats). Each
// is a parser of untrusted input — a repository is whatever its last committer
// made it — so a parser never touches the network, the file system or another
// process, never panics on any input (each has a fuzz target), and reports
// what it cannot read as a warning or an error rather than guessing.
//
// Coverage (coverage.go) states, for every upstream type the proxy fronts,
// either the formats parsed or why the type has no lock-file format; a test
// holds that table to the configuration's full set of upstream types.
//
// # Lock files written against this proxy
//
// A lock file resolved through the proxy records the proxy's URLs, and a
// personal cache link (internal/userlinks) puts the user's token into every
// one of them: "https://proxy.example.com/u/ptl1…/v1/npm/lodash/-/…". Such a
// URL is mapped back to the upstream it stands for (Proxy): the dependency
// records the upstream's name and its own registry URL, and the URL itself in
// the proxy's canonical, token-free form. The three shapes recognised are the
// personal prefix ("/u/<token>/v1/<upstream>/…"), the interception prefix
// ("/_pullthrough/v1/<upstream>/…") and the plain mount under a configured
// public base URL ("<publicUrl>/v1/<upstream>/…"); container image references
// through the registry alias are mapped the same way.
//
// The token is never kept: parsers remove anything spelled like one, together
// with the credentials of any URL, before a URL leaves them; mapping drops the
// path segment after the personal prefix whatever it looks like; and every
// warning and error passes through the same redaction before it reaches a
// report or a log.
package lockfiles
