// Package downloadlog is the proxy's download log: a bounded, queryable record
// of which package was downloaded from which client address (Task 176).
//
// Every other record the proxy keeps is organised around a decision or an
// artifact. The audit log is a tamper-evident sequence of events, the findings
// store explains a verdict, the usage meter totals bytes per tenant. None of
// them answers the question an operator asks the moment a package turns out to
// be malicious: who has it? The download log does. Each entry names the
// client address a request came from, the package coordinate the request
// resolved to (ecosystem, name, version), what happened (served, refused by a
// gate, not found), how many bytes left the proxy, and — when the client was
// authenticated — who it was.
//
// # What is recorded
//
// One entry per request for something a client installs: a package archive, a
// crate, a module zip, an image manifest or layer, a model weight file, a Git
// fetch. The index documents fetched on the way there (version lists, package
// metadata, checksum sidecars) are noise for this purpose and are left out
// unless Config.IncludeMetadata asks for them. A refused request is recorded
// like a served one — an attempt to pull a blocked package is at least as
// interesting as a successful pull — with the gate that refused it, and it is
// recorded whatever it asked for: a gate refuses the first request that names
// a blocked coordinate, which for some package managers is a metadata request,
// and the client never gets as far as the package itself.
//
// # Bounds
//
// The log is a ring: it holds at most Config.MaxEntries entries and drops the
// oldest when full, and it drops entries older than Config.Retention. Both
// bounds apply to the in-memory log and to its on-disk copy alike, so neither
// memory nor disk grows with traffic. Client addresses are personal data in
// most jurisdictions; the retention bound is the control that keeps the log
// from becoming an indefinite record of them.
//
// An entry is bounded too, and the bound is on what it keeps alive, not only on
// what it shows: every string it stores is a copy. What reaches Record is cut
// from a request — the path from the request line, the package name from the
// path — and a stored slice of a request line would pin the whole line, whose
// length the client chooses (see clean).
//
// # Persistence
//
// With Config.Path set, entries are appended to a JSON Lines file (one entry
// per line, the same shape the admin API returns) and reloaded on start, so the
// log survives a restart. Writing is decoupled from the pull path: Record only
// touches memory, and a background flush appends what is new about once a
// second. The file is rewritten in place (to a temporary file, then renamed)
// once it holds noticeably more than the log retains.
//
// # Locking
//
// Two locks guard state, and they are never held together. Log.mu guards the
// in-memory log and is held for as long as it takes to append an entry or copy
// a view — never across I/O. The file has its own lock (fileStore.mu), held
// across writes. The flush takes a view under Log.mu, releases it, and hands
// the view to the store; the store never calls back into the log, and the log
// reads the store's counters without its lock. A slow disk therefore delays the
// next write and nothing else: not recording, not queries, not the metrics
// scrape. (A third lock, Log.flushMu, only keeps two flushes from running at
// once; it is always the first one taken.)
//
// Readers do not hold Log.mu either while they scan: a view is an immutable
// snapshot (see view), which is what lets a query or an export of a large log
// run while downloads keep being recorded.
//
// A nil *Log is a valid, disabled log: every method is a no-op, so call sites
// need no nil checks.
package downloadlog
