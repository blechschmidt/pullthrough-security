// Package fullscan is the full scan (Task 192): it makes sure every artifact
// in the cache of an upstream in its scope has a current verdict of the LLM
// package-content scan gate (internal/llmpkgscan) — the artifacts the full
// mirror fetched, and the ones that were cached before anybody asked for the
// scan. A malicious verdict on such an artifact follows the gate's configured
// action ladder (annotate, block, quarantine) and raises the usual findings,
// SIEM and alert events, so a bad upload is blocked before any client asks for
// it.
//
// The scope is every upstream whose fullMirror block sets fullScan, or — with
// the global fullScan.enabled — every upstream the gate scans.
//
// # Where the artifacts come from
//
//   - The full mirror's fetches are judged by the gate at fetch time
//     (Gateway.SystemFetch with DeferLLMRefusal): the server hands the reading
//     to Note with SourceMirror after applying the ladder to it.
//   - A client's pull of a cached artifact is judged by the gate as always;
//     the gateway reports the reading (Dependencies.LLMScanObserver) and the
//     server hands it to Note with SourceClient.
//   - The backfill sweep lists the cache (Inventory) and adds every object
//     whose fill metadata (cache.MetaFill*) names an upstream in scope; the
//     full mirror reports the cached files it skips (SourceSeen).
//
// An artifact without a current verdict waits in a persistent priority queue:
// first those a client pulled (the gate could not judge them on the pull),
// then those the mirror fetched, then the backfill. A worker puts it before
// the gate with Gateway.SystemScan as the tenant whose cache namespace holds
// it — bytes that already have a verdict cost no model call — and applies the
// ladder (Gateway.EnforceLLMScan). Rules the gate keeps hold here too: an
// artifact the gate could not judge is never counted as benign ("unscanned is
// not benign"), a verdict is visible to a tenant only on bytes that tenant
// pulled (the scan runs as the tenant that holds the object), and the gate's
// refusals of the mirror's fetches are deferred to this package
// (DeferLLMRefusal), which applies the ladder.
//
// # Limits
//
// The full scan's own scans run at most Options.Concurrency at a time, and
// only while no client's scan waits for one of the gate's slots: the scans a
// client pull starts always come first. They are paid from a cost budget per
// UTC day and per UTC month; once either is spent the queue pauses until the
// window rolls over or the budget is raised. The gate's own budget, breaker
// and queue limits apply as well.
//
// # Re-scans
//
// A verdict is current while it was produced under the gate's signature: the
// model, the prompt version and the verdict schema version
// (llmpkgscan.ScanSignature). When the signature changes, every artifact
// whose verdict was produced under another one goes back into the queue. An
// operator's re-scan (Service.Rescan) puts artifacts back with a fresh model
// call even though their bytes have a verdict.
//
// # State
//
// The state lives in a directory (by default <fullMirror.stateDir>/fullscan)
// that every replica mounts; only the replica holding the full-mirror lease
// works, and it alone writes:
//
//	state.json             counters, budget ledger, published figures, the
//	                       names of the live snapshot and journal
//	items-<gen>-<id>.snap  the inventory as of the snapshot, one item per line
//	items-<gen>-<id>.log   the changes since, one per line
//	control.json           operators' pauses and re-scan requests
//	inbox/                 artifacts other replicas saw a client pull unjudged
//
// A replica that takes over writes a new snapshot and journal and moves the
// generation on: a former leader that writes again finds the generation moved
// and stands by. The inventory can always be rebuilt from the cache: a state
// that cannot be read is set aside and the sweep starts over.
package fullscan
