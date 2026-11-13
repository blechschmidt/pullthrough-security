// Package audit provides a tamper-evident audit log of security-relevant events
// in the proxy: every pull, cache hit/miss, scan verdict, policy/authorization
// decision, and authentication outcome.
//
// Tamper evidence is achieved with a keyed hash chain (a "blockchain" of log
// records). Each record carries the hash of its predecessor, and its own hash
// is an HMAC-SHA256 over the record's canonical serialization concatenated with
// the previous hash, keyed by a secret only the proxy holds. Consequently:
//
//   - Editing any past record invalidates that record's hash and every hash
//     after it, which Verify detects.
//   - Removing or reordering records breaks the chain linkage and the monotonic
//     sequence numbers.
//   - Without the HMAC key an attacker cannot recompute a valid chain, so even
//     full-file rewrites are detectable as long as the key is not also stolen.
//
// The log is append-only newline-delimited JSON (one record per line) so it is
// greppable and ingestible by standard tooling while remaining verifiable.
package audit

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/blechschmidt/pullthrough-security/internal/tracing"
)

// EventType enumerates the categories of audited events.
type EventType string

const (
	EventPull          EventType = "pull"            // a client pull/fetch request
	EventCache         EventType = "cache"           // a cache hit or miss
	EventScanVerdict   EventType = "scan_verdict"    // a commit/artifact scan result
	EventPolicy        EventType = "policy_decision" // an admission/policy decision
	EventAuth          EventType = "auth"            // an authentication outcome
	EventAuthorization EventType = "authorization"   // an RBAC authorization decision
	EventQuota         EventType = "quota"           // a quota check/exceed
	EventAdmin         EventType = "admin"           // an admin API mutation
	EventAttestation   EventType = "attestation"     // an outbound proxy-signed attestation issued
	EventSnapshot      EventType = "snapshot"        // a dependency snapshot/freeze/rollback action (Task 70)
	EventEgress        EventType = "egress_blocked"  // an outbound-egress / SSRF guard denial (Task 89)
	EventGitOps        EventType = "gitops"          // a GitOps config-bundle apply/rollback (Task 93)
	EventTLSPin        EventType = "tls_pin"         // an upstream TLS certificate/CA pin violation (Task 128)
	EventStepUpAuth    EventType = "stepup_auth"     // a WebAuthn/passkey step-up authentication ceremony or enforcement decision (Task 161)
	EventSuppression   EventType = "suppression"     // a gate finding suppressed/downgraded (VEX, reachability, policy, break-glass) (Task 165)
	EventRepository    EventType = "repository"      // a repository registered or removed in the repository registry (Task 180)
	EventReleaseTag    EventType = "release_tag"     // a tracked repository's tag created, moved or deleted (Task 180)
	EventReleasePin    EventType = "release_pin"     // a release's dependencies pinned (or not), a pinned object repaired or lost (Task 180)
	EventRepoScan      EventType = "repository_scan" // a tracked repository's dependencies scanned by the LLM package-content scan, a dependency flagged (Task 181)
)

// Decision is the outcome recorded for authz/policy/quota events.
type Decision string

const (
	DecisionAllow Decision = "allow"
	DecisionDeny  Decision = "deny"
	DecisionError Decision = "error"
)

// Event is a single audited occurrence. Only Type and Time are mandatory; the
// rest are populated as relevant to the event. Sensitive values (tokens,
// credentials) must never be placed in an Event — the audit log is not
// encrypted at rest.
type Event struct {
	Type EventType `json:"type"`
	Time time.Time `json:"time"`

	// Identity of the actor, when authenticated.
	Subject string `json:"subject,omitempty"`
	Team    string `json:"team,omitempty"`

	// Request context.
	Method     string `json:"method,omitempty"`
	Backend    string `json:"backend,omitempty"`    // upstream/backend name
	Ecosystem  string `json:"ecosystem,omitempty"`  // pip|npm|docker|git|...
	Resource   string `json:"resource,omitempty"`   // path or coordinate
	RemoteAddr string `json:"remoteAddr,omitempty"` // client source address
	Status     int    `json:"status,omitempty"`     // HTTP status served

	// Outcome.
	Decision Decision `json:"decision,omitempty"`
	Reason   string   `json:"reason,omitempty"`

	// Distributed-tracing correlation (Task 41): the W3C trace and span ids of
	// the request that produced this event, when tracing is active. They let an
	// operator pivot from an audited decision to its full latency trace in
	// Jaeger/Tempo. Populated automatically from the request context by Log when
	// not already set; empty when tracing is disabled.
	TraceID string `json:"traceId,omitempty"`
	SpanID  string `json:"spanId,omitempty"`

	// Detail is a small map of event-specific attributes (cache result,
	// verdict severity, quota counters, etc.). Keep values primitive.
	Detail map[string]any `json:"detail,omitempty"`
}

// Record is an Event wrapped with chain metadata. Seq is a 1-based monotonic
// counter; PrevHash links to the prior record; Hash is this record's keyed
// hash. The genesis record has PrevHash equal to GenesisHash.
type Record struct {
	Seq      uint64 `json:"seq"`
	Event    Event  `json:"event"`
	PrevHash string `json:"prevHash"`
	Hash     string `json:"hash"`
}

// GenesisHash is the synthetic predecessor hash of the first record.
const GenesisHash = "genesis"

// Sink is the durable destination of audit records. Implementations must be
// safe for concurrent use; Logger serializes writes before calling Append.
type Sink interface {
	// Append durably persists one record.
	Append(ctx context.Context, rec Record) error
	// Last returns the most recent record and true, or false if the sink is
	// empty. It is used to resume the hash chain across restarts.
	Last(ctx context.Context) (Record, bool, error)
	// Close flushes and releases resources.
	Close() error
}

// RecordReader is an optional Sink capability: returning every persisted record
// ordered by sequence. The transparency log uses it to rebuild its Merkle tree
// across process restarts. A Sink that does not implement it can still be used,
// but the Merkle tree then starts empty on restart (the hash chain is unaffected).
type RecordReader interface {
	ReadAll(ctx context.Context) ([]Record, error)
}

// Logger appends events to a Sink, maintaining the keyed hash chain. It is the
// single entry point the rest of the proxy uses; a nil *Logger is a valid no-op
// so audit logging can be disabled without nil checks at call sites.
type Logger struct {
	mu       sync.Mutex
	key      []byte
	sink     Sink
	seq      uint64
	lastHash string
	now      func() time.Time
	tlog     *transparencyLog // nil when the Merkle transparency layer is disabled
}

// Options configures a Logger.
type Options struct {
	// Key is the HMAC secret keying the hash chain. It must be non-empty;
	// without it the chain provides ordering but not cryptographic tamper
	// evidence against an attacker who can rewrite the file.
	Key []byte
	// Sink is the durable destination. Required.
	Sink Sink
	// Now overrides the clock (for tests). Defaults to time.Now.
	Now func() time.Time
	// Transparency, when non-nil, enables the Merkle transparency layer:
	// periodic signed checkpoints, inclusion proofs, and consistency proofs on
	// top of the hash chain.
	Transparency *TransparencyOptions
}

// NewLogger constructs a Logger, resuming the chain from the sink's last record
// so sequence numbers and linkage continue across process restarts.
func NewLogger(ctx context.Context, opts Options) (*Logger, error) {
	if opts.Sink == nil {
		return nil, fmt.Errorf("audit: sink is required")
	}
	if len(opts.Key) == 0 {
		return nil, fmt.Errorf("audit: hmac key is required for tamper evidence")
	}
	now := opts.Now
	if now == nil {
		now = time.Now
	}
	l := &Logger{
		key:      append([]byte(nil), opts.Key...),
		sink:     opts.Sink,
		now:      now,
		lastHash: GenesisHash,
	}
	last, ok, err := opts.Sink.Last(ctx)
	if err != nil {
		return nil, fmt.Errorf("audit: resuming chain: %w", err)
	}
	if ok {
		l.seq = last.Seq
		l.lastHash = last.Hash
	}

	if opts.Transparency != nil {
		var existing []Record
		if rr, ok := opts.Sink.(RecordReader); ok {
			existing, err = rr.ReadAll(ctx)
			if err != nil {
				return nil, fmt.Errorf("audit: resuming transparency log: %w", err)
			}
		}
		tlog, terr := newTransparencyLog(ctx, *opts.Transparency, existing, now)
		if terr != nil {
			return nil, terr
		}
		l.tlog = tlog
	}
	return l, nil
}

// Log appends an event to the chain. It is safe for concurrent use; events are
// serialized so the chain stays consistent. A nil Logger is a no-op. The
// event's Time is set to now when zero.
func (l *Logger) Log(ctx context.Context, ev Event) error {
	if l == nil {
		return nil
	}
	if ev.Time.IsZero() {
		ev.Time = l.now().UTC()
	} else {
		ev.Time = ev.Time.UTC()
	}

	// Correlate the active distributed trace into the record so an audited
	// decision can be pivoted to its full latency trace. Caller-supplied ids win.
	if ev.TraceID == "" {
		if tid := tracing.TraceIDFromContext(ctx); tid != "" {
			ev.TraceID = tid
			ev.SpanID = tracing.SpanIDFromContext(ctx)
		}
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	seq := l.seq + 1
	rec := Record{Seq: seq, Event: ev, PrevHash: l.lastHash}
	h, err := computeHash(l.key, rec)
	if err != nil {
		return fmt.Errorf("audit: hashing record: %w", err)
	}
	rec.Hash = h

	if err := l.sink.Append(ctx, rec); err != nil {
		return fmt.Errorf("audit: appending record: %w", err)
	}
	l.seq = seq
	l.lastHash = h

	if l.tlog != nil {
		if err := l.tlog.add(ctx, rec); err != nil {
			// The record is durably appended and the hash chain is intact; a
			// transparency-layer (checkpoint) failure must not lose the record.
			// Surface it so the caller can log it, without unwinding the append.
			return fmt.Errorf("audit: updating transparency log: %w", err)
		}
	}
	return nil
}

// TransparencyEnabled reports whether the Merkle transparency layer is active.
// A nil Logger reports false.
func (l *Logger) TransparencyEnabled() bool {
	return l != nil && l.tlog != nil
}

// Records returns a read-only snapshot of every audit record currently
// available from the underlying sink, ordered by sequence. It is the read seam
// forensic tooling (the incident-timeline reconstruction layer, Task 77) uses to
// replay the hash-chained event history. It returns nil when the Logger is nil
// or its sink does not support enumeration (i.e. does not implement
// RecordReader); the hash chain itself is unaffected by that capability.
func (l *Logger) Records(ctx context.Context) ([]Record, error) {
	if l == nil {
		return nil, nil
	}
	l.mu.Lock()
	sink := l.sink
	l.mu.Unlock()
	rr, ok := sink.(RecordReader)
	if !ok {
		return nil, nil
	}
	recs, err := rr.ReadAll(ctx)
	if err != nil {
		return nil, fmt.Errorf("audit: reading records: %w", err)
	}
	return recs, nil
}

// Seal forces an immediate checkpoint (signed tree head) over every record
// logged so far, persisting it to the checkpoint store. It is a no-op (returning
// false) on a nil Logger or when transparency is disabled. Operators call it on
// an interval and at shutdown.
func (l *Logger) Seal(ctx context.Context) (Checkpoint, bool, error) {
	if l == nil || l.tlog == nil {
		return Checkpoint{}, false, nil
	}
	cp, err := l.tlog.seal(ctx)
	if err != nil {
		return Checkpoint{}, false, err
	}
	return cp, true, nil
}

// LatestCheckpoint returns the most recently sealed checkpoint. The bool is
// false when transparency is disabled or nothing has been sealed yet.
func (l *Logger) LatestCheckpoint() (Checkpoint, bool) {
	if l == nil || l.tlog == nil {
		return Checkpoint{}, false
	}
	return l.tlog.latestCheckpoint()
}

// InclusionProof returns a proof that the record with the given 1-based sequence
// number is contained in the log, anchored to the latest signed checkpoint when
// the record is covered by it.
func (l *Logger) InclusionProof(seq uint64) (InclusionProof, error) {
	if l == nil || l.tlog == nil {
		return InclusionProof{}, fmt.Errorf("audit: transparency log is not enabled")
	}
	return l.tlog.inclusionProof(seq)
}

// ConsistencyProof returns a proof that the prefix of size from is an append-only
// prefix of the prefix of size to (to == 0 means the current tree size).
func (l *Logger) ConsistencyProof(from, to uint64) (ConsistencyProof, error) {
	if l == nil || l.tlog == nil {
		return ConsistencyProof{}, fmt.Errorf("audit: transparency log is not enabled")
	}
	return l.tlog.consistencyProof(from, to)
}

// Stats returns a snapshot of the audit log's state for the admin surface and
// metrics. A nil Logger reports a zero snapshot.
func (l *Logger) Stats() Stats {
	if l == nil {
		return Stats{}
	}
	l.mu.Lock()
	chainLen := l.seq
	tlog := l.tlog
	l.mu.Unlock()
	if tlog == nil {
		return Stats{ChainLength: chainLen}
	}
	return tlog.stats(chainLen)
}

// RecordVerificationFailure increments the transparency log's
// verification-failure counter (exposed to metrics). Verification entry points
// (the admin API and the verify-audit CLI) call it when a check fails.
func (l *Logger) RecordVerificationFailure() {
	if l == nil || l.tlog == nil {
		return
	}
	l.tlog.recordVerificationFailure()
}

// computeHash returns the keyed hash binding a record to its predecessor. It
// hashes a canonical, hash-independent serialization of the record (everything
// except the Hash field) so the computation is reproducible by Verify.
func computeHash(key []byte, rec Record) (string, error) {
	payload := struct {
		Seq      uint64 `json:"seq"`
		Event    Event  `json:"event"`
		PrevHash string `json:"prevHash"`
	}{Seq: rec.Seq, Event: rec.Event, PrevHash: rec.PrevHash}

	buf, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}
	mac := hmac.New(sha256.New, key)
	mac.Write(buf)
	return hex.EncodeToString(mac.Sum(nil)), nil
}

// VerifyChain validates an ordered slice of records against the key: it checks
// monotonic sequence numbers, correct predecessor linkage, and that each
// record's hash matches its recomputed keyed hash. It returns the index of the
// first broken record (and a descriptive error) or (-1, nil) when the whole
// chain is intact. An empty slice is trivially valid.
func VerifyChain(key []byte, records []Record) (int, error) {
	prev := GenesisHash
	var prevSeq uint64
	for i, rec := range records {
		if rec.Seq != prevSeq+1 {
			return i, fmt.Errorf("audit: record %d has seq %d, expected %d", i, rec.Seq, prevSeq+1)
		}
		if rec.PrevHash != prev {
			return i, fmt.Errorf("audit: record %d (seq %d) prevHash mismatch: chain broken or record removed", i, rec.Seq)
		}
		want, err := computeHash(key, rec)
		if err != nil {
			return i, fmt.Errorf("audit: record %d: %w", i, err)
		}
		if !hmac.Equal([]byte(want), []byte(rec.Hash)) {
			return i, fmt.Errorf("audit: record %d (seq %d) hash mismatch: record was tampered with", i, rec.Seq)
		}
		prev = rec.Hash
		prevSeq = rec.Seq
	}
	return -1, nil
}

// sortRecords orders records by sequence number; callers that read from
// unordered sources can normalize before verification.
func sortRecords(records []Record) {
	sort.Slice(records, func(i, j int) bool { return records[i].Seq < records[j].Seq })
}

// ParseRecords decodes newline-delimited JSON records (the on-disk format),
// skipping blank lines. It sorts the result by sequence for verification.
func ParseRecords(data string) ([]Record, error) {
	var recs []Record
	for n, line := range strings.Split(data, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var rec Record
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			return nil, fmt.Errorf("audit: line %d: %w", n+1, err)
		}
		recs = append(recs, rec)
	}
	sortRecords(recs)
	return recs, nil
}
