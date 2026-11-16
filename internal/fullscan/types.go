package fullscan

import (
	"context"
	"errors"
	"time"
	"unicode/utf8"

	"github.com/blechschmidt/pullthrough-security/internal/audit"
	"github.com/blechschmidt/pullthrough-security/internal/cache"
)

// Subject is the system principal the full scan scans as; the audit log and
// the gate's records name it.
const Subject = "system:full-scan"

// Priority is a queue class. Lower is served first.
type Priority int

// The queue classes, in the order they are served.
const (
	// PriorityClient: an artifact a client pulled that the gate could not
	// judge on the pull (its scan slots busy, its budget spent, the provider
	// failing), or one an operator asked to re-scan by path.
	PriorityClient Priority = iota
	// PriorityMirror: an artifact the full mirror fetched without a verdict.
	PriorityMirror
	// PriorityBackfill: an artifact found in the cache by the sweep, or one
	// whose verdict a new model, prompt or schema version made stale.
	PriorityBackfill
	numPriorities
)

// String names the class ("client", "mirror", "backfill").
func (p Priority) String() string {
	switch p {
	case PriorityClient:
		return "client"
	case PriorityMirror:
		return "mirror"
	case PriorityBackfill:
		return "backfill"
	}
	return "unknown"
}

// Item states.
const (
	// StatePending: waiting in the queue (never judged, judged under another
	// signature, or retrying).
	StatePending = "pending"
	// StateScanned: the gate holds a current verdict on the bytes (Verdict is
	// the gate's reading: benign, suspicious or malicious).
	StateScanned = "scanned"
	// StateUnscannable: the gate cannot examine the bytes, because of what
	// they are (Code: oversized, unsupported-format, provider-refusal, …).
	StateUnscannable = "unscannable"
	// StateNotApplicable: there is nothing the gate examines (Code:
	// not-package-content, out-of-scope, covered-by-image).
	StateNotApplicable = "not-applicable"
	// StateError: the attempts to judge it kept failing; the next sweep
	// queues it again.
	StateError = "error"
)

// CodeProviderRefusal is the unscanned code of an artifact the model refused
// to judge; the status counts it as refused, apart from the other unscannable
// artifacts.
const CodeProviderRefusal = "provider-refusal"

// Source says where a Note comes from.
type Source int

const (
	// SourceClient: the gate's reading of a client's pull.
	SourceClient Source = iota
	// SourceMirror: the gate's reading of the full mirror's fetch.
	SourceMirror
	// SourceSeen: the full mirror found the file in the cache (no reading).
	SourceSeen
)

// Artifact identifies a cached object in scope and how to put it before the
// gate again.
type Artifact struct {
	// Upstream is the upstream's name, Path the request path relative to its
	// mount, Accept the Accept header it was fetched with.
	Upstream string `json:"upstream"`
	Path     string `json:"path"`
	Accept   string `json:"accept,omitempty"`
	// Tenant is the tenant the scan runs as: the one whose request filled the
	// cache entry (with cache namespacing, the namespace that holds it).
	Tenant string `json:"tenant,omitempty"`
	// Key is the cache key; Digest and Size describe the cached bytes.
	Key    string `json:"key"`
	Digest string `json:"digest,omitempty"`
	Size   int64  `json:"size,omitempty"`
	// Cached is when the object entered the cache (or was first seen).
	Cached time.Time `json:"cached,omitzero"`
}

// ReadingKind classifies a reading.
type ReadingKind int

const (
	// ReadingVerdict: the gate holds a verdict on the bytes.
	ReadingVerdict ReadingKind = iota + 1
	// ReadingUnscanned: the gate has no verdict (Code says why).
	ReadingUnscanned
	// ReadingNotApplicable: the gate does not examine the object.
	ReadingNotApplicable
)

// Reading is the gate's reading of an artifact and what the action ladder did
// with it.
type Reading struct {
	Kind ReadingKind
	// Disposition is the gate's reading of a verdict: benign, suspicious or
	// malicious.
	Disposition string
	// Code is the unscanned reason code, or why the gate does not apply.
	Code string
	// Content reports that an unscanned artifact's own bytes defeated the scan
	// (oversized, unsupported, refused by the model); Retryable that a later
	// attempt is worth making (a provider fault, a timeout, a busy scanner, a
	// spent budget).
	Content   bool
	Retryable bool
	// Fresh reports that a model call produced the reading now; Cost is what
	// it cost (also for a scan that failed after spending).
	Fresh bool
	Cost  float64
	// Signature is the signature the verdict was produced under
	// (llmpkgscan.ScanSignature.String()); VerdictKey its key in the verdict
	// cache.
	Signature  string
	VerdictKey string
	// Digest and Size describe the bytes judged.
	Digest string
	Size   int64
	// Refused reports that the configured action refuses the artifact;
	// Action is the decision's action; Evicted that the ladder removed it from
	// the cache; KeptPinned that a release pin kept it.
	Refused    bool
	Action     string
	Evicted    bool
	KeptPinned bool
	// Gates is what the other admission gates said of the cached bytes:
	// GatesPassed (the full mirror's fetch, or the full scan's gate pass,
	// admitted them through every gate), GatesRefused (a gate refused them in
	// a gate pass: Gate names it), or empty (not established).
	Gates string
	Gate  string
	// Ecosystem, Name and Version are the coordinate the gate filed the
	// reading under (the security dossier's key), when it names one.
	Ecosystem string
	Name      string
	Version   string
}

// What the admission gates said of an artifact (Reading.Gates, Item.Gates).
const (
	GatesPassed  = "passed"
	GatesRefused = "refused"
)

// ScanOptions tune one scan.
type ScanOptions struct {
	// Refresh asks for a new model call even though the bytes have a verdict.
	Refresh bool
	// Gates asks, once the gate admits the bytes, for a gate pass: the cached
	// object put through every admission gate (Gateway.SystemFetch with
	// CacheOnly), nothing fetched or served.
	Gates bool
}

// Scanner puts a cached artifact before the gate and applies the action
// ladder to the reading. The server implements it with Gateway.SystemScan and
// Gateway.EnforceLLMScan.
type Scanner interface {
	// Scan judges the artifact. ErrGone reports an object the cache no longer
	// holds, ErrChanged one whose bytes are no longer the ones named; any
	// other error is a failed attempt.
	Scan(ctx context.Context, a Artifact, opts ScanOptions) (Reading, error)
	// Signature is the signature verdicts are produced under now.
	Signature() string
	// Load reports the gate's scan slots: running, waiting for a slot, total.
	Load() (running, waiting int64, slots int)
}

// Errors a Scanner returns.
var (
	ErrGone    = errors.New("fullscan: the object is not in the cache any more")
	ErrChanged = errors.New("fullscan: the cached object's bytes changed")
)

// Inventory lists the cache, for the backfill sweep (cache.FilesystemCache and
// the wrappers around it satisfy it).
type Inventory interface {
	Entries(ctx context.Context) ([]cache.Stat, error)
}

// AuditLogger records the full scan's events (*audit.Logger satisfies it).
type AuditLogger interface {
	Log(ctx context.Context, ev audit.Event) error
}

// Item is one tracked artifact. It is persisted as one line of the snapshot or
// the journal; the short keys keep a large inventory small on disk.
type Item struct {
	Key      string    `json:"k"`
	Upstream string    `json:"u"`
	Path     string    `json:"p"`
	Accept   string    `json:"a,omitempty"`
	Tenant   string    `json:"t,omitempty"`
	Digest   string    `json:"d,omitempty"`
	Size     int64     `json:"s,omitempty"`
	Cached   time.Time `json:"c,omitzero"`
	State    string    `json:"st"`
	// Queue position, while pending.
	Priority  Priority  `json:"pr,omitempty"`
	Seq       uint64    `json:"q,omitempty"`
	Enqueued  time.Time `json:"eq,omitzero"`
	NotBefore time.Time `json:"nb,omitzero"`
	Attempts  int       `json:"n,omitempty"`
	// Refresh asks the next scan for a new model call (an operator's
	// re-scan).
	Refresh bool `json:"rf,omitempty"`
	// The last reading.
	Verdict   string    `json:"v,omitempty"`
	Code      string    `json:"code,omitempty"`
	Signature string    `json:"sig,omitempty"`
	Scanned   time.Time `json:"at,omitzero"`
	Action    string    `json:"act,omitempty"`
	// Evicted reports that the action ladder removed the object from the
	// cache (at EvictedAt); the item is kept as the record of the verdict.
	Evicted   bool      `json:"ev,omitempty"`
	EvictedAt time.Time `json:"eva,omitzero"`
	LastError string    `json:"err,omitempty"`
	// Gates is what the admission gates said of the bytes (GatesPassed,
	// GatesRefused, or empty when it was judged only on a client's pull);
	// Gate the gate that refused them.
	Gates string `json:"g,omitempty"`
	Gate  string `json:"gt,omitempty"`
	// Ecosystem, Name and Version are the coordinate the gate filed the last
	// reading under: what the security dossier is asked about.
	Ecosystem string `json:"e,omitempty"`
	Name      string `json:"nm,omitempty"`
	Version   string `json:"vr,omitempty"`
	// Tenants are the other tenants known to have pulled the bytes (Tenant
	// being the one whose pull filled the cache entry), at most
	// maxItemTenants of them. A tenant-scoped reader is shown the figures and
	// verdicts of the artifacts its tenant pulled, as the gate shows a tenant
	// only the verdicts on bytes it pulled.
	Tenants []string `json:"ts,omitempty"`

	// heap bookkeeping (not persisted)
	hq     int // which heap: -1 none, 0..numPriorities-1 ready, delayedHeap
	hi     int // index in that heap
	parked bool
	busy   bool // a worker holds it
	again  bool // re-scan once the running scan is recorded
}

func (it *Item) artifact() Artifact {
	return Artifact{
		Upstream: it.Upstream, Path: it.Path, Accept: it.Accept, Tenant: it.Tenant,
		Key: it.Key, Digest: it.Digest, Size: it.Size, Cached: it.Cached,
	}
}

// maxItemTenants bounds the tenants an item records as having pulled it: the
// gate's own bound on the tenants a verdict is shown to
// (llmpkgscan.maxViewersPerKey). A tenant beyond it is not recorded, and its
// scoped views leave the artifact out (they fail closed).
const maxItemTenants = 64

// addTenant records that a tenant pulled the artifact, and reports whether
// that is news. The slice is replaced, never appended to in place: a copy of
// the item taken for a snapshot may still be reading the old one.
func (it *Item) addTenant(tenant string) bool {
	if tenant == "" || tenant == it.Tenant || len(tenant) > 256 {
		return false
	}
	for _, t := range it.Tenants {
		if t == tenant {
			return false
		}
	}
	if len(it.Tenants) >= maxItemTenants {
		return false
	}
	it.Tenants = append(it.Tenants[:len(it.Tenants):len(it.Tenants)], tenant)
	return true
}

// setFillTenant records that tenant's pull filled the cache entry now (the
// sweep reads it from the fill metadata): the tenant the scan runs as. The
// tenant it replaces stays among those who pulled the bytes.
func (it *Item) setFillTenant(tenant string) {
	if tenant == it.Tenant {
		return
	}
	old := it.Tenant
	kept := make([]string, 0, len(it.Tenants)+1)
	for _, t := range it.Tenants {
		if t != tenant {
			kept = append(kept, t)
		}
	}
	it.Tenant, it.Tenants = tenant, kept
	it.addTenant(old)
	if len(it.Tenants) == 0 {
		it.Tenants = nil
	}
}

// pullersOf calls fn for every tenant known to have pulled the bytes, once
// each.
func (it *Item) pullersOf(fn func(string)) {
	if it.Tenant != "" {
		fn(it.Tenant)
	}
	for _, t := range it.Tenants {
		if t != "" && t != it.Tenant {
			fn(t)
		}
	}
}

// pulledBy reports whether a tenant is known to have pulled the artifact.
func (it *Item) pulledBy(tenant string) bool {
	if tenant == "" {
		return false
	}
	if it.Tenant == tenant {
		return true
	}
	for _, t := range it.Tenants {
		if t == tenant {
			return true
		}
	}
	return false
}

// learnCoordinate records the coordinate a reading names, and reports whether
// that changed the item.
func (it *Item) learnCoordinate(r Reading) bool {
	if r.Name == "" {
		return false
	}
	eco, name, version := clip(r.Ecosystem, 64), clip(r.Name, 512), clip(r.Version, 256)
	if eco == it.Ecosystem && name == it.Name && version == it.Version {
		return false
	}
	it.Ecosystem, it.Name, it.Version = eco, name, version
	return true
}

// clip bounds a string a reading brings, so that one item line stays far
// below the store's line limit. It cuts on a rune boundary.
func clip(s string, n int) string {
	if len(s) <= n {
		return s
	}
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n]
}

// unscanned reports an item without a current verdict that the queue still
// owes a reading: pending or given up on.
func (it *Item) unscanned() bool { return it.State == StatePending || it.State == StateError }
