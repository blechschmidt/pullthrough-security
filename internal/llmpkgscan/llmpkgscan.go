package llmpkgscan

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/blechschmidt/pullthrough-security/internal/scan/commit"
	"golang.org/x/sync/singleflight"
)

// Request asks for the verdict on one artifact.
type Request struct {
	Artifact Artifact
	// Tenant is the requesting tenant, for budgeting. It is never sent to the
	// model and is not part of the cache key: identical bytes get one verdict.
	Tenant string
	// Open yields a fresh stream of the artifact's bytes. It is called with the
	// scan's own context — not the caller's — because the scan outlives a caller
	// that disconnects.
	Open func(ctx context.Context) (io.ReadCloser, error)
}

// Unscanned explains why an artifact has no verdict.
type Unscanned struct {
	// Code is the stable reason code (see the Code* constants).
	Code string `json:"code"`
	// Reason is the fixed, client-safe sentence for the code.
	Reason string `json:"reason"`
	// Detail is the diagnostic detail behind the failure — a provider error
	// message, the parser's complaint about the model's answer. It is for logs and
	// the admin surface: it must not be shown to a package client.
	Detail string `json:"detail,omitempty"`
	// Content reports that the artifact's own bytes caused it.
	Content bool `json:"content"`
	// Transient reports that the cause is expected to clear by itself shortly (a
	// provider fault, a timeout, a busy scanner): the pull is worth retrying.
	Transient bool `json:"transient"`
}

// Report is the gate's view of one artifact for one request.
type Report struct {
	Artifact Artifact `json:"-"`
	// Verdict is the stored verdict; nil when the artifact is unscanned.
	Verdict *Verdict `json:"verdict,omitempty"`
	// Cached reports that the verdict came from the verdict cache: no scan ran
	// for this request.
	Cached bool `json:"cached"`
	// Shared reports that this request joined a scan another request started.
	Shared bool `json:"shared,omitempty"`
	// Disposition is how the gate reads the verdict under the configured
	// thresholds; Reason says why in one line.
	Disposition Disposition `json:"disposition"`
	Reason      string      `json:"reason,omitempty"`
	// Unscanned is set when there is no verdict.
	Unscanned *Unscanned `json:"unscanned,omitempty"`
	// Risk is the ordinal 0..100 contribution for the risk-scoring engine.
	Risk int `json:"risk"`
	// Findings are the report's findings in catalog form.
	Findings []Finding `json:"findings,omitempty"`
}

// Scanned reports whether the report carries a verdict.
func (r *Report) Scanned() bool { return r != nil && r.Verdict != nil }

// codeNotArchive marks, in the negative cache and in a scan result, bytes that
// are not an archive of any kind. It is internal — it never appears in a
// report: notArchive turns it into the outcome for a particular request.
const codeNotArchive = "not-an-archive"

const notArchiveDetail = "the artifact is named like a package archive but is not an archive"

// notArchive is the outcome for bytes that are not an archive at all.
//
// A resource that does not claim to be a package either is a metadata document
// served under a package's coordinate — a wheel's METADATA sidecar, a .nuspec, a
// gemspec. No package manager installs code from it, so the gate does not apply
// (a nil report), which is different from "could not be scanned": it must not
// be refused under fail-closed, or every client breaks for no gain.
//
// A resource that is named like an installable archive but is not one is a
// package that went unexamined, and is reported as such. So is anything that
// starts like an archive this scanner cannot unpack, under any name — that case
// never reaches this function (see archiveMagic).
func (s *Service) notArchive(art Artifact) *Report {
	if claimsArchive(art.Filename) {
		return s.unscanned(art, CodeUnsupported, notArchiveDetail)
	}
	s.notPackage.Add(1)
	return nil
}

// queuePerSlot sizes the wait queue: this many scans may wait per scan slot.
const queuePerSlot = 8

// queueLimit is the number of scans that may wait for a slot.
func (s *Service) queueLimit() int { return cap(s.sem) * queuePerSlot }

// tenantShare is the number of scans — running or waiting — one tenant may have
// outstanding at a time: half of everything there is.
func (s *Service) tenantShare() int {
	share := (cap(s.sem) + s.queueLimit()) / 2
	if share < 1 {
		share = 1
	}
	return share
}

// outstanding returns the scans a tenant's requests started that have not
// finished yet.
func (s *Service) outstanding(tenant string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.load[tenant]
}

func (s *Service) addOutstanding(tenant string, delta int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if n := s.load[tenant] + delta; n > 0 {
		s.load[tenant] = n
	} else {
		delete(s.load, tenant)
	}
}

// Circuit-breaker and negative-cache tuning.
const (
	breakerThreshold = 5                // consecutive provider failures that open the breaker
	breakerCooldown  = 30 * time.Second // how long it stays open
	transientTTL     = 20 * time.Second // how long a transient failure is remembered
	maxNegEntries    = 20000
	maxCoordEntries  = 100000
	// maxNotifiedEntries bounds the budget-notice memory.
	maxNotifiedEntries = 10000
)

// Service is the LLM package-content scan gate. Construct one with NewService.
type Service struct {
	cfg      Config
	provider commit.Provider
	// tools is the provider's tool-use capability, or nil when the scan must use
	// the single-shot bundle (the provider lacks tool use, or mode is "bundle").
	tools  commit.ToolProvider
	store  VerdictStore
	budget *budget
	log    *slog.Logger
	now    func() time.Time

	// baseCtx is the parent of every scan's context. Scans are detached from the
	// requests that trigger them; Close cancels this to stop them.
	baseCtx context.Context
	cancel  context.CancelFunc
	wg      sync.WaitGroup

	flight singleflight.Group
	sem    chan struct{}

	mu       sync.Mutex
	closed   bool
	inflight map[string]struct{}
	neg      map[string]negEntry
	coords   map[string]map[string]struct{} // coordinate -> cache keys seen for it
	viewers  map[string]map[string]struct{} // cache key -> tenants given a report on it
	breaker  breakerState
	notified map[string]time.Time // budget scope+tenant -> last exhaustion notice
	load     map[string]int       // tenant -> scans it started that are running or waiting
	byCode   map[string]uint64
	byTool   map[string]uint64
	byEco    map[string]uint64
	byScope  map[string]uint64
	costUSD  float64
	scanSecs float64

	assessed       atomic.Uint64
	cacheHits      atomic.Uint64
	cacheMisses    atomic.Uint64
	negHits        atomic.Uint64
	joined         atomic.Uint64
	scans          atomic.Uint64
	scanErrors     atomic.Uint64
	verdictMal     atomic.Uint64
	verdictSus     atomic.Uint64
	verdictBenign  atomic.Uint64
	injected       atomic.Uint64
	truncatedScans atomic.Uint64
	providerCalls  atomic.Uint64
	providerErrs   atomic.Uint64
	inputTokens    atomic.Uint64
	outputTokens   atomic.Uint64
	cacheReadTok   atomic.Uint64
	turns          atomic.Uint64
	blocked        atomic.Uint64
	quarantined    atomic.Uint64
	annotated      atomic.Uint64
	failedOpen     atomic.Uint64
	failedClosed   atomic.Uint64
	notPackage     atomic.Uint64
	running        atomic.Int64
	waiting        atomic.Int64 // scans waiting for a slot
	// toolsOffUntil (unix nanoseconds) pauses the tool loop after the endpoint
	// rejected a tool-bearing request in auto mode; see suspendTools.
	toolsOffUntil atomic.Int64
}

type negEntry struct {
	code   string
	detail string
	until  time.Time
}

type breakerState struct {
	failures  int
	openUntil time.Time
}

// NewService validates cfg and constructs the gate.
func NewService(cfg Config) (*Service, error) {
	cfg = cfg.withDefaults()
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	s := &Service{
		cfg:      cfg,
		provider: cfg.Provider,
		store:    cfg.Store,
		budget:   newBudget(cfg.Budget),
		log:      cfg.Logger,
		now:      cfg.Now,
		sem:      make(chan struct{}, cfg.MaxConcurrent),
		inflight: make(map[string]struct{}),
		neg:      make(map[string]negEntry),
		coords:   make(map[string]map[string]struct{}),
		viewers:  make(map[string]map[string]struct{}),
		notified: make(map[string]time.Time),
		load:     make(map[string]int),
		byCode:   make(map[string]uint64),
		byTool:   make(map[string]uint64),
		byEco:    make(map[string]uint64),
		byScope:  make(map[string]uint64),
	}
	if s.store == nil {
		s.store = NewMemoryStore(0)
	}
	if cfg.Mode != ModeBundle {
		if tp, ok := cfg.Provider.(commit.ToolProvider); ok {
			s.tools = tp
		}
	}
	s.baseCtx, s.cancel = context.WithCancel(context.Background())
	s.warmCoordinates()
	return s, nil
}

// warmCoordinates rebuilds the coordinate index from verdicts persisted by an
// earlier process, so the admin and dossier views can find them by coordinate
// before the artifact is pulled again.
func (s *Service) warmCoordinates() {
	vs, err := s.store.List(s.baseCtx)
	if err != nil {
		s.log.Warn("llmpkgscan: listing stored verdicts failed", "error", err)
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, v := range vs {
		if v.Name != "" && len(s.coords) < maxCoordEntries {
			// The tenant whose pull paid for the scan is the one tenant known to
			// have had these bytes; any other is re-admitted when it next pulls them.
			s.addCoordLocked(coordKey(v.Ecosystem, v.Name, v.Version), v.Key, v.Tenant)
		}
	}
}

// Close stops in-flight scans and waits for them to unwind. It does not close
// the verdict store (its owner does).
func (s *Service) Close() error {
	if s == nil {
		return nil
	}
	// No scan may start once closing has begun: that is what makes waiting for
	// the ones already running sound (see begin).
	s.mu.Lock()
	s.closed = true
	s.mu.Unlock()
	s.cancel()
	s.wg.Wait()
	return nil
}

// begin registers a scan that is about to start, unless the service is
// closing. Registering under the same lock that Close takes means a scan is
// either counted before Close starts waiting or never started at all.
func (s *Service) begin() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return false
	}
	s.wg.Add(1)
	return true
}

// Enabled reports whether the gate is configured on. Safe on a nil receiver.
func (s *Service) Enabled() bool { return s != nil && s.cfg.Enabled }

// Applies reports whether the gate scans an ecosystem. Safe on a nil receiver.
func (s *Service) Applies(ecosystem string) bool {
	return s.Enabled() && s.cfg.ecosystemAllowed(ecosystem)
}

// AppliesTo reports whether the gate scans artifacts of an ecosystem fetched
// through a given upstream: the ecosystem must be in scope and the upstream
// must not be excluded. Safe on a nil receiver.
func (s *Service) AppliesTo(ecosystem, upstream string) bool {
	return s.Applies(ecosystem) && !s.cfg.upstreamExcluded(upstream)
}

// Action returns the configured action. Safe on a nil receiver.
func (s *Service) Action() Action {
	if s == nil {
		return ActionAnnotate
	}
	return s.cfg.Action
}

// FailMode returns the configured fail mode. Safe on a nil receiver.
func (s *Service) FailMode() FailMode {
	if s == nil {
		return FailOpen
	}
	return s.cfg.FailMode
}

// UsesTools reports whether scans may use the tool loop right now.
func (s *Service) UsesTools() bool { return s != nil && s.toolsUsable() }

// Assess returns the gate's report for an artifact, scanning it if it has no
// stored verdict. It returns (nil, nil) when the gate does not apply: the
// artifact's ecosystem is out of scope, its upstream is excluded, or the
// resource turns out not to be a package archive.
//
// It returns an error only when the caller's own context ends while it waits —
// the caller is gone, so there is no one to report to. Every other outcome,
// including every failure to scan, is a Report; a failure is a Report with
// Unscanned set and is never a clean verdict.
func (s *Service) Assess(ctx context.Context, req Request) (*Report, error) {
	if !s.AppliesTo(req.Artifact.Ecosystem, req.Artifact.Upstream) {
		return nil, nil
	}
	rep, err := s.assess(ctx, req)
	if rep != nil {
		s.assessed.Add(1)
	}
	return rep, err
}

// assess is Assess for an ecosystem in scope. A nil report with a nil error
// means the resource turned out not to be a package archive.
func (s *Service) assess(ctx context.Context, req Request) (*Report, error) {
	art := req.Artifact

	hexDigest, ok := NormalizeDigest(art.Digest)
	if !ok {
		// The cache did not record a sha256 for this entry: derive it. This reads
		// the artifact once per request, so it is the slow path, not the norm.
		d, err := s.hashArtifact(ctx, req)
		if err != nil {
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			var se *scanError
			if errors.As(err, &se) {
				return s.unscanned(art, se.code, se.err.Error()), nil
			}
			return s.unscanned(art, CodeUnavailable, "computing the artifact digest: "+err.Error()), nil
		}
		hexDigest = d
	}
	art.Digest = "sha256:" + hexDigest
	key := CacheKey(hexDigest, s.cfg.Model, PromptVersion)

	// 1. The verdict cache: identical bytes are scanned once.
	if v := s.lookup(ctx, key); v != nil {
		s.cacheHits.Add(1)
		// The tenant has now been given a report on these bytes: it may read the
		// verdict from the admin surface and the dossier too.
		s.noteCoordinate(art, key, req.Tenant)
		rep := s.report(art, v)
		rep.Cached = true
		return rep, nil
	}
	// 2. A remembered failure: do not pay again for a scan that just failed.
	if ne, hit := s.negative(key); hit {
		if ne.code == codeNotArchive {
			return s.notArchive(art), nil
		}
		s.negHits.Add(1)
		return s.unscanned(art, ne.code, ne.detail), nil
	}
	// 3. Cheap refusals before any work is queued.
	if art.Size > s.cfg.Limits.MaxArtifactBytes {
		detail := fmt.Sprintf("the artifact is %d bytes, over the %d-byte scan limit", art.Size, s.cfg.Limits.MaxArtifactBytes)
		s.remember(key, CodeOversized, detail)
		return s.unscanned(art, CodeOversized, detail), nil
	}
	if !s.breakerAllows() {
		return s.unscanned(art, CodeProviderUnavailable, "the provider circuit breaker is open"), nil
	}
	// A bounded queue. Scans beyond the slots wait for one, and a request waits
	// with its scan; past a point, waiting only guarantees a timeout — and an
	// unbounded line of waiters is something any client can build by asking for
	// many distinct artifacts. Beyond the bound the answer is immediate. (A
	// request for a digest already being scanned joins that scan and adds
	// nothing to the queue.)
	if !s.isInflight(key) {
		detail := ""
		switch {
		case int(s.waiting.Load()) >= s.queueLimit():
			detail = fmt.Sprintf("%d scans are already waiting for one of %d slots", s.waiting.Load(), cap(s.sem))
		case s.outstanding(req.Tenant) >= s.tenantShare():
			// One tenant may hold at most half of the slots and the queue, so a
			// client requesting many distinct artifacts cannot starve every other
			// tenant of scans.
			detail = fmt.Sprintf("the tenant already has %d scans running or waiting", s.outstanding(req.Tenant))
		}
		if detail != "" {
			s.mu.Lock()
			s.byCode[CodeBusy]++
			s.mu.Unlock()
			return s.unscanned(art, CodeBusy, detail), nil
		}
	}
	if allowed, scope := s.budget.allow(req.Tenant); !allowed {
		s.mu.Lock()
		s.byScope[scope]++
		s.mu.Unlock()
		if s.cfg.OnBudgetExhausted != nil && s.firstExhaustion(scope, req.Tenant) {
			s.cfg.OnBudgetExhausted(scope, req.Tenant)
		}
		return s.unscanned(art, CodeBudgetExhausted, "the "+scope+" cost ceiling was reached"), nil
	}

	// 4. Scan, sharing one scan among concurrent requests for the same digest.
	if s.isInflight(key) {
		s.joined.Add(1)
	}
	ch := s.flight.DoChan(key, func() (any, error) {
		if !s.begin() {
			return &scanResult{code: CodeUnavailable, detail: "the gate is shutting down"}, nil
		}
		defer s.wg.Done()
		return s.scan(key, hexDigest, art, req), nil
	})
	select {
	case res := <-ch:
		out, _ := res.Val.(*scanResult)
		if out != nil && out.code == codeNotArchive {
			return s.notArchive(art), nil
		}
		s.cacheMisses.Add(1)
		if out == nil {
			return s.unscanned(art, CodeInternalError, "the scan produced no result"), nil
		}
		if out.verdict != nil {
			s.noteCoordinate(art, key, req.Tenant)
			rep := s.report(art, out.verdict)
			rep.Shared = res.Shared
			rep.Cached = out.cached
			return rep, nil
		}
		return s.unscanned(art, out.code, out.detail), nil
	case <-ctx.Done():
		// The caller is gone. The scan carries on: its verdict is stored for the
		// next request, which is very likely this client's own retry.
		s.cacheMisses.Add(1)
		return nil, ctx.Err()
	}
}

// scanResult is what one scan produced, shared by every request that waited.
type scanResult struct {
	verdict *Verdict
	cached  bool
	code    string
	detail  string
}

// scan runs one scan to completion on its own context. It never returns nil and
// never panics: a panic anywhere beneath it (the unpacker, the provider SDK)
// becomes an "internal-error" result instead of taking the proxy down.
func (s *Service) scan(key, hexDigest string, art Artifact, req Request) (res *scanResult) {
	defer func() {
		if r := recover(); r != nil {
			s.log.Error("llmpkgscan: scan panicked", "artifact", art.Coordinate(), "panic", fmt.Sprint(r))
			res = s.failed(key, art, fail(CodeInternalError, fmt.Errorf("scanner panicked")))
		}
	}()

	ctx, cancel := context.WithTimeout(s.baseCtx, s.cfg.Timeout)
	defer cancel()
	s.setInflight(key, true)
	defer s.setInflight(key, false)
	s.addOutstanding(req.Tenant, 1)
	defer s.addOutstanding(req.Tenant, -1)

	// A previous flight may have stored the verdict between this request's cache
	// lookup and its turn to scan.
	if v := s.lookup(ctx, key); v != nil {
		return &scanResult{verdict: v, cached: true}
	}

	s.waiting.Add(1)
	select {
	case s.sem <- struct{}{}:
		s.waiting.Add(-1)
		defer func() { <-s.sem }()
	case <-ctx.Done():
		s.waiting.Add(-1)
		// Not a provider failure: nothing was asked of the provider, so this does
		// not count against the circuit breaker.
		return s.failed(key, art, failf(CodeBusy, "no scan slot became free within the scan's time limit"))
	}
	s.running.Add(1)
	defer s.running.Add(-1)
	start := s.now()

	if req.Open == nil {
		return s.failed(key, art, failf(CodeUnavailable, "no artifact stream was supplied"))
	}
	rc, err := req.Open(ctx)
	if err != nil {
		return s.failed(key, art, failf(CodeUnavailable, "opening the cached artifact: %v", err))
	}
	tree, err := buildTree(ctx, rc, s.cfg.Limits)
	_ = rc.Close()
	if errors.Is(err, errNotArchive) {
		// The bytes are not an archive of any kind. That is a property of the
		// bytes, so it is what gets remembered and shared with every request
		// waiting on this scan; what it means is decided per request, by what the
		// resource claims to be (see notArchive) — two requests for the same bytes
		// under different names must not inherit each other's answer.
		s.remember(key, codeNotArchive, "")
		if claimsArchive(art.Filename) {
			s.scanErrors.Add(1)
			s.mu.Lock()
			s.byCode[CodeUnsupported]++
			s.mu.Unlock()
			s.log.Warn("llmpkgscan: artifact not scanned",
				"artifact", art.Coordinate(), "ecosystem", art.Ecosystem, "code", CodeUnsupported, "error", notArchiveDetail)
		}
		return &scanResult{code: codeNotArchive}
	}
	if err != nil {
		return s.failed(key, art, treeError(ctx, err, s.cfg.Limits))
	}
	// The verdict is stored under the digest the cache recorded; it must describe
	// those bytes. If what was just read hashes differently, the cache entry
	// changed underneath the scan (or its metadata is wrong), and a verdict on
	// these bytes must not be filed under that digest.
	if tree.Digest != hexDigest {
		s.log.Error("llmpkgscan: artifact digest mismatch; refusing to record a verdict",
			"artifact", art.Coordinate(), "expected", hexDigest, "actual", tree.Digest)
		return s.failed(key, art, failf(CodeDigestMismatch, "the artifact's bytes do not match its recorded sha256 digest"))
	}

	injection := detectInjection(ctx, tree)
	run, err := s.runModel(ctx, tree, art)
	// Whatever the run consumed is charged, verdict or not.
	s.budget.record(req.Tenant, run.usage, run.costUSD)
	s.observeRun(run)
	if err != nil {
		return s.failed(key, art, classifyProviderError(ctx, err))
	}
	s.breakerRecord(true)

	end := s.now()
	v := &Verdict{
		Key:                 key,
		Digest:              "sha256:" + hexDigest,
		Verdict:             run.verdict.Verdict,
		Confidence:          run.verdict.Confidence,
		Reasons:             run.verdict.Reasons,
		Evidence:            run.verdict.Evidence,
		Injection:           injection,
		Anomalies:           tree.Anomalies,
		StructuralRisk:      tree.StrongAnomalies > 0,
		Provider:            s.provider.Name(),
		Model:               s.cfg.Model,
		PromptVersion:       PromptVersion,
		Mode:                run.mode,
		Turns:               run.turns,
		ToolCalls:           run.toolCalls,
		Format:              tree.Format,
		Files:               len(tree.Files),
		UnpackedBytes:       tree.UnpackedBytes,
		InputTokens:         run.usage.InputTokens,
		OutputTokens:        run.usage.OutputTokens,
		CacheReadTokens:     run.usage.CacheReadTokens,
		CacheCreationTokens: run.usage.CacheCreationTokens,
		CostUSD:             run.costUSD,
		Ecosystem:           CanonEcosystem(art.Ecosystem),
		Name:                art.Name,
		Version:             art.Version,
		Filename:            art.Filename,
		Tenant:              req.Tenant,
		ScannedAt:           end.UTC(),
		DurationMS:          end.Sub(start).Milliseconds(),
	}
	// What the verdict could not see. The unpack limits apply in both modes; in
	// bundle mode the prompt budget is a further limit, because there the model
	// cannot go and fetch what was left out.
	v.Coverage = append(v.Coverage, tree.Notes...)
	if run.mode == modeBundle && !run.seedComplete {
		v.Coverage = append(v.Coverage, "The package did not fit the prompt: the verdict is based on the highest-priority files only.")
	}
	v.Truncated = len(v.Coverage) > 0

	s.scans.Add(1)
	switch v.Verdict {
	case VerdictMalicious:
		s.verdictMal.Add(1)
	case VerdictSuspicious:
		s.verdictSus.Add(1)
	default:
		s.verdictBenign.Add(1)
	}
	if hasStrongInjection(injection) {
		s.injected.Add(1)
	}
	if v.Truncated {
		s.truncatedScans.Add(1)
	}
	s.mu.Lock()
	s.byEco[v.Ecosystem]++
	s.scanSecs += end.Sub(start).Seconds()
	s.mu.Unlock()

	// Persist on the service context: the verdict is paid for, and losing it to a
	// deadline that expired during the final provider call would mean paying again.
	if perr := s.store.Put(s.baseCtx, v); perr != nil {
		s.log.Error("llmpkgscan: persisting verdict failed", "artifact", art.Coordinate(), "error", perr)
	}
	if s.cfg.OnVerdict != nil {
		s.cfg.OnVerdict(v.clone())
	}
	return &scanResult{verdict: v}
}

// treeError maps an unpack failure onto a reason.
func treeError(ctx context.Context, err error, lim Limits) *scanError {
	switch {
	case errors.Is(err, errOversized):
		return failf(CodeOversized, "the artifact is larger than the %d-byte scan limit", lim.MaxArtifactBytes)
	case errors.Is(err, errUnsupported):
		return failf(CodeUnsupported, "the artifact is not an archive format the scanner can unpack: %v", err)
	case errors.Is(err, errNotArchive):
		return failf(CodeUnsupported, notArchiveDetail)
	case errors.Is(err, errEmpty):
		return failf(CodeEmptyArchive, "the archive contains no files")
	case errors.Is(err, errUnpackLimit):
		return failf(CodeUnpackLimit, "nothing could be unpacked from the archive within the scan limits")
	case errors.Is(err, context.DeadlineExceeded), errors.Is(err, context.Canceled), ctx.Err() != nil:
		return failf(CodeTimeout, "the scan did not finish within its time limit")
	default:
		return failf(CodeUnavailable, "the cached artifact could not be read")
	}
}

// failed records a scan that ended without a verdict and returns its result.
func (s *Service) failed(key string, art Artifact, se *scanError) *scanResult {
	s.scanErrors.Add(1)
	s.mu.Lock()
	s.byCode[se.code]++
	s.mu.Unlock()
	switch se.code {
	case CodeProviderError, CodeTimeout:
		s.breakerRecord(false)
	}
	detail := cleanText(se.err.Error(), 300)
	s.remember(key, se.code, detail)
	s.log.Warn("llmpkgscan: artifact not scanned",
		"artifact", art.Coordinate(), "ecosystem", art.Ecosystem, "code", se.code, "error", detail)
	return &scanResult{code: se.code, detail: detail}
}

// hashArtifact derives the artifact's sha256 by reading it, bounded by the
// artifact size limit.
func (s *Service) hashArtifact(ctx context.Context, req Request) (string, error) {
	if req.Open == nil {
		return "", failf(CodeUnavailable, "no artifact stream was supplied")
	}
	rc, err := req.Open(ctx)
	if err != nil {
		return "", err
	}
	defer rc.Close()
	h := sha256.New()
	n, err := io.Copy(h, io.LimitReader(rc, s.cfg.Limits.MaxArtifactBytes+1))
	if err != nil {
		return "", err
	}
	if n > s.cfg.Limits.MaxArtifactBytes {
		return "", failf(CodeOversized, "the artifact is larger than the %d-byte scan limit", s.cfg.Limits.MaxArtifactBytes)
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// lookup returns the stored verdict for key, honoring the cache TTL.
func (s *Service) lookup(ctx context.Context, key string) *Verdict {
	v, err := s.store.Get(ctx, key)
	if err != nil {
		if !errors.Is(err, ErrNotFound) && ctx.Err() == nil {
			s.log.Warn("llmpkgscan: reading stored verdict failed", "key", key, "error", err)
		}
		return nil
	}
	if v == nil || v.Key != key {
		return nil
	}
	if s.cfg.CacheTTL > 0 && s.now().Sub(v.ScannedAt) > s.cfg.CacheTTL {
		return nil
	}
	return v
}

// negative returns a remembered failure for key, if one is still current.
func (s *Service) negative(key string) (negEntry, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	ne, ok := s.neg[key]
	if !ok {
		return negEntry{}, false
	}
	if !s.now().Before(ne.until) {
		delete(s.neg, key)
		return negEntry{}, false
	}
	return ne, true
}

// remember records a failure so the same artifact is not scanned again at once.
// How long depends on the cause: something about the artifact itself is
// remembered for the full error TTL, a passing fault only briefly, and reasons
// that are not about the artifact at all (budget, breaker) not at all.
func (s *Service) remember(key, code, detail string) {
	var ttl time.Duration
	switch {
	case code == CodeBudgetExhausted || code == CodeProviderUnavailable:
		return
	case transient(code):
		ttl = transientTTL
		if s.cfg.ErrorTTL < ttl {
			ttl = s.cfg.ErrorTTL
		}
	default:
		ttl = s.cfg.ErrorTTL
	}
	if ttl <= 0 {
		return
	}
	now := s.now()
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.neg) >= maxNegEntries {
		for k, ne := range s.neg {
			if !now.Before(ne.until) {
				delete(s.neg, k)
			}
		}
		// Still full of live entries: drop arbitrary ones. Forgetting a failure
		// only costs a retry.
		for k := range s.neg {
			if len(s.neg) < maxNegEntries {
				break
			}
			delete(s.neg, k)
		}
	}
	s.neg[key] = negEntry{code: code, detail: detail, until: now.Add(ttl)}
}

// firstExhaustion reports whether a budget denial should be announced. A ceiling
// stays reached until its window rolls over, and every pull in between is
// denied; announcing each one would bury the alert it is meant to raise, so one
// notice is given per scope and tenant per budget window.
func (s *Service) firstExhaustion(scope, tenant string) bool {
	now := s.now()
	k := scope + "\x00" + tenant
	s.mu.Lock()
	defer s.mu.Unlock()
	if last, ok := s.notified[k]; ok && now.Sub(last) < s.cfg.Budget.Window {
		return false
	}
	if len(s.notified) >= maxNotifiedEntries {
		clear(s.notified)
	}
	s.notified[k] = now
	return true
}

// breakerAllows reports whether scans may currently reach the provider. After
// a run of consecutive provider failures the breaker opens for a cooldown, so
// an outage costs each request one fast refusal instead of a full timeout.
func (s *Service) breakerAllows() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return !s.now().Before(s.breaker.openUntil)
}

func (s *Service) breakerRecord(ok bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if ok {
		s.breaker.failures = 0
		return
	}
	s.breaker.failures++
	if s.breaker.failures >= breakerThreshold {
		s.breaker.openUntil = s.now().Add(breakerCooldown)
		// Half-open afterwards: one more failure re-opens it immediately.
		s.breaker.failures = breakerThreshold - 1
	}
}

func (s *Service) isInflight(key string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, ok := s.inflight[key]
	return ok
}

func (s *Service) setInflight(key string, on bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if on {
		s.inflight[key] = struct{}{}
	} else {
		delete(s.inflight, key)
	}
}

// observeCall folds one provider completion into the metrics.
func (s *Service) observeCall(u commit.Usage, costUSD float64, ok bool) {
	s.providerCalls.Add(1)
	if !ok {
		s.providerErrs.Add(1)
	}
	s.inputTokens.Add(uint64(u.InputTokens + u.CacheCreationTokens))
	s.cacheReadTok.Add(uint64(u.CacheReadTokens))
	s.outputTokens.Add(uint64(u.OutputTokens))
	if costUSD > 0 {
		s.mu.Lock()
		s.costUSD += costUSD
		s.mu.Unlock()
	}
}

// observeRun folds one model run's tool activity into the metrics.
func (s *Service) observeRun(run *modelRun) {
	s.turns.Add(uint64(run.turns))
	if len(run.byTool) == 0 {
		return
	}
	s.mu.Lock()
	for tool, n := range run.byTool {
		s.byTool[tool] += uint64(n)
	}
	s.mu.Unlock()
}

// --- coordinate index ---------------------------------------------------------
//
// Verdicts are stored by digest. The admin surface and the dossier ask by
// coordinate, so the service keeps an in-memory index from coordinate to the
// cache keys seen for it — and, per key, the tenants that were given a report
// on those bytes.
//
// The second half is an access-control list, not a convenience. A verdict quotes
// the package: its reasons describe the code and its evidence carries excerpts
// of it. For a private package that is confidential to the tenants entitled to
// pull it, so a tenant-scoped reader is shown a verdict only if that tenant has
// itself pulled those exact bytes through the gate. Knowing a coordinate is not
// enough.

// maxViewersPerKey bounds the tenants recorded per verdict. A tenant beyond the
// bound is simply not shown the verdict (it fails closed).
const maxViewersPerKey = 64

func coordKey(ecosystem, name, version string) string {
	return CanonEcosystem(ecosystem) + "\x00" + name + "\x00" + version
}

func (s *Service) noteCoordinate(art Artifact, key, tenant string) {
	if art.Name == "" {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.addCoordLocked(coordKey(art.Ecosystem, art.Name, art.Version), key, tenant)
}

func (s *Service) addCoordLocked(ck, key, tenant string) {
	set, ok := s.coords[ck]
	if !ok {
		if len(s.coords) >= maxCoordEntries {
			// Drop an arbitrary entry: the index is rebuilt for a coordinate the next
			// time it is pulled.
			for k, keys := range s.coords {
				for dropped := range keys {
					delete(s.viewers, dropped)
				}
				delete(s.coords, k)
				break
			}
		}
		set = make(map[string]struct{}, 1)
		s.coords[ck] = set
	}
	if _, known := set[key]; !known {
		if len(set) >= 8 {
			return
		}
		set[key] = struct{}{}
	}
	seen, ok := s.viewers[key]
	if !ok {
		seen = make(map[string]struct{}, 1)
		s.viewers[key] = seen
	}
	if len(seen) < maxViewersPerKey {
		seen[tenant] = struct{}{}
	}
}

// visibleLocked reports whether a tenant-scoped reader may see the verdict
// stored under key. An empty tenant is an unscoped (organization-wide) reader
// and sees everything. Bytes that were served to an unidentified client (the
// empty tenant among the viewers) are not confidential between tenants.
func (s *Service) visibleLocked(key, tenant string) bool {
	if tenant == "" {
		return true
	}
	seen := s.viewers[key]
	if _, ok := seen[tenant]; ok {
		return true
	}
	_, public := seen[""]
	return public
}

// ForCoordinate returns the stored verdicts for the artifacts served under a
// coordinate, newest first. An empty version matches every version seen.
//
// tenant scopes the answer: a non-empty tenant is shown only verdicts on bytes
// that tenant has itself pulled, with the scanning tenant and the spend removed;
// an empty tenant (an organization-wide reader) is shown everything.
func (s *Service) ForCoordinate(tenant, ecosystem, name, version string) []*Verdict {
	if s == nil || name == "" {
		return nil
	}
	eco := CanonEcosystem(ecosystem)
	var keys []string
	s.mu.Lock()
	for ck, set := range s.coords {
		ckEco, ckName, ckVersion := splitCoordKey(ck)
		if !strings.EqualFold(ckName, name) || (eco != "" && ckEco != eco) || (version != "" && ckVersion != version) {
			continue
		}
		for k := range set {
			if s.visibleLocked(k, tenant) {
				keys = append(keys, k)
			}
		}
	}
	s.mu.Unlock()

	seen := make(map[string]bool, len(keys))
	var out []*Verdict
	for _, k := range keys {
		if seen[k] {
			continue
		}
		seen[k] = true
		if v := s.lookup(s.baseCtx, k); v != nil {
			out = append(out, forReader(v, tenant))
		}
	}
	sortVerdicts(out)
	return out
}

// forReader returns the copy of a verdict a reader is given. A tenant-scoped
// reader is not told which tenant's pull triggered the scan, or what it cost
// that tenant.
func forReader(v *Verdict, tenant string) *Verdict {
	c := v.clone()
	if tenant != "" {
		c.Tenant = ""
		c.CostUSD = 0
		c.InputTokens, c.OutputTokens, c.CacheReadTokens, c.CacheCreationTokens = 0, 0, 0, 0
	}
	return c
}

func sortVerdicts(vs []*Verdict) {
	sort.Slice(vs, func(i, j int) bool {
		if !vs[i].ScannedAt.Equal(vs[j].ScannedAt) {
			return vs[i].ScannedAt.After(vs[j].ScannedAt)
		}
		return vs[i].Key < vs[j].Key
	})
}

func splitCoordKey(ck string) (eco, name, version string) {
	parts := [3]string{}
	i := 0
	start := 0
	for p := 0; p < len(ck) && i < 2; p++ {
		if ck[p] == 0 {
			parts[i] = ck[start:p]
			i++
			start = p + 1
		}
	}
	parts[i] = ck[start:]
	return parts[0], parts[1], parts[2]
}

// Verdicts returns stored verdicts, newest first, at most limit (0 = all),
// scoped to tenant exactly as ForCoordinate is.
func (s *Service) Verdicts(tenant string, limit int) []*Verdict {
	if s == nil {
		return nil
	}
	vs, err := s.store.List(s.baseCtx)
	if err != nil {
		s.log.Warn("llmpkgscan: listing stored verdicts failed", "error", err)
		return nil
	}
	out := make([]*Verdict, 0, len(vs))
	s.mu.Lock()
	for _, v := range vs {
		if v != nil && s.visibleLocked(v.Key, tenant) {
			out = append(out, v)
		}
	}
	s.mu.Unlock()
	for i, v := range out {
		out[i] = forReader(v, tenant)
	}
	sortVerdicts(out)
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out
}

// Prune removes stored verdicts older than the cache TTL. It is a no-op when no
// TTL is configured.
func (s *Service) Prune(ctx context.Context) (int, error) {
	if s == nil || s.cfg.CacheTTL <= 0 {
		return 0, nil
	}
	return s.store.Prune(ctx, s.now().Add(-s.cfg.CacheTTL))
}
