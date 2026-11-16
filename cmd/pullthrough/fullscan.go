package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"

	"github.com/blechschmidt/pullthrough-security/internal/audit"
	"github.com/blechschmidt/pullthrough-security/internal/config"
	"github.com/blechschmidt/pullthrough-security/internal/coord"
	"github.com/blechschmidt/pullthrough-security/internal/fullmirror"
	"github.com/blechschmidt/pullthrough-security/internal/fullscan"
	"github.com/blechschmidt/pullthrough-security/internal/llmpkgscan"
	"github.com/blechschmidt/pullthrough-security/internal/lockdown"
	"github.com/blechschmidt/pullthrough-security/internal/notify"
	"github.com/blechschmidt/pullthrough-security/internal/proxy"
)

// The full scan (Task 192): adapters between internal/fullscan, the gateway's
// LLM package-content scan gate and the full mirror.

// fullScanSource names the full scan in the gate's audit records.
const fullScanSource = "full-scan"

// buildFullScan builds the full scan, or returns nil when none is configured.
// Its scope is every upstream whose fullMirror block sets fullScan and — with
// fullScan.enabled — every upstream the gate scans. It reads no state and
// scans nothing: wireFullScan attaches it to the gateway and starts it.
func buildFullScan(cfg *config.Config, svc *llmpkgscan.Service, auditLog *audit.Logger, notifier *notify.Notifier, logger *slog.Logger) (*fullscan.Service, error) {
	if !cfg.FullScanRequested() {
		return nil, nil
	}
	if !svc.Enabled() {
		return nil, errors.New("the full scan needs the LLM package-content scan gate (llmPackageScan.enabled)")
	}
	eco := ecosystemMap(cfg)
	seen := map[string]bool{}
	var scope []string
	for _, name := range cfg.FullScanUpstreams() {
		if !svc.AppliesTo(eco[name], name) {
			return nil, fmt.Errorf("upstream %q: fullMirror.fullScan is set, but the LLM package scan does not cover %s artifacts (llmPackageScan.include / exclude)", name, eco[name])
		}
		seen[name] = true
		scope = append(scope, name)
	}
	if cfg.FullScan.Enabled {
		for name, typ := range eco {
			if !seen[name] && svc.AppliesTo(typ, name) {
				seen[name] = true
				scope = append(scope, name)
			}
		}
	}
	if len(scope) == 0 {
		return nil, errors.New("fullScan.enabled is set, but the LLM package scan covers none of the upstreams")
	}
	// Leave the gate a slot for the scans client pulls start.
	concurrency := cfg.FullScan.Concurrency
	if concurrency <= 0 {
		concurrency = fullscan.DefaultConcurrency
	}
	slots := svc.Status().MaxConcurrent
	if slots < 2 {
		return nil, fmt.Errorf("the full scan needs llmPackageScan.maxConcurrent of at least 2 (it is %d): one scan slot is always left to client pulls", slots)
	}
	if concurrency > slots-1 {
		logger.Info("full scan: concurrency held below llmPackageScan.maxConcurrent so client pulls keep a scan slot",
			"configured", concurrency, "effective", slots-1)
		concurrency = slots - 1
	}
	opts := fullscan.Options{
		Dir:           cfg.FullScanStateDir(),
		Upstreams:     scope,
		All:           cfg.FullScan.Enabled,
		Tenant:        cfg.FullMirror.Tenant,
		Concurrency:   concurrency,
		DailyUSD:      cfg.FullScan.Budget.DailyUSD,
		MonthlyUSD:    cfg.FullScan.Budget.MonthlyUSD,
		SweepInterval: cfg.FullScan.SweepInterval,
		MaxItems:      cfg.FullScan.MaxArtifacts,
		Logger:        logger.With("component", "fullscan"),
	}
	if auditLog != nil {
		opts.Audit = auditLog
	}
	if notifier != nil {
		opts.OnBudgetExhausted = func(window string, spent, ceiling float64) {
			notifier.Emit(context.Background(), notify.FullScanBudgetEvent(window, spent, ceiling))
		}
	}
	fs, err := fullscan.New(opts)
	if err != nil {
		return nil, err
	}
	logger.Info("full scan configured", "upstreams", scope, "all", cfg.FullScan.Enabled, "stateDir", opts.Dir,
		"concurrency", concurrency, "dailyUSD", opts.DailyUSD, "monthlyUSD", opts.MonthlyUSD)
	return fs, nil
}

// wireFullScan attaches the full scan to the gateway (its scans go through
// Gateway.SystemScan, the ladder through Gateway.EnforceLLMScan) and to the
// cache listing, gates it on the full mirror's lease and the emergency
// lockdown, and starts it.
func wireFullScan(ctx context.Context, fs *fullscan.Service, cfg *config.Config, gw *proxy.Gateway, svc *llmpkgscan.Service, inv fullscan.Inventory, guard *coord.Guard, lock *lockdown.Service) {
	if fs == nil {
		return
	}
	fs.Attach(gatewayFullScanner{gw: gw, svc: svc, roles: cfg.FullMirror.Roles}, inv)
	fs.SetLeaderGate(guard.IsLeader)
	if lock != nil {
		fs.SetKillSwitch(func() (bool, string) {
			st := lock.Status()
			return st.Active, string(st.Mode)
		})
	}
	fs.Start(ctx)
}

// fullScanInventory returns the cache listing the sweep reads, or nil when
// the cache cannot be listed.
func fullScanInventory(c any) fullscan.Inventory {
	if inv, ok := c.(fullscan.Inventory); ok {
		return inv
	}
	return nil
}

// gatewayFullScanner puts a cached artifact before the gate as the tenant that
// holds it, and applies the action ladder to the reading.
type gatewayFullScanner struct {
	gw    *proxy.Gateway
	svc   *llmpkgscan.Service
	roles []string
}

func (s gatewayFullScanner) Signature() string { return s.svc.Signature().String() }

func (s gatewayFullScanner) Load() (int64, int64, int) { return s.svc.Load() }

func (s gatewayFullScanner) Scan(ctx context.Context, a fullscan.Artifact, opts fullscan.ScanOptions) (fullscan.Reading, error) {
	// Paid from the full scan's own budget: a backlog never leaves the
	// clients' pulls without the gate's.
	sl, err := s.gw.SystemScan(ctx, proxy.SystemScanRequest{
		Backend: a.Upstream, Path: a.Path, Accept: a.Accept,
		Tenant: a.Tenant, Subject: fullscan.Subject, Roles: s.roles,
		CacheKey: a.Key, Digest: a.Digest, Refresh: opts.Refresh, OwnBudget: true,
	})
	switch {
	case errors.Is(err, proxy.ErrSystemScanGone):
		return fullscan.Reading{}, fullscan.ErrGone
	case errors.Is(err, proxy.ErrSystemScanChanged):
		return fullscan.Reading{}, fullscan.ErrChanged
	case err != nil:
		return fullscan.Reading{}, err
	}
	// A gate pass follows a reading the ladder lets through; its request
	// records the findings document of every gate, this one's included. A
	// reading without one records its own findings.
	gatePass := opts.Gates && !(sl.Applicable && sl.Report != nil && !sl.Decision.Served())
	var res proxy.SystemEnforceResult
	if enforceable(sl) {
		if res, err = s.gw.EnforceLLMScan(ctx, proxy.SystemEnforceRequest{
			Backend: a.Upstream, Path: a.Path, Tenant: a.Tenant, Subject: fullscan.Subject,
			CacheKey: a.Key, Scan: sl, RecordFindings: !gatePass, Source: fullScanSource,
		}); err != nil {
			return fullscan.Reading{}, err
		}
	}
	r := fullScanReading(sl, res)
	if gatePass && !r.Refused && !r.Evicted && !(r.Kind == fullscan.ReadingUnscanned && r.Retryable) {
		if err := s.gatePass(ctx, a, &r); err != nil {
			return fullscan.Reading{}, err
		}
	}
	return r, nil
}

// fullScanUserAgent names the full scan's gate passes where a gate records
// the request.
const fullScanUserAgent = "pullthrough-full-scan"

// gatePass puts the cached object through every admission gate, fetching and
// serving nothing (SystemFetch with CacheOnly): a gate whose verdict the
// object predates — one enabled, or one whose rules changed, since it was
// cached — judges it now, with its own action. Nobody asked for the object,
// so a refusal opens no break-glass review.
func (s gatewayFullScanner) gatePass(ctx context.Context, a fullscan.Artifact, r *fullscan.Reading) error {
	req := proxy.SystemFetchRequest{
		Backend: a.Upstream, Path: a.Path, Accept: a.Accept, Tenant: a.Tenant, Subject: fullscan.Subject,
		Roles: s.roles, UserAgent: fullScanUserAgent, NoReview: true, CacheOnly: true,
	}
	res, err := s.gw.SystemFetch(ctx, req, io.Discard)
	switch {
	case err != nil:
		return err
	case res.Admitted:
		r.Gates = fullscan.GatesPassed
	case res.Gate != "":
		r.Gates, r.Gate = fullscan.GatesRefused, res.Gate
		if lk, lerr := s.gw.SystemLookup(ctx, req); lerr == nil && lk.Cacheable && !lk.Cached {
			r.Evicted = true
		}
	case res.Status == http.StatusNotFound:
		return fullscan.ErrGone
	default:
		return fmt.Errorf("the gate pass answered %d: %s", res.Status, res.Reason)
	}
	return nil
}

// enforceable reports a reading the action ladder acts on: a verdict, or an
// artifact the gate cannot examine because of what it is. A passing fault (a
// busy scanner, a provider outage) is retried, not enforced.
func enforceable(sl *proxy.SystemLLMScan) bool {
	if sl == nil || !sl.Applicable || sl.Report == nil {
		return false
	}
	u := sl.Report.Unscanned
	return u == nil || u.Content
}

// fullScanReading translates the gateway's reading of an object.
func fullScanReading(sl *proxy.SystemLLMScan, res proxy.SystemEnforceResult) fullscan.Reading {
	r := fullscan.Reading{}
	if sl == nil {
		return fullscan.Reading{Kind: fullscan.ReadingNotApplicable, Code: proxy.LLMNotPackage}
	}
	r.Digest, r.Size = sl.Digest, sl.Size
	if !sl.Applicable || sl.Report == nil {
		r.Kind, r.Code = fullscan.ReadingNotApplicable, sl.NotApplicable
		return r
	}
	rep := sl.Report
	// The coordinate the gate files the reading under: what the security
	// dossier is asked about.
	r.Ecosystem, r.Name, r.Version = rep.Artifact.Ecosystem, rep.Artifact.Name, rep.Artifact.Version
	r.Cost = rep.SpentUSD
	r.Refused, r.Action, r.Evicted, r.KeptPinned = res.Refused, res.Action, res.Evicted, res.KeptPinned
	if r.Action == "" {
		r.Action = sl.Decision.Action
	}
	if v := rep.Verdict; v != nil {
		r.Kind, r.Disposition, r.Fresh = fullscan.ReadingVerdict, string(rep.Disposition), !rep.Cached
		r.Signature, r.VerdictKey = llmpkgscan.SignatureOf(v).String(), v.Key
		return r
	}
	u := rep.Unscanned
	r.Kind, r.Code, r.Content = fullscan.ReadingUnscanned, u.Code, u.Content
	// A spent budget, an open breaker and a busy scanner last a while for a
	// pull, but a later attempt of a scan is worth making.
	r.Retryable = u.Transient || u.Code == llmpkgscan.CodeBudgetExhausted || u.Code == llmpkgscan.CodeProviderUnavailable || u.Code == llmpkgscan.CodeBusy
	return r
}

// fullScanObserver hands the full scan the gate's reading of each cached
// artifact a client pulls.
type fullScanObserver struct{ fs *fullscan.Service }

// newFullScanObserver returns the observer, or nil without a full scan (an
// untyped nil, so "no observer" is not a non-nil interface holding nil).
func newFullScanObserver(fs *fullscan.Service) proxy.LLMScanObserver {
	if fs == nil {
		return nil
	}
	return fullScanObserver{fs: fs}
}

func (o fullScanObserver) ObserveLLMScan(_ context.Context, obs proxy.LLMScanObservation) {
	if !o.fs.InScope(obs.Backend) || obs.Scan == nil {
		return
	}
	r := fullScanReading(obs.Scan, proxy.SystemEnforceResult{
		Refused: obs.Scan.Applicable && obs.Scan.Report != nil && !obs.Scan.Decision.Served(),
		Action:  obs.Scan.Decision.Action, Evicted: obs.Evicted,
	})
	if r.Digest == "" {
		r.Digest, r.Size = obs.Digest, obs.Size
	}
	o.fs.Note(fullscan.Note{
		Source: fullscan.SourceClient,
		Artifact: fullscan.Artifact{
			Upstream: obs.Backend, Path: obs.Path, Accept: obs.Accept, Tenant: obs.Tenant,
			Key: obs.CacheKey, Digest: obs.Digest, Size: obs.Size,
		},
		Reading: &r,
	})
}

// mirrorFullScan is the full scan as the full mirror's fetcher uses it: for an
// upstream in its scope the gate's refusals are deferred to it
// (DeferLLMRefusal), which applies the ladder, and every reading of a fetch —
// and every file the mirror finds in the cache — is noted.
type mirrorFullScan struct {
	fs *fullscan.Service
	gw *proxy.Gateway
}

// inScope reports whether the full scan covers an upstream's artifacts.
func (m mirrorFullScan) inScope(upstream string) bool { return m.fs.InScope(upstream) }

// fetched notes the reading of a mirrored file and applies the ladder to a
// refusal the gate deferred. It returns the fetch result the engine is to
// count: a refusal by llmpkgscan when the ladder refused a verdict, the fetch
// as it was otherwise.
func (m mirrorFullScan) fetched(ctx context.Context, req fullmirror.FetchRequest, tenant string, res proxy.SystemFetchResult) proxy.SystemFetchResult {
	sl := res.LLMScan
	if !m.inScope(req.Upstream) || sl == nil {
		return res
	}
	key, digest, size := res.CacheKey, res.Digest, res.Size
	if !res.Admitted {
		if !sl.Deferred {
			return res
		}
		// The gate's refusal was deferred, and then a later gate refused the
		// file too (the policy engine, the risk score: they never saw the
		// withheld reading), or the fetch broke off after the gates. The
		// ladder still applies to what the cache holds.
		lk, err := m.gw.SystemLookup(ctx, proxy.SystemFetchRequest{Backend: req.Upstream, Path: req.Path, Accept: req.Accept, Tenant: tenant})
		if err != nil || !lk.Cached {
			return res
		}
		key, digest, size = lk.CacheKey, lk.Digest, lk.Size
	}
	art := fullscan.Artifact{
		Upstream: req.Upstream, Path: req.Path, Accept: req.Accept, Tenant: tenant,
		Key: key, Digest: digest, Size: size,
	}
	var enf proxy.SystemEnforceResult
	if sl.Deferred && enforceable(sl) {
		var err error
		enf, err = m.gw.EnforceLLMScan(ctx, proxy.SystemEnforceRequest{
			Backend: req.Upstream, Path: req.Path, Tenant: tenant, Subject: fullmirror.Subject,
			CacheKey: key, Scan: sl, Source: fullScanSource,
		})
		if err != nil {
			slog.Default().Warn("full scan: applying the action ladder to a mirrored file", "upstream", req.Upstream, "path", req.Path, "error", err)
		}
	} else if sl.Applicable && sl.Report != nil {
		// The gate served it (and audited and alerted on a flag itself).
		enf = proxy.SystemEnforceResult{Action: sl.Decision.Action}
	}
	r := fullScanReading(sl, enf)
	r.Digest, r.Size = digest, size
	switch {
	case !enf.Refused && res.Admitted:
		// The fetch went through every gate; only the LLM gate's refusal was
		// deferred to the full scan, and it does not refuse.
		r.Gates = fullscan.GatesPassed
	case !res.Admitted && res.Gate != "":
		r.Gates, r.Gate = fullscan.GatesRefused, res.Gate
	}
	m.fs.Note(fullscan.Note{Source: fullscan.SourceMirror, Artifact: art, Reading: &r})
	if res.Admitted && enf.Refused && sl.Report != nil && sl.Report.Scanned() {
		// A verdict the ladder refuses: the mirror counts the file as refused
		// by the gate, as it would without the deferral. (A file a later gate
		// refused too is counted as that gate's refusal, as reported.)
		res.Status = http.StatusForbidden
		res.Gate = "llmpkgscan"
		res.Code = sl.Decision.Code
		res.Reason = sl.Decision.Reason
		res.Action = sl.Decision.Action
		res.Admitted = false
	}
	return res
}

// seen notes a file the mirror found in the cache.
func (m mirrorFullScan) seen(req fullmirror.FetchRequest, tenant string, res proxy.SystemLookupResult) {
	if !m.inScope(req.Upstream) || !res.Cached || res.CacheKey == "" {
		return
	}
	m.fs.Note(fullscan.Note{Source: fullscan.SourceSeen, Artifact: fullscan.Artifact{
		Upstream: req.Upstream, Path: req.Path, Accept: req.Accept, Tenant: tenant,
		Key: res.CacheKey, Digest: res.Digest, Size: res.Size,
	}})
}
