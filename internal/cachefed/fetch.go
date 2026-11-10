package cachefed

import (
	"context"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/blechschmidt/pullthrough-security/internal/cache"
)

// Result is a peer cache hit returned to the gateway's cache-fill path. Content
// is a digest-verifying stream: reading it to EOF confirms the bytes match the
// expected digest, and a mismatch surfaces as ErrDigestMismatch (aborting the
// fill). The caller must Close Content.
type Result struct {
	// Content is the verified peer body. The caller streams it into the local
	// cache exactly as it would an upstream fetch.
	Content io.ReadCloser
	// Size is the content length advertised by the peer, or -1 when unknown.
	Size int64
	// Digest is the content digest the bytes are verified against.
	Digest string
	// ContentType is the artifact media type, when the peer reported one.
	ContentType string
	// Origin is the upstream URL/coordinate the serving peer originally fetched
	// from, when known.
	Origin string
	// Peer is the name of the peer that served the hit.
	Peer string
}

// Metadata projects the peer-supplied attributes onto the cache metadata map the
// gateway persists for a federated fill, so a cross-peer hit is recorded with
// the same origin/content-type bookkeeping as a direct upstream fetch.
func (r *Result) Metadata() map[string]string {
	meta := make(map[string]string, 3)
	if r.Origin != "" {
		meta[cache.MetaOrigin] = r.Origin
	}
	if r.ContentType != "" {
		meta[cache.MetaContentType] = r.ContentType
	}
	return meta
}

// Fetch attempts to satisfy a local cache miss for key from a sibling peer. The
// expectDigest, when non-empty, is the authoritative digest every peer response
// is re-verified against; when empty it is derived from a content-addressed key.
// Under RequireDigest (the default) a miss with no verifiable digest is not
// offered to peers at all (ErrNoDigest), guaranteeing peer bytes are never
// trusted blindly.
//
// It queries up to MaxPeerFanout healthy peers with per-peer header deadlines
// and optional hedging, returns the first verified 200 response's body, and
// cancels the losing in-flight requests. Transport errors, non-200 statuses, and
// verification failures all penalize the responsible peer's circuit breaker. It
// returns ErrNoPeer when no peer could serve the key.
func (f *Federation) Fetch(ctx context.Context, key, expectDigest string) (*Result, error) {
	if !f.Enabled() {
		return nil, ErrDisabled
	}

	expect := expectDigest
	if expect == "" && looksLikeDigest(key) {
		expect = key
	}
	// A locally-known digest (from the caller or a content-addressed key) is the
	// authoritative fixity baseline and defends against a malicious peer. When it
	// is absent and RequireDigest is set (the default), the miss is not offered to
	// peers at all. When RequireDigest is disabled, the fetch falls back to the
	// peer-advertised digest at receipt time — still always re-verified, but that
	// mode only defends against transit corruption, not a lying peer.
	localDigestKnown := looksLikeDigest(expect)
	if !localDigestKnown && f.cfg.RequireDigest {
		f.metrics.recordSkippedNoDigest()
		return nil, ErrNoDigest
	}

	candidates := f.selectCandidates()
	if len(candidates) == 0 {
		f.metrics.recordMiss()
		return nil, ErrNoPeer
	}

	// Each request runs under its own context derived from the caller's ctx (not
	// from a shared fan-out context) so the winning stream survives after the
	// losing requests are cancelled. hedgeStop releases any staggered candidate
	// that has not yet launched once a winner is chosen.
	var hedgeOnce sync.Once
	hedgeStop := make(chan struct{})
	stopHedge := func() { hedgeOnce.Do(func() { close(hedgeStop) }) }

	outCh := make(chan fetchOutcome, len(candidates))
	for i, p := range candidates {
		go f.attempt(ctx, i, p, key, hedgeStop, outCh)
	}

	received := 0
	for received < len(candidates) {
		var o fetchOutcome
		select {
		case <-ctx.Done():
			stopHedge()
			go f.drain(outCh, len(candidates)-received)
			return nil, ctx.Err()
		case o = <-outCh:
		}
		received++
		if o.resp == nil {
			// Failure, skip, or hedge-abort: already accounted for in attempt.
			continue
		}
		// First 200 wins. Release any not-yet-launched hedged candidates and drain
		// the rest in the background so the winner returns without waiting on them.
		stopHedge()
		if rem := len(candidates) - received; rem > 0 {
			go f.drain(outCh, rem)
		}
		return f.serveWinner(&o, expect, localDigestKnown, key)
	}

	f.metrics.recordMiss()
	return nil, ErrNoPeer
}

// attempt performs one peer read-through attempt and reports its outcome on ch.
// It honors the hedge stagger (for i>0) and a per-peer time-to-headers deadline,
// and records the peer's circuit-breaker outcome for a failure here; a 200 defers
// its success/failure accounting to the digest verifier that reads the body.
func (f *Federation) attempt(ctx context.Context, i int, p *peerState, key string, hedgeStop <-chan struct{}, ch chan<- fetchOutcome) {
	if f.cfg.HedgeDelay > 0 && i > 0 {
		timer := time.NewTimer(time.Duration(i) * f.cfg.HedgeDelay)
		select {
		case <-hedgeStop:
			timer.Stop()
			ch <- fetchOutcome{peer: p}
			return
		case <-ctx.Done():
			timer.Stop()
			ch <- fetchOutcome{peer: p}
			return
		case <-timer.C:
		}
	}

	allowed, isProbe := p.breaker.allow()
	if !allowed {
		ch <- fetchOutcome{peer: p}
		return
	}

	reqCtx, reqCancel := context.WithCancel(ctx)
	// Time-to-headers deadline: cancel the request if the peer has not produced
	// response headers within PeerTimeout. It is stopped once headers arrive so a
	// large body stream is bounded only by the caller's ctx, not PeerTimeout.
	ttfb := time.AfterFunc(f.cfg.PeerTimeout, reqCancel)
	start := f.now()
	resp, err := f.peerGet(reqCtx, p, key)
	ttfb.Stop()
	if err != nil {
		reqCancel()
		p.breaker.failure(isProbe, f.now().Sub(start).Seconds(), err.Error())
		f.metrics.recordPeerError()
		ch <- fetchOutcome{peer: p, probe: isProbe, err: err}
		return
	}
	ch <- fetchOutcome{peer: p, resp: resp, cancel: reqCancel, probe: isProbe, start: start}
}

// serveWinner wraps the winning peer response in a digest-verifying stream and
// builds the Result. The verifier records the peer's circuit-breaker outcome and
// the hit/verify metrics when the stream ends, and releases the request context
// on Close.
func (f *Federation) serveWinner(o *fetchOutcome, expect string, localDigestKnown bool, key string) (*Result, error) {
	wp := o.peer
	isProbe := o.probe
	body := o.resp.Body
	verifyDigest := expect
	if !localDigestKnown {
		// RequireDigest disabled: verify against the digest the peer computed over
		// its stored bytes. This is still a full re-verification of the stream.
		verifyDigest = o.resp.Header.Get(headerDigest)
	}
	verifier, ok := newDigestVerifier(body, verifyDigest, func(verified bool) {
		if verified {
			wp.breaker.success(isProbe, f.now().Sub(o.start).Seconds())
		} else {
			wp.breaker.failure(isProbe, f.now().Sub(o.start).Seconds(), "digest mismatch")
			f.metrics.recordVerifyFailure()
		}
	}, o.cancel)
	if !ok {
		// The peer advertised no usable digest and we hold none locally: we cannot
		// re-verify, so fail safe and never hand back unverifiable bytes.
		_, _ = io.Copy(io.Discard, io.LimitReader(body, 4<<10))
		_ = body.Close()
		o.cancel()
		wp.breaker.cancel(isProbe)
		f.metrics.recordSkippedNoDigest()
		return nil, ErrNoDigest
	}

	f.metrics.recordHit()
	f.logger.Debug("cache federation hit", "peer", wp.peer.Name, "key", key, "digest", verifyDigest)
	return &Result{
		Content:     verifier,
		Size:        o.resp.ContentLength,
		Digest:      verifyDigest,
		ContentType: firstNonEmpty(o.resp.Header.Get(headerContentType), o.resp.Header.Get("Content-Type")),
		Origin:      o.resp.Header.Get(headerOrigin),
		Peer:        wp.peer.Name,
	}, nil
}

// drain consumes up to n late outcomes after a winner was chosen (or the caller
// gave up), releasing each runner-up 200 without penalizing its breaker so a peer
// that merely lost the race is not counted as a failure. It keeps the attempt
// goroutines from blocking on the buffered channel.
func (f *Federation) drain(ch <-chan fetchOutcome, n int) {
	for i := 0; i < n; i++ {
		o := <-ch
		if o.resp != nil {
			if o.cancel != nil {
				o.cancel()
			}
			o.peer.breaker.cancel(o.probe)
			_, _ = io.Copy(io.Discard, io.LimitReader(o.resp.Body, 4<<10))
			_ = o.resp.Body.Close()
		}
	}
}

// fetchOutcome is one peer attempt's result on the read-through fan-out channel.
type fetchOutcome struct {
	peer   *peerState
	resp   *http.Response
	cancel context.CancelFunc
	probe  bool
	start  time.Time
	err    error
}

func firstNonEmpty(vs ...string) string {
	for _, v := range vs {
		if v != "" {
			return v
		}
	}
	return ""
}
