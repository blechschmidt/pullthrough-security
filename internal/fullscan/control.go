package fullscan

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/blechschmidt/pullthrough-security/internal/audit"
)

// control.json holds what operators asked for: pauses (of the whole full scan
// or of one upstream) and re-scan requests. Whichever replica receives a
// request writes it; the leader reads it and acts on it. It is small and is
// rewritten whole.

// controlFile is control.json.
type controlFile struct {
	Paused    bool                       `json:"paused,omitempty"`
	PausedBy  string                     `json:"pausedBy,omitempty"`
	PausedAt  time.Time                  `json:"pausedAt,omitzero"`
	Reason    string                     `json:"reason,omitempty"`
	Upstreams map[string]upstreamControl `json:"upstreams,omitempty"`
	// RescanSeq numbers the re-scan requests; Rescans are the latest of them
	// (at most maxRescanRequests).
	RescanSeq uint64          `json:"rescanSeq,omitempty"`
	Rescans   []RescanRequest `json:"rescans,omitempty"`
}

type upstreamControl struct {
	Paused   bool      `json:"paused,omitempty"`
	PausedBy string    `json:"pausedBy,omitempty"`
	PausedAt time.Time `json:"pausedAt,omitzero"`
	Reason   string    `json:"reason,omitempty"`
}

// RescanRequest asks for artifacts to be scanned again with a model call.
type RescanRequest struct {
	// Seq numbers the request (set when it is recorded).
	Seq uint64 `json:"seq,omitempty"`
	// Upstream limits it to one upstream ("" or "*": every one).
	Upstream string `json:"upstream,omitempty"`
	// Filter selects artifacts by their last reading: "all" (the default),
	// "malicious", "suspicious", "benign", "flagged" (malicious or
	// suspicious), "unscannable", "refused", "not-applicable" or "error".
	Filter string `json:"filter,omitempty"`
	// Path limits it to the artifact served under this path (with Upstream);
	// such a re-scan is queued ahead of the mirror and the backfill.
	Path string    `json:"path,omitempty"`
	By   string    `json:"by,omitempty"`
	At   time.Time `json:"at,omitzero"`
}

// Re-scan filters.
var rescanFilters = map[string]bool{
	"all": true, "malicious": true, "suspicious": true, "benign": true, "flagged": true,
	"unscannable": true, "refused": true, "not-applicable": true, "error": true,
}

// maxRescanRequests bounds the requests kept in control.json.
const maxRescanRequests = 50

// maxReasonLength bounds an operator's pause reason.
const maxReasonLength = 500

// ErrUnknownUpstream is returned for an upstream outside the full scan's
// scope.
var ErrUnknownUpstream = errors.New("fullscan: the upstream is not in the full scan's scope")

// ErrDisabled is returned when no full scan is configured.
var ErrDisabled = errors.New("fullscan: the full scan is not enabled")

// controlMu serializes this process's read-modify-write of control.json.
var controlMu sync.Mutex

func (s *Service) updateControl(edit func(*controlFile) error) error {
	controlMu.Lock()
	defer controlMu.Unlock()
	var c controlFile
	if err := readJSON(s.store.controlPath(), &c); err != nil && !errors.Is(err, errNoFile) {
		return err
	}
	if err := edit(&c); err != nil {
		return err
	}
	if err := writeJSON(s.store.controlPath(), c); err != nil {
		return err
	}
	s.mu.Lock()
	s.control, s.controlAt, s.controlOK = c, s.now(), true
	s.mu.Unlock()
	s.kick()
	return nil
}

// refreshControl re-reads control.json, at most every ControlRefresh unless
// force. An unreadable file keeps the last one read: it must not unpause the
// scan.
func (s *Service) refreshControl(force bool) controlFile {
	s.mu.Lock()
	fresh := s.controlOK && s.now().Sub(s.controlAt) < s.opts.ControlRefresh
	c := s.control
	s.mu.Unlock()
	if fresh && !force {
		return c
	}
	var nc controlFile
	if err := readJSON(s.store.controlPath(), &nc); err != nil && !errors.Is(err, errNoFile) {
		s.log.Warn("fullscan: reading the control file", "error", err)
		s.mu.Lock()
		ok := s.controlOK
		s.mu.Unlock()
		if !ok {
			// Nothing read yet: an operator's pause (an embargo on sending an
			// upstream's code to the provider) may be in the file. Hold until
			// it can be read.
			return controlFile{Paused: true, PausedBy: Subject, Reason: "control.json cannot be read (" + cleanMessage(err.Error()) + "); the full scan holds until it can"}
		}
		return c
	}
	s.mu.Lock()
	s.control, s.controlAt, s.controlOK = nc, s.now(), true
	s.mu.Unlock()
	return nc
}

func (s *Service) checkUpstream(upstream string) (string, bool, error) {
	upstream = strings.TrimSpace(upstream)
	if upstream == "" || upstream == "*" {
		return "", true, nil
	}
	if !s.inScope(upstream) {
		return "", false, fmt.Errorf("%w: %q", ErrUnknownUpstream, upstream)
	}
	return upstream, false, nil
}

// Pause stops the full scan of one upstream, or of every upstream when
// upstream is empty, until Resume. Scans in flight finish. The pause is
// persisted: it holds across restarts and on every replica.
func (s *Service) Pause(ctx context.Context, upstream, by, reason string) error {
	if !s.Enabled() {
		return ErrDisabled
	}
	reason = strings.TrimSpace(reason)
	if len(reason) > maxReasonLength {
		return fmt.Errorf("fullscan: the reason is longer than %d bytes", maxReasonLength)
	}
	reason = stripControl(reason)
	name, all, err := s.checkUpstream(upstream)
	if err != nil {
		return err
	}
	now := s.now().UTC()
	if err := s.updateControl(func(c *controlFile) error {
		if all {
			c.Paused, c.PausedBy, c.PausedAt, c.Reason = true, by, now, reason
			return nil
		}
		if c.Upstreams == nil {
			c.Upstreams = map[string]upstreamControl{}
		}
		c.Upstreams[name] = upstreamControl{Paused: true, PausedBy: by, PausedAt: now, Reason: reason}
		return nil
	}); err != nil {
		return err
	}
	s.audit(ctx, "paused", by, firstNonEmpty(name, "*"), map[string]any{"reason": reason})
	s.log.Info("full scan paused", "upstream", firstNonEmpty(name, "*"), "by", by, "reason", reason)
	return nil
}

// Resume lifts a pause: of one upstream, or — when upstream is empty — the
// global pause and every upstream's.
func (s *Service) Resume(ctx context.Context, upstream, by string) error {
	if !s.Enabled() {
		return ErrDisabled
	}
	name, all, err := s.checkUpstream(upstream)
	if err != nil {
		return err
	}
	if err := s.updateControl(func(c *controlFile) error {
		if all {
			c.Paused, c.PausedBy, c.PausedAt, c.Reason = false, "", time.Time{}, ""
			c.Upstreams = nil
			return nil
		}
		delete(c.Upstreams, name)
		return nil
	}); err != nil {
		return err
	}
	s.mu.Lock()
	if s.q != nil {
		s.q.unpark(name, s.now())
	}
	s.mu.Unlock()
	s.kick()
	s.audit(ctx, "resumed", by, firstNonEmpty(name, "*"), nil)
	s.log.Info("full scan resumed", "upstream", firstNonEmpty(name, "*"), "by", by)
	return nil
}

// Rescan asks for artifacts to be scanned again with a model call, even though
// their bytes have a verdict: of one upstream or every one, those whose last
// reading matches the filter, or the one artifact under a path. The request is
// persisted; the replica that leads acts on it.
func (s *Service) Rescan(ctx context.Context, req RescanRequest) (RescanRequest, error) {
	if !s.Enabled() {
		return RescanRequest{}, ErrDisabled
	}
	name, _, err := s.checkUpstream(req.Upstream)
	if err != nil {
		return RescanRequest{}, err
	}
	req.Upstream = name
	req.Filter = strings.ToLower(strings.TrimSpace(req.Filter))
	if req.Filter == "" {
		req.Filter = "all"
	}
	if !rescanFilters[req.Filter] {
		return RescanRequest{}, fmt.Errorf("fullscan: unknown re-scan filter %q (all, malicious, suspicious, benign, flagged, unscannable, refused, not-applicable, error)", req.Filter)
	}
	req.Path = strings.TrimSpace(req.Path)
	if req.Path != "" {
		if req.Upstream == "" {
			return RescanRequest{}, errors.New("fullscan: a re-scan by path names the upstream too")
		}
		if !strings.HasPrefix(req.Path, "/") || len(req.Path) > 2048 || strings.ContainsAny(req.Path, "\r\n\x00") {
			return RescanRequest{}, errors.New("fullscan: the path is the request path under the upstream's mount, starting with /")
		}
	}
	req.At = s.now().UTC()
	if err := s.updateControl(func(c *controlFile) error {
		c.RescanSeq++
		req.Seq = c.RescanSeq
		c.Rescans = append(c.Rescans, req)
		if n := len(c.Rescans); n > maxRescanRequests {
			c.Rescans = append([]RescanRequest(nil), c.Rescans[n-maxRescanRequests:]...)
		}
		return nil
	}); err != nil {
		return RescanRequest{}, err
	}
	s.audit(ctx, "rescan-requested", req.By, firstNonEmpty(req.Upstream, "*"), map[string]any{
		"request": req.Seq, "filter": req.Filter, "path": req.Path,
	})
	s.log.Info("full scan re-scan requested", "upstream", firstNonEmpty(req.Upstream, "*"), "filter", req.Filter, "path", req.Path, "by", req.By)
	return req, nil
}

// matches reports whether an item falls under a re-scan request.
func (r RescanRequest) matches(it *Item) bool {
	if it.Evicted {
		return false // nothing cached to scan
	}
	if r.Upstream != "" && it.Upstream != r.Upstream {
		return false
	}
	if r.Path != "" && it.Path != r.Path {
		return false
	}
	switch r.Filter {
	case "", "all":
		return true
	case "malicious", "suspicious", "benign":
		return it.State == StateScanned && it.Verdict == r.Filter
	case "flagged":
		return it.State == StateScanned && (it.Verdict == "malicious" || it.Verdict == "suspicious")
	case "unscannable":
		return it.State == StateUnscannable && it.Code != CodeProviderRefusal
	case "refused":
		return it.State == StateUnscannable && it.Code == CodeProviderRefusal
	case "not-applicable":
		return it.State == StateNotApplicable
	case "error":
		return it.State == StateError
	}
	return false
}

// paused reports whether the whole full scan is paused, and the detail.
func (c controlFile) pausedDetail() (bool, string) {
	if !c.Paused {
		return false, ""
	}
	d := "paused"
	if c.PausedBy != "" {
		d += " by " + c.PausedBy
	}
	if !c.PausedAt.IsZero() {
		d += " at " + c.PausedAt.UTC().Format(time.RFC3339)
	}
	if c.Reason != "" {
		d += ": " + c.Reason
	}
	return true, d
}

// audit records a full-scan event.
func (s *Service) audit(ctx context.Context, action, subject, upstream string, detail map[string]any) {
	if s.opts.Audit == nil {
		return
	}
	if subject == "" {
		subject = Subject
	}
	if detail == nil {
		detail = map[string]any{}
	}
	detail["action"] = action
	ev := audit.Event{
		Type:     audit.EventFullScan,
		Subject:  subject,
		Decision: audit.DecisionAllow,
		Reason:   "fullscan:" + action,
		Detail:   detail,
	}
	if upstream != "" && upstream != "*" {
		ev.Backend = upstream
	} else if upstream == "*" {
		detail["upstream"] = "*"
	}
	if err := s.opts.Audit.Log(context.WithoutCancel(ctx), ev); err != nil {
		s.log.Warn("fullscan: writing an audit event", "action", action, "error", err)
	}
}

func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

// maxMessage bounds a recorded error message.
const maxMessage = 300

// stripControl replaces control characters with spaces.
func stripControl(msg string) string {
	return strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return ' '
		}
		return r
	}, msg)
}

// cleanMessage prepares a message for the state file and the status: no
// control characters, bounded length.
func cleanMessage(msg string) string {
	msg = stripControl(msg)
	if len(msg) > maxMessage {
		cut := maxMessage
		for cut > 0 && msg[cut]&0xC0 == 0x80 {
			cut--
		}
		msg = msg[:cut] + "…"
	}
	return msg
}
