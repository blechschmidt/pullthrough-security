package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/pullthrough-security/internal/admin"
	"github.com/blechschmidt/pullthrough-security/internal/fullmirror"
)

// oneChangeFeed enumerates one package with one file.
type oneChangeFeed struct{}

func (oneChangeFeed) Bootstrap(context.Context, string) (fullmirror.Batch, error) {
	return fullmirror.Batch{Items: []fullmirror.Coordinate{{Name: "left-pad"}}, Next: "seq:7", Head: "seq:9", Lag: 2, LagKnown: true}, nil
}

func (oneChangeFeed) Changes(_ context.Context, cursor string) (fullmirror.Batch, error) {
	return fullmirror.Batch{Next: cursor}, nil
}

func (oneChangeFeed) Releases(context.Context, string) ([]fullmirror.Release, error) {
	return []fullmirror.Release{{Version: "1.3.0", Artifacts: []fullmirror.Artifact{{Path: "/left-pad/-/left-pad-1.3.0.tgz"}}}}, nil
}

// gateOnly refuses every file, as an admission gate would.
type gateOnly struct{}

func (gateOnly) Lookup(context.Context, fullmirror.FetchRequest) (fullmirror.LookupResult, error) {
	return fullmirror.LookupResult{Cacheable: true}, nil
}

func (gateOnly) Fetch(context.Context, fullmirror.FetchRequest, io.Writer) (fullmirror.FetchResult, error) {
	return fullmirror.FetchResult{Status: http.StatusForbidden, Gate: "malfeed", Code: "known_malicious"}, nil
}

func fullMirrorFixture(t *testing.T) []string {
	t.Helper()
	e, err := fullmirror.New(fullmirror.Options{
		Dir: t.TempDir(),
		Upstreams: []fullmirror.Upstream{{
			Settings: fullmirror.Settings{Upstream: "npm", Type: "npm", ByteBudget: 1 << 30, RequestsPerSecond: 1000, PollInterval: time.Hour},
			Feed:     oneChangeFeed{},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	e.Attach(gateOnly{})
	ctx, cancel := context.WithCancel(context.Background())
	e.Start(ctx)
	t.Cleanup(func() { cancel(); _ = e.Close() })
	deadline := time.Now().Add(5 * time.Second)
	for e.Status().Totals.Refused == 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	const token = "ptctl-fullmirror-test-token-0123456789"
	srv, err := admin.New(admin.Options{Cache: emptyCache{}, FullMirror: e, Token: token})
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	t.Setenv("PULLTHROUGH_STEPUP_TOKEN", "")
	return []string{"--url", ts.URL, "--token", token}
}

func TestPtctlFullMirror(t *testing.T) {
	g := fullMirrorFixture(t)
	out, err := runReposCmd(t, fullMirrorStatus, g...)
	if err != nil || !strings.Contains(out, "Full mirroring: 1 upstream(s)") || !strings.Contains(out, "npm") || !strings.Contains(out, "following") {
		t.Fatalf("status: %v\n%s", err, out)
	}
	if !strings.Contains(out, "Total: 0 fetched (0 B), 1 refused") || !strings.Contains(out, "DEFERRED") {
		t.Errorf("totals line missing: %s", out)
	}
	out, err = runReposCmd(t, fullMirrorStatus, append([]string{"--upstream", "npm"}, g...)...)
	if err != nil || !strings.Contains(out, "Files refused  1 (malfeed 1)") || !strings.Contains(out, "Cursor") || !strings.Contains(out, "seq:7") || !strings.Contains(out, "2 change(s)") {
		t.Fatalf("status --upstream: %v\n%s", err, out)
	}
	out, err = runReposCmd(t, fullMirrorStatus, append([]string{"--json"}, g...)...)
	var st fullmirror.Status
	if err != nil || json.Unmarshal([]byte(out), &st) != nil || st.Totals.Refused != 1 || st.Upstreams[0].Counters.RefusedBy["malfeed"] != 1 {
		t.Fatalf("status --json: %v\n%s", err, out)
	}
	if _, err := runReposCmd(t, fullMirrorStatus, append([]string{"--upstream", "pypi"}, g...)...); err == nil || !strings.Contains(err.Error(), "404") {
		t.Errorf("unknown upstream: %v", err)
	}

	out, err = runReposCmd(t, fullMirrorPause, append([]string{"--upstream", "npm", "--reason", "registry incident"}, g...)...)
	if err != nil || !strings.Contains(out, "paused: npm") {
		t.Fatalf("pause: %v %s", err, out)
	}
	out, _ = runReposCmd(t, fullMirrorStatus, append([]string{"--upstream", "npm"}, g...)...)
	if !strings.Contains(out, "Paused") || !strings.Contains(out, "registry incident") {
		t.Errorf("the pause is not shown: %s", out)
	}
	if out, err := runReposCmd(t, fullMirrorResume, g...); err != nil || !strings.Contains(out, "every upstream") {
		t.Fatalf("resume: %v %s", err, out)
	}
	if _, err := runReposCmd(t, fullMirrorResync, g...); err == nil {
		t.Error("a resync without --upstream was sent")
	}
	if out, err := runReposCmd(t, fullMirrorResync, append([]string{"--upstream", "npm"}, g...)...); err != nil || !strings.Contains(out, "resync requested: npm") {
		t.Fatalf("resync: %v %s", err, out)
	}
	if _, err := runReposCmd(t, fullMirrorPause, append([]string{"npm"}, g...)...); err == nil {
		t.Error("a positional upstream was accepted")
	}
}

func TestPtctlFullMirrorDisabledAndStepUp(t *testing.T) {
	const token = "ptctl-fullmirror-test-token-0123456789"
	srv, err := admin.New(admin.Options{Cache: emptyCache{}, Token: token})
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()
	out, err := runReposCmd(t, fullMirrorStatus, "--url", ts.URL, "--token", token)
	if err != nil || !strings.Contains(out, "not enabled") {
		t.Fatalf("disabled: %v %s", err, out)
	}

	// A proxy that wants a step-up says so; ptctl explains, and sends the
	// token it is given.
	var gotToken string
	stepUp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotToken = r.Header.Get("X-StepUp-Token")
		if gotToken == "" {
			w.Header().Set("X-StepUp-Required", "webauthn")
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = io.WriteString(w, `{"error":"this action requires a fresh passkey step-up assertion"}`)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{}`)
	}))
	defer stepUp.Close()
	_, err = runReposCmd(t, fullMirrorPause, "--url", stepUp.URL, "--token", token)
	var ae *apiError
	if !errors.As(err, &ae) || !ae.StepUp || !strings.Contains(err.Error(), "--stepup-token") {
		t.Fatalf("step-up refusal: %v", err)
	}
	if _, err := runReposCmd(t, fullMirrorPause, "--url", stepUp.URL, "--token", token, "--stepup-token", "fresh"); err != nil || gotToken != "fresh" {
		t.Fatalf("with a token: %v (sent %q)", err, gotToken)
	}
}
