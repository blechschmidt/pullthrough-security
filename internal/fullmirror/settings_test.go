package fullmirror

import (
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"
)

func discardLogger() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func TestParseWindow(t *testing.T) {
	w, err := ParseWindow("", "", "")
	if err != nil || !w.Always() || w.String() != "always" {
		t.Fatalf("empty window: %v %v %q", w, err, w.String())
	}
	if !w.Contains(time.Now()) {
		t.Error("the empty window is closed")
	}
	w, err = ParseWindow("22:00", "06:30", "Europe/Berlin")
	if err != nil {
		t.Fatal(err)
	}
	berlin, _ := time.LoadLocation("Europe/Berlin")
	for _, tc := range []struct {
		hh, mm int
		in     bool
	}{{21, 59, false}, {22, 0, true}, {23, 30, true}, {0, 0, true}, {6, 29, true}, {6, 30, false}, {12, 0, false}} {
		at := time.Date(2026, 11, 16, tc.hh, tc.mm, 0, 0, berlin)
		if got := w.Contains(at); got != tc.in {
			t.Errorf("%02d:%02d in window = %v, want %v", tc.hh, tc.mm, got, tc.in)
		}
	}
	noon := time.Date(2026, 11, 16, 12, 0, 0, 0, berlin)
	if open := w.NextOpen(noon); !open.Equal(time.Date(2026, 11, 16, 22, 0, 0, 0, berlin)) {
		t.Errorf("next open after noon: %s", open)
	}
	if open := w.NextOpen(time.Date(2026, 11, 16, 23, 0, 0, 0, berlin)); !open.Equal(time.Date(2026, 11, 16, 23, 0, 0, 0, berlin)) {
		t.Errorf("next open inside the window: %s", open)
	}
	day, _ := ParseWindow("09:00", "17:00", "")
	if open := day.NextOpen(time.Date(2026, 11, 16, 18, 0, 0, 0, time.UTC)); !open.Equal(time.Date(2026, 11, 17, 9, 0, 0, 0, time.UTC)) {
		t.Errorf("next open after the window: %s", open)
	}
	if got := w.String(); got != "22:00-06:30 Europe/Berlin" {
		t.Errorf("String() = %q", got)
	}
	for _, bad := range [][3]string{
		{"22:00", "", ""}, {"", "06:00", ""}, {"24:00", "06:00", ""}, {"7:00", "08:00", ""},
		{"07:60", "08:00", ""}, {"07:00", "07:00", ""}, {"07:00", "08:00", "Mars/Olympus"}, {"", "", "UTC"},
	} {
		if _, err := ParseWindow(bad[0], bad[1], bad[2]); err == nil {
			t.Errorf("ParseWindow(%q, %q, %q) accepted", bad[0], bad[1], bad[2])
		}
	}
}

func TestCompilePatternsAnchorsTheWholeName(t *testing.T) {
	res, err := CompilePatterns([]string{"lodash", "@acme/.*", "left-pad|right-pad"})
	if err != nil {
		t.Fatal(err)
	}
	s := Settings{Include: res}
	for name, want := range map[string]bool{
		"lodash": true, "lodash-evil": false, "evil-lodash": false, "@acme/core": true, "@acme": false,
		"left-pad": true, "right-pad": true, "left-pad2": false,
	} {
		if got := s.Wants(name); got != want {
			t.Errorf("Wants(%q) = %v, want %v", name, got, want)
		}
	}
	if s.Exclude, err = CompilePatterns([]string{"@acme/internal-.*"}); err != nil {
		t.Fatal(err)
	}
	if s.Wants("@acme/internal-tools") || !s.Wants("@acme/tools") {
		t.Error("exclude patterns not applied")
	}
	if all := (Settings{}); !all.Wants("anything") {
		t.Error("no include pattern must mean every package")
	}
	for _, bad := range []string{"", "(", "a{2,100000}", strings.Repeat("a", maxPatternLength+1), `\C`} {
		if _, err := CompilePatterns([]string{bad}); err == nil {
			t.Errorf("CompilePatterns(%q) accepted", bad)
		}
	}
}

func TestParseVersionPolicy(t *testing.T) {
	for _, tc := range []struct {
		versions string
		latest   int
		want     int
		ok       bool
	}{
		{"", 0, 0, true}, {"all", 0, 0, true}, {"ALL", 0, 0, true}, {"latest", 3, 3, true},
		{"latest", 0, 0, false}, {"all", 2, 0, false}, {"newest", 1, 0, false}, {"latest", -1, 0, false},
	} {
		got, err := ParseVersionPolicy(tc.versions, tc.latest)
		if (err == nil) != tc.ok || got != tc.want {
			t.Errorf("ParseVersionPolicy(%q, %d) = %d, %v", tc.versions, tc.latest, got, err)
		}
	}
	if got := (Settings{Latest: 3}).VersionPolicy(); got != "latest 3" {
		t.Errorf("VersionPolicy = %q", got)
	}
}

func TestSettingsDefaults(t *testing.T) {
	s := Settings{}.withDefaults()
	if s.Concurrency != DefaultConcurrency || s.RequestsPerSecond != DefaultRequestsPerSecond || s.PollInterval != DefaultPollInterval {
		t.Errorf("defaults %+v", s)
	}
	if got := (Settings{Concurrency: 1000}).withDefaults().Concurrency; got != MaxConcurrency {
		t.Errorf("concurrency capped at %d", got)
	}
}

func TestCleanMessageRemovesCredentials(t *testing.T) {
	got := cleanMessage("GET https://user:s3cret@registry.example.com/x failed\n" + strings.Repeat("é", 400))
	if strings.Contains(got, "s3cret") || strings.Contains(got, "\n") || len(got) > maxErrorMessage+len("…") {
		t.Errorf("cleanMessage = %q", got)
	}
	if !strings.Contains(got, "https://***@registry.example.com") {
		t.Errorf("the URL was mangled: %q", got)
	}
}

func TestRetryHelpers(t *testing.T) {
	if Permanent(nil) != nil || RetryAfter(nil, time.Second) != nil {
		t.Error("nil errors must stay nil")
	}
	err := RetryAfter(Permanent(io.EOF), 3*time.Second)
	if !IsPermanent(err) {
		t.Error("Permanent lost under RetryAfter")
	}
	if d, ok := RetryAfterOf(err); !ok || d != 3*time.Second {
		t.Errorf("RetryAfterOf = %s %v", d, ok)
	}
	if got := backoff(time.Second, 10*time.Second, 1); got != time.Second {
		t.Errorf("backoff 1 = %s", got)
	}
	if got := backoff(time.Second, 10*time.Second, 3); got != 4*time.Second {
		t.Errorf("backoff 3 = %s", got)
	}
	if got := backoff(time.Second, 10*time.Second, 50); got != 10*time.Second {
		t.Errorf("backoff 50 = %s", got)
	}
}
