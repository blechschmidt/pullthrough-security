package downloadlog

import (
	"fmt"
	"net/http"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode/utf8"
	"unsafe"
)

// clock is a settable time source.
type clock struct {
	mu  sync.Mutex
	now time.Time
}

func newClock() *clock {
	return &clock{now: time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)}
}

func (c *clock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *clock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

// newLog builds an enabled in-memory log on a fake clock.
func newLog(t *testing.T, cfg Config) (*Log, *clock) {
	t.Helper()
	c := newClock()
	cfg.Enabled = true
	if cfg.Now == nil {
		cfg.Now = c.Now
	}
	l, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { _ = l.Close() })
	return l, c
}

// entry returns a served package download with the given address and package.
func entry(ip, ecosystem, pkg, version string) Entry {
	return Entry{
		ClientIP:  ip,
		Ecosystem: ecosystem,
		Upstream:  ecosystem,
		Package:   pkg,
		Version:   version,
		Kind:      KindPackage,
		Method:    http.MethodGet,
		Path:      "/v1/" + ecosystem + "/" + pkg + "/" + version,
		Status:    http.StatusOK,
		Outcome:   OutcomeServed,
		Bytes:     100,
	}
}

func mustQuery(t *testing.T, l *Log, q Query) Result {
	t.Helper()
	res, err := l.Query(q)
	if err != nil {
		t.Fatalf("Query(%+v): %v", q, err)
	}
	return res
}

func ids(entries []Entry) []uint64 {
	out := make([]uint64, len(entries))
	for i, e := range entries {
		out[i] = e.ID
	}
	return out
}

func TestNilAndDisabledLogsAreNoOps(t *testing.T) {
	disabled, err := New(Config{Enabled: false, Path: t.TempDir() + "/never-created.jsonl"})
	if err != nil {
		t.Fatal(err)
	}
	for name, l := range map[string]*Log{"nil": nil, "disabled": disabled} {
		t.Run(name, func(t *testing.T) {
			if l.Enabled() {
				t.Fatal("Enabled() = true")
			}
			if l.Wants(KindPackage, OutcomeServed) {
				t.Fatal("Wants(package, served) = true")
			}
			l.Record(entry("10.0.0.1", "cargo", "cfg-if", "1.0.0"))
			res, err := l.Query(Query{})
			if err != nil || res.Total != 0 || res.Entries == nil || len(res.Entries) != 0 {
				t.Fatalf("Query = %+v, %v; want an empty, non-nil page", res, err)
			}
			sum, err := l.Summarize(Query{}, 0)
			if err != nil || sum.Total != 0 || sum.ByClient == nil || sum.ByPackage == nil || sum.ByEcosystem == nil {
				t.Fatalf("Summarize = %+v, %v; want empty, non-nil lists", sum, err)
			}
			if st := l.Stats(); st.Enabled || st.Retained != 0 || st.ByOutcome == nil {
				t.Fatalf("Stats = %+v", st)
			}
			if err := l.Flush(); err != nil {
				t.Fatalf("Flush: %v", err)
			}
			if err := l.Close(); err != nil {
				t.Fatalf("Close: %v", err)
			}
		})
	}
}

func TestRecordAssignsIDsAndReturnsNewestFirst(t *testing.T) {
	l, c := newLog(t, Config{})
	for i := 1; i <= 5; i++ {
		l.Record(entry("10.0.0.1", "cargo", fmt.Sprintf("crate-%d", i), "1.0.0"))
		c.Advance(time.Second)
	}
	res := mustQuery(t, l, Query{})
	if res.Total != 5 || len(res.Entries) != 5 {
		t.Fatalf("got %d/%d entries, want 5/5", len(res.Entries), res.Total)
	}
	for i, e := range res.Entries {
		wantID := uint64(5 - i)
		if e.ID != wantID {
			t.Fatalf("entry %d has ID %d, want %d (newest first)", i, e.ID, wantID)
		}
		if e.Package != fmt.Sprintf("crate-%d", wantID) {
			t.Fatalf("entry %d is %q", i, e.Package)
		}
		if e.Time.IsZero() || e.Time.Location() != time.UTC {
			t.Fatalf("entry %d has time %v, want a UTC time", i, e.Time)
		}
	}
	if !res.Entries[0].Time.After(res.Entries[4].Time) {
		t.Fatal("the newest entry does not carry the latest time")
	}
	if res.NextBefore != 0 {
		t.Fatalf("NextBefore = %d on a complete page", res.NextBefore)
	}
}

// The capacity is exact, also across the log's internal chunk boundaries, and
// what is dropped is always the oldest.
func TestCapacityEvictsOldest(t *testing.T) {
	for _, tc := range []struct{ capacity, record int }{
		{1, 3},
		{3, 5},
		{chunkSize - 1, chunkSize + 7},
		{chunkSize, 3 * chunkSize},
		{chunkSize + 1, 4*chunkSize + 3},
		{2*chunkSize + 17, 7 * chunkSize},
	} {
		t.Run(fmt.Sprintf("cap%d_rec%d", tc.capacity, tc.record), func(t *testing.T) {
			l, _ := newLog(t, Config{MaxEntries: tc.capacity})
			for i := 1; i <= tc.record; i++ {
				l.Record(entry("10.0.0.1", "go", fmt.Sprintf("example.com/m%d", i), "v1.0.0"))
			}
			res := mustQuery(t, l, Query{Limit: -1})
			if res.Total != tc.capacity || len(res.Entries) != tc.capacity {
				t.Fatalf("retained %d (total %d), want %d", len(res.Entries), res.Total, tc.capacity)
			}
			for i, e := range res.Entries {
				want := uint64(tc.record - i)
				if e.ID != want || e.Package != fmt.Sprintf("example.com/m%d", want) {
					t.Fatalf("entry %d = ID %d %q, want ID %d", i, e.ID, e.Package, want)
				}
			}
			st := l.Stats()
			if st.Retained != tc.capacity || st.Capacity != tc.capacity {
				t.Fatalf("Stats retained/capacity = %d/%d, want %d", st.Retained, st.Capacity, tc.capacity)
			}
			if want := uint64(tc.record - tc.capacity); st.Evicted != want {
				t.Fatalf("Evicted = %d, want %d", st.Evicted, want)
			}
			if st.Recorded != uint64(tc.record) {
				t.Fatalf("Recorded = %d, want %d", st.Recorded, tc.record)
			}
			// The log holds memory for what it retains, not for what passed through.
			if maxChunks := tc.capacity/chunkSize + 2; len(l.cur.chunks) > maxChunks {
				t.Fatalf("%d chunks held for a capacity of %d (want at most %d)", len(l.cur.chunks), tc.capacity, maxChunks)
			}
		})
	}
}

func TestRetentionExpiresOldEntries(t *testing.T) {
	l, c := newLog(t, Config{Retention: time.Hour})
	l.Record(entry("10.0.0.1", "cargo", "old", "1.0.0"))
	c.Advance(30 * time.Minute)
	l.Record(entry("10.0.0.1", "cargo", "mid", "1.0.0"))
	c.Advance(29 * time.Minute)
	l.Record(entry("10.0.0.1", "cargo", "new", "1.0.0"))

	if got := mustQuery(t, l, Query{}).Total; got != 3 {
		t.Fatalf("before expiry: %d entries, want 3", got)
	}

	// 61 minutes after "old": it is past the retention, the others are not.
	c.Advance(2 * time.Minute)
	res := mustQuery(t, l, Query{})
	if res.Total != 2 || res.Entries[0].Package != "new" || res.Entries[1].Package != "mid" {
		t.Fatalf("after 61m: %+v, want [new mid]", ids(res.Entries))
	}
	if st := l.Stats(); st.Expired != 1 || st.Retained != 2 {
		t.Fatalf("Stats = expired %d retained %d, want 1 / 2", st.Expired, st.Retained)
	}

	// Expiry needs no traffic: a query alone must not return an expired entry.
	c.Advance(2 * time.Hour)
	if got := mustQuery(t, l, Query{}).Total; got != 0 {
		t.Fatalf("after everything expired: %d entries, want 0", got)
	}
	st := l.Stats()
	if st.Expired != 3 || st.Retained != 0 || st.Oldest != nil || st.Newest != nil {
		t.Fatalf("Stats = %+v", st)
	}
	// And the log keeps working afterwards.
	l.Record(entry("10.0.0.2", "cargo", "again", "1.0.0"))
	if res := mustQuery(t, l, Query{}); res.Total != 1 || res.Entries[0].ID != 4 {
		t.Fatalf("after re-recording: %+v", res)
	}
}

func TestNegativeRetentionDisablesExpiry(t *testing.T) {
	l, c := newLog(t, Config{Retention: -1})
	l.Record(entry("10.0.0.1", "cargo", "ancient", "1.0.0"))
	c.Advance(100 * 365 * 24 * time.Hour)
	if got := mustQuery(t, l, Query{}).Total; got != 1 {
		t.Fatalf("%d entries, want 1: a negative retention keeps entries until the capacity evicts them", got)
	}
	if st := l.Stats(); st.RetentionSeconds != 0 {
		t.Fatalf("RetentionSeconds = %d, want 0 (no time limit)", st.RetentionSeconds)
	}
}

func TestDefaults(t *testing.T) {
	l, _ := newLog(t, Config{})
	st := l.Stats()
	if st.Capacity != DefaultMaxEntries {
		t.Errorf("default capacity = %d, want %d", st.Capacity, DefaultMaxEntries)
	}
	if want := int64(DefaultRetention / time.Second); st.RetentionSeconds != want {
		t.Errorf("default retention = %ds, want %ds", st.RetentionSeconds, want)
	}
	if st.Persistent || st.IncludeMetadata {
		t.Errorf("a default log is in-memory and records packages only: %+v", st)
	}
	huge, _ := newLog(t, Config{MaxEntries: MaxMaxEntries * 4})
	if got := huge.Stats().Capacity; got != MaxMaxEntries {
		t.Errorf("capacity above the maximum = %d, want it capped at %d", got, MaxMaxEntries)
	}
}

func TestMetadataIsRecordedOnlyOnRequest(t *testing.T) {
	meta := entry("10.0.0.1", "go", "rsc.io/quote", "")
	meta.Kind = KindMetadata

	l, _ := newLog(t, Config{})
	if l.Wants(KindMetadata, OutcomeServed) {
		t.Fatal("Wants(metadata, served) = true by default")
	}
	if !l.Wants(KindPackage, OutcomeServed) || !l.Wants(KindUnclassified, OutcomeServed) {
		t.Fatal("packages and unclassified resources must be recorded by default")
	}
	l.Record(meta)
	if got := mustQuery(t, l, Query{}).Total; got != 0 {
		t.Fatalf("a metadata request was recorded by default (%d entries)", got)
	}
	if st := l.Stats(); st.Recorded != 0 {
		t.Fatalf("Recorded = %d for a dropped entry", st.Recorded)
	}

	with, _ := newLog(t, Config{IncludeMetadata: true})
	with.Record(meta)
	res := mustQuery(t, with, Query{})
	if res.Total != 1 || res.Entries[0].Kind != KindMetadata {
		t.Fatalf("with IncludeMetadata: %+v", res)
	}
}

// A refused metadata request is kept even when metadata is not recorded: for a
// client that asks for a version's metadata first, it is the only trace of the
// attempt to obtain a blocked package.
func TestRefusedMetadataRequestIsAlwaysRecorded(t *testing.T) {
	l, _ := newLog(t, Config{})
	if !l.Wants(KindMetadata, OutcomeBlocked) {
		t.Fatal("Wants(metadata, blocked) = false")
	}
	for _, o := range []Outcome{OutcomeServed, OutcomeNotModified, OutcomeNotFound, OutcomeError} {
		if l.Wants(KindMetadata, o) {
			t.Fatalf("Wants(metadata, %s) = true by default", o)
		}
	}

	refused := entry("10.0.0.9", "go", "github.com/pkg/errors", "v0.9.1")
	refused.Kind, refused.Artifact = KindMetadata, "v0.9.1.info"
	refused.Outcome, refused.Status, refused.Gate = OutcomeBlocked, 403, "policy"
	l.Record(refused)

	// The outcome that decides is the one that is stored: a metadata entry with
	// an unknown outcome and a 404 status is a not-found, and stays out.
	odd := entry("10.0.0.9", "go", "example.com/missing", "v1.0.0")
	odd.Kind, odd.Outcome, odd.Status = KindMetadata, "nonsense", 404
	l.Record(odd)

	res := mustQuery(t, l, Query{})
	if res.Total != 1 {
		t.Fatalf("%d entries, want only the refused request", res.Total)
	}
	got := res.Entries[0]
	if got.Kind != KindMetadata || got.Outcome != OutcomeBlocked || got.Package != "github.com/pkg/errors" || got.Gate != "policy" {
		t.Fatalf("entry = %+v", got)
	}

	var disabled *Log
	if disabled.Wants(KindPackage, OutcomeServed) || disabled.Wants(KindMetadata, OutcomeBlocked) {
		t.Fatal("a nil log wants entries")
	}
}

func TestClassify(t *testing.T) {
	tests := []struct {
		status  int
		blocked bool
		want    Outcome
	}{
		{200, false, OutcomeServed},
		{206, false, OutcomeServed},
		{304, false, OutcomeNotModified},
		{404, false, OutcomeNotFound},
		{410, false, OutcomeNotFound},
		{403, false, OutcomeError}, // an upstream's own 403 is not a gate block
		{429, false, OutcomeError},
		{500, false, OutcomeError},
		{502, false, OutcomeError},
		{0, false, OutcomeError},
		{403, true, OutcomeBlocked},
		{429, true, OutcomeBlocked},
		{200, true, OutcomeBlocked}, // the gate's word wins over the status
	}
	for _, tc := range tests {
		if got := Classify(tc.status, tc.blocked); got != tc.want {
			t.Errorf("Classify(%d, %v) = %q, want %q", tc.status, tc.blocked, got, tc.want)
		}
	}
	for _, o := range Outcomes() {
		if !o.valid() {
			t.Errorf("outcome %q is not valid", o)
		}
	}
}

// Everything in an entry that a client or an upstream chose is bounded and free
// of control characters once stored.
func TestRecordSanitizesUntrustedFields(t *testing.T) {
	l, _ := newLog(t, Config{})
	e := entry("::ffff:10.1.2.3", "npm", "evil\x00pkg\r\nX-Injected: 1", strings.Repeat("9", 5000))
	e.ForwardedBy = "0010:0000::0001"
	e.UserAgent = "curl/8\x1b[31m\tred" + strings.Repeat("A", 4000)
	e.Path = "/v1/npm/" + strings.Repeat("é", 3000)
	e.Reason = "bad \xff\xfe bytes"
	e.Outcome = "made-up"
	e.Kind = "made-up"
	e.Status = 404
	e.Bytes = -5
	e.Size = -1
	e.DurationMs = -9
	l.Record(e)

	got := mustQuery(t, l, Query{}).Entries[0]
	if got.ClientIP != "10.1.2.3" {
		t.Errorf("ClientIP = %q, want the canonical 10.1.2.3", got.ClientIP)
	}
	if got.ForwardedBy != "10::1" {
		t.Errorf("ForwardedBy = %q, want the canonical 10::1", got.ForwardedBy)
	}
	if got.Package != "evilpkg  X-Injected: 1" {
		t.Errorf("Package = %q: control characters must be removed (line breaks become spaces)", got.Package)
	}
	if len(got.Version) > maxVersionLen || !strings.HasSuffix(got.Version, "…") {
		t.Errorf("Version is %d bytes ending %q; want it cut to %d with an ellipsis", len(got.Version), got.Version[len(got.Version)-3:], maxVersionLen)
	}
	if len(got.UserAgent) > maxUserAgentLen || strings.ContainsAny(got.UserAgent, "\x1b\t") {
		t.Errorf("UserAgent = %q (%d bytes)", got.UserAgent, len(got.UserAgent))
	}
	if len(got.Path) > maxPathLen || !utf8.ValidString(got.Path) {
		t.Errorf("Path is %d bytes, valid UTF-8: %v; a cut must fall on a rune boundary", len(got.Path), utf8.ValidString(got.Path))
	}
	if got.Reason != "bad  bytes" {
		t.Errorf("Reason = %q, want invalid UTF-8 removed", got.Reason)
	}
	if got.Outcome != OutcomeNotFound {
		t.Errorf("Outcome = %q, want an unknown outcome re-derived from the status (not_found)", got.Outcome)
	}
	if got.Kind != KindUnclassified {
		t.Errorf("Kind = %q, want an unknown kind to fall back to unclassified", got.Kind)
	}
	if got.Bytes != 0 || got.Size != 0 || got.DurationMs != 0 {
		t.Errorf("negative numbers survived: bytes %d size %d duration %d", got.Bytes, got.Size, got.DurationMs)
	}

	// An address that is not an IP address is kept (bounded), never dropped: the
	// entry must still be attributable to whatever the transport reported.
	odd := entry("unix:/run/pt.sock", "npm", "a", "1")
	l.Record(odd)
	if got := mustQuery(t, l, Query{}).Entries[0].ClientIP; got != "unix:/run/pt.sock" {
		t.Errorf("non-IP ClientIP = %q", got)
	}
	blank := entry("", "npm", "b", "1")
	l.Record(blank)
	if got := mustQuery(t, l, Query{}).Entries[0].ClientIP; got != "unknown" {
		t.Errorf("empty ClientIP = %q, want \"unknown\"", got)
	}
}

func TestCleanLeavesOrdinaryStringsAlone(t *testing.T) {
	for _, s := range []string{"", "cfg-if", "rsc.io/quote", "@scope/pkg", "pkg with space", "日本語パッケージ"} {
		if got := clean(s, 512); got != s {
			t.Errorf("clean(%q) = %q", s, got)
		}
	}
	if got := clean("  padded  ", 512); got != "padded" {
		t.Errorf("clean trims: got %q", got)
	}
	if got := clean("abcdef", 3); got != "…" || len(got) > 3 {
		t.Errorf("clean(abcdef, 3) = %q", got)
	}
	if got := clean("abcdef", 0); got != "" && got != "…" {
		t.Errorf("clean(abcdef, 0) = %q", got)
	}
}

// A name can be made to look like another one without being spelled like it:
// a right-to-left override reverses how the text is drawn, a zero-width space
// is not drawn at all. The log shows such characters for what they are, so a
// name that tried to pass for another is recognizable instead of convincing.
func TestCleanShowsInvisibleFormatCharacters(t *testing.T) {
	tests := []struct{ name, in, want string }{
		{"right-to-left override", "\u202egnp.exe", `\u{202E}gnp.exe`},
		{"zero-width space", "left\u200bpad", `left\u{200B}pad`},
		{"zero-width joiner", "left\u200dpad", `left\u{200D}pad`},
		{"left-to-right isolate", "a\u2066b\u2069c", `a\u{2066}b\u{2069}c`},
		{"byte order mark", "\ufeffreact", `\u{FEFF}react`},
		{"soft hyphen", "lo\u00addash", `lo\u{00AD}dash`},
		{"tag character", "pkg\U000e0041", `pkg\u{E0041}`},
		{"line separator", "a\u2028b", "a b"},
		{"paragraph separator", "a\u2029b", "a b"},
		{"C1 control", "a\u0085b", "ab"},
		// Ordinary non-ASCII text is none of these and is kept as it is.
		{"accents", "café-crème", "café-crème"},
		{"CJK", "日本語パッケージ", "日本語パッケージ"},
		{"emoji", "rocket-🚀", "rocket-🚀"},
	}
	for _, tc := range tests {
		got := clean(tc.in, 512)
		if got != tc.want {
			t.Errorf("%s: clean(%+q) = %q, want %q", tc.name, tc.in, got, tc.want)
		}
		// Entries are cleaned again when a persisted log is loaded: a second
		// pass must change nothing.
		if again := clean(got, 512); again != got {
			t.Errorf("%s: cleaning twice gives %q, then %q", tc.name, got, again)
		}
	}

	// It reaches the log: two downloads whose names would be drawn identically
	// are two different packages in the record.
	l, _ := newLog(t, Config{})
	l.Record(entry("10.0.0.5", "npm", "left-pad", "1.3.0"))
	l.Record(entry("10.0.0.6", "npm", "left\u200b-pad", "1.3.0"))
	res := mustQuery(t, l, Query{})
	if got := res.Entries[0].Package; got != `left\u{200B}-pad` {
		t.Errorf("the lookalike was recorded as %q", got)
	}
	if exact := mustQuery(t, l, Query{Package: "left-pad"}); exact.Total != 1 || exact.Entries[0].ClientIP != "10.0.0.5" {
		t.Errorf("filtering by the real name matched %d entries", exact.Total)
	}
}

// What reaches the log is cut from a request: the path is a substring of the
// request line, the package name a substring of the path. An entry that stored
// those substrings would keep the whole request line alive for as long as it
// stays in the log — a megabyte per entry if a client pads its query string,
// whatever the bounds on the fields say. So nothing an entry holds may point
// into memory the caller handed in.
func TestRecordedEntryDoesNotShareMemoryWithItsInput(t *testing.T) {
	// One large buffer, as a request line is, and every field a slice of it.
	line := "GET /v1/cargo/api/v1/crates/cfg-if/1.0.0/download?kind=package&outcome=served&via=10.9.9.9&ua=cargo/1.84.0" +
		"&digest=sha256:ab&sub=alice&team=platform&auth=token&trace=4bf92f&cache=HIT&gate=policy&code=malicious&why=flagged&pad=" +
		strings.Repeat("A", 1<<20)
	cut := func(sub string) string {
		i := strings.Index(line, sub)
		if i < 0 {
			t.Fatalf("the request line has no %q", sub)
		}
		return line[i : i+len(sub)]
	}
	l, _ := newLog(t, Config{})
	l.Record(Entry{
		ClientIP: "10.0.0.5", ForwardedBy: cut("10.9.9.9"),
		Ecosystem: cut("cargo"), Upstream: cut("cargo"), Package: cut("cfg-if"), Version: cut("1.0.0"),
		Artifact: cut("download"), Digest: cut("sha256:ab"), Kind: Kind(cut("package")),
		Method: cut("GET"), Path: cut("/v1/cargo/api/v1/crates/cfg-if/1.0.0/download"), Status: 200,
		Outcome: Outcome(cut("served")), Gate: cut("policy"), Code: cut("malicious"), Reason: cut("flagged"),
		Cache: cut("HIT"), Subject: cut("alice"), Tenant: cut("platform"), AuthMethod: cut("token"),
		UserAgent: cut("cargo/1.84.0"), TraceID: cut("4bf92f"),
	})
	// A non-IP client address is stored as given (bounded): it must be copied too.
	l.Record(Entry{ClientIP: cut("cfg-if"), Package: "x", Kind: KindPackage, Outcome: OutcomeServed})

	base := uintptr(unsafe.Pointer(unsafe.StringData(line)))
	end := base + uintptr(len(line))
	for _, e := range mustQuery(t, l, Query{}).Entries {
		v := reflect.ValueOf(e)
		for i := 0; i < v.NumField(); i++ {
			if v.Field(i).Kind() != reflect.String {
				continue
			}
			field := v.Field(i).String()
			if field == "" {
				continue
			}
			if p := uintptr(unsafe.Pointer(unsafe.StringData(field))); p >= base && p < end {
				t.Errorf("entry %d: %s (%q) points into the request line it was cut from, keeping all %d bytes of it alive",
					e.ID, v.Type().Field(i).Name, field, len(line))
			}
		}
	}
}

func TestStatsCountsByOutcome(t *testing.T) {
	l, c := newLog(t, Config{})
	blocked := entry("10.0.0.9", "cargo", "itoa", "1.0.11")
	blocked.Outcome, blocked.Status, blocked.Gate = OutcomeBlocked, 403, "policy"
	l.Record(entry("10.0.0.1", "cargo", "cfg-if", "1.0.0"))
	c.Advance(time.Minute)
	l.Record(entry("10.0.0.2", "cargo", "cfg-if", "1.0.0"))
	c.Advance(time.Minute)
	l.Record(blocked)

	st := l.Stats()
	if !st.Enabled || st.Retained != 3 || st.Recorded != 3 {
		t.Fatalf("Stats = %+v", st)
	}
	if st.ByOutcome[OutcomeServed] != 2 || st.ByOutcome[OutcomeBlocked] != 1 {
		t.Fatalf("ByOutcome = %v", st.ByOutcome)
	}
	if st.Oldest == nil || st.Newest == nil || st.Newest.Sub(*st.Oldest) != 2*time.Minute {
		t.Fatalf("Oldest/Newest = %v / %v", st.Oldest, st.Newest)
	}
	// The snapshot is a copy: mutating it must not reach the log.
	st.ByOutcome[OutcomeServed] = 99
	if l.Stats().ByOutcome[OutcomeServed] != 2 {
		t.Fatal("Stats().ByOutcome aliases the log's counters")
	}
}

// Downloads are recorded while queries, summaries and stats run. The log must
// stay consistent (and the race detector quiet): every page is in strictly
// descending ID order and never exceeds the capacity.
func TestConcurrentRecordAndQuery(t *testing.T) {
	const capacity = chunkSize + chunkSize/2
	l, _ := newLog(t, Config{MaxEntries: capacity, Now: time.Now})

	const writers, perWriter = 4, 3 * chunkSize
	var wg sync.WaitGroup
	stop := make(chan struct{})

	for w := 0; w < writers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := 0; i < perWriter; i++ {
				l.Record(entry(fmt.Sprintf("10.0.%d.%d", w, i%250), "cargo", fmt.Sprintf("crate-%d", i%17), "1.0.0"))
			}
		}(w)
	}

	readerErr := make(chan error, 3)
	for r := 0; r < 3; r++ {
		go func() {
			for {
				select {
				case <-stop:
					readerErr <- nil
					return
				default:
				}
				res, err := l.Query(Query{Limit: -1})
				if err != nil {
					readerErr <- err
					return
				}
				if len(res.Entries) > capacity {
					readerErr <- fmt.Errorf("a page of %d entries exceeds the capacity %d", len(res.Entries), capacity)
					return
				}
				for i := 1; i < len(res.Entries); i++ {
					if res.Entries[i].ID >= res.Entries[i-1].ID {
						readerErr <- fmt.Errorf("page out of order at %d: %d then %d", i, res.Entries[i-1].ID, res.Entries[i].ID)
						return
					}
					if res.Entries[i].Package == "" {
						readerErr <- fmt.Errorf("entry %d read before it was written", res.Entries[i].ID)
						return
					}
				}
				if _, err := l.Summarize(Query{Ecosystem: "cargo"}, 5); err != nil {
					readerErr <- err
					return
				}
				_ = l.Stats()

				// An export walks a snapshot while recording goes on: it must see
				// only whole entries, in descending order, and exactly as many as
				// it counted.
				sel, err := l.Select(Query{})
				if err != nil {
					readerErr <- err
					return
				}
				var walked int
				var last uint64
				var walkErr error
				sel.Each(func(e *Entry) bool {
					switch {
					case e.Package == "":
						walkErr = fmt.Errorf("entry %d walked before it was written", e.ID)
					case walked > 0 && e.ID >= last:
						walkErr = fmt.Errorf("walk out of order: %d then %d", last, e.ID)
					}
					last = e.ID
					walked++
					return walkErr == nil
				})
				if walkErr == nil && (walked != sel.Total() || walked > capacity) {
					walkErr = fmt.Errorf("walked %d entries, Total says %d, capacity %d", walked, sel.Total(), capacity)
				}
				if walkErr != nil {
					readerErr <- walkErr
					return
				}
			}
		}()
	}

	wg.Wait()
	close(stop)
	for r := 0; r < 3; r++ {
		if err := <-readerErr; err != nil {
			t.Fatal(err)
		}
	}

	res := mustQuery(t, l, Query{Limit: -1})
	if len(res.Entries) != capacity {
		t.Fatalf("retained %d, want the capacity %d", len(res.Entries), capacity)
	}
	if got, want := res.Entries[0].ID, uint64(writers*perWriter); got != want {
		t.Fatalf("newest ID = %d, want %d (every Record got its own ID)", got, want)
	}
	if st := l.Stats(); st.Recorded != uint64(writers*perWriter) || st.Evicted != uint64(writers*perWriter-capacity) {
		t.Fatalf("Stats = recorded %d evicted %d", st.Recorded, st.Evicted)
	}
}

func TestEntryCoordinate(t *testing.T) {
	if got := (Entry{Package: "cfg-if", Version: "1.0.0"}).Coordinate(); got != "cfg-if@1.0.0" {
		t.Errorf("Coordinate = %q", got)
	}
	if got := (Entry{Package: "octocat/Hello-World"}).Coordinate(); got != "octocat/Hello-World" {
		t.Errorf("Coordinate without a version = %q", got)
	}
}
