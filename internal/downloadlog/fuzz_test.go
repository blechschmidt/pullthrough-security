//go:build fuzz
// +build fuzz

// Fuzz targets for the download log (Task 176).
//
// What the log stores is chosen by whoever sent the request (package names,
// paths, the User-Agent), what it is asked comes from a URL (the admin API's
// filters), and what it loads at start is a file that a crash may have cut
// short or an operator may have edited. None of the three may crash the proxy,
// and each has a property worth holding for every input:
//
//   - a stored string never carries a control or invisible format character,
//     never exceeds its bound, and cleaning it again changes nothing;
//   - the wildcard matcher agrees with a textbook implementation;
//   - whatever is in the file, the log opens, and the entries it loaded are in
//     strictly ascending ID order so that recording can continue the sequence.
//
// Build-tag gated (`fuzz`). Run e.g.:
//
//	go test -tags fuzz -run='^$' -fuzz=FuzzLoad ./internal/downloadlog/
package downloadlog

import (
	"bytes"
	"encoding/csv"
	"io"
	"log/slog"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"unicode"
	"unicode/utf8"
)

// FuzzClean checks the sanitizer every stored string goes through.
func FuzzClean(f *testing.F) {
	for _, s := range []string{
		"", "cfg-if", "rsc.io/quote", "  padded  ", "evil\x00pkg\r\nX-Injected: 1",
		"curl/8\x1b[31m\tred", "bad \xff\xfe bytes", "‮gnp.exe", "left​pad",
		"a b", "a\u0085b", "日本語パッケージ", "rocket-🚀", strings.Repeat("é", 400),
		strings.Repeat("​", 300), "�", "=cmd|' /C calc'!A0",
	} {
		f.Add(s, uint16(512))
		f.Add(s, uint16(16))
	}
	f.Fuzz(func(t *testing.T, s string, bound uint16) {
		// Every bound in use leaves room for the ellipsis that marks a cut.
		max := int(bound)%4096 + len("…")
		got := clean(s, max)
		if len(got) > max {
			t.Fatalf("clean(%+q, %d) is %d bytes", s, max, len(got))
		}
		if !utf8.ValidString(got) {
			t.Fatalf("clean(%+q, %d) = %+q is not valid UTF-8", s, max, got)
		}
		for _, r := range got {
			if r < 0x20 || r == 0x7f || (r >= 0x80 && r < 0xa0) || r == lineSeparator || r == paragraphSeparator || unicode.Is(unicode.Cf, r) {
				t.Fatalf("clean(%+q, %d) = %+q still holds %U", s, max, got, r)
			}
		}
		if got != strings.TrimSpace(got) {
			t.Fatalf("clean(%+q, %d) = %+q is not trimmed", s, max, got)
		}
		if again := clean(got, max); again != got {
			t.Fatalf("cleaning twice differs: %+q, then %+q", got, again)
		}
	})
}

// globReference is the textbook dynamic-programming wildcard matcher.
func globReference(pattern, name string) bool {
	// match[j] reports whether pattern[:i] matches name[:j].
	match := make([]bool, len(name)+1)
	match[0] = true
	for i := 0; i < len(pattern); i++ {
		next := make([]bool, len(name)+1)
		if pattern[i] == '*' {
			next[0] = match[0]
			for j := 1; j <= len(name); j++ {
				next[j] = next[j-1] || match[j]
			}
		} else {
			for j := 1; j <= len(name); j++ {
				next[j] = match[j-1] && pattern[i] == name[j-1]
			}
		}
		match = next
	}
	return match[len(name)]
}

// FuzzGlobMatch checks the package filter's wildcard matcher against the
// reference for every pattern and name.
func FuzzGlobMatch(f *testing.F) {
	for _, tc := range [][2]string{
		{"", ""}, {"*", ""}, {"*", "anything"}, {"@acme/*", "@acme/widgets"}, {"*crypto*", "node-crypto-js"},
		{"a*b*c", "aXbYc"}, {"a*b*c", "abc"}, {"a*b*c", "acb"}, {"**", "x"}, {"*a", "ba"}, {"a*", "ab"},
		{"left-pad", "left-pad"}, {"left-pad", "left-pad2"}, {"a*a*a*a*b", strings.Repeat("a", 40)},
	} {
		f.Add(tc[0], tc[1])
	}
	f.Fuzz(func(t *testing.T, pattern, name string) {
		if len(pattern) > 256 || len(name) > 1024 {
			return // the reference is quadratic; the bounds on real input are tighter still
		}
		if got, want := globMatch(pattern, name), globReference(pattern, name); got != want {
			t.Fatalf("globMatch(%q, %q) = %v, the reference says %v", pattern, name, got, want)
		}
	})
}

// FuzzQueryFromValues parses arbitrary filter parameters and, when they are
// accepted, runs them: an accepted filter must be one the log can evaluate.
func FuzzQueryFromValues(f *testing.F) {
	for _, raw := range []string{
		"", "ip=10.0.0.5", "ip=10.0.0.0/8&package=cfg-*&outcome=blocked", "ip=::ffff:10.0.0.5", "ip=fe80::1%25eth0",
		"ip=not-an-address", "ip=10.0.0.0/33", "since=7d&until=1h", "since=2026-03-01T12:00:00Z", "since=1767225600",
		"since=-1h", "since=1d12h30m", "since=99999999d", "limit=0", "limit=-1", "limit=100000", "before=18446744073709551615",
		"before=-1", "kind=metadata&q=curl", "outcome=SERVED", "package=*&version=*", "top=5", "q=%00%ff", "format=csv",
		"package=" + strings.Repeat("*a", 200),
	} {
		f.Add(raw)
	}
	now := time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)
	log, err := New(Config{Enabled: true, Now: func() time.Time { return now }})
	if err != nil {
		f.Fatal(err)
	}
	for i, ip := range []string{"10.0.0.5", "10.0.0.6", "2001:db8::1", "192.168.1.20"} {
		log.Record(Entry{ClientIP: ip, Ecosystem: "cargo", Package: "cfg-if", Version: "1.0.0", Kind: KindPackage,
			Outcome: OutcomeServed, Status: 200, Bytes: int64(100 * (i + 1)), UserAgent: "cargo/1.84.0"})
	}

	f.Fuzz(func(t *testing.T, raw string) {
		values, err := url.ParseQuery(raw)
		if err != nil {
			return
		}
		q, err := QueryFromValues(values, now)
		if err != nil {
			return
		}
		res, err := log.Query(q)
		if err != nil {
			t.Fatalf("QueryFromValues accepted %q, Query rejects it: %v", raw, err)
		}
		if len(res.Entries) > res.Total || len(res.Entries) > MaxLimit {
			t.Fatalf("%q: a page of %d entries out of %d", raw, len(res.Entries), res.Total)
		}
		sum, err := log.Summarize(q, 0)
		if err != nil {
			t.Fatalf("%q: Summarize: %v", raw, err)
		}
		if sum.Total != res.Total {
			t.Fatalf("%q: the summary counts %d entries, the query %d", raw, sum.Total, res.Total)
		}
		sel, err := log.Select(q)
		if err != nil {
			t.Fatalf("%q: Select: %v", raw, err)
		}
		if sel.Total() != res.Total {
			t.Fatalf("%q: the selection counts %d entries, the query %d", raw, sel.Total(), res.Total)
		}
	})
}

// FuzzWriteCSV exports an entry made of arbitrary strings. The export must stay
// one well-formed row, and no cell may be something a spreadsheet would run.
func FuzzWriteCSV(f *testing.F) {
	for _, s := range []string{"cfg-if", "=cmd|' /C calc'!A0", "+1+1", "-2+3", "@SUM(A1)", "\tx", "\rx", "a,b", "a\"b", "a\nb", ""} {
		f.Add(s, s)
		f.Add(s, "10.0.0.5")
	}
	f.Fuzz(func(t *testing.T, a, b string) {
		e := Entry{
			ID: 1, Time: time.Unix(1767225600, 0), ClientIP: b, ForwardedBy: a, Ecosystem: a, Upstream: b,
			Package: a, Version: b, Artifact: a, Kind: Kind(b), Outcome: Outcome(a), Gate: b, Code: a, Reason: b,
			Cache: a, Subject: b, Tenant: a, AuthMethod: b, UserAgent: a, Method: b, Path: a, Digest: b, TraceID: a,
		}
		var buf bytes.Buffer
		if err := WriteCSV(&buf, []Entry{e}); err != nil {
			t.Fatal(err)
		}
		// A lone carriage return in a quoted cell is rewritten by the CSV
		// reader, so compare shapes and leading characters, not whole cells.
		r := csv.NewReader(&buf)
		r.LazyQuotes = false
		rows, err := r.ReadAll()
		if err != nil {
			t.Fatalf("the export of %+q / %+q is not valid CSV: %v", a, b, err)
		}
		if len(rows) != 2 || len(rows[1]) != len(csvHeader) {
			t.Fatalf("the export of %+q / %+q has %d rows; the entry row has %d cells, want %d", a, b, len(rows), len(rows[len(rows)-1]), len(csvHeader))
		}
		for i, cell := range rows[1] {
			if cell == "" {
				continue
			}
			switch cell[0] {
			case '=', '+', '-', '@', '\t', '\r':
				t.Fatalf("cell %q (%s) of the export starts with a formula trigger", cell, csvHeader[i])
			}
		}
	})
}

// FuzzLoad starts a log on a file with arbitrary content. A damaged file must
// never keep the proxy from starting, and what was loaded must be a log that
// recording can continue: IDs strictly ascending, the next one above them all,
// and a second start that sees the same entries plus the new one.
func FuzzLoad(f *testing.F) {
	line := func(id uint64, at string, pkg string) string {
		return `{"id":` + uitoa(id) + `,"time":"` + at + `","clientIp":"10.0.0.5","ecosystem":"cargo","upstream":"cargo","package":"` + pkg + `","kind":"package","method":"GET","path":"/v1/cargo/x","status":200,"outcome":"served","bytes":1,"durationMs":1}` + "\n"
	}
	now := time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)
	recent := now.Add(-time.Hour).Format(time.RFC3339)
	for _, s := range []string{
		"",
		line(1, recent, "a") + line(2, recent, "b"),
		line(2, recent, "a") + line(1, recent, "b"),
		line(7, recent, "a") + line(7, recent, "b"),
		line(18446744073709551615, recent, "max"),
		line(18446744073709551614, recent, "a") + line(18446744073709551615, recent, "b"),
		line(1, "2020-01-01T00:00:00Z", "expired") + line(2, recent, "kept"),
		line(1, "9999-12-31T23:59:59Z", "future"),
		line(1, recent, "a") + `{"id":2,"time":"` + recent + `","clientIp":"10.0`,
		"not json\n" + line(3, recent, "a") + "\n\n{}\n[]\nnull\n",
		`{"id":0,"time":"` + recent + `"}` + "\n",
		`{"id":1}` + "\n",
		`{"id":1,"time":"` + recent + `","status":99999999999999999999}` + "\n",
		`{"id":1,"time":"` + recent + `","outcome":"made-up","kind":"made-up","bytes":-5,"package":"a\u0000b"}` + "\n",
		strings.Repeat("x", 70000) + "\n" + line(1, recent, "after-a-long-line"),
		"\x00\x01\x02\xff\xfe",
	} {
		f.Add([]byte(s))
	}

	quiet := slog.New(slog.NewTextHandler(io.Discard, nil))
	open := func(t *testing.T, path string) *Log {
		l, err := New(Config{
			Enabled: true, Path: path, MaxEntries: 64, FlushInterval: time.Hour,
			Now: func() time.Time { return now }, Logger: quiet,
		})
		if err != nil {
			t.Fatalf("the log did not open: %v", err)
		}
		return l
	}
	ascending := func(t *testing.T, l *Log) []Entry {
		res, err := l.Query(Query{Limit: -1})
		if err != nil {
			t.Fatal(err)
		}
		for i := 1; i < len(res.Entries); i++ {
			if res.Entries[i].ID >= res.Entries[i-1].ID {
				t.Fatalf("loaded IDs are not strictly ascending: %d then %d", res.Entries[i].ID, res.Entries[i-1].ID)
			}
		}
		for _, e := range res.Entries {
			if e.ID == 0 {
				t.Fatal("an entry without an ID was loaded")
			}
		}
		return res.Entries
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		path := filepath.Join(t.TempDir(), "downloads.jsonl")
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}

		l := open(t, path)
		loaded := ascending(t, l)
		if len(loaded) > 64 {
			t.Fatalf("%d entries loaded into a log of 64", len(loaded))
		}
		// Recording continues the sequence above everything that was loaded.
		l.Record(Entry{ClientIP: "10.9.9.9", Ecosystem: "go", Package: "new", Kind: KindPackage, Outcome: OutcomeServed, Status: 200})
		after := ascending(t, l)
		if len(after) == 0 || after[0].Package != "new" {
			t.Fatalf("the entry recorded after loading is not the newest: %+v", after)
		}
		if len(loaded) > 0 && after[0].ID <= loaded[0].ID {
			t.Fatalf("the new entry got ID %d, not above the loaded %d", after[0].ID, loaded[0].ID)
		}
		if err := l.Close(); err != nil {
			t.Fatalf("closing: %v", err)
		}

		// A second start reads back exactly what the first one held.
		again := open(t, path)
		defer again.Close()
		reloaded := ascending(t, again)
		if len(reloaded) != len(after) {
			t.Fatalf("after a restart the log holds %d entries, before it %d", len(reloaded), len(after))
		}
		for i := range reloaded {
			if reloaded[i].ID != after[i].ID || reloaded[i].Package != after[i].Package {
				t.Fatalf("entry %d changed across the restart: %+v, was %+v", i, reloaded[i], after[i])
			}
		}
	})
}

func uitoa(n uint64) string {
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}
