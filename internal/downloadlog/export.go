package downloadlog

import (
	"encoding/csv"
	"io"
	"strconv"
	"time"
)

// csvHeader is the column order of the CSV export.
var csvHeader = []string{
	"time", "client_ip", "forwarded_by", "ecosystem", "upstream", "package", "version",
	"artifact", "kind", "outcome", "status", "gate", "code", "reason", "cache",
	"bytes", "size", "duration_ms", "subject", "tenant", "auth_method", "user_agent",
	"method", "path", "digest", "trace_id", "id",
}

// CSVWriter writes entries as CSV, one row at a time, so an export can be
// streamed without first collecting what it will hold.
//
// Most of an entry is chosen by whoever sent the request — the package name,
// the path, the User-Agent — and an export is opened in a spreadsheet by the
// person investigating them. A cell that starts with "=", "+", "-" or "@" is a
// formula to a spreadsheet, so such cells are prefixed with an apostrophe,
// which makes the application treat them as the text they are.
type CSVWriter struct {
	cw     *csv.Writer
	record []string
}

// NewCSVWriter returns a CSVWriter on w, having written the header row.
func NewCSVWriter(w io.Writer) (*CSVWriter, error) {
	c := &CSVWriter{cw: csv.NewWriter(w), record: make([]string, 0, len(csvHeader))}
	if err := c.cw.Write(csvHeader); err != nil {
		return nil, err
	}
	return c, nil
}

// Write appends one entry as a row. Rows are buffered; Flush writes what is
// pending.
func (c *CSVWriter) Write(e *Entry) error {
	c.record = append(c.record[:0],
		e.Time.UTC().Format(time.RFC3339Nano),
		csvCell(e.ClientIP),
		csvCell(e.ForwardedBy),
		csvCell(e.Ecosystem),
		csvCell(e.Upstream),
		csvCell(e.Package),
		csvCell(e.Version),
		csvCell(e.Artifact),
		csvCell(string(e.Kind)),
		csvCell(string(e.Outcome)),
		strconv.Itoa(e.Status),
		csvCell(e.Gate),
		csvCell(e.Code),
		csvCell(e.Reason),
		csvCell(e.Cache),
		strconv.FormatInt(e.Bytes, 10),
		strconv.FormatInt(e.Size, 10),
		strconv.FormatInt(e.DurationMs, 10),
		csvCell(e.Subject),
		csvCell(e.Tenant),
		csvCell(e.AuthMethod),
		csvCell(e.UserAgent),
		csvCell(e.Method),
		csvCell(e.Path),
		csvCell(e.Digest),
		csvCell(e.TraceID),
		strconv.FormatUint(e.ID, 10),
	)
	return c.cw.Write(c.record)
}

// Flush writes the buffered rows and reports the first error the writer met.
func (c *CSVWriter) Flush() error {
	c.cw.Flush()
	return c.cw.Error()
}

// WriteCSV writes entries as CSV with a header row, in the order given.
func WriteCSV(w io.Writer, entries []Entry) error {
	cw, err := NewCSVWriter(w)
	if err != nil {
		return err
	}
	for i := range entries {
		if err := cw.Write(&entries[i]); err != nil {
			return err
		}
	}
	return cw.Flush()
}

// csvCell neutralizes a value a spreadsheet would interpret as a formula.
func csvCell(s string) string {
	if s == "" {
		return s
	}
	switch s[0] {
	case '=', '+', '-', '@', '\t', '\r':
		return "'" + s
	}
	return s
}
