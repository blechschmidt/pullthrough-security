package audit

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

// MemorySink is an in-memory Sink for tests and ephemeral deployments. It is
// safe for concurrent use.
type MemorySink struct {
	mu      sync.Mutex
	records []Record
}

// NewMemorySink returns an empty in-memory sink.
func NewMemorySink() *MemorySink { return &MemorySink{} }

// Append stores a copy of the record.
func (m *MemorySink) Append(_ context.Context, rec Record) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.records = append(m.records, rec)
	return nil
}

// Last returns the most recently appended record.
func (m *MemorySink) Last(_ context.Context) (Record, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.records) == 0 {
		return Record{}, false, nil
	}
	return m.records[len(m.records)-1], true, nil
}

// Records returns a snapshot copy of all stored records.
func (m *MemorySink) Records() []Record {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]Record, len(m.records))
	copy(out, m.records)
	return out
}

// ReadAll returns every stored record, ordered by sequence. It implements
// RecordReader so the transparency log can rebuild its Merkle tree.
func (m *MemorySink) ReadAll(_ context.Context) ([]Record, error) {
	recs := m.Records()
	sortRecords(recs)
	return recs, nil
}

// Close is a no-op for the memory sink.
func (m *MemorySink) Close() error { return nil }

// FileSink is an append-only, newline-delimited-JSON Sink backed by a file. It
// is safe for concurrent use; writes are serialized and flushed (with an fsync)
// per record so a crash cannot silently truncate the chain mid-record.
type FileSink struct {
	mu   sync.Mutex
	f    *os.File
	path string
}

// NewFileSink opens (creating if needed) the audit log file for appending. The
// file is created with 0600 permissions since, while it holds no secrets, it is
// a sensitive security record.
func NewFileSink(path string) (*FileSink, error) {
	if path == "" {
		return nil, fmt.Errorf("audit: file sink path is required")
	}
	if dir := filepath.Dir(path); dir != "" {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return nil, fmt.Errorf("audit: creating log dir: %w", err)
		}
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return nil, fmt.Errorf("audit: opening log: %w", err)
	}
	return &FileSink{f: f, path: path}, nil
}

// Append writes one record as a JSON line and fsyncs it.
func (s *FileSink) Append(_ context.Context, rec Record) error {
	line, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	line = append(line, '\n')

	s.mu.Lock()
	defer s.mu.Unlock()
	if _, err := s.f.Write(line); err != nil {
		return err
	}
	return s.f.Sync()
}

// Last scans the file for the highest-sequence record. The audit log is
// expected to be modest in size relative to memory for this resume-on-startup
// operation; it reads the file once line by line.
func (s *FileSink) Last(_ context.Context) (Record, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	f, err := os.Open(s.path)
	if err != nil {
		if os.IsNotExist(err) {
			return Record{}, false, nil
		}
		return Record{}, false, err
	}
	defer f.Close()

	var last Record
	found := false
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 8*1024*1024)
	for sc.Scan() {
		line := sc.Bytes()
		if len(line) == 0 {
			continue
		}
		var rec Record
		if err := json.Unmarshal(line, &rec); err != nil {
			return Record{}, false, fmt.Errorf("audit: corrupt record while resuming: %w", err)
		}
		if !found || rec.Seq >= last.Seq {
			last = rec
			found = true
		}
	}
	if err := sc.Err(); err != nil {
		return Record{}, false, err
	}
	return last, found, nil
}

// ReadAll reads and parses every record from the backing file, ordered by
// sequence. It implements RecordReader so the transparency log can rebuild its
// Merkle tree across restarts.
func (s *FileSink) ReadAll(_ context.Context) ([]Record, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return ReadAllRecords(s.path)
}

// Close closes the underlying file.
func (s *FileSink) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.f == nil {
		return nil
	}
	err := s.f.Close()
	s.f = nil
	return err
}

// ReadAllRecords reads and parses every record from a file-backed audit log,
// returning them ordered by sequence. It is used by verification tooling and
// the admin surface; it does not require an open FileSink.
func ReadAllRecords(path string) ([]Record, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("audit: reading log: %w", err)
	}
	return ParseRecords(string(data))
}
