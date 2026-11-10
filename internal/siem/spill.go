package siem

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
)

// errSpillFull is returned by spillQueue.push when the configured byte budget is
// exhausted. The forwarder treats it as a signal to drop (and count) the event.
var errSpillFull = errors.New("siem: spill queue full")

// spillQueue is a bounded, file-backed FIFO of events used to absorb bursts when
// the in-memory queue is full, without growing memory without bound and while
// surviving a restart. Events are stored as newline-delimited JSON. A read
// offset tracks the front; the file is compacted (rewritten without the
// consumed prefix) when it drains or the consumed prefix grows large, so the
// on-disk size stays bounded by maxBytes.
//
// It is safe for concurrent use.
type spillQueue struct {
	mu       sync.Mutex
	path     string
	f        *os.File
	readOff  int64
	writeOff int64
	count    int
	maxBytes int64
}

// openSpill opens (creating as needed) the spill file at path, replaying any
// events left by a previous run so forwarding resumes after a restart. A
// non-positive maxBytes disables the byte budget (unbounded on disk).
func openSpill(path string, maxBytes int64) (*spillQueue, error) {
	if dir := filepath.Dir(path); dir != "" {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return nil, fmt.Errorf("siem: creating spill directory: %w", err)
		}
	}
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return nil, fmt.Errorf("siem: opening spill file: %w", err)
	}
	q := &spillQueue{path: path, f: f, maxBytes: maxBytes}
	if err := q.recover(); err != nil {
		_ = f.Close()
		return nil, err
	}
	return q, nil
}

// recover scans the existing file to count pending events and position the write
// offset at end-of-file.
func (q *spillQueue) recover() error {
	info, err := q.f.Stat()
	if err != nil {
		return fmt.Errorf("siem: stat spill file: %w", err)
	}
	q.writeOff = info.Size()
	if q.writeOff == 0 {
		return nil
	}
	if _, err := q.f.Seek(0, io.SeekStart); err != nil {
		return fmt.Errorf("siem: seeking spill file: %w", err)
	}
	r := bufio.NewReader(q.f)
	count := 0
	for {
		_, err := r.ReadBytes('\n')
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("siem: scanning spill file: %w", err)
		}
		count++
	}
	q.count = count
	return nil
}

// len returns the number of pending (unconsumed) events.
func (q *spillQueue) len() int {
	q.mu.Lock()
	defer q.mu.Unlock()
	return q.count
}

// push appends an event to the back of the queue. It returns errSpillFull when
// the configured byte budget would be exceeded.
func (q *spillQueue) push(ev Event) error {
	line, err := json.Marshal(ev)
	if err != nil {
		return err
	}
	line = append(line, '\n')

	q.mu.Lock()
	defer q.mu.Unlock()
	if q.maxBytes > 0 && (q.writeOff-q.readOff)+int64(len(line)) > q.maxBytes {
		return errSpillFull
	}
	if _, err := q.f.WriteAt(line, q.writeOff); err != nil {
		return fmt.Errorf("siem: writing to spill file: %w", err)
	}
	q.writeOff += int64(len(line))
	q.count++
	return nil
}

// pop removes and returns up to max events from the front of the queue. It
// returns an empty slice when the queue is empty.
func (q *spillQueue) pop(max int) ([]Event, error) {
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.count == 0 || max <= 0 {
		return nil, nil
	}
	if _, err := q.f.Seek(q.readOff, io.SeekStart); err != nil {
		return nil, fmt.Errorf("siem: seeking spill file: %w", err)
	}
	r := bufio.NewReader(q.f)
	out := make([]Event, 0, max)
	for len(out) < max && q.count > 0 {
		line, err := r.ReadBytes('\n')
		if len(line) > 0 {
			q.readOff += int64(len(line))
			var ev Event
			if uerr := json.Unmarshal(trimNewline(line), &ev); uerr == nil {
				out = append(out, ev)
			}
			// A corrupt line is skipped but still consumed, so a single bad record
			// never wedges the queue.
			q.count--
		}
		if err != nil {
			if err == io.EOF {
				break
			}
			return out, fmt.Errorf("siem: reading spill file: %w", err)
		}
	}
	if err := q.maybeCompactLocked(); err != nil {
		return out, err
	}
	return out, nil
}

// trimNewline drops a trailing '\n' (and '\r') from a line.
func trimNewline(b []byte) []byte {
	for len(b) > 0 && (b[len(b)-1] == '\n' || b[len(b)-1] == '\r') {
		b = b[:len(b)-1]
	}
	return b
}

// maybeCompactLocked reclaims consumed disk space. When the queue is empty it
// truncates the file; otherwise, once the consumed prefix exceeds half the file,
// it rewrites the live tail to the front. The caller must hold q.mu.
func (q *spillQueue) maybeCompactLocked() error {
	if q.count == 0 {
		if err := q.f.Truncate(0); err != nil {
			return fmt.Errorf("siem: truncating spill file: %w", err)
		}
		q.readOff, q.writeOff = 0, 0
		return nil
	}
	if q.readOff == 0 || q.readOff < (q.writeOff/2) {
		return nil
	}
	live := q.writeOff - q.readOff
	buf := make([]byte, live)
	if _, err := q.f.ReadAt(buf, q.readOff); err != nil && err != io.EOF {
		return fmt.Errorf("siem: compacting spill file: %w", err)
	}
	if _, err := q.f.WriteAt(buf, 0); err != nil {
		return fmt.Errorf("siem: compacting spill file: %w", err)
	}
	if err := q.f.Truncate(live); err != nil {
		return fmt.Errorf("siem: truncating spill file: %w", err)
	}
	q.readOff = 0
	q.writeOff = live
	return nil
}

// close releases the spill file.
func (q *spillQueue) close() error {
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.f == nil {
		return nil
	}
	err := q.f.Close()
	q.f = nil
	return err
}
