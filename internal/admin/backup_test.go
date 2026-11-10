package admin

import (
	"context"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/blechschmidt/pullthrough-security/internal/backup"
)

// fakeBackup is a stub BackupController for the admin handler tests.
type fakeBackup struct {
	enabled  bool
	status   backup.Snapshot
	runErr   error
	runCount int
}

func (f *fakeBackup) Enabled() bool           { return f.enabled }
func (f *fakeBackup) Status() backup.Snapshot { return f.status }
func (f *fakeBackup) RunOnce(context.Context) error {
	f.runCount++
	if f.runErr == nil {
		f.status.SuccessCount++
		f.status.AgeSeconds = 0
	}
	return f.runErr
}

func TestBackupStatusDisabled(t *testing.T) {
	srv := newTestServer(t, Options{})
	var resp backupStatusResponse
	if code := getJSON(t, srv, "/admin/api/backup", "", &resp); code != http.StatusOK {
		t.Fatalf("status code = %d", code)
	}
	if resp.Enabled {
		t.Error("expected disabled when no backup controller wired")
	}
}

func TestBackupStatusEnabled(t *testing.T) {
	fb := &fakeBackup{
		enabled: true,
		status: backup.Snapshot{
			LastSuccess:  time.Unix(1700000000, 0).UTC(),
			AgeSeconds:   42,
			SuccessCount: 3,
			LastBytes:    1024,
		},
	}
	srv := newTestServer(t, Options{Backup: fb})
	var resp backupStatusResponse
	if code := getJSON(t, srv, "/admin/api/backup", "", &resp); code != http.StatusOK {
		t.Fatalf("status code = %d", code)
	}
	if !resp.Enabled || resp.Status.AgeSeconds != 42 || resp.Status.SuccessCount != 3 {
		t.Fatalf("unexpected status: %+v", resp)
	}
}

func TestBackupRunTriggers(t *testing.T) {
	fb := &fakeBackup{enabled: true}
	srv := newTestServer(t, Options{Backup: fb})
	rec := postJSON(t, srv, "/admin/api/backup/run", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("status code = %d, body=%s", rec.Code, rec.Body.String())
	}
	if fb.runCount != 1 {
		t.Errorf("RunOnce called %d times, want 1", fb.runCount)
	}
}

func TestBackupRunFails(t *testing.T) {
	fb := &fakeBackup{enabled: true, runErr: errors.New("disk full")}
	srv := newTestServer(t, Options{Backup: fb})
	rec := postJSON(t, srv, "/admin/api/backup/run", "")
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status code = %d, want 503", rec.Code)
	}
}

func TestBackupRunNotConfigured(t *testing.T) {
	srv := newTestServer(t, Options{})
	rec := postJSON(t, srv, "/admin/api/backup/run", "")
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status code = %d, want 404", rec.Code)
	}
}
