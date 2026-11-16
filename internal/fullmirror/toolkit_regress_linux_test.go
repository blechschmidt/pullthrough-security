//go:build linux

package fullmirror

import (
	"context"
	"errors"
	"os"
	"syscall"
	"testing"
)

// An I/O error that has nothing to do with the copy (no file descriptor left)
// is retried, not taken for an invalid cursor.
func TestIndexFeedIOErrorIsNotACursorFault(t *testing.T) {
	src := newFakeIndex()
	src.set("a", pkgs("alpha@1", "beta@1")...)
	f := newTestIndexFeed(t, src, 10)
	_, cursor := drainBootstrap(t, f)
	fresh := testIndexFeed{newIndexFeed("test", Env{Dir: f.files.dir}, src)}
	var lim syscall.Rlimit
	if err := syscall.Getrlimit(syscall.RLIMIT_NOFILE, &lim); err != nil {
		t.Skip(err)
	}
	// A soft limit at the lowest free descriptor number — the one open
	// returns — leaves no descriptor to open. (The count of open descriptors
	// would not do: the limit bounds numbers, and a process can have gaps
	// below it, as CI runners' test processes do.)
	devnull, err := os.Open(os.DevNull)
	if err != nil {
		t.Skip(err)
	}
	lowest := devnull.Fd()
	devnull.Close()
	low := syscall.Rlimit{Cur: uint64(lowest), Max: lim.Max}
	if err := syscall.Setrlimit(syscall.RLIMIT_NOFILE, &low); err != nil {
		t.Skip(err)
	}
	_, err = fresh.Changes(context.Background(), cursor)
	if rerr := syscall.Setrlimit(syscall.RLIMIT_NOFILE, &lim); rerr != nil {
		t.Fatal(rerr)
	}
	if err == nil || errors.Is(err, ErrCursorInvalid) {
		t.Errorf("no descriptor left: %v", err)
	}
	if _, err := fresh.Changes(context.Background(), cursor); err != nil {
		t.Errorf("the cursor itself is valid: %v", err)
	}
}
