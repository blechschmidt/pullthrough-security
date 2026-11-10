package coord

import (
	"context"
	"errors"
	"testing"
)

func TestFileBackendCASLifecycle(t *testing.T) {
	dir := t.TempDir()
	clk := newFakeClock()
	b, err := newFileBackend(dir)
	if err != nil {
		t.Fatalf("newFileBackend: %v", err)
	}
	a := newNode(b, "node-a", clk)
	bn := newNode(b, "node-b", clk)
	ctx := context.Background()

	lease, err := a.AcquireLease(ctx, "backup", testTTL)
	if err != nil {
		t.Fatalf("node-a acquire: %v", err)
	}
	if _, err := bn.AcquireLease(ctx, "backup", testTTL); !errors.Is(err, ErrLeaseHeld) {
		t.Fatalf("node-b acquire err = %v, want ErrLeaseHeld", err)
	}

	// Renewal succeeds and updates the on-disk content-hash version.
	if _, err := a.RenewLease(ctx, lease, testTTL); err != nil {
		t.Fatalf("renew: %v", err)
	}

	// Expire and steal across the shared directory.
	clk.Advance(testTTL + 1)
	stolen, err := bn.AcquireLease(ctx, "backup", testTTL)
	if err != nil {
		t.Fatalf("node-b steal: %v", err)
	}
	if stolen.FencingToken <= lease.FencingToken {
		t.Errorf("steal token %d not greater than %d", stolen.FencingToken, lease.FencingToken)
	}

	// Resign releases the lease in place (expired, token preserved) so a fresh
	// acquisition steals it at a strictly higher token.
	if err := bn.Resign(ctx, stolen); err != nil {
		t.Fatalf("resign: %v", err)
	}
	rec, _, found, err := b.load(ctx, "backup")
	if err != nil || !found {
		t.Fatalf("expected released lease record present, found=%v err=%v", found, err)
	}
	if clk.Now().Before(rec.ExpiresAt) {
		t.Fatalf("expected resigned lease to read as expired, expiresAt=%v now=%v", rec.ExpiresAt, clk.Now())
	}
	reacquired, err := a.AcquireLease(ctx, "backup", testTTL)
	if err != nil {
		t.Fatalf("re-acquire after resign: %v", err)
	}
	if reacquired.FencingToken <= stolen.FencingToken {
		t.Errorf("re-acquire token %d not greater than resigned %d", reacquired.FencingToken, stolen.FencingToken)
	}
}

func TestFileBackendRequiresDir(t *testing.T) {
	if _, err := newFileBackend("  "); err == nil {
		t.Fatal("expected error for empty dir")
	}
}

func TestServiceFileModeEndToEnd(t *testing.T) {
	dir := t.TempDir()
	clk := newFakeClock()
	mk := func(id string) *Service {
		s, err := New(Config{
			Enabled: true, Mode: "file", NodeID: id, Dir: dir,
			LeaseTTL: testTTL, RenewInterval: 10, RetryInterval: 10,
		}, nil, WithClock(clk.Now))
		if err != nil {
			t.Fatalf("New(%s): %v", id, err)
		}
		return s
	}
	sa, sb := mk("node-a"), mk("node-b")
	defer sa.Close()
	defer sb.Close()
	ga, gb := sa.Guard("j"), sb.Guard("j")
	ctx := context.Background()

	sa.tick(ctx, ga)
	sb.tick(ctx, gb)
	if !ga.IsLeader() || gb.IsLeader() {
		t.Fatalf("expected only node-a leader: a=%v b=%v", ga.IsLeader(), gb.IsLeader())
	}
}
