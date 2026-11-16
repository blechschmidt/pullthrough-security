package fullscan

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/blechschmidt/pullthrough-security/internal/llmpkgscan"
	"github.com/blechschmidt/pullthrough-security/internal/llmpkgscan/pkgscantest"
)

// A leader that is about to wait longer than the persist interval writes what
// its step changed first: the figures the replicas that do not lead show are
// in the state file. With a persist interval longer than a step and shorter
// than the paused loop's half-minute wait, only that write can publish, within
// the test's ten seconds, the client's artifact the paused leader took in from
// the inbox — before the fix it stayed unpublished for the half minute (CI's
// fast FIPS runners hit it in TestTheInboxCarriesClientPullsToTheLeader, whose
// persist interval is a millisecond: a step faster than that skipped the write).
func TestAPausedLeaderPublishesWhatItTookIn(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	fc := newFakeCache()
	fc.put(objectKey("pulled"), "npm", objectPath("pulled"), "", tarball("pulled", false), time.Now())
	opts := testOptions(dir)
	opts.PersistInterval = 5 * time.Second
	follower, err := New(opts)
	if err != nil {
		t.Fatal(err)
	}
	follower.SetLeaderGate(func() bool { return false })
	follower.Attach(&gateScanner{svc: newGate(t, "mock-model", llmpkgscan.NewMemoryStore(0), &pkgscantest.Provider{}, llmpkgscan.ActionBlock), cache: fc}, fc)
	follower.Start(ctx)
	t.Cleanup(func() { _ = follower.Close() })
	follower.Note(Note{Source: SourceClient, Artifact: Artifact{Upstream: "npm", Path: objectPath("pulled"), Key: objectKey("pulled")},
		Reading: &Reading{Kind: ReadingUnscanned, Code: llmpkgscan.CodeBusy, Retryable: true}})
	waitFor(t, "the inbox file", func() bool {
		entries, _ := os.ReadDir(filepath.Join(dir, "inbox"))
		return len(entries) == 1
	})

	leader, err := New(opts)
	if err != nil {
		t.Fatal(err)
	}
	if err := leader.Pause(ctx, "", "op", ""); err != nil {
		t.Fatal(err)
	}
	leader.Attach(&gateScanner{svc: newGate(t, "mock-model", llmpkgscan.NewMemoryStore(0), &pkgscantest.Provider{}, llmpkgscan.ActionBlock), cache: fc}, fc)
	leader.Start(ctx)
	t.Cleanup(func() { _ = leader.Close() })
	waitFor(t, "the leader to queue the client's artifact", func() bool { return leader.Status().Queue.Client == 1 })
	waitFor(t, "the follower to see the leader's figures", func() bool {
		follower.mu.Lock()
		follower.peeked = nil
		follower.mu.Unlock()
		return follower.Status().Queue.Client == 1
	})
}
