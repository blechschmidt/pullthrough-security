package backup

import (
	"bytes"
	"context"
	"fmt"
	"path/filepath"
	"testing"

	"github.com/blechschmidt/pullthrough-security/internal/audit"
)

// TestMerkleConsistencyProofsSurviveRoundTrip is the requirement that the
// tamper-evident audit log's Merkle transparency guarantees survive a
// backup/restore round-trip: after backing up the audit log file and its
// checkpoint file and restoring them into a fresh deployment, the sealed
// checkpoints still cross-verify against the records (VerifyLog), and fresh
// inclusion/consistency proofs produced by a logger re-opened over the restored
// files still verify.
func TestMerkleConsistencyProofsSurviveRoundTrip(t *testing.T) {
	ctx := context.Background()
	key := []byte("merkle-test-hmac-key")

	srcDir := t.TempDir()
	logPath := filepath.Join(srcDir, "audit.log")
	ckptPath := logPath + ".checkpoints"

	// Build a logger with the Merkle transparency layer persisting to files, seal
	// checkpoints frequently so several are produced.
	origRoot, origSize := buildAuditLog(t, ctx, logPath, ckptPath, key)

	// Back up the two audit files as metadata sources (cache is empty).
	src := newStore(t)
	sources := []MetadataSource{
		{Name: "audit-log", Path: logPath, Optional: true},
		{Name: "audit-checkpoints", Path: ckptPath, Optional: true},
	}
	buf, res := backupToBuffer(t, Options{Cache: src, Sources: sources})

	// Restore into a fresh deployment directory.
	dstDir := t.TempDir()
	dst := newStore(t)
	if _, err := NewRestorer().Restore(ctx, bytes.NewReader(buf.Bytes()), RestoreOptions{
		Cache: dst,
		Targets: map[string]string{
			"audit-log":         dstDir,
			"audit-checkpoints": dstDir,
		},
		ExpectedManifestDigest: res.ManifestDigest,
	}); err != nil {
		t.Fatalf("Restore: %v", err)
	}

	restoredLog := filepath.Join(dstDir, "audit.log")
	restoredCkpt := filepath.Join(dstDir, "audit.log.checkpoints")

	// 1. The restored records + checkpoints still cross-verify (key-independent
	//    Merkle line of defense).
	records, err := audit.ReadAllRecords(restoredLog)
	if err != nil {
		t.Fatalf("ReadAllRecords: %v", err)
	}
	checkpoints, err := audit.ReadCheckpoints(restoredCkpt)
	if err != nil {
		t.Fatalf("ReadCheckpoints: %v", err)
	}
	if len(checkpoints) == 0 {
		t.Fatal("no checkpoints survived the round-trip")
	}
	results, err := audit.VerifyLog(records, checkpoints, nil)
	if err != nil {
		t.Fatalf("VerifyLog after restore: %v", err)
	}
	for _, v := range results {
		if !v.OK() {
			t.Errorf("checkpoint at tree size %d failed after restore: %s", v.TreeSize, v.Problem)
		}
	}

	// 2. A logger re-opened over the restored files resumes the same tree: its
	//    latest checkpoint matches the original root/size, and a fresh
	//    inclusion + consistency proof verify.
	sink, err := audit.NewFileSink(restoredLog)
	if err != nil {
		t.Fatalf("reopen sink: %v", err)
	}
	defer sink.Close()
	ckStore, err := audit.NewFileCheckpointStore(restoredCkpt)
	if err != nil {
		t.Fatalf("reopen checkpoint store: %v", err)
	}
	defer ckStore.Close()

	logger, err := audit.NewLogger(ctx, audit.Options{
		Key:  key,
		Sink: sink,
		Transparency: &audit.TransparencyOptions{
			Origin:    "pullthrough-audit",
			SealEvery: 4,
			Store:     ckStore,
		},
	})
	if err != nil {
		t.Fatalf("reopen logger: %v", err)
	}

	cp, ok := logger.LatestCheckpoint()
	if !ok {
		t.Fatal("restored logger has no checkpoint")
	}
	if cp.RootHash != origRoot {
		t.Errorf("restored root %s != original %s", cp.RootHash, origRoot)
	}
	if cp.TreeSize != origSize {
		t.Errorf("restored tree size %d != original %d", cp.TreeSize, origSize)
	}

	// Inclusion proof for a record within the sealed tree must verify.
	incl, err := logger.InclusionProof(2)
	if err != nil {
		t.Fatalf("InclusionProof: %v", err)
	}
	if err := audit.VerifyInclusion(incl); err != nil {
		t.Errorf("inclusion proof failed after restore: %v", err)
	}

	// Consistency proof between two sealed sizes must verify.
	cons, err := logger.ConsistencyProof(4, origSize)
	if err != nil {
		t.Fatalf("ConsistencyProof: %v", err)
	}
	if err := audit.VerifyConsistency(cons); err != nil {
		t.Errorf("consistency proof failed after restore: %v", err)
	}
}

// buildAuditLog writes a populated, sealed transparency log to the given files
// and returns the latest checkpoint's root and tree size.
func buildAuditLog(t *testing.T, ctx context.Context, logPath, ckptPath string, key []byte) (root string, size uint64) {
	t.Helper()
	sink, err := audit.NewFileSink(logPath)
	if err != nil {
		t.Fatalf("NewFileSink: %v", err)
	}
	ckStore, err := audit.NewFileCheckpointStore(ckptPath)
	if err != nil {
		t.Fatalf("NewFileCheckpointStore: %v", err)
	}
	logger, err := audit.NewLogger(ctx, audit.Options{
		Key:  key,
		Sink: sink,
		Transparency: &audit.TransparencyOptions{
			Origin:    "pullthrough-audit",
			SealEvery: 4,
			Store:     ckStore,
		},
	})
	if err != nil {
		t.Fatalf("NewLogger: %v", err)
	}

	for i := 0; i < 12; i++ {
		if err := logger.Log(ctx, audit.Event{
			Type:     audit.EventPull,
			Subject:  fmt.Sprintf("artifact-%d", i),
			Resource: fmt.Sprintf("/pkg/artifact-%d", i),
		}); err != nil {
			t.Fatalf("Log: %v", err)
		}
	}
	// Seal a final checkpoint over all records.
	if _, _, err := logger.Seal(ctx); err != nil {
		t.Fatalf("Seal: %v", err)
	}
	cp, ok := logger.LatestCheckpoint()
	if !ok {
		t.Fatal("no checkpoint after sealing")
	}
	if err := ckStore.Close(); err != nil {
		t.Fatalf("close checkpoint store: %v", err)
	}
	if err := sink.Close(); err != nil {
		t.Fatalf("close sink: %v", err)
	}
	return cp.RootHash, cp.TreeSize
}
