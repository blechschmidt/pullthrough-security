package audit

import (
	"context"
	"encoding/hex"
	"fmt"
	"sync"
	"sync/atomic"
	"time"
)

// DefaultOrigin is the checkpoint origin used when none is configured.
const DefaultOrigin = "pullthrough-audit"

// DefaultSealEvery is how many appended records trigger an automatic checkpoint
// when no explicit batch size is configured.
const DefaultSealEvery = 1000

// InclusionProof proves that a single record (leaf) is contained in the log at
// a given TreeSize whose Merkle root is RootHash. A client recomputes the leaf
// hash for its record and follows Path to RootHash; if RootHash matches a signed
// checkpoint, the record is provably in the log.
type InclusionProof struct {
	LeafIndex uint64   `json:"leafIndex"`
	TreeSize  uint64   `json:"treeSize"`
	LeafHash  string   `json:"leafHash"`
	RootHash  string   `json:"rootHash"`
	Path      []string `json:"path"`
	// Checkpoint is the signed tree head the proof is anchored to, when the
	// proof's TreeSize equals a sealed checkpoint. Nil for proofs against the
	// unsealed live tree.
	Checkpoint *Checkpoint `json:"checkpoint,omitempty"`
}

// ConsistencyProof proves that the log of size FirstSize (root FirstRoot) is an
// append-only prefix of the log of size SecondSize (root SecondRoot): no earlier
// record was edited, deleted, or reordered.
type ConsistencyProof struct {
	FirstSize  uint64   `json:"firstSize"`
	SecondSize uint64   `json:"secondSize"`
	FirstRoot  string   `json:"firstRoot"`
	SecondRoot string   `json:"secondRoot"`
	Path       []string `json:"path"`
}

// Stats is a point-in-time snapshot of the transparency log, surfaced to the
// admin API and the metrics bridge.
type Stats struct {
	ChainLength          uint64 `json:"chainLength"`
	TreeSize             uint64 `json:"treeSize"`
	Checkpoints          uint64 `json:"checkpoints"`
	LastSealUnix         int64  `json:"lastSealUnix"`
	Signed               bool   `json:"signed"`
	Origin               string `json:"origin"`
	KeyID                string `json:"keyId,omitempty"`
	VerificationFailures uint64 `json:"verificationFailures"`
}

// transparencyLog maintains the Merkle tree over the log's records and the
// sealed checkpoints. It is owned by a Logger and always accessed under the
// Logger's mutex for mutation (add/seal); read methods take their own lock so
// the admin surface can query proofs concurrently with appends.
type transparencyLog struct {
	mu     sync.Mutex
	origin string
	leaves [][]byte // per-record Merkle leaf hashes, in sequence order

	sealEvery   int
	sinceSeal   int
	signer      *Signer
	store       CheckpointStore
	latest      Checkpoint
	haveLatest  bool
	checkpoints uint64

	lastSealUnix int64
	verifyFails  atomic.Uint64
	now          func() time.Time
}

// TransparencyOptions configures the Merkle transparency layer of a Logger.
type TransparencyOptions struct {
	// Origin identifies the log in its checkpoints. Defaults to DefaultOrigin.
	Origin string
	// SealEvery seals a checkpoint automatically after this many appended
	// records. Defaults to DefaultSealEvery; set negative to disable
	// size-triggered sealing (rely on interval/manual sealing instead).
	SealEvery int
	// Signer optionally signs sealed checkpoints. When nil, checkpoints are
	// sealed but unsigned (still tamper-evident against a key-less attacker).
	Signer *Signer
	// Store persists sealed checkpoints. Defaults to an in-memory store.
	Store CheckpointStore
}

// newTransparencyLog constructs the transparency layer, seeding its leaves from
// already-persisted records (for resume across restarts) and loading the latest
// persisted checkpoint.
func newTransparencyLog(ctx context.Context, opts TransparencyOptions, existing []Record, now func() time.Time) (*transparencyLog, error) {
	origin := opts.Origin
	if origin == "" {
		origin = DefaultOrigin
	}
	sealEvery := opts.SealEvery
	if sealEvery == 0 {
		sealEvery = DefaultSealEvery
	}
	store := opts.Store
	if store == nil {
		store = NewMemoryCheckpointStore()
	}
	if now == nil {
		now = time.Now
	}

	t := &transparencyLog{
		origin:    origin,
		sealEvery: sealEvery,
		signer:    opts.Signer,
		store:     store,
		now:       now,
	}
	for _, rec := range existing {
		t.leaves = append(t.leaves, recordLeafHash(rec))
	}

	cps, err := store.All(ctx)
	if err != nil {
		return nil, fmt.Errorf("audit: loading checkpoints: %w", err)
	}
	if n := len(cps); n > 0 {
		t.latest = cps[n-1]
		t.haveLatest = true
		t.checkpoints = uint64(n)
		t.lastSealUnix = t.latest.SealedAt.Unix()
	}
	// Account records appended since the last checkpoint so size-triggered
	// sealing resumes sensibly.
	t.sinceSeal = len(t.leaves) - int(t.sealedSize())
	if t.sinceSeal < 0 {
		t.sinceSeal = 0
	}
	return t, nil
}

// sealedSize returns the tree size of the latest checkpoint (0 if none). The
// caller must hold t.mu.
func (t *transparencyLog) sealedSize() uint64 {
	if t.haveLatest {
		return t.latest.TreeSize
	}
	return 0
}

// add records a new leaf and seals a checkpoint when the batch threshold is
// reached. The Logger calls it under its own mutex after a durable append.
func (t *transparencyLog) add(ctx context.Context, rec Record) error {
	t.mu.Lock()
	t.leaves = append(t.leaves, recordLeafHash(rec))
	t.sinceSeal++
	due := t.sealEvery > 0 && t.sinceSeal >= t.sealEvery
	t.mu.Unlock()

	if due {
		if _, err := t.seal(ctx); err != nil {
			return err
		}
	}
	return nil
}

// seal computes the Merkle root over every record so far, builds a (optionally
// signed) checkpoint, persists it, and makes it the latest. It is safe to call
// when nothing new has been appended (it re-seals the same size).
func (t *transparencyLog) seal(ctx context.Context) (Checkpoint, error) {
	t.mu.Lock()
	size := len(t.leaves)
	root := merkleRoot(t.leaves)
	cp := Checkpoint{
		Origin:   t.origin,
		TreeSize: uint64(size),
		RootHash: hex.EncodeToString(root),
		SealedAt: t.now().UTC(),
	}
	signer := t.signer
	t.mu.Unlock()

	if signer != nil {
		if err := signer.sign(&cp); err != nil {
			return Checkpoint{}, err
		}
	}
	if err := t.store.Append(ctx, cp); err != nil {
		return Checkpoint{}, fmt.Errorf("audit: persisting checkpoint: %w", err)
	}

	t.mu.Lock()
	t.latest = cp
	t.haveLatest = true
	t.checkpoints++
	t.sinceSeal = 0
	t.lastSealUnix = cp.SealedAt.Unix()
	t.mu.Unlock()
	return cp, nil
}

// latestCheckpoint returns the most recently sealed checkpoint, if any.
func (t *transparencyLog) latestCheckpoint() (Checkpoint, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.latest, t.haveLatest
}

// size returns the current number of records in the tree.
func (t *transparencyLog) size() uint64 {
	t.mu.Lock()
	defer t.mu.Unlock()
	return uint64(len(t.leaves))
}

// inclusionProof builds a proof that the record with sequence number seq (1-based)
// is in the log. The proof is anchored to the latest sealed checkpoint when seq
// is covered by it (so a client can verify against a signed root); otherwise it
// is anchored to the current live tree.
func (t *transparencyLog) inclusionProof(seq uint64) (InclusionProof, error) {
	t.mu.Lock()
	defer t.mu.Unlock()

	n := len(t.leaves)
	if seq == 0 || seq > uint64(n) {
		return InclusionProof{}, fmt.Errorf("audit: no record with sequence %d (log has %d records)", seq, n)
	}
	index := int(seq - 1)

	// Prefer the largest sealed tree that still covers this leaf, so the proof
	// resolves to a signed root.
	treeSize := n
	var anchored *Checkpoint
	if t.haveLatest && t.latest.TreeSize >= seq {
		treeSize = int(t.latest.TreeSize)
		cp := t.latest
		anchored = &cp
	}

	leaves := t.leaves[:treeSize]
	path := inclusionPath(index, leaves)
	root := merkleRoot(leaves)

	return InclusionProof{
		LeafIndex:  uint64(index),
		TreeSize:   uint64(treeSize),
		LeafHash:   hex.EncodeToString(t.leaves[index]),
		RootHash:   hex.EncodeToString(root),
		Path:       toHexSlice(path),
		Checkpoint: anchored,
	}, nil
}

// consistencyProof builds a proof that the prefix of size from is consistent
// with the prefix of size to (from <= to <= current size).
func (t *transparencyLog) consistencyProof(from, to uint64) (ConsistencyProof, error) {
	t.mu.Lock()
	defer t.mu.Unlock()

	n := uint64(len(t.leaves))
	if to == 0 {
		to = n
	}
	if from == 0 || from > to || to > n {
		return ConsistencyProof{}, fmt.Errorf("audit: invalid consistency range from=%d to=%d (log has %d records)", from, to, n)
	}

	path := consistencyPath(int(from), t.leaves[:to])
	firstRoot := merkleRoot(t.leaves[:from])
	secondRoot := merkleRoot(t.leaves[:to])

	return ConsistencyProof{
		FirstSize:  from,
		SecondSize: to,
		FirstRoot:  hex.EncodeToString(firstRoot),
		SecondRoot: hex.EncodeToString(secondRoot),
		Path:       toHexSlice(path),
	}, nil
}

// stats returns a snapshot of the transparency log. chainLength is supplied by
// the Logger (the authoritative sequence counter).
func (t *transparencyLog) stats(chainLength uint64) Stats {
	t.mu.Lock()
	defer t.mu.Unlock()
	st := Stats{
		ChainLength:          chainLength,
		TreeSize:             uint64(len(t.leaves)),
		Checkpoints:          t.checkpoints,
		LastSealUnix:         t.lastSealUnix,
		Signed:               t.signer != nil,
		Origin:               t.origin,
		VerificationFailures: t.verifyFails.Load(),
	}
	if t.signer != nil {
		st.KeyID = t.signer.KeyID()
	}
	return st
}

// recordVerificationFailure increments the verification-failure counter exposed
// to metrics; the admin/CLI verification paths call it when a check fails.
func (t *transparencyLog) recordVerificationFailure() {
	t.verifyFails.Add(1)
}

// toHexSlice hex-encodes each node hash for JSON transport.
func toHexSlice(nodes [][]byte) []string {
	out := make([]string, len(nodes))
	for i, n := range nodes {
		out[i] = hex.EncodeToString(n)
	}
	return out
}

// fromHexSlice decodes a hex-encoded proof path.
func fromHexSlice(hexes []string) ([][]byte, error) {
	out := make([][]byte, len(hexes))
	for i, h := range hexes {
		b, err := hex.DecodeString(h)
		if err != nil {
			return nil, fmt.Errorf("audit: invalid proof node %q: %w", h, err)
		}
		out[i] = b
	}
	return out, nil
}

// VerifyInclusion checks an inclusion proof end-to-end: the leaf hash and the
// audit path must reconstruct to RootHash at the stated index and tree size. It
// returns nil when the record is provably in the log.
func VerifyInclusion(p InclusionProof) error {
	leaf, err := hex.DecodeString(p.LeafHash)
	if err != nil {
		return fmt.Errorf("audit: invalid leaf hash: %w", err)
	}
	root, err := hex.DecodeString(p.RootHash)
	if err != nil {
		return fmt.Errorf("audit: invalid root hash: %w", err)
	}
	path, err := fromHexSlice(p.Path)
	if err != nil {
		return err
	}
	if !verifyInclusion(leaf, int(p.LeafIndex), int(p.TreeSize), path, root) {
		return fmt.Errorf("audit: inclusion proof does not verify for leaf %d in tree of size %d", p.LeafIndex, p.TreeSize)
	}
	return nil
}

// VerifyInclusionForRecord verifies that proof attests to rec specifically, by
// recomputing rec's leaf hash and confirming it matches the proof's leaf before
// verifying the path. This binds the proof to a concrete record.
func VerifyInclusionForRecord(rec Record, p InclusionProof) error {
	want := hex.EncodeToString(recordLeafHash(rec))
	if want != p.LeafHash {
		return fmt.Errorf("audit: proof leaf hash does not match record (seq %d)", rec.Seq)
	}
	return VerifyInclusion(p)
}

// VerifyConsistency checks a consistency proof: that the FirstSize prefix (root
// FirstRoot) is an append-only prefix of the SecondSize tree (root SecondRoot).
func VerifyConsistency(p ConsistencyProof) error {
	first, err := hex.DecodeString(p.FirstRoot)
	if err != nil {
		return fmt.Errorf("audit: invalid first root: %w", err)
	}
	second, err := hex.DecodeString(p.SecondRoot)
	if err != nil {
		return fmt.Errorf("audit: invalid second root: %w", err)
	}
	path, err := fromHexSlice(p.Path)
	if err != nil {
		return err
	}
	if !verifyConsistency(int(p.FirstSize), int(p.SecondSize), path, first, second) {
		return fmt.Errorf("audit: consistency proof does not verify (%d -> %d)", p.FirstSize, p.SecondSize)
	}
	return nil
}

// RootOverRecords recomputes the Merkle root over the given records (ordered by
// sequence) and returns it hex-encoded. It is used by offline verification to
// re-derive the root for a prefix of the log and compare it against a sealed
// checkpoint.
func RootOverRecords(records []Record) string {
	leaves := make([][]byte, len(records))
	for i, rec := range records {
		leaves[i] = recordLeafHash(rec)
	}
	return hex.EncodeToString(merkleRoot(leaves))
}
