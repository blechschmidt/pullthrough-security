package rekor

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"sync"
	"time"
)

// FakeLog is an in-memory Sigstore-Rekor-compatible transparency log: a genuine
// append-only RFC 6962 Merkle tree that signs real Signed Entry Timestamps and
// produces real inclusion proofs. It implements Client, so the full submit →
// record → verify round trip is exercised in tests (and used to generate the
// committed golden fixtures) with no network and no external tooling.
//
// It is shipped in the package (not a _test.go file) deliberately: sibling
// packages' tests — attestbundle, selfrelease, sigverify — wire it as the Rekor
// Client to prove their integration end to end against a log whose entries this
// package's own Verifier accepts.
type FakeLog struct {
	mu     sync.Mutex
	key    *ecdsa.PrivateKey
	logID  string
	now    func() time.Time
	leaves [][]byte // leaf preimages (entry bodies), in append order
}

// NewFakeLog constructs an empty fake log with a fresh P-256 log key. now may be
// nil (uses time.Now).
func NewFakeLog(now func() time.Time) *FakeLog {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic("rekor: generating fake log key: " + err.Error())
	}
	if now == nil {
		now = time.Now
	}
	// The log ID is the hex SHA-256 of the DER public key, matching Rekor's
	// convention.
	der, _ := x509.MarshalPKIXPublicKey(&key.PublicKey)
	sum := sha256.Sum256(der)
	return &FakeLog{key: key, logID: hex.EncodeToString(sum[:]), now: now}
}

// PublicKey returns the log's signing public key, for building a Verifier.
func (f *FakeLog) PublicKey() crypto.PublicKey { return &f.key.PublicKey }

// PublicKeyPEM returns the log public key as a PEM PUBLIC KEY block.
func (f *FakeLog) PublicKeyPEM() []byte {
	der, _ := x509.MarshalPKIXPublicKey(&f.key.PublicKey)
	return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
}

// Verifier returns a Verifier trusting this log's key.
func (f *FakeLog) Verifier() *Verifier { return NewVerifier([]crypto.PublicKey{&f.key.PublicKey}) }

// LogID returns the log's identifier.
func (f *FakeLog) LogID() string { return f.logID }

// Submit implements Client: it appends the envelope as a new leaf and returns a
// log entry carrying a valid SET and inclusion proof for the resulting tree.
func (f *FakeLog) Submit(_ context.Context, req SubmitRequest) (*LogEntry, error) {
	if len(req.Envelope) == 0 {
		return nil, fmt.Errorf("rekor: fake submit requires an envelope")
	}
	return f.Append(req.Envelope), nil
}

// Append adds leafBytes to the log and returns the corresponding entry (SET +
// inclusion proof for the tree as it stands after the append). Exported so a
// fixture generator can drive the log directly.
func (f *FakeLog) Append(leafBytes []byte) *LogEntry {
	f.mu.Lock()
	defer f.mu.Unlock()

	index := int64(len(f.leaves))
	f.leaves = append(f.leaves, append([]byte(nil), leafBytes...))
	treeSize := int64(len(f.leaves))

	entry := &LogEntry{
		UUID:           hex.EncodeToString(hashLeaf(leafBytes)),
		LogID:          f.logID,
		LogIndex:       index,
		Body:           base64.StdEncoding.EncodeToString(leafBytes),
		IntegratedTime: f.now().Unix(),
	}

	// Build the inclusion proof against the current tree.
	leafHashes := f.leafHashesLocked()
	proof := inclusionProofPath(int(index), leafHashes)
	root := merkleTreeHash(leafHashes)
	hexHashes := make([]string, len(proof))
	for i, h := range proof {
		hexHashes[i] = hex.EncodeToString(h)
	}
	entry.InclusionProof = &InclusionProof{
		LogIndex: index,
		RootHash: hex.EncodeToString(root),
		TreeSize: treeSize,
		Hashes:   hexHashes,
	}

	// Sign the Signed Entry Timestamp over the canonical payload.
	set := f.signSET(entry)
	entry.SET = base64.StdEncoding.EncodeToString(set)
	return entry
}

func (f *FakeLog) leafHashesLocked() [][]byte {
	out := make([][]byte, len(f.leaves))
	for i, l := range f.leaves {
		out[i] = hashLeaf(l)
	}
	return out
}

func (f *FakeLog) signSET(entry *LogEntry) []byte {
	msg := canonicalSETPayload(entry)
	digest := sha256.Sum256(msg)
	sig, err := ecdsa.SignASN1(rand.Reader, f.key, digest[:])
	if err != nil {
		panic("rekor: signing fake SET: " + err.Error())
	}
	return sig
}

// merkleTreeHash computes the RFC 6962 Merkle Tree Hash over a slice of
// already-leaf-hashed nodes.
func merkleTreeHash(leafHashes [][]byte) []byte {
	n := len(leafHashes)
	switch n {
	case 0:
		empty := sha256.Sum256(nil)
		return empty[:]
	case 1:
		return leafHashes[0]
	}
	k := largestPowerOfTwoLessThan(n)
	left := merkleTreeHash(leafHashes[:k])
	right := merkleTreeHash(leafHashes[k:])
	return hashChildren(left, right)
}

// inclusionProofPath computes the RFC 6962 audit path for the leaf at index m in
// a tree whose leaf hashes are given. The returned order (inner siblings first,
// then the border) is exactly what rootFromInclusionProof consumes.
func inclusionProofPath(m int, leafHashes [][]byte) [][]byte {
	n := len(leafHashes)
	if n <= 1 {
		return nil
	}
	k := largestPowerOfTwoLessThan(n)
	if m < k {
		sub := inclusionProofPath(m, leafHashes[:k])
		return append(sub, merkleTreeHash(leafHashes[k:]))
	}
	sub := inclusionProofPath(m-k, leafHashes[k:])
	return append(sub, merkleTreeHash(leafHashes[:k]))
}

// largestPowerOfTwoLessThan returns the largest power of two strictly less than
// n (n must be >= 2).
func largestPowerOfTwoLessThan(n int) int {
	k := 1
	for k < n {
		k <<= 1
	}
	return k >> 1
}
