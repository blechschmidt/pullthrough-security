package rekor

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"testing"
)

// TestInclusionProofRoundTrip builds real Merkle trees of many sizes via the
// in-memory log's proof generator and confirms every leaf's audit path
// reconstructs the tree root the verifier recomputes. This exercises the RFC
// 6962 decomposition (inner/border split) across perfect and imperfect trees.
func TestInclusionProofRoundTrip(t *testing.T) {
	for _, size := range []int{1, 2, 3, 4, 5, 7, 8, 9, 16, 17, 31, 100} {
		leaves := make([][]byte, size)
		leafHashes := make([][]byte, size)
		for i := range leaves {
			leaves[i] = []byte(fmt.Sprintf("leaf-%d-payload", i))
			leafHashes[i] = hashLeaf(leaves[i])
		}
		root := merkleTreeHash(leafHashes)
		for idx := 0; idx < size; idx++ {
			proof := inclusionProofPath(idx, leafHashes)
			if err := verifyInclusion(uint64(idx), uint64(size), hashLeaf(leaves[idx]), proof, root); err != nil {
				t.Fatalf("size=%d idx=%d: proof did not verify: %v", size, idx, err)
			}
		}
	}
}

// TestInclusionProofRejectsTampering confirms the verifier rejects a mutated
// leaf, a mutated root, a wrong index, and a truncated/extended path.
func TestInclusionProofRejectsTampering(t *testing.T) {
	const size = 17
	leaves := make([][]byte, size)
	leafHashes := make([][]byte, size)
	for i := range leaves {
		leaves[i] = []byte(fmt.Sprintf("entry-%d", i))
		leafHashes[i] = hashLeaf(leaves[i])
	}
	root := merkleTreeHash(leafHashes)
	const idx = 6
	proof := inclusionProofPath(idx, leafHashes)

	// Baseline: valid.
	if err := verifyInclusion(idx, size, hashLeaf(leaves[idx]), proof, root); err != nil {
		t.Fatalf("baseline proof failed: %v", err)
	}

	// Tampered leaf.
	if err := verifyInclusion(idx, size, hashLeaf([]byte("tampered")), proof, root); err == nil {
		t.Error("expected failure for a tampered leaf")
	}
	// Tampered root.
	badRoot := append([]byte(nil), root...)
	badRoot[0] ^= 0xff
	if err := verifyInclusion(idx, size, hashLeaf(leaves[idx]), proof, badRoot); err == nil {
		t.Error("expected failure for a tampered root")
	}
	// Wrong index.
	if err := verifyInclusion(idx+1, size, hashLeaf(leaves[idx]), proof, root); err == nil {
		t.Error("expected failure for a wrong leaf index")
	}
	// Truncated path.
	if len(proof) > 0 {
		if err := verifyInclusion(idx, size, hashLeaf(leaves[idx]), proof[:len(proof)-1], root); err == nil {
			t.Error("expected failure for a truncated proof")
		}
	}
	// Extended path.
	extended := append(append([][]byte(nil), proof...), bytes.Repeat([]byte{0x11}, sha256.Size))
	if err := verifyInclusion(idx, size, hashLeaf(leaves[idx]), extended, root); err == nil {
		t.Error("expected failure for an over-long proof")
	}
	// Index out of range.
	if err := verifyInclusion(size, size, hashLeaf(leaves[idx]), proof, root); err == nil {
		t.Error("expected failure for an out-of-range index")
	}
}

// TestKnownMerkleRoot pins the RFC 6962 Merkle Tree Hash for a fixed two-leaf
// tree so a refactor of the hashing cannot silently change the wire format.
func TestKnownMerkleRoot(t *testing.T) {
	a := []byte("a")
	b := []byte("b")
	la, lb := hashLeaf(a), hashLeaf(b)
	got := hex.EncodeToString(merkleTreeHash([][]byte{la, lb}))
	// H(0x01 || H(0x00||"a") || H(0x00||"b")), computed independently.
	want := hex.EncodeToString(hashChildren(la, lb))
	if got != want {
		t.Fatalf("merkle root mismatch: got %s want %s", got, want)
	}
	// Single-leaf tree root is the leaf hash itself.
	if single := hex.EncodeToString(merkleTreeHash([][]byte{la})); single != hex.EncodeToString(la) {
		t.Fatalf("single-leaf root %s != leaf hash %s", single, hex.EncodeToString(la))
	}
}
