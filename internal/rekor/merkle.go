package rekor

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"math/bits"
)

// This file implements RFC 6962 Merkle-tree inclusion-proof verification, the
// cryptographic core of transparency-log trust. It is a self-contained port of
// the well-known transparency-dev/merkle algorithm so the proxy carries no extra
// dependency and the logic is unit-testable against golden fixtures.
//
// RFC 6962 hashing:
//
//	leaf hash   = SHA-256(0x00 || leaf_bytes)
//	parent hash = SHA-256(0x01 || left || right)
//
// Rekor's Merkle leaf preimage is the base64-decoded `body` of the log entry.

const hashSize = sha256.Size

// hashLeaf computes the RFC 6962 leaf hash (domain-separated with a 0x00 prefix).
func hashLeaf(leaf []byte) []byte {
	h := sha256.New()
	h.Write([]byte{0x00})
	h.Write(leaf)
	return h.Sum(nil)
}

// hashChildren computes the RFC 6962 interior-node hash of (left, right),
// domain-separated with a 0x01 prefix.
func hashChildren(left, right []byte) []byte {
	h := sha256.New()
	h.Write([]byte{0x01})
	h.Write(left)
	h.Write(right)
	return h.Sum(nil)
}

// verifyInclusion checks a Merkle inclusion proof: that leafHash is the hash of
// the leaf at index within a tree of treeSize leaves whose root is root. proof
// is the ordered list of sibling hashes along the audit path. It returns nil on
// success and a descriptive error otherwise.
func verifyInclusion(index, treeSize uint64, leafHash []byte, proof [][]byte, root []byte) error {
	calc, err := rootFromInclusionProof(index, treeSize, leafHash, proof)
	if err != nil {
		return err
	}
	if !bytes.Equal(calc, root) {
		return fmt.Errorf("rekor: inclusion proof does not reconstruct the signed root hash")
	}
	return nil
}

// rootFromInclusionProof recomputes the Merkle root implied by a leaf and its
// audit path, following RFC 6962 §2.1.1. It validates the proof length so a
// truncated or padded path is rejected rather than silently mis-hashed.
func rootFromInclusionProof(index, treeSize uint64, leafHash []byte, proof [][]byte) ([]byte, error) {
	if index >= treeSize {
		return nil, fmt.Errorf("rekor: leaf index %d is out of range for tree size %d", index, treeSize)
	}
	if len(leafHash) != hashSize {
		return nil, fmt.Errorf("rekor: leaf hash has size %d, want %d", len(leafHash), hashSize)
	}

	inner, border := decompInclProof(index, treeSize)
	if got, want := len(proof), int(inner+border); got != want {
		return nil, fmt.Errorf("rekor: inclusion proof has %d hashes, want %d for index %d / size %d", got, want, index, treeSize)
	}
	for i, h := range proof {
		if len(h) != hashSize {
			return nil, fmt.Errorf("rekor: inclusion proof hash[%d] has size %d, want %d", i, len(h), hashSize)
		}
	}

	res := runInner(inner, leafHash, index, proof)
	for _, h := range proof[inner:] {
		res = hashChildren(h, res)
	}
	return res, nil
}

// decompInclProof splits the proof into its inner (bottom, below the lowest
// perfect subtree boundary) and border (top) segments.
func decompInclProof(index, size uint64) (inner, border uint64) {
	inner = innerProofSize(index, size)
	border = uint64(bits.OnesCount64(index >> inner))
	return inner, border
}

// innerProofSize is the number of inner nodes in the proof for a leaf at index
// in a tree of the given size.
func innerProofSize(index, size uint64) uint64 {
	return uint64(bits.Len64(index ^ (size - 1)))
}

// runInner folds the inner (bottom) segment of the proof into the running hash,
// choosing left/right at each level from the corresponding bit of index.
func runInner(inner uint64, seed []byte, index uint64, proof [][]byte) []byte {
	res := seed
	for i := uint64(0); i < inner; i++ {
		h := proof[i]
		if (index>>i)&1 == 0 {
			res = hashChildren(res, h)
		} else {
			res = hashChildren(h, res)
		}
	}
	return res
}
