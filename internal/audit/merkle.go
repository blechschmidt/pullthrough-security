package audit

import (
	"bytes"
	"crypto/sha256"
)

// This file implements an RFC 6962 ("Certificate Transparency") binary Merkle
// tree over the audit log's records. The hash-chain in audit.go makes any edit
// to a record detectable to anyone holding the HMAC key; the Merkle tree adds a
// second, independent guarantee: a small, periodically-signed checkpoint (the
// tree root over a prefix of the log) lets anyone — even without the HMAC key —
// detect a retroactive edit, deletion, or reordering, because the recomputed
// root will no longer match the signed checkpoint. It also yields compact
// inclusion proofs (a specific event is in the log) and consistency proofs (a
// later log is an append-only extension of an earlier one).
//
// The two domain-separated hash functions are exactly those of RFC 6962:
//
//	leaf hash:  SHA-256(0x00 || leaf-data)
//	node hash:  SHA-256(0x01 || left-hash || right-hash)
//
// All functions below operate on the precomputed leaf hashes ([][]byte), so the
// leaf-data encoding (recordLeafData) is the single place that decides what a
// record commits to.

// rfc6962LeafPrefix and rfc6962NodePrefix are the domain-separation tags.
const (
	rfc6962LeafPrefix = 0x00
	rfc6962NodePrefix = 0x01
)

// leafHash returns SHA-256(0x00 || data) — the Merkle tree hash of a single leaf.
func leafHash(data []byte) []byte {
	h := sha256.New()
	h.Write([]byte{rfc6962LeafPrefix})
	h.Write(data)
	return h.Sum(nil)
}

// nodeHash returns SHA-256(0x01 || left || right) — the hash of an interior node.
func nodeHash(left, right []byte) []byte {
	h := sha256.New()
	h.Write([]byte{rfc6962NodePrefix})
	h.Write(left)
	h.Write(right)
	return h.Sum(nil)
}

// emptyRootHash is the Merkle tree hash of an empty log: SHA-256 of the empty
// string, per RFC 6962.
func emptyRootHash() []byte {
	sum := sha256.Sum256(nil)
	return sum[:]
}

// largestPowerOfTwoLessThan returns the largest power of two strictly smaller
// than n (n >= 2). It is the split point k used throughout RFC 6962's recursive
// definitions.
func largestPowerOfTwoLessThan(n int) int {
	k := 1
	for k<<1 < n {
		k <<= 1
	}
	return k
}

// merkleRoot computes the Merkle Tree Hash (MTH) over the precomputed leaf
// hashes, per RFC 6962 §2.1.
func merkleRoot(leaves [][]byte) []byte {
	n := len(leaves)
	switch {
	case n == 0:
		return emptyRootHash()
	case n == 1:
		// leaves[i] is already a leaf hash, so MTH({d}) == leaves[0].
		return leaves[0]
	}
	k := largestPowerOfTwoLessThan(n)
	return nodeHash(merkleRoot(leaves[:k]), merkleRoot(leaves[k:]))
}

// inclusionPath returns the audit path proving that the leaf at index m is part
// of the tree formed by leaves, per RFC 6962 §2.1.1 (PATH).
func inclusionPath(m int, leaves [][]byte) [][]byte {
	n := len(leaves)
	if n <= 1 {
		return nil
	}
	k := largestPowerOfTwoLessThan(n)
	if m < k {
		return append(inclusionPath(m, leaves[:k]), merkleRoot(leaves[k:]))
	}
	return append(inclusionPath(m-k, leaves[k:]), merkleRoot(leaves[:k]))
}

// verifyInclusion checks an audit path: that leaf (a leaf hash) at index m in a
// tree of size n reconstructs to root, per RFC 6962 §2.1.1's verification
// procedure.
func verifyInclusion(leaf []byte, m, n int, path [][]byte, root []byte) bool {
	if m >= n {
		return false
	}
	fn, sn := m, n-1
	r := append([]byte(nil), leaf...)
	for _, p := range path {
		if fn == sn || fn&1 == 1 {
			r = nodeHash(p, r)
			for fn&1 == 0 {
				fn >>= 1
				sn >>= 1
			}
		} else {
			r = nodeHash(r, p)
		}
		fn >>= 1
		sn >>= 1
	}
	return sn == 0 && bytes.Equal(r, root)
}

// consistencyPath returns the consistency proof between an earlier tree of size
// m and the current tree (leaves), per RFC 6962 §2.1.2 (PROOF / SUBPROOF).
func consistencyPath(m int, leaves [][]byte) [][]byte {
	n := len(leaves)
	if m <= 0 || m > n {
		return nil
	}
	if m == n {
		return nil
	}
	return subProof(m, leaves, true)
}

// subProof implements RFC 6962 §2.1.2's SUBPROOF recursion. b indicates whether
// the earlier tree (size m) is a complete subtree of the current node's range.
func subProof(m int, leaves [][]byte, b bool) [][]byte {
	n := len(leaves)
	if m == n {
		if b {
			return nil
		}
		return [][]byte{merkleRoot(leaves)}
	}
	k := largestPowerOfTwoLessThan(n)
	if m <= k {
		return append(subProof(m, leaves[:k], b), merkleRoot(leaves[k:]))
	}
	return append(subProof(m-k, leaves[k:], false), merkleRoot(leaves[:k]))
}

// verifyConsistency checks a consistency proof: that a tree of size m with root
// root1 is a prefix of a tree of size n with root root2. This is the standard
// RFC 6962 verification (matching the reference implementations in Trillian).
func verifyConsistency(m, n int, proof [][]byte, root1, root2 []byte) bool {
	switch {
	case m < 0 || m > n:
		return false
	case m == n:
		return len(proof) == 0 && bytes.Equal(root1, root2)
	case m == 0:
		// Every tree is consistent with the empty tree; no proof nodes needed.
		return len(proof) == 0
	case len(proof) == 0:
		return false
	}

	// Find the first node on the path from leaf m-1 that is a left child (an
	// even index after right-shifting away the trailing ones).
	node := m - 1
	last := n - 1
	for node&1 == 1 {
		node >>= 1
		last >>= 1
	}

	i := 0
	var h1, h2 []byte
	if node > 0 {
		// The earlier tree is not itself a complete subtree; the first proof
		// node seeds both reconstructions.
		h1 = proof[i]
		h2 = proof[i]
		i++
	} else {
		// The earlier tree is a complete subtree: root1 is the seed.
		h1 = root1
		h2 = root1
	}

	for node > 0 {
		if node&1 == 1 {
			if i >= len(proof) {
				return false
			}
			c := proof[i]
			i++
			h1 = nodeHash(c, h1)
			h2 = nodeHash(c, h2)
		} else if node < last {
			if i >= len(proof) {
				return false
			}
			c := proof[i]
			i++
			h2 = nodeHash(h2, c)
		}
		node >>= 1
		last >>= 1
	}

	for last > 0 {
		if i >= len(proof) {
			return false
		}
		c := proof[i]
		i++
		h2 = nodeHash(h2, c)
		last >>= 1
	}

	return i == len(proof) && bytes.Equal(h1, root1) && bytes.Equal(h2, root2)
}

// recordLeafData returns the bytes a record commits to as a Merkle leaf. We use
// the record's keyed chain Hash: it already binds Seq, the full Event, and
// PrevHash (via the HMAC in computeHash), and as a hex string it round-trips
// byte-for-byte through the on-disk JSON, so a leaf recomputed by the offline
// verifier matches the one sealed at append time exactly.
func recordLeafData(rec Record) []byte {
	return []byte(rec.Hash)
}

// recordLeafHash returns the Merkle leaf hash for a record.
func recordLeafHash(rec Record) []byte {
	return leafHash(recordLeafData(rec))
}
