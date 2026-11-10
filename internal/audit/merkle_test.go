package audit

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"testing"
)

// makeLeaves builds n distinct leaf hashes for tree-shape tests.
func makeLeaves(n int) [][]byte {
	leaves := make([][]byte, n)
	for i := 0; i < n; i++ {
		leaves[i] = leafHash([]byte(fmt.Sprintf("leaf-%d", i)))
	}
	return leaves
}

func TestEmptyAndSingleRoot(t *testing.T) {
	empty := sha256.Sum256(nil)
	if !bytes.Equal(merkleRoot(nil), empty[:]) {
		t.Fatalf("empty root mismatch")
	}
	one := makeLeaves(1)
	if !bytes.Equal(merkleRoot(one), one[0]) {
		t.Fatalf("single-leaf root must equal the leaf hash")
	}
}

func TestRootKnownShape(t *testing.T) {
	// For two leaves the root is nodeHash(leaf0, leaf1); verify the manual shape.
	leaves := makeLeaves(2)
	want := nodeHash(leaves[0], leaves[1])
	if !bytes.Equal(merkleRoot(leaves), want) {
		t.Fatalf("2-leaf root shape mismatch")
	}
	// For three leaves, k=2: nodeHash(nodeHash(l0,l1), l2).
	leaves = makeLeaves(3)
	want = nodeHash(nodeHash(leaves[0], leaves[1]), leaves[2])
	if !bytes.Equal(merkleRoot(leaves), want) {
		t.Fatalf("3-leaf root shape mismatch")
	}
}

func TestInclusionProofAllLeaves(t *testing.T) {
	for n := 1; n <= 33; n++ {
		leaves := makeLeaves(n)
		root := merkleRoot(leaves)
		for m := 0; m < n; m++ {
			path := inclusionPath(m, leaves)
			if !verifyInclusion(leaves[m], m, n, path, root) {
				t.Fatalf("inclusion proof failed for leaf %d in tree of %d", m, n)
			}
			// A wrong leaf must not verify against the same path.
			bad := leafHash([]byte("tampered"))
			if verifyInclusion(bad, m, n, path, root) {
				t.Fatalf("tampered leaf %d/%d wrongly verified", m, n)
			}
			// A wrong root must not verify.
			badRoot := append([]byte(nil), root...)
			badRoot[0] ^= 0xff
			if verifyInclusion(leaves[m], m, n, path, badRoot) {
				t.Fatalf("leaf %d/%d verified against wrong root", m, n)
			}
		}
	}
}

func TestConsistencyProofAllPairs(t *testing.T) {
	const maxN = 24
	leaves := makeLeaves(maxN)
	for m := 1; m <= maxN; m++ {
		for n := m; n <= maxN; n++ {
			path := consistencyPath(m, leaves[:n])
			root1 := merkleRoot(leaves[:m])
			root2 := merkleRoot(leaves[:n])
			if !verifyConsistency(m, n, path, root1, root2) {
				t.Fatalf("consistency proof failed for %d -> %d", m, n)
			}
			// A tampered earlier root must break consistency (for m < n; when
			// m == n the proof is empty and only equality is checked).
			if m < n {
				badRoot1 := append([]byte(nil), root1...)
				badRoot1[0] ^= 0xff
				if verifyConsistency(m, n, path, badRoot1, root2) {
					t.Fatalf("consistency %d->%d verified with a tampered first root", m, n)
				}
			}
		}
	}
}

func TestConsistencyDetectsRewrittenPrefix(t *testing.T) {
	// A tree whose earlier prefix was rewritten must fail consistency against
	// the original prefix root.
	orig := makeLeaves(10)
	root1 := merkleRoot(orig[:4])

	rewritten := makeLeaves(10)
	rewritten[2] = leafHash([]byte("rewritten-leaf"))
	root2 := merkleRoot(rewritten)
	path := consistencyPath(4, rewritten)

	if verifyConsistency(4, 10, path, root1, root2) {
		t.Fatalf("consistency must fail when the committed prefix was rewritten")
	}
}

func TestLargestPowerOfTwoLessThan(t *testing.T) {
	cases := map[int]int{2: 1, 3: 2, 4: 2, 5: 4, 7: 4, 8: 4, 9: 8, 16: 8, 17: 16}
	for n, want := range cases {
		if got := largestPowerOfTwoLessThan(n); got != want {
			t.Fatalf("largestPowerOfTwoLessThan(%d)=%d, want %d", n, got, want)
		}
	}
}

func TestRecordLeafHashStableAcrossRoundTrip(t *testing.T) {
	// The leaf hash must be identical whether computed from an in-memory record
	// or one parsed back from its on-disk JSON, so offline verification matches
	// what was sealed.
	rec := Record{Seq: 7, PrevHash: "abc", Hash: "deadbeef", Event: Event{Type: EventPolicy, Subject: "alice"}}
	h1 := hex.EncodeToString(recordLeafHash(rec))

	line, err := json.Marshal(rec)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	recs, err := ParseRecords(string(line))
	if err != nil || len(recs) != 1 {
		t.Fatalf("parse: %v (n=%d)", err, len(recs))
	}
	h2 := hex.EncodeToString(recordLeafHash(recs[0]))
	if h1 != h2 {
		t.Fatalf("leaf hash changed across round-trip: %s != %s", h1, h2)
	}
}
