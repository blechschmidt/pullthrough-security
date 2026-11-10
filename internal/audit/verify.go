package audit

import (
	"crypto"
	"fmt"
)

// CheckpointVerification is the result of validating a single sealed checkpoint
// against the actual record log.
type CheckpointVerification struct {
	TreeSize    uint64
	RootHash    string
	RootMatches bool   // the recomputed Merkle root over records[:TreeSize] matches RootHash
	Signed      bool   // the checkpoint carried a signature
	SignatureOK bool   // the signature verified (only meaningful when a public key was supplied)
	Consistent  bool   // this checkpoint is an append-only extension of the previous one
	Problem     string // human-readable description of the first failure, if any
}

// OK reports whether the checkpoint passed every applicable check.
func (v CheckpointVerification) OK() bool { return v.Problem == "" }

// VerifyLog cross-checks a set of sealed checkpoints against the actual record
// log: every checkpoint's root must match the Merkle root recomputed over the
// corresponding record prefix, each checkpoint must be a consistent append-only
// extension of the previous one, and (when pub is non-nil) every signature must
// verify. This is the second, key-independent line of defense: even an attacker
// who holds the HMAC key and forges a self-consistent chain cannot make an
// edited prefix match a previously-sealed (and ideally signed) checkpoint root.
//
// records must be ordered by sequence and contiguous. pub may be nil to skip
// signature verification. It returns one result per checkpoint and an overall
// error summarizing the first failure (nil when everything verifies).
func VerifyLog(records []Record, checkpoints []Checkpoint, pub crypto.PublicKey) ([]CheckpointVerification, error) {
	results := make([]CheckpointVerification, 0, len(checkpoints))
	var firstErr error
	note := func(err error) {
		if firstErr == nil {
			firstErr = err
		}
	}

	var prev *Checkpoint
	for i := range checkpoints {
		cp := checkpoints[i]
		res := CheckpointVerification{
			TreeSize: cp.TreeSize,
			RootHash: cp.RootHash,
			Signed:   cp.Signed(),
		}

		switch {
		case cp.TreeSize > uint64(len(records)):
			res.Problem = fmt.Sprintf("checkpoint covers %d records but the log only has %d (records were deleted/truncated)", cp.TreeSize, len(records))
			note(fmt.Errorf("audit: %s", res.Problem))
		default:
			wantRoot := RootOverRecords(records[:cp.TreeSize])
			res.RootMatches = wantRoot == cp.RootHash
			if !res.RootMatches {
				res.Problem = fmt.Sprintf("checkpoint root for tree size %d does not match the log (a record in that prefix was altered)", cp.TreeSize)
				note(fmt.Errorf("audit: %s", res.Problem))
			}
		}

		// Consistency with the previous checkpoint: a later checkpoint must be
		// an append-only extension of the earlier one.
		if prev == nil {
			res.Consistent = true
		} else if res.Problem == "" {
			res.Consistent = checkpointsConsistent(records, *prev, cp)
			if !res.Consistent {
				res.Problem = fmt.Sprintf("checkpoint at tree size %d is not a consistent extension of the one at %d", cp.TreeSize, prev.TreeSize)
				note(fmt.Errorf("audit: %s", res.Problem))
			}
		}

		// Signature verification, when a public key is supplied.
		if pub != nil && cp.Signed() {
			if err := VerifyCheckpointSignature(pub, cp); err != nil {
				res.SignatureOK = false
				if res.Problem == "" {
					res.Problem = "checkpoint signature failed to verify: " + err.Error()
					note(fmt.Errorf("audit: %w", err))
				}
			} else {
				res.SignatureOK = true
			}
		}

		results = append(results, res)
		cpCopy := cp
		prev = &cpCopy
	}

	return results, firstErr
}

// checkpointsConsistent verifies that the prefix of size prev.TreeSize is an
// append-only prefix of the size cp.TreeSize, by generating and checking a
// consistency proof from the actual records.
func checkpointsConsistent(records []Record, prev, cp Checkpoint) bool {
	if prev.TreeSize > cp.TreeSize || cp.TreeSize > uint64(len(records)) {
		return false
	}
	leaves := make([][]byte, cp.TreeSize)
	for i := uint64(0); i < cp.TreeSize; i++ {
		leaves[i] = recordLeafHash(records[i])
	}
	path := consistencyPath(int(prev.TreeSize), leaves)
	firstRoot := merkleRoot(leaves[:prev.TreeSize])
	secondRoot := merkleRoot(leaves)
	return verifyConsistency(int(prev.TreeSize), int(cp.TreeSize), path, firstRoot, secondRoot)
}
