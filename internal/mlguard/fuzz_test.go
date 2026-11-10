//go:build fuzz
// +build fuzz

// Fuzz target for the ML weight pickle-opcode scanner (Task 30, Task 110).
//
// scanPickle consumes attacker-controlled model-weight bytes on the pull path, so
// it must never panic, must stay within its opcode/memory budget, and must fail
// closed (stop at the first malformed opcode) on hostile input.
//
// Build-tag gated (`fuzz`). Run e.g.:
//
//	go test -tags fuzz -run=^$ -fuzz=FuzzScanPickle ./internal/mlguard/
package mlguard

import "testing"

func FuzzScanPickle(f *testing.F) {
	f.Add(reducePickle("os", "system", "echo pwned"))
	f.Add(stackGlobalPickle("subprocess", "Popen"))
	f.Add(benignTorchPickle())
	f.Add([]byte{})
	f.Add([]byte{opProto})
	f.Add([]byte{opGlobal, 'o', 's'})
	f.Add([]byte{opShortBinU, 0xff, 'a'})

	f.Fuzz(func(t *testing.T, data []byte) {
		sc := scanPickle(data)
		if sc.OpcodeCount > maxOpcodes {
			t.Fatalf("opcode budget exceeded: %d", sc.OpcodeCount)
		}
		for _, g := range sc.Globals {
			// Classification must be safe for any extracted import.
			_, _, _ = classifyGlobal(g)
		}
	})
}
