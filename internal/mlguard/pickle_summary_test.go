package mlguard

import (
	"bytes"
	"fmt"
	"math/rand"
	"reflect"
	"slices"
	"strings"
	"testing"
)

// SummarizePickle is the read-only view of a pickle that other gates show a
// reviewer: the LLM package-content scan renders it, in the proxy's own voice,
// as "this pickle imports … and calls …". These tests pin what that statement
// rests on: the imports a stream names (GLOBAL, INST, STACK_GLOBAL), the opcodes
// that call them, and that a walk which did not see the whole stream says so.
//
// Nothing here is ever unpickled. The hand-built streams reuse the helpers of
// pickle_test.go; the literals below were written by CPython 3.12
// (pickle.dumps) and are embedded so the tests need no interpreter.
const (
	// {"weights": [1.0, 2.0], "name": "demo", "n": 3} under each binary protocol.
	psDataP2 = "\x80\x02}q\x00(X\x07\x00\x00\x00weightsq\x01]q\x02(G?\xf0\x00\x00\x00\x00\x00\x00G@\x00\x00\x00\x00\x00\x00\x00eX\x04\x00\x00\x00nameq\x03X\x04\x00\x00\x00demoq\x04X\x01\x00\x00\x00nq\x05K\x03u."
	psDataP3 = "\x80\x03}q\x00(X\x07\x00\x00\x00weightsq\x01]q\x02(G?\xf0\x00\x00\x00\x00\x00\x00G@\x00\x00\x00\x00\x00\x00\x00eX\x04\x00\x00\x00nameq\x03X\x04\x00\x00\x00demoq\x04X\x01\x00\x00\x00nq\x05K\x03u."
	psDataP4 = "\x80\x04\x959\x00\x00\x00\x00\x00\x00\x00}\x94(\x8c\x07weights\x94]\x94(G?\xf0\x00\x00\x00\x00\x00\x00G@\x00\x00\x00\x00\x00\x00\x00e\x8c\x04name\x94\x8c\x04demo\x94\x8c\x01n\x94K\x03u."
	psDataP5 = "\x80\x05\x959\x00\x00\x00\x00\x00\x00\x00}\x94(\x8c\x07weights\x94]\x94(G?\xf0\x00\x00\x00\x00\x00\x00G@\x00\x00\x00\x00\x00\x00\x00e\x8c\x04name\x94\x8c\x04demo\x94\x8c\x01n\x94K\x03u."

	// collections.OrderedDict(a=1).
	psOrderedDictP2 = "\x80\x02ccollections\nOrderedDict\nq\x00)Rq\x01X\x01\x00\x00\x00aq\x02K\x01s."
	psOrderedDictP4 = "\x80\x04\x95)\x00\x00\x00\x00\x00\x00\x00\x8c\x0bcollections\x94\x8c\x0bOrderedDict\x94\x93\x94)R\x94\x8c\x01a\x94K\x01s."

	// Objects whose __reduce__ returns (os.system, ("echo pwned",)),
	// (subprocess.Popen, (["echo", "pwned"],)) and (eval, ("1+1",)). CPython
	// writes os.system under its real module (posix) and, under protocol 2, maps
	// subprocess and builtins to their Python 2 names.
	psSystemP2 = "\x80\x02cposix\nsystem\nq\x00X\x0a\x00\x00\x00echo pwnedq\x01\x85q\x02Rq\x03."
	psSystemP4 = "\x80\x04\x95%\x00\x00\x00\x00\x00\x00\x00\x8c\x05posix\x94\x8c\x06system\x94\x93\x94\x8c\x0aecho pwned\x94\x85\x94R\x94."
	psPopenP2  = "\x80\x02ccommands\nPopen\nq\x00]q\x01(X\x04\x00\x00\x00echoq\x02X\x05\x00\x00\x00pwnedq\x03e\x85q\x04Rq\x05."
	psPopenP4  = "\x80\x04\x95/\x00\x00\x00\x00\x00\x00\x00\x8c\x0asubprocess\x94\x8c\x05Popen\x94\x93\x94]\x94(\x8c\x04echo\x94\x8c\x05pwned\x94e\x85\x94R\x94."
	psEvalP2   = "\x80\x02c__builtin__\neval\nq\x00X\x03\x00\x00\x001+1q\x01\x85q\x02Rq\x03."
	psEvalP4   = "\x80\x04\x95\x1f\x00\x00\x00\x00\x00\x00\x00\x8c\x08builtins\x94\x8c\x04eval\x94\x93\x94\x8c\x031+1\x94\x85\x94R\x94."
)

// psCalls is the call opcodes a summary reports, as one comparable value.
type psCalls struct{ Reduce, Build, Inst, NewObj bool }

func psCallsOf(s PickleSummary) psCalls {
	return psCalls{Reduce: s.Reduce, Build: s.Build, Inst: s.Inst, NewObj: s.NewObj}
}

// psDangerous reports whether the gate's own classifier flags an import the
// summary names. The import is split at its last dot, which is exact for every
// name used here.
func psDangerous(imp string) bool {
	i := strings.LastIndexByte(imp, '.')
	if i < 0 {
		return false
	}
	_, _, ok := classifyGlobal(globalRef{Module: imp[:i], Name: imp[i+1:]})
	return ok
}

// psCorpus is every well-formed stream these tests use.
func psCorpus() map[string][]byte {
	return map[string][]byte{
		"data p2":               []byte(psDataP2),
		"data p3":               []byte(psDataP3),
		"data p4":               []byte(psDataP4),
		"data p5":               []byte(psDataP5),
		"OrderedDict p2":        []byte(psOrderedDictP2),
		"OrderedDict p4":        []byte(psOrderedDictP4),
		"torch weights":         benignTorchPickle(),
		"os.system p2":          []byte(psSystemP2),
		"os.system p4":          []byte(psSystemP4),
		"subprocess.Popen p2":   []byte(psPopenP2),
		"subprocess.Popen p4":   []byte(psPopenP4),
		"eval p2":               []byte(psEvalP2),
		"eval p4":               []byte(psEvalP4),
		"GLOBAL os.system":      reducePickle("os", "system", "echo pwned"),
		"STACK_GLOBAL os.popen": stackGlobalPickle("os", "popen"),
	}
}

// A pickle that holds data, or builds the containers and tensors a weight file
// is made of, names no dangerous callable — and the summary says exactly what
// it does name.
func TestSummarizePickleBenign(t *testing.T) {
	for _, tc := range []struct {
		name    string
		data    []byte
		imports []string
		calls   psCalls
		opcodes int // 0: not pinned
	}{
		{"plain data, protocol 2", []byte(psDataP2), nil, psCalls{}, 0},
		{"plain data, protocol 3", []byte(psDataP3), nil, psCalls{}, 0},
		{"plain data, protocol 4", []byte(psDataP4), nil, psCalls{}, 0},
		{"plain data, protocol 5", []byte(psDataP5), nil, psCalls{}, 0},
		{"the smallest pickle", []byte{opProto, 2, opNone, opStop}, nil, psCalls{}, 3},
		{"no PROTO opcode (protocol 0)", []byte("(dp0\nVn\np1\nI3\ns."), nil, psCalls{}, 0},
		{"OrderedDict, protocol 2 (GLOBAL)", []byte(psOrderedDictP2), []string{"collections.OrderedDict"}, psCalls{Reduce: true}, 0},
		{"OrderedDict, protocol 4 (STACK_GLOBAL)", []byte(psOrderedDictP4), []string{"collections.OrderedDict"}, psCalls{Reduce: true}, 0},
		{"torch weights", benignTorchPickle(), []string{"collections.OrderedDict", "torch._utils._rebuild_tensor_v2"}, psCalls{Reduce: true}, 8},
	} {
		got := SummarizePickle(tc.data)
		if !slices.Equal(got.Imports, tc.imports) {
			t.Errorf("%s: Imports = %q, want %q", tc.name, got.Imports, tc.imports)
		}
		if calls := psCallsOf(got); calls != tc.calls {
			t.Errorf("%s: call opcodes = %+v, want %+v", tc.name, calls, tc.calls)
		}
		if got.Truncated {
			t.Errorf("%s: a complete stream was reported as cut short", tc.name)
		}
		if got.Opcodes <= 0 || (tc.opcodes != 0 && got.Opcodes != tc.opcodes) {
			t.Errorf("%s: Opcodes = %d, want %d", tc.name, got.Opcodes, tc.opcodes)
		}
		for _, imp := range got.Imports {
			if psDangerous(imp) {
				t.Errorf("%s: import %q of a benign pickle is one the gate flags", tc.name, imp)
			}
		}
	}
}

// The pickles the gate exists for: a code-execution primitive imported by
// GLOBAL, INST or STACK_GLOBAL and invoked when the file is loaded. The summary
// names the callable and the opcode that calls it.
func TestSummarizePickleDangerousImports(t *testing.T) {
	for _, tc := range []struct {
		name    string
		data    []byte
		imports []string
		calls   psCalls
		opcodes int // 0: not pinned
	}{
		// Hand-built, as an attacker would.
		{"os.system, GLOBAL + REDUCE", reducePickle("os", "system", "echo pwned"), []string{"os.system"}, psCalls{Reduce: true}, 7},
		{"subprocess.Popen, GLOBAL + REDUCE", reducePickle("subprocess", "Popen", "echo pwned"), []string{"subprocess.Popen"}, psCalls{Reduce: true}, 7},
		{"builtins.eval, GLOBAL + REDUCE", reducePickle("builtins", "eval", "__import__('os').system('echo pwned')"), []string{"builtins.eval"}, psCalls{Reduce: true}, 7},
		{"os.system, STACK_GLOBAL + REDUCE", stackGlobalPickle("os", "system"), []string{"os.system"}, psCalls{Reduce: true}, 8},
		{"subprocess.Popen, STACK_GLOBAL + REDUCE", stackGlobalPickle("subprocess", "Popen"), []string{"subprocess.Popen"}, psCalls{Reduce: true}, 8},
		{"builtins.eval, STACK_GLOBAL + REDUCE", stackGlobalPickle("builtins", "eval"), []string{"builtins.eval"}, psCalls{Reduce: true}, 8},
		{"builtins.exec, STACK_GLOBAL + REDUCE", stackGlobalPickle("builtins", "exec"), []string{"builtins.exec"}, psCalls{Reduce: true}, 8},
		// The other ways a stream imports and calls.
		{"os.system, INST", []byte("\x80\x02(S'echo pwned'\nios\nsystem\n."), []string{"os.system"}, psCalls{Inst: true}, 5},
		{"os.system, GLOBAL + OBJ", []byte("\x80\x02(cos\nsystem\nS'echo pwned'\no."), []string{"os.system"}, psCalls{Inst: true}, 6},
		{"subprocess.Popen, GLOBAL + NEWOBJ", []byte("\x80\x02csubprocess\nPopen\nS'echo pwned'\n\x85\x81."), []string{"subprocess.Popen"}, psCalls{NewObj: true}, 6},
		{"subprocess.Popen, GLOBAL + NEWOBJ_EX", []byte("\x80\x04csubprocess\nPopen\n)}\x92."), []string{"subprocess.Popen"}, psCalls{NewObj: true}, 6},
		{"GLOBAL + REDUCE + BUILD", []byte("\x80\x02cos\nsystem\n)R}b."), []string{"os.system"}, psCalls{Reduce: true, Build: true}, 7},
		// Protocol 0, as text: no PROTO opcode at all.
		{"os.system, protocol 0", []byte("cos\nsystem\n(S'echo pwned'\ntR."), []string{"os.system"}, psCalls{Reduce: true}, 6},
		// Padding around a name does not keep it from being named as what it is.
		{"os.system, padded names", []byte("\x80\x02c os \r\n\tsystem \n)R."), []string{"os.system"}, psCalls{Reduce: true}, 5},
		// What CPython writes for an object whose __reduce__ names the callable.
		{"CPython: os.system, protocol 2", []byte(psSystemP2), []string{"posix.system"}, psCalls{Reduce: true}, 0},
		{"CPython: os.system, protocol 4", []byte(psSystemP4), []string{"posix.system"}, psCalls{Reduce: true}, 15},
		{"CPython: subprocess.Popen, protocol 2", []byte(psPopenP2), []string{"commands.Popen"}, psCalls{Reduce: true}, 0},
		{"CPython: subprocess.Popen, protocol 4", []byte(psPopenP4), []string{"subprocess.Popen"}, psCalls{Reduce: true}, 0},
		{"CPython: eval, protocol 2", []byte(psEvalP2), []string{"__builtin__.eval"}, psCalls{Reduce: true}, 0},
		{"CPython: eval, protocol 4", []byte(psEvalP4), []string{"builtins.eval"}, psCalls{Reduce: true}, 0},
	} {
		got := SummarizePickle(tc.data)
		if !slices.Equal(got.Imports, tc.imports) {
			t.Errorf("%s: Imports = %q, want %q", tc.name, got.Imports, tc.imports)
		}
		if calls := psCallsOf(got); calls != tc.calls {
			t.Errorf("%s: call opcodes = %+v, want %+v", tc.name, calls, tc.calls)
		}
		if got.Truncated {
			t.Errorf("%s: a complete stream was reported as cut short", tc.name)
		}
		if tc.opcodes != 0 && got.Opcodes != tc.opcodes {
			t.Errorf("%s: Opcodes = %d, want %d", tc.name, got.Opcodes, tc.opcodes)
		}
		// What the summary names is what the gate's classifier judges.
		for _, imp := range got.Imports {
			if !psDangerous(imp) {
				t.Errorf("%s: import %q is not one the gate flags", tc.name, imp)
			}
		}
	}
}

// Imports are listed once each, in the order the stream names them — whichever
// opcode names them.
func TestSummarizePickleImportsInStreamOrderWithoutDuplicates(t *testing.T) {
	var b bytes.Buffer
	b.Write([]byte{opProto, 4})
	b.Write(globalV0("collections", "OrderedDict"))
	b.Write(shortUnicode("torch._utils"))
	b.Write(shortUnicode("_rebuild_tensor_v2"))
	b.WriteByte(opStackGlobal)
	b.Write(globalV0("os", "system"))
	b.Write(globalV0("collections", "OrderedDict")) // again
	b.WriteString("(inumpy\ndtype\n")               // INST
	b.Write(shortUnicode("os"))
	b.Write(shortUnicode("system"))
	b.WriteByte(opStackGlobal) // again, by another opcode
	b.Write(globalV0("builtins", "eval"))
	b.WriteByte(opStop)

	got := SummarizePickle(b.Bytes())
	want := []string{"collections.OrderedDict", "torch._utils._rebuild_tensor_v2", "os.system", "numpy.dtype", "builtins.eval"}
	if !slices.Equal(got.Imports, want) {
		t.Errorf("Imports = %q, want %q", got.Imports, want)
	}
	if got.Truncated || !got.Inst || got.Reduce {
		t.Errorf("summary = %+v", got)
	}
	// The imports the gate's own rules flag are named separately, once each and
	// in stream order, so a reader that lists a bounded number of imports can put
	// them first.
	if wantFlagged := []string{"os.system", "builtins.eval"}; !slices.Equal(got.Flagged, wantFlagged) {
		t.Errorf("Flagged = %q, want %q", got.Flagged, wantFlagged)
	}
}

// Flagged is exactly the imports the gate's classifier flags: a summary cannot
// call an import dangerous that the gate would pass, or the reverse.
func TestSummarizePickleFlaggedAgreesWithTheClassifier(t *testing.T) {
	for name, data := range psCorpus() {
		got := SummarizePickle(data)
		var want []string
		for _, imp := range got.Imports {
			if psDangerous(imp) {
				want = append(want, imp)
			}
		}
		if !slices.Equal(got.Flagged, want) {
			t.Errorf("%s: Flagged = %q, want %q (of imports %q)", name, got.Flagged, want, got.Imports)
		}
	}
	// A file that only rebuilds tensors flags nothing.
	if got := SummarizePickle(benignTorchPickle()); len(got.Flagged) != 0 {
		t.Errorf("a benign weight file flags %q", got.Flagged)
	}
}

// Each call opcode is reported as what it is, with or without an import in
// sight: a REDUCE whose callable the walk could not name is still a call.
func TestSummarizePickleCallOpcodes(t *testing.T) {
	for _, tc := range []struct {
		name   string
		opcode byte
		want   psCalls
	}{
		{"REDUCE", 'R', psCalls{Reduce: true}},
		{"BUILD", 'b', psCalls{Build: true}},
		{"OBJ", 'o', psCalls{Inst: true}},
		{"NEWOBJ", 0x81, psCalls{NewObj: true}},
		{"NEWOBJ_EX", 0x92, psCalls{NewObj: true}},
		{"none (APPEND)", 'a', psCalls{}},
		{"none (SETITEM)", 's', psCalls{}},
		{"none (TUPLE)", 't', psCalls{}},
		{"none (MEMOIZE)", opMemoize, psCalls{}},
	} {
		got := SummarizePickle([]byte{opProto, 4, opEmptyTuple, tc.opcode, opStop})
		if calls := psCallsOf(got); calls != tc.want {
			t.Errorf("%s: call opcodes = %+v, want %+v", tc.name, calls, tc.want)
		}
		if len(got.Imports) != 0 || got.Truncated || got.Opcodes != 4 {
			t.Errorf("%s: summary = %+v", tc.name, got)
		}
	}
}

// Input that is cut off, or is no pickle at all, never panics. A walk that
// stopped early says so (Truncated) and keeps what it saw before it stopped:
// an import named before the cut is still reported.
func TestSummarizePickleGarbageAndTruncatedInput(t *testing.T) {
	t.Run("nothing to walk", func(t *testing.T) {
		for name, data := range map[string][]byte{"nil": nil, "empty": {}} {
			got := SummarizePickle(data)
			if len(got.Imports) != 0 || psCallsOf(got) != (psCalls{}) || got.Opcodes != 0 || got.Truncated {
				t.Errorf("%s: summary = %+v, want an empty one", name, got)
			}
		}
	})

	t.Run("not a pickle", func(t *testing.T) {
		for name, data := range map[string][]byte{
			"unknown opcodes":    {0xff, 0xfe, 0xfd},
			"zeros":              make([]byte, 64),
			"zip":                []byte("PK\x03\x04\x14\x00\x00\x00\x08\x00"),
			"gzip":               {0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00},
			"ELF":                []byte("\x7fELF\x02\x01\x01\x00"),
			"safetensors header": []byte("\x10\x00\x00\x00\x00\x00\x00\x00{\"w\":{}}"),
			"JSON":               []byte(`{"weights": [1.0, 2.0]}`),
			"text":               []byte("hello world, this is not a pickle\n"),
			"a path":             []byte("/etc/passwd"),
		} {
			got := SummarizePickle(data)
			if !got.Truncated {
				t.Errorf("%s: the walk of something that is no pickle is not marked as cut short: %+v", name, got)
			}
			if len(got.Imports) != 0 {
				t.Errorf("%s: imports %q were read out of something that is no pickle", name, got.Imports)
			}
			if got.Opcodes < 1 || got.Opcodes > len(data) {
				t.Errorf("%s: Opcodes = %d for %d bytes", name, got.Opcodes, len(data))
			}
		}
	})

	t.Run("cut inside an opcode's argument", func(t *testing.T) {
		exploit := reducePickle("os", "system", "echo pwned")
		for _, tc := range []struct {
			name    string
			data    []byte
			imports []string
		}{
			{"PROTO without its argument", []byte{opProto}, nil},
			{"GLOBAL without a module line", []byte{opProto, 2, opGlobal, 'o', 's'}, nil},
			{"GLOBAL without a name line", []byte("\x80\x02cos\nsys"), nil},
			{"INST without a name line", []byte("\x80\x02(ios\nsys"), nil},
			{"SHORT_BINUNICODE longer than the data", []byte{opProto, 4, opShortBinU, 0xff, 'a'}, nil},
			{"BINUNICODE longer than the data", []byte{opProto, 2, opBinUnicode, 0xff, 0xff, 0xff, 0x7f, 'a'}, nil},
			{"BINUNICODE8 with a length of all ones", append([]byte{opProto, 4, 0x8d}, bytes.Repeat([]byte{0xff}, 8)...), nil},
			{"BINBYTES8 with a length past the data", []byte{opProto, 4, 0x8e, 0, 0, 0, 0, 0, 0, 0, 0x80, 'a'}, nil},
			{"BININT cut", []byte{opProto, 2, 'J', 1, 2}, nil},
			{"FRAME cut", []byte{opProto, 4, 0x95, 1, 2, 3}, nil},
			{"LONG1 cut", []byte{opProto, 2, 0x8a, 9, 1, 2}, nil},
			{"STRING without a terminator", []byte("\x80\x02S'never ends"), nil},
			// The import is in hand before the stream breaks off.
			{"exploit cut inside its argument", exploit[:len(exploit)-6], []string{"os.system"}},
			{"CPython exploit cut inside its argument", []byte(psSystemP4[:35]), []string{"posix.system"}},
			{"import, then an unknown opcode", append(globalV0("os", "system"), 0xff, opReduce, opStop), []string{"os.system"}},
		} {
			got := SummarizePickle(tc.data)
			if !got.Truncated {
				t.Errorf("%s: not marked as cut short: %+v", tc.name, got)
			}
			if !slices.Equal(got.Imports, tc.imports) {
				t.Errorf("%s: Imports = %q, want %q", tc.name, got.Imports, tc.imports)
			}
			// What lies past the cut was not seen, and is not claimed.
			if got.Reduce {
				t.Errorf("%s: a REDUCE past the cut is reported", tc.name)
			}
		}
	})

	t.Run("every prefix of a real stream", func(t *testing.T) {
		for name, data := range psCorpus() {
			full := SummarizePickle(data)
			for n := 0; n <= len(data); n++ {
				got := SummarizePickle(data[:n])
				// A prefix never shows more than the whole: its imports are the first
				// of the whole stream's, in the same order.
				if len(got.Imports) > len(full.Imports) || !slices.Equal(got.Imports, full.Imports[:len(got.Imports)]) {
					t.Fatalf("%s[:%d]: Imports = %q, not a prefix of %q", name, n, got.Imports, full.Imports)
				}
				if got.Opcodes > n || got.Opcodes > full.Opcodes {
					t.Fatalf("%s[:%d]: Opcodes = %d (the whole stream has %d)", name, n, got.Opcodes, full.Opcodes)
				}
				if (got.Reduce && !full.Reduce) || (got.Build && !full.Build) || (got.Inst && !full.Inst) || (got.NewObj && !full.NewObj) {
					t.Fatalf("%s[:%d]: reports a call opcode the whole stream does not have: %+v", name, n, got)
				}
			}
			if full.Truncated {
				t.Errorf("%s: the whole stream is reported as cut short", name)
			}
		}
	})

	t.Run("damaged streams", func(t *testing.T) {
		rng := rand.New(rand.NewSource(170))
		var corpus [][]byte
		for _, data := range psCorpus() {
			corpus = append(corpus, data)
		}
		for i := 0; i < 20000; i++ {
			data := append([]byte(nil), corpus[rng.Intn(len(corpus))]...)
			for flips := 1 + rng.Intn(4); flips > 0; flips-- {
				switch pos := rng.Intn(len(data)); rng.Intn(3) {
				case 0:
					data[pos] = byte(rng.Intn(256))
				case 1:
					data = append(data[:pos], data[pos+1:]...)
				default:
					data = append(data[:pos], append([]byte{byte(rng.Intn(256))}, data[pos:]...)...)
				}
				if len(data) == 0 {
					break
				}
			}
			before := append([]byte(nil), data...)
			got := SummarizePickle(data)
			if got.Opcodes > len(data) {
				t.Fatalf("%x: Opcodes = %d for %d bytes", data, got.Opcodes, len(data))
			}
			if again := SummarizePickle(data); !reflect.DeepEqual(got, again) {
				t.Fatalf("%x: two walks differ: %+v, %+v", data, got, again)
			}
			if !bytes.Equal(data, before) {
				t.Fatalf("%x: the walk modified its input", before)
			}
			seen := map[string]bool{}
			for _, imp := range got.Imports {
				if imp == "" || seen[imp] {
					t.Fatalf("%x: Imports = %q: empty or repeated entry", data, got.Imports)
				}
				seen[imp] = true
			}
		}
	})
}

// The summary is the gate's own scan, restated: the same imports (once each),
// the same call opcodes, the same count, the same "cut short".
func TestSummarizePickleAgreesWithTheGateScan(t *testing.T) {
	samples := psCorpus()
	samples["cut short"] = []byte(psSystemP4[:35])
	samples["not a pickle"] = []byte("PK\x03\x04")
	samples["empty"] = nil
	for name, data := range samples {
		sc := scanPickle(data)
		got := SummarizePickle(data)

		var want []string
		seen := map[string]bool{}
		for _, g := range sc.Globals {
			if q := g.qualified(); !seen[q] {
				seen[q] = true
				want = append(want, q)
			}
		}
		if !slices.Equal(got.Imports, want) {
			t.Errorf("%s: Imports = %q, the scan's globals are %q", name, got.Imports, want)
		}
		if got.Reduce != sc.HasReduce || got.Build != sc.HasBuild || got.Inst != sc.HasInst || got.NewObj != sc.HasNewObj {
			t.Errorf("%s: call opcodes %+v differ from the scan's %+v", name, psCallsOf(got), sc)
		}
		if got.Opcodes != sc.OpcodeCount || got.Truncated != sc.Truncated {
			t.Errorf("%s: Opcodes/Truncated = %d/%v, the scan's are %d/%v", name, got.Opcodes, got.Truncated, sc.OpcodeCount, sc.Truncated)
		}
	}
}

// A pickle may name a callable thousands of times; the summary names it once.
func TestSummarizePickleThousandsOfGlobals(t *testing.T) {
	const n = 5000

	t.Run("the same callable over and over", func(t *testing.T) {
		var b bytes.Buffer
		b.Write([]byte{opProto, 2})
		for i := 0; i < n; i++ {
			b.Write(globalV0("collections", "OrderedDict"))
			b.WriteByte(opEmptyTuple)
			b.WriteByte(opReduce)
		}
		b.WriteByte(opStop)
		got := SummarizePickle(b.Bytes())
		if !slices.Equal(got.Imports, []string{"collections.OrderedDict"}) {
			t.Errorf("Imports has %d entries, want the one callable", len(got.Imports))
		}
		if got.Opcodes != 3*n+2 || !got.Reduce || got.Truncated {
			t.Errorf("summary = {Opcodes:%d Reduce:%v Truncated:%v}, want %d opcodes walked to the end", got.Opcodes, got.Reduce, got.Truncated, 3*n+2)
		}
	})

	t.Run("a few callables, each many times, by every importing opcode", func(t *testing.T) {
		names := []string{"OrderedDict", "defaultdict", "deque", "Counter", "ChainMap"}
		var b bytes.Buffer
		b.Write([]byte{opProto, 4})
		for i := 0; i < n; i++ {
			name := names[i%len(names)]
			switch i % 3 {
			case 0:
				b.Write(globalV0("collections", name))
			case 1:
				b.Write(shortUnicode("collections"))
				b.Write(shortUnicode(name))
				b.WriteByte(opStackGlobal)
			default:
				b.WriteString("(icollections\n" + name + "\n")
			}
		}
		b.WriteByte(opStop)
		got := SummarizePickle(b.Bytes())
		want := []string{"collections.OrderedDict", "collections.defaultdict", "collections.deque", "collections.Counter", "collections.ChainMap"}
		if !slices.Equal(got.Imports, want) {
			t.Errorf("Imports = %d entries starting %q, want %q", len(got.Imports), got.Imports[:min(len(got.Imports), 6)], want)
		}
		if got.Truncated {
			t.Error("a complete stream was reported as cut short")
		}
	})

	t.Run("a dangerous callable among thousands of benign ones is not lost", func(t *testing.T) {
		var b bytes.Buffer
		b.Write([]byte{opProto, 2})
		for i := 0; i < n; i++ {
			if i == n/2 {
				b.Write(globalV0("os", "system"))
			}
			b.Write(globalV0("pkg.mod", fmt.Sprintf("Name%04d", i)))
		}
		b.WriteByte(opStop)
		got := SummarizePickle(b.Bytes())
		if len(got.Imports) != n+1 || got.Imports[0] != "pkg.mod.Name0000" || got.Imports[n/2] != "os.system" || got.Imports[n] != fmt.Sprintf("pkg.mod.Name%04d", n-1) {
			t.Errorf("Imports has %d entries; os.system at its place in the stream: %v", len(got.Imports), len(got.Imports) > n/2 && got.Imports[n/2] == "os.system")
		}
	})
}

// The walk is bounded, and a walk that hit a bound says so: the opcode budget
// stops it, the string constants it keeps to resolve STACK_GLOBAL are capped in
// size and in number, and a stream past any of these is reported as partial
// rather than as clean.
func TestSummarizePickleWalkIsBounded(t *testing.T) {
	t.Run("opcode budget", func(t *testing.T) {
		// More opcodes than the budget, then an import the walk never reaches.
		var b bytes.Buffer
		b.Write([]byte{opProto, 2})
		b.Write(bytes.Repeat([]byte{opNone}, maxOpcodes+16))
		b.Write(globalV0("os", "system"))
		b.Write([]byte{opEmptyTuple, opReduce, opStop})

		got := SummarizePickle(b.Bytes())
		if got.Opcodes != maxOpcodes {
			t.Errorf("Opcodes = %d, want the budget of %d", got.Opcodes, maxOpcodes)
		}
		if !got.Truncated {
			t.Error("a walk that stopped at the opcode budget is not marked as cut short: its empty import list would read as a clean bill")
		}
		if len(got.Imports) != 0 || got.Reduce {
			t.Errorf("the walk went past its budget: %+v", got)
		}

		// One opcode fewer than the budget allows is walked to the end.
		b.Reset()
		b.Write([]byte{opProto, 2})
		b.Write(bytes.Repeat([]byte{opNone}, maxOpcodes-16))
		b.Write(globalV0("os", "system"))
		b.Write([]byte{opEmptyTuple, opReduce, opStop})
		got = SummarizePickle(b.Bytes())
		if got.Truncated || !slices.Equal(got.Imports, []string{"os.system"}) || !got.Reduce {
			t.Errorf("a stream within the budget: %+v", got)
		}
	})

	t.Run("string constants are capped", func(t *testing.T) {
		// STACK_GLOBAL operands of 10,000 bytes each, as a sized constant
		// (BINUNICODE) and as a line (UNICODE).
		for name, long := range map[string]func(c byte) []byte{
			"BINUNICODE": func(c byte) []byte {
				b := []byte{opBinUnicode, 0x10, 0x27, 0x00, 0x00}
				return append(b, bytes.Repeat([]byte{c}, 10000)...)
			},
			"UNICODE": func(c byte) []byte {
				b := append([]byte{'V'}, bytes.Repeat([]byte{c}, 10000)...)
				return append(b, '\n')
			},
		} {
			var b bytes.Buffer
			b.Write([]byte{opProto, 4})
			b.Write(long('m'))
			b.Write(long('n'))
			b.Write([]byte{opStackGlobal, opStop})
			got := SummarizePickle(b.Bytes())
			if len(got.Imports) != 1 || got.Truncated {
				t.Fatalf("%s: summary = {%d imports, Truncated:%v}", name, len(got.Imports), got.Truncated)
			}
			imp := got.Imports[0]
			if len(imp) > 2*maxStringLen+1 {
				t.Errorf("%s: the import is %d bytes, over two capped constants (%d)", name, len(imp), 2*maxStringLen+1)
			}
			if !strings.HasPrefix(imp, "mmmm") || !strings.HasSuffix(imp, "nnnn") || !strings.Contains(imp, "m.n") {
				t.Errorf("%s: the import is not the head of the module and of the name: %.20q … %.20q", name, imp, imp[len(imp)-20:])
			}
		}
	})

	t.Run("the constant stack is capped and still resolves", func(t *testing.T) {
		// More string constants than the walk keeps, then the two that matter.
		var b bytes.Buffer
		b.Write([]byte{opProto, 4})
		filler := shortUnicode("x")
		for i := 0; i < maxStackStrings+1000; i++ {
			b.Write(filler)
		}
		b.Write(shortUnicode("os"))
		b.Write(shortUnicode("system"))
		b.Write([]byte{opStackGlobal, opEmptyTuple, opReduce, opStop})
		got := SummarizePickle(b.Bytes())
		if !slices.Equal(got.Imports, []string{"os.system"}) || !got.Reduce || got.Truncated {
			t.Errorf("summary = %+v", got)
		}
	})

	// NOT pinned here (reported with reproductions), because the current walk
	// does not hold them:
	//
	//   - memory: every STACK_GLOBAL opcode — one byte of input — keeps a new
	//     string of up to maxStringLen bytes alive, so a stream of a megabyte
	//     can hold gigabytes; and Imports is capped neither in the number of
	//     distinct entries nor, for a GLOBAL line, in the length of one;
	//   - STACK_GLOBAL is resolved from the last two string constants in the
	//     byte stream, not from the unpickler's stack: operands fetched from
	//     the memo (BINGET) resolve to whatever constants were pushed last;
	//   - the walk ends at the first STOP and does not say that more of the
	//     file follows (a legacy torch file is several pickles in a row).
}
