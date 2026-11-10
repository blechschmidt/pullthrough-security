package mlguard

import (
	"bytes"
	"testing"
)

// Pickle opcode constants used to hand-build test streams, matching CPython's
// pickle module.
const (
	opProto       = 0x80
	opStop        = '.'
	opGlobal      = 'c'
	opStackGlobal = 0x93
	opReduce      = 'R'
	opShortBinU   = 0x8c
	opMemoize     = 0x94
	opEmptyTuple  = ')'
	opMark        = '('
	opTuple       = 't'
	opBinUnicode  = 'X'
	opBinInt1     = 'K'
	opNone        = 'N'
)

// shortUnicode emits SHORT_BINUNICODE <len> <utf8>.
func shortUnicode(s string) []byte {
	b := []byte{opShortBinU, byte(len(s))}
	return append(b, []byte(s)...)
}

// globalV0 emits a protocol-0 GLOBAL opcode: 'c' module '\n' name '\n'.
func globalV0(module, name string) []byte {
	b := []byte{opGlobal}
	b = append(b, []byte(module)...)
	b = append(b, '\n')
	b = append(b, []byte(name)...)
	b = append(b, '\n')
	return b
}

// reducePickle builds a classic "__reduce__ runs os.system" exploit pickle using
// protocol-0 GLOBAL + REDUCE.
func reducePickle(module, name, arg string) []byte {
	var b bytes.Buffer
	b.WriteByte(opProto)
	b.WriteByte(2)
	b.Write(globalV0(module, name))
	b.WriteByte(opMark)
	b.Write([]byte{opBinUnicode, byte(len(arg)), 0, 0, 0})
	b.WriteString(arg)
	b.WriteByte(opTuple)
	b.WriteByte(opReduce)
	b.WriteByte(opStop)
	return b.Bytes()
}

// stackGlobalPickle builds an exploit using the protocol-4 STACK_GLOBAL opcode,
// whose module/name come from the two preceding string pushes.
func stackGlobalPickle(module, name string) []byte {
	var b bytes.Buffer
	b.WriteByte(opProto)
	b.WriteByte(4)
	b.Write(shortUnicode(module))
	b.WriteByte(opMemoize)
	b.Write(shortUnicode(name))
	b.WriteByte(opMemoize)
	b.WriteByte(opStackGlobal)
	b.WriteByte(opReduce)
	b.WriteByte(opStop)
	return b.Bytes()
}

// benignTorchPickle emits the GLOBAL/REDUCE pattern a legitimate torch weight
// uses (collections.OrderedDict and a tensor rebuild helper) — no dangerous
// import, so it must NOT be flagged.
func benignTorchPickle() []byte {
	var b bytes.Buffer
	b.WriteByte(opProto)
	b.WriteByte(2)
	b.Write(globalV0("collections", "OrderedDict"))
	b.WriteByte(opEmptyTuple)
	b.WriteByte(opReduce)
	b.Write(globalV0("torch._utils", "_rebuild_tensor_v2"))
	b.WriteByte(opEmptyTuple)
	b.WriteByte(opReduce)
	b.WriteByte(opStop)
	return b.Bytes()
}

func TestScanPickleDetectsOsSystem(t *testing.T) {
	sc := scanPickle(reducePickle("os", "system", "echo pwned"))
	if !sc.HasReduce {
		t.Error("REDUCE not detected")
	}
	found := false
	for _, g := range sc.Globals {
		if g.Module == "os" && g.Name == "system" {
			found = true
		}
	}
	if !found {
		t.Errorf("os.system GLOBAL not extracted; globals=%+v", sc.Globals)
	}
}

func TestScanPickleStackGlobal(t *testing.T) {
	sc := scanPickle(stackGlobalPickle("subprocess", "Popen"))
	if len(sc.Globals) != 1 || sc.Globals[0].Module != "subprocess" || sc.Globals[0].Name != "Popen" {
		t.Fatalf("STACK_GLOBAL not resolved: %+v", sc.Globals)
	}
	if !sc.HasReduce {
		t.Error("REDUCE not detected")
	}
}

func TestScanPickleBenignHasNoDangerousGlobals(t *testing.T) {
	sc := scanPickle(benignTorchPickle())
	for _, g := range sc.Globals {
		if _, _, ok := classifyGlobal(g); ok {
			t.Errorf("benign torch global flagged as dangerous: %q", g.qualified())
		}
	}
	if !sc.HasReduce {
		t.Error("benign torch pickle does use REDUCE")
	}
}

func TestScanPickleNeverPanicsOnGarbage(t *testing.T) {
	inputs := [][]byte{
		nil,
		{},
		{opProto},                          // truncated PROTO arg
		{opGlobal, 'o', 's'},               // GLOBAL missing terminators
		{opShortBinU, 0xff, 'a'},           // length overruns buffer
		bytes.Repeat([]byte{opReduce}, 64), // many opcodes, no strings
		{0xff, 0xfe, 0xfd},                 // unknown opcodes
	}
	for i, in := range inputs {
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("input %d panicked: %v", i, r)
				}
			}()
			_ = scanPickle(in)
		}()
	}
}

func TestClassifyGlobal(t *testing.T) {
	cases := []struct {
		module, name string
		wantSev      Severity
		wantOK       bool
	}{
		{"os", "system", SeverityCritical, true},
		{"subprocess", "Popen", SeverityCritical, true},
		{"builtins", "eval", SeverityCritical, true},
		{"builtins", "print", SeverityHigh, true},
		{"socket", "socket", SeverityCritical, true},
		{"base64", "b64decode", SeverityHigh, true},
		{"importlib", "import_module", SeverityHigh, true},
		{"collections", "OrderedDict", "", false},
		{"torch._utils", "_rebuild_tensor_v2", "", false},
		{"numpy.core.multiarray", "_reconstruct", "", false},
	}
	for _, c := range cases {
		sev, _, ok := classifyGlobal(globalRef{Module: c.module, Name: c.name})
		if ok != c.wantOK || sev != c.wantSev {
			t.Errorf("classifyGlobal(%s.%s) = (%q,%v), want (%q,%v)",
				c.module, c.name, sev, ok, c.wantSev, c.wantOK)
		}
	}
}
