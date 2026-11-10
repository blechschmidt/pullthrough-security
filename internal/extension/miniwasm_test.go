package extension

import (
	"context"
	"testing"
)

// buildMiniModule assembles, by hand, a minimal valid WebAssembly module with no
// imports (i.e. not produced by a language runtime). It exports the host ABI:
//
//	pt_abi_version() -> i32   returns abiVersion
//	pt_alloc(i32) -> i32      returns a fixed scratch offset (ignores the size)
//	pt_eval(i32,i32) -> i64   ignores its input and returns a static "allow" verdict
//	                          baked into a data segment, packed as (offset<<32|len)
//	memory                    one page
//
// It serves two purposes in the conformance suite: it proves the host can load
// and drive a tiny zero-import module written in no particular language (not just
// the heavy Go-runtime fixtures), and it lets us test ABI-version negotiation by
// reporting an arbitrary version.
func buildMiniModule(abiVersion byte) []byte {
	verdict := []byte(`{"decision":"allow"}`) // 20 bytes, placed at offset 8

	uleb := func(n int) []byte {
		var out []byte
		for {
			b := byte(n & 0x7f)
			n >>= 7
			if n != 0 {
				b |= 0x80
			}
			out = append(out, b)
			if n == 0 {
				return out
			}
		}
	}
	vec := func(count int, body []byte) []byte { return append(uleb(count), body...) }
	section := func(id byte, content []byte) []byte {
		return append(append([]byte{id}, uleb(len(content))...), content...)
	}
	name := func(s string) []byte { return append(uleb(len(s)), []byte(s)...) }

	// Type section: () -> i32, (i32) -> i32, (i32,i32) -> i64.
	types := vec(3, concat(
		[]byte{0x60, 0x00, 0x01, 0x7f},             // () -> i32
		[]byte{0x60, 0x01, 0x7f, 0x01, 0x7f},       // (i32) -> i32
		[]byte{0x60, 0x02, 0x7f, 0x7f, 0x01, 0x7e}, // (i32,i32) -> i64
	))
	// Function section: funcs use types 0,1,2.
	funcs := vec(3, []byte{0x00, 0x01, 0x02})
	// Memory section: one memory, min 1 page.
	mems := vec(1, []byte{0x00, 0x01})
	// Export section: memory + the three ABI functions.
	exports := vec(4, concat(
		append(name("memory"), 0x02, 0x00),
		append(name(ExportABIVersion), 0x00, 0x00),
		append(name(ExportAlloc), 0x00, 0x01),
		append(name(ExportEval), 0x00, 0x02),
	))
	// Code section.
	body0 := concat([]byte{0x00}, []byte{0x41, abiVersion}, []byte{0x0b}) // i32.const ver
	body1 := concat([]byte{0x00}, []byte{0x41, 0x80, 0x08}, []byte{0x0b}) // i32.const 1024
	body2 := concat([]byte{0x00},                                         // pt_eval: (8<<32)|20
		[]byte{0x42, 0x08, 0x42, 0x20, 0x86, 0x42, 0x14, 0x84}, []byte{0x0b})
	code := vec(3, concat(
		append(uleb(len(body0)), body0...),
		append(uleb(len(body1)), body1...),
		append(uleb(len(body2)), body2...),
	))
	// Data section: active segment, memory 0, offset i32.const 8, the verdict bytes.
	data := vec(1, concat([]byte{0x00, 0x41, 0x08, 0x0b}, vec(len(verdict), verdict)))

	return concat(
		[]byte{0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00}, // magic + version
		section(1, types),
		section(3, funcs),
		section(5, mems),
		section(7, exports),
		section(10, code),
		section(11, data),
	)
}

func concat(parts ...[]byte) []byte {
	var out []byte
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

func TestMiniModuleLoadsAndEvaluates(t *testing.T) {
	// A zero-import, hand-built module at the supported ABI version loads and
	// returns its static allow verdict.
	sb, err := newSandbox(context.Background(), buildMiniModule(ABIVersion), Limits{})
	if err != nil {
		t.Fatalf("newSandbox(v%d): %v", ABIVersion, err)
	}
	defer sb.close(context.Background())

	in, _ := MarshalHostInput("mini", HostInput{})
	v, outcome, err := sb.invoke(context.Background(), in)
	if err != nil {
		t.Fatalf("invoke: %v", err)
	}
	if outcome != OutcomeAllow || v.Decision != DecisionAllow {
		t.Fatalf("outcome=%s decision=%s, want allow/allow", outcome, v.Decision)
	}
}

func TestMiniModuleABIVersionMismatchRejected(t *testing.T) {
	// A module reporting a future ABI version must be refused at load.
	_, err := newSandbox(context.Background(), buildMiniModule(ABIVersion+1), Limits{})
	if err == nil {
		t.Fatal("expected ABI version mismatch to be rejected")
	}
}

func TestMiniModuleViaManagerInlineWASM(t *testing.T) {
	// Inline WASM (no file) loads through the manager and evaluates.
	mgr, err := NewManager(context.Background(), Config{
		Enabled: true,
		Modules: []ModuleConfig{{Name: "mini", WASM: buildMiniModule(ABIVersion)}},
	})
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	defer mgr.Close(context.Background())

	res := mgr.Evaluate(context.Background(), HostInput{})
	if res.Decision != DecisionAllow {
		t.Fatalf("decision = %s, want allow", res.Decision)
	}
	if len(res.Modules) != 1 || res.Modules[0].Outcome != OutcomeAllow {
		t.Fatalf("expected one allow module result, got %+v", res.Modules)
	}
}
