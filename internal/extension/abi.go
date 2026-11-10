package extension

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
)

// This file defines the stable, versioned host<->module ABI. It is the single
// source of truth a module author (in any language that compiles to wasm) must
// implement against, and it is intentionally small and self-describing so it can
// evolve without breaking existing modules.
//
// # Wire contract (ABI v1)
//
// A module MUST export a linear memory named "memory" and the following
// functions:
//
//	pt_abi_version() -> i32
//	    Returns the ABI revision the module implements. The host refuses to load
//	    a module whose reported version it does not support, so a module built
//	    against a future ABI fails fast at load rather than misbehaving per-call.
//
//	pt_alloc(size: i32) -> i32
//	    Allocates `size` bytes in the module's linear memory and returns the
//	    offset (pointer). The allocation must remain valid (not reclaimed by a GC)
//	    until pt_free is called for it. Returns 0 on failure.
//
//	pt_eval(ptr: i32, size: i32) -> i64
//	    Evaluates the host input — the UTF-8 JSON document at [ptr, ptr+size) —
//	    and returns a *packed* result: the high 32 bits are the offset of the
//	    UTF-8 JSON verdict in linear memory and the low 32 bits are its length
//	    (see packResult). A return value of 0 signals an internal module error
//	    (the host treats it as OutcomeError).
//
// A module MAY export:
//
//	pt_free(ptr: i32)
//	    Releases a buffer previously returned by pt_alloc. The host calls it
//	    best-effort after reading the verdict; a module without it simply leaks
//	    within its (discarded-after-call) instance, which is harmless.
//
// The host instantiates a *fresh module instance per invocation*, so a module
// carries no state between requests: every pull sees clean linear memory.
//
// # Documents
//
// The host marshals a HostInput (see extension.go) as the input JSON and expects
// a Verdict as the output JSON. Both are plain JSON so a module need not link any
// proxy Go type. The host stamps and the module may verify ABIVersion.

// ABIVersion is the host ABI revision this build implements and stamps into every
// HostInput. Bump it only for a breaking change to the export contract or the
// document shapes; additive, backward-compatible fields do not require a bump.
const ABIVersion = 1

// Exported function and memory names the host looks up on a loaded module. They
// are part of the ABI and must not change without a version bump.
const (
	ExportMemory     = "memory"
	ExportABIVersion = "pt_abi_version"
	ExportAlloc      = "pt_alloc"
	ExportEval       = "pt_eval"
	ExportFree       = "pt_free"
	exportInitialize = "_initialize" // WASI reactor initializer (language-runtime detail)
)

// Verdict-size bounds. A module is untrusted operator-supplied code; even a
// well-behaved one can return a pathological verdict, so the host caps what it
// will read back and decode. These are defense-in-depth on top of MaxOutputBytes
// (which bounds the raw byte read before any JSON parsing).
const (
	maxReasonBytes    = 2048
	maxAnnotations    = 32
	maxAnnotationKey  = 128
	maxAnnotationByte = 1024
)

var (
	// errBadDecision is returned when a module's verdict names an unknown decision.
	errBadDecision = errors.New("extension: verdict has an invalid decision")
	// errVerdictTooLarge is returned when a decoded verdict exceeds the ABI bounds.
	errVerdictTooLarge = errors.New("extension: verdict exceeds ABI size limits")
)

// MarshalHostInput serializes the request context for a module, stamping the
// current ABIVersion so the wire document is self-describing. The module name is
// recorded so a shared module can branch on which gate it serves.
func MarshalHostInput(module string, in HostInput) ([]byte, error) {
	in.ABIVersion = ABIVersion
	in.Module = module
	b, err := json.Marshal(in)
	if err != nil {
		return nil, fmt.Errorf("extension: marshal host input: %w", err)
	}
	return b, nil
}

// ParseVerdict decodes and validates a module's JSON verdict under the ABI size
// bounds. It rejects an unknown decision and an oversized reason/annotation set
// so a misbehaving module cannot inject unbounded data into the audit log,
// response headers, or notifications. The decode is strict (unknown fields are
// rejected) so a typo'd field surfaces as an error rather than being silently
// dropped.
func ParseVerdict(b []byte) (Verdict, error) {
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	var v Verdict
	if err := dec.Decode(&v); err != nil {
		return Verdict{}, fmt.Errorf("extension: decode verdict: %w", err)
	}
	if !v.Decision.Valid() {
		return Verdict{}, fmt.Errorf("%w: %q", errBadDecision, v.Decision)
	}
	if len(v.Reason) > maxReasonBytes {
		return Verdict{}, fmt.Errorf("%w: reason is %d bytes", errVerdictTooLarge, len(v.Reason))
	}
	if len(v.Annotations) > maxAnnotations {
		return Verdict{}, fmt.Errorf("%w: %d annotations", errVerdictTooLarge, len(v.Annotations))
	}
	for k, val := range v.Annotations {
		if len(k) > maxAnnotationKey || len(val) > maxAnnotationByte {
			return Verdict{}, fmt.Errorf("%w: annotation %q", errVerdictTooLarge, k)
		}
	}
	return v, nil
}

// packResult encodes an (offset, length) pair into the i64 a module returns from
// pt_eval: the high 32 bits hold the offset and the low 32 bits the length. It is
// exported so a Go module author can reuse it to build their return value.
func packResult(offset, length uint32) int64 {
	return int64(uint64(offset)<<32 | uint64(length))
}

// unpackResult splits the packed i64 returned by pt_eval back into (offset,
// length).
func unpackResult(packed int64) (offset, length uint32) {
	u := uint64(packed)
	return uint32(u >> 32), uint32(u & 0xffffffff)
}
