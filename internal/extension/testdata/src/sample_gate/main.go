// sample_gate is the reference custom admission gate for the WASM extensibility
// mechanism (Task 59), documented in docs/extensions.md. It demonstrates the kind
// of org-specific policy enterprises want without forking the proxy:
//
//   - Dependency-confusion guard for internal namespaces: a package whose name
//     carries the org's reserved prefix ("@acme/" for npm-style scopes, or an
//     "acme-"/"com.acme." prefix) must originate from the org's own backend.
//     Seeing it served from a public upstream is a classic dependency-confusion
//     attack, so the gate BLOCKS it.
//
//   - Risk-aware escalation: an artifact the proxy's composite risk engine placed
//     in the "critical" band is BLOCKED outright, layering the org's own hard line
//     on top of the proxy's scoring.
//
//   - Typosquat awareness: when the proxy's nameguard flagged a typosquat, the
//     gate WARNs (admits but annotates) so the org's tooling can follow up.
//
// Everything else is allowed. The gate is a pure function of the host input: it
// performs no I/O (the sandbox denies it anyway) and returns a structured verdict.
//
// Build (from this directory):
//
//	GOOS=wasip1 GOARCH=wasm go build -buildmode=c-shared -o ../../sample_gate.wasm .
package main

import (
	"encoding/json"
	"strings"
	"unsafe"
)

var pinned = map[uint32][]byte{}

//go:wasmexport pt_abi_version
func ptABIVersion() int32 { return 1 }

//go:wasmexport pt_alloc
func ptAlloc(n int32) int32 {
	if n <= 0 {
		return 0
	}
	b := make([]byte, n)
	p := uint32(uintptr(unsafe.Pointer(&b[0])))
	pinned[p] = b
	return int32(p)
}

//go:wasmexport pt_free
func ptFree(p int32) { delete(pinned, uint32(p)) }

type hostInput struct {
	Signals struct {
		Artifact struct {
			Ecosystem string `json:"ecosystem"`
			Backend   string `json:"backend"`
			Name      string `json:"name"`
			Version   string `json:"version"`
		} `json:"artifact"`
		Nameguard *struct {
			Typosquat bool `json:"typosquat"`
		} `json:"nameguard"`
	} `json:"signals"`
	Risk *struct {
		Band string `json:"band"`
	} `json:"risk"`
}

type verdict struct {
	Decision    string            `json:"decision"`
	Reason      string            `json:"reason,omitempty"`
	Annotations map[string]string `json:"annotations,omitempty"`
}

// internalNamespace reports whether name belongs to the org's reserved namespace.
// Tune these prefixes to your organization.
func internalNamespace(name string) bool {
	return strings.HasPrefix(name, "@acme/") ||
		strings.HasPrefix(name, "acme-") ||
		strings.HasPrefix(name, "com.acme.")
}

// trustedBackend reports whether the backend the artifact was routed to is the
// org's own (internal) registry rather than a public mirror.
func trustedBackend(backend string) bool {
	b := strings.ToLower(backend)
	return strings.Contains(b, "internal") || strings.Contains(b, "acme") || strings.Contains(b, "private")
}

//go:wasmexport pt_eval
func ptEval(ptr int32, n int32) int64 {
	in := pinned[uint32(ptr)]
	var doc hostInput
	_ = json.Unmarshal(in[:n], &doc)
	art := doc.Signals.Artifact

	v := verdict{Decision: "allow"}

	switch {
	case internalNamespace(art.Name) && !trustedBackend(art.Backend):
		v.Decision = "block"
		v.Reason = "internal-namespace package served from a non-org backend (possible dependency confusion)"
		v.Annotations = map[string]string{"rule": "dependency-confusion", "backend": art.Backend}
	case doc.Risk != nil && strings.EqualFold(doc.Risk.Band, "critical"):
		v.Decision = "block"
		v.Reason = "artifact in the critical risk band"
		v.Annotations = map[string]string{"rule": "risk-band", "band": doc.Risk.Band}
	case doc.Signals.Nameguard != nil && doc.Signals.Nameguard.Typosquat:
		v.Decision = "warn"
		v.Reason = "nameguard flagged a possible typosquat"
		v.Annotations = map[string]string{"rule": "typosquat"}
	}

	out, _ := json.Marshal(v)
	p := ptAlloc(int32(len(out)))
	copy(pinned[uint32(p)], out)
	return (int64(uint32(p)) << 32) | int64(uint32(len(out)))
}

func main() {}
