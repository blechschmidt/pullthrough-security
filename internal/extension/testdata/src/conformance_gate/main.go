// conformance_gate is the test-fixture extension module exercised by the host
// conformance suite (internal/extension). A single module implements every
// behavior the suite asserts, selected by a trigger substring in the artifact
// name, so the host's handling of each outcome (allow / warn / block / timeout /
// fuel exhaustion / memory growth / malformed verdict / sandbox-denied syscalls)
// can be tested against one deterministic binary.
//
// It also doubles as a reference implementation of the host ABI (see
// internal/extension/abi.go) for a Go module author.
//
// Build (from this directory):
//
//	GOOS=wasip1 GOARCH=wasm go build -buildmode=c-shared -o ../../conformance_gate.wasm .
package main

import (
	"encoding/json"
	"os"
	"strings"
	"unsafe"
)

// pinned keeps every buffer returned by ptAlloc alive so the Go garbage collector
// cannot reclaim memory the host is still reading from or writing to. The host
// calls ptFree when it is done with a buffer.
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

// hostInput mirrors the subset of internal/extension.HostInput this fixture reads.
type hostInput struct {
	ABIVersion int    `json:"abiVersion"`
	Module     string `json:"module"`
	Signals    struct {
		Artifact struct {
			Ecosystem string `json:"ecosystem"`
			Backend   string `json:"backend"`
			Name      string `json:"name"`
			Version   string `json:"version"`
			Digest    string `json:"digest"`
		} `json:"artifact"`
		Tenant string `json:"tenant"`
	} `json:"signals"`
	Risk *struct {
		Score int    `json:"score"`
		Band  string `json:"band"`
	} `json:"risk"`
}

// verdict mirrors internal/extension.Verdict.
type verdict struct {
	Decision    string            `json:"decision"`
	Reason      string            `json:"reason,omitempty"`
	Annotations map[string]string `json:"annotations,omitempty"`
}

//go:noinline
func recurse(n int) int {
	if n <= 0 {
		return 0
	}
	return 1 + recurse(n-1)
}

//go:wasmexport pt_eval
func ptEval(ptr int32, n int32) int64 {
	in := pinned[uint32(ptr)]
	var doc hostInput
	_ = json.Unmarshal(in[:n], &doc)
	name := doc.Signals.Artifact.Name

	switch {
	case strings.Contains(name, "ext-timeout"):
		// Spin forever; the host's wall-clock deadline must terminate us.
		x := 0
		for {
			x++
			if x < 0 {
				break
			}
		}
	case strings.Contains(name, "ext-recurse"):
		// Deep recursion drives the host's function-call fuel meter to exhaustion.
		_ = recurse(1_000_000)
	case strings.Contains(name, "ext-grow"):
		// Attempt to allocate far past any sane memory limit.
		junk := make([][]byte, 0)
		for i := 0; i < 1<<30; i++ {
			junk = append(junk, make([]byte, 1<<20))
		}
		_ = junk
	case strings.Contains(name, "ext-badjson"):
		// Return bytes that are not a valid verdict; the host must reject them.
		return emit([]byte(`{"decision": this is not json`))
	}

	v := verdict{Decision: "allow", Annotations: map[string]string{"name": name}}
	switch {
	case strings.Contains(name, "ext-block"):
		v.Decision = "block"
		v.Reason = "blocked by conformance fixture"
		v.Annotations["rule"] = "ext-block"
	case strings.Contains(name, "ext-warn"):
		v.Decision = "warn"
		v.Reason = "warned by conformance fixture"
	case strings.Contains(name, "ext-risk"):
		// Decide relative to the host-supplied composite risk score.
		if doc.Risk != nil && doc.Risk.Score >= 75 {
			v.Decision = "block"
			v.Reason = "risk score above fixture threshold"
			v.Annotations["riskScore"] = itoa(doc.Risk.Score)
		}
	case strings.Contains(name, "ext-probe-fs"):
		// Prove the sandbox denies host filesystem access: try to read the root
		// directory and report what we could see (the host asserts it is empty/denied).
		entries, err := os.ReadDir("/")
		if err != nil {
			v.Annotations["fsProbe"] = "denied:" + err.Error()
		} else {
			v.Annotations["fsProbe"] = "read:" + itoa(len(entries))
		}
	}

	out, _ := json.Marshal(v)
	return emit(out)
}

// emit copies b into a freshly pinned buffer and returns the packed (ptr<<32|len)
// the host expects from pt_eval.
func emit(b []byte) int64 {
	p := ptAlloc(int32(len(b)))
	copy(pinned[uint32(p)], b)
	return (int64(uint32(p)) << 32) | int64(uint32(len(b)))
}

// itoa avoids importing strconv into the guest for a single conversion.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}

func main() {}
