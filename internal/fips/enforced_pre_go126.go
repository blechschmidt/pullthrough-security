//go:build !go1.26

package fips

import (
	"os"
	"strings"
)

// moduleEnforced reports whether the Go FIPS 140-3 cryptographic module is in
// enforcing ("only") mode, where any attempt to use a non-approved algorithm
// fails rather than being silently permitted.
//
// crypto/fips140.Enforced was only added in Go 1.26, but the project's baseline
// toolchain is Go 1.24 — the Go release that carries the FIPS 140-3 *validated*
// cryptographic module, which is the whole point of the FIPS build variant, so
// we do not bump the baseline merely to reach a newer reporting API. On Go 1.24
// and 1.25 we therefore derive the same signal from the GODEBUG fips140 setting:
// the module runs in enforcing mode exactly when started with
// GODEBUG=fips140=only. (On Go 1.26+ the build tag selects enforced_go126.go,
// which calls crypto/fips140.Enforced directly.)
func moduleEnforced() bool {
	return godebugValue("fips140") == "only"
}

// godebugValue returns the value of a single GODEBUG key as seen in the process
// environment ("" when unset). GODEBUG is a comma-separated list of key=value
// pairs; the runtime applies last-value-wins, which this mirrors.
func godebugValue(key string) string {
	val := ""
	for _, kv := range strings.Split(os.Getenv("GODEBUG"), ",") {
		k, v, ok := strings.Cut(strings.TrimSpace(kv), "=")
		if ok && strings.TrimSpace(k) == key {
			val = strings.TrimSpace(v)
		}
	}
	return val
}
