//go:build go1.26

package fips

import "crypto/fips140"

// moduleEnforced reports whether the Go FIPS 140-3 cryptographic module is in
// enforcing ("only") mode, where any attempt to use a non-approved algorithm
// fails rather than being silently permitted.
//
// On Go 1.26+ this is the authoritative crypto/fips140.Enforced. The pre-1.26
// build of this helper (enforced_pre_go126.go) derives the same signal from the
// GODEBUG fips140 setting, because crypto/fips140.Enforced did not exist before
// Go 1.26 and the project's baseline is Go 1.24 (the Go release carrying the
// FIPS 140-3 validated module).
func moduleEnforced() bool { return fips140.Enforced() }
