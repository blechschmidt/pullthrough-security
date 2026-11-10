//go:build fips

package fips

// BuildVariant reports the compile-time crypto build variant. This file is
// compiled into the binary only when it is built with the "fips" build tag
// (see the Makefile `build-fips` target, which also sets GOFIPS140 so the Go
// FIPS 140-3 cryptographic module is linked in).
const BuildVariant = "fips"
