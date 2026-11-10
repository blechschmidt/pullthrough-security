//go:build !fips

package fips

// BuildVariant reports the compile-time crypto build variant. This file is
// compiled into the default (non-FIPS) build. The binary can still enable FIPS
// enforcement at runtime via fips.enabled, but it was not compiled with the
// dedicated FIPS build tag; operators requiring the validated module should
// build the "fips" variant (see the Makefile `build-fips` target).
const BuildVariant = "standard"
