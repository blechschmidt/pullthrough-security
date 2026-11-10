// Nested module: this directory is a WebAssembly guest compiled with
// GOOS=wasip1 GOARCH=wasm. It has its own go.mod so the parent module's
// `go build ./...` and `go vet ./...` ignore it (the //go:wasmexport directives
// only compile for the wasm target). It is not imported by any Go code; it is
// built into internal/extension/testdata/conformance_gate.wasm.
module conformancegate

go 1.24
