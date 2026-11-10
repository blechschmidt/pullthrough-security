// Nested module: a WebAssembly extension-gate guest compiled with
// GOOS=wasip1 GOARCH=wasm. It has its own go.mod so the parent module ignores it.
// Built into internal/extension/testdata/sample_gate.wasm and documented in
// docs/extensions.md as the reference custom admission gate.
module samplegate

go 1.24
