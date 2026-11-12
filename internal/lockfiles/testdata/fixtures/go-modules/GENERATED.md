# go-modules

Generated with go1.26.3 on the host (`go mod tidy`, GOTOOLCHAIN=local) from a
main.go importing rsc.io/quote, golang.org/x/text/language and the local module.

- `rsc.io/sampler` is an indirect requirement (`// indirect`).
- `golang.org/x/text v0.14.0` is replaced by `v0.15.0`: go.sum holds the hashes of v0.15.0, the
  version actually fetched.
- `example.com/local` is replaced by the directory ./local — not fetched.
- go.sum's `golang.org/x/text v0.0.0-20170915032832-14c0d48ead0c/go.mod` line is the hash of a go.mod
  file from the module graph only: that version's source is never downloaded.
