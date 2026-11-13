# go-modules

Generated 2026-11-13 with go1.26.3 on the host (GOTOOLCHAIN=local, scratch GOPATH/GOMODCACHE,
proxy.golang.org). Unedited tool output.

A main package importing github.com/google/uuid, github.com/spf13/cobra and github.com/spf13/pflag:

    go get github.com/spf13/cobra@v1.8.0 github.com/spf13/pflag@v1.0.9 github.com/google/uuid@v1.5.0
    go mod tidy                                       # before/
    go get github.com/spf13/pflag@v1.0.10 github.com/google/uuid@v1.6.0
    go mod tidy                                       # after/

go.mod: a require block, and mousetrap as a single-line `require … // indirect`. go.sum: cobra's
go.mod requires pflag v1.0.5, so `pflag v1.0.5/go.mod` is there next to the selected version —
and v1.0.10 sorts after it as a semantic version, before it as text. `go mod tidy` dropped the
`/go.mod` lines of pflag v1.0.9 and uuid v1.5.0 from after/go.sum, as they left the module graph;
the native rewrite keeps them (the updater does not load the module graph), and is otherwise
identical to after/.
