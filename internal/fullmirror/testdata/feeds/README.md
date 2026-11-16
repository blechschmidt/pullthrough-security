# Feed adapter fixtures

The files under `<type>/` are responses of the live registries, recorded on 2026-11-16 with
small requests (User-Agent `pullthrough-full-mirror-research/1.0`) and trimmed to a few
entries, keeping each format exactly as served: npm's replication feed and packuments, PyPI's
XML-RPC changelog and simple pages, the Go module index, the NuGet catalog, RubyGems' compact
index, Packagist's change log and metadata, Hackage's index tail, CPAN's RECENT files and
CHECKSUMS, the Julia General registry, the Bazel Central Registry's metadata, ConanCenter's
revision API and Homebrew's formula JSON.

Where a document reaches an adapter through the proxy's gated pipeline (`Env.Read`), the
fixture carries the rewrite the backend applies for clients: its download URLs point into the
proxy (`http://proxy.example/v1/<upstream>/…`), as they would through a real backend.

`git/` holds a real exchange with GitHub's Git server for the Bazel Central Registry
(`bazelbuild/bazel-central-registry`): the protocol-v2 capability advertisement
(`info-refs.bin`), an `ls-refs` answer (`ls-refs.bin`, HEAD 4410f9ba…), the blob-less fetch of
that head with its parent 9ee49c80… as `have` (`fetch-incremental.bin`: one commit and the 24
trees it added), and the parent's root and `modules` trees in the adapters' tree-store format
(`bcr-parent-trees.gz`) — everything the diff of the two commits reads.

`*/golden/` holds what the adapters make of them. After a deliberate change, regenerate with
`go test ./internal/fullmirror -run <Test> -update-feed-golden` and review the diff.
