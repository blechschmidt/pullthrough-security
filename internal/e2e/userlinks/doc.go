// Package userlinks is the integration suite of personal cache links (Task
// 177): cache users sign in through an OIDC identity provider and are handed
// their own address for every package source, so that the download log records
// who pulled a package and not only from which address.
//
// It exercises the feature the way its two kinds of people meet it — a user at
// a browser and a package manager, an operator at the admin API — and with the
// thing that makes the feature hard: real package managers, which follow the
// links they are given.
//
// # What is real
//
//   - the `pullthrough` binary, started from a YAML configuration file — two
//     of them where a check is about replicas — so the production wiring is
//     under test: configuration → sign-in → link registry → gateway → download
//     log → admin API;
//   - the sign-in: an OpenID Connect authorization-code flow with PKCE against
//     an identity provider that signs real ID tokens (internal/userlinks/
//     oidctest), driven by an HTTP client that keeps cookies and follows
//     redirects, as a browser does;
//   - the clients: the real `npm`, `pip`, `cargo` and `go` install a package,
//     the real Docker Engine pulls an image and the real `git` clones a
//     repository through the user's personal address, each configured with the
//     very snippet the links page hands out. (A client that is not installed
//     is skipped, unless PT_USERLINKS_CLIENTS=real — which CI sets — makes
//     that a failure.)
//
// # What is stubbed
//
// The upstreams: an npm registry, a PyPI index with its file host, a crates.io,
// a GOPROXY and a container registry, serving small packages the suite builds
// itself in the formats the ecosystems ship — and a Git server, which is Git's
// own `git http-backend` over a repository the suite creates. No request leaves
// the machine.
//
// # What is asserted
//
// Per ecosystem, with the real client:
//
//   - install         a signed-in user's package manager installs a package
//     through their personal address
//   - attributed      the download log names the user and the link — and the
//     index documents the client read on the way were rewritten so that it
//     never left its personal address
//   - two-users       a second user installs the same package from the same
//     machine: the log tells the two apart, which an address cannot
//   - no-leak         the link is not in the files the client wrote where the
//     generated configuration promises so (package-lock.json, Cargo.lock, a
//     checkout's .git/config)
//   - revoked         after the user revokes the link, the client fails and
//     nothing is served
//
// And across ecosystems: a download without a link stays anonymous; the link's
// token is in nothing the proxy wrote or sent — its log, the audit log, the
// download log's file, the registry's store, the requests the upstreams saw;
// the user's page shows where the link was last used; the admin API lists
// links, summarizes downloads per user and revokes everything of a user at
// once; links survive a restart; a second replica sharing the registry honours
// a link created on the first at once and its revocation within the refresh
// interval; with client authentication switched on, a link authenticates, is
// subject to RBAC, and works as an ordinary credential — an npm auth token, the
// password of `docker login`, a Git credential; the metrics count all of it.
//
// Everything but this file carries the `integration` build tag:
//
//	go test -tags integration ./internal/e2e/userlinks/
//
// The suite writes user-links-matrix.{md,json} — the ecosystem × check matrix
// and the download log as the proxy recorded it — to $PT_TEST_REPORT_DIR.
package userlinks
