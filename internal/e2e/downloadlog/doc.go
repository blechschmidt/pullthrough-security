// Package downloadlog is the integration suite of the download log (Task 176):
// the admin console's record of which package was downloaded from which client
// address. It exercises the feature the way an operator meets it, with the two
// ecosystems the task names — Rust (cargo) and Go modules.
//
// # What is real
//
//   - the `pullthrough` binary, started from a YAML configuration file, so the
//     production wiring is under test: configuration → download log →
//     gateway → admin API;
//   - the package managers: the real `cargo` and the real `go` command fetch
//     packages through the proxy. (Where one is not installed, a scripted
//     client that speaks the same protocol stands in; CI requires the real
//     ones.)
//   - the client addresses. Every "client machine" of the suite reaches the
//     proxy from its own source address, at the TCP level, so the address in a
//     log entry is one the proxy observed — not one a test wrote into a
//     request structure.
//
// # What is stubbed
//
// The upstream registries: a crates.io (sparse index and crate downloads) and a
// GOPROXY, serving small packages the suite builds itself, in the formats the
// ecosystems ship (a .crate tarball whose checksum the index states, a module
// zip). No request leaves the machine; the proxy's egress guard is configured to
// allow loopback only.
//
// # How a client gets an address
//
// Each client machine has an egress — a small HTTP forwarding proxy the package
// manager is pointed at (HTTP_PROXY for go, http.proxy for cargo) — which
// connects to the pull-through proxy from a distinct loopback source address
// (127.0.10.1, 127.0.10.2, …; on Linux all of 127.0.0.0/8 is local). Two
// egresses play special roles: one is the address listed in
// server.trustedProxies and adds an X-Forwarded-For header, as a load balancer
// does; another adds the same header without being trusted, as a client forging
// its address would.
//
// # What is asserted, per ecosystem
//
// The log is read through the admin API, exactly as the console reads it.
//
//   - install          the real client installs a package through the proxy
//   - logged           the log shows that package, version and client address,
//     served, with the artifact's size — and nothing for the index requests
//     around it
//   - cache-hit        a second machine installs it: logged against the second
//     address, served from cache
//   - who-pulled       filtering by the package lists exactly those two machines
//   - blocked          a package the dependency firewall denies: the client
//     fails, and the attempt is logged with the gate that refused it
//   - what-pulled      filtering by an address, or a CIDR, lists that machine's
//     entries only
//   - forwarded        behind the trusted proxy, the logged address is the
//     client's, and the entry names the proxy it was forwarded by
//   - spoof-rejected   an untrusted peer's X-Forwarded-For is ignored
//
// and across both: filtering by ecosystem, the CSV export, the admin
// credential, the metrics, and persistence across a restart of the proxy.
//
// Everything but this file carries the `integration` build tag:
//
//	go test -tags integration ./internal/e2e/downloadlog/
//
// The suite writes download-log-matrix.{md,json} — the ecosystem × check matrix
// and the log as the proxy recorded it — to $PT_TEST_REPORT_DIR.
package downloadlog
