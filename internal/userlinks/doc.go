// Package userlinks gives the people who use the cache an identity (Task 177):
// they sign in through the organization's OIDC identity provider and are handed
// personal cache links — the proxy's ordinary package-source URLs under a path
// prefix that is theirs alone — so that every download through such a link is
// attributed to the person, not merely to an address.
//
//	https://proxy.example.com/v1/npm/                              anyone
//	https://proxy.example.com/u/ptl1k3j5…q2/v1/npm/                alice@example.com
//
// The download log (Task 176) answers "which address pulled this package". An
// address is a laptop on a VPN pool today and someone else's tomorrow, a NAT
// gateway in front of a floor, a CI runner shared by forty teams. A personal
// link answers "who".
//
// # The pieces
//
//   - A token names a link. It is 160 random bits in a spelling that survives
//     every place a package manager puts a URL (lower-case letters and digits
//     only), carries a checksum so a mistyped or truncated one is recognised
//     without consulting anything, and starts with a fixed prefix so that
//     secret scanners can be taught to find it. See NewToken.
//   - The Registry knows every link: whose it is, when it expires, whether it
//     was revoked. It holds a hash of each token, never the token; a token is
//     shown once, when the link is created.
//   - The Service signs users in (OIDC authorization-code flow with PKCE),
//     serves the self-service page where they create and revoke their links,
//     and resolves the token of an incoming request to the identity behind it.
//
// # One registry, several replicas
//
// A link created on one replica must work on the next request, which a load
// balancer may send to another. The registry therefore lives in a Store that
// all replicas share — a directory on a shared volume, or the object store the
// shared cache already uses — and is laid out so that replicas never have to
// take turns: every object in it is written once, or is written by one replica
// only, or says the same thing whoever writes it.
//
//	link/<token hash>     a link; written when it is created, never changed
//	revoked/<link id>     the fact that a link was revoked; written once
//	block/<subject key>   "nothing issued to this user before T is valid"
//	usage/<node>          when each link was last used, as seen by one replica
//
// A replica keeps the registry in memory and refreshes it from the store every
// few seconds; a request never waits for the store. A token the replica does not
// know is looked up in the store directly, once, so a link works everywhere the
// moment it exists. A revocation is immediate on the replica that performed it
// and reaches the others with their next refresh (Config.SyncInterval).
//
// # What a link is not
//
// A token in a URL is a password in a URL. Reverse proxies log it, shells
// remember it, and some package managers copy the URLs they downloaded from
// into lock files that are then committed. The package does what it can on its
// side — the proxy never logs a token, never stores one, never sends one
// upstream — and offers the same token as an ordinary HTTP credential for the
// clients that can present one. What remains is bounded by expiry and
// revocation. docs/user-links.md is explicit about it.
package userlinks
