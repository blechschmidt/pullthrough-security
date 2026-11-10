// Package git implements a read-only Git pull-through proxy supporting both the
// smart HTTP protocol (info/refs + git-upload-pack) and Git-over-SSH.
//
// Two serving modes are supported:
//
//   - Mirror mode (preferred): the proxy maintains local bare mirrors of the
//     requested repositories (using the git binary) and serves clones/fetches
//     from them, refreshing from upstream on a bounded interval. This caches
//     packs and objects safely — the mirror is the cache — and backs both the
//     HTTP and SSH endpoints. Authentication to upstream (HTTPS tokens or SSH
//     keys) is injected when refreshing the mirror.
//
//   - Pass-through mode (fallback, HTTP only): when mirroring is disabled or the
//     git binary is unavailable, smart-HTTP requests are streamed directly to
//     the upstream Git host over HTTPS with credential injection. Ref
//     advertisements may be cached for a short TTL; pack negotiation responses
//     are never cached because they depend on the client's wants/haves.
//
// The proxy is deliberately read-only: it serves git-upload-pack (clone/fetch)
// and rejects git-receive-pack (push). This is a supply-chain security control —
// the proxy is an ingress for pulling external code, never an egress for
// publishing into upstreams.
package git

import (
	"errors"
	"fmt"
	"strings"
)

// Git smart-protocol service names.
const (
	serviceUploadPack  = "git-upload-pack"
	serviceReceivePack = "git-receive-pack"
)

// Smart-HTTP content types (RFC-less, but stable git conventions).
const (
	ctUploadPackAdvertisement = "application/x-git-upload-pack-advertisement"
	ctUploadPackRequest       = "application/x-git-upload-pack-request"
	ctUploadPackResult        = "application/x-git-upload-pack-result"
)

// flushPkt is the git pkt-line flush packet.
const flushPkt = "0000"

// ErrPushRejected is returned when a client attempts a push (git-receive-pack)
// against the read-only proxy.
var ErrPushRejected = errors.New("git: push (receive-pack) is not permitted by the read-only proxy")

// ErrInvalidService indicates an unknown or unsupported smart-protocol service.
var ErrInvalidService = errors.New("git: unsupported service")

// pktLine encodes s as a single git pkt-line: a 4-hex-digit big-endian length
// prefix (counting the 4 prefix bytes themselves) followed by the data. It
// panics only if s is longer than the protocol maximum (65516 bytes), which the
// proxy never produces.
func pktLine(s string) string {
	n := len(s) + 4
	if n > 65520 {
		panic("git: pkt-line payload too large")
	}
	return fmt.Sprintf("%04x%s", n, s)
}

// serviceAdvertisementHeader returns the smart-HTTP preamble that precedes a raw
// ref advertisement: the "# service=<svc>\n" pkt-line followed by a flush
// packet. git's CGI front-end emits this before the output of
// "git <svc> --advertise-refs".
func serviceAdvertisementHeader(service string) string {
	return pktLine("# service="+service+"\n") + flushPkt
}

// validateService reports the canonical service name for a smart-protocol
// request, rejecting pushes and unknown services. Only git-upload-pack
// (clone/fetch) is permitted.
func validateService(service string) (string, error) {
	switch service {
	case serviceUploadPack:
		return serviceUploadPack, nil
	case serviceReceivePack:
		return "", ErrPushRejected
	case "":
		return "", fmt.Errorf("%w: empty service", ErrInvalidService)
	default:
		return "", fmt.Errorf("%w: %q", ErrInvalidService, service)
	}
}

// gitEndpoint identifies the smart-protocol endpoint addressed by a request
// path, after the repository path is stripped.
type gitEndpoint int

const (
	endpointUnknown gitEndpoint = iota
	endpointInfoRefs
	endpointUploadPack
	endpointReceivePack
)

// lfsObjectsInfix is the smart-HTTP path segment that introduces the Git LFS
// batch API and per-object transfer endpoints, appearing after the repository
// path: "<repo-path>/info/lfs/objects/batch" and
// "<repo-path>/info/lfs/objects/<oid>".
const lfsObjectsInfix = "/info/lfs/objects/"

// lfsEndpoint identifies the Git LFS endpoint addressed by a request path.
type lfsEndpoint int

const (
	lfsEndpointNone   lfsEndpoint = iota
	lfsEndpointBatch              // POST <repo>/info/lfs/objects/batch
	lfsEndpointObject             // GET  <repo>/info/lfs/objects/<oid>
)

// splitLFSEndpoint recognizes the Git LFS batch API and per-object transfer
// endpoints within a smart-HTTP request path. It returns the (un-sanitized)
// repository path, the matched LFS endpoint, and — for an object transfer — the
// object id segment. ok is false when the path is not an LFS endpoint, in which
// case the caller falls through to the ordinary smart-protocol dispatch.
func splitLFSEndpoint(path string) (repoPath string, endpoint lfsEndpoint, oid string, ok bool) {
	path = strings.TrimPrefix(path, "/")
	switch {
	case strings.HasSuffix(path, lfsObjectsInfix+"batch"):
		return strings.TrimSuffix(path, lfsObjectsInfix+"batch"), lfsEndpointBatch, "", true
	case path == "info/lfs/objects/batch":
		return "", lfsEndpointBatch, "", true
	}
	// Per-object transfer: "<repo>/info/lfs/objects/<oid>". The oid must be the
	// final single segment (no further slashes), so locate the last occurrence of
	// the infix and require a slash-free tail.
	if idx := strings.LastIndex(path, lfsObjectsInfix); idx >= 0 {
		tail := path[idx+len(lfsObjectsInfix):]
		if tail != "" && !strings.Contains(tail, "/") && tail != "batch" {
			return path[:idx], lfsEndpointObject, tail, true
		}
	}
	return "", lfsEndpointNone, "", false
}

// splitRepoEndpoint splits a smart-HTTP request path of the form
// "<repo-path>/info/refs", "<repo-path>/git-upload-pack", or
// "<repo-path>/git-receive-pack" into the repository path and the endpoint.
// The returned repoPath has no leading or trailing slash.
func splitRepoEndpoint(path string) (repoPath string, endpoint gitEndpoint, ok bool) {
	path = strings.TrimPrefix(path, "/")
	switch {
	case strings.HasSuffix(path, "/info/refs"):
		return strings.TrimSuffix(path, "/info/refs"), endpointInfoRefs, true
	case path == "info/refs":
		return "", endpointInfoRefs, true
	case strings.HasSuffix(path, "/"+serviceUploadPack):
		return strings.TrimSuffix(path, "/"+serviceUploadPack), endpointUploadPack, true
	case path == serviceUploadPack:
		return "", endpointUploadPack, true
	case strings.HasSuffix(path, "/"+serviceReceivePack):
		return strings.TrimSuffix(path, "/"+serviceReceivePack), endpointReceivePack, true
	case path == serviceReceivePack:
		return "", endpointReceivePack, true
	default:
		return "", endpointUnknown, false
	}
}
