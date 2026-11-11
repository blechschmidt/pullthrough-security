package nix

import (
	"strings"

	"github.com/blechschmidt/pullthrough-security/internal/backends"
)

// A Nix binary cache (https://cache.nixos.org and any HTTP binary cache built by
// `nix copy --to`) is a small, mostly content-addressed HTTP tree. The proxy
// mounts a cache at its route root ("<publicBase>/v1/<name>", configured as a
// Nix `substituters` entry) and honors the binary-cache protocol:
//
//	/nix-cache-info             cache descriptor (StoreDir, Priority, ...)  (live)
//	/<storehash>.narinfo        signed metadata for one store path         (live, sig-verified)
//	/nar/<filehash>.nar[.ext]   the (compressed) NAR archive               (immutable, verified)
//
// The <storehash> is the 32-character Nix base-32 truncated hash that names a
// store path (/nix/store/<storehash>-<name>). The <filehash> is the Nix base-32
// SHA-256 of the compressed NAR file and is literally the NAR's content address:
// the file name equals its own hash, so a fetched NAR can be verified against the
// hash in its URL with no sibling resource (see verify.go), exactly as the Julia
// backend verifies a tarball against the git-tree-sha1 in its URL.
//
// This file classifies an inbound path (with the "/v1/<name>" route prefix
// already stripped, retaining its leading slash) into one of these resource
// kinds and extracts the storehash/filehash, which feed the admission gates and
// the cacheability decision. Every path segment is validated because the upstream
// URL is built from these segments.

// resourceKind enumerates the classes of resource a binary-cache path addresses.
type resourceKind int

const (
	// kindCacheInfo is the /nix-cache-info descriptor. Small, mutable config
	// (priority/store dir), served live and not content-addressed.
	kindCacheInfo resourceKind = iota
	// kindNarInfo is a /<storehash>.narinfo document. It is served live so its
	// ed25519 signature is re-verified on every fetch and its URL field rewritten
	// through the proxy; it is not cached (and never gated, being small text).
	kindNarInfo
	// kindNar is a /nar/<filehash>.nar[.ext] archive. Immutable, cacheable, and
	// verified against the SHA-256 content address named in its URL.
	kindNar
)

// storeHashLen is the character length of a store-path hash: Nix truncates the
// store-path hash to 20 bytes (160 bits), which is 32 Nix base-32 characters.
const storeHashLen = 32

// narInfoSuffix is the extension of a narinfo document.
const narInfoSuffix = ".narinfo"

// narSuffix is the extension that precedes any optional compression suffix on a
// NAR file name.
const narSuffix = ".nar"

// knownCompressionExts are the compression suffixes a NAR file may carry. The
// uncompressed form carries none. A name that is the SHA-256 of the file as
// stored is verifiable under every one of them without a codec; a name that is
// the SHA-256 of the uncompressed NAR is verifiable under the ones the backend
// decodes (see decodableExts in verify.go).
var knownCompressionExts = []string{".xz", ".zst", ".zstd", ".bz2", ".br", ".lzip", ".gz"}

// resource is the parsed classification of an inbound binary-cache request.
type resource struct {
	kind resourceKind
	// filename is the final path component, for diagnostics.
	filename string
	// storeHash is the store-path hash of a narinfo request; empty otherwise.
	storeHash string
	// fileHash is the content-address hash of a NAR request; empty otherwise.
	fileHash string
	// fileHashVerifiable reports whether fileHash is a Nix base-32 SHA-256 the
	// backend can recompute. A hash of another length is still a valid content
	// address (so it is cached), but is served unverified.
	fileHashVerifiable bool
}

// classify parses an inbound path into a resource. It returns ok=false for paths
// that do not fit the binary-cache protocol, so an unrecognized request is
// reported as unsupported rather than blindly proxied.
func classify(path string) (resource, bool) {
	clean := strings.Trim(path, "/")
	if clean == "" {
		return resource{}, false
	}
	segs := strings.Split(clean, "/")
	for _, s := range segs {
		if s == "" || s == "." || s == ".." {
			return resource{}, false
		}
	}

	switch {
	case len(segs) == 1 && segs[0] == "nix-cache-info":
		return resource{kind: kindCacheInfo, filename: segs[0]}, true

	case len(segs) == 1 && strings.HasSuffix(segs[0], narInfoSuffix):
		hash := strings.TrimSuffix(segs[0], narInfoSuffix)
		if len(hash) == storeHashLen && isNixBase32(hash) {
			return resource{kind: kindNarInfo, filename: segs[0], storeHash: hash}, true
		}

	case len(segs) == 2 && segs[0] == "nar":
		if hash, _, ok := parseNarName(segs[1]); ok && isNixBase32(hash) {
			return resource{
				kind:               kindNar,
				filename:           segs[1],
				fileHash:           hash,
				fileHashVerifiable: len(hash) == nixBase32Len(sha256Bytes),
			}, true
		}
	}
	return resource{}, false
}

// parseNarName splits a NAR file name "<hash>.nar[.ext]" into its content-address
// hash and optional compression extension. It returns ok=false if the name does
// not carry the ".nar" marker.
func parseNarName(name string) (hash, ext string, ok bool) {
	rest := name
	for _, ce := range knownCompressionExts {
		if strings.HasSuffix(rest, ce) {
			ext = ce
			rest = strings.TrimSuffix(rest, ce)
			break
		}
	}
	if !strings.HasSuffix(rest, narSuffix) {
		return "", "", false
	}
	hash = strings.TrimSuffix(rest, narSuffix)
	if hash == "" {
		return "", "", false
	}
	return hash, ext, true
}

// cacheable reports whether the resource may be cached. Only the content-
// addressed NAR archives are immutable; nix-cache-info and narinfo are served
// live (so the narinfo signature is re-verified and its URL re-rewritten).
func (r resource) cacheable() bool {
	return r.kind == kindNar
}

// artifact classifies the resource for the content gates (see
// backends.ArtifactClass). A NAR is the store path itself — the files Nix
// unpacks into /nix/store and that are then run or linked against — so it is
// the payload, compressed or not. The narinfo that describes a store path and
// the nix-cache-info descriptor are small text documents a client only reads.
func (r resource) artifact() backends.Artifact {
	switch r.kind {
	case kindNar:
		return backends.Payload()
	case kindNarInfo, kindCacheInfo:
		return backends.Metadata()
	default:
		return backends.Artifact{}
	}
}

// verifiable reports whether the backend should recompute and check the NAR
// against the SHA-256 in its URL.
func (r resource) verifiable() bool {
	return r.kind == kindNar && r.fileHashVerifiable
}

// kindLabel returns a stable diagnostic label for a resource kind.
func (r resource) kindLabel() string {
	switch r.kind {
	case kindCacheInfo:
		return "cache-info"
	case kindNarInfo:
		return "narinfo"
	case kindNar:
		return "nar"
	default:
		return "other"
	}
}
