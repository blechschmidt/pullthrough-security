package proxy

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"os"

	"github.com/blechschmidt/pullthrough-security/internal/backends"
	"github.com/blechschmidt/pullthrough-security/internal/cache"
	"github.com/blechschmidt/pullthrough-security/internal/llmpkgscan"
)

// The LLM package-scan gate on the serve paths that do not go through
// serveCacheable (Task 174).
//
// A content gate that only runs on cached artifacts has a hole exactly the
// shape of everything a backend does not cache: a Maven snapshot jar, an image
// manifest pulled by tag, a model repository's code on a moving branch, an
// installer served from a path the protocol adapter does not know, a package a
// hostile index routes through a path that reads as an index. Those are
// streamed from the upstream straight to the client. This file is the gate on
// that stream, on Git LFS objects, and on the cache-federation endpoint a
// sibling proxy reads from.

// llmManifestMaxBytes bounds an image manifest held in memory on the direct
// path. Registries cap manifests at 4 MiB.
const llmManifestMaxBytes = 4 << 20

// directBody is what gateLLMPkgScanDirect leaves to serve: the response body,
// possibly replaced by a spooled copy, and its size when that is now known.
type directBody struct {
	content io.Reader
	size    int64 // -1 when unknown
	cleanup func()
}

// gateLLMPkgScanDirect puts a non-cacheable upstream response before the gate,
// before any of its bytes are written.
//
// Whether there is anything to examine is decided as on the cached path: a
// payload always is, anything else when its bytes are something a machine
// unpacks or runs. That takes the first bytes of the body only; a metadata
// document is then streamed on untouched. A response that is to be examined is
// first spooled to a temporary file — the scan needs the artifact whole, and
// the client must not receive a byte until the verdict exists — and then
// served from the spool.
//
// It returns the body to serve and true, or false when a refusal was written
// (or the client is gone).
func (g *Gateway) gateLLMPkgScanDirect(w http.ResponseWriter, r *http.Request, name, ecosystem string, resolved *backends.Resolved, body io.Reader, size int64) (directBody, bool) {
	pass := directBody{content: body, size: size, cleanup: func() {}}
	svc := g.deps.LLMPkgScan
	if !svc.AppliesTo(ecosystem, name) || r.Method == http.MethodHead {
		return pass, true
	}
	art := llmPkgScanArtifactFor(ecosystem, name, resolved, "", size)
	sub := llmScanSubject{backend: name, ecosystem: ecosystem, art: art}

	if resolved.Artifact.Kind == backends.KindOCIManifest {
		return g.gateLLMManifestDirect(w, r, sub, resolved, body)
	}

	br := bufio.NewReaderSize(body, llmpkgscan.SniffBytes)
	if art.Class != llmpkgscan.ClassPayload {
		prefix, _ := br.Peek(llmpkgscan.SniffBytes)
		if llmpkgscan.NeedsLongProbe(prefix) {
			// Compressed: telling an index from an archive means looking inside.
			br = bufio.NewReaderSize(br, llmpkgscan.ProbeBytes)
			prefix, _ = br.Peek(llmpkgscan.ProbeBytes)
		}
		if !llmpkgscan.Applicable(art.Class, art.IndexArchive, prefix, art.Filename) {
			pass.content = br
			return pass, true
		}
	}

	// Something to examine: hold the response in a spool file. One byte past the
	// scan limit is enough to know the artifact is too large to scan whole.
	limit := svc.Limits().MaxArtifactBytes
	spool, err := os.CreateTemp("", "pullthrough-llmscan-*")
	if err != nil {
		g.deps.Logger.Error("LLM package-scan gate: creating a spool file failed", "backend", name, "error", err)
		http.Error(w, "internal error while holding the response for scanning", http.StatusInternalServerError)
		return pass, false
	}
	cleanup := func() {
		_ = spool.Close()
		_ = os.Remove(spool.Name())
	}
	hasher := sha256.New()
	n, err := io.Copy(io.MultiWriter(spool, hasher), io.LimitReader(br, limit+1))
	if err != nil {
		cleanup()
		if r.Context().Err() == nil {
			g.deps.Logger.Warn("reading the upstream response for scanning failed",
				"backend", name, "upstream", resolved.UpstreamURL, "error", err)
			http.Error(w, "upstream fetch failed", http.StatusBadGateway)
		}
		return pass, false
	}
	sub.art.Size = n
	oversized := n > limit
	if !oversized {
		// The whole artifact is in hand: its digest is known and the verdict can
		// be stored under it.
		sub.art.Digest = "sha256:" + hex.EncodeToString(hasher.Sum(nil))
	}
	// An artifact too large to hold is not read to its end, so it has no digest
	// and no verdict can be filed for it: it is reported oversized and the fail
	// mode decides. (A metadata-only scan needs the artifact in the cache.)
	path := spool.Name()
	sub.open = func(context.Context) (io.ReadCloser, error) { return os.Open(path) }

	if !g.admitLLMPkgScan(w, r, sub) {
		cleanup()
		return pass, false
	}
	if _, err := spool.Seek(0, io.SeekStart); err != nil {
		cleanup()
		http.Error(w, "internal error while serving the scanned response", http.StatusInternalServerError)
		return pass, false
	}
	out := directBody{content: spool, size: n, cleanup: cleanup}
	if oversized {
		// Served under fail-open: what was spooled, then the rest of the stream.
		out.content, out.size = io.MultiReader(spool, br), size
	}
	return out, true
}

// gateLLMManifestDirect puts an image manifest that is not cached — one pulled
// by tag — before the gate. A manifest is small, so it is held in memory; its
// digest is computed here, from the very bytes that will be served.
func (g *Gateway) gateLLMManifestDirect(w http.ResponseWriter, r *http.Request, sub llmScanSubject, resolved *backends.Resolved, body io.Reader) (directBody, bool) {
	pass := directBody{content: body, size: -1, cleanup: func() {}}
	manifest, err := io.ReadAll(io.LimitReader(body, llmManifestMaxBytes+1))
	if err != nil {
		if r.Context().Err() == nil {
			http.Error(w, "upstream fetch failed", http.StatusBadGateway)
		}
		return pass, false
	}
	out := directBody{content: bytes.NewReader(manifest), size: int64(len(manifest)), cleanup: func() {}}
	if len(manifest) > llmManifestMaxBytes {
		// Not a manifest any registry would serve. It is passed to the gate as it
		// is, which reports it as a package it could not examine.
		out.content, out.size = io.MultiReader(bytes.NewReader(manifest), body), -1
	}
	backend, ok := g.deps.Backends.Get(sub.backend)
	if !ok {
		return out, true
	}
	sum := sha256.Sum256(manifest)
	sub.art.Digest = "sha256:" + hex.EncodeToString(sum[:])
	sub.art.Size = int64(len(manifest))
	sub.art.Class = llmpkgscan.ClassPayload
	sub.open = func(context.Context) (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(manifest)), nil }
	sub.image = g.llmImageSource(r, sub.backend, backend, resolved.Coordinate.Name)
	sub.reviewCoordinate = imageReviewCoordinate(resolved.Coordinate.Name, sub.art.Digest)
	if !g.admitLLMPkgScan(w, r, sub) {
		return pass, false
	}
	return out, true
}

// GateLFSObject puts a Git LFS object before the LLM package-scan gate. It is
// called by the Git backend for every object request — a cache hit as much as a
// miss, a Range request as much as a whole download — after the object is in
// the cache and before any of its bytes are written.
//
// A Git clone or fetch is not this gate's: commits are what the commit-scan
// pipeline reads (for the repositories it watches; it refuses no clone). The
// objects an LFS pointer stands for never appear in a commit's diff, so no
// commit scan could see them, and this is the one gate on them. An LFS
// object is an opaque blob of any kind, so it is judged from its bytes: an
// archive, an executable, a script or a pickle is examined; an image, a video
// or a dataset is not.
//
// It returns true when the object may be served and false when a refusal was
// written.
func (g *Gateway) GateLFSObject(w http.ResponseWriter, r *http.Request, upstreamName, repo, oid string, size int64, cacheKey string) bool {
	svc := g.deps.LLMPkgScan
	if !svc.AppliesTo(llmpkgscan.EcosystemGitLFS, upstreamName) {
		return true
	}
	digest := "sha256:" + oid
	admitted := g.admitLLMPkgScan(w, r, llmScanSubject{
		backend:   upstreamName,
		ecosystem: llmpkgscan.EcosystemGitLFS,
		art: llmpkgscan.Artifact{
			Ecosystem: llmpkgscan.EcosystemGitLFS,
			Upstream:  upstreamName,
			Name:      repo,
			Version:   oid,
			Digest:    digest,
			Size:      size,
			Class:     llmpkgscan.ClassUnknown,
		},
		open: g.llmScanCacheOpener(cacheKey, ""),
		evict: func(ctx context.Context) {
			if err := g.deps.Cache.Delete(ctx, cacheKey); err != nil && !errors.Is(err, cache.ErrNotFound) {
				g.deps.Logger.Warn("LLM package-scan gate: evicting a Git LFS object failed", "key", cacheKey, "error", err)
			}
		},
	})
	if !admitted {
		// The Git backend calls this gate directly, not through gateTrace: name
		// the refusal in the download log here (Task 176).
		noteRefusal(r, "llmpkgscan")
	}
	return admitted
}

// ErrPeerRefused is returned by PeerServeGuard for an artifact this proxy has a
// verdict against.
var ErrPeerRefused = errors.New("the artifact is refused by this proxy's LLM package-content scan")

// PeerServeGuard decides whether a cached entry may be handed to a sibling
// proxy through the cache-federation endpoint. That endpoint serves the cache
// by key, to another proxy rather than to a package client, and so runs none of
// the admission gates; the receiving proxy runs its own. What must not happen
// is that this proxy hands out bytes it has itself judged malicious — an
// artifact sits in the cache from the moment it is fetched until the verdict
// that evicts it, and under the annotate action it stays there.
//
// So a stored verdict is enforced here: an entry whose bytes have a verdict the
// gate currently refuses, or that is a blob implicated by a refused image, is
// not served to a peer. Nothing is scanned. It returns nil to allow.
func (g *Gateway) PeerServeGuard(ctx context.Context, _ string, stat *cache.Stat) error {
	svc := g.deps.LLMPkgScan
	if !svc.Enabled() || stat == nil {
		return nil
	}
	digest := stat.Metadata[cache.MetaDigest]
	if digest == "" {
		return nil
	}
	if _, standing, ok := svc.StoredVerdict(ctx, digest); ok && standing.Refused {
		svc.NoteEnforced("peer")
		return ErrPeerRefused
	}
	if svc.BlobStatus(ctx, digest).Refused {
		svc.NoteEnforced("peer")
		return ErrPeerRefused
	}
	return nil
}
