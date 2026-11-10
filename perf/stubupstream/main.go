// Command stubupstream is a deterministic, in-process stand-in for the real
// package-manager and Docker registries, used by the load-testing harness so the
// proxy can be driven at high request rates without depending on (or hammering)
// public infrastructure. It is NOT a production component.
//
// It serves two protocols:
//
//   - Generic artifact (package managers): any GET that is not a /v2/ Docker path
//     returns a deterministic body whose size is derived from the request path,
//     with a stable ETag. Repeating a path yields identical bytes, so the proxy's
//     content-addressable cache treats it as cacheable; unique paths model
//     cache-miss (cold-fill) load.
//
//   - Docker Registry v2: a minimal implementation enforcing the bearer-token
//     handshake. On startup it generates a fixed set of synthetic blobs and image
//     manifests, computes their sha256 digests, and serves them by digest with a
//     Docker-Content-Digest header (so the proxy's digest verification passes).
//     The digest set is published at GET /_perf/digests for the harness to feed
//     into the k6 script.
//
// Usage:
//
//	stubupstream -addr :9000 -blobs 50 -blob-size 65536
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"hash/fnv"
	"log"
	"net/http"
	"strconv"
	"strings"
)

func main() {
	addr := flag.String("addr", ":9000", "listen address")
	blobs := flag.Int("blobs", 50, "number of synthetic Docker blobs/manifests to generate")
	blobSize := flag.Int("blob-size", 64<<10, "size in bytes of each synthetic Docker blob")
	flag.Parse()

	reg := newRegistry(*blobs, *blobSize)

	mux := http.NewServeMux()
	mux.HandleFunc("/_perf/digests", reg.handleDigests)
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("ok")) })
	mux.HandleFunc("/token", reg.handleToken)
	mux.HandleFunc("/v2/", reg.handleV2)
	mux.HandleFunc("/", handleArtifact)

	log.Printf("stub upstream listening on %s (%d docker blobs of %d bytes)", *addr, *blobs, *blobSize)
	srv := &http.Server{Addr: *addr, Handler: mux}
	if err := srv.ListenAndServe(); err != nil {
		log.Fatalf("stub upstream: %v", err)
	}
}

// --- Generic artifact (package-manager) endpoint ----------------------------

// handleArtifact serves a deterministic body for any non-Docker path. The body
// length is a stable function of the path so repeated requests are byte-identical
// (cacheable) while distinct paths produce distinct content (cache-miss load).
func handleArtifact(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	h := fnv.New64a()
	_, _ = h.Write([]byte(r.URL.Path))
	seed := h.Sum64()
	// 1 KiB .. ~257 KiB, deterministic per path.
	size := 1024 + int(seed%(256<<10))
	etag := `"` + strconv.FormatUint(seed, 16) + `"`

	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("ETag", etag)
	w.Header().Set("Content-Length", strconv.Itoa(size))
	if r.Method == http.MethodHead {
		w.WriteHeader(http.StatusOK)
		return
	}
	buf := make([]byte, 4096)
	for i := range buf {
		buf[i] = byte(seed >> (uint(i%8) * 8))
	}
	written := 0
	for written < size {
		n := len(buf)
		if size-written < n {
			n = size - written
		}
		if _, err := w.Write(buf[:n]); err != nil {
			return
		}
		written += n
	}
}

// --- Docker Registry v2 emulation -------------------------------------------

const stubToken = "stub-bearer-token"

type registry struct {
	// blobs maps "sha256:<hex>" -> content.
	blobs map[string][]byte
	// manifests maps "sha256:<hex>" -> manifest JSON.
	manifests map[string][]byte
	blobDigests     []string
	manifestDigests []string
	indexBody       []byte
	indexDigest     string
}

func newRegistry(n, size int) *registry {
	r := &registry{
		blobs:     make(map[string][]byte, n),
		manifests: make(map[string][]byte, n),
	}
	for i := 0; i < n; i++ {
		blob := synthBytes(fmt.Sprintf("blob-%d", i), size)
		bd := digest(blob)
		r.blobs[bd] = blob
		r.blobDigests = append(r.blobDigests, bd)

		mf := []byte(fmt.Sprintf(
			`{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json","config":{"mediaType":"application/vnd.oci.image.config.v1+json","digest":%q,"size":%d},"layers":[{"mediaType":"application/vnd.oci.image.layer.v1.tar+gzip","digest":%q,"size":%d}]}`,
			bd, len(blob), bd, len(blob)))
		md := digest(mf)
		r.manifests[md] = mf
		r.manifestDigests = append(r.manifestDigests, md)
	}
	r.indexBody = []byte(`{"schemaVersion":2,"mediaType":"application/vnd.oci.image.index.v1+json","manifests":[]}`)
	r.indexDigest = digest(r.indexBody)
	return r
}

// handleDigests publishes the generated digest set. With ?kind=blobs or
// ?kind=manifests it returns a bare comma-separated list (text/plain) so the
// shell harness can consume it without jq; otherwise it returns full JSON.
func (r *registry) handleDigests(w http.ResponseWriter, req *http.Request) {
	switch req.URL.Query().Get("kind") {
	case "blobs":
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte(strings.Join(r.blobDigests, ",")))
	case "manifests":
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte(strings.Join(r.manifestDigests, ",")))
	default:
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"blobs":     r.blobDigests,
			"manifests": r.manifestDigests,
		})
	}
}

func (r *registry) handleToken(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_, _ = fmt.Fprintf(w, `{"token":%q,"expires_in":300}`, stubToken)
}

func (r *registry) handleV2(w http.ResponseWriter, req *http.Request) {
	if req.Header.Get("Authorization") != "Bearer "+stubToken {
		realm := "http://" + req.Host + "/token"
		w.Header().Set("WWW-Authenticate", `Bearer realm="`+realm+`",service="stub-registry"`)
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	path := req.URL.Path
	// GET /v2/ -> version check.
	if path == "/v2/" {
		w.Header().Set("Docker-Distribution-Api-Version", "registry/2.0")
		w.WriteHeader(http.StatusOK)
		return
	}

	kind, ref := parsePath(path)
	switch kind {
	case "blobs":
		body, ok := r.blobs[ref]
		if !ok {
			http.NotFound(w, req)
			return
		}
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Docker-Content-Digest", ref)
		w.Header().Set("Content-Length", strconv.Itoa(len(body)))
		if req.Method == http.MethodGet {
			_, _ = w.Write(body)
		}
	case "manifests":
		// A digest reference returns the image manifest; a tag returns the index.
		if body, ok := r.manifests[ref]; ok {
			w.Header().Set("Content-Type", "application/vnd.oci.image.manifest.v1+json")
			w.Header().Set("Docker-Content-Digest", ref)
			if req.Method == http.MethodGet {
				_, _ = w.Write(body)
			}
			return
		}
		// Treat anything else as a tag -> serve the (empty) index.
		w.Header().Set("Content-Type", "application/vnd.oci.image.index.v1+json")
		w.Header().Set("Docker-Content-Digest", r.indexDigest)
		if req.Method == http.MethodGet {
			_, _ = w.Write(r.indexBody)
		}
	default:
		http.NotFound(w, req)
	}
}

// parsePath splits "/v2/<name>/blobs/<ref>" or "/v2/<name>/manifests/<ref>" into
// its kind ("blobs"|"manifests") and reference (digest or tag).
func parsePath(path string) (kind, ref string) {
	for _, k := range []string{"/blobs/", "/manifests/"} {
		if i := strings.LastIndex(path, k); i >= 0 {
			return strings.Trim(k, "/"), path[i+len(k):]
		}
	}
	return "", ""
}

func synthBytes(seed string, size int) []byte {
	out := make([]byte, size)
	h := fnv.New64a()
	_, _ = h.Write([]byte(seed))
	s := h.Sum64()
	for i := range out {
		out[i] = byte(s >> (uint(i%8) * 8))
		if i%8 == 7 {
			s = s*1103515245 + 12345
		}
	}
	return out
}

func digest(b []byte) string {
	sum := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(sum[:])
}
