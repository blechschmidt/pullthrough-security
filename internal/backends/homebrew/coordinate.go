package homebrew

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/blechschmidt/pullthrough-security/internal/backends"
)

// Resolving the coordinate of a bottle requested on the registry-native path.
//
// The admission gates that run between Resolve and Fetch — name guard,
// dependency firewall, known-malware feed, and above all the policy gate, which
// applies only to a coordinate carrying BOTH a name and a version — need to know
// which formula version a blob is before a single byte of it is fetched. The
// blob URL does not say. The backend therefore establishes the coordinate from
// the best source available, in a fixed order:
//
//  1. The learned index. brew downloads the formula's image index along with
//     the bottle, and the backend records (repository, digest) -> version as
//     that index passes through (manifest.go). When brew downloads serially the
//     index arrives first and this costs a map lookup. When it downloads in
//     parallel the bottle request can overtake its manifest, so if a manifest
//     fetch is in progress for the bottle's repository the request waits for it
//     (bounded; flights.go) before looking again.
//
//  2. The formula JSON API. When the index has no entry — the proxy restarted,
//     the entry was evicted, or the manifest request was served by another
//     replica — the backend asks formulae.brew.sh for the formula's document and
//     looks the digest up among its current bottles. The document also carries
//     the formula's true name (resolving the lossy "+" spelling, see name.go)
//     and its version as "versions.stable", the same string the index yields.
//     The answer is memoized in the index. This applies to the core tap only
//     (formulae.brew.sh publishes nothing for third-party taps), and is skipped
//     entirely in offline (sealed) mode so Resolve performs no network I/O there.
//     If the API has no answer, the index is consulted once more: a manifest
//     that arrived while the API was being asked still wins.
//
//  3. The digest. When neither source knows the bottle — the formula API is
//     unreachable, the formula has since moved on to a newer version whose
//     bottles replaced this one in the document, or the repository belongs to a
//     third-party tap — the version becomes "sha256:<digest>": a stable,
//     collision-free stand-in that can never be mistaken for a real version
//     (which is always an OCI tag and so contains no ":"). The name still comes
//     from the repository path (or the formula document, if that much was
//     found). The point of this last resort is that the request is never left
//     without a version: every name-keyed rule (a denylisted or typosquatted
//     formula, a deny-by-default allowlist, a per-coordinate break-glass or
//     lockdown) still applies, and the policy gate still runs, instead of the
//     bottle slipping through as an uncoordinated blob. Rules keyed on a
//     specific version cannot match it, which is the unavoidable cost of not
//     knowing the version; the versionSource metadata and the
//     pullthrough_homebrew_bottle_version_fallback_total counter make that
//     condition visible.
//
// The order is deterministic, and sources 1 and 2 agree by construction, so a
// bottle resolves to the same coordinate on every replica that can reach either
// of them.

// Version sources, recorded per request in MetaVersionSource.
const (
	// versionSourceURL: the synthetic "/bottle/<name>/<version>/…" endpoint,
	// whose URL carries the coordinate.
	versionSourceURL = "url"
	// versionSourceManifest: learned from the OCI image index the client fetched
	// along with the bottle.
	versionSourceManifest = "manifest"
	// versionSourceFormulaAPI: recovered from the formula JSON API.
	versionSourceFormulaAPI = "formula-api"
	// versionSourceDigest: unknown; a version derived from the blob digest is
	// used so the gates still see a complete coordinate.
	versionSourceDigest = "digest"
)

const (
	// formulaLookupTimeout bounds the formula-API recovery of one bottle's
	// coordinate. It runs inside Resolve, ahead of the gates, so it must not be
	// able to stall a pull for long: on expiry the request proceeds with the
	// digest-derived version.
	formulaLookupTimeout = 5 * time.Second
	// unresolvedTTL is how long an empty-handed formula-API lookup is remembered
	// for a bottle before it is tried again.
	unresolvedTTL = time.Minute
	// lookupBackoff is how long formula-API recovery is suspended after the API
	// failed (unreachable, erroring, or timing out), so an outage costs one slow
	// lookup rather than formulaLookupTimeout on every bottle request.
	lookupBackoff = 30 * time.Second
	// maxFormulaLookupBytes bounds a per-formula document read during recovery
	// (a real one is tens of KiB).
	maxFormulaLookupBytes = 4 << 20 // 4 MiB
)

// digestVersion is the stand-in version for a bottle whose formula version is
// unknown: the blob's own content address, in the "sha256:<hex>" form the
// Docker backend also uses for digest-addressed objects.
func digestVersion(digest string) string { return "sha256:" + digest }

// bottleCoordinate establishes the formula name and version for a bottle
// requested on the registry-native path, and reports where the version came
// from. It always returns a non-empty name and version.
func (b *Backend) bottleCoordinate(ctx context.Context, res resource) (name, version, source string) {
	key := bottleKey{repo: res.repo, digest: res.digest}
	fact, ok := b.learned(ctx, key)
	if !ok {
		fact = b.recoverBottle(ctx, key)
		if !fact.known() {
			// The formula API had no answer. If the bottle's manifest request
			// arrived in the meantime, what it teaches supersedes that.
			if late, ok := b.learned(ctx, key); ok && late.known() {
				fact = late
			}
		}
	}
	name = res.name
	if fact.name != "" {
		name = fact.name
	}
	if fact.known() {
		return name, fact.version, fact.source
	}
	return name, digestVersion(res.digest), versionSourceDigest
}

// learned returns what the index holds for a bottle. If the version is not
// known yet and a manifest fetch is in progress for the bottle's repository —
// brew sent the two requests in parallel — it first waits (bounded) for that
// fetch to finish and teach the index.
func (b *Backend) learned(ctx context.Context, key bottleKey) (bottleFact, bool) {
	if fact, ok := b.index.get(key); ok && fact.known() {
		return fact, true
	}
	b.flights.wait(ctx, key.repo, b.manifestWait)
	return b.index.get(key)
}

// recoverBottle asks the formula JSON API about a bottle the index does not
// know, memoizes whatever it finds, and returns the fact now in force (the zero
// fact when recovery is not possible or not permitted).
func (b *Backend) recoverBottle(ctx context.Context, key bottleKey) bottleFact {
	tap, image := splitRepo(key.repo)
	if b.offline || tap != coreTap || b.lookupsSuspended() {
		return bottleFact{}
	}

	lookupCtx, cancel := context.WithTimeout(ctx, b.lookupTimeout)
	defer cancel()
	doc, found, err := b.lookupFormula(lookupCtx, image)
	if err != nil {
		if ctx.Err() != nil {
			// The client went away mid-lookup: that says nothing about the API or
			// the bottle, so remember nothing.
			return bottleFact{}
		}
		b.suspendLookups()
	}

	// Remember an empty-handed lookup briefly so it is not repeated per request.
	fact := bottleFact{expires: b.now().Add(unresolvedTTL)}
	if err == nil && found {
		fact.name = qualifyFormula(tap, doc.Name)
		if version := strings.TrimSpace(doc.Versions.Stable); validVersion(version) {
			// The document lists every platform's bottle for this version; record
			// them all, so the sibling platforms need no lookup of their own.
			known := bottleFact{name: fact.name, version: version, source: versionSourceFormulaAPI}
			for _, file := range doc.Bottle.Stable.Files {
				digest := strings.ToLower(strings.TrimSpace(file.SHA256))
				if len(digest) != sha256HexLen || !isHex(digest) {
					continue
				}
				if digest == key.digest {
					fact = known
					continue
				}
				b.index.putIfUnknown(bottleKey{repo: key.repo, digest: digest}, known)
			}
		}
	}
	return b.index.putIfUnknown(key, fact)
}

// lookupFormula fetches the formula JSON document for an image name, trying the
// formula names the image may stand for (formulaNameCandidates). It reports
// found=false when no candidate yields a usable document, and an error when the
// API itself failed and so could not give a definite answer. A document is
// accepted only if its own name maps back to the image under brew's forward
// mapping.
func (b *Backend) lookupFormula(ctx context.Context, image string) (formulaDoc, bool, error) {
	for _, candidate := range formulaNameCandidates(image) {
		doc, ok, err := b.fetchFormulaDoc(ctx, candidate)
		if err != nil {
			return formulaDoc{}, false, err
		}
		if !ok {
			continue
		}
		doc.Name = strings.TrimSpace(doc.Name)
		if doc.Name == "" || imageFormulaName(doc.Name) != image {
			continue
		}
		return doc, true, nil
	}
	return formulaDoc{}, false, nil
}

// fetchFormulaDoc fetches and decodes "/api/formula/<name>.json". It reports
// ok=false with a nil error when the API answered but there is no usable
// document under that name — it does not exist (404/410), or what is there is
// implausibly large or not a formula document — which is a statement about
// that one name. An error means the API failed to answer (unreachable, an
// error status, a broken transfer), which is a statement about the API and
// suspends further lookups.
func (b *Backend) fetchFormulaDoc(ctx context.Context, name string) (doc formulaDoc, ok bool, err error) {
	rawURL := b.joinPath("/api/formula/" + name + ".json").String()
	resp, err := b.get(ctx, rawURL, "")
	if err != nil {
		return formulaDoc{}, false, err
	}
	defer drainClose(resp.Body)
	if resp.Status == http.StatusNotFound || resp.Status == http.StatusGone {
		return formulaDoc{}, false, nil
	}
	if !resp.IsSuccess() {
		return formulaDoc{}, false, &backends.StatusError{Status: resp.Status, URL: rawURL}
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxFormulaLookupBytes+1))
	if err != nil {
		return formulaDoc{}, false, fmt.Errorf("homebrew %q: reading formula document: %w", b.name, err)
	}
	if len(data) > maxFormulaLookupBytes || json.Unmarshal(data, &doc) != nil {
		return formulaDoc{}, false, nil
	}
	return doc, true, nil
}

// lookupsSuspended reports whether formula-API recovery is in its backoff
// window after a recent failure.
func (b *Backend) lookupsSuspended() bool {
	until := b.lookupResume.Load()
	return until != 0 && b.now().UnixNano() < until
}

// suspendLookups opens the backoff window.
func (b *Backend) suspendLookups() {
	b.lookupResume.Store(b.now().Add(lookupBackoff).UnixNano())
}
