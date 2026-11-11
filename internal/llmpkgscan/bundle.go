package llmpkgscan

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
)

// Verdicts in an air-gap bundle.
//
// The gate needs an LLM provider; an air-gapped instance has none. What it can
// have is the verdicts the connected instance already reached on the very bytes
// it is being handed: a verdict is keyed by the artifact's digest, so it means
// the same thing on either side of the gap. The bundle export collects the
// verdicts on record for the artifacts it carries, and the import files them in
// the importing instance's verdict store — after which a pull there is answered
// from the store exactly like a second pull on the connected side: a refusing
// verdict is enforced, a clean one admits the artifact, and no scan is needed.
//
// A verdict is looked up under a key derived from the digest, the model and
// the prompt version. The importing instance therefore has to be configured
// with the same llmPackageScan.model (and run a release with the same prompt
// version) for an imported verdict to be the one it finds; otherwise it has no
// verdict for the artifact and its fail mode decides.

// BundleGate is the gate name this package's verdicts carry in a bundle.
const BundleGate = "llmpkgscan"

// maxBundleVerdictBytes bounds one verdict record read from a bundle. A stored
// verdict is a few kilobytes; an image's lists every blob.
const maxBundleVerdictBytes = 4 << 20

// BundledVerdict is one verdict prepared for a bundle.
type BundledVerdict struct {
	// Digest is the "sha256:<hex>" digest of the artifact the verdict is about.
	Digest string
	// Record is the verdict's JSON encoding.
	Record []byte
}

// ExportVerdicts returns the verdicts in store whose artifact digest
// ("sha256:<hex>") is in digests, every variant of each (a full reading, a
// metadata-only one, an image's), ordered by digest and key.
func ExportVerdicts(ctx context.Context, store VerdictStore, digests map[string]bool) ([]BundledVerdict, error) {
	if store == nil || len(digests) == 0 {
		return nil, nil
	}
	all, err := store.List(ctx)
	if err != nil {
		return nil, fmt.Errorf("llmpkgscan: listing verdicts: %w", err)
	}
	sort.Slice(all, func(i, j int) bool {
		if all[i].Digest != all[j].Digest {
			return all[i].Digest < all[j].Digest
		}
		return all[i].Key < all[j].Key
	})
	var out []BundledVerdict
	for _, v := range all {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		h, ok := NormalizeDigest(v.Digest)
		if !ok || !digests["sha256:"+h] {
			continue
		}
		if validateBundledVerdict(v) != nil {
			// A record that would be refused on import is not worth carrying.
			continue
		}
		raw, err := json.Marshal(v)
		if err != nil {
			return nil, fmt.Errorf("llmpkgscan: encoding verdict %s: %w", v.Key, err)
		}
		out = append(out, BundledVerdict{Digest: "sha256:" + h, Record: raw})
	}
	return out, nil
}

// ErrVerdictPresent is returned by ImportVerdict when the store already holds
// a verdict under the record's key. The stored one is kept: a verdict this
// instance reached, or imported earlier, is not replaced by a bundle.
var ErrVerdictPresent = errors.New("llmpkgscan: a verdict is already stored under this key")

// ImportVerdict validates a verdict record from a bundle and files it in store.
// digest is the artifact digest the bundle states for it; the record must be
// about exactly those bytes.
//
// It checks what the store's key structure relies on, so that a record cannot
// be filed as the verdict of an artifact other than the one it names: the key
// must be the one the gate derives from the record's own digest, model, prompt
// version and variant. It does not, and cannot, check that the verdict is the
// one a scan would reach — that is a matter of trusting the bundle, which the
// caller establishes before calling (see mirror.ImportOptions.Verdicts).
func ImportVerdict(ctx context.Context, store VerdictStore, digest string, record []byte) (*Verdict, error) {
	if store == nil {
		return nil, errors.New("llmpkgscan: no verdict store")
	}
	if len(record) > maxBundleVerdictBytes {
		return nil, fmt.Errorf("llmpkgscan: verdict record is %d bytes, over the %d-byte bound", len(record), maxBundleVerdictBytes)
	}
	var v Verdict
	if err := json.Unmarshal(record, &v); err != nil {
		return nil, fmt.Errorf("llmpkgscan: verdict record is not valid JSON: %w", err)
	}
	if err := validateBundledVerdict(&v); err != nil {
		return nil, err
	}
	want, ok := NormalizeDigest(digest)
	if got, _ := NormalizeDigest(v.Digest); !ok || got != want {
		return nil, fmt.Errorf("llmpkgscan: verdict record is about %s, not about the artifact %s it was carried for", v.Digest, digest)
	}
	if existing, err := store.Get(ctx, v.Key); err == nil && existing != nil {
		return existing, ErrVerdictPresent
	} else if err != nil && !errors.Is(err, ErrNotFound) {
		return nil, fmt.Errorf("llmpkgscan: reading the verdict store: %w", err)
	}
	if err := store.Put(ctx, &v); err != nil {
		return nil, fmt.Errorf("llmpkgscan: storing the verdict: %w", err)
	}
	return &v, nil
}

// variantOf names the variant a stored verdict was filed under (see
// variantFor): how the artifact behind the digest was read.
func variantOf(v *Verdict) string {
	switch {
	case v.Kind == KindImage:
		return variantImage
	case v.RootFS && v.Scope == ScopeMetadataOnly:
		return variantLayerMetadataOnly
	case v.RootFS:
		return variantLayer
	case v.Scope == ScopeMetadataOnly:
		return variantMetadataOnly
	}
	return variantFull
}

// validateBundledVerdict checks that a verdict is internally consistent: a
// sha256 digest, one of the three verdicts, a confidence within [0,1], a model
// and prompt version, and a key that is the one the gate derives from them.
func validateBundledVerdict(v *Verdict) error {
	h, ok := NormalizeDigest(v.Digest)
	if !ok {
		return fmt.Errorf("llmpkgscan: verdict record names %q, which is not a sha256 digest", v.Digest)
	}
	switch v.Verdict {
	case VerdictMalicious, VerdictSuspicious, VerdictBenign:
	default:
		return fmt.Errorf("llmpkgscan: verdict record carries the unknown verdict %q", v.Verdict)
	}
	if !(v.Confidence >= 0 && v.Confidence <= 1) { // also rejects NaN
		return fmt.Errorf("llmpkgscan: verdict record carries confidence %v, outside [0,1]", v.Confidence)
	}
	if v.Model == "" || v.PromptVersion <= 0 {
		return errors.New("llmpkgscan: verdict record names no model or prompt version")
	}
	switch v.Scope {
	case "", ScopeMetadataOnly:
	default:
		return fmt.Errorf("llmpkgscan: verdict record carries the unknown scope %q", v.Scope)
	}
	if want := CacheKeyVariant(h, v.Model, v.PromptVersion, variantOf(v)); v.Key != want {
		return fmt.Errorf("llmpkgscan: verdict record is filed under key %q, which is not the key of the artifact, model and prompt version it names", v.Key)
	}
	// What an image verdict says about blobs is acted on when those blobs are
	// pulled, so it must be about blobs of that image: every digest well-formed,
	// and nothing implicated, declared unexamined or named as the config that is
	// not among the blobs the verdict lists.
	listed := make(map[string]bool, len(v.Blobs))
	for _, d := range v.Blobs {
		h, ok := NormalizeDigest(d)
		if !ok {
			return fmt.Errorf("llmpkgscan: verdict record lists blob %q, which is not a sha256 digest", d)
		}
		listed[h] = true
	}
	about := append(append([]string(nil), v.Implicated...), v.Unexamined...)
	if v.Config != "" {
		about = append(about, v.Config)
	}
	for _, d := range about {
		h, ok := NormalizeDigest(d)
		if !ok {
			return fmt.Errorf("llmpkgscan: verdict record lists blob %q, which is not a sha256 digest", d)
		}
		if !listed[h] {
			return fmt.Errorf("llmpkgscan: verdict record makes a statement about blob %q, which is not one of the image's blobs", d)
		}
	}
	if v.Kind != KindImage && (len(v.Blobs) > 0 || v.Config != "") {
		return errors.New("llmpkgscan: verdict record lists image blobs but is not the verdict of an image")
	}
	if v.Kind == KindImage && v.RootFS {
		return errors.New("llmpkgscan: verdict record is both an image verdict and the reading of a single layer")
	}
	return nil
}
