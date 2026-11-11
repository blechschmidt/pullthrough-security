package llmpkgscan

import (
	"context"
	"strings"
)

// Blobs of scanned images.
//
// An image verdict is stored under the manifest's digest, but a client fetches
// an image in pieces: the manifest, then the config and every layer as separate
// blobs, by digest. Refusing only the manifest would leave the pieces of an
// image the gate judged malicious downloadable by anyone who has the manifest
// from elsewhere; examining every blob on its own, on the other hand, would pay
// for each layer twice — once in the image, once alone.
//
// So the gate remembers, for every blob of an image it has a verdict on, what
// that verdict says about the blob. A blob pulled later is then
//
//   - refused, when a verdict the current action refuses implicates it — it is
//     a layer the verdict's evidence cites, or the config of that image;
//   - served without a scan of its own, when an image scan read it in full;
//   - examined on its own (as the layer archive it is), when no image scan did.
//
// Three rules keep the index from becoming a weakness of its own.
//
// Only what a scan read counts as examined. The budgets of an image scan are
// shared by all its layers and spent top-most layer first, so on a large image
// the base layers are named in the verdict as not examined. Such a layer is NOT
// covered by that verdict: it is examined on its own when it is pulled, with a
// budget of its own. Otherwise padding an image with a few large top layers
// would be all it takes to get a layer served that no scan ever opened.
//
// Only the implicated blobs of a refused image are refused, never every blob it
// has: images share their base layers with thousands of others, and refusing
// those because one image built on them is malicious would let anyone take a
// popular base image offline by publishing malware on top of it.
//
// And the config is refused only as the config of a refused image, not as a
// digest. A manifest can name any blob of the registry as its config, so "the
// config of a malicious image is refused" would, taken literally, let anyone
// have a blob of their choosing refused for everybody: publish a throwaway
// image that names another image's config (or one of its small layers) and
// carries something blatant in a layer of its own. Therefore
//
//   - a blob is implicated as a config only when it reads as an image config
//     (so a layer named as "config" is not), and
//   - a config that an image the gate currently serves also has as its config
//     is served. A config pins the content of its layers — every runtime checks
//     them against its diff IDs — so two images that share one are the same
//     image, or one of them is a forgery no runtime will start. Either way the
//     refused image stays refused where it matters: at its manifest, and at the
//     layers its verdict cites, for which no such exception exists.

// Bounds on the blob index.
const (
	// maxBlobEntries bounds the blobs indexed; maxBlobVerdicts the image verdicts
	// remembered per blob as merely covering it (a base layer is shared by any
	// number of images).
	maxBlobEntries  = 200000
	maxBlobVerdicts = 64
)

// blobRole is what one image verdict says about one of the image's blobs.
type blobRole uint8

const (
	// blobExamined: the scan read as much of the blob as a scan of the blob
	// alone would (LayerFact.Covered) — its config, a layer whose members it
	// listed completely, or one cut short only by the size limit.
	blobExamined blobRole = 1 << iota
	// blobImplicated: the verdict holds something against the blob.
	blobImplicated
	// blobIsConfig: the blob is the image's config, and reads as an image config.
	blobIsConfig
)

// implicatedBlobs returns the blobs of an image a verdict holds something
// against: for any verdict other than benign, the image's config — when it is
// an image config, see above — and the layers its evidence cites.
//
// A citation the proxy confirmed (the quoted text is in the named file) is what
// implicates a layer. Only when no citation inside a layer could be confirmed
// do unconfirmed ones count, and then only those naming a file that exists: the
// model's say-so about a path is not grounds for refusing a layer other images
// share.
func implicatedBlobs(image *imageBuild, v *Verdict) []string {
	if v.Verdict == VerdictBenign {
		return nil
	}
	seen := map[string]bool{}
	var out []string
	add := func(digest string) {
		if digest != "" && !seen[digest] {
			seen[digest] = true
			out = append(out, digest)
		}
	}
	add(image.imageConfig)
	cited := func(confirmedOnly bool) (n int) {
		for _, ev := range v.Evidence {
			if confirmedOnly != ev.Verified {
				continue
			}
			dir, _, ok := layerRelative(ev.Path)
			if !ok {
				continue
			}
			if !ev.Verified {
				if _, exists := image.tree.Lookup(ev.Path); !exists {
					continue
				}
			}
			if d := image.layerDirs[dir]; d != "" {
				add(d)
				n++
			}
		}
		return n
	}
	if cited(true) == 0 {
		cited(false)
	}
	return out
}

// indexBlobs records the blobs of an image verdict.
func (s *Service) indexBlobs(v *Verdict) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.indexBlobsLocked(v)
}

func (s *Service) indexBlobsLocked(v *Verdict) {
	if v == nil || v.Kind != KindImage || len(v.Blobs) == 0 {
		return
	}
	set := func(digests []string) map[string]bool {
		out := make(map[string]bool, len(digests))
		for _, d := range digests {
			if h, ok := NormalizeDigest(d); ok {
				out[h] = true
			}
		}
		return out
	}
	implicated, unexamined := set(v.Implicated), set(v.Unexamined)
	config, _ := NormalizeDigest(v.Config)
	for _, d := range v.Blobs {
		h, ok := NormalizeDigest(d)
		if !ok {
			continue
		}
		var role blobRole
		if !unexamined[h] {
			role |= blobExamined
		}
		if implicated[h] {
			role |= blobImplicated
		}
		if config != "" && h == config {
			role |= blobIsConfig
		}
		if role == 0 {
			// A layer the manifest lists and the scan never read: this verdict says
			// nothing about it.
			continue
		}
		roles := s.blobs[h]
		if roles == nil {
			if len(s.blobs) >= maxBlobEntries {
				// Forget an arbitrary blob that is merely covered. A blob the index
				// does not know is examined on its own, so forgetting costs a scan,
				// never a refusal.
				for k, known := range s.blobs {
					if merelyCovered(known) {
						delete(s.blobs, k)
						break
					}
				}
				if len(s.blobs) >= maxBlobEntries {
					continue
				}
			}
			roles = make(map[string]blobRole, 1)
			s.blobs[h] = roles
		}
		if _, known := roles[v.Key]; !known && len(roles) >= maxBlobVerdicts && role == blobExamined {
			// Widely shared: enough verdicts already say it was examined. One that
			// implicates it, or has it as its config, is always recorded.
			continue
		}
		roles[v.Key] = role
	}
}

// merelyCovered reports whether no verdict implicates the blob or has it as its
// config: forgetting such an entry can cost a scan and nothing else.
func merelyCovered(roles map[string]blobRole) bool {
	for _, r := range roles {
		if r != blobExamined {
			return false
		}
	}
	return true
}

// BlobStatus is what the image verdicts on record say about one blob.
type BlobStatus struct {
	// Covered reports that at least one current image verdict examined the blob:
	// it was read in full as part of an image and needs no scan of its own.
	Covered bool
	// Refused reports that a verdict the gate currently refuses implicates the
	// blob. Verdict is that verdict.
	Refused bool
	Verdict *Verdict
}

// BlobStatus reports what the image verdicts on record say about the blob with
// the given digest. It scans nothing. Safe on a nil receiver.
func (s *Service) BlobStatus(ctx context.Context, digest string) BlobStatus {
	var st BlobStatus
	if s == nil {
		return st
	}
	h, ok := NormalizeDigest(digest)
	if !ok {
		return st
	}
	s.mu.Lock()
	roles := make(map[string]blobRole, len(s.blobs[h]))
	for k, r := range s.blobs[h] {
		roles[k] = r
	}
	s.mu.Unlock()

	// Verdicts that implicate the blob, or have it as their config, are the ones
	// that can refuse it or keep it from being refused: every one that is still
	// current is consulted.
	var (
		asLayer, asConfig *Verdict // refusing verdicts that implicate the blob
		vouched           bool     // an image the gate serves has it as its config
	)
	earlier := func(cur, v *Verdict) *Verdict {
		if cur == nil || v.Key < cur.Key {
			return v // the same answer on every call, whatever the map order
		}
		return cur
	}
	for key, role := range roles {
		if role == blobExamined {
			continue
		}
		v := s.lookup(ctx, key)
		if v == nil {
			continue // expired or evicted: it no longer says anything
		}
		if role&blobExamined != 0 {
			st.Covered = true
		}
		refused := s.Standing(v).Refused
		switch {
		case refused && role&blobImplicated != 0 && role&blobIsConfig != 0:
			asConfig = earlier(asConfig, v)
		case refused && role&blobImplicated != 0:
			asLayer = earlier(asLayer, v)
		case !refused && role&blobIsConfig != 0:
			vouched = true
		}
	}
	switch {
	case asLayer != nil:
		st.Refused, st.Verdict = true, asLayer
	case asConfig != nil && !vouched:
		st.Refused, st.Verdict = true, asConfig
	}
	if st.Refused {
		st.Covered = true
		return st
	}
	if st.Covered {
		return st
	}
	// One current verdict that examined the blob settles the rest.
	for key, role := range roles {
		if role != blobExamined {
			continue
		}
		if s.lookup(ctx, key) != nil {
			st.Covered = true
			return st
		}
	}
	return st
}

// ReportFor builds the report a pull of art would get from a stored verdict,
// without scanning anything: the verdict under the current thresholds, with its
// findings. It is how a stored verdict is enforced on a path that does not go
// through Assess — a blob of a refused image, an artifact a sibling proxy asks
// for. Safe on a nil receiver (it returns nil).
func (s *Service) ReportFor(art Artifact, v *Verdict) *Report {
	if s == nil || v == nil {
		return nil
	}
	if d, ok := NormalizeDigest(art.Digest); ok {
		art.Digest = "sha256:" + d
	} else {
		art.Digest = v.Digest
	}
	rep := s.report(art, v)
	rep.Cached = true
	return rep
}

// StoredVerdict returns the verdict on record for the bytes with the given
// sha256 digest, under the current model and prompt version, and how the gate
// currently reads it. It scans nothing. ok is false when there is none.
//
// Every way an artifact can have been read is consulted — as a whole, as the
// metadata of one too large to read whole, as a layer of a root filesystem, as
// the image a manifest describes — and the most severe reading wins: the bytes
// are the same whatever the reading was called.
func (s *Service) StoredVerdict(ctx context.Context, digest string) (v *Verdict, standing Standing, ok bool) {
	if s == nil {
		return nil, Standing{}, false
	}
	h, valid := NormalizeDigest(digest)
	if !valid {
		return nil, Standing{}, false
	}
	for _, variant := range allVariants {
		cand := s.lookup(ctx, CacheKeyVariant(h, s.cfg.Model, PromptVersion, variant))
		if cand == nil {
			continue
		}
		st := s.Standing(cand)
		if !ok || st.Risk > standing.Risk || (st.Refused && !standing.Refused) {
			v, standing, ok = cand, st, true
		}
	}
	return v, standing, ok
}

// DescribeVariant names, for an operator, how a verdict's artifact was read.
func DescribeVariant(v *Verdict) string {
	if v == nil {
		return ""
	}
	var parts []string
	switch v.Kind {
	case KindImage:
		parts = append(parts, "image")
	case KindFile:
		parts = append(parts, "single file")
	}
	if v.RootFS {
		parts = append(parts, "image layer")
	}
	if v.Scope == ScopeMetadataOnly {
		parts = append(parts, "metadata only")
	}
	return strings.Join(parts, ", ")
}
