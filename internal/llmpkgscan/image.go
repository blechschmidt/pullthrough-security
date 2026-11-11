package llmpkgscan

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"
	"sort"
	"strings"

	"github.com/blechschmidt/pullthrough-security/internal/contentscan"
)

// OCI / Docker images.
//
// An image is not one artifact but a manifest naming a config blob and a list
// of layer blobs, each fetched by digest. What a container runs is spread over
// all of them: the config says what is executed (entrypoint, command,
// environment, user) and records how the image was built (its history), and the
// layers hold the files. Judging any one blob alone misses the point — an
// entrypoint is only alarming next to the script it names — so the gate
// examines the image as a whole, when its manifest is pulled: the config and
// history, rendered readably, plus the file inventory and the readable content
// of every layer, top-most first.
//
// The verdict is stored under the manifest's digest. The manifest
// content-addresses everything else, so that digest identifies exactly the
// image that was examined.

// ImageSource gives an image scan access to the blobs its manifest references.
type ImageSource struct {
	// Blob opens the blob with the given digest ("sha256:<hex>") from the
	// repository the manifest was pulled from. size is the size the manifest
	// declares. It is called with the scan's own context.
	Blob func(ctx context.Context, digest string, size int64) (io.ReadCloser, error)
}

// ImageFacts is what the proxy established about an image, stated to the model
// outside the untrusted material.
type ImageFacts struct {
	// Platform is "os/architecture[/variant]" from the image config.
	Platform string
	// Config is the digest of the config blob.
	Config string
	// Layers describes every layer of the manifest, in manifest order (base
	// first).
	Layers []LayerFact
}

// LayerFact is one layer of an image and how much of it the scan saw.
type LayerFact struct {
	// Index is the layer's 1-based position in the manifest; Dir the directory
	// its files appear under in the tree.
	Index int
	Dir   string
	// Digest and Size are the manifest's.
	Digest string
	Size   int64
	// Files is the number of files listed from it; Coverage says how much of it
	// was examined: "examined", "partially examined: …" or "NOT examined: …".
	Files    int
	Coverage string
	// Covered reports that this scan read as much of the layer as a scan of the
	// layer on its own would: every member was listed, or the only thing that
	// cut it short is the size limit that would stop a scan of its own at the
	// same byte. Only such a layer is covered by the image's verdict; any other —
	// one the image's shared budgets did not reach or ran out in — is examined on
	// its own when it is pulled.
	Covered bool
}

// Bounds on the documents of an image.
const (
	// maxManifestBytes bounds an image manifest. Registries cap them at 4 MiB.
	maxManifestBytes = 4 << 20
	// maxImageConfigBytes bounds an image config blob.
	maxImageConfigBytes = 8 << 20
	// maxImageLayers bounds the layers of one image; Docker itself stops at 127.
	maxImageLayers = 512
)

// Errors specific to an image.
var (
	// errImageIndex: the manifest is an index (a multi-platform manifest list).
	// It names other manifests and holds nothing to install; the manifest a
	// client selects from it is examined when that one is pulled.
	errImageIndex = errors.New("llmpkgscan: manifest is an image index")
	// errBlobUnavailable: a blob the manifest references could not be fetched.
	errBlobUnavailable = errors.New("llmpkgscan: image blob unavailable")
	// errBlobMismatch: a blob's bytes do not hash to the digest the manifest
	// names for it.
	errBlobMismatch = errors.New("llmpkgscan: image blob does not match its digest")
)

type ociDescriptor struct {
	MediaType string   `json:"mediaType"`
	Digest    string   `json:"digest"`
	Size      int64    `json:"size"`
	URLs      []string `json:"urls"`
}

type ociManifest struct {
	SchemaVersion int             `json:"schemaVersion"`
	MediaType     string          `json:"mediaType"`
	ArtifactType  string          `json:"artifactType"`
	Config        *ociDescriptor  `json:"config"`
	Layers        []ociDescriptor `json:"layers"`
	Manifests     []ociDescriptor `json:"manifests"`
	FSLayers      json.RawMessage `json:"fsLayers"`
}

// ociImageConfig is the part of an image config the scan renders.
type ociImageConfig struct {
	Architecture string `json:"architecture"`
	OS           string `json:"os"`
	Variant      string `json:"variant"`
	Created      string `json:"created"`
	Author       string `json:"author"`
	Config       struct {
		User         string              `json:"User"`
		Env          []string            `json:"Env"`
		Entrypoint   []string            `json:"Entrypoint"`
		Cmd          []string            `json:"Cmd"`
		WorkingDir   string              `json:"WorkingDir"`
		Shell        []string            `json:"Shell"`
		OnBuild      []string            `json:"OnBuild"`
		StopSignal   string              `json:"StopSignal"`
		Labels       map[string]string   `json:"Labels"`
		Volumes      map[string]struct{} `json:"Volumes"`
		ExposedPorts map[string]struct{} `json:"ExposedPorts"`
		Healthcheck  *struct {
			Test []string `json:"Test"`
		} `json:"Healthcheck"`
	} `json:"config"`
	History []struct {
		Created    string `json:"created"`
		CreatedBy  string `json:"created_by"`
		Comment    string `json:"comment"`
		EmptyLayer bool   `json:"empty_layer"`
	} `json:"history"`
	RootFS struct {
		Type    string   `json:"type"`
		DiffIDs []string `json:"diff_ids"`
	} `json:"rootfs"`
}

// isImage reports whether a config looks like a container image config (as
// opposed to the config of another kind of OCI artifact: a Helm chart's
// metadata, the empty descriptor of a signature).
func (c *ociImageConfig) isImage() bool {
	return len(c.RootFS.DiffIDs) > 0 || len(c.History) > 0 || len(c.Config.Entrypoint) > 0 || len(c.Config.Cmd) > 0
}

// ParseImageManifest reports whether data is an image manifest this gate
// examines, and which blobs it references: the config first, then the layers
// in manifest order. index is true for a manifest list / image index, which
// names other manifests and is not itself examined.
func ParseImageManifest(data []byte) (blobs []string, index bool, err error) {
	m, err := parseManifest(data)
	if errors.Is(err, errImageIndex) {
		return nil, true, nil
	}
	if err != nil {
		return nil, false, err
	}
	if m.Config != nil {
		blobs = append(blobs, m.Config.Digest)
	}
	for _, l := range m.Layers {
		blobs = append(blobs, l.Digest)
	}
	return blobs, false, nil
}

func parseManifest(data []byte) (*ociManifest, error) {
	var m ociManifest
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, fmt.Errorf("%w: the manifest is not valid JSON", errUnsupported)
	}
	if len(m.Manifests) > 0 {
		return nil, errImageIndex
	}
	if len(m.FSLayers) > 0 && m.Config == nil {
		return nil, fmt.Errorf("%w: Docker schema 1 manifests are not supported", errUnsupported)
	}
	if m.Config == nil && len(m.Layers) == 0 {
		return nil, fmt.Errorf("%w: the manifest names no config and no layers", errUnsupported)
	}
	if len(m.Layers) > maxImageLayers {
		return nil, fmt.Errorf("%w: the manifest names %d layers", errUnsupported, len(m.Layers))
	}
	check := func(d ociDescriptor) error {
		if _, ok := NormalizeDigest(d.Digest); !ok {
			return fmt.Errorf("%w: the manifest references a blob by something other than a sha256 digest", errUnsupported)
		}
		if d.Size < 0 {
			return fmt.Errorf("%w: the manifest declares a negative blob size", errUnsupported)
		}
		return nil
	}
	if m.Config != nil {
		if err := check(*m.Config); err != nil {
			return nil, err
		}
	}
	for _, l := range m.Layers {
		if err := check(l); err != nil {
			return nil, err
		}
	}
	return &m, nil
}

// imageBuild is the result of assembling an image.
type imageBuild struct {
	tree *Tree
	// blobs are the digests of every blob of the image (config and layers);
	// layerDirs maps a layer's tree directory to its digest.
	blobs     []string
	layerDirs map[string]string
	// imageConfig is the digest of the config blob when that blob reads as an
	// image config, and empty otherwise. A manifest may name any blob as its
	// config; only one that is a config is treated as one (see blobs.go).
	imageConfig string
	// unexamined are the digests of the layers that were not examined in full.
	unexamined []string
}

// buildImageTree assembles the tree of an image from its manifest: composed
// entries for the config, what the image runs and how it was built, and the
// files of each layer under layers/NN-<digest>/.
//
// Layers are walked top-most first. The member and byte budgets are shared by
// the whole image, and when they run out it is the oldest layers — as a rule
// the base image, which thousands of images share — that go unexamined, not the
// ones this image added. Every layer that was not examined in full is named.
//
// A layer larger than the per-artifact limit follows the oversize mode: under
// "fail" the image as a whole is oversized; under "metadata-only" the layer's
// first MaxArtifactBytes are read and the view is marked partial.
func buildImageTree(ctx context.Context, manifest []byte, src ImageSource, lim Limits, oversize Oversize) (*imageBuild, error) {
	m, err := parseManifest(manifest)
	if err != nil {
		return nil, err
	}
	if src.Blob == nil {
		return nil, fmt.Errorf("%w: no blob source", errBlobUnavailable)
	}

	b := newTreeBuilder(lim)
	t := b.t
	t.Kind, t.Format = KindImage, KindImage
	sum := sha256.Sum256(manifest)
	t.Digest = hex.EncodeToString(sum[:])
	t.ArtifactBytes = int64(len(manifest))
	facts := &ImageFacts{}
	t.Image = facts
	out := &imageBuild{tree: t, layerDirs: make(map[string]string)}

	synth := func(name string, data []byte) {
		truncated := false
		if lim.MaxFileBytes > 0 && int64(len(data)) > lim.MaxFileBytes {
			data, truncated = data[:lim.MaxFileBytes], true
		}
		b.visit(contentscan.ArchiveEntry{Name: name, Data: data, Size: int64(len(data)), Truncated: truncated, Synthetic: true})
	}
	synth("image/manifest.json", indentJSON(manifest))

	// --- config -----------------------------------------------------------------
	var cfg ociImageConfig
	installable := false
	if m.Config != nil {
		out.blobs = append(out.blobs, m.Config.Digest)
		facts.Config = m.Config.Digest
		if m.Config.Size > maxImageConfigBytes {
			return nil, fmt.Errorf("%w: the image config is %d bytes", errUnsupported, m.Config.Size)
		}
		raw, err := readBlob(ctx, src, *m.Config, maxImageConfigBytes)
		if err != nil {
			return nil, err
		}
		t.ArtifactBytes += int64(len(raw))
		if len(bytes.TrimSpace(raw)) > 0 {
			synth("image/config.json", indentJSON(raw))
			if !json.Valid(raw) {
				// A manifest may name any blob as its config. One that is not a JSON
				// document was shown here as the opaque bytes it is, not unpacked: if
				// it is in fact an archive or an executable, this scan has not
				// examined it, and its verdict must not vouch for it when it is pulled.
				out.unexamined = append(out.unexamined, m.Config.Digest)
				t.anomaly("the blob the manifest names as its config is not a JSON document")
				t.note("The blob the manifest names as its config is not a JSON document. It is listed as image/config.json as the bytes it is and was NOT unpacked or examined as an archive.")
			}
		}
		if json.Unmarshal(raw, &cfg) == nil && cfg.isImage() {
			installable = true
			out.imageConfig = m.Config.Digest
			facts.Platform = platformOf(&cfg)
			synth("image/run.txt", renderImageRun(&cfg))
			if len(cfg.History) > 0 {
				synth("image/history.txt", renderImageHistory(&cfg))
			}
		}
	}

	// --- layers, top-most first -------------------------------------------------
	facts.Layers = make([]LayerFact, len(m.Layers))
	for i, l := range m.Layers {
		hexDigest, _ := NormalizeDigest(l.Digest)
		dir := fmt.Sprintf("layers/%03d-%s", i+1, hexDigest[:12])
		facts.Layers[i] = LayerFact{Index: i + 1, Dir: dir, Digest: l.Digest, Size: l.Size, Coverage: "NOT examined: the scan's budget was spent on the layers above it"}
		out.blobs = append(out.blobs, l.Digest)
		out.layerDirs[dir] = l.Digest
		t.ArtifactBytes += l.Size
	}
	budgetLeft := true
	incomplete := false
	for i := len(m.Layers) - 1; i >= 0; i-- {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		l, fact := m.Layers[i], &facts.Layers[i]
		if !budgetLeft {
			incomplete = true
			continue
		}
		if len(l.URLs) > 0 || strings.Contains(l.MediaType, "foreign") || strings.Contains(l.MediaType, "nondistributable") {
			// A foreign layer is fetched by the client from somewhere else; the
			// registry does not hold it.
			fact.Coverage = "NOT examined: a foreign (non-distributable) layer the registry does not serve"
			incomplete = true
			continue
		}
		partial := false
		if l.Size > lim.MaxArtifactBytes {
			if oversize != OversizeMetadataOnly {
				return nil, errOversized
			}
			partial = true
		}
		rc, err := src.Blob(ctx, l.Digest, l.Size)
		if err != nil {
			return nil, fmt.Errorf("%w: layer %d (%s): %v", errBlobUnavailable, i+1, l.Digest, err)
		}
		stats, walked, lerr := b.walkLayer(ctx, rc, fact.Dir+"/", l, partial)
		_ = rc.Close()
		if lerr != nil {
			return nil, lerr
		}
		fact.Files = stats.Files
		t.UnpackedBytes += stats.UnpackedBytes
		if walked {
			installable = true
		}
		switch {
		case partial:
			fact.Coverage = fmt.Sprintf("partially examined: the layer is larger than the %d-byte limit, so only its first %d bytes were read", lim.MaxArtifactBytes, lim.MaxArtifactBytes)
			incomplete = true
			fact.Covered = cutBySizeAlone(stats)
		case !stats.Complete() && inventoryCut(stats):
			fact.Coverage = "partially examined: " + strings.Join(stats.Incomplete, ", ")
			incomplete = true
		default:
			fact.Coverage, fact.Covered = "examined", true
		}
		b.noteIncomplete(stats, fmt.Sprintf("Layer %d: ", i+1), partial)
		budgetLeft = b.spend(stats)
	}

	// What was not seen, in the model's own terms — and, by digest, for the blob
	// index: a layer this scan read less of than a scan of its own would is not
	// covered by its verdict (LayerFact.Covered).
	var unexamined []string
	seenUnexamined := map[string]bool{}
	for _, f := range facts.Layers {
		if f.Coverage != "examined" {
			unexamined = append(unexamined, fmt.Sprintf("layer %d (%s): %s", f.Index, f.Dir, f.Coverage))
		}
		if !f.Covered && !seenUnexamined[f.Digest] {
			seenUnexamined[f.Digest] = true
			out.unexamined = append(out.unexamined, f.Digest)
		}
	}
	if len(unexamined) > 0 {
		t.note("Not every layer of the image was examined in full: %s. Files in a layer that was not examined are invisible to this review.", strings.Join(unexamined, "; "))
	}
	if !installable {
		// Neither an image config nor a layer holding anything to unpack or run:
		// a signature, an attestation, an SBOM stored as an OCI artifact.
		return nil, errNotArchive
	}
	if oversize == OversizeMetadataOnly {
		for _, f := range facts.Layers {
			if strings.HasPrefix(f.Coverage, "partially examined: the layer is larger") {
				t.Partial = true
			}
		}
	}

	if _, err := b.finish(incomplete); err != nil {
		return nil, err
	}
	rankImage(t, &cfg)
	return out, nil
}

// cutBySizeAlone reports whether the only thing that kept a walk of a layer
// above the size limit from being complete is that limit: it ran into the end
// of what may be read (which also breaks the member it was in), and nothing
// else — not the member or byte budgets the image's layers share, and not a
// part it could not open.
func cutBySizeAlone(stats contentscan.ArchiveStats) bool {
	for _, r := range stats.Incomplete {
		switch r {
		case contentscan.IncompleteArchiveBytes, contentscan.IncompleteMalformed, contentscan.IncompleteFileBytes:
		default:
			return false
		}
	}
	return true
}

// inventoryCut reports whether a walk missed members, as opposed to having
// merely cut a large file short.
func inventoryCut(stats contentscan.ArchiveStats) bool {
	for _, r := range stats.Incomplete {
		if r != contentscan.IncompleteFileBytes {
			return true
		}
	}
	return false
}

// walkLayer files one layer's members under prefix. walked reports that the
// layer held something to unpack or run. In a full walk the layer is read to
// its end and its digest checked: the manifest names the bytes a client will
// receive, and a verdict must be about those.
//
// A layer of an OCI artifact need not be a filesystem archive — a WebAssembly
// module, the JSON payload of a signature — and such a layer is one file.
func (b *treeBuilder) walkLayer(ctx context.Context, r io.Reader, prefix string, l ociDescriptor, partial bool) (stats contentscan.ArchiveStats, walked bool, err error) {
	hasher := sha256.New()
	src := &countReader{r: io.TeeReader(r, hasher)}
	br := bufio.NewReaderSize(src, ProbeBytes)
	head, _ := br.Peek(headBytes)
	if NeedsLongProbe(head) {
		head, _ = br.Peek(ProbeBytes)
	}
	if cerr := ctx.Err(); cerr != nil {
		return stats, false, cerr
	}
	peeled, _, peeledOK := contentscan.PeelCompression(head)
	walked = !peeledOK || contentscan.Recognizes(peeled) || executableMagic(peeled) || unsupportedArchiveMagic(head)

	b.prefix = prefix
	defer func() { b.prefix = "" }()
	stats, werr := contentscan.WalkArtifact(ctx, br, b.archiveLimits(b.lim.MaxArtifactBytes),
		contentscan.ArchiveOptions{Filename: "blob", SingleFile: true}, b.visit, b.onLink)
	if cerr := ctx.Err(); cerr != nil {
		return stats, walked, cerr
	}
	b.judgeLinks(true) // a layer is a root filesystem
	// A container runtime reads a layer from its first byte, as a tar. Whether
	// the blob would also open as a zip from its end is of no consequence to
	// anything that runs the image, so that it could not be re-read as one is
	// not held against it. (A zip reading that was examined stays in the tree.)
	stats.Incomplete = slices.DeleteFunc(stats.Incomplete, func(r string) bool { return r == contentscan.IncompleteSecondReading })
	if werr != nil {
		// A layer that starts like an archive and cannot be unpacked stays in the
		// inventory as the opaque blob it is, and the view is incomplete.
		stats.Incomplete = append(stats.Incomplete, contentscan.IncompleteNestedFormat)
		b.visit(contentscan.ArchiveEntry{Name: "blob", Data: append([]byte(nil), head[:min(len(head), headBytes)]...), Size: l.Size, Truncated: true})
		stats.Files++
	}
	if partial {
		return stats, walked, nil
	}
	if _, cerr := io.Copy(io.Discard, io.LimitReader(br, b.lim.MaxArtifactBytes+1-src.n)); cerr != nil {
		return stats, walked, fmt.Errorf("%w: reading layer %s: %v", errBlobUnavailable, l.Digest, cerr)
	}
	want, _ := NormalizeDigest(l.Digest)
	if src.n > b.lim.MaxArtifactBytes || hex.EncodeToString(hasher.Sum(nil)) != want {
		return stats, walked, fmt.Errorf("%w: layer %s", errBlobMismatch, l.Digest)
	}
	return stats, walked, nil
}

// readBlob reads a small blob whole and checks it against its digest.
func readBlob(ctx context.Context, src ImageSource, d ociDescriptor, limit int64) ([]byte, error) {
	rc, err := src.Blob(ctx, d.Digest, d.Size)
	if err != nil {
		return nil, fmt.Errorf("%w: %s: %v", errBlobUnavailable, d.Digest, err)
	}
	defer rc.Close()
	data, err := io.ReadAll(io.LimitReader(rc, limit+1))
	if err != nil {
		return nil, fmt.Errorf("%w: reading %s: %v", errBlobUnavailable, d.Digest, err)
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("%w: blob %s is larger than %d bytes", errUnsupported, d.Digest, limit)
	}
	want, _ := NormalizeDigest(d.Digest)
	if got := sha256.Sum256(data); hex.EncodeToString(got[:]) != want {
		return nil, fmt.Errorf("%w: %s", errBlobMismatch, d.Digest)
	}
	return data, nil
}

// indentJSON pretty-prints a JSON document so it is read line by line; a
// document that does not parse is returned as it is.
func indentJSON(data []byte) []byte {
	var out bytes.Buffer
	if json.Indent(&out, bytes.TrimSpace(data), "", "  ") != nil {
		return data
	}
	out.WriteByte('\n')
	return out.Bytes()
}

func platformOf(c *ociImageConfig) string {
	p := strings.TrimSpace(c.OS) + "/" + strings.TrimSpace(c.Architecture)
	if v := strings.TrimSpace(c.Variant); v != "" {
		p += "/" + v
	}
	return cleanText(p, 64)
}

// renderImageRun lays out what a container started from the image executes,
// and with what: the part of the config a reviewer reads first.
func renderImageRun(c *ociImageConfig) []byte {
	var b strings.Builder
	argv := func(label string, v []string) {
		if len(v) == 0 {
			return
		}
		j, _ := json.Marshal(v)
		fmt.Fprintf(&b, "%s %s\n", label, j)
	}
	user := c.Config.User
	if strings.TrimSpace(user) == "" {
		user = "(not set: the container runs as root)"
	}
	fmt.Fprintf(&b, "USER %s\n", oneLineText(user))
	argv("ENTRYPOINT", c.Config.Entrypoint)
	argv("CMD", c.Config.Cmd)
	if len(c.Config.Entrypoint) == 0 && len(c.Config.Cmd) == 0 {
		b.WriteString("ENTRYPOINT and CMD are not set: the image runs nothing by default\n")
	}
	if c.Config.WorkingDir != "" {
		fmt.Fprintf(&b, "WORKDIR %s\n", oneLineText(c.Config.WorkingDir))
	}
	argv("SHELL", c.Config.Shell)
	if c.Config.Healthcheck != nil {
		argv("HEALTHCHECK", c.Config.Healthcheck.Test)
	}
	for _, trigger := range c.Config.OnBuild {
		fmt.Fprintf(&b, "ONBUILD %s\n", oneLineText(trigger))
	}
	if c.Config.StopSignal != "" {
		fmt.Fprintf(&b, "STOPSIGNAL %s\n", oneLineText(c.Config.StopSignal))
	}
	for _, e := range c.Config.Env {
		fmt.Fprintf(&b, "ENV %s\n", oneLineText(e))
	}
	for _, p := range sortedKeys(c.Config.ExposedPorts) {
		fmt.Fprintf(&b, "EXPOSE %s\n", oneLineText(p))
	}
	for _, v := range sortedKeys(c.Config.Volumes) {
		fmt.Fprintf(&b, "VOLUME %s\n", oneLineText(v))
	}
	labels := make([]string, 0, len(c.Config.Labels))
	for k := range c.Config.Labels {
		labels = append(labels, k)
	}
	sort.Strings(labels)
	for _, k := range labels {
		fmt.Fprintf(&b, "LABEL %s=%s\n", oneLineText(k), oneLineText(c.Config.Labels[k]))
	}
	return []byte(b.String())
}

// renderImageHistory lays out the build steps the image config records, oldest
// first, numbering the ones that produced a layer the way the layer directories
// are numbered. The history is written by whoever built the image and need not
// be true; it is what the image claims about itself.
func renderImageHistory(c *ociImageConfig) []byte {
	var b strings.Builder
	layer := 0
	for _, h := range c.History {
		tag := "[no layer]"
		if !h.EmptyLayer {
			layer++
			tag = fmt.Sprintf("[layer %03d]", layer)
		}
		step := oneLineText(h.CreatedBy)
		if step == "" {
			step = "(no command recorded)"
		}
		fmt.Fprintf(&b, "%s %s", tag, step)
		if c := oneLineText(h.Comment); c != "" {
			fmt.Fprintf(&b, "   # %s", c)
		}
		b.WriteByte('\n')
	}
	return []byte(b.String())
}

// oneLineText folds config text onto one line. It does not otherwise alter it:
// the model must see the command as the image records it.
func oneLineText(s string) string {
	if !strings.ContainsAny(s, "\r\n") {
		return s
	}
	return strings.Join(strings.Fields(s), " ")
}

func sortedKeys(m map[string]struct{}) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// layerRelative splits a tree path under layers/NN-<digest>/ into the layer
// directory and the path inside the layer. ok is false for any other path.
func layerRelative(p string) (dir, rel string, ok bool) {
	rest, found := strings.CutPrefix(p, "layers/")
	if !found {
		return "", "", false
	}
	name, rel, found := strings.Cut(rest, "/")
	if !found || name == "" {
		return "", "", false
	}
	return "layers/" + name, rel, true
}

// rankImage raises what an image runs: the composed description of its config,
// and — in the top-most layer that has it — every file the entrypoint, the
// command or the healthcheck names.
func rankImage(t *Tree, cfg *ociImageConfig) {
	roles := map[string]nameRule{
		"image/run.txt":       {scoreAutoExec + 20, "what the image runs when a container starts (composed from the image config)"},
		"image/history.txt":   {scoreAutoExec + 10, "the build steps the image config records (the image's own claim about how it was built)"},
		"image/config.json":   {scoreManifest, "the image config"},
		"image/manifest.json": {scoreConfig, "the image manifest"},
	}
	for _, f := range t.Files {
		if r, ok := roles[f.Path]; ok {
			f.Score, f.Role = r.score, r.role
		}
	}
	// Paths the config executes. Only absolute paths and bare program names can
	// be resolved without a shell; "sh -c ..." strings are covered by the model
	// reading run.txt.
	wanted := map[string]string{}
	add := func(argv []string, why string) {
		for i, a := range argv {
			if i > 3 {
				break
			}
			a = strings.TrimSpace(a)
			if a == "" || strings.ContainsAny(a, " \t\n;|&$`") {
				continue
			}
			wanted[strings.TrimPrefix(a, "/")] = why
		}
	}
	add(cfg.Config.Entrypoint, "named by the image ENTRYPOINT: runs when a container starts")
	add(cfg.Config.Cmd, "named by the image CMD: runs when a container starts")
	if cfg.Config.Healthcheck != nil {
		add(cfg.Config.Healthcheck.Test, "named by the image HEALTHCHECK: run periodically inside the container")
	}
	if len(wanted) == 0 {
		return
	}
	// The top-most layer wins: it is the file the container actually sees.
	best := map[string]*File{}
	for _, f := range t.Files {
		dir, rel, ok := layerRelative(f.Path)
		if !ok {
			continue
		}
		key := rel
		if _, hit := wanted[key]; !hit {
			// A bare program name ("nginx") matches the usual binary directories.
			found := false
			for _, bin := range []string{"usr/local/bin/", "usr/local/sbin/", "usr/bin/", "usr/sbin/", "bin/", "sbin/"} {
				if name, isBin := strings.CutPrefix(rel, bin); isBin && !strings.Contains(name, "/") {
					if _, hit := wanted[name]; hit {
						key, found = name, true
						break
					}
				}
			}
			if !found {
				continue
			}
		}
		if cur, ok := best[key]; !ok || dir > layerDirOf(cur.Path) {
			best[key] = f
		}
	}
	for key, f := range best {
		if f.Score < scoreAutoExec {
			f.Score = scoreAutoExec
		}
		f.Role = wanted[key]
	}
}

func layerDirOf(p string) string {
	dir, _, _ := layerRelative(p)
	return dir
}
