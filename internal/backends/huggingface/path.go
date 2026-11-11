package huggingface

import (
	"strings"

	"github.com/blechschmidt/pullthrough-security/internal/backends"
)

// The Hugging Face Hub exposes two request families the proxy fronts:
//
//	Blob resolve (the download path, immutable when pinned to a commit):
//	  GET /{repo}/resolve/{revision}/{path}                     model file
//	  GET /datasets/{repo}/resolve/{revision}/{path}            dataset file
//	  GET /spaces/{repo}/resolve/{revision}/{path}              space file
//
//	Repository metadata (mutable, revalidated):
//	  GET /api/models/{repo}[/revision/{rev}]                   model metadata
//	  GET /api/datasets/{repo}[/revision/{rev}]                 dataset metadata
//	  GET /api/spaces/{repo}[/revision/{rev}]                   space metadata
//
// {repo} is "owner/name" (e.g. "bigscience/bloom") or a bare canonical name
// (e.g. "gpt2"). {revision} is a branch ("main"), a tag, or a 40-hex Git commit
// SHA. A resolve pinned to a commit SHA is immutable and content-addressable, so
// the proxy caches it indefinitely; a resolve against a branch/tag is mutable and
// revalidated (never cached under a moving name). Large weight files are stored
// in Git LFS and served via a CDN redirect the upstream returns on the resolve
// endpoint; the backend follows that redirect transparently and verifies the
// delivered bytes against the SHA-256 the resolve response advertises (see lfs.go
// / huggingface.go).
//
// classify parses an inbound path (with the "/v1/<name>" route prefix already
// stripped, retaining its leading slash) into one of these resource kinds and
// derives the repository coordinate — which feeds the admission gates (nameguard,
// policy, the ML weight-scanning gate, vulnscan, license, policyengine) and the
// cacheability decision.

// resourceKind enumerates the classes of resource an HF Hub path can address.
type resourceKind int

const (
	// kindResolve is a repository blob download (model/dataset/space file).
	kindResolve resourceKind = iota
	// kindModelInfo is a model-repository metadata document (/api/models/...).
	kindModelInfo
	// kindDatasetInfo is a dataset-repository metadata document.
	kindDatasetInfo
	// kindSpaceInfo is a space-repository metadata document.
	kindSpaceInfo
)

// repoType is the Hub repository class a path addresses.
type repoType int

const (
	repoModel repoType = iota
	repoDataset
	repoSpace
)

func (t repoType) label() string {
	switch t {
	case repoDataset:
		return "dataset"
	case repoSpace:
		return "space"
	default:
		return "model"
	}
}

// resource is the parsed classification of an inbound HF Hub request path.
type resource struct {
	kind     resourceKind
	repoType repoType
	// repoID is the bare repository id "owner/name" (or a canonical "name").
	repoID string
	// revision is the branch, tag, or commit SHA a resolve (or pinned metadata)
	// request targets.
	revision string
	// filepath is the repository-relative path of a resolved blob.
	filepath string
	// infoDocument reports that an /api path is positively a repository-info
	// document: "/api/{type}/{repo}" or "/api/{type}/{repo}/revision/{rev}", with
	// nothing else after it. classifyAPI accepts the whole /api/{type}/ subtree
	// under the same three kinds, so the kind alone does not say this.
	infoDocument bool
}

// classify parses an inbound path into a resource. It returns ok=false for paths
// that cannot be expressed in the Hub layout, so an unrecognized request is
// reported as unsupported rather than blindly proxied.
func classify(path string) (resource, bool) {
	clean := strings.Trim(path, "/")
	if clean == "" {
		return resource{}, false
	}
	segs := strings.Split(clean, "/")
	for _, s := range segs {
		// Reject empty segments and any path traversal; the upstream URL is built
		// from these segments, so they must be inert. A dot inside a filename
		// ("pytorch_model.bin") is fine — only the bare "." / ".." segments are
		// rejected.
		if s == "" || s == "." || s == ".." {
			return resource{}, false
		}
	}

	if segs[0] == "api" {
		return classifyAPI(segs[1:])
	}
	return classifyResolve(segs)
}

// classifyResolve parses a "{prefix}/{repo}/resolve/{revision}/{path}" blob path.
func classifyResolve(segs []string) (resource, bool) {
	rt := repoModel
	start := 0
	switch segs[0] {
	case "datasets":
		rt, start = repoDataset, 1
	case "spaces":
		rt, start = repoSpace, 1
	}

	// Locate the "resolve" delimiter among the segments after the optional
	// repo-type prefix.
	resolveIdx := -1
	for i := start; i < len(segs); i++ {
		if segs[i] == "resolve" {
			resolveIdx = i
			break
		}
	}
	if resolveIdx < 0 {
		return resource{}, false
	}
	repoSegs := segs[start:resolveIdx]
	rest := segs[resolveIdx+1:]
	// Need a repo id, a revision, and at least one file-path segment.
	if len(repoSegs) == 0 || len(rest) < 2 {
		return resource{}, false
	}
	return resource{
		kind:     kindResolve,
		repoType: rt,
		repoID:   strings.Join(repoSegs, "/"),
		revision: rest[0],
		filepath: strings.Join(rest[1:], "/"),
	}, true
}

// apiStopWords are the sub-resource keywords that terminate the repo-id portion
// of an /api/{type}/{repo}/... metadata path.
var apiStopWords = map[string]bool{
	"revision": true, "tree": true, "refs": true, "blob": true, "blobs": true,
	"commits": true, "commit": true, "compare": true, "paths-info": true,
	"parquet": true, "croissant": true, "lfs-files": true,
}

// classifyAPI parses the segments following "/api/", e.g. "models/{repo}" or
// "datasets/{repo}/revision/{rev}".
func classifyAPI(segs []string) (resource, bool) {
	if len(segs) < 2 {
		return resource{}, false
	}
	var kind resourceKind
	var rt repoType
	switch segs[0] {
	case "models":
		kind, rt = kindModelInfo, repoModel
	case "datasets":
		kind, rt = kindDatasetInfo, repoDataset
	case "spaces":
		kind, rt = kindSpaceInfo, repoSpace
	default:
		return resource{}, false
	}

	rest := segs[1:]
	var repoSegs []string
	var revision string
	for i := 0; i < len(rest); i++ {
		if apiStopWords[rest[i]] {
			if rest[i] == "revision" && i+1 < len(rest) {
				revision = rest[i+1]
			}
			break
		}
		repoSegs = append(repoSegs, rest[i])
	}
	if len(repoSegs) == 0 {
		return resource{}, false
	}
	// The repository-info document itself is a repo id of one or two segments
	// ("gpt2", "owner/name"), either alone or followed by exactly
	// "revision/{rev}". Every other path this function accepts is some other
	// sub-resource of the /api/{type}/ subtree.
	bare := len(rest) == len(repoSegs)
	pinned := revision != "" && len(rest) == len(repoSegs)+2
	return resource{
		kind:         kind,
		repoType:     rt,
		repoID:       strings.Join(repoSegs, "/"),
		revision:     revision,
		infoDocument: len(repoSegs) <= 2 && (bare || pinned),
	}, true
}

// coordinateName returns the package name used to address the repository in the
// admission gates. Datasets and spaces are namespaced by their repo type so a
// model "owner/name" and a dataset "owner/name" are distinct coordinates.
func (r resource) coordinateName() string {
	switch r.repoType {
	case repoDataset:
		return "datasets/" + r.repoID
	case repoSpace:
		return "spaces/" + r.repoID
	default:
		return r.repoID
	}
}

// cacheable reports whether the resource may be cached. A blob resolve pinned to
// an immutable commit SHA is content-addressable and cached; metadata documents
// are revalidated live. A weight file (pickle/safetensors/...) is ALSO cached
// even on a mutable branch/tag — not for immutability but so the content-safety
// pipeline (SHA-256 verification + the ML pickle-scanning gate) runs on every
// weight pull, which only happens on the cacheable serve path. The cache key
// embeds the revision, so a branch and a commit are distinct entries; operators
// who need freshness should pin a commit SHA (see docs/clients.md).
func (r resource) cacheable() bool {
	if r.kind != kindResolve {
		return false
	}
	return isCommitRevision(r.revision) || weightFormat(r.baseFilename()) != formatOther
}

// isResolve reports whether the resource is a blob download.
func (r resource) isResolve() bool { return r.kind == kindResolve }

// artifact classifies the resource for the content gates (see
// backends.ArtifactClass).
//
// A resolved repository file is a payload when its name says a client will load
// or run it: a model-weight file (weightFormat), or a file with a code-bearing
// or archive extension (codeBearing). Any other resolved file — a JSON config,
// a README, an image, a Parquet shard — is left unclassified rather than called
// metadata: a repository holds whatever its owner committed, under any name, so
// a gate still judges such a file from its bytes.
//
// A repository-info document is metadata, but only where the path is positively
// one (resource.infoDocument). classifyAPI gives the same three kinds to every
// path beneath /api/{models,datasets,spaces}/, and that subtree is not documents
// alone: "/api/datasets/{repo}/parquet/{config}/{split}/{n}.parquet" serves a
// data file. The other sub-resources are left unclassified.
func (r resource) artifact() backends.Artifact {
	switch r.kind {
	case kindResolve:
		if name := r.baseFilename(); weightFormat(name) != formatOther || codeBearing(name) {
			// A repository serves its files one by one: a weight file, a script.
			return backends.PayloadFile()
		}
	case kindModelInfo, kindDatasetInfo, kindSpaceInfo:
		if r.infoDocument {
			return backends.Metadata()
		}
	}
	return backends.Artifact{}
}

// kindLabel returns a stable diagnostic label for a resource kind.
func (r resource) kindLabel() string {
	switch r.kind {
	case kindResolve:
		return "resolve-" + r.repoType.label()
	case kindModelInfo:
		return "model-info"
	case kindDatasetInfo:
		return "dataset-info"
	case kindSpaceInfo:
		return "space-info"
	default:
		return "other"
	}
}

// baseFilename returns the final path component of the resolved blob path.
func (r resource) baseFilename() string {
	if i := strings.LastIndex(r.filepath, "/"); i >= 0 {
		return r.filepath[i+1:]
	}
	return r.filepath
}

// isCommitRevision reports whether rev is a full 40-hex Git commit SHA, the only
// revision form the Hub guarantees to be immutable (branches and tags move).
func isCommitRevision(rev string) bool {
	if len(rev) != 40 {
		return false
	}
	for i := 0; i < len(rev); i++ {
		c := rev[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') && (c < 'A' || c > 'F') {
			return false
		}
	}
	return true
}

// Weight-file format classification. The ML safety gate (internal/mlguard) owns
// the authoritative, content-aware classification; the backend derives the same
// label from the filename extension so it can be surfaced as cache metadata and
// drive the served-format metrics.
const (
	formatSafetensors = "safetensors"
	formatPickle      = "pickle"
	formatGGUF        = "gguf"
	formatOtherWeight = "weights"
	formatOther       = ""
)

// weightFormat labels a resolved blob by its filename extension.
func weightFormat(name string) string {
	lower := strings.ToLower(name)
	switch {
	case strings.HasSuffix(lower, ".safetensors"):
		return formatSafetensors
	case strings.HasSuffix(lower, ".bin"),
		strings.HasSuffix(lower, ".pkl"),
		strings.HasSuffix(lower, ".pickle"),
		strings.HasSuffix(lower, ".pt"),
		strings.HasSuffix(lower, ".pth"),
		strings.HasSuffix(lower, ".ckpt"),
		strings.HasSuffix(lower, ".model") && strings.Contains(lower, "pytorch"):
		return formatPickle
	case strings.HasSuffix(lower, ".gguf"), strings.HasSuffix(lower, ".ggml"):
		return formatGGUF
	case strings.HasSuffix(lower, ".h5"),
		strings.HasSuffix(lower, ".hdf5"),
		strings.HasSuffix(lower, ".onnx"),
		strings.HasSuffix(lower, ".npz"),
		strings.HasSuffix(lower, ".npy"),
		strings.HasSuffix(lower, ".msgpack"):
		return formatOtherWeight
	default:
		return formatOther
	}
}

// codeBearingExts are the file-name extensions of repository files that are
// code, or may hold it: scripts and modules a loader imports or a user runs
// (custom model code, a dataset loading script, a Space's app, a notebook),
// native and bytecode libraries, serialized-model formats that are not weight
// files to weightFormat but can execute code when loaded, and archives of any of
// these.
var codeBearingExts = []string{
	// Scripts, modules and notebooks.
	".py", ".pyc", ".pyw", ".ipynb",
	".sh", ".bash", ".ps1", ".bat", ".cmd",
	".js", ".mjs", ".cjs", ".ts",
	".rb", ".pl", ".lua",
	// Compiled code.
	".jar", ".so", ".dll", ".dylib", ".exe", ".wasm",
	// Serialized models and graphs.
	".joblib", ".dill", ".keras", ".pb", ".tflite", ".mlmodel",
	// Archives.
	".zip", ".tar", ".tar.gz", ".tgz", ".tar.bz2", ".tar.xz", ".gz", ".7z", ".whl",
}

// codeBearing reports whether a resolved file's name, compared without regard
// to letter case, ends in one of the codeBearingExts.
//
// It decides only which files are ALWAYS examined, whatever their bytes look
// like. It is not a list of what is safe to skip: a file it does not name is
// left unclassified, not called metadata, so the content gates still sniff its
// bytes and examine it when they turn out to be an archive, an executable or a
// script. A name outside the set therefore costs nothing but the certainty.
func codeBearing(name string) bool {
	lower := strings.ToLower(name)
	for _, ext := range codeBearingExts {
		if strings.HasSuffix(lower, ext) {
			return true
		}
	}
	return false
}
