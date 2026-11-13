// Package update is the pure half of the repository maintenance updater (Task
// 182): what a newer version of a dependency must look like in a lock file,
// and how each lock-file format is brought there.
//
// The repository registry (internal/repos) selects the updates: for each
// dependency the default branch's lock files pin it lists the newer versions
// the registry offers through the proxy, keeps those the manifest's declared
// constraint allows, and vets each candidate — every admission gate, and a
// benign verdict of the LLM package-content scan for the exact bytes. This
// package then writes the chosen versions into the lock files:
//
//   - Natively, for formats whose entries are independent of each other once
//     the new version declares the same dependencies as the old one: the
//     version, the resolved URL and the integrity values are replaced in
//     place, from the digests of the bytes the proxy fetched, verified and
//     cached (Change.Artifacts). Nothing else of the file changes.
//   - Through the real package manager, in a network-less sandbox whose only
//     registry is the proxy, when the update needs the dependency graph
//     resolved again (internal/repos/sandbox).
//   - Not at all, with the reason, for formats neither can update safely.
//
// Every rewritten lock file is parsed again (internal/lockfiles) and held to
// what was intended: exactly the changed dependencies moved, to the intended
// versions and digests, and nothing else (Verify).
package update

// Method says how a lock-file format is updated.
type Method string

const (
	// Native: the proxy rewrites the lock file (and its manifest, where the
	// manifest holds the version, as go.mod does) itself.
	Native Method = "native"
	// Sandbox: the ecosystem's real package manager re-resolves the lock
	// file in a network-less sandbox whose only registry is the proxy.
	Sandbox Method = "sandbox"
	// Unsupported: the format is not updated; FormatSupport.Reason says why.
	Unsupported Method = "unsupported"
)

// FormatSupport says how one lock-file format — "<type>/<format>", as
// internal/lockfiles names its parsers — is updated.
type FormatSupport struct {
	Type   string `json:"type"`
	Format string `json:"format"`
	// Method is how an update that needs no re-resolution is written.
	Method Method `json:"method"`
	// Fallback is what an update that needs the graph resolved again (the
	// new version declares other dependencies) gets: Sandbox or Unsupported.
	Fallback Method `json:"fallback"`
	// Tool is the package manager the sandbox runs ("npm", "cargo", "go",
	// "uv"), when Method or Fallback is Sandbox.
	Tool string `json:"tool,omitempty"`
	// Manifests are the files read for the declared constraints, or
	// rewritten with the lock file ("package.json", "Cargo.toml", "go.mod").
	Manifests []string `json:"manifests,omitempty"`
	// Reason explains the method: when the native rewrite applies, or why the
	// format is not updated.
	Reason string `json:"reason"`
}

// Change is one dependency update to write into a lock file.
type Change struct {
	// Type is the canonical upstream type ("npm", "pip", "cargo", "go").
	Type string `json:"type"`
	// Name is the package's name as internal/lockfiles names it.
	Name string `json:"name"`
	// From is the version the lock file pins now; To the version to pin.
	From string `json:"from"`
	To   string `json:"to"`
	// Artifacts are the new version's objects as the proxy fetched, verified
	// and cached them. Their digests are what the lock file records: they are
	// computed over the cached bytes, never copied from registry metadata.
	Artifacts []Artifact `json:"artifacts"`
}

// Artifact is one object of a new version, with the digests of its bytes.
type Artifact struct {
	// Role is what the object is to the dependency (locate.Artifact.Role):
	// "package" (the artifact itself: an npm tarball, a .crate, a Go module
	// zip), "file" (one distribution file of a Python release), "go.mod",
	// "info".
	Role string `json:"role"`
	// File is the distribution file's name, when the protocol has one (a
	// wheel's or an sdist's file name).
	File string `json:"file,omitempty"`
	// Size is the object's length in bytes.
	Size int64 `json:"size"`
	// SHA256, SHA512 and SHA1 are lower-case hex digests of the bytes.
	SHA256 string `json:"sha256"`
	SHA512 string `json:"sha512,omitempty"`
	SHA1   string `json:"sha1,omitempty"`
	// H1 is the Go module hash of a module zip or of a go.mod (role
	// "package" or "go.mod" of a Go module): the base64 text without the
	// "h1:" prefix, as internal/lockfiles reports it.
	H1 string `json:"h1,omitempty"`
}

// ArtifactsOf returns the artifacts of a role.
func (c Change) ArtifactsOf(role string) []Artifact {
	var out []Artifact
	for _, a := range c.Artifacts {
		if a.Role == role {
			out = append(out, a)
		}
	}
	return out
}

// Updater rewrites one lock-file format natively.
type Updater interface {
	// Key is the format's "<type>/<format>" (internal/lockfiles).
	Key() string
	// Apply rewrites the lock file at lockPath for the changes. files holds
	// the lock file's content and the content of the siblings the format
	// needs (go.mod for go.sum and the other way round; package.json next to
	// package-lock.json), keyed by repository path (slash-separated). It
	// returns the files it changed, keyed the same way, with their new
	// content; a file it did not change is not in the result.
	//
	// An error means the native rewrite cannot be made safely (an entry in a
	// shape the updater does not rewrite, a version pinned by a replace
	// directive, an entry it cannot find): the caller falls back to the
	// format's FormatSupport.Fallback. Apply never returns a partial rewrite.
	Apply(lockPath string, files map[string][]byte, changes []Change) (map[string][]byte, error)
}
