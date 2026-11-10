package rebuildverify

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"sort"
	"strings"
)

// Sentinel errors a Builder returns to classify a non-mismatch outcome. The
// Service maps each to the "unsupported" verdict (fail-open): a builder that
// cannot run must never produce a false "mismatch".
var (
	// ErrToolchainUnavailable: the build toolchain is not present (e.g. air-gapped
	// host without the compiler). The verification is skipped.
	ErrToolchainUnavailable = errors.New("rebuildverify: build toolchain unavailable")
	// ErrUnsupported: the ecosystem (or this specific artifact) cannot be rebuilt
	// deterministically by the registered builder.
	ErrUnsupported = errors.New("rebuildverify: reproducible rebuild not supported")
)

// BuildContext carries everything a Builder needs to rebuild an artifact from
// its attested source.
type BuildContext struct {
	// Coordinate identifies the artifact (and carries its upstream digest).
	Coordinate Coordinate
	// Source is the attested source revision, including a located local clone in
	// RepoDir when available.
	Source Source
	// RepoDir is a local clone of the source repository (may be empty when the
	// Service has no locator and the caller supplied no directory).
	RepoDir string
	// UpstreamDigest is the upstream-served artifact's content digest.
	UpstreamDigest string
	// Upstream optionally opens the upstream-served artifact bytes so a builder can
	// compute a normalized upstream digest for comparison. May be nil.
	Upstream func() (io.ReadCloser, error)
}

// BuildOutput is a Builder's result.
type BuildOutput struct {
	// Digest is the digest of the rebuilt artifact ("sha256:..." or raw hex).
	Digest string
	// UpstreamDigest, when set, is a normalized digest of the upstream artifact the
	// builder computed itself (for content-rather-than-address comparison); when
	// empty the Service compares against the coordinate's upstream digest.
	UpstreamDigest string
	// Normalized reports whether the comparison is over normalized (rather than
	// byte-identical) representations.
	Normalized bool
	// Detail carries optional builder-specific diagnostics surfaced in the admin
	// view.
	Detail map[string]string
}

// Builder rebuilds an artifact from its attested source and reports the rebuilt
// digest. Implementations MUST be sandboxed and offline/air-gap aware: when the
// toolchain or source is unavailable they return ErrToolchainUnavailable /
// ErrUnsupported rather than failing the verification.
type Builder interface {
	// Name is a stable identifier for metrics and the admin surface.
	Name() string
	// Supports reports whether the builder handles the given ecosystem.
	Supports(ecosystem string) bool
	// Build rebuilds the artifact and returns its digest.
	Build(ctx context.Context, bc BuildContext) (BuildOutput, error)
}

// Registry holds the ordered set of builders; the first that Supports an
// ecosystem handles it.
type Registry struct {
	builders []Builder
}

// NewRegistry constructs a registry from the given builders.
func NewRegistry(builders ...Builder) *Registry {
	r := &Registry{}
	for _, b := range builders {
		if b != nil {
			r.builders = append(r.builders, b)
		}
	}
	return r
}

// Register appends a builder to the registry.
func (r *Registry) Register(b Builder) {
	if r != nil && b != nil {
		r.builders = append(r.builders, b)
	}
}

// For returns the first builder that supports the ecosystem, or nil.
func (r *Registry) For(ecosystem string) Builder {
	if r == nil {
		return nil
	}
	for _, b := range r.builders {
		if b.Supports(ecosystem) {
			return b
		}
	}
	return nil
}

// Supports reports whether any builder handles the ecosystem.
func (r *Registry) Supports(ecosystem string) bool { return r.For(ecosystem) != nil }

// Ecosystems returns the sorted, de-duplicated set of ecosystems the registry's
// builders advertise (for the admin surface).
func (r *Registry) Ecosystems() []string {
	if r == nil {
		return nil
	}
	seen := make(map[string]struct{})
	for _, b := range r.builders {
		if tb, ok := b.(ecosystemLister); ok {
			for _, e := range tb.ecosystems() {
				seen[e] = struct{}{}
			}
		}
	}
	out := make([]string, 0, len(seen))
	for e := range seen {
		out = append(out, e)
	}
	sort.Strings(out)
	return out
}

// ecosystemLister lets the registry enumerate a builder's advertised
// ecosystems; the built-in builders implement it.
type ecosystemLister interface {
	ecosystems() []string
}

// BuiltinBuilders returns the default registry of toolchain-gated stub builders
// for the ecosystems with reproducible toolchains. Each builder skips gracefully
// (ErrToolchainUnavailable) when its toolchain is absent and otherwise degrades
// to ErrUnsupported — a production operator registers a real sandboxed builder
// (via Config.Registry) without changing any wiring. Stub builders ensure the
// subsystem degrades gracefully rather than blocking pulls it cannot verify.
func BuiltinBuilders() *Registry {
	return NewRegistry(
		newToolchainBuilder("go", []string{"go", "golang"}, []string{"go"}, "Go module"),
		newToolchainBuilder("npm", []string{"npm", "node"}, []string{"npm", "node"}, "npm package (install scripts disabled)"),
		newToolchainBuilder("python", []string{"python", "pypi", "pip"}, []string{"python3", "python"}, "Python sdist/wheel"),
		newToolchainBuilder("container", []string{"docker", "oci", "container"}, []string{"buildctl", "docker"}, "container image (buildkit)"),
	)
}

// toolchainBuilder is a stub builder that detects whether the ecosystem's build
// toolchain is present and, since this deployment ships no embedded sandboxed
// rebuilder, degrades to ErrUnsupported when it is (and ErrToolchainUnavailable
// when it is not). It exists so the subsystem is fully wired and air-gap aware
// out of the box.
type toolchainBuilder struct {
	name     string
	ecos     []string
	binaries []string
	label    string
	// lookPath is injectable for tests; nil uses exec.LookPath.
	lookPath func(string) (string, error)
}

func newToolchainBuilder(name string, ecos, binaries []string, label string) *toolchainBuilder {
	return &toolchainBuilder{name: name, ecos: ecos, binaries: binaries, label: label}
}

func (b *toolchainBuilder) Name() string { return b.name }

func (b *toolchainBuilder) ecosystems() []string { return b.ecos }

func (b *toolchainBuilder) Supports(ecosystem string) bool {
	eco := strings.ToLower(strings.TrimSpace(ecosystem))
	for _, e := range b.ecos {
		if e == eco {
			return true
		}
	}
	return false
}

func (b *toolchainBuilder) Build(ctx context.Context, bc BuildContext) (BuildOutput, error) {
	if !b.toolchainPresent() {
		return BuildOutput{}, fmt.Errorf("%w: none of %v found in PATH for %s", ErrToolchainUnavailable, b.binaries, b.label)
	}
	// The toolchain is present, but a deterministic rebuild must run inside an
	// operator-supplied sandbox (network-isolated, pinned toolchain). This default
	// builder does not execute an unsandboxed build; it degrades to unsupported so
	// the gate fails open. Register a real Builder via Config.Registry to enable
	// verification for this ecosystem.
	return BuildOutput{}, fmt.Errorf("%w: deterministic %s rebuild requires an operator-supplied sandboxed builder", ErrUnsupported, b.label)
}

func (b *toolchainBuilder) toolchainPresent() bool {
	look := b.lookPath
	if look == nil {
		look = exec.LookPath
	}
	for _, bin := range b.binaries {
		if _, err := look(bin); err == nil {
			return true
		}
	}
	return false
}

// StubBuilder is an explicit no-op builder for ecosystems with no reproducible
// toolchain; it advertises support but always reports the artifact unsupported,
// so an operator can register it to make "unsupported" an explicit, observable
// verdict rather than a silent gap.
type StubBuilder struct {
	name string
	ecos []string
}

// NewStubBuilder constructs a stub builder advertising the given ecosystems.
func NewStubBuilder(name string, ecosystems ...string) *StubBuilder {
	lowered := make([]string, 0, len(ecosystems))
	for _, e := range ecosystems {
		lowered = append(lowered, strings.ToLower(strings.TrimSpace(e)))
	}
	return &StubBuilder{name: name, ecos: lowered}
}

func (b *StubBuilder) Name() string { return b.name }

func (b *StubBuilder) ecosystems() []string { return b.ecos }

func (b *StubBuilder) Supports(ecosystem string) bool {
	eco := strings.ToLower(strings.TrimSpace(ecosystem))
	for _, e := range b.ecos {
		if e == eco {
			return true
		}
	}
	return false
}

func (b *StubBuilder) Build(ctx context.Context, bc BuildContext) (BuildOutput, error) {
	return BuildOutput{}, fmt.Errorf("%w: no reproducible-build toolchain for ecosystem %q", ErrUnsupported, bc.Coordinate.Ecosystem)
}
