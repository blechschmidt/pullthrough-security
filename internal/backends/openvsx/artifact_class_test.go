package openvsx

import (
	"context"
	"net/http"
	"net/url"
	"testing"

	"github.com/blechschmidt/pullthrough-security/internal/backends"
)

// TestResolveArtifactClass pins what Resolve tells the content gates. The .vsix
// archive is a payload. Nothing is metadata: the backend forwards the whole /api
// and /vscode trees, and they serve the extension under other names too (the
// gallery protocol's VSIXPackage asset), so every other path is left for a gate
// to judge from the bytes.
func TestResolveArtifactClass(t *testing.T) {
	b := newTestBackend(t, newFakeRemote(t), "https://proxy.example/v1/openvsx", nil)

	cases := []struct {
		name     string
		path     string
		class    backends.ArtifactClass
		servedAs string // what Resolved.ArtifactFilename reports
	}{
		{
			"extension archive", "/api/dracula-theme/theme-dracula/2.25.1/file/dracula-theme.theme-dracula-2.25.1.vsix",
			backends.ArtifactPayload, "dracula-theme.theme-dracula-2.25.1.vsix",
		},
		{
			"target-platform extension archive", "/api/ms-vscode/cpptools/linux-x64/1.0.0/file/ms-vscode.cpptools-linux-x64-1.0.0.vsix",
			backends.ArtifactPayload, "ms-vscode.cpptools-linux-x64-1.0.0.vsix",
		},

		// /api documents.
		{"extension metadata", "/api/dracula-theme/theme-dracula", backends.ArtifactUnclassified, "theme-dracula"},
		{"version metadata", "/api/dracula-theme/theme-dracula/2.25.1", backends.ArtifactUnclassified, "2.25.1"},
		{"query", "/api/-/query", backends.ArtifactUnclassified, "query"},

		// The VS Code gallery protocol, which downloads the .vsix as an "asset".
		{"gallery query", "/vscode/gallery/extensionquery", backends.ArtifactUnclassified, "extensionquery"},
		{
			"gallery asset that is the extension archive",
			"/vscode/asset/dracula-theme/theme-dracula/2.25.1/Microsoft.VisualStudio.Services.VSIXPackage",
			backends.ArtifactUnclassified, "Microsoft.VisualStudio.Services.VSIXPackage",
		},

		// Other /file/ resources, including archives outside the recognized form.
		{
			"checksum sidecar", "/api/dracula-theme/theme-dracula/2.25.1/file/dracula-theme.theme-dracula-2.25.1.sha256",
			backends.ArtifactUnclassified, "dracula-theme.theme-dracula-2.25.1.sha256",
		},
		{"extension manifest", "/api/dracula-theme/theme-dracula/2.25.1/file/package.json", backends.ArtifactUnclassified, "package.json"},
		{"archive suffix in upper case", "/api/dracula-theme/theme-dracula/2.25.1/file/x.VSIX", backends.ArtifactUnclassified, "x.VSIX"},
		{"archive too high in the tree", "/api/dracula-theme/file/x.vsix", backends.ArtifactUnclassified, "x.vsix"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resolved, err := b.Resolve(context.Background(), &backends.Request{
				Method: http.MethodGet, Path: tc.path, Query: url.Values{}, Header: http.Header{},
			})
			if err != nil {
				t.Fatalf("Resolve(%q): %v", tc.path, err)
			}
			got := resolved.Artifact
			if got.Class != tc.class {
				t.Errorf("Resolve(%q) class = %s, want %s", tc.path, got.Class, tc.class)
			}
			if got.Class == backends.ArtifactMetadata {
				t.Errorf("Resolve(%q) is classified metadata; this backend cannot positively identify any", tc.path)
			}
			if got.Kind != "" {
				t.Errorf("Resolve(%q) kind = %q, want none", tc.path, got.Kind)
			}
			// Every resource is fetched from a URL that ends in its own name.
			if got.Filename != "" {
				t.Errorf("Resolve(%q) filename = %q, want none", tc.path, got.Filename)
			}
			if name := resolved.ArtifactFilename(); name != tc.servedAs {
				t.Errorf("Resolve(%q).ArtifactFilename() = %q, want %q", tc.path, name, tc.servedAs)
			}
		})
	}
}
