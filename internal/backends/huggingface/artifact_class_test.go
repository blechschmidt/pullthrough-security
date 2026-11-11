package huggingface

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/blechschmidt/pullthrough-security/internal/backends"
)

// TestResolveArtifactClass pins what Resolve tells the content gates about a Hub
// path. A resolved file is a payload when its name says a client loads or runs
// it (a weight file, code, an archive); any other resolved file is left for a
// gate to judge from its bytes, never called metadata. Only a repository-info
// document is metadata.
func TestResolveArtifactClass(t *testing.T) {
	b := newTestBackend(t, newFakeRemote(t), nil)

	cases := []struct {
		name  string
		path  string
		class backends.ArtifactClass
	}{
		// Weight files.
		{"pickle weights", "/bert/resolve/main/pytorch_model.bin", backends.ArtifactPayload},
		{"safetensors weights", "/bert/resolve/main/model.safetensors", backends.ArtifactPayload},
		{"gguf weights pinned to a commit", "/org/m/resolve/" + commitSHA + "/model.gguf", backends.ArtifactPayload},
		{"onnx weights in a subdirectory", "/org/m/resolve/main/onnx/model.onnx", backends.ArtifactPayload},

		// Code and archives.
		{"custom model code", "/org/m/resolve/main/modeling_custom.py", backends.ArtifactPayload},
		{"dataset loading script", "/datasets/org/d/resolve/main/d.py", backends.ArtifactPayload},
		{"space application", "/spaces/owner/app/resolve/main/app.py", backends.ArtifactPayload},
		{"notebook", "/org/m/resolve/main/demo.ipynb", backends.ArtifactPayload},
		{"keras model", "/org/m/resolve/main/model.keras", backends.ArtifactPayload},
		{"shared library", "/org/m/resolve/main/lib/ops.so", backends.ArtifactPayload},
		{"archive in upper case", "/org/m/resolve/main/sub/dir/MODEL.TAR.GZ", backends.ArtifactPayload},
		{"bzip2 tarball", "/org/m/resolve/main/bundle.tar.bz2", backends.ArtifactPayload},
		{"wheel", "/org/m/resolve/main/dist/pkg-1.0-py3-none-any.whl", backends.ArtifactPayload},

		// Everything else a repository holds: sniffed, not skipped.
		{"model config", "/org/m/resolve/main/config.json", backends.ArtifactUnclassified},
		{"readme", "/org/m/resolve/main/README.md", backends.ArtifactUnclassified},
		{"tokenizer json is not javascript", "/org/m/resolve/main/tokenizer.json", backends.ArtifactUnclassified},
		{"image", "/org/m/resolve/main/logo.png", backends.ArtifactUnclassified},
		{"parquet shard", "/datasets/squad/resolve/main/data/train.parquet", backends.ArtifactUnclassified},
		{"bare bzip2 file", "/org/m/resolve/main/data.bz2", backends.ArtifactUnclassified},
		{"file without an extension", "/org/m/resolve/main/LICENSE", backends.ArtifactUnclassified},

		// Repository-info documents.
		{"model info", "/api/models/org/m", backends.ArtifactMetadata},
		{"canonical model info", "/api/models/gpt2", backends.ArtifactMetadata},
		{"model info at a revision", "/api/models/org/m/revision/main", backends.ArtifactMetadata},
		{"canonical model info at a commit", "/api/models/gpt2/revision/" + commitSHA, backends.ArtifactMetadata},
		{"dataset info", "/api/datasets/squad", backends.ArtifactMetadata},
		{"dataset info at a revision", "/api/datasets/org/d/revision/main", backends.ArtifactMetadata},
		{"space info", "/api/spaces/owner/app", backends.ArtifactMetadata},

		// The rest of the /api subtree shares the info kinds but is not positively
		// an info document.
		{"file tree", "/api/models/org/m/tree/main", backends.ArtifactUnclassified},
		{"refs", "/api/models/org/m/refs", backends.ArtifactUnclassified},
		{"parquet file of a dataset", "/api/datasets/org/d/parquet/default/train/0.parquet", backends.ArtifactUnclassified},
		{"revision without a value", "/api/models/org/m/revision", backends.ArtifactUnclassified},
		{"something below a revision", "/api/models/org/m/revision/main/extra", backends.ArtifactUnclassified},
		{"three-segment repository id", "/api/models/a/b/c", backends.ArtifactUnclassified},
		{"resolve-shaped path under /api", "/api/models/org/m/resolve/main/evil.py", backends.ArtifactUnclassified},
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
			// A repository serves its files one by one: every payload may be a
			// single file.
			wantKind := backends.ArtifactKind("")
			if got.Class == backends.ArtifactPayload {
				wantKind = backends.KindFile
			}
			if got.Kind != wantKind {
				t.Errorf("Resolve(%q) kind = %q, want %q", tc.path, got.Kind, wantKind)
			}
			// A Hub URL ends in the name of the file it serves.
			if got.Filename != "" {
				t.Errorf("Resolve(%q) filename = %q, want none", tc.path, got.Filename)
			}
			want := tc.path[strings.LastIndex(tc.path, "/")+1:]
			if name := resolved.ArtifactFilename(); name != want {
				t.Errorf("Resolve(%q).ArtifactFilename() = %q, want %q", tc.path, name, want)
			}
		})
	}
}

// TestCodeBearing covers the whole extension set, in either letter case, and the
// names that must stay outside it.
func TestCodeBearing(t *testing.T) {
	exts := []string{
		".py", ".pyc", ".pyw", ".ipynb", ".sh", ".bash", ".ps1", ".bat", ".cmd",
		".js", ".mjs", ".cjs", ".ts", ".rb", ".pl", ".lua",
		".jar", ".so", ".dll", ".dylib", ".exe", ".wasm",
		".joblib", ".dill", ".keras", ".pb", ".tflite", ".mlmodel",
		".zip", ".tar", ".tar.gz", ".tgz", ".tar.bz2", ".tar.xz", ".gz", ".7z", ".whl",
	}
	if len(codeBearingExts) != len(exts) {
		t.Errorf("codeBearingExts has %d entries, want %d", len(codeBearingExts), len(exts))
	}
	for _, ext := range exts {
		for _, name := range []string{"file" + ext, "FILE" + strings.ToUpper(ext), "dir.d/Mixed.Name" + ext} {
			if !codeBearing(name) {
				t.Errorf("codeBearing(%q) = false, want true", name)
			}
		}
	}
	for _, name := range []string{
		"", "py", "README", "README.md", "config.json", "tokenizer.json", "vocab.txt",
		"logo.png", "train.parquet", "data.csv", "data.bz2", "data.xz",
		"script.py.txt", "lib.so.1", "model.safetensors", "pytorch_model.bin",
	} {
		if codeBearing(name) {
			t.Errorf("codeBearing(%q) = true, want false", name)
		}
	}
}
