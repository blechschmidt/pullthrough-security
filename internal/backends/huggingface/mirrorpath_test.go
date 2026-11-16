package huggingface

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/blechschmidt/pullthrough-security/internal/backends"
	"github.com/blechschmidt/pullthrough-security/internal/upstream"
)

func mirrorPathResolve(t *testing.T, b *Backend, p string) *backends.Resolved {
	t.Helper()
	dec, err := url.PathUnescape(p)
	if err != nil {
		t.Fatalf("%s does not decode: %v", p, err)
	}
	res, err := b.Resolve(context.Background(), &backends.Request{Method: http.MethodGet, Path: dec, Query: url.Values{}, Header: http.Header{}})
	if err != nil {
		t.Fatalf("%s: %v", p, err)
	}
	return res
}

// A resolve path ResolvePath builds, decoded as the server decodes a request,
// resolves to the cacheable file of the repository at the commit; InfoPath's
// document resolves as the repository's metadata.
func TestResolvePathRoundTrips(t *testing.T) {
	b, err := New(Options{Name: "hf-test", UpstreamURL: "https://huggingface.co", Client: upstream.NewWithHTTPClient(http.DefaultClient, "test")})
	if err != nil {
		t.Fatal(err)
	}
	sha := "d039ab0d4b9311b617e8ffec1d06c8464364aeb3"
	for _, tc := range []struct {
		kind, repo, file, want, coordinate string
	}{
		{RepoModel, "HuggingFaceTB/SmolVLM-256M-Instruct", "config.json", "/HuggingFaceTB/SmolVLM-256M-Instruct/resolve/" + sha + "/config.json", "HuggingFaceTB/SmolVLM-256M-Instruct"},
		{RepoModel, "HuggingFaceTB/SmolVLM-256M-Instruct", "onnx/vision_encoder_q4.onnx", "/HuggingFaceTB/SmolVLM-256M-Instruct/resolve/" + sha + "/onnx/vision_encoder_q4.onnx", "HuggingFaceTB/SmolVLM-256M-Instruct"},
		{RepoModel, "gpt2", ".gitattributes", "/gpt2/resolve/" + sha + "/.gitattributes", "gpt2"},
		{RepoModel, "o/m", "dir with space/ä #1?.txt", "/o/m/resolve/" + sha + "/dir%20with%20space/%C3%A4%20%231%3F.txt", "o/m"},
		{RepoModel, "o/m", "100%.bin", "/o/m/resolve/" + sha + "/100%25.bin", "o/m"},
		{RepoModel, "o/m", "resolve/x.json", "/o/m/resolve/" + sha + "/resolve/x.json", "o/m"},
		{RepoDataset, "fka/prompts.chat", "prompts.csv", "/datasets/fka/prompts.chat/resolve/" + sha + "/prompts.csv", "datasets/fka/prompts.chat"},
		{RepoSpace, "o/app", "app.py", "/spaces/o/app/resolve/" + sha + "/app.py", "spaces/o/app"},
	} {
		p, ok := ResolvePath(tc.kind, tc.repo, sha, tc.file)
		if !ok || p != tc.want {
			t.Errorf("ResolvePath(%s, %s, %s) = %q, %v; want %q", tc.kind, tc.repo, tc.file, p, ok, tc.want)
			continue
		}
		res := mirrorPathResolve(t, b, p)
		if !res.Cacheable || res.Coordinate.Name != tc.coordinate || res.Coordinate.Version != sha || res.Metadata[MetaPath] != tc.file {
			t.Errorf("%s resolves to %+v, file %q (cacheable %v)", p, res.Coordinate, res.Metadata[MetaPath], res.Cacheable)
		}
	}
	for _, tc := range []struct{ kind, repo, commit, file string }{
		{RepoModel, "o/m", "main", "config.json"},                       // a branch moves: not cached
		{RepoModel, "o/m", sha[:39], "config.json"},                     // not a full SHA
		{RepoModel, "o/m", strings.Repeat("g", 40), "config.json"},      // not hex
		{RepoModel, "datasets/x", sha, "config.json"},                   // read as a dataset
		{RepoModel, "spaces/x", sha, "config.json"},                     // read as a space
		{RepoModel, "api/models", sha, "config.json"},                   // read as the API
		{RepoModel, "o/resolve", sha, "config.json"},                    // the first "resolve" is the delimiter
		{RepoModel, "o/m", sha, ""},                                     // no file
		{RepoModel, "o/m", sha, "a/../b"},                               // a dot segment
		{RepoModel, "o/m", sha, "/abs"},                                 // an empty segment
		{RepoModel, "o/m", sha, "a//b"},                                 //
		{RepoModel, "o/m", sha, "a\nb"},                                 // a control character
		{RepoModel, "", sha, "config.json"},                             //
		{RepoModel, "o//m", sha, "config.json"},                         //
		{"collection", "o/m", sha, "config.json"},                       // no such kind
		{RepoDataset, "o/m", strings.ToUpper(sha)[:39] + "x", "a.json"}, //
	} {
		if p, ok := ResolvePath(tc.kind, tc.repo, tc.commit, tc.file); ok {
			t.Errorf("ResolvePath(%+v) = %q, want a refusal", tc, p)
		}
	}

	for _, tc := range []struct{ kind, repo, want, coordinate, label string }{
		{RepoModel, "HuggingFaceTB/SmolVLM-256M-Instruct", "/api/models/HuggingFaceTB/SmolVLM-256M-Instruct/revision/main", "HuggingFaceTB/SmolVLM-256M-Instruct", "model-info"},
		{RepoDataset, "fka/prompts.chat", "/api/datasets/fka/prompts.chat/revision/main", "datasets/fka/prompts.chat", "dataset-info"},
		{RepoSpace, "o/app", "/api/spaces/o/app/revision/main", "spaces/o/app", "space-info"},
		{RepoModel, "gpt2", "/api/models/gpt2/revision/main", "gpt2", "model-info"},
	} {
		p, ok := InfoPath(tc.kind, tc.repo, "main")
		if !ok || p != tc.want {
			t.Errorf("InfoPath(%s, %s) = %q, %v; want %q", tc.kind, tc.repo, p, ok, tc.want)
			continue
		}
		res := mirrorPathResolve(t, b, p)
		if res.Cacheable || res.Coordinate.Name != tc.coordinate || res.Metadata[metaKind] != tc.label || res.Artifact != backends.Metadata() {
			t.Errorf("%s resolves to %+v (%s, cacheable %v)", p, res.Coordinate, res.Metadata[metaKind], res.Cacheable)
		}
	}
	for _, tc := range []struct{ kind, repo, rev string }{
		{RepoModel, "o/m", "refs/pr/1"}, {RepoModel, "o/tree", "main"}, {RepoModel, "o/m/x", "main"}, {RepoModel, "o/m", ""},
		{RepoModel, "", "main"}, {"collection", "o/m", "main"}, {RepoModel, "o/m", ".."},
	} {
		if p, ok := InfoPath(tc.kind, tc.repo, tc.rev); ok {
			t.Errorf("InfoPath(%+v) = %q, want a refusal", tc, p)
		}
	}
}
