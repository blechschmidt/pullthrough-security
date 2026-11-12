//go:build integration
// +build integration

package pkgscan

import (
	"bytes"
	"crypto/sha1"
	"encoding/hex"
	"net/http"
	"strconv"
	"strings"
)

// Hugging Face Hub: a repository serves its files one by one, at
// "/<repo>/resolve/<revision>/<path>". huggingface_hub's snapshot_download
// (what `hf download` and a model's first load use to fetch a repository)
// first asks "/api/models/<repo>/revision/<rev>" which commit the revision is
// at and which files it holds, then downloads each file pinned to that commit —
// among them config.json, whose auto_map names the module transformers imports
// under trust_remote_code, and that module. A file named like code (".py") is a
// payload, examined as the single file it is; pinned to a 40-hex commit it is
// immutable and cached.
//
// Every response to a resolve carries X-Repo-Commit: huggingface_hub rejects
// one without it. A file stored in Git (not LFS) has its Git blob ID as its
// ETag, which is not a SHA-256: the proxy has no content digest to verify such
// a file against, exactly as with the real Hub.

func init() {
	register(eco{
		ID: "huggingface", Type: "huggingface", Title: "Hugging Face Hub",
		Format:   "custom model code (.py), pinned to a commit",
		Registry: huggingfaceRegistry,
	})
}

// hfCodeFile is the module of custom model code every fixture repository holds,
// and hfAutoModel the class in it that config.json's auto_map names.
const (
	hfCodeFile  = "modeling_pte2e.py"
	hfAutoModel = "modeling_pte2e.PTE2EModel"
)

// hfCodeLead is what the module holds in front of the variant's text.
const hfCodeLead = "# coding=utf-8\n" +
	"# Custom model code of the pullthrough llm-package-scan e2e fixture. transformers\n" +
	"# imports it (trust_remote_code=True) for the class config.json names in auto_map.\n"

// hfCode renders the module: the variant's text as comments, then a model class.
func hfCode(s pkgSpec) []byte {
	return []byte(hfCodeLead + s.Text("# ") +
		"\n\nclass PTE2EModel:\n    \"\"\"Returns its input unchanged.\"\"\"\n\n    def forward(self, x):\n        return x\n")
}

// hfCommitOf is the commit a fixture repository's revision "main" is at: 40 hex
// digits, unique to the repository.
func hfCommitOf(s pkgSpec) string {
	sum := sha1.Sum([]byte("pte2e-commit\x00" + s.Token))
	return hex.EncodeToString(sum[:])
}

// hfGitBlobID is the Git object ID of a file's content, which the Hub sends as
// the ETag of a file that is not stored in LFS.
func hfGitBlobID(content []byte) string {
	h := sha1.New()
	h.Write([]byte("blob " + strconv.Itoa(len(content)) + "\x00"))
	h.Write(content)
	return hex.EncodeToString(h.Sum(nil))
}

// hfServeFile serves one repository file the way the Hub's resolve endpoint
// does for a file held in Git.
func hfServeFile(commit string, content []byte, contentType string) http.HandlerFunc {
	etag := `"` + hfGitBlobID(content) + `"`
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Repo-Commit", commit)
		w.Header().Set("ETag", etag)
		w.Header().Set("Content-Type", contentType)
		http.ServeContent(w, r, "", stubModTime, bytes.NewReader(content))
	}
}

func huggingfaceRegistry(env stubEnv) (*registry, error) {
	reg := newRegistry()
	for _, s := range env.Specs {
		repo := "pte2e/" + s.Slug()
		commit := hfCommitOf(s)
		code := hfCode(s)
		config := jsonDoc(map[string]any{
			"architectures": []string{"PTE2EModel"},
			"auto_map":      map[string]string{"AutoModel": hfAutoModel},
			"model_type":    "pte2e",
		})
		info := "/api/models/" + repo + "/revision/main"
		reg.mux.File(info, jsonDoc(map[string]any{
			"id": repo, "modelId": repo, "sha": commit,
			"lastModified": "2024-01-02T03:04:05.000Z", "private": false, "gated": false, "disabled": false,
			"library_name": "transformers", "tags": []string{"transformers", "custom_code"},
			"siblings": []map[string]string{{"rfilename": ".gitattributes"}, {"rfilename": "config.json"}, {"rfilename": hfCodeFile}},
		}), "application/json")
		resolve := "/" + repo + "/resolve/" + commit + "/"
		reg.mux.Handle(resolve+"config.json", hfServeFile(commit, config, "application/json"))
		reg.mux.Handle(resolve+hfCodeFile, hfServeFile(commit, code, "text/plain; charset=utf-8"))

		reg.add(s.Variant, &pkgPull{
			// The coordinate is the repository and the revision the file was
			// requested at.
			Name: repo, Version: commit,
			Preamble: []step{
				// The revision resolves to the commit every file is then pinned to.
				{Path: info, Contains: []string{commit, hfCodeFile}},
				// config.json names the module transformers imports.
				{Path: resolve + "config.json", Contains: []string{hfAutoModel}},
			},
			Payload: step{Path: resolve + hfCodeFile},
			Body:    code,
			// A single file is listed under its own name.
			Marker:       hfCodeFile,
			MarkerOffset: strings.Count(hfCodeLead, "\n"),
		})
	}
	return reg, nil
}
