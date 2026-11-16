//go:build integration
// +build integration

package fullmirror

import (
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"sort"
	"strings"
)

// Conan: the adapter follows conan-center-index's Git history, the
// repository ConanCenter is built from: a recipe is the directory
// "recipes/<name>/" — config.yml mapping its versions to a recipe folder
// ("all"), the folder's conanfile.py, and the folder's test_package, which is
// not exported with the recipe and lies outside what the adapter follows. The
// adapter diffs the trees of the head commits and reports each recipe whose
// directory changed, by name. For each it asks the remote's recipe search
// which versions it serves ("/v2/conans/search?q=<name>/*", sent to the
// remote directly), then reads through the proxy each version's latest recipe
// revision and its file list, and — with the feed option binaries — the
// recipe revision's package search, each selected package's latest package
// revision and its file list: the files of those revisions are what the
// mirror fetches.
//
// The stub's Git repository is a real one served by `git http-backend` (feed
// option url, as for a remote other than ConanCenter); a publication is a
// commit adding the recipe's directory, one per recipe as conan-center-index
// merges one pull request per recipe change, with the conanfile.py the stub
// remote's recipe revision holds. The stub remote (the LLM package-scan
// suite's) serves the revisions, file lists and files a client downloads for
// an install. The two searches a client does not need for one are served in
// front of it as ConanCenter's Artifactory serves them: the recipe search
// lists the references of the recipes published ("name/version@_/_", in text
// order), the package search of a recipe revision each package ID with the
// settings and options of its conaninfo.txt, the file itself and its
// requirements. Feed option binaries: the stub's one configuration
// (os=Linux, arch=x86_64). The adapter reports a commit once it has settled
// (feed option settle, by default an hour: ConanCenter promotes a merged
// change within minutes); the suite's commits are dated two hours back, so
// the row runs with the default, through the settle path, and every commit has
// settled when the mirror polls.

func init() {
	register(row{
		Type:    "conan",
		Feed:    "Git repository (conan-center-index layout) over smart HTTP, `git http-backend`; the remote's recipe and package searches",
		Start:   conanFeedStart,
		Publish: conanPublish,
		Options: func(env *feedEnv) map[string]string {
			return map[string]string{"url": conanRepo(env).URL(), "binaries": "os=Linux,arch=x86_64"}
		},
		Files:   conanFiles,
		Resumed: func(env *feedEnv, _ []string) error { return gitHaveResumed(env, "cci") },
		Notes: []string{
			"one recipe revision and one binary package per version: newer revisions of a published version are not covered",
		},
	})
}

func conanRepo(env *feedEnv) *gitRepo { return env.get("repo").(*gitRepo) }

func conanFeedStart(env *feedEnv) error {
	// The recorder and gitHaveCommit are the bazel row's (row_bazel.go).
	fetches := newGitHaveLog(env, "cci")
	repo, err := newGitRepo(env, "cci")
	if err != nil {
		return err
	}
	env.set("repo", repo)
	env.set("fetches", fetches)
	if _, err := repo.commit("Initial index", map[string][]byte{
		"README.md": []byte("# pullthrough full-mirror e2e: recipes laid out as conan-center-index\n"),
	}); err != nil {
		return err
	}
	env.Stub.Handle("/v2/conans/search", func(w http.ResponseWriter, r *http.Request) { conanRecipeSearch(env, w, r) })
	env.Stub.Fallback(func(w http.ResponseWriter, r *http.Request) bool { return conanPackageSearch(env, w, r) })
	return conanPublish(env, env.Publications())
}

// conanPublish commits each recipe published: its config.yml, its folder's
// conanfile.py (the stub remote's latest recipe revision's) and test package.
func conanPublish(env *feedEnv, added []publication) error {
	repo := conanRepo(env)
	for _, p := range added {
		recipe, _, _ := strings.Cut(p.Pkg.Path, "/packages/")
		conanfile, err := env.fetch(recipe + "/files/conanfile.py")
		if err != nil {
			return err
		}
		dir := "recipes/" + p.Pkg.Name + "/"
		files := map[string][]byte{
			dir + "config.yml":       []byte("versions:\n  \"" + p.Pkg.Version + "\":\n    folder: all\n"),
			dir + "all/conanfile.py": conanfile,
			dir + "all/test_package/conanfile.py": []byte("from conan import ConanFile\n\n\n" +
				"class TestPackageConan(ConanFile):\n    settings = \"os\", \"arch\", \"compiler\", \"build_type\"\n\n" +
				"    def requirements(self):\n        self.requires(self.tested_reference_str)\n\n" +
				"    def test(self):\n        pass\n"),
		}
		if err := gitHaveCommit(env, repo, []publication{p}, fmt.Sprintf("(#%d) %s/%s: new recipe", 20000+p.Seq, p.Pkg.Name, p.Pkg.Version), files); err != nil {
			return err
		}
	}
	return nil
}

// conanFiles are a package's files as the adapter lists them: the latest
// recipe revision's (conanfile.py, conanmanifest.txt), then the selected
// binary package's latest revision's (conan_package.tgz — the payload —,
// conaninfo.txt, conanmanifest.txt). The manifests and conaninfo.txt are
// metadata to the backend, and the download log as shipped
// (downloadLog.includeMetadata off) records no fetch of metadata that was
// served.
func conanFiles(_ *feedEnv, p publication) []file {
	recipe, _, _ := strings.Cut(p.Pkg.Path, "/packages/")
	binary := p.Pkg.Path[:strings.LastIndex(p.Pkg.Path, "/")]
	// The manifests and conaninfo.txt are metadata to the backend
	// (conan/path.go): the download log leaves them out.
	return []file{
		{Path: p.Pkg.Path},
		{Path: recipe + "/files/conanfile.py"}, {Path: recipe + "/files/conanmanifest.txt", Metadata: true},
		{Path: binary + "/conaninfo.txt", Metadata: true}, {Path: binary + "/conanmanifest.txt", Metadata: true},
	}
}

// conanRecipeSearch answers the remote's recipe search: the references of the
// recipes published that the pattern matches, as fnmatch matches it (a "*"
// spans any characters), without regard to case.
func conanRecipeSearch(env *feedEnv, w http.ResponseWriter, r *http.Request) {
	pattern := r.URL.Query().Get("q")
	if pattern == "" {
		pattern = "*"
	}
	quoted := regexp.QuoteMeta(pattern)
	quoted = strings.ReplaceAll(strings.ReplaceAll(quoted, `\*`, ".*"), `\?`, ".")
	match, err := regexp.Compile("(?i)^" + quoted + "$")
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	results := []string{}
	for _, p := range env.Publications() {
		if ref := p.Pkg.Name + "/" + p.Pkg.Version; match.MatchString(ref) {
			results = append(results, ref+"@_/_")
		}
	}
	sort.Strings(results)
	writeJSON(w, map[string]any{"results": results})
}

// conanPackageSearch answers the package search of a published recipe's
// latest revision, "/v2/conans/<name>/<version>/_/_/revisions/<rrev>/search":
// its one binary package, described by its conaninfo.txt.
func conanPackageSearch(env *feedEnv, w http.ResponseWriter, r *http.Request) bool {
	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/v2/conans/"), "/")
	if !strings.HasPrefix(r.URL.Path, "/v2/conans/") || len(parts) != 7 || parts[2] != "_" || parts[3] != "_" || parts[4] != "revisions" || parts[6] != "search" {
		return false
	}
	for _, p := range env.Publications() {
		recipe, rest, _ := strings.Cut(p.Pkg.Path, "/packages/")
		if p.Pkg.Name != parts[0] || p.Pkg.Version != parts[1] || !strings.HasSuffix(recipe, "/revisions/"+parts[5]) {
			continue
		}
		pkgID, _, _ := strings.Cut(rest, "/")
		info, err := env.fetch(p.Pkg.Path[:strings.LastIndex(p.Pkg.Path, "/")] + "/conaninfo.txt")
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return true
		}
		sections := conanInfoSections(string(info))
		writeJSON(w, map[string]any{pkgID: map[string]any{
			"settings": sections["settings"], "options": sections["options"], "content": string(info), "requires": []string{},
		}})
		return true
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusNotFound)
	body, _ := json.Marshal(map[string]any{"errors": []map[string]any{{"status": 404, "message": "Not Found"}}})
	_, _ = w.Write(body)
	return true
}

// conanInfoSections reads the key=value lines of a conaninfo.txt's sections
// ("[settings]", "[options]"); every section asked for is a map, empty when
// the file has none.
func conanInfoSections(info string) map[string]map[string]string {
	out := map[string]map[string]string{"settings": {}, "options": {}}
	section := ""
	for _, line := range strings.Split(info, "\n") {
		line = strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]"):
			section = line[1 : len(line)-1]
		case section != "" && strings.Contains(line, "="):
			if m, ok := out[section]; ok {
				k, v, _ := strings.Cut(line, "=")
				m[k] = v
			}
		}
	}
	return out
}
