//go:build integration
// +build integration

package fullmirror

import "fmt"

// Cargo: the adapter follows a registry's Git index — crates.io-index's
// layout, one file per crate named by its name ("pt/e2/pte2e-seed") holding a
// JSON line per version — by diffing the trees of its head commits, and reads
// each crate's versions from the sparse index through the proxy. The stub's
// Git index is a real repository served by `git http-backend` (feed option
// url, as for a private registry); a publication is a commit adding the
// crate's file, with the line the sparse index serves. The restart is checked
// in the Git protocol's terms (row_bazel.go): the restarted mirror's first
// fetch names the commit it stored as one it has, and asks for the new head.

func init() {
	register(row{
		Type:  "cargo",
		Feed:  "Git index (crates.io-index layout) over smart HTTP, `git http-backend`",
		Start: cargoFeedStart,
		Publish: func(env *feedEnv, added []publication) error {
			return cargoCommit(env, added, "publish")
		},
		Options: func(env *feedEnv) map[string]string {
			return map[string]string{"url": cargoRepo(env).URL()}
		},
		Resumed: func(env *feedEnv, _ []string) error { return gitHaveResumed(env, "crates-index") },
	})
}

func cargoRepo(env *feedEnv) *gitRepo { return env.get("repo").(*gitRepo) }

func cargoFeedStart(env *feedEnv) error {
	// The recorder of the fetches comes before the repository's own route.
	fetches := newGitHaveLog(env, "crates-index")
	repo, err := newGitRepo(env, "crates-index")
	if err != nil {
		return err
	}
	env.set("repo", repo)
	env.set("fetches", fetches)
	config := []byte(fmt.Sprintf(`{"dl": %q, "api": %q}`+"\n", env.URL()+"/api/v1/crates", env.URL()))
	if _, err := repo.commit("initial index", map[string][]byte{"config.json": config}); err != nil {
		return err
	}
	return cargoCommit(env, env.Publications(), "publish")
}

// cargoCommit commits the index files of the crates published.
func cargoCommit(env *feedEnv, pubs []publication, verb string) error {
	files := map[string][]byte{}
	for _, p := range pubs {
		path := cargoIndexFile(p.Pkg.Name)
		line, err := env.fetch("/" + path)
		if err != nil {
			return err
		}
		files[path] = line
	}
	return gitHaveCommit(env, cargoRepo(env), pubs, fmt.Sprintf("%s %d crate(s)", verb, len(pubs)), files)
}

// cargoIndexFile is a crate's file in the index: "<first two>/<next two>/<name>"
// for a name of four or more characters, as every fixture name is.
func cargoIndexFile(name string) string { return name[:2] + "/" + name[2:4] + "/" + name }
