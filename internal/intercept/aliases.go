package intercept

import "sort"

// clientHosts lists, per ecosystem and public registry, the routing rules a
// stock client uses for that registry besides the URL an operator configures
// for it. A client in interception mode keeps its built-in defaults, and those
// do not always name the host the registry is best known by: Maven's built-in
// central repository is repo.maven.apache.org, not repo1.maven.org; Bundler
// fetches rubygems.org's index from index.rubygems.org; Yarn's default registry
// is registry.yarnpkg.com, which serves npm's registry. Each entry is a host
// that serves the same registry with the same path layout, so the upstream
// configured for one serves the other.
//
// One entry is a host of another kind: brew installs bottles from ghcr.io,
// whose URLs it reads from the signed formula index it gets from
// formulae.brew.sh — a document the proxy cannot rewrite, so the bottle
// downloads arrive at ghcr.io itself. The Homebrew backend serves ghcr.io's
// registry-native bottle paths (the ones HOMEBREW_ARTIFACT_DOMAIN makes brew
// request). An upstream configured for ghcr.io (a container registry) keeps the
// host: client hosts never take a rule an upstream URL claims.
//
// The keys are the rule of the upstream URL as RuleOf spells it.
var clientHosts = map[string]map[string][]string{
	"maven": {
		"repo1.maven.org/maven2":       {"repo.maven.apache.org/maven2"},
		"repo.maven.apache.org/maven2": {"repo1.maven.org/maven2"},
	},
	"npm": {
		"registry.npmjs.org":   {"registry.yarnpkg.com"},
		"registry.yarnpkg.com": {"registry.npmjs.org"},
	},
	"rubygems": {
		"rubygems.org":       {"index.rubygems.org"},
		"index.rubygems.org": {"rubygems.org"},
	},
	"homebrew": {
		"formulae.brew.sh": {"ghcr.io"},
	},
	"dart": {
		"pub.dev":          {"pub.dartlang.org"},
		"pub.dartlang.org": {"pub.dev"},
	},
}

// ClientHosts returns the routing rules, beyond the upstream URL's own, that a
// stock client of ecosystem uses for the public registry upstreamURL points at
// (see clientHosts). It returns nil for any other registry.
func ClientHosts(ecosystem, upstreamURL string) []string {
	rules := clientHosts[ecosystem][RuleOf(upstreamURL)]
	if len(rules) == 0 {
		return nil
	}
	out := append([]string(nil), rules...)
	sort.Strings(out)
	return out
}
