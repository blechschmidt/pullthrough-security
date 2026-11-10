package reposcore

import (
	"context"
	"sort"
	"strconv"
	"strings"
	"time"
)

// RepoFacts is the raw, offline-derivable observation set for a repository. It is
// deliberately separated from scoring (see score.go) so the git extraction can be
// tested over fixture repositories and the scoring math can be tested without a
// repository at all.
type RepoFacts struct {
	// HeadSHA is the commit HEAD resolves to in the local clone.
	HeadSHA string `json:"headSha,omitempty"`

	// CommitsAnalyzed is the number of recent commits examined (bounded by the
	// configured window).
	CommitsAnalyzed int `json:"commitsAnalyzed"`
	// SignedCommits is how many of the analyzed commits carry a cryptographic
	// signature (git's %G? flag reported anything other than "no signature" /
	// "cannot check"). Offline we count signature presence, not key validity.
	SignedCommits int `json:"signedCommits"`
	// GoodSignedCommits is how many analyzed commits had a *valid* signature (%G?
	// == G), which requires the signing key to be present locally.
	GoodSignedCommits int `json:"goodSignedCommits"`

	// Tags is the total tag count; SignedTags counts annotated tags carrying a
	// signature.
	Tags       int `json:"tags"`
	SignedTags int `json:"signedTags"`

	// DistinctAuthors is the number of distinct commit-author identities in the
	// analyzed window.
	DistinctAuthors int `json:"distinctAuthors"`
	// BusFactor is the smallest number of authors that together account for more
	// than half of the analyzed commits — a coarse proxy for how concentrated
	// maintenance is in a few people.
	BusFactor int `json:"busFactor"`
	// TopAuthorShare is the fraction of analyzed commits by the single most
	// prolific author, in [0,1].
	TopAuthorShare float64 `json:"topAuthorShare"`

	// LastCommitUnix is the committer timestamp of the most recent commit.
	LastCommitUnix int64 `json:"lastCommitUnix,omitempty"`
	// LastCommitAgeDays is how many days ago the most recent commit landed,
	// relative to the analysis clock.
	LastCommitAgeDays int `json:"lastCommitAgeDays"`
	// ActiveDays is the number of distinct calendar days (UTC) on which a commit
	// landed within the analyzed window.
	ActiveDays int `json:"activeDays"`

	// HasCI / CISystems record continuous-integration configuration.
	HasCI     bool     `json:"hasCi"`
	CISystems []string `json:"ciSystems,omitempty"`
	// HasSecurityPolicy records a SECURITY.md (or equivalent) security policy.
	HasSecurityPolicy bool `json:"hasSecurityPolicy"`
	// HasCodeowners records a CODEOWNERS file (an offline branch-protection hint).
	HasCodeowners bool `json:"hasCodeowners"`
	// HasDepAutomation / DepTools record dependency-update automation.
	HasDepAutomation bool     `json:"hasDepAutomation"`
	DepTools         []string `json:"depTools,omitempty"`

	// BranchProtected and BranchProtectionKnown carry an authoritative
	// branch-protection setting supplied by an online Enricher; when
	// BranchProtectionKnown is false the scorer falls back to the CODEOWNERS hint.
	BranchProtected       bool `json:"branchProtected,omitempty"`
	BranchProtectionKnown bool `json:"branchProtectionKnown,omitempty"`

	// FilesError / HistoryError record a non-fatal extraction failure for one
	// dimension so the report can degrade rather than fail outright.
	FilesError   string `json:"filesError,omitempty"`
	HistoryError string `json:"historyError,omitempty"`
}

// gatherFacts derives the offline RepoFacts from a local git directory. It is
// best-effort: a failure in one dimension (file tree vs. history) is recorded on
// the facts and does not abort the others. An empty repository (no HEAD) returns
// an error so the caller marks the report unresolved.
func gatherFacts(ctx context.Context, g *gitRunner, now time.Time, window int) (RepoFacts, error) {
	var f RepoFacts
	head, err := g.headRef(ctx)
	if err != nil {
		return f, err
	}
	f.HeadSHA = head

	if err := gatherHistory(ctx, g, now, window, &f); err != nil {
		f.HistoryError = err.Error()
	}
	if err := gatherTags(ctx, g, &f); err != nil {
		// Tag signing is a minor signal; fold a failure into the history note.
		if f.HistoryError == "" {
			f.HistoryError = err.Error()
		}
	}
	if err := gatherFiles(ctx, g, &f); err != nil {
		f.FilesError = err.Error()
	}
	return f, nil
}

// gatherHistory walks the recent commit history once, extracting the signed-commit
// counts and authorship/recency statistics. It issues a single `git log` so the
// cost is one process regardless of the window size.
func gatherHistory(ctx context.Context, g *gitRunner, now time.Time, window int, f *RepoFacts) error {
	if window <= 0 {
		window = defaultWindow
	}
	// Format: signature-flag, committer-unix, author-email — tab-separated, one
	// line per commit. %x09 is a literal tab so emails/names cannot break parsing.
	out, err := g.lines(ctx, "log", "--no-show-signature",
		"--max-count="+strconv.Itoa(window), "--pretty=format:%G?%x09%ct%x09%aE", "HEAD")
	if err != nil {
		return err
	}

	authorCounts := map[string]int{}
	activeDays := map[int64]struct{}{}
	var newest int64
	for _, line := range out {
		parts := strings.SplitN(line, "\t", 3)
		if len(parts) < 3 {
			continue
		}
		f.CommitsAnalyzed++

		switch flag := strings.TrimSpace(parts[0]); flag {
		case "G":
			f.SignedCommits++
			f.GoodSignedCommits++
		case "U", "X", "Y", "R", "B":
			// A signature is present but its validity could not be confirmed offline
			// (unknown key, expired, etc.). It still demonstrates a signing practice,
			// so it counts toward signature presence but not toward valid signatures.
			f.SignedCommits++
		default:
			// "N" (no signature) or "E" (cannot check) — not signed.
		}

		if ts, err := strconv.ParseInt(strings.TrimSpace(parts[1]), 10, 64); err == nil {
			if ts > newest {
				newest = ts
			}
			activeDays[ts/86400] = struct{}{}
		}

		email := strings.ToLower(strings.TrimSpace(parts[2]))
		if email != "" {
			authorCounts[email]++
		}
	}

	f.DistinctAuthors = len(authorCounts)
	f.ActiveDays = len(activeDays)
	f.BusFactor = busFactor(authorCounts, f.CommitsAnalyzed)
	f.TopAuthorShare = topAuthorShare(authorCounts, f.CommitsAnalyzed)

	if newest > 0 {
		f.LastCommitUnix = newest
		age := now.Sub(time.Unix(newest, 0))
		if age < 0 {
			age = 0
		}
		f.LastCommitAgeDays = int(age / (24 * time.Hour))
	}
	return nil
}

// gatherTags counts tags and, among annotated tags, how many carry a signature.
func gatherTags(ctx context.Context, g *gitRunner, f *RepoFacts) error {
	// objecttype distinguishes annotated tags (tag) from lightweight ones (commit);
	// contents:signature is non-empty only for signed annotated tags.
	out, err := g.lines(ctx, "for-each-ref",
		"--format=%(objecttype)%x09%(contents:signature)", "refs/tags")
	if err != nil {
		return err
	}
	for _, line := range out {
		f.Tags++
		parts := strings.SplitN(line, "\t", 2)
		if len(parts) == 2 && parts[0] == "tag" && strings.Contains(parts[1], "-----BEGIN") {
			f.SignedTags++
		}
	}
	return nil
}

// gatherFiles lists the tree of the default branch once and classifies the paths
// of interest (CI, security policy, CODEOWNERS, dependency automation). One
// `ls-tree` keeps the cost bounded regardless of repository size; the output is a
// flat list of paths, which is all the classification needs.
func gatherFiles(ctx context.Context, g *gitRunner, f *RepoFacts) error {
	out, err := g.lines(ctx, "ls-tree", "-r", "--name-only", "--full-tree", "HEAD")
	if err != nil {
		return err
	}
	ci := map[string]struct{}{}
	dep := map[string]struct{}{}
	for _, raw := range out {
		path := strings.ToLower(strings.TrimSpace(raw))
		if path == "" {
			continue
		}
		base := path
		if i := strings.LastIndex(path, "/"); i >= 0 {
			base = path[i+1:]
		}

		if sys := ciSystemFor(path, base); sys != "" {
			ci[sys] = struct{}{}
		}
		if tool := depToolFor(path, base); tool != "" {
			dep[tool] = struct{}{}
		}
		if isSecurityPolicy(path, base) {
			f.HasSecurityPolicy = true
		}
		if isCodeowners(path, base) {
			f.HasCodeowners = true
		}
	}
	f.HasCI = len(ci) > 0
	f.CISystems = sortedKeys(ci)
	f.HasDepAutomation = len(dep) > 0
	f.DepTools = sortedKeys(dep)
	return nil
}

// ciSystemFor returns a CI system name for a known CI configuration path, or "".
func ciSystemFor(path, base string) string {
	switch {
	case strings.HasPrefix(path, ".github/workflows/") && (strings.HasSuffix(base, ".yml") || strings.HasSuffix(base, ".yaml")):
		return "github-actions"
	case base == ".gitlab-ci.yml":
		return "gitlab-ci"
	case path == ".circleci/config.yml":
		return "circleci"
	case base == "jenkinsfile":
		return "jenkins"
	case base == "azure-pipelines.yml" || base == "azure-pipelines.yaml":
		return "azure-pipelines"
	case base == ".travis.yml":
		return "travis"
	case base == ".drone.yml":
		return "drone"
	case base == "appveyor.yml" || base == ".appveyor.yml":
		return "appveyor"
	case strings.HasPrefix(path, ".buildkite/"):
		return "buildkite"
	case base == "cloudbuild.yaml" || base == "cloudbuild.yml":
		return "cloud-build"
	default:
		return ""
	}
}

// depToolFor returns a dependency-update-automation tool name for a known config
// path, or "".
func depToolFor(path, base string) string {
	switch {
	case base == "dependabot.yml" || base == "dependabot.yaml":
		return "dependabot"
	case base == "renovate.json" || base == "renovate.json5" || base == ".renovaterc" || base == ".renovaterc.json" || base == ".renovaterc.json5":
		return "renovate"
	case strings.HasSuffix(path, "/renovate.json"):
		return "renovate"
	default:
		return ""
	}
}

// isSecurityPolicy reports whether a path is a recognized security policy. GitHub
// recognizes SECURITY.md in the repo root, docs/, or .github/.
func isSecurityPolicy(path, base string) bool {
	if base != "security.md" && base != "security.markdown" && base != "security.rst" && base != "security.txt" && base != "security.adoc" {
		return false
	}
	dir := ""
	if i := strings.LastIndex(path, "/"); i >= 0 {
		dir = path[:i]
	}
	return dir == "" || dir == "docs" || dir == ".github" || dir == ".github/profile"
}

// isCodeowners reports whether a path is a CODEOWNERS file (root, docs/, or
// .github/), the same locations GitHub/GitLab recognize.
func isCodeowners(path, base string) bool {
	if base != "codeowners" {
		return false
	}
	dir := ""
	if i := strings.LastIndex(path, "/"); i >= 0 {
		dir = path[:i]
	}
	return dir == "" || dir == "docs" || dir == ".github" || dir == ".gitlab"
}

// busFactor returns the smallest number of authors whose cumulative commits
// exceed half of total. It is 0 when there is no history.
func busFactor(counts map[string]int, total int) int {
	if total <= 0 || len(counts) == 0 {
		return 0
	}
	vals := make([]int, 0, len(counts))
	for _, n := range counts {
		vals = append(vals, n)
	}
	sort.Sort(sort.Reverse(sort.IntSlice(vals)))
	half := float64(total) / 2
	cum, bus := 0, 0
	for _, n := range vals {
		cum += n
		bus++
		if float64(cum) > half {
			break
		}
	}
	return bus
}

// topAuthorShare returns the fraction of commits by the most prolific author.
func topAuthorShare(counts map[string]int, total int) float64 {
	if total <= 0 {
		return 0
	}
	max := 0
	for _, n := range counts {
		if n > max {
			max = n
		}
	}
	return float64(max) / float64(total)
}

func sortedKeys(m map[string]struct{}) []string {
	if len(m) == 0 {
		return nil
	}
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
