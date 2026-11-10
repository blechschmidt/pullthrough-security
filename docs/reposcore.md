# Source-repository health (OpenSSF Scorecard-style) signals

The repository-health provider (`internal/reposcore`) derives lightweight,
[OpenSSF Scorecard](https://github.com/ossf/scorecard)-style health signals for
the **source repository a package was built from** and folds them into the
admission pipeline as a per-repo health/risk score. It answers a question the
other gates do not: *"even if this exact artifact is clean, is the project behind
it maintained in a way that makes future compromise more or less likely?"* A
single-maintainer repo with no branch protection, unsigned commits, no CI, and no
activity in two years is a materially riskier dependency than a well-governed one,
independent of whether today's release is malicious.

It is a **signal provider, not a hard gate**: it never blocks a pull on its own.
Its score feeds the [policy-as-code engine](../README.md) and the
[unified risk-scoring engine](observability.md) (with per-tenant weights), which
make the actual admission decisions.

## Where it runs

The provider runs on the pull path **after** the provenance/policy gate (which
establishes the artifact → source-commit/repository association) and **before**
the policy-as-code and risk-scoring gates, so its signal is in the per-request
accumulator those gates evaluate. It only runs for artifacts whose provenance
association yielded a repository URL; without one there is nothing to score.

```
… → provenance/policy → (content gates) → repo-health → policy-engine → risk-score → serve
```

## Offline / air-gap friendly by design

Every signal is derived from a **local git clone** using the `git` binary alone —
no GitHub/GitLab API calls. The default locator keeps blob-filtered, shallow bare
clones under a cache directory:

- With `repoScore.allowFetch: false` (the default, and the air-gapped posture) the
  provider scores **only repositories already present on disk**. A repository it
  has never seen yields an *unresolved* report that contributes **nothing** to
  risk — a missing source repo is the provenance signal's concern, not this one's.
- With `repoScore.allowFetch: true` it clones not-yet-seen repositories on demand
  (`git clone --bare --filter=blob:none --depth=N`), which fetches commit and tree
  metadata — everything the signals need — without downloading file contents, so
  the clone stays small and fast.

An optional **online enrichment hook** (`reposcore.Enricher`) can supply the few
signals that genuinely require a forge API (authoritative branch-protection
settings) without changing the offline path. With no enricher configured, the
provider links and calls no online code at all.

Derived facts are cached per repository (tenant-independent) and re-scored per
tenant on each request, so per-tenant weights are honored without re-cloning.

## The signals and their heuristics

All seven sub-signals are scored to a health value in `[0,1]` (1 = healthiest),
combined by a weighted average into a `0..100` health score, and inverted into a
`0..100` risk score (`risk = 100 - health`) for the risk engine. A coarse letter
grade summarizes the score (A ≥ 85, B ≥ 70, C ≥ 55, D ≥ 40, F < 40).

| Signal | How it is derived (offline) | Health rationale |
|--------|-----------------------------|------------------|
| **branch-protection** | Presence of a `CODEOWNERS` file (root, `docs/`, `.github/`, `.gitlab/`) as a **hint**; an online enricher can replace it with the true setting | Protected default branches resist tampered/force-pushed history. Offline we can only *hint* at it. |
| **signed-commits** | `git log --pretty=%G?` over the recent window; a small bonus for signed annotated tags | Signed history is tamper-evident and ties commits to identities. |
| **ci** | Presence of a known CI config (`.github/workflows/*`, `.gitlab-ci.yml`, `.circleci/config.yml`, `Jenkinsfile`, Azure Pipelines, Travis, Drone, AppVeyor, Buildkite, Cloud Build) | CI implies automated testing/linting and reproducible builds. |
| **security-policy** | Presence of `SECURITY.md` (root, `docs/`, or `.github/`) | A disclosure policy signals a project that expects and handles vulnerability reports. |
| **maintainers** | Distinct commit-author count and **bus factor** (smallest set of authors > 50% of commits) over the recent window | A broader, less concentrated maintainer base is harder to compromise via a single account. |
| **activity** | Age of the most recent commit, blended with the number of distinct active days in the window | Actively-maintained projects patch faster and notice tampering sooner. |
| **dep-automation** | Presence of Dependabot (`.github/dependabot.yml`) or Renovate (`renovate.json`, `.renovaterc*`) config | Automated dependency updates reduce the window of exposure to upstream CVEs. |

### Scoring details

- **signed-commits**: a *valid* signature (`%G? == G`, key present locally) counts
  fully; a *present-but-unverifiable* signature (`U`/`X`/`Y`/`R`/`B` — signed, but
  the key cannot be checked offline) counts at 60%, so a project that signs but
  whose keys are not in the local keyring still scores well.
- **maintainers**: bus factor 1 → 0.2, 2 → 0.55, 3 → 0.8, ≥4 → 1.0. A single author
  responsible for >90% of commits caps the score at 0.2 even when several authors
  appear.
- **activity**: recency ≤ 30 days → 1.0, decaying linearly to 0 at 730 days (2
  years); blended 70/30 with active-day cadence (saturating at 20 distinct days).
- **branch-protection**: an authoritative enricher value is trusted directly; a
  `CODEOWNERS` hint scores 0.5 and is flagged `hint: true` in the breakdown.

The recent history window (default 200 commits) bounds the cost of the `git log`
on large repositories, keeping the signal "recent" and the analysis cheap.

## Explainability

Like the risk engine, every report carries an ordered, weighted breakdown so
"why is this repo's health 48/100?" is always answerable. Each `SubSignal` carries
its `health` (0..1), its `weight`, the `points` it contributed to the composite,
whether it is a heuristic `hint`, and a human-readable `detail`. The weakest
weighted signals are listed in `weak` for an at-a-glance view, and a one-line
`summary` names them.

The per-repo health/risk also appears:

- as the **repohealth** contribution in the **Risk** admin tab's risk-assessment
  breakdown (with per-tenant weights);
- on the **commit node** in the supply-chain graph (`repoHealth` / `repoHealthGrade`);
- in the **Repo Health** admin tab (per-grade distribution, average health, recent
  per-repo reports);
- on served responses as `X-Repo-Health` / `X-Repo-Health-Grade` headers.

## Configuration

```yaml
repoScore:
  enabled: true            # off by default (needs a writable cache dir)
  cacheDir: ""             # default: <cache.dir>/reposcore
  allowFetch: false        # true = clone not-yet-mirrored repos on demand
  window: 200              # recent commits examined
  cloneDepth: 256          # shallow-clone depth (negative = full history)
  cacheTtl: 6h             # how long a derived report is reused
  fetchTimeout: 60s        # bound on a single on-demand clone
  analyzeTimeout: 20s      # bound on a single repository analysis
  gitBinary: git
  weights:                 # relative; an all-zero block keeps the defaults
    branchProtection: 0.18
    signedCommits:    0.18
    ci:               0.15
    maintainers:      0.15
    securityPolicy:   0.12
    activity:         0.12
    depAutomation:    0.10
  tenants:
    team-a:
      weights:             # per-tenant override of the weighting model
        signedCommits: 0.40
```

To let the risk engine weigh repository health more or less heavily, set
`riskScore.weights.repoHealth` (default `0.08`).

## Metrics

| Metric | Type | Meaning |
|--------|------|---------|
| `pullthrough_reposcore_evaluated_total` | counter | Repository-health evaluations performed |
| `pullthrough_reposcore_resolved_total` | counter | Evaluations that resolved a local clone |
| `pullthrough_reposcore_unresolved_total` | counter | Evaluations with no local clone available |
| `pullthrough_reposcore_cache_hits_total` | counter | Evaluations served from the facts cache |
| `pullthrough_reposcore_online_total` | counter | Evaluations that used online enrichment |
| `pullthrough_reposcore_errors_total` | counter | Evaluations that recorded an extraction error |
| `pullthrough_reposcore_cache_size` | gauge | Repositories with a cached facts extraction |
| `pullthrough_reposcore_avg_health` | gauge | Average resolved-repo health (0..100) |
| `pullthrough_reposcore_repos_by_grade_total{grade}` | gauge | Resolved-repo count per health grade |

## Limitations

These heuristics are intentionally **lightweight, offline approximations** of the
full OpenSSF Scorecard and must be read as such:

- **Branch protection is a hint, not a fact.** Offline, the proxy cannot see a
  forge's branch-protection settings; it infers from `CODEOWNERS` presence, which
  is neither necessary nor sufficient for protection. Use the online enrichment
  hook for an authoritative value.
- **Signature validity depends on local keys.** Offline, a present signature whose
  key is absent counts only as partial credit; the provider cannot confirm the
  signer's identity or trust without the keyring. It measures *signing practice*,
  not *trust*.
- **Authorship ≠ identity.** Bus factor and maintainer counts are derived from
  commit-author emails over a bounded recent window. They can be inflated by
  shared/bot accounts or deflated by rebases and squash-merges, and only reflect
  the analyzed window, not the project's full history.
- **File presence ≠ effectiveness.** A `SECURITY.md`, a CI config, or a
  `dependabot.yml` proves the file exists, not that the policy is followed, the CI
  actually runs meaningful checks, or the automation is enabled. They are positive
  but shallow signals.
- **Shallow/partial clones bound visibility.** With `cloneDepth` set, signals are
  computed over a truncated history; very large or very old projects may look less
  active than they are.
- **Repository association quality caps everything.** A health score is only as
  trustworthy as the provenance association that produced the repository URL; a
  heuristic (unattested) association can point at the wrong repository.

Because of these limits the provider never blocks on its own — it nudges the
composite risk score — and operators should weight it accordingly relative to the
authoritative gates (vulnerabilities, signatures, malware feeds).
