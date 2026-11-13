# Repositories: tag tracking and release pinning

The repository registry (Task 180) keeps your releases reproducible from the
proxy's cache. You register a repository. The proxy then follows its tags. When
a tag appears or moves, the proxy reads the lock files at the tagged commit,
fetches every dependency they pin through its own admission gates, and
**pins** those cache objects. Retention, eviction and garbage collection then
never delete them, and a pinned object whose bytes go bad is fetched again.
Moving or deleting the tag later changes nothing about the old release: its
commit keeps its manifest and its pins, and the API calls it *historical*.

Every dependency those lock files pin is also put before the
[LLM package-content scan](llm-package-scan.md): each release once it is
pinned, the default branch's head when it moves and on a schedule, and any
revision on request (Task 181, see [Dependency scans](#dependency-scans)).

It builds on three earlier pieces:

* the incremental commit scanner's mirror, poll and webhook machinery
  ([commit-watch.md](commit-watch.md)),
* lock-file discovery ([lockfiles.md](lockfiles.md)),
* the gated serve pipeline every client request goes through.

## What happens when a tag appears or moves

1. **Tracking.** Each repository has a bare mirror (`repositories.mirrorDir`).
   The mirror is refreshed by a poll every `repositories.pollInterval`, by a
   push webhook at `repositories.webhookPath`, or on request
   (`ptctl repos sync`). Polls run on the HA leader only. The webhook is served
   only when `repositories.webhookSecret` is set, and a delivery is verified
   with it (GitHub's `X-Hub-Signature-256`) before anything in it is read:
   otherwise anyone could have the proxy fetch from the Git host. Tag pushes
   trigger a sync. So do pushes to the default branch when
   [dependency scans](#dependency-scans) are on (its new head is scanned);
   other branch pushes are acknowledged and ignored. Syncs of
   a repository are coalesced: deliveries that arrive while one runs make it
   run once more, not once each. A refresh that fails changes nothing. In
   particular, a mirror that cannot be fetched is never read as "every tag was
   deleted". When a repository's `url` changes, its mirror fetches from the
   new one.
2. **History.** Every tag-to-commit association is recorded in an append-only
   history: tag, commit, first seen, last seen, superseded by. A new tag adds
   a record. A tag that is force-moved or deleted also adds a record, which
   supersedes the previous one; records are never rewritten. Each record is
   written with an exclusive create (`link(2)`), so an existing record cannot
   be replaced. Each record also carries the SHA-256 hash of its predecessor,
   so an altered or removed record is detected (`ptctl repos verify`). A chain
   whose newest records were removed, or rewritten and re-hashed, still links
   up on its own; the head the tracker last saw (its state object
   `live/<repo>`) and the head held in memory tell. A repository whose history
   does not verify is not appended to. `pullthrough restore` drops the
   trackers' state when it restores the histories: it is rebuilt from them,
   and a history restored from an older snapshot would otherwise read as
   truncated. Every created,
   moved and deleted tag is written to the tamper-evident audit log
   (`release_tag`). A moved or deleted tag also raises a notification
   (`release_tag`): a release tag that moves after publication is the classic
   sign of a tampered release. The mirror keeps every tagged commit reachable
   under `refs/pullthrough/keep/`, so an old release can still be read after
   its tag has gone.
3. **Lock-file discovery.** The lock files at the commit are read from the
   mirror's objects. The repository's `lockfiles` globs select them; by
   default every lock file outside vendored code and test fixtures is read.
   Both halves of a pair (`go.mod` and `go.sum`) must match the globs.
4. **Fetching.** Each distinct dependency is fetched through the gated serve
   pipeline, exactly as a client request would be:
   * every admission gate runs (name guard, malware feed, firewall, maturity,
     policy, signatures, vulnerabilities, licenses, install hooks, content and
     LLM scans, …). With [dependency scans](#dependency-scans) on, the LLM
     scan's refusal is left to the release's scan: the bytes are pinned, kept
     for forensics, and the release is marked;
   * digests are verified where the backend checks them;
   * the request is recorded in the download log.

   The requester is the system principal `system:release-pinner` of the
   repository's tenant. With `auth.cacheNamespacing` on, each tenant's pins
   therefore live in that tenant's own cache namespace, and the tenant's own
   policies apply. With `auth.enabled` the principal is authorized like a
   client: it holds the roles `repositories.roles` names (or the repository's
   own `roles`), and a dependency from an upstream none of them grants is
   refused (gate `access-control`, audited as a denial). The lock files name
   the registries, so without that check a commit could have the proxy fetch
   from any upstream it fronts. Rate limits, quotas and behavioural anomaly
   detection do not apply to these requests: the proxy is making them to
   itself, and a release's burst of dependencies would read as one identity
   fanning out. In the download log they show as client `system`, via
   `system` (`ptctl downloads --via system`).
5. **Checking.** The bytes each object was served with are hashed and compared
   with the digests the lock file records: sha1/256/384/512 and md5, the Go
   module hash `h1:` of a module zip or go.mod, and a Terraform provider's
   `zh:` hashes. An object whose bytes do not match is **not pinned**. It is
   reported as a mismatch, audited and alerted on. Some lock files record no
   usable digest:
   * none at all (a `gradle.lockfile`): the object is pinned as served (trust
     on first use) and marked unverified;
   * a digest of something else (NuGet's signature-less `contentHash`, Yarn
     Berry's cache zip): the backend's own verification stands, and the
     object is marked unchecked.
6. **The manifest.** A release manifest keyed by (repository, commit) stores:
   * the lock files read;
   * every dependency with its lock-file digests and status;
   * each cache object fetched: request path, cache key, the cache's content
     digest, the per-gate verdicts, and the result of the digest check.
7. **Pinning.** The objects of the manifest are pinned. An object is held from
   the moment every gate admitted it, before a byte is served, so it cannot be
   evicted between the fetch and the stored manifest. After the manifest is
   stored, every pinned object is checked to still be in the cache.

A dependency that is refused by a gate, does not match its lock file, cannot
be fetched, or cannot be fetched through the proxy at all is recorded with the
reason. The release is then **not fully pinned** (status `partial` or
`failed`). What failed is retried after `pinning.retryInterval`, doubling with
each attempt up to `pinning.maxAttempts`; dependencies already pinned are not
fetched again. `ptctl repos pin <repo> <commit>` retries at once and resets the
attempt budget.

At a repository's first sync every existing tag is recorded. Only the
`backfillTags` most recently committed releases are pinned (default 10; `-1`
all, `0` none). Any other tagged commit can be pinned with `ptctl repos pin`.

## Pinning rules

| Path | What a pin means |
|------|------------------|
| LRU eviction (`cache.maxSizeBytes`) | never evicts a pinned object. A cache whose pinned objects alone exceed the bound stays over it. |
| TTL expiry (`cache.ttl`) | a pinned object never expires. |
| Garbage collection (`cacheGC`) | the `release-pin` retention source claims every pinned key and re-reads the manifests before each pass. `allowEvictPinned` does not apply to it. |
| Quarantine by a gate, admin purge | `Delete` refuses a pinned key (`cache: object is pinned by a release manifest`). Serving stays refused anyway: the gates run on every request, cache hits included. |
| Negative cache | a pinned key is never answered from the negative cache, so a remembered 404 cannot hide a restored object. |
| Byte and request quotas | count requests; they never delete cache objects. Pinning requests are not counted against a tenant's rate limits. |
| Tiered storage | may demote a pinned object to the cold tier; never drops it (every move is copy-then-delete). |
| Integrity self-heal | corrupt bytes are removed, and the pinned object is fetched again at once. If the fresh copy is not the pinned digest, or cannot be fetched, the object is lost: the manifests that pin it record it as failed (`lost to an integrity failure: …`), those releases stop pinning its key — whatever the cache holds under it is an ordinary entry again, not one kept forever — and are no longer fully pinned. They are retried after `pinning.retryInterval`. A `PullthroughPinnedObjectLost` alert fires and a `release_pin` notification goes out. |
| Backup / restore | registrations, histories, manifests, dependency scan reports and the maintenance updater's state and run reports are backup sources (`repos-registry`, `repos-history`, `repos-manifests`, `repos-scans`, `repos-updates`, `repos-update-runs`, `repos-update-dry-runs`). The mirrors, the trackers' last-seen times and the default branches' scan state are rebuilt. |
| Dependency scan | a malicious verdict never deletes a pinned object. The release keeps the bytes, for forensics, and the gate refuses them to every client while the verdict stands (see [Dependency scans](#dependency-scans)). |
| Air-gap export / import | bundles carry the manifests and the pinned keys they hold. An import stores the manifests only from a bundle whose manifest digest was verified (`-manifest-digest`), and never overwrites an object the importing instance has pinned. |

Pins are permanent: removing a repository (`ptctl repos remove`) stops its
tracking but keeps its history, manifests and pins.

## Dependency scans

Task 181 scans every dependency a repository's lock files pin with the
sandboxed [LLM package-content scan gate](llm-package-scan.md). The scans
need that gate (`llmPackageScan.enabled`); they are on by default when it is
(`repositories.scan.enabled`).

### When a scan runs

| Trigger | What is scanned |
|---------|-----------------|
| A release is pinned (a tag appears or moves) | the release manifest: each dependency through its **pinned** objects, read from the cache. A retry of the pin, which pins more, is scanned again. |
| A push to the default branch (webhook), a poll | the default branch's head, when it moved. The branch is the remote's default branch (its `HEAD`), or the repository's `branch`. |
| The schedule (`repositories.scan.interval`, default 24h) | the default branch's head again, even when it did not move. |
| `ptctl repos scan <repo> [--rev REV]`, `POST /api/repos/scan?name=&rev=` | the revision named: a tag, a branch, a commit or a prefix of one. Without a revision, the default branch's head, fetched first. |
| A new model or prompt version | every release again: the verdict cache keys on both, so a new model reads every package anew. |

A commit that is a pinned release is always scanned through its pins,
whatever asked for the scan. If it is also the default branch's head, the
report says so (`branch`). The default branch's head, and any other revision,
is scanned by fetching each dependency through the gated serve pipeline, as
the scanner (`system:repository-scanner` of the repository's tenant, with its
roles), without pinning anything.

### What a scan does with each dependency

* **The verdict cache is reused.** A dependency's bytes that already have a
  verdict under the current model and prompt version (from a client's pull,
  the pin, another repository) cost no model call. The report counts the
  verdicts the cache answered (`cached`) and the dependencies that needed a
  model call (`scanned`).
* **Cost budget and concurrency are the gate's.** Scans run under
  `llmPackageScan.budget`, `maxConcurrent`, the queue and the per-tenant
  share, as the repository's tenant. `repositories.scan.workers` (default 1)
  revisions and `concurrency` (default 2) dependencies of each are scanned at a
  time, so a large repository does not take the gate's slots from clients.
* **Unscanned is never benign.** A dependency the scan cannot cover is
  reported `unscanned`, with a reason code:

  | Code | Why |
  |------|-----|
  | `unsupported` | it cannot be fetched through the proxy (a Git dependency, an unsupported registry; see [which dependencies can be pinned](#which-dependencies-can-be-pinned)) |
  | `fetch-refused` | an admission gate refused it (the gate and its reason are in the report) |
  | `fetch-failed` | it could not be fetched (retried) |
  | `not-pinned` | a release dependency the pinner has not pinned yet; the release is scanned again once it is |
  | `no-digest` | the proxy serves it without caching it: there are no recorded bytes to bind a verdict to |
  | `lockfile-mismatch` | the bytes served are not the ones the lock file pins |
  | `out-of-scope` | the gate does not scan its ecosystem or upstream (`llmPackageScan.include`, `exclude`, `excludeUpstreams`) |
  | `no-package-content` | none of its objects is package content (a Go module of which only `go.mod` is fetched) |
  | `scan-failed` | the object could not be put before the gate (retried) |
  | the gate's own codes | `oversized`, `unsupported-format`, `provider-refusal`, `malformed-output`, … ; `budget-exhausted`, `provider-error`, `timeout`, `scanner-busy`, `provider-unavailable` are retried |

  A dependency is benign only when every object of it the gate examines is,
  and a clean reading counts only for bytes that were admitted, recorded and
  matched against the lock file. A scan with an unscanned dependency is
  `incomplete`, never `clean` — and so is one with a lock file that could not
  be read (a format the parser refuses, a file over the size limit): what such
  a file pins was never seen. What a passing cause left unscanned is scanned
  again after `repositories.scan.retryInterval` (doubling, up to
  `maxAttempts`); the retry keeps every other result.

### The action ladder

The gate's configured action applies, as on a pull (see
[llm-package-scan.md](llm-package-scan.md)):

| Verdict | `annotate` | `block` | `quarantine` |
|---------|------------|---------|--------------|
| malicious | finding + notification + manifest marked | finding + notification + manifest marked; clients refused | same as `block` |
| suspicious | finding (+ notification, medium) | finding (+ notification, medium) | finding + notification (high) + manifest flag; clients refused |
| unscanned | finding (note); `failMode` decides what clients get | | |

A malicious verdict on a release's dependency marks its manifest
**contains malicious dependency** (`scan.containsMaliciousDependency`, with the
flagged coordinates in `scan.flagged`). The release's pins are untouched: the
bytes are **kept for forensics**, never deleted. Since a release is pinned for
reproducibility, the release pinner does not refuse a dependency the LLM gate
refuses when release scans are on: it pins the bytes, and the scan marks the
release and reports the dependency. The deferred verdict is not handed on to
the gates after it (a policy rule on `input.llmPackageScan`, the risk score), so
they do not refuse the same verdict in its place. A client's pull of those bytes
is judged, and refused, as always. A refusal of pinned bytes keeps them; its
audit record says `keptPinned`. When another gate refuses bytes the LLM gate
had judged (for reasons of its own), the release does not pin them, but the
manifest keeps the LLM gate's reading of them (`objects[].llm`) and the scan
reports the verdict.

A break-glass grant that releases the artifact (an approved review of the
gate's refusal) releases the dependency — when grants release every flagged
object of it (a released wheel does not release the sdist next to it). Its
finding is reported suppressed (mechanism `break-glass`, in the suppression
trail), and it neither marks the release nor raises a notification; the report
still shows the verdict.

A flagged dependency is announced once — a `repository_scan` notification and
a `repository_scan` audit record — not at every rescan: a malicious dependency
that stays in the default branch is announced once for the branch, and once for
each release that pins it.

### The report

Each scan stores a report per commit (`scans/<repo>/<commit>` in the state
directory). For each dependency it records:

* the verdict (`malicious`, `suspicious`, `benign`, `unscanned`) and the
  proxy's sentence for it, or the unscanned reason;
* the lock-file lines that pin it (`package-lock.json:42`);
* where the verdict came from: the artifact digest, the provider, the model,
  the prompt version, when it was reached, whether the verdict cache answered;
* the evidence: the reasons the model stated and the places it cited, each
  marked verified when the proxy found the quoted text there. These are model
  output about untrusted content, shown as text only;
* every object of the dependency and the gate's reading of each.

The report is exposed through:

| Surface | What |
|---------|------|
| Admin API | `GET /api/repos/scan?name=&rev=[&verdict=malicious,suspicious,unscanned]` (the report; default the default branch's head), `GET /api/repos/scans?name=` (the head, every release, what is queued), `GET /api/repos/scan/sarif?name=&rev=` (`&all=1`: the head and every release) |
| `ptctl` | `ptctl repos scan <repo> [--rev REV] [--wait]`, `ptctl repos report <repo> [--rev REV] [--verdict flagged] [--sarif FILE]` |
| Admin UI | the **Repositories** tab: each repository's head scan and releases, the per-dependency table, the evidence, *Scan now*, SARIF download |
| Dossier | *Dependency scans in repositories*: every release and default-branch head whose lock files pin the coordinate, with the verdict there |
| SARIF | one result per lock-file location of each dependency that is not benign: `llmpkgscan/malicious-dependency` (error), `llmpkgscan/suspicious-dependency` (warning), `llmpkgscan/unscanned-dependency` (note), at the lock file's path and line; and a note at each lock file that could not be read. The message is the proxy's. The properties carry the verdict, model, time, digest and `verifiedEvidence` (the places the proxy confirmed); the model's reasons, its excerpts and any place only the model named stay on the admin surface. At most 20 locations per dependency and 10,000 results per document (`omittedResults` says how many more the report holds) |
| Findings layer | each scan's findings document (`repo:<name>@<commit>`, and `repo:<name>@<branch>` for the head) goes through de-duplication, the suppression trail, the findings store (`/api/findings/sarif?package=repo:<name>`) and the SIEM forwarder |
| Query API, MCP | query fields `repoScanVerdict`, `repoScanRepos`, `repoScanFlagged`, `repoScanUnscanned`, `repoScanModel`, `repoScanAt`; the MCP tool `get_repository_scan` (it leaves out the model's reasons and the package's excerpts: an agent is not handed text an attacker wrote) |
| Metrics | `pullthrough_repo_scans_total{kind,status}`, `scan_duration_seconds`, `scan_dependencies_total{verdict}`, `scan_queue`, `malicious_dependencies{repo}` |

The default branch's state only moves forward: a scan of a head the branch
has left in the meantime does not become the "current head" report, and such a
scan is not retried. Reports of revisions that are neither releases nor the
current head are pruned beyond the 20 newest per repository; release reports
stay as long as the releases. A scan asked for while the same commit is being
scanned (a re-pin that pinned more) runs again once that scan ends, and a
release whose pins changed after its scan began is scanned again.

### High availability

Scan requests are recorded in the shared state directory (`scanreqs/`); only
the leader runs them, so a request made through any replica's API is picked up
by the leader within a minute. A scan asked for while its release is still
being pinned is kept and runs once the release is pinned. Reports written by
the leader are re-read by every replica.

## Maintenance updates

Task 182 keeps a **maintenance branch** in each registered repository — a
Dependabot-style branch that only ever proposes updates the proxy has vetted.
A run lists, for every dependency the default branch's lock files pin, the
newer versions its registry offers, keeps those the project's declared
constraint allows, vets them, writes the newest one that passes into the lock
files, and pushes the result on top of the default branch's head. It needs the
[LLM package-content scan](llm-package-scan.md) (`llmPackageScan.enabled`):
nothing is proposed without a benign verdict.

Runs are scheduled every `repositories.updates.interval` (default 24h) on the
HA leader, and run on request:

```sh
ptctl repos update widgets --dry-run   # compute and show; push nothing
ptctl repos update widgets             # push the maintenance branch
ptctl repos updates widgets            # the branch's state and the newest runs
```

### Selecting updates

1. **Listing.** For each dependency of a type whose versions can be listed —
   npm, PyPI, Cargo and Go registries — the version list is read from the
   registry's metadata **through the proxy** (the gated pipeline, as the system
   principal `system:repository-updater` of the repository's tenant, with its
   roles), from the same upstream the dependency is located through: an npm
   packument, a PyPI simple page, a Cargo sparse-index file, a Go module's
   `@v/list`. The updater never talks to a registry itself.
2. **Compatibility.** A candidate must be newer and allowed by every
   constraint declared on the dependency:

   | Ecosystem | Declared constraint |
   |-----------|---------------------|
   | npm | the ranges of `package.json` and of every package in the lock file that depends on it, each resolved to the install position it reaches (node-semver: caret, tilde, x-ranges, hyphen ranges, `\|\|`) |
   | Cargo | the requirements of the workspace's `Cargo.toml` files and of every crate in `Cargo.lock` that depends on it (from the dependents' index entries; Cargo's caret default) |
   | PyPI | the PEP 440 specifiers of the requirements file's pip-tools input (`requirements.in`), of `pyproject.toml`, and of every other pinned project's `Requires-Dist` |
   | Go | the module's major version: minimal version selection moves within one module path (`exclude` directives honoured) |

   The version engine (`internal/versions`) also evaluates Maven and NuGet
   ranges and RubyGems requirements, as those tools do; the versions of those
   ecosystems are not listed yet (see the table below). When nothing declares a
   constraint, a candidate
   must stay within the **same major version** (`repositories.updates.maxBump:
   minor`, the default) or be a **patch** release (`maxBump: patch`; a
   repository's `updates.maxBump` overrides). Pre-releases are proposed only for
   a dependency pinned to a pre-release, yanked versions never. When a requirement
   on the dependency cannot be read (a dependent's index entry or metadata is
   unavailable), no candidate is proposed: it could not be shown to satisfy it.
3. **Vetting.** Candidates are tried newest first, at most
   `repositories.updates.maxCandidates` (default 3) per dependency, until one
   passes:
   * the **ignore list** of the repository (`updates.ignore`: `npm/lodash`,
     `pip/django@>=5.0`, `cargo/serde@1.0.200`, `*/internal-*`);
   * the **dependency firewall** and the **maturity cooldown**, asked before
     anything is fetched;
   * **every admission gate**: each object of the candidate is fetched through
     the gated pipeline, exactly as a client's pull, and must be admitted and
     cached;
   * a **benign LLM package-scan verdict for the exact bytes** of every object
     the gate examines — the stored verdict when there is one, a scan made on
     demand otherwise. A malicious, suspicious or unscanned reading (pending,
     failed, out of the gate's scope, the budget spent) skips the candidate;
   * the bytes must be those the registry metadata states (npm's
     `dist.integrity` and `shasum`, Cargo's `cksum`, the hash a PyPI simple
     page lists for each file).

   Every candidate passed over is reported with its reason (`malicious`,
   `suspicious`, `unscanned`, `incompatible`, `constraint-unknown`, `ignored`,
   `firewall`, `cooldown`, `refused`, `digest`, `fetch-failed`, `limit`,
   `not-writable`, `resolution`, `verify-failed`), and so is the newest
   incompatible version of each dependency.

The updater runs on the proxy's own behalf, never on a client's: nothing it
does uses a client's network, credentials or address. Registry metadata and
package content reach it only through the proxy's gated pipeline (recorded in
the download log as client `system`), and a sandboxed package manager has no
network at all.

### Writing the lock files

The new version, its resolved URL and its integrity values come from the bytes
the proxy fetched, verified and cached — never from registry metadata. Each
rewritten lock file is parsed again and held to what was intended: exactly the
updated dependencies moved, to the intended versions and digests, and nothing
else changed. A rewrite that does not pass is not committed.

* **Natively**, when the new version declares the same dependencies as the
  pinned one (its packument entry, index entry, go.mod or Requires-Dist
  compares equal): only the targeted entries' version, resolved URL and
  digests change, byte for byte, and go.mod's `require` line with them.
* **Through the sandboxed package manager**, when the dependency graph has to
  be resolved again: `npm update --package-lock-only`, `cargo update
  --precise`, `go get`. The tool runs in a container of its official image
  (the client lab's and the ecosystem tests' images) with **no network**
  (`--network none`), a read-only root, every capability dropped, as an
  unprivileged user, given only the manifests and lock files below the lock
  file's directory (Cargo's `*.rs` targets as empty placeholders; never the
  repository's own `.npmrc`, `.cargo/config.toml` or toolchain pins, which
  would point the tool elsewhere or carry credentials). Its one way out is a unix
  socket to a **session of the proxy** that a short-lived token, minted for the
  run, binds to the **scanned-benign-only** policy: registry metadata is served
  through the admission gates (the updated package's metadata offers no version
  newer than the vetted one, and none the updater skipped), and package content
  only when every gate admits it and the LLM scan judged those exact bytes
  benign — an archive nobody judged is never served. Since lock-only
  resolvers do not download what they resolve, every entry the resolution adds
  or changes is vetted the same way afterwards, its recorded digests held to the
  bytes the proxy serves; one that fails fails the lock file's update. The
  sandbox needs `repositories.updates.sandbox.runtime` (docker or podman) and
  this binary built statically (the release binaries are): it runs inside the
  container as the relay.
* **Not at all**, for the formats below, with the reason — nor for a project
  that vendors its dependencies next to the lock file (`vendor/modules.txt`, a
  `cargo vendor` source replacement): its build reads the vendored copies,
  which only `go mod vendor` or `cargo vendor` would update.

<!-- BEGIN GENERATED: maintenance update formats. Regenerate with `go test ./internal/repos/update -run TestRepositoriesDocIsCurrent -update`; source: internal/repos/update/catalog.go. -->

**Updated natively** — the proxy rewrites the lock file itself; when the new version declares other
dependencies, the fallback applies:

| Type | Format | Fallback | Manifests read | When |
|---|---|---|---|---|
| `cargo` | `Cargo.lock` | sandboxed `cargo` | `Cargo.toml` | Native when the new version's index entry declares the same dependencies, features and links: `version` and `checksum` (the SHA-256 of the .crate the proxy verified) are rewritten, and references that name the old version. Otherwise `cargo update --precise` re-resolves in the sandbox (crates.io dependencies). |
| `go` | `go.mod` | sandboxed `go` | `go.mod` | Native when the new version's go.mod requires the same modules at the same versions: the `require` line in go.mod and the `h1:` lines in go.sum (the module hash of the zip and of the go.mod the proxy verified) are rewritten. Otherwise `go get` re-resolves in the sandbox (minimal version selection within the major version). |
| `go` | `go.sum` | sandboxed `go` | `go.mod` | Written together with go.mod (see go.mod). |
| `npm` | `npm-shrinkwrap.json` | sandboxed `npm` | `package.json` | As `package-lock.json`, of which it is the published form. |
| `npm` | `package-lock.json` | sandboxed `npm` | `package.json` | Native when the new version declares the same dependencies, platform and installation metadata as the old one (its packument entries compare equal): `version`, `resolved` and `integrity` of every install position of the old version are rewritten from the bytes the proxy verified. Otherwise `npm update --package-lock-only` re-resolves the tree in the sandbox, its packument trimmed to the vetted version. |
| `pip` | `requirements.txt` | unsupported | `requirements.in`, `pyproject.toml` | Native when the new release declares the same requirements (Requires-Dist, from the index's JSON API) and every other pinned project's requirements allow it: the `==` pin and its `--hash` lines (one per distribution file of the release, from the bytes the proxy verified) are rewritten. A release with other requirements is not proposed: re-resolving needs the file's pip-tools or uv input, which the sandbox does not run yet. |

**Not updated:**

| Type | Format | Why |
|---|---|---|
| `ansible` | `requirements.yml` | A requirements file pins versions without digests and is not resolved by a lock. The updater lists newer versions through the proxy for the npm, PyPI, Cargo and Go registries only; this ecosystem's versions are not listed yet. |
| `bazel` | `MODULE.bazel.lock` | Bzlmod records registry file hashes of every visited version, which Bazel computes. The updater lists newer versions through the proxy for the npm, PyPI, Cargo and Go registries only; this ecosystem's versions are not listed yet. |
| `composer` | `composer.lock` | composer.lock carries a content hash of composer.json and dist references only Composer computes. The updater lists newer versions through the proxy for the npm, PyPI, Cargo and Go registries only; this ecosystem's versions are not listed yet. |
| `conan` | `conan.lock` | Conan locks recipe revisions computed by Conan. The updater lists newer versions through the proxy for the npm, PyPI, Cargo and Go registries only; this ecosystem's versions are not listed yet. |
| `conda` | `@EXPLICIT spec` | An explicit spec is the output of a solve of the whole environment. The updater lists newer versions through the proxy for the npm, PyPI, Cargo and Go registries only; this ecosystem's versions are not listed yet. |
| `conda` | `conda-lock.yml` | conda-lock re-solves the whole environment per platform. The updater lists newer versions through the proxy for the npm, PyPI, Cargo and Go registries only; this ecosystem's versions are not listed yet. |
| `conda` | `pixi.lock` | pixi re-solves every environment and platform together. The updater lists newer versions through the proxy for the npm, PyPI, Cargo and Go registries only; this ecosystem's versions are not listed yet. |
| `cpan` | `cpanfile.snapshot` | Carton re-resolves the snapshot. The updater lists newer versions through the proxy for the npm, PyPI, Cargo and Go registries only; this ecosystem's versions are not listed yet. |
| `cran` | `renv.lock` | renv records no digests to rewrite, and renv itself snapshots the library. The updater lists newer versions through the proxy for the npm, PyPI, Cargo and Go registries only; this ecosystem's versions are not listed yet. |
| `dart` | `pubspec.lock` | pub re-resolves the whole lock (`dart pub upgrade`). The updater lists newer versions through the proxy for the npm, PyPI, Cargo and Go registries only; this ecosystem's versions are not listed yet. |
| `docker` | `Dockerfile` | Base images are pinned by digest of a tag, not by a version within a range; moving them is not a dependency update the updater can vet against a declared constraint. |
| `docker` | `compose` | As Dockerfile. |
| `git` | `.gitmodules` | Submodules are pinned to commits, which have no versions to order and no package content the LLM scan vets as a package. |
| `hackage` | `cabal.project.freeze` | cabal re-solves the plan. The updater lists newer versions through the proxy for the npm, PyPI, Cargo and Go registries only; this ecosystem's versions are not listed yet. |
| `hackage` | `stack.yaml.lock` | Stack records snapshot and package hashes it computes. The updater lists newer versions through the proxy for the npm, PyPI, Cargo and Go registries only; this ecosystem's versions are not listed yet. |
| `helm` | `Chart.lock` | Chart.lock's digest is a hash of the dependency list Helm computes. The updater lists newer versions through the proxy for the npm, PyPI, Cargo and Go registries only; this ecosystem's versions are not listed yet. |
| `helm` | `requirements.lock` | As Chart.lock. The updater lists newer versions through the proxy for the npm, PyPI, Cargo and Go registries only; this ecosystem's versions are not listed yet. |
| `hex` | `mix.lock` | Mix evaluates mix.lock, and its outer and inner checksums are computed by Hex. The updater lists newer versions through the proxy for the npm, PyPI, Cargo and Go registries only; this ecosystem's versions are not listed yet. |
| `homebrew` | `Brewfile.lock.json` | Homebrew no longer writes Brewfile.lock.json. The updater lists newer versions through the proxy for the npm, PyPI, Cargo and Go registries only; this ecosystem's versions are not listed yet. |
| `jsr` | `deno.lock` | Deno locks module file sets by their own integrity hashes. The updater lists newer versions through the proxy for the npm, PyPI, Cargo and Go registries only; this ecosystem's versions are not listed yet. |
| `julia` | `Manifest.toml` | Pkg records git-tree hashes of the source trees, which Pkg computes. The updater lists newer versions through the proxy for the npm, PyPI, Cargo and Go registries only; this ecosystem's versions are not listed yet. |
| `maven` | `gradle.lockfile` | Gradle writes the lock from the build's own resolution, which only running the build reproduces. The updater lists newer versions through the proxy for the npm, PyPI, Cargo and Go registries only; this ecosystem's versions are not listed yet. |
| `maven` | `pom.xml` | A POM is the build itself, not a lock file; changing its versions is a change of the build. The updater lists newer versions through the proxy for the npm, PyPI, Cargo and Go registries only; this ecosystem's versions are not listed yet. |
| `nix` | `flake.lock` | Flake inputs are source revisions with NAR hashes, not registry versions. The updater lists newer versions through the proxy for the npm, PyPI, Cargo and Go registries only; this ecosystem's versions are not listed yet. |
| `npm` | `pnpm-lock.yaml` | pnpm keys snapshots and their dependency graph by version and peer suffix; a rewrite needs pnpm itself, which the sandbox does not run yet. |
| `npm` | `yarn.lock` | A yarn.lock entry records the resolution of each range, keyed by the ranges; moving one entry means re-resolving with Yarn itself, which the sandbox does not run yet. |
| `nuget` | `packages.lock.json` | `contentHash` is the SHA-512 of the package with its signature removed, which the proxy cannot recompute from the bytes it serves; the lock is re-resolved by `dotnet restore`, which the sandbox does not run yet. The updater lists newer versions through the proxy for the npm, PyPI, Cargo and Go registries only; this ecosystem's versions are not listed yet. |
| `pip` | `Pipfile.lock` | Pipfile.lock carries a hash of the Pipfile and is re-resolved by Pipenv, which the sandbox does not run yet. |
| `pip` | `pdm.lock` | pdm.lock carries a content hash of pyproject.toml and is re-resolved by PDM, which the sandbox does not run yet. |
| `pip` | `poetry.lock` | poetry.lock carries a content hash of pyproject.toml and is re-resolved by Poetry, which the sandbox does not run yet. |
| `pip` | `uv.lock` | uv.lock records every release's dependency markers per resolution fork; it is re-resolved by uv, which the sandbox does not run yet. |
| `puppet` | `Puppetfile` | r10k evaluates the Puppetfile; it records no digests. The updater lists newer versions through the proxy for the npm, PyPI, Cargo and Go registries only; this ecosystem's versions are not listed yet. |
| `rubygems` | `Gemfile.lock` | Bundler re-resolves the whole lock (`bundle lock --update`), which the sandbox does not run yet. The updater lists newer versions through the proxy for the npm, PyPI, Cargo and Go registries only; this ecosystem's versions are not listed yet. |
| `swift` | `Package.resolved` | SwiftPM pins registry releases without a checksum and source-control pins by revision. The updater lists newer versions through the proxy for the npm, PyPI, Cargo and Go registries only; this ecosystem's versions are not listed yet. |
| `terraform` | `*.tf modules` | Module versions are written in configuration, not a lock file. The updater lists newer versions through the proxy for the npm, PyPI, Cargo and Go registries only; this ecosystem's versions are not listed yet. |
| `terraform` | `*.tf overrides` | Module versions are written in configuration, not a lock file. The updater lists newer versions through the proxy for the npm, PyPI, Cargo and Go registries only; this ecosystem's versions are not listed yet. |
| `terraform` | `.terraform.lock.hcl` | Provider hashes cover every platform's zip (`zh:`/`h1:`), which `terraform providers lock` computes. The updater lists newer versions through the proxy for the npm, PyPI, Cargo and Go registries only; this ecosystem's versions are not listed yet. |

<!-- END GENERATED: maintenance update formats -->

### Pushing the branch

The commit — signed when `repositories.updates.signingKey` holds an OpenSSH
private key (git's SSH signature format; register its public key as a signing
key on the Git host) — is built on top of the default branch's current head,
and pushed to `repositories.updates.branch` (default `pullthrough/maintenance`,
per repository `updates.branch`) over HTTPS or SSH with the repository's
`credentialsRef`. Its message lists each update (old → new, verdict, the
scan IDs of its verdicts) and each skipped candidate with its reason. A scan ID
is the LLM package scan's verdict key — the artifact's SHA-256 and a signature
of the model and prompt version — under which the verdict, its reasons and
cited files are kept (`GET /admin/api/llmpkgscan/verdicts?name=`, the
package's dossier).

* **Nothing changed, nothing pushed.** When the branch already holds the same
  files on the same head, the run ends `unchanged`; with no update at all it
  ends `no-updates`. Neither pushes.
* **Nothing left to propose.** When a run finds no vetted update any more —
  the branch was merged, or what it proposes is no longer vetted (a verdict
  changed, the firewall or the cooldown now refuses it) — and the branch is the
  updater's, the branch is deleted (with the lease), which closes its GitHub pull
  request; the run ends `retired`. A run on which something only passingly
  failed (a registry that could not be read, a scan that did not happen) never
  deletes it.
* **A lease on the last push.** The push uses `--force-with-lease` against the
  commit the updater pushed last (or the branch's absence). A branch someone
  else pushed to is never overwritten: the run ends `conflict`, says so, and
  notifies (`repository_update`); delete the branch, or merge it, and the next
  run starts it over. A branch deleted after its pull request was merged is
  simply created again.
* **A moving default branch.** When the default branch moves while a run
  computes, the run starts over on the new head (up to three times). When it
  moved since the last push, the branch is rebuilt on top of it.
* **Pull requests.** With `repositories.updates.pullRequests.enabled` and a
  repository's `updates.forge` (`github` or `gitlab`) and `forgeTokenRef`, the
  run opens a pull/merge request from the branch to the default branch, or
  updates the open one's title and body.

Every push, and every push refused, is in the tamper-evident audit log
(`repository_update`: the branch, the commit, the base, the lease, the
updates). The run's report is kept (`updates/<repo>/<run>` in the state
directory, the newest 20; dry runs apart, under `updatedry/`, the newest 5).

### Configuration

```yaml
repositories:
  updates:
    enabled: true
    interval: 24h                      # negative: on request only
    branch: pullthrough/maintenance
    maxBump: minor                     # without a declared constraint: minor (same major) or patch
    maxCandidates: 3
    maxUpdates: 50
    signingKey: file:///etc/pullthrough/maintenance-signing-key   # OpenSSH private key; empty: unsigned
    pullRequests: {enabled: true, labels: [dependencies]}
    sandbox:
      runtime: docker                  # or podman; empty: no sandbox
      # images: {npm: node:22-slim, cargo: rust:1-slim, go: golang:1.24-alpine}
  repos:
    - name: widgets
      url: https://github.com/acme/widgets.git
      credentialsRef: vault://kv/git/widgets#token      # also used to push
      updates:
        ignore: ["npm/lodash@>=5", "pip/django@>=5.0"]
        forge: github
        forgeTokenRef: vault://kv/github/widgets-bot#token
```

## Configuration

```yaml
repositories:
  enabled: true
  # stateDir: /var/lib/pullthrough/repositories   # default <cache.dir>/repositories
  pollInterval: 5m
  webhookPath: /webhooks/repos
  webhookSecret: env://REPO_WEBHOOK_SECRET  # no secret, no webhook
  backfillTags: 10
  roles: [release-pinner]                    # auth.roles the pinner fetches with (auth.enabled)
  pinning:
    concurrency: 4                         # dependencies of a release fetched at a time
    platforms: [linux/amd64, linux/arm64]  # images and Terraform providers
    retryInterval: 1h
    maxAttempts: 5
  scan:                                    # Task 181; needs llmPackageScan.enabled
    releases: true                         # each release once pinned
    defaultBranch: true                    # the default branch's head on push and poll
    interval: 24h                          # and again at least this often
    concurrency: 2                         # dependencies of one revision at a time
    retryInterval: 1h                      # passing causes (budget, provider) are retried
  repos:
    - name: widgets
      url: https://github.com/acme/widgets.git
      credentialsRef: vault://kv/git/widgets#token   # resolved at each fetch, never stored
      tenant: team-a
      lockfiles: ["package-lock.json", "services/*/go.*"]
      tags: ["v*"]
      upstreams: {cargo: crates}            # only needed when the lock file's registry is not enough
      # roles: [widgets-pinner]             # instead of repositories.roles
      # branch: develop                     # the branch whose head is scanned (default: the remote's HEAD)
```

Every key is listed in [configuration-reference.md](configuration-reference.md#repositories).
Some details:

* **URLs.** `url` must be `https://`, `ssh://` or scp-like `user@host:path`
  (`allowedSchemes`). Credentials in the URL, option-like URLs (`-…`) and
  remote-helper URLs (`ext::`, which run programs) are refused. Git runs with
  `GIT_ALLOW_PROTOCOL` limited to the allowed schemes, `protocol.ext.allow=never`
  and no hooks.
* **Credentials.** `credentialsRef` is a secret reference (`env://`,
  `file://`, `vault://…#key`), never the secret. It is resolved through the
  secrets provider at each fetch and handed to git through the environment,
  never on the command line or in the mirror's config. SSH URLs use the proxy
  host's SSH configuration.
* **Registry choice.** A dependency is fetched only through an upstream that
  fronts the registry its lock file names. That is the same host and path, or
  two names of the same public registry (`registry.yarnpkg.com` and
  `registry.npmjs.org`, the crates.io index URL and `index.crates.io`, …).
  Fetching a package of the same name from another registry would pin a
  different package: such a dependency is `unsupported`, with the registry
  named. A lock file that names no registry (`go.sum`, a requirements file
  without an index URL) is fetched through the one upstream of its type; with
  several, the dependency is `unsupported` until the repository's `upstreams`
  chooses: taking one would be a guess, and a private package's name looked
  up in a public registry is how dependency confusion works. A repository's
  `upstreams` map overrides the choice per type.
* **Roles.** With `auth.enabled`, the release pinner needs roles to fetch with
  (see step 4): `repositories.roles`, or a repository's own `roles`. The
  configuration is refused when a configured repository would have none, or
  names a role `auth.roles` does not define; so is an API registration. A
  tenant-bound identity cannot choose the roles of a repository it registers:
  they decide which upstreams the pinner reaches on its tenant's behalf. It
  gets `repositories.roles`.
* **Names.** A repository's name stays bound to its tenant and URL after the
  repository is removed through the API or dropped from the configuration:
  its history and releases are kept, and only the same tenant can register the
  name again, for the same URL, which continues the history.
* **High availability.** The state directory must be one every replica
  mounts: the pins in it protect the shared cache on every replica. With
  `coordination.enabled`, every replica re-reads the shared state every
  minute: registrations made through another replica's API, and the
  manifests, which are the pins (only those that changed are read). The garbage
  collector re-reads the manifests before each pass. Only the leader polls,
  takes webhook deliveries and pins. A release that a sync or a `ptctl repos
  pin` on another replica queued stays pending in the shared state, and the
  leader picks it up within a minute. A replica that loses the leadership in
  the middle of a release stops, and the new leader resumes it. A sync on any
  replica first catches up with the history records the others wrote. With an
  S3 shared cache, bucket lifecycle rules know nothing of pins: do not expire
  objects under the cache prefix by age.

## Which dependencies can be pinned

A dependency's objects are found from its lock-file entry. Most types need
only that entry. Some need an index read through the proxy first: PyPI simple
pages, the NuGet service index, Maven POMs (for the packaging), and OCI image
indexes, which are walked to the selected platforms' manifests, configs and
layers.

| Type | Objects pinned |
|------|----------------|
| npm | the tarball (the lock file's `resolved` URL when it is under the upstream) |
| pip | the distribution files the lock file hashes, found on the simple page; with no hashes, every file of the version |
| cargo | the `.crate` |
| go | `.info`, `.mod` and `.zip`. A module go.sum hashes only by its go.mod is not downloaded by the build, so only its `.mod` is pinned |
| nuget | the `.nupkg` under the feed's package base address |
| maven | the POM and the main artifact its packaging names |
| rubygems | the `.gem` (platform included) |
| docker | the image index or manifest, and each selected platform's manifest, config and layers (foreign layers excluded) |
| helm | the chart archive, as the index rewrite names it |
| dart, hex, hackage, puppet, ansible, swift, bazel, julia, cran, cpan | the release archive |
| conda, homebrew | the file at the URL the lock file records |
| terraform | the provider zip for each configured platform (default linux/amd64) |

These types are recorded as `unsupported`, with the reason, and the release is
then not fully pinned:

* Git dependencies, including submodules: they are served from Git mirrors,
  not the package cache.
* Composer: distributions are addressed by a dist reference that composer.lock
  does not carry in a usable form.
* Conan: binary packages are addressed by package ID.
* JSR: modules are sets of files listed in a version manifest.
* Nix flake inputs.

`locate.SupportedTypes()` and `locate.UnsupportedTypes()` are the source of
truth, and a test holds every lock-file type to one or the other.

## API and `ptctl`

| Question | `ptctl` | Admin API |
|----------|---------|-----------|
| Register a repository *(administer)* | `ptctl repos add <name> <url> --owner T --credentials-ref env://VAR --lockfile 'GLOB' --tag 'v*' [--role R]` | `POST /api/repos` |
| What is registered? | `ptctl repos list` | `GET /api/repos` |
| A repository and its current tags | `ptctl repos show <name>` | `GET /api/repos/show?name=` |
| Tag history: every commit each tag pointed at | `ptctl repos tags <name> [--tag T]` | `GET /api/repos/tags?name=&tag=` |
| Releases by tag (current and historical commits) | `ptctl repos releases <name> --tag T [--full]` | `GET /api/repos/releases?name=&tag=&full=1` |
| Releases by commit, across repositories | `ptctl repos commit <sha>` | `GET /api/repos/releases?commit=` |
| Which releases contain a dependency or object? | `ptctl repos lookup npm/lodash@4.17.21`, `ptctl repos lookup --digest sha256:…` | `GET /api/repos/lookup?coordinate=` or `?digest=` |
| Sync now | `ptctl repos sync <name>` | `POST /api/repos/sync?name=` |
| Pin (or retry) a release now | `ptctl repos pin <name> <commit>` | `POST /api/repos/pin?name=&commit=` |
| Verify the history's hash chain | `ptctl repos verify <name>` | `GET /api/repos/verify?name=` |
| Stop tracking *(administer)* | `ptctl repos remove <name>` | `POST /api/repos/remove?name=` |
| Scan the dependencies now *(operate)* | `ptctl repos scan <name> [--rev REV] [--wait]` | `POST /api/repos/scan?name=&rev=` |
| A scan's report | `ptctl repos report <name> [--rev REV] [--verdict flagged]` | `GET /api/repos/scan?name=&rev=&verdict=` |
| The report as SARIF | `ptctl repos report <name> [--rev REV] --sarif FILE` | `GET /api/repos/scan/sarif?name=&rev=` |
| A repository's scans | — | `GET /api/repos/scans?name=` |
| Run the maintenance updater *(operate)* | `ptctl repos update <name> [--dry-run]` | `POST /api/repos/update?name=&dryRun=1` |
| A maintenance run's report | `ptctl repos update <name> --run ID` | `GET /api/repos/update?name=&run=` |
| The maintenance branch's state and runs | `ptctl repos updates <name>` | `GET /api/repos/updates?name=` |

Each release is shown with:

* `state`: `current` while a tag points at its commit, `historical` afterwards;
* `currentTags` and `formerTags`;
* `status` (`pending`, `pinned`, `partial`, `failed`), `fullyPinned`, and a
  `reason` when it is not fully pinned.

A lookup lists the matching dependencies of each release with their status.

The API is hard-scoped to the caller's tenant, like the dossier: a
tenant-bound identity sees, registers and removes its own tenant's
repositories only, and cannot choose a repository's roles.

The [dossier](admin-ui-walkthrough.md#dossier--the-per-coordinate-360-view) of a coordinate has a *Shipped in releases* section
listing the releases that pin it. The [provenance graph](observability.md#supply-chain-graph-task-33)
has a `release` node per release, with `shipped-in` edges from the versions it
pins. A blast-radius query (`/api/provgraph/blast`) therefore also lists the
releases that ship an affected artifact. Release nodes are scoped to the
caller's tenant.

## Audit events, notifications and metrics

| Audit event | Recorded when |
|-------------|---------------|
| `repository` | a repository is registered or removed |
| `release_tag` | a tag is created, moved or deleted (with the commits, the record's sequence number and hash) |
| `release_pin` | a release was pinned (allow) or not fully pinned (deny); a dependency's bytes did not match its lock file; a pinned object was restored or lost after an integrity failure |
| `repository_scan` | a dependency scan finished (deny when it found a malicious or suspicious dependency); a dependency was flagged (`event: dependency-flagged`, with the coordinate, digest, model and lock-file lines) |
| `policy_decision` `llmpkgscan:deferred:*` | the LLM gate's refusal of an object the release pinner or the scanner fetched, left to the scan |
| `repository_update` | a maintenance branch was pushed (allow), or a push was refused because the branch holds commits the updater did not push, or failed (deny) |

Notifications: `release_tag` for moved (high) and deleted (medium) tags.
`release_pin` for:

* a release not fully pinned, on its first and its last attempt;
* a digest mismatch (high);
* a lost pinned object (critical).

`repository_scan` for a dependency the LLM scan judges malicious (critical),
or suspicious (high under `quarantine`, medium otherwise), once per dependency
and digest. The summary is the proxy's sentence; the model's words are never
in a notification.

`repository_update` (medium) for a maintenance run whose branch holds commits
the updater did not push: it is left as it is.

Metrics (`pullthrough_repo_*`):

| Metric | Meaning |
|--------|---------|
| `repositories` | repositories tracked |
| `tags_tracked{repo}` | current tags per repository |
| `tag_events_total{event}` | history records written: created, moved, deleted |
| `pinned_objects`, `pinned_bytes` | distinct cache objects pinned, and their size |
| `pin_failures_total{reason}` | dependencies not pinned: refused (a gate, or `access-control`), digest, fetch, unsupported, locate, store |
| `releases_total{status}` | pinning attempts by outcome; `pin_duration_seconds` their duration |
| `pin_queue` | releases waiting to be pinned |
| `sync_errors_total{repo}` | failed syncs |
| `webhooks_total{outcome}` | webhook deliveries: accepted, ignored, deferred, rejected |
| `pin_repairs_total{outcome}` | integrity repairs of pinned objects: restored, lost |
| `scans_total{kind,status}` | dependency scans by kind (release, head, revision) and status (complete, incomplete, failed); `scan_duration_seconds` their duration |
| `scan_dependencies_total{verdict}` | dependencies scanned, by verdict |
| `scan_queue` | revisions waiting for a scan |
| `malicious_dependencies{repo}` | malicious dependencies (not released by break-glass) in each repository's current scans: the head and every release |
| `update_runs_total{status}` | maintenance runs by status (pushed, unchanged, no-updates, retired, dry-run, conflict, failed); `update_duration_seconds` their duration |
| `updates_total{method}` | dependency updates written, by method (native, sandbox) |
| `update_skipped_total{reason}` | candidate versions passed over, by reason |
| `update_pushes_total{outcome}`, `update_pull_requests_total{outcome}` | pushes (pushed, deleted, failed) and pull/merge requests by outcome |

## Alerts

| Alert | Severity | Fires when | Respond |
|-------|----------|-----------|---------|
| `PullthroughReleasePinFailures` | warning | dependencies of a release were refused, could not be fetched, or the manifest could not be stored | `ptctl repos releases <repo>` names each and why. A refusal needs an admission decision (break-glass, or a fixed dependency); fetch failures are retried. |
| `PullthroughReleaseDigestMismatch` | critical | the bytes served for a dependency are not those its lock file pins | Treat as a possible registry compromise or a wrong lock file. Compare the digests in the manifest (`--full`) with the registry's before rebuilding the release. |
| `PullthroughPinnedObjectLost` | critical | a pinned object failed its integrity check and could not be fetched again with its pinned digest | Restore it from a backup or an air-gap bundle; the releases that pin it (`ptctl repos lookup --digest …`) are not reproducible until then. |
| `PullthroughRepositoryMaliciousDependency` | critical | a current scan of a repository (its default branch's head, a release) found a malicious dependency | `ptctl repos report <repo> --verdict flagged` names it, the lock-file lines and the model. Remove or replace it and rebuild; review the evidence in the admin console before releasing a false positive through break-glass. The release's pinned bytes are kept for forensics. |
| `PullthroughRepositorySyncFailing` | warning | a repository's tags could not be fetched three times in 30 minutes | Check `ptctl repos show <repo>`: the credentials reference, network, or a history that no longer verifies (`ptctl repos verify`). |
| `PullthroughMaintenanceRunsFailing` | warning | two or more maintenance runs ended `failed` or `conflict` within 6 hours | `ptctl repos updates <repo>` shows the state and the runs; `ptctl repos update <repo> --run ID` the reason. A conflict means the branch holds commits the updater did not push: merge or delete the branch. A failure names the step (credentials, the push, the default branch). |
