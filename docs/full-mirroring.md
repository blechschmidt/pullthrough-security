# Full mirroring: following each registry ahead of client requests

The proxy is a pull-through cache: it fetches an artifact the first time a client asks for
it, runs it through the [admission gates](gates-reference.md) and caches it. That leaves two
gaps. The first client to ask for a new version waits for the fetch and every scan, including
the [LLM package scan](llm-package-scan.md), which can take minutes. And nothing is known
about an upload until somebody installs it: a malicious version is examined only when a
developer or a CI job has already asked for it.

Full mirroring closes both gaps. The proxy follows a registry, fetches each new upload as it
appears and runs it through the same gates, so the verdict exists before the first install,
and a disconnected site can be filled ahead of time (see [air-gapped.md](air-gapped.md)).

Whether a registry can be followed, and at what cost, depends on what it publishes. This page
records that for every upstream type the proxy supports, checked against the live registries
on 2026-11-15, and describes the engine that follows them:

- the engine: configuration, cursor state, and syncing through the gated pipeline (Task 189,
  in place: see [Running the full mirror](#running-the-full-mirror));
- adapters for the tier-(a) feeds (Task 190) and for the indexes and listings of tiers (b)
  and (c) (Task 191), in place: see [Feed adapters](#feed-adapters);
- scanning everything mirrored (Task 192), a view in the admin console (Task 193) and an
  end-to-end test suite (Task 194).

The **implementation status** column says, per type, what its feed adapter follows; the
configuration refuses full mirroring of a type nothing can follow: Docker Hub, Swift package
registries, the Nix binary cache, generic upstreams and Git hosting (tier (d)), and the
Terraform Registry (see [its section](#terraform)). For those the proxy fetches ahead of time
only three things: what tracked repositories pin ([repositories.md](repositories.md)), what an
operator lists in a pre-warm manifest ([air-gapped.md](air-gapped.md)), and what predictive
pre-warming guesses from past pulls ([prewarm.md](prewarm.md)). The last of these tries the
next patch and minor version numbers; a feed says what was actually published.

## The four tiers

Every type is in one of four tiers, by the best way its registry offers to learn about new
uploads:

- **(a) Incremental change feed.** The registry publishes its changes in order, and a follower
  asks for "everything since cursor X": npm's `_changes` sequence, PyPI's serial, the Go module
  index, the NuGet catalog, the Git history behind crates.io, Homebrew, Julia, the BCR and
  ConanCenter. This is the cheapest and most complete tier: a poll costs one small request when
  nothing changed, and nothing is missed while the cursor stays valid. Cursors do expire,
  though. Packagist keeps only 24 hours of changes, RubyGems rewrites `/versions` every month,
  the crates.io Git index is squashed weekly, and npm has reset its sequence before. Every
  follower needs a fallback full pass.
- **(b) Complete index to poll and diff.** The registry publishes its whole current state:
  APT's `Packages`, CRAN's `PACKAGES`, Hex's `/names`, conda's repodata, Maven Central's index,
  Open VSX's sitemap. This is simple and complete, but every change costs a re-read of the
  index (from 379 KB for Hex's `/names` to 468 MB for one conda subdir) unless the registry
  offers a delta: APT pdiffs, conda's sharded repodata, Maven's incremental index chunks, Hex's
  per-package `updated_at`. An index can also lag: Maven Central rebuilds its index only every
  two weeks. Most indexes list current versions only, so a superseded version is visible only
  to a follower that saw it while it was current.
- **(c) Paginated listings only.** The follower pages through a listing until it reaches what
  it has seen. That works when the listing is sorted by time (pub.dev, Hugging Face, Puppet
  Forge, Ansible Galaxy). When it is not (JSR, the Terraform Registry), finding new versions
  takes a pass over the whole listing. Offset paging shifts as items arrive, so pages must
  overlap. Listings cost the most per discovered upload and run into rate limits first.
- **(d) No practical enumeration.** Docker Hub, Swift package registries, the Nix binary
  cache, generic upstreams and Git hosting cannot be listed. At most a partial feed applies:
  the tags of repositories one names, one Nix channel's outputs.

## Before mirroring a whole registry

Three things limit what "full" can mean. Each registry's section below spells them out.

- **Terms of use.** Maven Central's terms forbid "scraping or mirroring any content". npm's
  terms call five million requests a month by one organisation unreasonable. Docker Hub
  forbids mirroring "for an unauthorized commercial service". What these terms rule out is
  copying the registry, not fetching what one depends on as it is published.
- **Size.** Full copies range from about 3 GB (Puppet Forge), 20.4 GB (Hackage) and 40 GB
  (CPAN) through 410 GB (CRAN), 5,451 GB (Debian, every architecture) and 51.6 TB (PyPI) to
  636 TB (the Nix cache) and more than 20 PB (Hugging Face). The realistic target is rarely the whole registry. It
  is every new version of the packages one already depends on, which a feed reveals within
  minutes, plus whatever tracked repositories pin.
- **Rate limits and identification.** PyPI's XML-RPC allows 5 requests per second and 50 per
  minute per IP; Hugging Face 500 API calls per IP in five-minute windows without an account;
  Docker Hub documents 100 per 6 hours per IPv4 address or IPv6 /64 without an account (its
  response headers showed a one-hour window). Maven Central limits downloads of its index per
  IP. crates.io and Packagist ask for a User-Agent that identifies the client and its
  operator. A follower must pace itself per registry, and an operator may need to supply
  contact details.

## Running the full mirror

The full-mirror engine (`internal/fullmirror`) follows the registry of every upstream that
enables `fullMirror`, and fetches each new file through the proxy's own gated serve pipeline
before any client asks for it. It needs a feed adapter for the upstream's type ([Feed adapters](#feed-adapters) below).
A type with nothing to follow is refused when the configuration loads, with the section of this
page that says why:

```
config: upstream "hub": fullMirror.enabled: Docker Hub cannot be followed: its tier is (d), no
practical enumeration (see docs/full-mirroring.md#docker)
```

That holds for every tier-(d) type (`docker`, `swift`, `nix`, `generic`, `git`), which cannot be
enumerated, and for `terraform`, whose listings would take a full pass for every new version
and whose provider binaries live outside the registry.

### Configuration

```yaml
fullMirror:                    # shared by every mirrored upstream
  stateDir: /var/lib/pullthrough/fullmirror   # default <cache.dir>/fullmirror
  tenant: mirror               # who the mirror fetches as (default: the default tenant)
  roles: [mirror]              # access-control roles; required with auth.enabled
upstreams:
  npm:
    type: npm
    url: https://registry.npmjs.org
    fullMirror:
      enabled: true
      include: ["@acme/.*", "lodash", "react(-dom)?"]   # RE2, matched against the whole name
      exclude: ["@acme/internal-.*"]
      versions: latest         # "all" (the default) or "latest"
      latest: 3
      maxArtifactBytes: 268435456   # per file; 0 = no limit
      byteBudget: 107374182400      # in total; required
      concurrency: 2
      requestsPerSecond: 2
      pollInterval: 5m
      offPeak: {start: "22:00", end: "06:00", timezone: Europe/Berlin}
      dryRun: false
```

| Setting | Meaning |
|---|---|
| `enabled` | Follow the registry. Refused for a type no feed adapter follows. |
| `include`, `exclude` | RE2 patterns matched against the **whole** package name (`lodash` does not match `lodash-evil`). A package is mirrored when it matches an include pattern (or none is given) and no exclude pattern. |
| `versions`, `latest` | `all` mirrors every version a change concerns. `latest` with `latest: N` mirrors the N newest versions of each package, in the ecosystem's own version order where the proxy knows it (npm, cargo, pip, go, nuget, maven, rubygems), otherwise in the order the registry lists them. Yanked versions never count; pre-releases count only for a package that has no other version. |
| `maxArtifactBytes` | The largest file fetched (0: no limit). A size the registry states is checked before anything is fetched; otherwise the cache fill is cut off at the limit and nothing is cached. Counted as skipped (`too-large`). |
| `byteBudget` | Required. The most bytes the mirror adds to the cache from this upstream, in total. A file that does not fit in what is left is not fetched; the mirror then waits — its queue intact, the cursor where it was — until the budget is raised. (A file that fits once the other fetches in flight are done waits for them instead.) In flight at that moment, files of unknown size can take the total slightly past it. |
| `concurrency` | Packages worked on at a time (default 2, at most 32). |
| `requestsPerSecond` | Paces every request made to the upstream for the mirror — feed polls, version lists, file fetches (default 2). |
| `pollInterval` | Time between two polls of a feed that has nothing more to give (default 5m, at least 10s). |
| `offPeak` | A daily window (`HH:MM` bounds in an IANA time zone, default UTC; it may wrap midnight). Outside it the mirror neither polls nor fetches; a batch resumes where it stopped. |
| `dryRun` | Poll the feed, apply every policy and check the cache, but fetch nothing: what would be fetched is counted as skipped (`dry-run`). |

The configuration also refuses a full mirror with the in-memory cache (the cursor would
outlive what it fetched), without a state directory when the cache is not a filesystem cache,
and without `fullMirror.roles` when `auth.enabled`.

### How it works

- **One follower per upstream, on the leader.** In a multi-replica deployment only the
  replica holding the `full-mirror` lease ([coordination.md](coordination.md)) polls and
  fetches. The state directory must be shared: whichever replica leads continues from it. A
  replica that finds the state written by someone else since it last read it stands by
  instead of overwriting it.
- **Bootstrap, then changes.** A follower that starts from nothing enumerates the registry
  with the adapter's `Bootstrap`, page by page; after the last page it follows the registry's
  changes from the cursor the enumeration started at, so nothing published meanwhile is
  missed. A cursor the registry no longer knows (npm resetting its sequence, Packagist's
  one-day log) starts the enumeration over, with an audit event.
- **Batches survive restarts.** Each batch of changes is stored (`batch.json`) before work
  starts, its progress as it goes, and the cursor only once every change of it is dealt with.
  A restart, a lost leadership, a pause, the end of the window or a spent budget leaves the
  batch to be resumed where it stopped; what a resumed batch finds in the cache is not fetched
  again.
- **Through the gated pipeline, never around it.** For each change the follower applies the
  name patterns, asks the adapter for the package's versions and files, applies the version
  policy, and asks the gateway whether the cache already holds each file (`SystemLookup`: no
  fetch, no gate). The rest is fetched with `Gateway.SystemFetch` as the system principal
  `system:full-mirror` of `fullMirror.tenant` with `fullMirror.roles`: the same resolution,
  admission gates, digest checks and cache fill as a client pull. The engine never writes to
  the cache itself. Each fetch is in the [download log](download-log.md) with `via=system`,
  that subject, and the User-Agent `pullthrough-full-mirror`.
- **A refusal is a verdict — when it is one.** A file an admission gate refuses is counted as
  **refused**, by gate, and not asked for again — it is not a failure. Three kinds of refusal
  are not verdicts:
  - *"Not yet."* A refusal with a `Retry-After` (a version still in its
    [maturity cooldown](maturity.md), an LLM scan still running) or by a gate that could not
    judge the file (`fail-closed`: its scanner unavailable) **defers** the file: it waits in the
    upstream's deferred queue (`deferred.json`, at most 20,000 files) and is asked for again when
    the gate said it may pass, or after 15 minutes. The batch goes on. A file deferred 30 times
    is counted as refused.
  - *Every file would be refused.* A refusal by access control (the mirror's roles do not grant
    the upstream) or by an [organization freeze](snapshots.md) **holds** the upstream: the batch
    stops, the reason is recorded, and the mirror tries again after 5 minutes.
  - *An emergency lockdown engaged mid-batch:* the batch stops and resumes once it is lifted.

  The mirror's refusals open no [break-glass review](approvals.md): nobody asked for the file,
  so no operator is asked to approve it. A grant an operator already gave applies.
- **Retries, backoff, Retry-After.** A transient failure (a 5xx, a 429, a network error) is
  retried up to five times, waiting 2s and doubling up to 1m. A `Retry-After` from the
  upstream — the proxy now relays it on 429 and 503, as seconds, at most a day — holds every
  request of the mirror to that upstream. A file that still fails stops the round and backs
  the upstream off (1m, doubling up to 30m); after three such rounds it is counted as
  **failed** and left behind — the package's other files go on — so one broken file cannot
  stall a feed. A worker's failed round stops the batch without being charged to the other
  workers' packages, and the files a package dealt with before its round failed are not
  dealt with again.
- **Rate limits.** Besides `requestsPerSecond`, the proxy's own rate limiter
  (`rateLimit`, [configuration.md](configuration.md#ratelimit)) admits each fetch as the mirror's
  tenant: its per-tenant and global request-rate and concurrency policies hold for the
  mirror as for any client (a refusal is a wait, not a failure). Give the mirror a tenant of
  its own (`fullMirror.tenant` with an `auth.teams` entry and its `rateLimit`) to keep it
  from sharing the clients' allowance. `outbound.maxConnsPerHost` applies too: the fetches
  use the upstream's transport.
- **Kill-switch.** While an [emergency lockdown](lockdown.md) is engaged — any mode — the
  mirror fetches nothing.

### Status and controls

`GET /admin/api/fullmirror/status` reports the mirror overall and each upstream: the state
(`following`, `bootstrapping`, `paused`, `off-peak`, `budget-exhausted`, `backing-off`,
`lockdown`, `standby`, `starting`, `error`), the cursor and phase, the feed's head and the lag
behind it, the last and next poll, the batch still queued, the deferred queue and when its
next file is due, the counters (packages mirrored, excluded, deleted; files fetched, refused by
gate, failed, skipped by reason, deferred; retries), the budget spent, and the recent errors.
`?upstream=<name>` returns one upstream.

| Endpoint | Capability | Step-up |
|---|---|---|
| `GET /admin/api/fullmirror/status` | read | — |
| `POST /admin/api/fullmirror/pause` `{"upstream": "npm", "reason": "…"}` (no upstream: every one) | operate | yes |
| `POST /admin/api/fullmirror/resume` `{"upstream": "npm"}` (no upstream: the global pause and every upstream's) | operate | yes |
| `POST /admin/api/fullmirror/resync` `{"upstream": "npm"}` | administer | yes |

The full mirror is instance-wide: a tenant-bound identity may read its status but not steer
it. Pauses are persisted (they hold across restarts and on every replica); a resync forgets
the upstream's cursor and enumerates the registry again — the cache spares the refetch, the
counters and the budget spent are kept. With `webauthn.enforce` the three controls need a
fresh [passkey step-up](webauthn-stepup.md).

```
ptctl fullmirror status [--upstream npm] [--json]
ptctl fullmirror pause  [--upstream npm] [--reason "upstream incident"]
ptctl fullmirror resume [--upstream npm]
ptctl fullmirror resync --upstream npm
```

`ptctl` passes a step-up token given with `--stepup-token` (or `PULLTHROUGH_STEPUP_TOKEN`);
without one, a protected control is refused with an explanation.

**Metrics** (`pullthrough_fullmirror_*`, per upstream): `upstreams`, `leader`, `paused`,
`state{state}`, `packages_total{outcome}`, `artifacts_total{outcome}` (fetched, refused,
failed, skipped), `skipped_total{reason}`, `refused_total{gate}`, `fetched_bytes_total`,
`retries_total`, `polls_total{result}`, `queued`, `deferred`, `deferrals_total`, `in_flight`,
`lag`, `lag_seconds`, `last_poll_timestamp_seconds`, `budget_bytes`, `budget_used_bytes`. The
counters are the persisted tallies: they carry over restarts.

**Audit events** (`full_mirror`): `paused`, `resumed`, `resync-requested` (with the
operator), `resync`, `bootstrap-started`, `bootstrap-finished`, `cursor-reset`,
`budget-exhausted`, `budget-raised`, `type-changed`.

**Backup.** The state directory is a backup source (`full-mirror`). The leader rewrites its
files every few seconds, so the backup copies each file once, while it builds the snapshot's
manifest, instead of failing on the change ([backup-restore.md](backup-restore.md)). A restored
proxy continues from the restored cursors.

### Feed adapters

Every registry of tiers (a), (b) and (c) except Terraform has a feed adapter: the change feeds
of tier (a) since Task 190, the indexes of tier (b) and the listings of tier (c) since Task 191.
The implementation-status column of the [summary](#summary) says what each one follows. They
share these rules:

- **The feed comes from the upstream's `url`.** For the public registry the adapter knows the
  public feed (npm's replica at replicate.npmjs.com, index.golang.org, packagist.org's change
  log, the Git repositories the Git-backed registries are built from). For another upstream it
  takes the same feed under the upstream's own URL where that registry software serves one
  (a CouchDB-backed npm registry, Athens, hackage-server, a CPAN mirror, PkgServer.jl), and
  otherwise refuses the configuration until `fullMirror.feed.url` names the feed. The table
  below says, per type, which private and self-hosted upstreams work.
- **Package metadata is read through the gated pipeline,** as a client reads it — with the
  upstream's credentials, mirrors and the backend's URL rewriting — and every artifact path
  comes from the backend itself: its own path builders, the URLs it wrote into the documents
  it served, or repos/locate, which the [release pinner](repositories.md) holds to every
  backend's parser. The mirror fetches exactly the paths clients request, so what it caches is
  what they are served. A gate's verdict on a metadata document is final for the package; a
  refusal by access control, a lockdown or a refused authorization upstream (401, 403) holds
  the upstream instead of giving the package up.
- **Credentials stay on the upstream's origin.** The upstream's credentials go only with
  requests to the scheme, host and port of its `url`, and are dropped from a redirect that
  leaves it; a feed on another host (replicate.npmjs.com, index.golang.org, packagist.org,
  github.com) never sees them.
- **Every answer is untrusted input:** bodies are read up to a bound and refused past it,
  names and versions are checked before they become a path, an item a registry got wrong is
  dropped rather than failing its batch, and a cursor that does not read back (another
  adapter's, a damaged state file's) starts the enumeration over.
- **A change is picked up once.** An adapter reads a package's metadata when its feed reports
  the change. Registries serve that metadata through CDNs (npm's packuments and crates.io's
  sparse index are cached for minutes); a read that still gets the document from before the
  publish mirrors what it lists, and the version it lacks follows with the package's next
  change or a resync.

Options go under `fullMirror.feed`; an unknown key is refused when the configuration loads:

```yaml
upstreams:
  crates:
    type: cargo
    url: https://index.crates.io
    fullMirror:
      enabled: true
      byteBudget: 107374182400
      feed:
        url: https://git.internal.example/cargo-index.git   # crates.io's is known; required for a private registry
        branch: main                                        # default: the repository's HEAD
```

Per type, what is followed, what is mirrored for each version, how private and self-hosted
upstreams fare, and the options (every adapter also takes `url`):

| Type | Feed and cursor | Mirrored per version | Private and self-hosted upstreams | Options |
|---|---|---|---|---|
| `npm` | replicate.npmjs.com `_changes` from a sequence (one beyond `update_seq`, confirmed past the CDN, is a reset); `_all_docs` to start | the tarball the packument names | a CouchDB-backed registry at its own root; Verdaccio, Artifactory, Nexus and GitHub Packages serve no `_changes`: not followable unless `url` names a replica that does | — |
| `pip` | PyPI's XML-RPC changelog from a serial; the PEP 691 project list (the 46 MB `/simple/`) to start | every file of the version the simple page lists (sizes, upload time, yanked) | another Warehouse as is; an index without XML-RPC is followed with `mode: simple` (it diffs every project's `_last-serial`, the 46 MB list per changed poll — set a long `pollInterval`); in `auto` mode the follower switches to it once three polls in a row find XML-RPC missing; Artifactory, Nexus and devpi serve no serials: not followable | `mode` (`auto`, `xmlrpc`, `simple`), `settle` (5m) |
| `cargo` | the Git index's trees, diffed between head commits | the `.crate` | a registry with a Git index, named by `url`; one that serves only a sparse index cannot be followed | `branch` |
| `go` | index.golang.org from a timestamp (records already reported at that instant are dropped); the whole index replayed to start | `.info`, `.mod` and `.zip` of each tagged version; pseudo-versions are left to client pulls | Athens' `/index` under the upstream's URL; goproxy.io and the other public GOPROXYs, Artifactory and Nexus have no index: `url` must name one | — |
| `nuget` | the catalog by commit timestamp, each batch ending at a commit boundary (a cursor beyond the last commit restarts the replay); the whole catalog replayed to start | the `.nupkg` of each version the flat container lists (unlisted ones included) | a feed whose service index names a `Catalog/3.0.0`; Artifactory, Nexus, Azure Artifacts and GitHub Packages name none: `url` must name a catalog index | `settle` (10m) |
| `rubygems` | the compact index `/versions` by Range requests from the end of a stored copy, checked against its digest (the monthly rewrite is diffed against the copy) | every platform's `.gem` of the version | any server of the compact index as is (Gemstash, a rubygems.org mirror) | — |
| `composer` | Packagist's `changes.json` from `since` (a `resync` restarts the enumeration); `packages/list.json` to start | the dist archive of each tagged version (dev branches are not mirrored) | Satis, Artifactory and Nexus have no change log: a Packagist-compatible site must be named by `url` | — |
| `hackage` | the index tarball's tail by Range requests (the last entry's header hash detects a replaced index); `/packages/` to start | the sdist, in the short form cabal requests; deprecated versions are marked yanked | a hackage-server as is; a static mirror needs `url` (a hackage-server to follow) | — |
| `cpan` | the RECENT files from an epoch (a changed `dirtymark` restarts); `02packages.details.txt.gz` to start | every archive of the distribution its author's `CHECKSUMS` lists; names are `AUTHOR/Distribution` | a full CPAN mirror as is; minicpan, Pinto, Artifactory and Nexus have no RECENT files: `url` must name a full mirror | — |
| `julia` | the Pkg server's registry snapshots, diffed: each new registry tree is read through the proxy and indexed | the package tarball by uuid and git-tree-sha1; the binaries a package's Artifacts.toml names are not followed | PkgServer.jl as is | `flavor` (`conservative`, `eager`) |
| `bazel` | bazel-central-registry's trees, diffed between settled head commits | MODULE.bazel, the source archive, and the patches and overlay files its source.json lists | a registry with a Git history, named by `url`; a static tree without one cannot be followed | `branch`, `settle` (10m) |
| `conan` | conan-center-index's trees, diffed between settled head commits; versions from the remote's recipe search | the files of each version's latest recipe revision; binary packages per `binaries` | Artifactory, Nexus and conan_server have no feed: `url` must name a repository laid out as conan-center-index | `branch`, `settle` (1h), `binaries` (`none`, `all`, or settings such as `os=Linux,arch=x86_64;os=Macos,arch=armv8`) |
| `homebrew` | homebrew-core's `Formula` trees, diffed between settled head commits; for a mirror of the JSON API (`mode: index`), its `/api/formula.json` polled conditionally and diffed | the bottles of the formula's current version (the JSON API lists no other); disabled formulae are skipped | a JSON API mirror (`HOMEBREW_API_DOMAIN`) is followed through its formula index; the Git history needs `url`, a homebrew-core clone | `mode` (`auto`: `git` for formulae.brew.sh or with `url`, `index` otherwise; `git`, `index`), `branch`, `settle` (30m), `platforms` (bottle tags) |
| `apt` | each suite's `InRelease` (or `Release`), polled conditionally; the `Packages` indexes whose SHA-256 changed, read by hash and verified against it, diffed against a stored copy | every `.deb` (`.udeb`, `.ddeb`) of the version at its `Filename`, with its size; versions with their epoch, in dpkg order | aptly, reprepro, Pulp, Artifactory and Nexus archives as is | `suites` (required), `components` (`main`), `architectures` (`amd64`; `all` reads `binary-all` where the Release lists it) |
| `yum` | `repodata/repomd.xml`, polled conditionally; the primary (zstd, gzip or xz; size and checksum verified), streamed and diffed against a stored copy | every `.rpm` of the version (`[epoch:]version-release`, rpm order), all architectures, with size and time | one upstream is one repository root; Pulp, Artifactory, Nexus and createrepo_c trees as is | — |
| `helm` | `index.yaml`, polled conditionally and read as a stream, diffed against a stored copy | the chart archive, at the path the backend's rewritten index hands clients | ChartMuseum, Artifactory, Nexus, GitLab and Harbor as is; an OCI upstream (setting `oci`) cannot be followed | `settle` (15m) |
| `conda` | each followed subdir's `repodata.json.zst` (`repodata.json` where there is none), polled conditionally, diffed (an unchanged subdir copied, one that stops answering kept for three polls) | every file of the version — every build, both formats — of the followed subdirs, with size and upload time | Artifactory, Nexus, Quetz and prefix.dev channels as is; a 403 for a missing document counts as not found (S3) | `subdirs` (noarch, linux-64, linux-aarch64, osx-64, osx-arm64, win-64), `index` (`repodata`, `current`), `settle` (30m) |
| `cran` | `src/contrib/PACKAGES.gz` (`PACKAGES` where there is none), polled conditionally, diffed | the current source tarball (archived versions and binaries are not followed) | Posit Package Manager, Bioconductor, miniCRAN, Artifactory and Nexus as is | `settle` (45m) |
| `hex` | the signed `/names` and `/versions`, polled conditionally, `/versions` verified and diffed (`/names` gives the head time) | the tarball; retired versions marked yanked | organisation repositories as is; mini_repo and Artifactory need `publicKey` (or `none`) | `publicKey` (hex.pm's), `repository` (the name the index must carry) |
| `maven` | a repository manager's Maven Indexer index under `.index/`: the properties file polled conditionally, incremental chunks applied while the chain lasts, otherwise the full index streamed and diffed | the classifier-less files the index lists and the POM; classifier files per `classifiers` | Nexus and Artifactory repositories that publish an index; Maven Central (and copies of its index) is refused: its terms forbid mirroring it | `classifiers` |
| `openvsx` | `sitemap.xml`, diffed; the search listing by time, read at every poll, for a second publication on a day | one `.vsix` per version and target platform, from each platform's version listing | any openvsx-server, also one in mirror mode | `platforms` |
| `jsr` | every page of api.jsr.io's package list at each poll, diffed | every module file of the version, from its manifest (file lists kept per package) | no self-hosted JSR in common use: `url` names an API that lists packages as api.jsr.io does | — |
| `huggingface` | `/api/models` (or datasets, spaces) by last modification for each configured author and search, read in turn down to a high-water mark | the files of the commit `main` is at; gated and private repositories skipped unless `restricted` is `include` | Artifactory and Nexus remotes serve no listing: `url` names the Hub's API | `author` and/or `search` (one required; at most 32 authors), `kind`, `files`, `restricted` |
| `puppet` | `/v3/releases?sort_by=release_date` down to a high-water mark and a day below it, by module; Bootstrap from the releases sorted by module | the release tarball; deleted releases as yanked | only the Forge itself; `url` names it for an Artifactory remote | `settle` (90m; 3h30m in front of the Forge) |
| `ansible` | the collection-version search by `-pulp_created`, filtered by distribution, down to a high-water mark and a day below it; Bootstrap from the collection index | the collection artifact | galaxy_ng and pulp_ansible distributions as is; Artifactory and Nexus need `url` naming a Galaxy NG; a Private Automation Hub cannot be followed | `settle` (10m) |
| `dart` | pub.dev's Atom feed of the newest versions down to a high-water mark, the live package listing where the feed does not reach back (unchecked page boundaries looked at again later); Bootstrap from `/api/package-names` | the archive of every version; retracted versions yanked | other pub servers need `url` naming a site that serves pub.dev's feed and listings | `settle` (5m; 2h30m in front of pub.dev) |

`settle` holds a feed back from changes younger than the period, where what the feed reports
reaches the documents clients read — or the documents the backend verifies a file against —
only minutes later: the registries built from a Git
repository serve a commit's content after it is pushed (bcr.bazel.build is uploaded after a
push, ConanCenter promotes merged recipes and serves its revision pointers from a CDN,
formulae.brew.sh is regenerated and cached), NuGet's flat container lists a version minutes
after the catalog commits it, and a PyPI simple page can reach the CDN after the changelog
names the release. A change read before they have caught up would mirror the previous state —
or, where the feed names the version, take the version for gone. `0` reports every change at
once. For the Git-backed feeds the period runs from the commit time, which can be earlier than
the moment the commit reached the branch (a merge queue stamps a commit when it queues it), so
it is a lower bound; a commit stamped early atop one that has not settled waits for it. A
Bootstrap lists the head without waiting, so a package whose metadata the enumeration reads
within the period of a commit can miss that commit's change; a resync catches it. Other feeds
wait in their own terms: CPAN's reports an upload once its author's `CHECKSUMS` lists it (or
after two hours), and Go's keeps the versions the index announced in its last two batches —
in the state directory, across restarts — while `@v/list` lags behind. The index feeds of Helm,
conda and CRAN read a compressed index the backend does not verify against (it reads the plain
`index.yaml`, `repodata.json` or `PACKAGES`, cached separately by the CDN): they report a file
once it has been listed for the period, counted from the poll that first saw it on the
registry's clock (the response's `Date`), and keep that table in the state directory. The
listing feeds of pub.dev, the Puppet Forge and Galaxy hold back versions younger than the
period; behind a cache of their own (an Artifactory remote, a pub.dev mirror) the default
rises to the cache's lifetime.

**Choosing the poll interval.** An index feed re-reads its whole index whenever it changed, so
its cost per poll is the size of the index, and a busy registry changes at every poll: the
catalog notes what conda-forge's default subdirs and JSR's package list cost at the default
interval of five minutes. For those two, and for large Helm repositories and APT suites, a
`pollInterval` of 30 minutes to an hour keeps the traffic reasonable at the price of later
news. A listing feed is cheap when quiet (one request); the Hugging Face Hub's rate limit
caps `requestsPerSecond` (see its section).

#### Git-backed registries

The crates.io index, the Bazel Central Registry, conan-center-index and homebrew-core are
followed through the Git repositories they are built from. The adapter speaks Git's smart HTTP
protocol (version 2) itself, over the upstream's HTTP client, rather than running a `git`
binary, which would bypass the [egress policy](egress-ssrf.md) and the TLS pins: the egress
allowlist must admit the repository's host (github.com for the public registries). It fetches
trees only, never file contents. The first poll fetches the head commit's trees in one
depth-1, blob-less fetch; later polls fetch only the trees changed since the commit whose trees
the follower stores (in its directory under the state directory), and diff the two trees —
pruning every subtree whose id did not change. The difference does not depend on the history
in between: the crates.io index squashes its history weekly, and a squashed or force-pushed
branch is just another tree to compare. When an incremental fetch would cost more than a
fresh snapshot (a follower days behind a busy index), or names a tree the store lacks, the
adapter asks for a snapshot instead. Every object's id is computed from its content as it is
read, so each tree walked is the one the head commit names; packs are bounded in size, in
what they inflate to, and in time.

#### Index-polling registries

The registries of tier (b) publish their whole current state, and the adapters of APT, YUM,
Helm, conda, CRAN, Hex, Maven (where an index is published), Open VSX and JSR (whose
alphabetical listing is read whole at every pass), and Homebrew's JSON API, follow them by
keeping a copy of that state and diffing each new one against it:

- **The copy.** An adapter reads its index as a stream — decompressing it (gzip, bzip2, xz or
  zstd, with the decoder's memory bounded as for the [content scan](gates-reference.md)) and
  parsing it as it arrives — into records: one per file a version lists (an APT `.deb`, a conda
  package file), or one per version or per package where the index names no files. The records
  are sorted in runs of bounded size that spill to the adapter's directory under the state
  directory and are merged into the copy: gzip blocks with an index of the blocks, named by the
  SHA-256 of the records. Building a copy of an index of hundreds of thousands of files holds
  a few tens of megabytes of memory, however large the index; reading the same index twice
  makes the same copy. A package listing more files than any real one does (the index is
  untrusted input) is left out of the copy and counted, rather than failing the index. Every
  block is checked as it is read; a copy whose content does not match its name is removed and
  never trusted, and the cursor that names it starts the enumeration over (an I/O error of the
  state directory is retried instead).
- **A poll** reads the index conditionally: the cursor keeps the validators of the last read (an
  ETag or Last-Modified, the digests a signed `InRelease` or `repomd.xml` lists), so a registry
  that answers "not modified" costs one small request, and the parts of a multi-part index that
  did not change (an unchanged suite's `Packages`, an unchanged conda subdir) are copied from
  the previous copy rather than read again. A changed index becomes a new copy, and its
  difference from the cursor's copy is what the poll reports: each package that appeared, each
  version added or changed (with the version: only its files are fetched), and what is gone. A
  difference larger than a batch is reported over several batches; both copies stay until the
  engine has stored a cursor past them. Bootstrap reads the index once and lists every package
  of the copy, page by page; what is published while the engine works through them is in the
  first difference.
- **Releases** come from the newest copy where the index names the files (APT, YUM, Helm, conda,
  CRAN, Hex, Maven), so a version a difference reports is always there. Where the files come
  from a package's own metadata document (Homebrew's formula JSON, Open VSX's extension
  document, JSR's version manifests), the copy holds one record per package and changes name the
  package only: the engine looks at its current versions, and a document a CDN still serves from
  before the change does not lose a version.
- **The cost** is a re-read of the whole index for every change, at the poll interval: a few
  hundred kilobytes for Hex, tens of megabytes for an APT suite, Helm's large repositories,
  Homebrew's JSON or a YUM repository, and more for conda's busiest subdirs, which change every
  few minutes — set `pollInterval` to what the bandwidth allows. The table above says what each
  type reads.

#### Listing registries

Puppet Forge, Ansible Galaxy, pub.dev and the Hugging Face Hub offer listings sorted newest
first. Their adapters keep a high-water mark — the newest time they have reported — and the
items they saw in a lookback window below it (ten minutes by default), and page each listing
from its first page down to that window: everything newer than the mark is reported, and so is
an item in the window that became visible late (its time stamp taken before it was committed).
The newest item of the pass becomes the next mark — unless its time lies more than an hour
ahead of the proxy's clock: such an item is reported, but one bogus date must not hide
everything published after it. A Bootstrap takes the mark from the first pages before it
enumerates the registry (through a name list or a listing of every package), so what is
published during the enumeration comes with the first poll. Offset-paged listings shift while
they are read: an item published during a pass pushes the others down (an item seen twice is
reported once), and pages overlap by a few items so that an item deleted during a pass does not
hide its neighbour. A pass longer than one poll continues in the next, one page back. Listings
cost the most requests per discovered upload: mind each registry's rate limits (the table
above).

### Writing a feed adapter

A feed adapter implements `fullmirror.Feed` and registers itself with `fullmirror.Register`
from an `init` function of the `fullmirror` package, so that every binary that validates
configuration knows it; the entry's `Status` in `catalog_data.go` must then say
`implemented` or `partial` (a test holds the two together). The contract:

- `Bootstrap(ctx, cursor)` enumerates the registry page by page (cursor `""` first); the last
  page has `More` false and a `Next` cursor that `Changes` continues from, taken when the
  enumeration began. `Changes(ctx, cursor)` returns what changed after the cursor. Every batch
  has a non-empty `Next` (at most 64 KiB); a bigger state belongs in `Env.Dir`.
- A cursor the registry no longer knows is reported with an error wrapping
  `fullmirror.ErrCursorInvalid`; an error retrying cannot fix with `fullmirror.Permanent`; a
  registry's requested wait with `fullmirror.RetryAfter`.
- `Releases(ctx, name)` lists a package's versions, oldest first, each with its files as
  paths of the upstream's mount (`/v1/<upstream><path>`), and their sizes when the registry
  states them. A change may name a version, or only the package (the policy then decides).
- `Env.HTTP` reaches the registry through the upstream's transport (egress allowlist, TLS
  policy and pins), paced by `requestsPerSecond`; `Env.Read` fetches a path of the mount
  through the gated pipeline (a metadata document as clients see it); `Env.Dir` is a directory
  of the adapter's own, backed up with the state — file by file, so a cursor that does not
  match the files there must be detected and answered with `ErrCursorInvalid`.

Most of that is done for an adapter whose registry fits a pattern. One for a complete index
supplies an `indexSource` — how to read the index, conditionally, into records — and embeds
`indexFeed` (`pollfeed.go`), which keeps the copies (`snapshot.go`), the cursor and the
differences; one for a newest-first listing supplies a `listingSource` and embeds `listingFeed`
(`listfeed.go`); one for a Git-built index uses `gitIndex` (`gitfeed_tree.go`). Large documents
are read with `kit.getStream` and `openContent` (`decompress.go`), as streams, never whole.

## Private and self-hosted upstreams

When an upstream is Artifactory, Nexus or a self-hosted server rather than the public
registry, the public feed does not apply. A remote (proxy) repository answers clients'
requests, but neither Artifactory nor Nexus documents relaying its upstream's change feed.
What they offer instead (Artifactory's AQL with a `modified` filter, Nexus's components API
and repository webhooks) enumerates only what that server hosts or has cached. A few
self-hosted servers do have a feed of their own: devpi replication, the `/index` of Athens,
openvsx-server's mirror mode, and GitLab and Gitea system hooks. Each section says what is
known for its ecosystem.

## How the entries were checked

Every feed carries a *Checked live* line: a request made on 2026-11-15 from a single host,
saying what was asked and what came back. Most requests were a HEAD, a byte range or a few
KB. Where a figure needed a whole document (a sitemap, a name list, a channel's store paths,
Fedora's size listing, Hackage's index), that document was read once. The downloaded data was
kept in a throwaway directory, outside the repository. Rate
limits, terms and sizes come from the sources listed under each entry. "Not documented" means
nothing was found in the vendor's documentation, not that the feature is proven absent.
Registries change, so re-check an entry before relying on one of its numbers.

Three findings concern this proxy itself:

- Current Fedora repositories publish `primary.xml` only as zstd and zchunk, and the `yum`
  backend decoded only gzip: against them it recorded no package digests and served RPMs
  unverified. Fixed in Task 191: the backend now decodes gzip, xz and zstd primaries, as a
  stream (see the [yum](#yum) section).
- **Open:** the `apt` backend verifies a `.deb` only against a `Packages` index it has itself
  served, fetched by name and plain, gzip or bzip2. APT clients fetch the indexes by hash, and
  the full mirror fetches `.deb`s without reading an index through the proxy, so in both cases
  `.deb`s are served and cached without that check (counted by
  `pullthrough_apt_checksum_missing_total`). The apt feed adapter verifies every `Packages`
  file it reads against the suite's `InRelease`, but it only chooses which paths to fetch;
  closing the gap needs the backend to read the index itself (or the mirror to hand the
  index's digest to the fetch).
- The `yum` example in [backends.md](backends.md) points at Fedora 40 on
  dl.fedoraproject.org, whose `repomd.xml` now answers 404 (the release directory keeps only a
  README): Fedora moved the release to archives.fedoraproject.org when it reached its end of
  life.

<!-- BEGIN GENERATED: full-mirroring catalog. Regenerate with `make full-mirroring-reference-gen`; source: internal/fullmirror (catalog.go, catalog_data.go). -->

## Summary

One row per upstream type. **How to follow it** names the type's best feed; every feed, with its endpoint and the
live check that confirmed it, is in the type's section below. **Implementation status** is filled in as the
full-mirror engine and its feed adapters land.

| Type | Registry | Tier | How to follow it | Cursor | Full-mirror size | Implementation status |
|---|---|---|---|---|---|---|
| [`ansible`](#ansible) | [galaxy.ansible.com](https://galaxy.ansible.com) | **(c)** paginated listings only | collection versions, newest first | page | 4,686 collections, 54,484 collection versions; 37,920 roles | implemented (Task 191: follows the collection-version search (`order_by=-pulp_created`, `distribution_base_path` = the upstream's `repository`) down to a high-water mark and a day below it, versions younger than feed option `settle` held back (default 10m), after enumerating the repository's collection index; a search that lists nothing while the index lists collections fails. Versions from the versions list read from the registry (the pipeline takes no query). Roles are not followed. Feed option `url` names a Galaxy NG for an Artifactory or Nexus remote.) |
| [`apt`](#apt) / `deb` | [deb.debian.org/debian](https://deb.debian.org/debian) | **(b)** complete index to poll and diff | Release and Packages indexes | validator | Debian: 5,451 GB for every architecture, about 1,340 GB for amd64 + all + source; Ubuntu: about 3.6 TB | implemented (Task 191: polls each suite's `InRelease` (or `Release`) conditionally and reads, by hash and verified, the `Packages` indexes whose SHA-256 changed, diffing a stored copy; versions and files from the index itself (dpkg order). Feed options `suites` (required), `components` (default `main`), `architectures` (default `amd64`; `all` reads `binary-all` where the Release lists it, and is skipped where it does not, as on Ubuntu), `url` (another archive root). The apt backend verifies a `.deb` only against a `Packages` file it served by name: mirrored `.deb`s are cached without that check (see the findings below).) |
| [`bazel`](#bazel) | [bcr.bazel.build](https://bcr.bazel.build) | **(a)** incremental change feed | BCR commits | commit | metadata only; the archives live at their upstream URLs | implemented (Task 190: diffs the trees of bazel-central-registry's head commits once they have settled (feed option `settle`, default 10m), one change per version directory; versions from metadata.json read through the proxy, each with MODULE.bazel, the source archive and the patches and overlay files its source.json lists. Another registry needs feed option `url`, its Git repository.) |
| [`cargo`](#cargo) | [index.crates.io](https://index.crates.io) | **(a)** incremental change feed | Git index commits | commit | 378,819 crates; more than 100 GB of crate files already in 2022 | implemented (Task 190: diffs the trees of the Git index's head commits (a blob-less smart-HTTP fetch, unaffected by the weekly squash); versions from the sparse index read through the proxy. A private registry needs feed option `url`, its Git index.) |
| [`composer`](#composer) | [repo.packagist.org](https://repo.packagist.org) | **(a)** incremental change feed | metadata changes | timestamp | 481,164 packages, 6,077,934 versions (metadata only) | implemented (Task 190: follows Packagist `metadata/changes.json` from the stored `since` (a `resync` means a new enumeration from `packages/list.json`), `~dev` documents skipped; versions from `/p2/<vendor>/<package>.json` read through the proxy, metadata older than its update retried. A repository other than Packagist needs feed option `url`, a Packagist-compatible site.) |
| [`conan`](#conan) | [center2.conan.io](https://center2.conan.io) | **(a)** incremental change feed | conan-center-index commits | commit | 9,729 recipe versions of 1,943 libraries; binaries not counted | implemented (Task 190: diffs the trees of conan-center-index's head commits once they have settled (feed option `settle`, default 1h), one change per recipe; versions from the remote's recipe search, each with the files of its latest recipe revision read through the proxy, binary packages per feed option `binaries` (none, all, or settings to match). Another remote needs feed option `url`, a Git repository laid out as conan-center-index.) |
| [`conda`](#conda) | [conda.anaconda.org/conda-forge](https://conda.anaconda.org/conda-forge) | **(b)** complete index to poll and diff | repodata per subdir | validator | more than 3 TB (all subdirs; an old vendor figure) | implemented (Task 191: polls each followed subdir's `repodata.json.zst` (`repodata.json` where there is none, the `.zst` asked for again at every poll; a 403 counts as not found, as S3 answers) conditionally and diffs it against a stored copy, an unchanged subdir copied rather than read again, one that stops answering kept for 3 polls; a file is reported once listed for feed option `settle` (default 30m, from the poll that first saw it), so that the plain `repodata.json` the backend verifies against lists it. Versions from the stored copy, each with every file (every build, both formats) of the subdirs followed. Feed options `subdirs` (default noarch, linux-64, linux-aarch64, osx-64, osx-arm64, win-64), `index` (`repodata`, or `current`: `current_repodata.json`, the latest versions only), `settle` and `url` (another channel).) |
| [`cpan`](#cpan) | [cpan.metacpan.org](https://cpan.metacpan.org) | **(a)** incremental change feed | RECENT files | timestamp | about 40 GB (all of CPAN); about 1 GB for the latest releases only | implemented (Task 190: follows `RECENT-1h.json` from the stored epoch (a longer interval file when the cursor is older than its `minmax.min`; a changed `dirtymark`, or a cursor no file within the read bound reaches, means a new enumeration) after listing what `02packages.details.txt.gz` indexes; an upload is reported once its author directory's `CHECKSUMS` is rewritten, and its versions come from that `CHECKSUMS` read through the proxy. Names are `AUTHOR/Distribution`. Feed option `url` names a full mirror for a minicpan or Pinto upstream.) |
| [`cran`](#cran) | [cloud.r-project.org](https://cloud.r-project.org) | **(b)** complete index to poll and diff | PACKAGES index | validator | about 410 GB (sources, archive and binaries) | implemented (Task 191: polls `src/contrib/PACKAGES.gz` (`PACKAGES` where there is none, `PACKAGES.gz` asked for again at every poll; a 403 counts as not found) conditionally and diffs it against a stored copy; a version is reported once listed for feed option `settle` (default 45m, from the poll that first saw it; the version it supersedes is kept meanwhile), so that the plain `PACKAGES` the backend verifies against lists it. Each package's current version from the stored copy, with its source tarball where R downloads it. Archived versions (listed only in `Meta/archive.rds`) and Windows/macOS binaries are not followed. Feed options `settle` and `url` (another repository root).) |
| [`dart`](#dart) / `pub` | [pub.dev](https://pub.dev) | **(c)** paginated listings only | packages by publish time | page | 95,662 packages; bytes not published | implemented (Task 191: follows the Atom feed of the 100 newest versions down to a high-water mark, and the live `/packages.json` listing where the feed does not reach back (the document of a page's last package tells where to stop; a page boundary pub.dev's instances may disagree on is kept in the cursor and looked at again 35 minutes later), by package name, versions younger than feed option `settle` held back (default 5m; 2h30m when the upstream is a server in front of pub.dev); Bootstrap lists `/api/package-names` and the feed's packages. Versions from the package document read through the proxy, retracted ones as yanked. Another pub server needs feed option `url`, a site that serves pub.dev's feed and listings.) |
| [`docker`](#docker) | [registry-1.docker.io](https://registry-1.docker.io) | **(d)** no practical enumeration | tags of a named repository (partial) | validator | not published | not started (no registry-wide feed to follow) |
| [`generic`](#generic) | operator-defined | **(d)** no practical enumeration | — | — | operator-defined | not applicable (operator-defined upstream) |
| [`git`](#git) | [github.com](https://github.com) | **(d)** no practical enumeration | refs of a named repository (partial) | commit | not applicable | partial (named repositories are followed for the commit scan: `scanning.watch`) |
| [`go`](#go) | [proxy.golang.org](https://proxy.golang.org) | **(a)** incremental change feed | module index | timestamp | 71.4 million module versions checksummed; no byte total published | implemented (Task 190: replays the module index from its start, then follows it by timestamp (the records already reported at the stored instant are dropped); tagged versions only, pseudo-versions are left to client pulls. Versions from `@v/list` read through the proxy. Other upstreams are taken to serve Athens' `/index`; feed option `url` names another index.) |
| [`hackage`](#hackage) | [hackage.haskell.org](https://hackage.haskell.org) | **(a)** incremental change feed | index tarball tail | byte offset | 20.4 GB of package tarballs (155,731 package versions); the index is 1.05 GB | implemented (Task 190: follows `01-index.tar` with Range requests from the stored end (the hash of the last entry's header detects a replaced index), a change per new `package.json`, after listing `/packages/`; versions from `/package/{name}/preferred`, read from the repository (the backend serves neither JSON document), sdists in the short form clients request. Feed option `url` names a hackage-server for a static mirror.) |
| [`helm`](#helm) | [charts.bitnami.com/bitnami](https://charts.bitnami.com/bitnami) | **(b)** complete index to poll and diff | repository `index.yaml` | validator | per repository (Bitnami's index alone is 27.6 MB) | implemented (Task 191: polls the repository's `index.yaml` conditionally (ETag/Last-Modified, redirects followed) and diffs it against a stored copy, one record per chart version (`created` left out: an index regenerated without `--merge` re-reports nothing); the index is read as a stream (one of at most 8 MiB the streaming reader does not handle is read whole with yaml.v3, a larger one is refused). A version is reported once listed for feed option `settle` (default 15m, from the poll that first saw it), so that the index the backend reads lists it too. Versions from the stored copy, each with its archive at the path the backend's rewritten index hands clients. Feed option `url` names another copy of the index; an OCI upstream (setting `oci`) cannot be followed.) |
| [`hex`](#hex) | [repo.hex.pm](https://repo.hex.pm) | **(b)** complete index to poll and diff | names and versions | validator | not published | implemented (Task 191: polls the signed `/names` and `/versions` with conditional requests and diffs `/versions`, one change per version added, retired or gone; versions and their tarballs from the copy, retired versions yanked. `/versions` must verify (hex.pm's key, which also signs its organisations' repositories; feed option `publicKey` names another, or `none`) and name the repository (`hexpm`, an organisation's own name; feed option `repository`); `/names` gives only the head time. Feed option `url` names another repository.) |
| [`homebrew`](#homebrew) | [formulae.brew.sh](https://formulae.brew.sh) | **(a)** incremental change feed | homebrew-core commits | commit | not published | implemented (Task 190: diffs the Formula trees of homebrew-core's head commits once they have settled (feed option `settle`, default 30m); the current version from the formula JSON read through the proxy, one artifact per bottle (feed option `platforms` keeps some; disabled formulae are skipped). Task 191: a mirror of the JSON API is followed through its formula index, `/api/formula.json`, polled conditionally and diffed, one change per version added or rebottled; the version and its bottles from the copy of the index, at the paths the backend rewrites them to (feed option `mode`: `auto`, the default, `git` or `index`).) |
| [`huggingface`](#huggingface) | [huggingface.co](https://huggingface.co) | **(c)** paginated listings only | repositories by last modification | page | more than 20 PB | partial (Task 191: follows the listing by last modification (`/api/models`, or datasets or spaces per feed option `kind`) for the scope feed options `author` (comma-separated, at most 32, one listing each, read in turn down to the mark's lookback window) and/or `search` name — the whole Hub is not enumerated; hf.co's listing is read at huggingface.co. The files of the commit main is at, from the metadata read through the proxy (feed option `files` keeps some; gated and private repositories are skipped unless feed option `restricted` is `include`). Feed option `url` names the listing API for an upstream that is not the Hub.) |
| [`jsr`](#jsr) | [jsr.io](https://jsr.io) | **(c)** paginated listings only | package list | page | 23,228 packages; bytes not published | implemented (Task 191: reads every page of the management API's package list at each poll, to its first empty page, into a copy diffed against the last (a publish moves the version count, not `updatedAt`), changes by package; versions from `meta.json` and their module files from each version's manifest, read through the proxy (every package's file lists kept: a publish reads the new version's manifest only). Another upstream needs feed option `url`, an API that lists packages as api.jsr.io does.) |
| [`julia`](#julia) | [pkg.julialang.org](https://pkg.julialang.org) | **(a)** incremental change feed | General registry commits | commit | not published | implemented (Task 190: diffs the Pkg server's registry snapshots (`/registries` in the flavour of feed option `flavor`, `conservative` or `eager`): each new registry tree is read through the proxy and its `Registry.toml` and `Versions.toml` files indexed in the state directory; versions from the stored index, package tarballs by uuid and git-tree-sha1. Package artifacts are not followed.) |
| [`maven`](#maven) | [repo1.maven.org/maven2](https://repo1.maven.org/maven2) | **(b)** complete index to poll and diff | Maven Indexer index | validator | not published | partial (Task 191: follows a repository manager's Maven Indexer index (`<url>/.index/`): the properties file read conditionally, the chunks after the stored one applied to the stored copy while its chain lasts (a chunk gone or malformed, a full index older than the properties, or another `classifiers` selection makes it a full read), otherwise the full index streamed and diffed; releases from the stored copy, each document standing for its file and its release's POM (a POM alone for the main artifact its packaging names), classifiers per feed option `classifiers`, snapshots skipped. Maven Central itself is refused, by its host names (Google's copies too) and at every read by its index id `central` or its chain id: its terms forbid mirroring it. Feed option `url` names another index directory.) |
| [`nix`](#nix) | [cache.nixos.org](https://cache.nixos.org) | **(d)** no practical enumeration | channel store paths (partial) | validator | 636 TB, more than 1 billion objects | not started (no registry-wide feed to follow) |
| [`npm`](#npm) | [registry.npmjs.org](https://registry.npmjs.org) | **(a)** incremental change feed | replication feed (`_changes`) | sequence | 4.6 million packages; no published byte total | implemented (Task 190: follows `_changes` from the stored sequence (one beyond `update_seq` means a reset and a new enumeration) after listing `_all_docs`; versions from the packument read through the proxy. Feed option `url` names a CouchDB replica for a private registry.) |
| [`nuget`](#nuget) | [api.nuget.org](https://api.nuget.org) | **(a)** incremental change feed | catalog | timestamp | 594,190 packages, 14,044,198 versions; no byte total published | implemented (Task 190: follows the catalog (`Catalog/3.0.0` of the service index) by commit timestamp: the pages committed after the cursor, their newer leaves in commit order, each batch ending at a commit boundary and at commits older than feed option `settle` (default 10m: the flat container lists a version minutes after the catalog commits it); a cursor beyond the last commit (a rebuilt catalog) means a new replay from the first page. Versions from the flat container read through the proxy. Feed option `url` names a catalog index for a feed whose service index names none (Artifactory, Nexus, Azure Artifacts, GitHub Packages).) |
| [`openvsx`](#openvsx) | [open-vsx.org](https://open-vsx.org) | **(b)** complete index to poll and diff | sitemap | validator | 21,414 extensions; bytes not published | implemented (Task 191: polls the sitemap (conditionally, where the server sends validators) and diffs it, one change per extension whose date moved; the search listing by time, read at every poll, adds second publications on a day (a server re-dating every extension, as one in mirror mode does, is recognised). Versions from each target platform's version listing, up to 2,000 a platform, past pre-release lines; one `.vsix` per version and platform (feed option `platforms` keeps some). Feed option `url` names another sitemap.) |
| [`pip`](#pip) | [pypi.org](https://pypi.org) | **(a)** incremental change feed | XML-RPC changelog | sequence | 51.6 TB (every file of every release) | implemented (Task 190: follows the XML-RPC changelog from the stored serial (one beyond `changelog_last_serial` means a reset and a new enumeration), rows older than feed option `settle` (default 5m: a release's simple page can reach the CDN later), after listing the PEP 691 project list; feed option `mode` `simple`, the fallback where XML-RPC is missing, diffs every project's `_last-serial` against a stored copy instead. Versions from the simple page read through the proxy; names are PEP 503-normalized. Feed option `url` names another Warehouse.) |
| [`puppet`](#puppet) | [forgeapi.puppet.com](https://forgeapi.puppet.com) | **(c)** paginated listings only | releases by date | page | 7,707 modules, 54,827 releases; about 3 GB (estimate) | implemented (Task 191: follows `/v3/releases?sort_by=release_date` down to a high-water mark and a day below it, by module name, releases younger than feed option `settle` held back (default 90m: the CDN serves module documents up to an hour old; 3h30m when the upstream is a server in front of the Forge), after enumerating the modules from the same listing sorted by module; versions from the module document read through the proxy, deleted releases as yanked, premium and login-required modules only with credentials. Feed option `url` names the Forge for an Artifactory remote.) |
| [`rubygems`](#rubygems) | [rubygems.org](https://rubygems.org) | **(a)** incremental change feed | compact index `/versions` | byte offset | 198,697 gems; no byte total published | implemented (Task 190: follows the compact index `/versions` with Range requests from the end of a stored copy (If-None-Match, Repr-Digest checked); a digest mismatch, a torn tail or another `created_at` (the monthly rewrite) fetches the whole file and diffs it against the copy. Versions from `/info/<gem>` read through the proxy, platform gems as files of their version. Feed option `url` names another compact-index base.) |
| [`swift`](#swift) | [tuist.dev/api/registry/swift](https://tuist.dev/api/registry/swift) | **(d)** no practical enumeration | Swift Package Index package list (partial) | commit | about 10,000 packages and 160,000 releases | not started (no registry-wide feed to follow) |
| [`terraform`](#terraform) | [registry.terraform.io](https://registry.terraform.io) | **(c)** paginated listings only | module listing | page | 7,761 providers, 24,770 modules; provider binaries are on GitHub | not applicable (no feed adapter (Task 191): the listings name only each module's and provider's latest version, so a new version surfaces only in a full pass over both listings (about 330 requests) and a version list per changed entry, and provider binaries are GitHub release assets outside the registry; full mirroring is refused, and tracked repositories pin the providers their lock files name) |
| [`yum`](#yum) / `rpm` | [dl.fedoraproject.org/pub/fedora/linux](https://dl.fedoraproject.org/pub/fedora/linux) | **(b)** complete index to poll and diff | repomd.xml and primary | validator | 4.7 TB for all of Fedora Linux; one release's `Everything/x86_64` tree about 250 GB, plus 145 GB of its updates | implemented (Task 191: polls `repodata/repomd.xml` conditionally and, when its primary changed, streams the primary (zstd, gzip or xz; size and checksums verified) into a stored copy it diffs; versions (`[epoch:]version-release`, rpm order) and files from the primary itself. One upstream is one repository root; feed option `url` names another mirror of it.) |

## Types by tier

- **(a) incremental change feed** (13): [`bazel`](#bazel), [`cargo`](#cargo), [`composer`](#composer), [`conan`](#conan), [`cpan`](#cpan), [`go`](#go), [`hackage`](#hackage), [`homebrew`](#homebrew), [`julia`](#julia), [`npm`](#npm), [`nuget`](#nuget), [`pip`](#pip), [`rubygems`](#rubygems)
- **(b) complete index to poll and diff** (8): [`apt`](#apt) / `deb`, [`conda`](#conda), [`cran`](#cran), [`helm`](#helm), [`hex`](#hex), [`maven`](#maven), [`openvsx`](#openvsx), [`yum`](#yum) / `rpm`
- **(c) paginated listings only** (6): [`ansible`](#ansible), [`dart`](#dart) / `pub`, [`huggingface`](#huggingface), [`jsr`](#jsr), [`puppet`](#puppet), [`terraform`](#terraform)
- **(d) no practical enumeration** (5): [`docker`](#docker), [`generic`](#generic), [`git`](#git), [`nix`](#nix), [`swift`](#swift)

### Tiers

| Tier | Meaning |
|---|---|
| **(a)** incremental change feed | The registry publishes its changes in order; the follower stores a cursor and asks for what came after it. Cheap per poll, nothing is missed while the cursor stays valid. |
| **(b)** complete index to poll and diff | The registry publishes its complete current state; the follower re-reads it (conditionally, or through a delta where one exists) and diffs it against its previous copy. |
| **(c)** paginated listings only | The registry only answers paginated listings; the follower pages until it reaches what it has seen, or reads the whole listing when it is not sorted by time. |
| **(d)** no practical enumeration | The registry cannot be enumerated; only what clients request, or a partial feed (one channel, the repositories one names), can be mirrored ahead of time. |

### Cursor kinds

| Cursor | What the follower stores |
|---|---|
| sequence | an integer the registry assigns to every change, in order |
| timestamp | the registry's time stamp of the last change processed (never the follower's clock) |
| commit | a commit of the Git repository the registry is built from |
| byte offset | the length of an append-only file already read; the rest comes with an HTTP Range request |
| validator | the ETag, Last-Modified or digest of the index copy held, plus that copy to diff against |
| page | a position in a listing (page, offset or opaque cursor) and the newest item already seen |

## Registries

### ansible

**Ansible Galaxy** — upstream type `ansible`, registry <https://galaxy.ansible.com>. Tier **(c) paginated listings only**. Implementation: implemented (Task 191: follows the collection-version search (`order_by=-pulp_created`, `distribution_base_path` = the upstream's `repository`) down to a high-water mark and a day below it, versions younger than feed option `settle` held back (default 10m), after enumerating the repository's collection index; a search that lists nothing while the index lists collections fails. Versions from the versions list read from the registry (the pipeline takes no query). Roles are not followed. Feed option `url` names a Galaxy NG for an Artifactory or Nexus remote.).

**Feeds**

- **collection versions, newest first** — cursor: page

  `https://galaxy.ansible.com/api/v3/plugin/ansible/search/collection-versions/?order_by=-pulp_created&limit=100&offset={offset}`

  Galaxy NG's search lists every collection version newest first by `pulp_created`, with `meta.count` and `links.next`; page from offset 0 until a version already seen, overlapping pages because offsets shift. `is_highest=true` gives one row per collection. Each version's metadata and artifact then come through the v3 API.

  *Checked live:* 2026-11-15: `limit=2` → `meta.count` 54,484, newest created 21:46Z; the collections index refused `ordering=-updated_at` (400, not an available choice).

**Rate limits.** None documented; Galaxy sits behind Cloudflare and sent no rate-limit headers.

**Terms of use.** No mirroring clause found. Red Hat requires a requirements file when Automation Hub syncs from galaxy.ansible.com, "to prevent customers from syncing everything in galaxy" — a sign that full syncs are unwelcome.

**Full-mirror size.** 4,686 collections, 54,484 collection versions; 37,920 roles. Live counts on 2026-11-15. Roles are GitHub repositories, not files on Galaxy; collection bytes are not published.

**Private and self-hosted upstreams.** Private Automation Hub, galaxy_ng and pulp_ansible serve the same v3 API, and sync from Galaxy with a requirements file or (pulp_ansible 0.30 and later) `sync_highest_versions`. Artifactory has Ansible local/remote/virtual repositories and Nexus an Ansible Galaxy format; whether they answer the search endpoint is not documented.

**Sources.** [pulp_ansible: collections](https://pulpproject.org/pulp_ansible/docs/user/guides/collections/) · [Automation Hub: requirements file for galaxy.ansible.com remotes (AAH-2280)](https://issues.redhat.com/browse/AAH-2280)

### apt

**Debian / Ubuntu APT archives** — upstream type `apt` (also `deb`), registry <https://deb.debian.org/debian>. Tier **(b) complete index to poll and diff**. Implementation: implemented (Task 191: polls each suite's `InRelease` (or `Release`) conditionally and reads, by hash and verified, the `Packages` indexes whose SHA-256 changed, diffing a stored copy; versions and files from the index itself (dpkg order). Feed options `suites` (required), `components` (default `main`), `architectures` (default `amd64`; `all` reads `binary-all` where the Release lists it, and is skipped where it does not, as on Ubuntu), `url` (another archive root). The apt backend verifies a `.deb` only against a `Packages` file it served by name: mirrored `.deb`s are cached without that check (see the findings below).).

**Feeds**

- **Release and Packages indexes** — cursor: validator

  `https://deb.debian.org/debian/dists/{suite}/InRelease`

  `InRelease` (signed) lists every index of the suite with its size and hashes; `{component}/binary-{arch}/Packages.xz` lists every package with its `Filename`, size and SHA-256. Poll `InRelease` with a conditional request; when it changed, fetch the changed `Packages` files (by hash, `Acquire-By-Hash: yes`) and diff. The archive is published four times a day; stable changes only at point releases and is updated in between through `{codename}-updates` and the security archive.

  *Checked live:* 2026-11-15: stable `InRelease` → 140 KB, Debian 13.7 (trixie) of 2026-09-12 with `Acquire-By-Hash: yes`; `main/binary-amd64/Packages.xz` → 9,678,380 bytes; Ubuntu's `noble/InRelease` → 200.

- **index diffs (pdiffs)** — cursor: validator

  `https://deb.debian.org/debian/dists/{suite}/{component}/binary-{arch}/Packages.diff/Index`

  Ed-style patches from earlier `Packages` files to the current one, keyed by each earlier file's SHA-256: a follower holding a recent copy downloads a few KB instead of the whole index. Published for suites that change between point releases (unstable, testing, the -updates suites).

  *Checked live:* 2026-11-15: unstable's `Packages.diff/Index` → history back to 2026-11-02, four entries a day; stable has none (404).

**Rate limits.** None published for deb.debian.org.

**Terms of use.** Debian's mirroring guide prescribes ftpsync over rsync from an upstream mirror ("Do not use your own scripts, and do not just use single-pass rsyncs") and advises against service names that resolve to several addresses (its example is ftp.us.debian.org; the CDN name deb.debian.org is one too). A follower that polls one suite's `InRelease` over HTTP is a cache, not what the guide calls a mirror.

**Full-mirror size.** Debian: 5,451 GB for every architecture, about 1,340 GB for amd64 + all + source; Ubuntu: about 3.6 TB. https://www.debian.org/mirror/size (updated daily, read 2026-11-15); Ubuntu's mirror documentation (September 2025).

**Private and self-hosted upstreams.** A private APT repository (aptly, Pulp, Artifactory, Nexus) publishes the same Release/Packages layout for what it holds, so the same poll applies. Artifactory's AQL (a `created`/`modified` filter) and Nexus's components REST API (continuation token) and repository webhooks enumerate only what such a server hosts or has cached; neither documents relaying its upstream's feed.

**Notes**

- `Packages` lists current versions only: a superseded version drops out of the index (snapshot.debian.org keeps the history), so a mirror that wants every version keeps what it fetched.

**Sources.** [Debian: setting up a mirror](https://www.debian.org/mirror/ftpmirror) · [Debian: mirror size](https://www.debian.org/mirror/size) · [Ubuntu release team: mirrors](https://documentation.ubuntu.com/project/release-team/mirrors)

### bazel

**Bazel Central Registry (BCR)** — upstream type `bazel`, registry <https://bcr.bazel.build>. Tier **(a) incremental change feed**. Implementation: implemented (Task 190: diffs the trees of bazel-central-registry's head commits once they have settled (feed option `settle`, default 10m), one change per version directory; versions from metadata.json read through the proxy, each with MODULE.bazel, the source archive and the patches and overlay files its source.json lists. Another registry needs feed option `url`, its Git repository.).

**Feeds**

- **BCR commits** — cursor: commit

  `https://github.com/bazelbuild/bazel-central-registry`

  bcr.bazel.build is a static tree built from this repository: a new version is a commit adding `modules/{name}/{version}/` (`MODULE.bazel`, `source.json`) and listing it in `modules/{name}/metadata.json`. Diff the stored commit against the new head; each new `source.json` names the source archive (mostly a GitHub release or tag archive) and its SRI `integrity`, which is what Bazel downloads.

  *Checked live:* 2026-11-15: `git ls-remote` → HEAD 4410f9ba…; `bazel_registry.json` → `{"mirrors": []}`; `modules/rules_go/metadata.json` lists its versions.

**Rate limits.** None documented for bcr.bazel.build; the Git feed and most source archives are on GitHub, whose unauthenticated limits apply.

**Terms of use.** None found. Bazel documents `mirrors` in `bazel_registry.json` and `mirror_urls` in `source.json` for mirroring source archives.

**Full-mirror size.** Metadata only; the archives live at their upstream URLs. The registry protocol stores no archives. Count: the directories under `modules/`; bytes: the archives every `source.json` names (not computed).

**Private and self-hosted upstreams.** A self-hosted registry is any static tree, Git repository or `file://` path with the same layout — no listing either. Artifactory has a remote-only Bazel Modules repository; Nexus has no Bazel format.

**Notes**

- The registry protocol has no list of modules and no feed; only the Git history enumerates it.

**Sources.** [Bazel registries](https://bazel.build/external/registry) · [bazelbuild/bazel-central-registry](https://github.com/bazelbuild/bazel-central-registry)

### cargo

**crates.io (Cargo)** — upstream type `cargo`, registry <https://index.crates.io>. Tier **(a) incremental change feed**. Implementation: implemented (Task 190: diffs the trees of the Git index's head commits (a blob-less smart-HTTP fetch, unaffected by the weekly squash); versions from the sparse index read through the proxy. A private registry needs feed option `url`, its Git index.).

**Feeds**

- **Git index commits** — cursor: commit

  `https://github.com/rust-lang/crates.io-index`

  The Git index "is updated live whenever new versions are published": each commit changes the index file of a crate (one JSON line per version with its `cksum`; a yank edits the line). Fetch, diff the stored commit against the new head and download `https://static.crates.io/crates/{name}/{name}-{version}.crate` for each new line. The history is squashed into one commit weekly; the old history moves to a `snapshot-YYYY-MM-DD` branch of rust-lang/crates.io-index-archive and the squash commit names the previous head, so a vanished cursor is recovered from the archive — or by diffing the two trees.

  *Checked live:* 2026-11-15: `git ls-remote` → HEAD 8d0b4b6f… and, a minute later, 534b96e5…; the repository has `master` and pull-request refs, no snapshot branches; crates.io-index-archive has `snapshot-2026-10-12`, `-10-19`, `-10-26`, `-11-02` and `-11-09`.

- **daily database dump** — cursor: validator

  `https://static.crates.io/db-dump.tar.gz`

  A PostgreSQL CSV dump published every 24 hours: every crate and version with its checksum and `crate_size`. The inventory to start a mirror from, and the way to compute its size.

  *Checked live:* 2026-11-15: HEAD → 307 to cloudfront-static.crates.io, `content-length: 2246923427`, `last-modified: Sun, 15 Nov 2026 02:07:43 GMT`.

- **sparse index (per crate)** (partial) — cursor: validator

  `https://index.crates.io/{prefix}/{name}`

  What cargo reads: one file per crate with `ETag`/`Last-Modified`, cached 10 minutes at the CDN. No listing and no change feed — for re-checking crates one already follows, not for discovering new ones.

  *Checked live:* 2026-11-15: HEAD `/an/yh/anyhow` → 200 with `etag`, `last-modified`, `cache-control: public,max-age=600`; `config.json` names `dl: https://static.crates.io/crates`.

**Rate limits.** The crates.io API: at most one request per second, with a User-Agent that identifies the client (contact details recommended). The index and static.crates.io are CDN-served; no limits are published for them.

**Terms of use.** The data-access policy sends bulk users to the index and the database dump instead of crawling the API; it says nothing about downloading crate files in bulk.

**Full-mirror size.** 378,819 crates; more than 100 GB of crate files already in 2022. `num_crates` from https://crates.io/api/v1/summary on 2026-11-15. The byte total is the sum of `crate_size` in the dump's versions table (not computed here); a third-party tool reported more than 100 GB for every version in 2022.

**Private and self-hosted upstreams.** Private Cargo registries (Artifactory's Cargo repositories, self-hosted servers) serve a sparse or Git index of their own; any history it has covers only what they host or have cached. Artifactory's AQL (a `created`/`modified` filter) and Nexus's components REST API (continuation token) and repository webhooks enumerate only what such a server hosts or has cached; neither documents relaying its upstream's feed.

**Sources.** [crates.io snapshot branches move to an archive repository (Rust blog, 2022)](https://blog.rust-lang.org/2022/02/14/crates-io-snapshot-branches/) · [Cargo's crate index: upcoming squash into one commit (internals)](https://internals.rust-lang.org/t/cargos-crate-index-upcoming-squash-into-one-commit/8440) · [RFC 3463: crates.io policy update (data access, crawler rules)](https://rust-lang.github.io/rfcs/3463-crates-io-policy-update.html) · [crates.io data access](https://crates.io/data-access)

### composer

**Packagist (Composer)** — upstream type `composer`, registry <https://repo.packagist.org>. Tier **(a) incremental change feed**. Implementation: implemented (Task 190: follows Packagist `metadata/changes.json` from the stored `since` (a `resync` means a new enumeration from `packages/list.json`), `~dev` documents skipped; versions from `/p2/<vendor>/<package>.json` read through the proxy, metadata older than its update retried. A repository other than Packagist needs feed option `url`, a Packagist-compatible site.).

**Feeds**

- **metadata changes** — cursor: timestamp

  `https://packagist.org/metadata/changes.json?since={since}`

  `since` is in units of 1/10000 s (`10000 * time()`); without it Packagist answers 400 with the current `timestamp` to start from. Actions: `update` (re-fetch `https://repo.packagist.org/p2/{vendor}/{package}.json`, or its `~dev.json`, and require `Last-Modified` at least the action's `time`), `delete`, and `resync` of `*` when the cursor is older than the log — "The changes log is kept for up to 24h", so poll at least daily or rebuild from the package list.

  *Checked live:* 2026-11-15: no `since` → 400 with `timestamp` 17947827250011; `since` one hour back → 200 with `update` actions (`phpsyntax/phpsyntax`, `cakephp/cakephp~dev`, …).

- **package list** — cursor: validator

  `https://packagist.org/packages/list.json`

  Every package name (filterable by `vendor` and `type`): the inventory for a first sync and after a `resync`.

  *Checked live:* 2026-11-15: HEAD → 200, `cache-control: public, s-maxage=300`.

**Rate limits.** "a maximum of 10 concurrent requests, or up to 20 if you only fetch static files"; spread the load, avoid the full hour, use HTTP/2 and `If-Modified-Since`.

**Terms of use.** Packagist asks for a User-Agent with contact details (`mailto=`) so it can reach a misbehaving client before blocking its IP. Packagist hosts metadata only: the archives are zipballs from GitHub, GitLab or Bitbucket, under their terms.

**Full-mirror size.** 481,164 packages, 6,077,934 versions (metadata only). https://packagist.org/statistics.json on 2026-11-15. The archives live on the VCS hosts; their total is not published.

**Private and self-hosted upstreams.** Satis builds a static repository without a change feed. Artifactory and Nexus Composer repositories document no `changes.json`. Artifactory's AQL (a `created`/`modified` filter) and Nexus's components REST API (continuation token) and repository webhooks enumerate only what such a server hosts or has cached; neither documents relaying its upstream's feed.

**Sources.** [Packagist API documentation](https://packagist.org/apidoc) · [Packagist statistics](https://packagist.org/statistics)

### conan

**ConanCenter (center2.conan.io)** — upstream type `conan`, registry <https://center2.conan.io>. Tier **(a) incremental change feed**. Implementation: implemented (Task 190: diffs the trees of conan-center-index's head commits once they have settled (feed option `settle`, default 1h), one change per recipe; versions from the remote's recipe search, each with the files of its latest recipe revision read through the proxy, binary packages per feed option `binaries` (none, all, or settings to match). Another remote needs feed option `url`, a Git repository laid out as conan-center-index.).

**Feeds**

- **conan-center-index commits** — cursor: commit

  `https://github.com/conan-io/conan-center-index`

  ConanCenter's recipes: a merged pull request changes `recipes/{name}/…`, then ConanCenter's CI exports a new recipe revision and builds binaries for center2 (the delay is not documented). Diff the stored commit, then ask center2 for the changed references' revisions (`/v2/conans/{name}/{version}/_/_/revisions`) until the new one appears.

  *Checked live:* 2026-11-15: `git ls-remote` → HEAD 6f3abb46…; `/v2/conans/zlib/1.3.1/_/_/revisions` → 200, revisions with times (latest 2025-12-09).

- **recipe search** (partial) — cursor: validator

  `https://center2.conan.io/v2/conans/search?q=*`

  Every recipe reference (`name/version@_/_`) in one response: new versions show up, a new revision of an existing version or new binaries do not.

  *Checked live:* 2026-11-15: `q=*` → 9,729 references (221 KB); `q=zlib*` → 24.

**Rate limits.** None documented.

**Terms of use.** No availability guarantee: Conan's documentation recommends hosting your own copy of the ConanCenter recipes and binaries you use. center.conan.io (Conan 1) has been frozen since November 2024.

**Full-mirror size.** 9,729 recipe versions of 1,943 libraries; binaries not counted. Live search on 2026-11-15 (Conan's documentation says "over 1500" libraries). Revision and binary counts and bytes are not published.

**Private and self-hosted upstreams.** Artifactory (Conan local/remote/virtual) and Nexus (Conan proxy/hosted/group) have Conan repositories; whether their search lists an upstream's references is not documented. Conan 2's `local-recipes-index` remote serves a clone of conan-center-index directly, which makes the Git history the feed.

**Sources.** [Conan Center will stop receiving updates for Conan 1 (2024-09-30)](https://blog.conan.io/2024/09/30/Conan-Center-will-stop-receiving-updates-for-Conan-1.html) · [Using ConanCenter (Conan 2 docs)](https://docs.conan.io/2/devops/using_conancenter.html) · [Introducing the local-recipes-index remote](https://blog.conan.io/2024/04/23/Introducing-local-recipes-index-remote.html)

### conda

**conda-forge (anaconda.org)** — upstream type `conda`, registry <https://conda.anaconda.org/conda-forge>. Tier **(b) complete index to poll and diff**. Implementation: implemented (Task 191: polls each followed subdir's `repodata.json.zst` (`repodata.json` where there is none, the `.zst` asked for again at every poll; a 403 counts as not found, as S3 answers) conditionally and diffs it against a stored copy, an unchanged subdir copied rather than read again, one that stops answering kept for 3 polls; a file is reported once listed for feed option `settle` (default 30m, from the poll that first saw it), so that the plain `repodata.json` the backend verifies against lists it. Versions from the stored copy, each with every file (every build, both formats) of the subdirs followed. Feed options `subdirs` (default noarch, linux-64, linux-aarch64, osx-64, osx-arm64, win-64), `index` (`repodata`, or `current`: `current_repodata.json`, the latest versions only), `settle` and `url` (another channel).).

**Feeds**

- **repodata per subdir** — cursor: validator

  `https://conda.anaconda.org/conda-forge/{subdir}/repodata.json.zst`

  Every package file of a subdir (`linux-64`, `noarch`, …) with its size and hashes; poll with ETag and diff. Uncompressed, linux-64 is 468 MB and noarch 196 MB (29.6 MB as zstd).

  *Checked live:* 2026-11-15: HEAD noarch `repodata.json` → 196,244,999 bytes, `.zst` → 29,637,890; linux-64 → 468,076,086; all modified within the previous 30 minutes.

- **sharded repodata index** — cursor: validator

  `https://conda.anaconda.org/conda-forge/{subdir}/repodata_shards.msgpack.zst`

  CEP-16: maps each package name to the SHA-256 of its shard (`shards/{sha256}.msgpack.zst`); a changed hash means that package changed, so a follower diffs a 1 MB index and fetches only the changed shards.

  *Checked live:* 2026-11-15: noarch shard index → 989,071 bytes, modified 22:29Z (the copy on fast.prefix.dev was last modified 2025-06-14).

**Rate limits.** None published.

**Terms of use.** conda-forge packages are free to use, including commercially. Anaconda's own `defaults` channels (repo.anaconda.com) fall under Anaconda's terms of service, which require a paid license for larger organisations; those terms do not cover conda-forge.

**Full-mirror size.** More than 3 TB (all subdirs; an old vendor figure). Anaconda's Package Security Manager mirroring documentation gives conda-forge 3 TB in the same sentence that gives PyPI 10 TB (51.6 TB today), and a 2021 conda-forge thread gave the same 3 TB. Exact: the sum of `size` over every subdir's repodata.

**Private and self-hosted upstreams.** Artifactory (Conda local/remote/virtual), Nexus (Conda proxy/hosted/group), Quetz and prefix.dev channels serve repodata for what they hold, so the same poll applies. Artifactory's AQL (a `created`/`modified` filter) and Nexus's components REST API (continuation token) and repository webhooks enumerate only what such a server hosts or has cached; neither documents relaying its upstream's feed.

**Notes**

- Measured on 2026-11-16: following conda-forge's six default subdirs reads 236 MB of zstd per poll that finds them all changed (about 1.6 GB of JSON, under a minute of CPU), and conda-forge changes every few minutes — about 17 GB a day at a 5-minute poll interval; `current_repodata.json` of the same subdirs is 41 MB.
- Incremental repodata patches (JLAP) are not served: `repodata.jlap` → 404 on 2026-11-15.

**Sources.** [conda: sharded repodata](https://docs.conda.io/projects/conda/en/stable/dev-guide/deep-dives/sharded.html) · [How we reduced conda's index fetch bandwidth by 99% (JLAP)](https://conda.discourse.group/t/how-we-reduced-condas-index-fetch-bandwidth-by-99/257) · [Anaconda Package Security Manager: mirrors](https://www.anaconda.com/docs/psm/on-prem/latest/admin/mirrors) · [conda-forge: total size of the conda-forge repo (2021)](https://groups.google.com/g/conda-forge/c/AlY_u8TCjO8)

### cpan

**CPAN (Perl)** — upstream type `cpan`, registry <https://cpan.metacpan.org>. Tier **(a) incremental change feed**. Implementation: implemented (Task 190: follows `RECENT-1h.json` from the stored epoch (a longer interval file when the cursor is older than its `minmax.min`; a changed `dirtymark`, or a cursor no file within the read bound reaches, means a new enumeration) after listing what `02packages.details.txt.gz` indexes; an upload is reported once its author directory's `CHECKSUMS` is rewritten, and its versions come from that `CHECKSUMS` read through the proxy. Names are `AUTHOR/Distribution`. Feed option `url` names a full mirror for a minicpan or Pinto upstream.).

**Feeds**

- **RECENT files** — cursor: timestamp

  `https://cpan.metacpan.org/RECENT-1h.json`

  File::Rsync::Mirror::Recent's event log: `{path, type: new|delete, epoch}` entries with unique, strictly decreasing epochs. `RECENT-1h` covers the last hour and is merged into `6h`, `1d`, `1W`, `1M`, `1Q`, `1Y` and `Z` (everything); poll the hour file and read a longer one when the stored epoch is older than its `minmax.min`. A changed `dirtymark` means a full re-sync. Distribution paths are under `authors/id/`.

  *Checked live:* 2026-11-15: `RECENT-1h.json` (4 KB) on cpan.metacpan.org and www.cpan.org → 31 events, produced by rrrgo v0.2.6; `RECENT-1Y.json` is 72.6 MB.

- **package index** (partial) — cursor: validator

  `https://cpan.metacpan.org/modules/02packages.details.txt.gz`

  Every indexed package with the distribution that provides it — the latest release only: the inventory of a minimal mirror (minicpan), not the history.

  *Checked live:* 2026-11-15: HEAD → 2,553,916 bytes, modified 22:17Z.

**Rate limits.** MetaCPAN asks API users to "be polite" (search requests return at most 5,000 hits). rsync mirrors of www.cpan.org are asked to sync "once or twice a day".

**Terms of use.** "We are not currently adding new public mirrors"; private mirrors rsync from `cpan-rsync.perl.org::CPAN`, and the mirroring page names rrr-client (the RECENT-file client) for near-instant mirroring.

**Full-mirror size.** About 40 GB (all of CPAN); about 1 GB for the latest releases only. www.cpan.org's mirroring page (undated). BackPAN, which also keeps releases deleted from CPAN, is not included.

**Private and self-hosted upstreams.** minicpan (CPAN::Mini) and Pinto build static repositories with no RECENT files. Artifactory and Nexus have no CPAN format.

**Sources.** [File::Rsync::Mirror::Recentfile](https://metacpan.org/pod/File::Rsync::Mirror::Recentfile) · [How to mirror CPAN](https://www.cpan.org/misc/how-to-mirror.html) · [MetaCPAN API documentation](https://github.com/metacpan/metacpan-api/blob/master/docs/API-docs.md)

### cran

**CRAN (R)** — upstream type `cran`, registry <https://cloud.r-project.org>. Tier **(b) complete index to poll and diff**. Implementation: implemented (Task 191: polls `src/contrib/PACKAGES.gz` (`PACKAGES` where there is none, `PACKAGES.gz` asked for again at every poll; a 403 counts as not found) conditionally and diffs it against a stored copy; a version is reported once listed for feed option `settle` (default 45m, from the poll that first saw it; the version it supersedes is kept meanwhile), so that the plain `PACKAGES` the backend verifies against lists it. Each package's current version from the stored copy, with its source tarball where R downloads it. Archived versions (listed only in `Meta/archive.rds`) and Windows/macOS binaries are not followed. Feed options `settle` and `url` (another repository root).).

**Feeds**

- **PACKAGES index** — cursor: validator

  `https://cloud.r-project.org/src/contrib/PACKAGES.gz`

  Every current source package with its version and MD5 sum; poll and diff. Superseded versions move to `src/contrib/Archive/{name}/` and are listed in `src/contrib/Meta/archive.rds` (an R serialised object). Windows and macOS binaries have a `PACKAGES` per R version.

  *Checked live:* 2026-11-15: `PACKAGES` 7,491,081 bytes, `PACKAGES.gz` 1,980,364 (both modified 21:42Z); `Meta/archive.rds` 5,584,516.

- **packages by date** (partial) — cursor: timestamp

  `https://cloud.r-project.org/web/packages/available_packages_by_date.html`

  Current packages sorted by publication date, as an HTML page.

  *Checked live:* 2026-11-15: 200, 4,986,460 bytes.

**Rate limits.** None published for cloud.r-project.org (sponsored by Posit). rsync mirrors sync "at least twice a week, better every 1-2 days, but not more than twice a day."

**Terms of use.** Mirrors rsync from cran.r-project.org (SSH recommended) and are listed once CRAN accepts them.

**Full-mirror size.** About 410 GB (sources, archive and binaries). CRAN mirror HOWTO: "The full size of CRAN was approx 410 GB on 2024-02-22".

**Private and self-hosted upstreams.** Posit Package Manager, miniCRAN, Artifactory (CRAN) and Nexus (R) serve `PACKAGES` for what they hold, so the same poll applies. Artifactory's AQL (a `created`/`modified` filter) and Nexus's components REST API (continuation token) and repository webhooks enumerate only what such a server hosts or has cached; neither documents relaying its upstream's feed.

**Sources.** [CRAN mirror HOWTO](https://cran.r-project.org/mirror-howto.html) · [CRAN mirrors](https://cran.r-project.org/mirrors.html)

### dart

**pub.dev (Dart and Flutter)** — upstream type `dart` (also `pub`), registry <https://pub.dev>. Tier **(c) paginated listings only**. Implementation: implemented (Task 191: follows the Atom feed of the 100 newest versions down to a high-water mark, and the live `/packages.json` listing where the feed does not reach back (the document of a page's last package tells where to stop; a page boundary pub.dev's instances may disagree on is kept in the cursor and looked at again 35 minutes later), by package name, versions younger than feed option `settle` held back (default 5m; 2h30m when the upstream is a server in front of pub.dev); Bootstrap lists `/api/package-names` and the feed's packages. Versions from the package document read through the proxy, retracted ones as yanked. Another pub server needs feed option `url`, a site that serves pub.dev's feed and listings.).

**Feeds**

- **packages by publish time** — cursor: page

  `https://pub.dev/api/packages?page={page}`

  100 packages per page with their latest version and pubspec, most recently published first (an undocumented endpoint that may change without notice); page until a package whose latest version is already known. `/api/packages/{name}` lists every version with its `archive_url` and `archive_sha256`.

  *Checked live:* 2026-11-15: page 1 → 100 packages, the first three published at 22:29Z, 22:29Z and 22:24Z (checked through `/api/packages/{name}`), `next_url` page 2.

- **newest versions (Atom feed)** (partial) — cursor: timestamp

  `https://pub.dev/feed.atom`

  The 100 most recently published versions, newest first (retracted and moderated versions left out), each entry `v{version} of {package}` with its publication time in `<updated>` and a changelog excerpt escaped for markup only (control characters can occur). Built from a datastore query and cached for three minutes, it covers two to four hours of publishing: a follower reads it at every poll and falls back to the listing after a longer pause.

  *Checked live:* 2026-11-16: 100 entries from 05:07:32Z to 07:23:56Z (2h16m, 87 packages), 80,092 bytes, `cache-control: no-store`.

- **package names** (partial) — cursor: validator

  `https://pub.dev/api/package-names`

  Every package name (to be cached "for at least 2 hours"; the order may change, so diff as a set): finds new packages, not new versions. Answers only clients that accept gzip (406 otherwise).

  *Checked live:* 2026-11-15: 95,662 names, 461,872 bytes gzipped.

**Rate limits.** None published.

**Terms of use.** No crawling policy found; the documented API is the name list and per-package metadata, and undocumented endpoints may change or disappear without notice.

**Full-mirror size.** 95,662 packages; bytes not published. Name count on 2026-11-15; the sum of the archives is not computed.

**Private and self-hosted upstreams.** The hosted-repository specification v2 has no listing endpoint, so spec-only servers (unpub, OnePub) are tier (d) unless they add one. Artifactory (Pub) and Nexus (Pub/Flutter proxy/hosted/group) support the format; a listing is not documented.

**Notes**

- pub.dev serves its package listings (`/api/packages`, `/packages.json`) from an in-memory list on each server instance, refreshed every 15 minutes, so consecutive pages can come from instances that disagree: five requests for page 1 within ten seconds came back in three different states on 2026-11-16. A pass over the listing can skip a package at a page boundary unless the boundary is checked again later.

**Sources.** [pub.dev API](https://pub.dev/help/api) · [Hosted pub repository specification v2](https://github.com/dart-lang/pub/blob/master/doc/repository-spec-v2.md)

### docker

**Docker Hub** — upstream type `docker`, registry <https://registry-1.docker.io>. Tier **(d) no practical enumeration**. Implementation: not started (no registry-wide feed to follow).

**Feeds**

- **tags of a named repository** (partial) — cursor: validator

  `https://registry-1.docker.io/v2/{namespace}/{repository}/tags/list?n=1000`

  Every tag of one repository, paged by `n` and `last` (`Link: …; rel="next"`); compare with the previous list and resolve the changed tags' manifests (HEAD requests do not count as pulls). Covers only the repositories one names.

  *Checked live:* 2026-11-15: `library/alpine/tags/list?n=3` with an anonymous pull token → 200 and a `Link` to the next page.

- **Hub search** (partial) — cursor: page

  `https://hub.docker.com/v2/search/repositories/?query={query}&page_size=100`

  Search, not enumeration: repositories matching a query, with pull counts.

  *Checked live:* 2026-11-15: `query=alpine` → `count` 104,570, `x-ratelimit-limit: 180`.

**Rate limits.** Pulls: Docker's usage page lists 100 per 6 hours per IPv4 address or IPv6 /64 without an account, 200 for personal accounts and unlimited for paid plans; the registry's own `ratelimit-limit` header on 2026-11-15 read `100;w=3600` (a one-hour window) for anonymous requests over IPv6 and IPv4. Plan on the documented figure; separate abuse limits answer 429.

**Terms of use.** Docker's terms (effective 2026-08-26) forbid automated access "except as permitted by Docker", transferring "excessive amounts of data", and using the service "to mirror or replicate content for an unauthorized commercial service".

**Full-mirror size.** Not published. Docker Hub publishes neither a catalog nor a storage figure.

**Private and self-hosted upstreams.** A self-hosted registry can be enumerated: `GET /v2/_catalog` (distribution, Harbor, Artifactory, Nexus; `n`/`last` paging in lexical order) plus `tags/list` make it tier (b), and Harbor and Quay can send a webhook on every push. GHCR and Quay.io do not list public repositories.

**Notes**

- An anonymous token for `registry:catalog:*` is refused (400) and `/v2/_catalog` answers 401.

**Sources.** [Docker Hub usage and limits](https://docs.docker.com/docker-hub/usage/) · [Docker terms of service](https://www.docker.com/legal/docker-terms-service/) · [OCI distribution specification](https://github.com/opencontainers/distribution-spec/blob/main/spec.md)

### generic

**Generic declarative upstreams** — upstream type `generic`, no public registry. Tier **(d) no practical enumeration**. Implementation: not applicable (operator-defined upstream).

**Feeds.** None.

**Rate limits.** Whatever the upstream sets.

**Terms of use.** Whatever the upstream's terms say.

**Full-mirror size.** Operator-defined. A generic upstream serves what its routes declare.

**Private and self-hosted upstreams.** Artifactory remote repositories can list the far side ("List Remote Folder Items", off by default since 7.93) and the Storage API lists folders for privileged users; Nexus raw repositories list hosted and cached content through the components API, not their upstream. A plain HTTP server with directory listings can be crawled and diffed (tier b).

**Notes**

- Nothing in a generic upstream's configuration says how to enumerate it; following one would need its own declaration (a listing URL and how to read it).

**Sources.** [Generic backend (this repository)](https://github.com/blechschmidt/pullthrough-security/blob/main/docs/generic-backend.md) · [Artifactory: remote list browsing](https://jfrog.com/help/r/jfrog-artifactory-documentation/remote-list-browsing) · [Nexus: components API](https://help.sonatype.com/en/components-api.html)

### git

**Git hosting (GitHub and other forges)** — upstream type `git`, registry <https://github.com>. Tier **(d) no practical enumeration**. Implementation: partial (named repositories are followed for the commit scan: `scanning.watch`).

**Feeds**

- **refs of a named repository** (partial) — cursor: commit

  `https://github.com/{owner}/{repository}`

  `git ls-remote` lists every ref with its commit; compare with the stored refs and fetch what moved. Covers the repositories one names — what the commit watcher (`scanning.watch`) already does.

  *Checked live:* 2026-11-15: `git ls-remote https://github.com/golang/go refs/tags/go1.23.0` → 6885bad7….

- **GitHub public events** (partial) — cursor: page

  `https://api.github.com/events?per_page=100`

  The latest 300 public events across GitHub, delayed "anywhere from 30s to 6h", polled with ETag at the `X-Poll-Interval`: a sample, not a feed.

  *Checked live:* 2026-11-15: `per_page=2` → last page 150 (300 events), `x-poll-interval: 60`, `x-ratelimit-limit: 60` without authentication.

**Rate limits.** GitHub's REST API: 60 requests an hour per IP without authentication, 5,000 with. GitHub tightened its limits for unauthenticated traffic in 2025 without publishing numbers; unauthenticated Git and raw downloads can be throttled.

**Terms of use.** Governed by GitHub's terms and Acceptable Use Policies (not reviewed for this page).

**Full-mirror size.** Not applicable. There is no registry to copy; a mirror holds the repositories one names.

**Private and self-hosted upstreams.** Self-hosted forges can send instance-wide events: GitLab system hooks (administrators only; by default not for a push of more than three branches or tags) and Gitea system webhooks ("all eligible activity on the instance"); Bitbucket Data Center has no built-in instance-wide webhook. On such an instance the git type is effectively tier (a).

**Sources.** [GitHub REST API: events](https://docs.github.com/en/rest/activity/events) · [GitHub REST API: rate limits](https://docs.github.com/en/rest/using-the-rest-api/rate-limits-for-the-rest-api) · [GitHub changelog: updated rate limits for unauthenticated requests (2025-05-08)](https://github.blog/changelog/2025-05-08-updated-rate-limits-for-unauthenticated-requests/) · [GitLab system hooks](https://docs.gitlab.com/administration/system_hooks/) · [Gitea webhooks](https://docs.gitea.com/usage/webhooks)

### go

**Go module mirror (proxy.golang.org)** — upstream type `go`, registry <https://proxy.golang.org>. Tier **(a) incremental change feed**. Implementation: implemented (Task 190: replays the module index from its start, then follows it by timestamp (the records already reported at the stored instant are dropped); tagged versions only, pseudo-versions are left to client pulls. Versions from `@v/list` read through the proxy. Other upstreams are taken to serve Athens' `/index`; feed option `url` names another index.).

**Feeds**

- **module index** — cursor: timestamp

  `https://index.golang.org/index?since={timestamp}&limit=2000`

  Newline-delimited `{Path, Version, Timestamp}` records "sorted in chronological order"; pass the last `Timestamp` back as `since` (RFC 3339, inclusive — drop the record already seen). `limit` defaults to and is capped at 2000. By default only versions the mirror has cached; `include=all` lists every version proxy.golang.org or sum.golang.org ever served. Then fetch `/{module}/@v/{version}.info`, `.mod` and `.zip`; new versions "should be available within one minute".

  *Checked live:* 2026-11-15: `limit=3` → the first records date from 2019-04-10; `since=2026-11-15T00:00:00Z&limit=3` → three records from 00:00:12Z; `limit=2000` → 2000 lines (232 KB); `limit=2500` → 400.

- **checksum database log** — cursor: sequence

  `https://sum.golang.org/latest`

  The transparency log of every module version's go.mod and zip hashes: `/latest` is the signed tree size, `/tile/…` the records in order, so the tree size is a resumable cursor over everything ever checksummed — including versions the mirror no longer caches.

  *Checked live:* 2026-11-15: `/latest` → `go.sum database tree`, size 71,436,673.

**Rate limits.** None documented.

**Terms of use.** There is no terms-of-service page; the privacy page (2019-08-06) says requests are logged and IP addresses kept no longer than 30 days. "proxy.golang.org does not save all modules forever."

**Full-mirror size.** 71.4 million module versions checksummed; no byte total published. sum.golang.org tree size on 2026-11-15 (each leaf is one module version). The mirror publishes no storage figure; tens of millions of module zips make a full copy many terabytes (estimate).

**Private and self-hosted upstreams.** Athens has an `/index` of its own (same format, `since`/`limit`, covering only what it has stored) and a `/catalog`. Every GOPROXY lists one module's versions at `/{module}/@v/list`. Artifactory and Nexus Go repositories document no index. Artifactory's AQL (a `created`/`modified` filter) and Nexus's components REST API (continuation token) and repository webhooks enumerate only what such a server hosts or has cached; neither documents relaying its upstream's feed.

**Notes**

- `https://proxy.golang.org/cached-only/…` serves only what the mirror already has, without fetching from the origin.

**Sources.** [index.golang.org](https://index.golang.org/) · [proxy.golang.org](https://proxy.golang.org/) · [proxy.golang.org privacy](https://proxy.golang.org/privacy) · [Go modules reference: checksum database](https://go.dev/ref/mod#checksum-database)

### hackage

**Hackage (Haskell)** — upstream type `hackage`, registry <https://hackage.haskell.org>. Tier **(a) incremental change feed**. Implementation: implemented (Task 190: follows `01-index.tar` with Range requests from the stored end (the hash of the last entry's header detects a replaced index), a change per new `package.json`, after listing `/packages/`; versions from `/package/{name}/preferred`, read from the repository (the backend serves neither JSON document), sdists in the short form clients request. Feed option `url` names a hackage-server for a static mirror.).

**Feeds**

- **index tarball tail** — cursor: byte offset

  `https://hackage.haskell.org/01-index.tar`

  Every package description and revision ever uploaded, appended in order (`.cabal` files, `package.json` with each tarball's hashes and length, preferred versions). Fetch from the stored length with a Range request — cabal's hackage-security does exactly that — and check the result against `snapshot.json` (TUF), which carries the index's length and hashes. The history is never rewritten. For each new `package.json` download `/package/{name}-{version}.tar.gz`.

  *Checked live:* 2026-11-15: HEAD → 1,054,606,848 bytes, `accept-ranges: bytes`, last modified 21:42:02Z; `Range: bytes=-2048` → 206 ending with the newest upload's `.cabal`; the `.tar.gz` variant is 141,083,630 bytes.

- **recent uploads** (partial) — cursor: timestamp

  `https://hackage.haskell.org/packages/recent.rss`

  The 20 most recent uploads (`/packages/recent/revisions.rss` for revisions).

  *Checked live:* 2026-11-15: 200, "Showing 1 - 20 most recent additions".

**Rate limits.** None documented; responses come through a CDN with `cache-control: max-age=60`.

**Terms of use.** Mirrors are first-class: `mirrors.json` is a TUF-signed list (version 13, expiring 2027-06-01: hackage.fpcomplete.com and a DreamObjects bucket), and hackage-mirror-tool syncs to S3 every few minutes.

**Full-mirror size.** 20.4 GB of package tarballs (155,731 package versions); the index is 1.05 GB. The sum of the tarball lengths in the index's `package.json` entries (20,391,133,570 bytes), computed from `01-index.tar.gz` on 2026-11-15; hackage-mirror-tool's README gave about 7.1 GiB in 2016.

**Private and self-hosted upstreams.** A self-hosted hackage-server serves the same index and TUF files. Artifactory and Nexus have no Hackage format.

**Sources.** [Hackage API](https://hackage.haskell.org/api) · [hackage-security](https://github.com/haskell/hackage-security) · [hackage-mirror-tool](https://github.com/haskell-hvr/hackage-mirror-tool)

### helm

**Helm chart repositories** — upstream type `helm`, registry <https://charts.bitnami.com/bitnami>. Tier **(b) complete index to poll and diff**. Implementation: implemented (Task 191: polls the repository's `index.yaml` conditionally (ETag/Last-Modified, redirects followed) and diffs it against a stored copy, one record per chart version (`created` left out: an index regenerated without `--merge` re-reports nothing); the index is read as a stream (one of at most 8 MiB the streaming reader does not handle is read whole with yaml.v3, a larger one is refused). A version is reported once listed for feed option `settle` (default 15m, from the poll that first saw it), so that the index the backend reads lists it too. Versions from the stored copy, each with its archive at the path the backend's rewritten index hands clients. Feed option `url` names another copy of the index; an OCI upstream (setting `oci`) cannot be followed.).

**Feeds**

- **repository `index.yaml`** — cursor: validator

  `https://charts.bitnami.com/bitnami/index.yaml`

  A classic chart repository publishes one `index.yaml` with every chart version, its archive URLs and `digest`; poll it (ETag/Last-Modified) and diff. It covers one repository — Helm has no central registry.

  *Checked live:* 2026-11-15: Bitnami's index redirects to `https://repo.broadcom.com/bitnami-files/index.yaml` (27.6 MB, modified 2026-11-14); prometheus-community's is 6.8 MB.

- **Artifact Hub search** (partial) — cursor: page

  `https://artifacthub.io/api/v1/packages/search?kind=0&sort=last_updated&limit=60&offset={offset}`

  Charts of every repository listed on Artifact Hub, by `last_updated`, at most 60 per page (total in `Pagination-Total-Count`): a way to discover repositories and new chart versions across them.

  *Checked live:* 2026-11-15: `limit=2` → 200, newest package `bi-stack` 0.0.4.

- **Artifact Hub Helm exporter** (partial) — cursor: validator

  `https://artifacthub.io/api/v1/helm-exporter`

  "the latest version available of all charts listed in Artifact Hub" with each repository's URL, in one document cached for an hour.

  *Checked live:* 2026-11-15: 200, 2,759,297 bytes, `cache-control: max-age=3600`.

**Rate limits.** Chart repositories are static files (often GitHub Pages) with no published limits; Artifact Hub documents a 429 without numbers.

**Terms of use.** Per repository. Bitnami announced in 2025 that its packaged charts stay available on `docker.io/bitnamicharts` as OCI artifacts "but they will no longer receive updates", and removed its free public image catalog (scheduled for 2025-09-29).

**Full-mirror size.** Per repository (Bitnami's index alone is 27.6 MB). Helm has no central registry, so there is no total; a repository's size is the sum of the archives its `index.yaml` lists.

**Private and self-hosted upstreams.** ChartMuseum, Artifactory and Nexus Helm repositories serve an `index.yaml` of what they hold, so the same poll applies. Charts in OCI registries (`oci://`) have no index and behave like the docker type (tier d).

**Sources.** [Artifact Hub API (OpenAPI)](https://raw.githubusercontent.com/artifacthub/hub/master/docs/api/openapi.yaml) · [Bitnami charts: upcoming changes (issue 35164)](https://github.com/bitnami/charts/issues/35164) · [Helm: chart repository guide](https://helm.sh/docs/topics/chart_repository/)

### hex

**Hex (Elixir and Erlang)** — upstream type `hex`, registry <https://repo.hex.pm>. Tier **(b) complete index to poll and diff**. Implementation: implemented (Task 191: polls the signed `/names` and `/versions` with conditional requests and diffs `/versions`, one change per version added, retired or gone; versions and their tarballs from the copy, retired versions yanked. `/versions` must verify (hex.pm's key, which also signs its organisations' repositories; feed option `publicKey` names another, or `none`) and name the repository (`hexpm`, an organisation's own name; feed option `repository`); `/names` gives only the head time. Feed option `url` names another repository.).

**Feeds**

- **names and versions** — cursor: validator

  `https://repo.hex.pm/names`

  Signed, gzipped protobuf: `/names` lists every public package with its `updated_at`, `/versions` every package's versions. Poll both, diff, fetch `/packages/{name}` (the signed release list with checksums) for the names whose `updated_at` moved, then `/tarballs/{name}-{version}.tar`. `/names` is marked as being "for full registry sync". Both are small (379 KB and 392 KB).

  *Checked live:* 2026-11-15: `/names` 378,972 bytes and `/versions` 392,124 bytes, both modified 22:36:28Z.

- **packages by update time** — cursor: page

  `https://hex.pm/api/packages?sort=updated_at&page={page}`

  The API's listing, newest first, 100 per page.

  *Checked live:* 2026-11-15: 200 with `x-ratelimit-limit: 100`.

**Rate limits.** API: 100 requests per minute per IP (500 when authenticated), with `X-RateLimit-*` headers; 304 answers do not count. repo.hex.pm is CDN-served.

**Terms of use.** "The repository can be mirrored by setting up a caching proxy in front of it"; mirrors "do not need to be trusted" because the registry resources are signed. `HEX_MIRROR` selects a mirror.

**Full-mirror size.** Not published. Count packages from `/names` and releases from `/versions`; bytes are the sum of the release tarballs (not computed).

**Private and self-hosted upstreams.** Artifactory has Hex local/remote/virtual repositories (a remote re-signs the registry with its own key); Nexus has no Hex format; mini_repo can mirror hex.pm; organisations' private repositories have their own `/repos/{repo}/names`.

**Sources.** [Hex registry v2 specification](https://github.com/hexpm/specifications/blob/main/registry-v2.md) · [Hex repository endpoints](https://github.com/hexpm/specifications/blob/main/endpoints.md) · [Hex API (rate limits)](https://github.com/hexpm/specifications/blob/main/apiary.apib) · [Hex mirrors](https://hex.pm/docs/mirrors) · [Artifactory Hex repositories](https://docs.jfrog.com/artifactory/docs/hex-repositories)

### homebrew

**Homebrew (formulae.brew.sh, bottles on ghcr.io)** — upstream type `homebrew`, registry <https://formulae.brew.sh>. Tier **(a) incremental change feed**. Implementation: implemented (Task 190: diffs the Formula trees of homebrew-core's head commits once they have settled (feed option `settle`, default 30m); the current version from the formula JSON read through the proxy, one artifact per bottle (feed option `platforms` keeps some; disabled formulae are skipped). Task 191: a mirror of the JSON API is followed through its formula index, `/api/formula.json`, polled conditionally and diffed, one change per version added or rebottled; the version and its bottles from the copy of the index, at the paths the backend rewrites them to (feed option `mode`: `auto`, the default, `git` or `index`).).

**Feeds**

- **homebrew-core commits** — cursor: commit

  `https://github.com/Homebrew/homebrew-core`

  Every formula is a Ruby file `Formula/{letter}/{name}.rb` here, with a bottle block (a SHA-256 per platform) committed once its bottles are on ghcr.io; formulae.brew.sh's JSON is generated from this repository. Diff the stored commit against the new head and, for each changed formula, read `https://formulae.brew.sh/api/formula/{name}.json` and fetch the new bottles. The repository is large; casks live in Homebrew/homebrew-cask (the proxy passes cask documents through and serves no cask downloads).

  *Checked live:* 2026-11-15: `git ls-remote` → HEAD 0d406593….

- **formula and cask JSON** — cursor: validator

  `https://formulae.brew.sh/api/formula.jws.json`

  Every formula with its current version and its bottles' URLs and SHA-256 per platform (`formula.jws.json` is the signed form brew downloads, `formula.json` the plain one), and every cask in `cask.json`. Regenerated within minutes of a homebrew-core change: the poll-and-diff alternative to the Git history, at 35 MB per changed poll. Only current versions are listed.

  *Checked live:* 2026-11-15: `formula.json` 32,238,782 bytes, `formula.jws.json` 34,929,508, `cask.json` 19,469,952, each modified minutes before the request.

**Rate limits.** None documented for formulae.brew.sh; bottle downloads use anonymous ghcr.io tokens, for which no limits are published. The Git feed is on github.com, whose limits for unauthenticated clients apply.

**Terms of use.** None found.

**Full-mirror size.** Not published. The sum of the bottles for the platforms one supports: each formula has a bottle per supported macOS version and Linux; the JSON lists their URLs, not their sizes.

**Private and self-hosted upstreams.** Homebrew's own mirror settings (`HOMEBREW_API_DOMAIN` for the JSON, `HOMEBREW_BOTTLE_DOMAIN` for bottles) point clients at static copies, which have no feed of their own; no Homebrew repository type is documented for Artifactory or Nexus.

**Notes**

- Tier (a) through homebrew-core's history; formulae.brew.sh on its own is a complete index (tier b).

**Sources.** [Homebrew formulae JSON API](https://formulae.brew.sh/docs/api/) · [brew: Library/Homebrew/api/formula.rb (signed JSON)](https://github.com/Homebrew/brew/blob/HEAD/Library/Homebrew/api/formula.rb) · [Homebrew/homebrew-core](https://github.com/Homebrew/homebrew-core)

### huggingface

**Hugging Face Hub** — upstream type `huggingface`, registry <https://huggingface.co>. Tier **(c) paginated listings only**. Implementation: partial (Task 191: follows the listing by last modification (`/api/models`, or datasets or spaces per feed option `kind`) for the scope feed options `author` (comma-separated, at most 32, one listing each, read in turn down to the mark's lookback window) and/or `search` name — the whole Hub is not enumerated; hf.co's listing is read at huggingface.co. The files of the commit main is at, from the metadata read through the proxy (feed option `files` keeps some; gated and private repositories are skipped unless feed option `restricted` is `include`). Feed option `url` names the listing API for an upstream that is not the Hub.).

**Feeds**

- **repositories by last modification** — cursor: page

  `https://huggingface.co/api/models?sort=lastModified&direction=-1&limit=100`

  Models (and `/api/datasets`, `/api/spaces`), most recently changed first; the next page is in the `Link` header as an opaque keyset cursor on (`lastModified`, `_id`) that stays stable while new commits arrive. A commit to any repository bumps its `lastModified`, so page back to the newest change of the previous pass, then read each repository's files at its revision and download them. The maximum page size is not documented.

  *Checked live:* 2026-11-15: `limit=2` → newest `lastModified` 22:46:22Z, `Link: <…&cursor=eyIkb3IiOlt7Imxhc3RNb2RpZmllZCI6…>; rel="next"`, `ratelimit-policy: "fixed window";"api";q=500;w=300`.

**Rate limits.** Five-minute fixed windows. Anonymous: 500 API calls, 3,000 file resolutions and 100 pages per IP; free accounts 1,000 / 5,000 / 200; paid plans more (figures of September 2025, subject to change). 429 when exceeded.

**Terms of use.** "Upgrade your account if you need elevated, large-scale access." Many repositories are gated (licence acceptance) or private. The terms of service were not reviewed for a crawling clause.

**Full-mirror size.** More than 20 PB. A lower bound: Hugging Face moved 500,000 repositories holding 20 PB to its Xet storage in 2025.

**Private and self-hosted upstreams.** Artifactory (Hugging Face and Machine Learning repositories) and Nexus (Hugging Face proxy) cache models and datasets for clients; neither documents its upstream's `/api/models` listing. Hugging Face webhooks cover only the repositories or users one watches.

**Notes**

- At the anonymous limit of 500 API calls per 5 minutes a follower must stay below 1.7 requests a second (about 3 with a free account's token); its listing, metadata and file requests all count, and so do other clients behind the same egress address.

**Sources.** [Hugging Face Hub API](https://huggingface.co/docs/hub/api) · [Hugging Face Hub rate limits](https://huggingface.co/docs/hub/rate-limits) · [Migrating the Hub to Xet (2025-07-15)](https://huggingface.co/blog/migrating-the-hub-to-xet)

### jsr

**JSR (JavaScript Registry)** — upstream type `jsr`, registry <https://jsr.io>. Tier **(c) paginated listings only**. Implementation: implemented (Task 191: reads every page of the management API's package list at each poll, to its first empty page, into a copy diffed against the last (a publish moves the version count, not `updatedAt`), changes by package; versions from `meta.json` and their module files from each version's manifest, read through the proxy (every package's file lists kept: a publish reads the new version's manifest only). Another upstream needs feed option `url`, an API that lists packages as api.jsr.io does.).

**Feeds**

- **package list** — cursor: page

  `https://api.jsr.io/packages?limit=100&page={page}`

  Every package with `updatedAt` and `latestVersion`, 1–100 per page (`total` in the response). There is no sort parameter and the order is alphabetical, so each pass reads every page and compares `updatedAt`. Versions come from `https://jsr.io/@{scope}/{name}/meta.json` (with `createdAt`), files from `{version}_meta.json`, cacheable forever.

  *Checked live:* 2026-11-15: `limit=2` → `total` 23,228; `sortBy`/`sort` parameters ignored (alphabetical order).

- **recent activity** (partial) — cursor: timestamp

  `https://api.jsr.io/stats`

  The 10 newest packages and 10 most recently uploaded versions, cached four hours: a hint, too short and too stale to follow.

  *Checked live:* 2026-11-15: `newest`, `updated`, `featured` with 10 entries each, `cache-control: public, max-age=14400`.

**Rate limits.** None stated: "If a tool is misbehaving, we may block it from using the management API."

**Terms of use.** JSR asks tools to read versions from `meta.json`, not from the management API.

**Full-mirror size.** 23,228 packages; bytes not published. Package total on 2026-11-15. JSR serves source files, so packages are small.

**Private and self-hosted upstreams.** There is no self-hosted JSR server in common use.

**Notes**

- Measured on 2026-11-16: a full pass over the package list is 214 requests and about 11 MB, so polling every 5 minutes costs about 61,600 requests and 3.2 GB a day; an hourly poll about 5,100 requests and 260 MB.

**Sources.** [JSR API](https://jsr.io/docs/api) · [JSR management API (OpenAPI)](https://api.jsr.io/.well-known/openapi)

### julia

**Julia General registry (Pkg servers)** — upstream type `julia`, registry <https://pkg.julialang.org>. Tier **(a) incremental change feed**. Implementation: implemented (Task 190: diffs the Pkg server's registry snapshots (`/registries` in the flavour of feed option `flavor`, `conservative` or `eager`): each new registry tree is read through the proxy and its `Registry.toml` and `Versions.toml` files indexed in the state directory; versions from the stored index, package tarballs by uuid and git-tree-sha1. Package artifacts are not followed.).

**Feeds**

- **General registry commits** — cursor: commit

  `https://github.com/JuliaRegistries/General`

  The registry is a Git repository: a new version is a commit that adds an entry with its `git-tree-sha1` to `{L}/{Name}/Versions.toml`. Diff the stored commit against the new head and fetch each new version from the Pkg server as `/package/{uuid}/{tree-sha1}` (plus the artifacts it names). A Pkg server's registry list names a tree of a General commit, so the server's state maps onto this history — but by default it lags (see the registry flavours below), so a new version can be in Git before the Pkg server serves it.

  *Checked live:* 2026-11-15: `git ls-remote` → HEAD 3a25a072… (an hour later ad00b696…).

- **registry snapshot (eager flavour)** — cursor: validator

  `https://pkg.julialang.org/registries.eager`

  A Pkg server publishes two flavours of its registry list. `/registries` redirects to `/registries.conservative`, the default, which only publishes a registry once the storage servers hold every resource in it; `/registries.eager` (or the `Julia-Registry-Preference: eager` header) names the newest tree. Everything else is content-addressed and cacheable forever. A new tree hash means new versions; `/registry/{uuid}/{hash}` is the whole registry as a tarball (no delta), so without the Git history the follower diffs two snapshots.

  *Checked live:* 2026-11-15: `/registries` → 301 to eu-central.pkg.julialang.org, then 302 to `/registries.conservative` → tree d6419a18… (unchanged for over 35 minutes); `/registries.eager` → d3afc365…, a newer tree.

**Rate limits.** None documented. The Git feed is on github.com, whose limits for unauthenticated clients apply.

**Terms of use.** None found. PkgServer.jl ships a deployment for running one's own Pkg server; the storage servers behind pkg.julialang.org require client certificates issued by their operator.

**Full-mirror size.** Not published. Count packages and versions from the registry's `Registry.toml` and `Versions.toml`; each version is a source tarball plus the artifacts (binaries) it declares.

**Private and self-hosted upstreams.** PkgServer.jl speaks the same protocol, flavours included. Artifactory and Nexus have no Julia format.

**Sources.** [Pkg server protocol](https://pkgdocs.julialang.org/v1/protocol/) · [Julia environment variables: JULIA_PKG_SERVER_REGISTRY_PREFERENCE](https://docs.julialang.org/en/v1/manual/environment-variables/) · [JuliaRegistries/General](https://github.com/JuliaRegistries/General) · [PkgServer.jl](https://github.com/JuliaPackaging/PkgServer.jl)

### maven

**Maven Central** — upstream type `maven`, registry <https://repo1.maven.org/maven2>. Tier **(b) complete index to poll and diff**. Implementation: partial (Task 191: follows a repository manager's Maven Indexer index (`<url>/.index/`): the properties file read conditionally, the chunks after the stored one applied to the stored copy while its chain lasts (a chunk gone or malformed, a full index older than the properties, or another `classifiers` selection makes it a full read), otherwise the full index streamed and diffed; releases from the stored copy, each document standing for its file and its release's POM (a POM alone for the main artifact its packaging names), classifiers per feed option `classifiers`, snapshots skipped. Maven Central itself is refused, by its host names (Google's copies too) and at every read by its index id `central` or its chain id: its terms forbid mirroring it. Feed option `url` names another index directory.).

**Feeds**

- **Maven Indexer index** — cursor: validator

  `https://repo1.maven.org/maven2/.index/nexus-maven-repository-index.properties`

  The full index (`nexus-maven-repository-index.gz`) and incremental chunks `nexus-maven-repository-index.{n}.gz` chained from the properties file (`nexus.index.last-incremental`; the last 30 are kept): a follower holding chunk n fetches n+1 to the last, otherwise the full index. Records are Lucene documents (Maven Indexer format) with groupId, artifactId, version, packaging and SHA-1. Sonatype rebuilds the index on "a roughly two-week cycle", calls it "largely a deprecated artifact" and limits index downloads per IP: new releases reach it weeks late, so fetch it at most once per cycle and poll the `maven-metadata.xml` of the artifacts one depends on for timely news.

  *Checked live:* 2026-11-15: the properties file is dated Thu Oct 22 17:25:57 UTC 2026 (last incremental 941, chunks 912–941); the full index is 3,351,259,806 bytes, modified 2026-10-22. A second HEAD of the full index from the same host 38 minutes later → 429 with `retry-after: 86400`: "Individual ip limits apply to this file."

- **maven-metadata.xml per artifact** (partial) — cursor: validator

  `https://repo1.maven.org/maven2/{group-path}/{artifact}/maven-metadata.xml`

  Every version of one artifact with `lastUpdated`: the way to follow the artifacts one depends on.

  *Checked live:* 2026-11-15: `org/slf4j/slf4j-api` → latest 2.1.0-alpha1, `lastUpdated` 20260922145706.

**Rate limits.** Index files have per-IP download limits (a second request for the full index within the hour was refused for 24 hours). Beyond that Sonatype rate-limits abusive traffic patterns with 429s and blocks of "up to a maximum of 30 days", aimed at "the top few percent", and recommends consolidating requests through a repository manager.

**Terms of use.** **Full mirroring is forbidden.** The Central Repository Terms of Service (last updated 2026-03-31) list "Attempting to download all or large portions of the Materials stored in Central (a.k.a., scraping or mirroring any content)" as abuse. They also introduce tiered access ("Consumption Tier"): consumption "at reasonable levels (as determined by Sonatype at its discretion)" stays free. Follow the artifacts you depend on, not Central.

**Full-mirror size.** Not published. Sonatype publishes component counts, not storage. An undated third-party copy measured about 10 TB around 2019 (unverified); a full copy is excluded by the terms anyway.

**Private and self-hosted upstreams.** Nexus and Artifactory can publish a Maven Indexer index of what they host, and are what Sonatype recommends in front of Central (downloading Central's index once for everyone behind them). JFrog notes that Central's 429s surface as 404s through an Artifactory remote. Artifactory's AQL (a `created`/`modified` filter) and Nexus's components REST API (continuation token) and repository webhooks enumerate only what such a server hosts or has cached; neither documents relaying its upstream's feed.

**Notes**

- search.maven.org's Solr API ignores a caller's `sort` (it reports `score desc,timestamp desc,g asc,a asc`), so it cannot be paged by time.

**Sources.** [Apache Maven: the Central index](https://maven.apache.org/repository/central-index.html) · [Maven Central: 429 errors on index files](https://central.sonatype.org/faq/429-maven-index/) · [Central Repository Terms of Service](https://central.sonatype.org/terms.html) · [Maven Central: 429 errors (rate limiting)](https://central.sonatype.org/faq/429-error/) · [JFrog: 429 rate limits from Maven Central surface as 404s](https://jfrog.com/help/r/artifactory-429-rate-limits-from-maven-central-public-upstreams-surface-as-404s)

### nix

**Nix binary cache (cache.nixos.org)** — upstream type `nix`, registry <https://cache.nixos.org>. Tier **(d) no practical enumeration**. Implementation: not started (no registry-wide feed to follow).

**Feeds**

- **channel store paths** (partial) — cursor: validator

  `https://channels.nixos.org/{channel}/store-paths.xz`

  The output paths of one channel release (a redirect to releases.nixos.org): diff two releases and fetch `/{hash}.narinfo` and the NARs for the new paths and their references. Covers one channel's outputs, not the cache.

  *Checked live:* 2026-11-15: nixos-unstable → nixos-26.11pre1119549, 6,003,848 bytes of xz, 227,961 paths.

**Rate limits.** None published; the cache is an S3 bucket behind Fastly serving about 5,700 requests a second.

**Terms of use.** None found; "new mirroring options" are listed as future work.

**Full-mirror size.** 636 TB, more than 1 billion objects. NixOS Foundation, July 2026 figures in its binary-cache story of 2026-09-20.

**Private and self-hosted upstreams.** Attic, Cachix, Harmonia and nix-serve serve the same narinfo/NAR protocol, which has no listing; a cache backed by an S3 bucket one owns can be listed through S3.

**Notes**

- `nix-cache-info` declares `WantMassQuery: 1`; the bucket refuses anonymous listing (403) and there is no index.

**Sources.** [NixOS: the Nix binary cache (2026-09-20)](https://nixos.org/blog/stories/2026/nix-binary-cache/) · [NixOS Discourse: garbage collecting cache.nixos.org](https://discourse.nixos.org/t/garbage-collecting-cache-nixos-org/74249)

### npm

**npm registry** — upstream type `npm`, registry <https://registry.npmjs.org>. Tier **(a) incremental change feed**. Implementation: implemented (Task 190: follows `_changes` from the stored sequence (one beyond `update_seq` means a reset and a new enumeration) after listing `_all_docs`; versions from the packument read through the proxy. Feed option `url` names a CouchDB replica for a private registry.).

**Feeds**

- **replication feed (`_changes`)** — cursor: sequence

  `https://replicate.npmjs.com/_changes?since={seq}&limit=10000`

  Each result names a package (`id`), its new revision and `deleted` when it was removed, in order of the integer `seq`; store `last_seq` and pass it back as `since`. `limit` defaults to 1000 and is capped at 10000. Since npm's 2025 replication migration the feed carries no documents and is poll-only: `include_docs`, `feed=longpoll|continuous`, `style` and `since=now` are refused, so the follower fetches each changed packument from `https://registry.npmjs.org/{name}` and the tarballs it names. `GET https://replicate.npmjs.com/` returns the current `update_seq`.

  *Checked live:* 2026-11-15: the root returned `doc_count` 4,610,317 and `update_seq` 144,828,896; `_changes?since=144828890&limit=3` → 200 with three changes and `last_seq` 144828900, `limit=10000` → 200; `limit=10001`, `include_docs=true`, `feed=longpoll`, `style=all_docs` and `since=now` → 400. The same cursor requested twice 20 s apart was revalidated at the CDN (`cf-cache-status: EXPIRED`), not served stale.

- **all package names (`_all_docs`)** — cursor: page

  `https://replicate.npmjs.com/_all_docs?startkey=%22{name}%22&limit=10000`

  Every package name in key order, at most 10000 per request: the starting inventory for a follower that begins from nothing, and a reconciliation pass for packages the change feed missed.

  *Checked live:* 2026-11-15: `_all_docs?limit=2` → 200, `total_rows` 4,610,317.

**Rate limits.** No numeric limit is published for the registry or the replication endpoint, and the responses checked carried no rate-limit headers.

**Terms of use.** npm's Open-Source Terms allow replication ("You may replicate data from the Public Registry using the Public APIs") but also say that "under no circumstances are five million requests to npm Services in a single month-long period by any single individual, organization… remotely reasonable". A full initial mirror (a packument per package plus every tarball) is far beyond that; following the feed after mirroring the packages one depends on is not.

**Full-mirror size.** 4.6 million packages; no published byte total. `doc_count` at replicate.npmjs.com on 2026-11-15. npm publishes no storage figure; a 2023 third-party analysis (Sandworm) put all versions at about 24 TB — not verified here.

**Private and self-hosted upstreams.** Artifactory and Nexus npm repositories document no `_changes` endpoint. Artifactory's AQL (a `created`/`modified` filter) and Nexus's components REST API (continuation token) and repository webhooks enumerate only what such a server hosts or has cached; neither documents relaying its upstream's feed.

**Notes**

- The sequence has been reset before (npm's 2021 CouchDB upgrade): a follower must notice a stored `since` beyond the current `update_seq` and fall back to a full pass.
- After the 2025 migration users reported packages missing from the feed; reconcile against `_all_docs` now and then.

**Sources.** [npm staff: changes to the replication APIs (GitHub community discussion 152515)](https://github.com/orgs/community/discussions/152515) · [GitHub changelog: changes and deprecation notice for npm replication APIs (2025-02-27)](https://github.blog/changelog/2025-02-27-changes-and-deprecation-notice-for-npm-replication-apis/) · [GitHub changelog: npm CouchDB upgrade will reset the sequence number (2021-09-08)](https://github.blog/changelog/2021-09-08-npm-couchdb-upgrade-will-reset-sequence-number) · [npm Open-Source Terms](https://docs.npmjs.com/policies/open-source-terms)

### nuget

**NuGet Gallery (nuget.org)** — upstream type `nuget`, registry <https://api.nuget.org>. Tier **(a) incremental change feed**. Implementation: implemented (Task 190: follows the catalog (`Catalog/3.0.0` of the service index) by commit timestamp: the pages committed after the cursor, their newer leaves in commit order, each batch ending at a commit boundary and at commits older than feed option `settle` (default 10m: the flat container lists a version minutes after the catalog commits it); a cursor beyond the last commit (a rebuilt catalog) means a new replay from the first page. Versions from the flat container read through the proxy. Feed option `url` names a catalog index for a feed whose service index names none (Artifactory, Nexus, Azure Artifacts, GitHub Packages).).

**Feeds**

- **catalog** — cursor: timestamp

  `https://api.nuget.org/v3/catalog0/index.json`

  The append-only catalog (`Catalog/3.0.0` in the service index): pages of at most 550 leaves, each a `PackageDetails` (push, list/unlist, deprecation, vulnerability update) or `PackageDelete` with its `commitTimeStamp`. Read the pages whose `commitTimeStamp` is newer than the cursor, process their newer leaves, store the last timestamp processed ("no catalog commit will ever be added with a time less than or equal to" it). Leaves carry `packageHash` (SHA-512) and `packageSize`; the .nupkg comes from `https://api.nuget.org/v3-flatcontainer/{id}/{version}/{id}.{version}.nupkg`. Handle duplicate leaves idempotently.

  *Checked live:* 2026-11-15: the index (4.5 MB, `cache-control: no-store`) is an `AppendOnlyCatalog` of 23,568 pages, last commit 2026-11-15T22:44:28Z.

**Rate limits.** Over a limit nuget.org answers 429 with the time to wait. Documented limits cover the v2 API (20,000 requests a minute per IP for `/api/v2/Packages`) and web pages; none are listed for the catalog or the flat container.

**Terms of use.** Microsoft documents the catalog for clients that process every package operation (its catalog-reader guidance). nuget.org's terms of use were not reviewed for this page.

**Full-mirror size.** 594,190 packages, 14,044,198 versions; no byte total published. https://www.nuget.org/stats/totals on 2026-11-15. The byte total is the sum of `packageSize` over the catalog's leaves (not computed here).

**Private and self-hosted upstreams.** Microsoft notes that "not all package sources implement the catalog"; Artifactory and Nexus document none for their NuGet repositories. Artifactory's AQL (a `created`/`modified` filter) and Nexus's components REST API (continuation token) and repository webhooks enumerate only what such a server hosts or has cached; neither documents relaying its upstream's feed.

**Notes**

- The catalog is not available in China: the service index there has no Catalog resource.

**Sources.** [NuGet catalog resource](https://learn.microsoft.com/en-us/nuget/api/catalog-resource) · [NuGet API rate limits](https://learn.microsoft.com/en-us/nuget/api/rate-limits) · [nuget.org statistics](https://www.nuget.org/stats)

### openvsx

**Open VSX** — upstream type `openvsx`, registry <https://open-vsx.org>. Tier **(b) complete index to poll and diff**. Implementation: implemented (Task 191: polls the sitemap (conditionally, where the server sends validators) and diffs it, one change per extension whose date moved; the search listing by time, read at every poll, adds second publications on a day (a server re-dating every extension, as one in mirror mode does, is recognised). Versions from each target platform's version listing, up to 2,000 a platform, past pre-release lines; one `.vsix` per version and platform (feed option `platforms` keeps some). Feed option `url` names another sitemap.).

**Feeds**

- **sitemap** — cursor: validator

  `https://open-vsx.org/sitemap.xml`

  Every extension (`/extension/{namespace}/{name}`) with a `lastmod` date. openvsx-server's own mirror mode reads it, asks `/api/{namespace}/{name}` for each extension and downloads the versions it lacks, deleting extensions gone upstream. `lastmod` is a date, so re-check the extensions modified on the current day at every poll.

  *Checked live:* 2026-11-15: 21,414 `<url>` entries (2.6 MB, `cache-control: public, max-age=600`) — the same count as the search API's `totalSize`.

- **search by timestamp** — cursor: page

  `https://open-vsx.org/api/-/search?sortBy=timestamp&sortOrder=desc&size=100&offset={offset}`

  Extensions by their latest version's timestamp, newest first, offset-paged.

  *Checked live:* 2026-11-15: `size=2` → `totalSize` 21,414, newest published 22:42Z; `x-ratelimit-limit: 10800`.

**Rate limits.** The Eclipse Foundation introduced rate limiting for open-vsx.org in 2025–2026 (tiers, observation first; no numbers published); responses carry `x-ratelimit-limit: 10800`. Sustained or commercial-scale users are asked to get in touch.

**Terms of use.** No mirroring clause beyond the Eclipse Foundation's terms of use; the server's mirror mode exists for self-hosted instances.

**Full-mirror size.** 21,414 extensions; bytes not published. Sitemap count on 2026-11-15. A full copy is every version (and target platform) of every extension's `.vsix` — not computed.

**Private and self-hosted upstreams.** A self-hosted openvsx-server serves the same API and sitemap and can itself mirror open-vsx.org (`ovsx.data.mirror.enabled`). Artifactory documents a remote-only "AI Editor Extensions" repository type (whether it fronts Open VSX was not verified); Nexus documents no such format.

**Notes**

- open-vsx.org sends no validators for its sitemap (checked 2026-11-16), so every poll reads it whole, plus one to three pages of the search listing by time.

**Sources.** [openvsx-server mirror mode (source)](https://github.com/eclipse-openvsx/openvsx/tree/master/server/src/main/java/org/eclipse/openvsx/mirror) · [Eclipse Foundation: Open VSX rate limiting (2026-02-11)](https://blogs.eclipse.org/node/8762)

### pip

**Python Package Index (PyPI)** — upstream type `pip`, registry <https://pypi.org>. Tier **(a) incremental change feed**. Implementation: implemented (Task 190: follows the XML-RPC changelog from the stored serial (one beyond `changelog_last_serial` means a reset and a new enumeration), rows older than feed option `settle` (default 5m: a release's simple page can reach the CDN later), after listing the PEP 691 project list; feed option `mode` `simple`, the fallback where XML-RPC is missing, diffs every project's `_last-serial` against a stored copy instead. Versions from the simple page read through the proxy; names are PEP 503-normalized. Feed option `url` names another Warehouse.).

**Feeds**

- **XML-RPC changelog** — cursor: sequence

  `https://pypi.org/pypi`

  `changelog_since_serial(serial)` returns `[name, version, timestamp, action, serial]` rows newer than the serial — at most 50,000 per call — and `changelog_last_serial()` the head. Actions cover new projects, releases, files, removals and ownership; the follower re-reads each named project from the JSON simple API and downloads new files from files.pythonhosted.org. PyPI calls these mirroring methods its only fully supported mirroring interface "until an improved mechanism for mirroring is implemented", and also says no new integration should use XML-RPC, which is planned for deprecation.

  *Checked live:* 2026-11-15: `changelog_last_serial` → 43,702,696; `changelog_since_serial(43702693)` → two rows for `sentalign-rust` (`create`, `add Owner …`); response headers `ratelimit-policy: "xmlrpc.client-0";q=5;w=1, "xmlrpc.client-1";q=50;w=60` (per IP).

- **simple index with serials (PEP 691 JSON)** — cursor: validator

  `https://pypi.org/simple/`

  With `Accept: application/vnd.pypi.simple.v1+json` the index lists every project with its `_last-serial` (the global one is `meta._last-serial` and the `X-PyPI-Last-Serial` header). Diff against the previous copy and re-read the projects whose serial moved: 46 MB per poll, cached 10 minutes at the CDN. bandersnatch, PyPA's mirror client, made this its default in 2025 and removed XML-RPC in 2026 — the fallback when XML-RPC goes away.

  *Checked live:* 2026-11-15: HEAD → 200, `content-length: 46188765`, `x-pypi-last-serial: 43701540`, `cache-control: max-age=600, public`; the body starts `{"meta":{"_last-serial":43702439,"api-version":"1.4"},"projects":[{"_last-serial":3075854,"name":"0"},…`.

- **RSS feeds** (partial) — cursor: timestamp

  `https://pypi.org/rss/updates.xml`

  The last 100 releases (`updates.xml`) and the 40 newest projects (`packages.xml`). PyPI's API guide recommends them "for periodically checking for new packages or updates", but 100 releases cover only minutes: a hint between polls, not a feed to follow.

  *Checked live:* 2026-11-15: 100 and 40 items; the 100 releases spanned 18 minutes (22:26:54 to 22:44:58 UTC, a Sunday evening).

**Rate limits.** XML-RPC: 5 requests per second and 50 per minute per IP (the live `ratelimit-policy` header; PyPI's docs call it "a very restrictive rate limit"). The JSON and file APIs have no limit at the edge ("there is currently no rate limiting of PyPI APIs at the edge"), but PyPI asks clients not to make thousands of requests within minutes.

**Terms of use.** PyPI "reserves the right to temporarily or permanently prohibit a consumer based on irresponsible activity" and points high-volume users to their own mirror or cache. No clause forbids mirroring; bandersnatch is PyPA's own mirror client.

**Full-mirror size.** 51.6 TB (every file of every release). `total_packages_size` = 51,558,788,849,503 bytes from https://pypi.org/stats/ (JSON) on 2026-11-15. The largest projects alone run to hundreds of GB (tf-nightly 965.5 GB, tensorflow 429.0 GB).

**Private and self-hosted upstreams.** devpi replicas follow their primary through devpi's own changelog protocol (`/+changelog/{serial}`, `X-DEVPI-SERIAL`). Artifactory and Nexus PyPI repositories document neither PyPI's XML-RPC changelog nor its serials. Artifactory's AQL (a `created`/`modified` filter) and Nexus's components REST API (continuation token) and repository webhooks enumerate only what such a server hosts or has cached; neither documents relaying its upstream's feed.

**Notes**

- A follower that fell more than 50,000 changes behind calls `changelog_since_serial` again with the last serial it received until it reaches the head.

**Sources.** [PyPI XML-RPC API (warehouse docs)](https://github.com/pypi/warehouse/blob/main/docs/dev/api-reference/xml-rpc.md) · [warehouse: XML-RPC views (the 50,000-row cap)](https://github.com/pypi/warehouse/blob/main/warehouse/legacy/api/xmlrpc/views.py) · [PyPI APIs: overview, rate limiting and caching](https://docs.pypi.org/api/) · [PyPI index API (PEP 691, `_last-serial`)](https://docs.pypi.org/api/index-api/) · [PyPI statistics](https://pypi.org/stats/) · [bandersnatch, the PyPA mirror client](https://github.com/pypa/bandersnatch)

### puppet

**Puppet Forge** — upstream type `puppet`, registry <https://forgeapi.puppet.com>. Tier **(c) paginated listings only**. Implementation: implemented (Task 191: follows `/v3/releases?sort_by=release_date` down to a high-water mark and a day below it, by module name, releases younger than feed option `settle` held back (default 90m: the CDN serves module documents up to an hour old; 3h30m when the upstream is a server in front of the Forge), after enumerating the modules from the same listing sorted by module; versions from the module document read through the proxy, deleted releases as yanked, premium and login-required modules only with credentials. Feed option `url` names the Forge for an Artifactory remote.).

**Feeds**

- **releases by date** — cursor: page

  `https://forgeapi.puppet.com/v3/releases?sort_by=release_date&limit=100&offset={offset}&with_html=false&exclude_fields=readme+changelog+license+reference`

  Every module release, newest first, offset-paged (`pagination.total`, `next`); page from offset 0 until a release already seen, overlapping pages because offsets shift as releases arrive. Each release names its `file_uri`, `file_size` and `file_sha256`; excluding the README, changelog and licence keeps a page small.

  *Checked live:* 2026-11-15: `total` 54,827, newest jdowning-rbenv-4.0.0 (13:58 -0800); `limit=100` → 100 releases; modules by `latest_release` → 7,707.

**Rate limits.** None documented; no rate-limit headers.

**Terms of use.** No download restrictions found; Perforce's 2025 changes concern Puppet Core and the PDK, not downloading modules from the Forge.

**Full-mirror size.** 7,707 modules, 54,827 releases; about 3 GB (estimate). Live counts on 2026-11-15; the 100 newest releases average 58 KB (median 34 KB), times 54,827.

**Private and self-hosted upstreams.** Artifactory has Puppet local/remote/virtual repositories; Nexus has no Puppet format; there is no official self-hosted Forge.

**Sources.** [Puppet Forge API v3](https://forgeapi.puppet.com/) · [Puppet module developer EULA FAQ (2025)](https://puppet.com/blog/puppet-module-developer-eula-faq)

### rubygems

**RubyGems.org** — upstream type `rubygems`, registry <https://rubygems.org>. Tier **(a) incremental change feed**. Implementation: implemented (Task 190: follows the compact index `/versions` with Range requests from the end of a stored copy (If-None-Match, Repr-Digest checked); a digest mismatch, a torn tail or another `created_at` (the monthly rewrite) fetches the whole file and diffs it against the copy. Versions from `/info/<gem>` read through the proxy, platform gems as files of their version. Feed option `url` names another compact-index base.).

**Feeds**

- **compact index `/versions`** — cursor: byte offset

  `https://rubygems.org/versions`

  One line per gem (`name versions md5-of-info`), appended as gems are pushed or yanked. It is "append only during the month" and "recalculated at the start of each month, removing yanked rubygems" — the first line, `created_at:`, changes then. Fetch the bytes after the stored length with a Range request; a changed `created_at`, a 416 or a `Repr-Digest` mismatch means the file was rewritten, so fetch it whole. For each appended line fetch `/info/{name}` and the gem from `/gems/{name}-{version}.gem`.

  *Checked live:* 2026-11-15: HEAD → 24,368,445 bytes, `accept-ranges: bytes`; `Range: bytes=0-300` → 206 starting `created_at: 2026-11-01T00:00:04Z`; `Range: bytes=-400` → 206 ending with the latest push (`nero 0.7.0.rc7`).

- **versions by time window** — cursor: timestamp

  `https://rubygems.org/api/v1/timeframe_versions.json?from={from}&to={to}&page={page}`

  Versions created in a window of at most seven days, 30 per page; walk the pages until one is empty. A cross-check for the compact index and a way to catch up across a monthly rewrite.

  *Checked live:* 2026-11-15: from 00:00 to 00:10 UTC → 200 with the versions pushed in those ten minutes.

- **activity** (partial) — cursor: timestamp

  `https://rubygems.org/api/v1/activity/just_updated.json`

  The 50 most recently updated gems (`latest.json`: the 50 newest gems), cached a minute.

  *Checked live:* 2026-11-15: 200, `cache-control: max-age=60, public`.

**Rate limits.** 10 requests per second per IP for the API and website and 15 for the dependency API, enforced at the load balancer; application limits answer 429 with `Retry-After`, and extreme cases are blackholed.

**Terms of use.** No mirroring clause found; the compact-index guide points bulk users to rubygems.org's public data dumps.

**Full-mirror size.** 198,697 gems; no byte total published. https://rubygems.org/stats on 2026-11-15. Versions are the entries of `/versions`; the byte total is not published.

**Private and self-hosted upstreams.** Gemstash and Artifactory/Nexus RubyGems repositories document no change feed of their upstream. Artifactory's AQL (a `created`/`modified` filter) and Nexus's components REST API (continuation token) and repository webhooks enumerate only what such a server hosts or has cached; neither documents relaying its upstream's feed.

**Notes**

- A global push webhook (`gem_name=*`) exists, but it needs a RubyGems.org account and an endpoint reachable from the internet.

**Sources.** [RubyGems.org compact index API](https://guides.rubygems.org/rubygems-org-compact-index-api/) · [RubyGems.org API (activity, timeframe versions, webhooks)](https://guides.rubygems.org/rubygems-org-api/) · [RubyGems.org rate limits](https://guides.rubygems.org/rubygems-org-rate-limits/) · [RubyGems.org statistics](https://rubygems.org/stats)

### swift

**Swift package registries (Tuist's public registry)** — upstream type `swift`, registry <https://tuist.dev/api/registry/swift>. Tier **(d) no practical enumeration**. Implementation: not started (no registry-wide feed to follow).

**Feeds**

- **Swift Package Index package list** (partial) — cursor: commit

  `https://github.com/SwiftPackageIndex/PackageList`

  The Swift Package Index's list of package repositories (`packages.json` in a Git repository), which Tuist's registry mirrors. Map each repository to its registry identifier (`GET /identifiers?url=`) and list its releases (`GET /{scope}/{name}`): about 10,000 requests per pass.

  *Checked live:* 2026-11-15: `packages.json` → 669,137 bytes; Tuist `GET /apple/swift-argument-parser` → 200 with its releases; the registry root answers 200 with an empty body.

**Rate limits.** Tuist: 10,000 requests a minute without login and 100,000 with `tuist registry login` (announcement of 2025-11-26; a docs page says 1,000 and 20,000). The registry specification lets a server answer 429 with `Retry-After`.

**Terms of use.** None found beyond Tuist's announcement that the registry is open without an account.

**Full-mirror size.** About 10,000 packages and 160,000 releases. Tuist's announcement (2025-11-26); the source archives are built from the packages' Git tags.

**Private and self-hosted upstreams.** The registry specification has no listing endpoint, so Artifactory's and Nexus's Swift registries cannot be enumerated through the protocol either. Artifactory's AQL (a `created`/`modified` filter) and Nexus's components REST API (continuation token) and repository webhooks enumerate only what such a server hosts or has cached; neither documents relaying its upstream's feed.

**Notes**

- SE-0292 defines only per-package endpoints (`/{scope}/{name}`, `/{scope}/{name}/{version}`, `/identifiers`): a registry cannot be enumerated through the protocol.

**Sources.** [Swift package registry service specification](https://github.com/swiftlang/swift-package-manager/blob/main/Documentation/PackageRegistry/Registry.md) · [Tuist: opening the registry (2025-11-26)](https://tuist.dev/blog/2025/11/26/opening-registry) · [SwiftPackageIndex/PackageList](https://github.com/SwiftPackageIndex/PackageList)

### terraform

**Terraform Registry (and the OpenTofu registry)** — upstream type `terraform`, registry <https://registry.terraform.io>. Tier **(c) paginated listings only**. Implementation: not applicable (no feed adapter (Task 191): the listings name only each module's and provider's latest version, so a new version surfaces only in a full pass over both listings (about 330 requests) and a version list per changed entry, and provider binaries are GitHub release assets outside the registry; full mirroring is refused, and tracked repositories pin the providers their lock files name).

**Feeds**

- **module listing** — cursor: page

  `https://registry.terraform.io/v1/modules?limit=100&offset={offset}`

  The documented List Modules API: every module with its latest `version` and `published_at`, offset-paged (`meta.next_offset`), in the order the modules were created, oldest first. New modules arrive at the end, so page on from the stored offset; a new version of an existing module does not move it, so catching those takes a pass over the whole listing (about 250 requests at 100 per page), then `/v1/modules/{namespace}/{name}/{provider}/versions`.

  *Checked live:* 2026-11-15: `limit=2` → `next_offset` 2, starting with long-established modules (GoogleCloudPlatform/lb-http, managed-instance-group); offsets 24767–24769 → the last three, published 2026-11-14 and 15 with 3 to 13 downloads, and no `next_offset`: 24,770 modules (the website's `/v2/modules` reports 25,033).

- **provider listing** — cursor: page

  `https://registry.terraform.io/v2/providers?page%5Bsize%5D=100&page%5Bnumber%5D={page}`

  The website's undocumented JSON:API listing of every provider, alphabetical (`sort=-published-at` is refused). Versions per provider at `/v1/providers/{namespace}/{type}/versions`; the binaries are GitHub release assets named in each version's download document.

  *Checked live:* 2026-11-15: `page[size]=2` → `total-count` 7,761; `sort=-published-at` → 400 "Invalid sort option"; `/v1/providers?limit=2` also lists providers with their latest version.

- **OpenTofu registry commits** (partial) — cursor: commit

  `https://github.com/opentofu/registry`

  A different registry: registry.opentofu.org is generated from this Git repository (providers and modules as JSON files, new versions found from their GitHub releases and tags), so for an upstream pointed there its commits are a tier-(a) feed. The binaries stay on GitHub.

  *Checked live:* 2026-11-15: `git ls-remote` → HEAD f871e932…; registry.opentofu.org `/v1/providers/hashicorp/random/versions` → 200 (a static file).

**Rate limits.** "Clients placing excessive load on the service might be rate-limited and receive a 429"; no numbers.

**Terms of use.** The registry's terms could not be read (a JavaScript-only page); secondary sources quote a restriction of downloads to use "with, or in support of, HashiCorp Terraform" (unverified). Endpoints not in the API documentation are "subject to change".

**Full-mirror size.** 7,761 providers, 24,770 modules; provider binaries are on GitHub. Live counts on 2026-11-15; bytes = providers × versions × platforms × archive size (not computed). Modules are source archives from their VCS.

**Private and self-hosted upstreams.** The provider and module registry protocols define no listing, so a private registry is enumerable only through its own management API, if it has one.

**Notes**

- Tier (c), not (d): both listings enumerate everything. New modules show up at the end of the module listing; new versions of existing modules and providers only through a full pass over both listings (about 330 requests at 100 per page) and their version lists.
- An upstream at registry.opentofu.org can instead be followed through the OpenTofu repository's history (tier a).

**Sources.** [Terraform registry API](https://developer.hashicorp.com/terraform/registry/api-docs) · [Building the OpenTofu registry (2024-09-12)](https://opentofu.org/blog/building-the-opentofu-registry/) · [opentofu/registry](https://github.com/opentofu/registry)

### yum

**Fedora and RHEL-family YUM repositories** — upstream type `yum` (also `rpm`), registry <https://dl.fedoraproject.org/pub/fedora/linux>. Tier **(b) complete index to poll and diff**. Implementation: implemented (Task 191: polls `repodata/repomd.xml` conditionally and, when its primary changed, streams the primary (zstd, gzip or xz; size and checksums verified) into a stored copy it diffs; versions (`[epoch:]version-release`, rpm order) and files from the primary itself. One upstream is one repository root; feed option `url` names another mirror of it.).

**Feeds**

- **repomd.xml and primary** — cursor: validator

  `https://dl.fedoraproject.org/pub/fedora/linux/updates/{release}/Everything/{arch}/repodata/repomd.xml`

  `repomd.xml` has a `revision` and the location, size and checksum of `primary` (every package with its location and checksum). Poll it; when the revision moved, fetch the new primary and diff. Current Fedora publishes primary as zstd (`.zst`) and zchunk (`.zck`, which lets a client fetch only the changed chunks) — no gzip.

  *Checked live:* 2026-11-15: updates/44 x86_64 `repomd.xml` → revision 1794702405, `primary.xml.zst` 7.0 MB, `primary.xml.zck` 9.3 MB, no `.gz`. `releases/40/Everything/x86_64/os/repodata/repomd.xml` → 404, Fedora 41's too (the release directories keep only a README): releases past their end of life move to archives.fedoraproject.org.

- **file list with times (quick-fedora-mirror)** — cursor: validator

  `https://dl.fedoraproject.org/pub/fedora/fullfiletimelist-fedora`

  Every file of the rsync module with its time and size, rewritten as the tree changes: quick-fedora-mirror diffs it to transfer only what changed (a whole-tree view, 207 MB).

  *Checked live:* 2026-11-15: HEAD → 206,844,839 bytes, last modified 08:12Z; the file starts `[Version] 2 … [Files]`.

**Rate limits.** None published. The master rsync modules on dl.fedoraproject.org are restricted to tier-1 mirrors by IP; the public modules are read-only and open.

**Terms of use.** Fedora asks mirrors to use quick-fedora-mirror, pull from a tier-1 mirror and, for private mirrors, run `report_mirror` after each sync.

**Full-mirror size.** 4.7 TB for all of Fedora Linux; one release's `Everything/x86_64` tree about 250 GB, plus 145 GB of its updates. `https://dl.fedoraproject.org/pub/DIRECTORY_SIZES.txt` of 2026-11-15: `/pub/fedora/linux` 4.7T, `releases/44` 734G (`Everything/x86_64` 248G), `updates/44` 331G (`Everything/x86_64` 145G); EPEL 1002G; end-of-life releases in `/pub/archive` 32T.

**Private and self-hosted upstreams.** Pulp, Artifactory and Nexus YUM repositories generate repodata for what they hold, so the same poll applies. Artifactory's AQL (a `created`/`modified` filter) and Nexus's components REST API (continuation token) and repository webhooks enumerate only what such a server hosts or has cached; neither documents relaying its upstream's feed.

**Notes**

- Until Task 191 this proxy's yum backend decoded only gzip-compressed primaries, so against current Fedora repodata (`.zst`/`.zck` only) it recorded no package digests and served RPMs unverified. It now decodes gzip, xz and zstd primaries and reads them as a stream, one package at a time (`internal/backends/yum/stream.go`); zchunk is not decoded, and `repomd.xml` lists a `.zst` (or `.gz`) primary beside it. It records a primary's digests only once it has verified the primary against `repomd.xml` (whose signature it checks when a keyring is configured) and parsed it whole; populations run one at a time, and none while `repomd.xml` still names the primary loaded.

**Sources.** [Fedora infrastructure: mirroring](https://fedoraproject.org/wiki/Infrastructure/Mirroring) · [Fedora infrastructure: mirror tiering](https://fedoraproject.org/wiki/Infrastructure/Mirroring/Tiering) · [dl.fedoraproject.org directory sizes](https://dl.fedoraproject.org/pub/DIRECTORY_SIZES.txt)

<!-- END GENERATED: full-mirroring catalog -->

## Keeping this page current

The catalog lives in `internal/fullmirror/catalog_data.go`, one entry per upstream type. To
change the page:

1. Edit the entry.
2. Run `make full-mirroring-reference-gen`, which rewrites only the part between the markers
   above.
3. Commit both files.

`make full-mirroring-reference-check` runs in CI and fails when the page is stale.
`go test ./internal/fullmirror` fails in these cases:

- an upstream type the configuration accepts has no entry;
- an entry breaks its tier's rule: a tier-(a) entry leads with a resumable cursor, (b) with a
  complete index, (c) with a listing, and (d) has only partial feeds;
- a feed has no dated live check;
- a source is not a link.

The tasks that build the full-mirror engine and its adapters set each entry's `Status`, which
is the implementation-status column.
