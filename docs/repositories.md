# Repositories: tag tracking and release pinning

The repository registry (Task 180) keeps your releases reproducible from the
proxy's cache. You register a repository. The proxy then follows its tags. When
a tag appears or moves, the proxy reads the lock files at the tagged commit,
fetches every dependency they pin through its own admission gates, and
**pins** those cache objects. Retention, eviction and garbage collection then
never delete them, and a pinned object whose bytes go bad is fetched again.
Moving or deleting the tag later changes nothing about the old release: its
commit keeps its manifest and its pins, and the API calls it *historical*.

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
   otherwise anyone could have the proxy fetch from the Git host. Only tag
   pushes trigger a sync; branch pushes are acknowledged and ignored. Syncs of
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
     LLM scans, …);
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
| Backup / restore | registrations, histories and manifests are backup sources (`repos-registry`, `repos-history`, `repos-manifests`). The mirrors and the trackers' last-seen times are rebuilt. |
| Air-gap export / import | bundles carry the manifests and the pinned keys they hold. An import stores the manifests only from a bundle whose manifest digest was verified (`-manifest-digest`), and never overwrites an object the importing instance has pinned. |

Pins are permanent: removing a repository (`ptctl repos remove`) stops its
tracking but keeps its history, manifests and pins.

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
  repos:
    - name: widgets
      url: https://github.com/acme/widgets.git
      credentialsRef: vault://kv/git/widgets#token   # resolved at each fetch, never stored
      tenant: team-a
      lockfiles: ["package-lock.json", "services/*/go.*"]
      tags: ["v*"]
      upstreams: {cargo: crates}            # only needed when the lock file's registry is not enough
      # roles: [widgets-pinner]             # instead of repositories.roles
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

Notifications: `release_tag` for moved (high) and deleted (medium) tags.
`release_pin` for:

* a release not fully pinned, on its first and its last attempt;
* a digest mismatch (high);
* a lost pinned object (critical).

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

## Alerts

| Alert | Severity | Fires when | Respond |
|-------|----------|-----------|---------|
| `PullthroughReleasePinFailures` | warning | dependencies of a release were refused, could not be fetched, or the manifest could not be stored | `ptctl repos releases <repo>` names each and why. A refusal needs an admission decision (break-glass, or a fixed dependency); fetch failures are retried. |
| `PullthroughReleaseDigestMismatch` | critical | the bytes served for a dependency are not those its lock file pins | Treat as a possible registry compromise or a wrong lock file. Compare the digests in the manifest (`--full`) with the registry's before rebuilding the release. |
| `PullthroughPinnedObjectLost` | critical | a pinned object failed its integrity check and could not be fetched again with its pinned digest | Restore it from a backup or an air-gap bundle; the releases that pin it (`ptctl repos lookup --digest …`) are not reproducible until then. |
| `PullthroughRepositorySyncFailing` | warning | a repository's tags could not be fetched three times in 30 minutes | Check `ptctl repos show <repo>`: the credentials reference, network, or a history that no longer verifies (`ptctl repos verify`). |
