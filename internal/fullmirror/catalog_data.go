package fullmirror

// The research behind this catalog was done on 2026-11-15: every feed was
// checked against the live endpoint with a small request (recorded in the
// feed's Verified field), and the rate limits, terms and sizes come from the
// sources each entry lists. "Not documented" means nothing was found in the
// vendor's documentation, not that the feature is proven absent. Registries
// change: re-check an entry before building on a number in it, and update the
// entry (then `make full-mirroring-reference-gen`) when it no longer holds.

// planPartial is the implementation-status note of a tier-(d) registry with a
// partial feed only.
const planPartial = "no registry-wide feed to follow"

// privateAQLNexus is the part of every "private upstreams" answer that holds
// for Artifactory and Nexus regardless of the ecosystem.
const privateAQLNexus = "Artifactory's AQL (a `created`/`modified` filter) and Nexus's components REST API (continuation token) and repository webhooks enumerate only what such a server hosts or has cached; neither documents relaying its upstream's feed."

var catalog = []Entry{
	// --- (a) incremental change feeds -----------------------------------------
	{
		Type:     "npm",
		Title:    "npm registry",
		Registry: "https://registry.npmjs.org",
		Tier:     TierFeed,
		Feeds: []FeedSpec{
			{
				Name:   "replication feed (`_changes`)",
				URL:    "https://replicate.npmjs.com/_changes?since={seq}&limit=10000",
				Cursor: CursorSequence,
				Semantics: "Each result names a package (`id`), its new revision and `deleted` when it was removed, in order of the integer `seq`; " +
					"store `last_seq` and pass it back as `since`. `limit` defaults to 1000 and is capped at 10000. Since npm's 2025 replication " +
					"migration the feed carries no documents and is poll-only: `include_docs`, `feed=longpoll|continuous`, `style` and `since=now` " +
					"are refused, so the follower fetches each changed packument from `https://registry.npmjs.org/{name}` and the tarballs it names. " +
					"`GET https://replicate.npmjs.com/` returns the current `update_seq`.",
				Verified: "2026-11-15: the root returned `doc_count` 4,610,317 and `update_seq` 144,828,896; `_changes?since=144828890&limit=3` → 200 with " +
					"three changes and `last_seq` 144828900, `limit=10000` → 200; `limit=10001`, `include_docs=true`, `feed=longpoll`, `style=all_docs` " +
					"and `since=now` → 400. The same cursor requested twice 20 s apart was revalidated at the CDN (`cf-cache-status: EXPIRED`), not served stale.",
			},
			{
				Name:   "all package names (`_all_docs`)",
				URL:    "https://replicate.npmjs.com/_all_docs?startkey=%22{name}%22&limit=10000",
				Cursor: CursorPage,
				Semantics: "Every package name in key order, at most 10000 per request: the starting inventory for a follower that begins from " +
					"nothing, and a reconciliation pass for packages the change feed missed.",
				Verified: "2026-11-15: `_all_docs?limit=2` → 200, `total_rows` 4,610,317.",
			},
		},
		RateLimits: "No numeric limit is published for the registry or the replication endpoint, and the responses checked carried no rate-limit headers.",
		Terms: "npm's Open-Source Terms allow replication (\"You may replicate data from the Public Registry using the Public APIs\") but also say " +
			"that \"under no circumstances are five million requests to npm Services in a single month-long period by any single individual, " +
			"organization… remotely reasonable\". A full initial mirror (a packument per package plus every tarball) is far beyond that; following " +
			"the feed after mirroring the packages one depends on is not.",
		Size: Size{
			Figure: "4.6 million packages; no published byte total",
			Basis: "`doc_count` at replicate.npmjs.com on 2026-11-15. npm publishes no storage figure; a 2023 third-party analysis (Sandworm) put " +
				"all versions at about 24 TB — not verified here.",
		},
		Private: "Artifactory and Nexus npm repositories document no `_changes` endpoint. " + privateAQLNexus,
		Notes: []string{
			"The sequence has been reset before (npm's 2021 CouchDB upgrade): a follower must notice a stored `since` beyond the current `update_seq` and fall back to a full pass.",
			"After the 2025 migration users reported packages missing from the feed; reconcile against `_all_docs` now and then.",
		},
		Sources: []Source{
			{"npm staff: changes to the replication APIs (GitHub community discussion 152515)", "https://github.com/orgs/community/discussions/152515"},
			{"GitHub changelog: changes and deprecation notice for npm replication APIs (2025-02-27)", "https://github.blog/changelog/2025-02-27-changes-and-deprecation-notice-for-npm-replication-apis/"},
			{"GitHub changelog: npm CouchDB upgrade will reset the sequence number (2021-09-08)", "https://github.blog/changelog/2021-09-08-npm-couchdb-upgrade-will-reset-sequence-number"},
			{"npm Open-Source Terms", "https://docs.npmjs.com/policies/open-source-terms"},
		},
		Status: ImplStatus{StateImplemented, "Task 190: follows `_changes` from the stored sequence (one beyond `update_seq` means a reset and a new enumeration) after listing `_all_docs`; versions from the packument read through the proxy. Feed option `url` names a CouchDB replica for a private registry."},
	},
	{
		Type:     "pip",
		Title:    "Python Package Index (PyPI)",
		Registry: "https://pypi.org",
		Tier:     TierFeed,
		Feeds: []FeedSpec{
			{
				Name:   "XML-RPC changelog",
				URL:    "https://pypi.org/pypi",
				Cursor: CursorSequence,
				Semantics: "`changelog_since_serial(serial)` returns `[name, version, timestamp, action, serial]` rows newer than the serial — at most " +
					"50,000 per call — and `changelog_last_serial()` the head. Actions cover new projects, releases, files, removals and ownership; " +
					"the follower re-reads each named project from the JSON simple API and downloads new files from files.pythonhosted.org. PyPI " +
					"calls these mirroring methods its only fully supported mirroring interface \"until an improved mechanism for mirroring is " +
					"implemented\", and also says no new integration should use XML-RPC, which is planned for deprecation.",
				Verified: "2026-11-15: `changelog_last_serial` → 43,702,696; `changelog_since_serial(43702693)` → two rows for `sentalign-rust` " +
					"(`create`, `add Owner …`); response headers `ratelimit-policy: \"xmlrpc.client-0\";q=5;w=1, \"xmlrpc.client-1\";q=50;w=60` (per IP).",
			},
			{
				Name:   "simple index with serials (PEP 691 JSON)",
				URL:    "https://pypi.org/simple/",
				Cursor: CursorValidator,
				Semantics: "With `Accept: application/vnd.pypi.simple.v1+json` the index lists every project with its `_last-serial` (the global one " +
					"is `meta._last-serial` and the `X-PyPI-Last-Serial` header). Diff against the previous copy and re-read the projects whose serial " +
					"moved: 46 MB per poll, cached 10 minutes at the CDN. bandersnatch, PyPA's mirror client, made this its default in 2025 and " +
					"removed XML-RPC in 2026 — the fallback when XML-RPC goes away.",
				Verified: "2026-11-15: HEAD → 200, `content-length: 46188765`, `x-pypi-last-serial: 43701540`, `cache-control: max-age=600, public`; " +
					"the body starts `{\"meta\":{\"_last-serial\":43702439,\"api-version\":\"1.4\"},\"projects\":[{\"_last-serial\":3075854,\"name\":\"0\"},…`.",
			},
			{
				Name:    "RSS feeds",
				URL:     "https://pypi.org/rss/updates.xml",
				Cursor:  CursorTimestamp,
				Partial: true,
				Semantics: "The last 100 releases (`updates.xml`) and the 40 newest projects (`packages.xml`). PyPI's API guide recommends them " +
					"\"for periodically checking for new packages or updates\", but 100 releases cover only minutes: a hint between polls, not a feed to follow.",
				Verified: "2026-11-15: 100 and 40 items; the 100 releases spanned 18 minutes (22:26:54 to 22:44:58 UTC, a Sunday evening).",
			},
		},
		RateLimits: "XML-RPC: 5 requests per second and 50 per minute per IP (the live `ratelimit-policy` header; PyPI's docs call it \"a very " +
			"restrictive rate limit\"). The JSON and file APIs have no limit at the edge (\"there is currently no rate limiting of PyPI APIs at the " +
			"edge\"), but PyPI asks clients not to make thousands of requests within minutes.",
		Terms: "PyPI \"reserves the right to temporarily or permanently prohibit a consumer based on irresponsible activity\" and points high-volume " +
			"users to their own mirror or cache. No clause forbids mirroring; bandersnatch is PyPA's own mirror client.",
		Size: Size{
			Figure: "51.6 TB (every file of every release)",
			Basis: "`total_packages_size` = 51,558,788,849,503 bytes from https://pypi.org/stats/ (JSON) on 2026-11-15. The largest projects " +
				"alone run to hundreds of GB (tf-nightly 965.5 GB, tensorflow 429.0 GB).",
		},
		Private: "devpi replicas follow their primary through devpi's own changelog protocol (`/+changelog/{serial}`, `X-DEVPI-SERIAL`). " +
			"Artifactory and Nexus PyPI repositories document neither PyPI's XML-RPC changelog nor its serials. " + privateAQLNexus,
		Notes: []string{
			"A follower that fell more than 50,000 changes behind calls `changelog_since_serial` again with the last serial it received until it reaches the head.",
		},
		Sources: []Source{
			{"PyPI XML-RPC API (warehouse docs)", "https://github.com/pypi/warehouse/blob/main/docs/dev/api-reference/xml-rpc.md"},
			{"warehouse: XML-RPC views (the 50,000-row cap)", "https://github.com/pypi/warehouse/blob/main/warehouse/legacy/api/xmlrpc/views.py"},
			{"PyPI APIs: overview, rate limiting and caching", "https://docs.pypi.org/api/"},
			{"PyPI index API (PEP 691, `_last-serial`)", "https://docs.pypi.org/api/index-api/"},
			{"PyPI statistics", "https://pypi.org/stats/"},
			{"bandersnatch, the PyPA mirror client", "https://github.com/pypa/bandersnatch"},
		},
		Status: ImplStatus{StateImplemented, "Task 190: follows the XML-RPC changelog from the stored serial (one beyond `changelog_last_serial` means a reset and a new enumeration), rows older than feed option `settle` (default 5m: a release's simple page can reach the CDN later), after listing the PEP 691 project list; feed option `mode` `simple`, the fallback where XML-RPC is missing, diffs every project's `_last-serial` against a stored copy instead. Versions from the simple page read through the proxy; names are PEP 503-normalized. Feed option `url` names another Warehouse."},
	},
	{
		Type:     "cargo",
		Title:    "crates.io (Cargo)",
		Registry: "https://index.crates.io",
		Tier:     TierFeed,
		Feeds: []FeedSpec{
			{
				Name:   "Git index commits",
				URL:    "https://github.com/rust-lang/crates.io-index",
				Cursor: CursorCommit,
				Semantics: "The Git index \"is updated live whenever new versions are published\": each commit changes the index file of a crate " +
					"(one JSON line per version with its `cksum`; a yank edits the line). Fetch, diff the stored commit against the new head and " +
					"download `https://static.crates.io/crates/{name}/{name}-{version}.crate` for each new line. The history is squashed into one " +
					"commit weekly; the old history moves to a `snapshot-YYYY-MM-DD` branch of rust-lang/crates.io-index-archive and the " +
					"squash commit names the previous head, so a vanished cursor is recovered from the archive — or by diffing the two trees.",
				Verified: "2026-11-15: `git ls-remote` → HEAD 8d0b4b6f… and, a minute later, 534b96e5…; the repository has `master` and pull-request " +
					"refs, no snapshot branches; crates.io-index-archive has `snapshot-2026-10-12`, `-10-19`, `-10-26`, `-11-02` and `-11-09`.",
			},
			{
				Name:   "daily database dump",
				URL:    "https://static.crates.io/db-dump.tar.gz",
				Cursor: CursorValidator,
				Semantics: "A PostgreSQL CSV dump published every 24 hours: every crate and version with its checksum and `crate_size`. The " +
					"inventory to start a mirror from, and the way to compute its size.",
				Verified: "2026-11-15: HEAD → 307 to cloudfront-static.crates.io, `content-length: 2246923427`, `last-modified: Sun, 15 Nov 2026 02:07:43 GMT`.",
			},
			{
				Name:    "sparse index (per crate)",
				URL:     "https://index.crates.io/{prefix}/{name}",
				Cursor:  CursorValidator,
				Partial: true,
				Semantics: "What cargo reads: one file per crate with `ETag`/`Last-Modified`, cached 10 minutes at the CDN. No listing and no " +
					"change feed — for re-checking crates one already follows, not for discovering new ones.",
				Verified: "2026-11-15: HEAD `/an/yh/anyhow` → 200 with `etag`, `last-modified`, `cache-control: public,max-age=600`; `config.json` names `dl: https://static.crates.io/crates`.",
			},
		},
		RateLimits: "The crates.io API: at most one request per second, with a User-Agent that identifies the client (contact details recommended). " +
			"The index and static.crates.io are CDN-served; no limits are published for them.",
		Terms: "The data-access policy sends bulk users to the index and the database dump instead of crawling the API; it says nothing about downloading crate files in bulk.",
		Size: Size{
			Figure: "378,819 crates; more than 100 GB of crate files already in 2022",
			Basis: "`num_crates` from https://crates.io/api/v1/summary on 2026-11-15. The byte total is the sum of `crate_size` in the dump's " +
				"versions table (not computed here); a third-party tool reported more than 100 GB for every version in 2022.",
		},
		Private: "Private Cargo registries (Artifactory's Cargo repositories, self-hosted servers) serve a sparse or Git index of their own; " +
			"any history it has covers only what they host or have cached. " + privateAQLNexus,
		Sources: []Source{
			{"crates.io snapshot branches move to an archive repository (Rust blog, 2022)", "https://blog.rust-lang.org/2022/02/14/crates-io-snapshot-branches/"},
			{"Cargo's crate index: upcoming squash into one commit (internals)", "https://internals.rust-lang.org/t/cargos-crate-index-upcoming-squash-into-one-commit/8440"},
			{"RFC 3463: crates.io policy update (data access, crawler rules)", "https://rust-lang.github.io/rfcs/3463-crates-io-policy-update.html"},
			{"crates.io data access", "https://crates.io/data-access"},
		},
		Status: ImplStatus{StateImplemented, "Task 190: diffs the trees of the Git index's head commits (a blob-less smart-HTTP fetch, unaffected by the weekly squash); versions from the sparse index read through the proxy. A private registry needs feed option `url`, its Git index."},
	},
	{
		Type:     "go",
		Title:    "Go module mirror (proxy.golang.org)",
		Registry: "https://proxy.golang.org",
		Tier:     TierFeed,
		Feeds: []FeedSpec{
			{
				Name:   "module index",
				URL:    "https://index.golang.org/index?since={timestamp}&limit=2000",
				Cursor: CursorTimestamp,
				Semantics: "Newline-delimited `{Path, Version, Timestamp}` records \"sorted in chronological order\"; pass the last `Timestamp` back " +
					"as `since` (RFC 3339, inclusive — drop the record already seen). `limit` defaults to and is capped at 2000. By default only " +
					"versions the mirror has cached; `include=all` lists every version proxy.golang.org or sum.golang.org ever served. Then fetch " +
					"`/{module}/@v/{version}.info`, `.mod` and `.zip`; new versions \"should be available within one minute\".",
				Verified: "2026-11-15: `limit=3` → the first records date from 2019-04-10; `since=2026-11-15T00:00:00Z&limit=3` → three records from " +
					"00:00:12Z; `limit=2000` → 2000 lines (232 KB); `limit=2500` → 400.",
			},
			{
				Name:   "checksum database log",
				URL:    "https://sum.golang.org/latest",
				Cursor: CursorSequence,
				Semantics: "The transparency log of every module version's go.mod and zip hashes: `/latest` is the signed tree size, `/tile/…` the " +
					"records in order, so the tree size is a resumable cursor over everything ever checksummed — including versions the mirror " +
					"no longer caches.",
				Verified: "2026-11-15: `/latest` → `go.sum database tree`, size 71,436,673.",
			},
		},
		RateLimits: "None documented.",
		Terms: "There is no terms-of-service page; the privacy page (2019-08-06) says requests are logged and IP addresses kept no longer than 30 " +
			"days. \"proxy.golang.org does not save all modules forever.\"",
		Size: Size{
			Figure: "71.4 million module versions checksummed; no byte total published",
			Basis: "sum.golang.org tree size on 2026-11-15 (each leaf is one module version). The mirror publishes no storage figure; tens of " +
				"millions of module zips make a full copy many terabytes (estimate).",
		},
		Private: "Athens has an `/index` of its own (same format, `since`/`limit`, covering only what it has stored) and a `/catalog`. Every " +
			"GOPROXY lists one module's versions at `/{module}/@v/list`. Artifactory and Nexus Go repositories document no index. " + privateAQLNexus,
		Notes: []string{
			"`https://proxy.golang.org/cached-only/…` serves only what the mirror already has, without fetching from the origin.",
		},
		Sources: []Source{
			{"index.golang.org", "https://index.golang.org/"},
			{"proxy.golang.org", "https://proxy.golang.org/"},
			{"proxy.golang.org privacy", "https://proxy.golang.org/privacy"},
			{"Go modules reference: checksum database", "https://go.dev/ref/mod#checksum-database"},
		},
		Status: ImplStatus{StateImplemented, "Task 190: replays the module index from its start, then follows it by timestamp (the records already reported at the stored instant are dropped); tagged versions only, pseudo-versions are left to client pulls. Versions from `@v/list` read through the proxy. Other upstreams are taken to serve Athens' `/index`; feed option `url` names another index."},
	},
	{
		Type:     "nuget",
		Title:    "NuGet Gallery (nuget.org)",
		Registry: "https://api.nuget.org",
		Tier:     TierFeed,
		Feeds: []FeedSpec{
			{
				Name:   "catalog",
				URL:    "https://api.nuget.org/v3/catalog0/index.json",
				Cursor: CursorTimestamp,
				Semantics: "The append-only catalog (`Catalog/3.0.0` in the service index): pages of at most 550 leaves, each a `PackageDetails` " +
					"(push, list/unlist, deprecation, vulnerability update) or `PackageDelete` with its `commitTimeStamp`. Read the pages whose " +
					"`commitTimeStamp` is newer than the cursor, process their newer leaves, store the last timestamp processed (\"no catalog commit " +
					"will ever be added with a time less than or equal to\" it). Leaves carry `packageHash` (SHA-512) and `packageSize`; the .nupkg " +
					"comes from `https://api.nuget.org/v3-flatcontainer/{id}/{version}/{id}.{version}.nupkg`. Handle duplicate leaves idempotently.",
				Verified: "2026-11-15: the index (4.5 MB, `cache-control: no-store`) is an `AppendOnlyCatalog` of 23,568 pages, last commit 2026-11-15T22:44:28Z.",
			},
		},
		RateLimits: "Over a limit nuget.org answers 429 with the time to wait. Documented limits cover the v2 API (20,000 requests a minute per IP for " +
			"`/api/v2/Packages`) and web pages; none are listed for the catalog or the flat container.",
		Terms: "Microsoft documents the catalog for clients that process every package operation (its catalog-reader guidance). nuget.org's terms of use were not reviewed for this page.",
		Size: Size{
			Figure: "594,190 packages, 14,044,198 versions; no byte total published",
			Basis:  "https://www.nuget.org/stats/totals on 2026-11-15. The byte total is the sum of `packageSize` over the catalog's leaves (not computed here).",
		},
		Private: "Microsoft notes that \"not all package sources implement the catalog\"; Artifactory and Nexus document none for their NuGet repositories. " + privateAQLNexus,
		Notes: []string{
			"The catalog is not available in China: the service index there has no Catalog resource.",
		},
		Sources: []Source{
			{"NuGet catalog resource", "https://learn.microsoft.com/en-us/nuget/api/catalog-resource"},
			{"NuGet API rate limits", "https://learn.microsoft.com/en-us/nuget/api/rate-limits"},
			{"nuget.org statistics", "https://www.nuget.org/stats"},
		},
		Status: ImplStatus{StateImplemented, "Task 190: follows the catalog (`Catalog/3.0.0` of the service index) by commit timestamp: the pages committed after the cursor, their newer leaves in commit order, each batch ending at a commit boundary and at commits older than feed option `settle` (default 10m: the flat container lists a version minutes after the catalog commits it); a cursor beyond the last commit (a rebuilt catalog) means a new replay from the first page. Versions from the flat container read through the proxy. Feed option `url` names a catalog index for a feed whose service index names none (Artifactory, Nexus, Azure Artifacts, GitHub Packages)."},
	},
	{
		Type:     "rubygems",
		Title:    "RubyGems.org",
		Registry: "https://rubygems.org",
		Tier:     TierFeed,
		Feeds: []FeedSpec{
			{
				Name:   "compact index `/versions`",
				URL:    "https://rubygems.org/versions",
				Cursor: CursorOffset,
				Semantics: "One line per gem (`name versions md5-of-info`), appended as gems are pushed or yanked. It is \"append only during the " +
					"month\" and \"recalculated at the start of each month, removing yanked rubygems\" — the first line, `created_at:`, changes then. " +
					"Fetch the bytes after the stored length with a Range request; a changed `created_at`, a 416 or a `Repr-Digest` mismatch means " +
					"the file was rewritten, so fetch it whole. For each appended line fetch `/info/{name}` and the gem from `/gems/{name}-{version}.gem`.",
				Verified: "2026-11-15: HEAD → 24,368,445 bytes, `accept-ranges: bytes`; `Range: bytes=0-300` → 206 starting `created_at: 2026-11-01T00:00:04Z`; " +
					"`Range: bytes=-400` → 206 ending with the latest push (`nero 0.7.0.rc7`).",
			},
			{
				Name:   "versions by time window",
				URL:    "https://rubygems.org/api/v1/timeframe_versions.json?from={from}&to={to}&page={page}",
				Cursor: CursorTimestamp,
				Semantics: "Versions created in a window of at most seven days, 30 per page; walk the pages until one is empty. A cross-check " +
					"for the compact index and a way to catch up across a monthly rewrite.",
				Verified: "2026-11-15: from 00:00 to 00:10 UTC → 200 with the versions pushed in those ten minutes.",
			},
			{
				Name:      "activity",
				URL:       "https://rubygems.org/api/v1/activity/just_updated.json",
				Cursor:    CursorTimestamp,
				Partial:   true,
				Semantics: "The 50 most recently updated gems (`latest.json`: the 50 newest gems), cached a minute.",
				Verified:  "2026-11-15: 200, `cache-control: max-age=60, public`.",
			},
		},
		RateLimits: "10 requests per second per IP for the API and website and 15 for the dependency API, enforced at the load balancer; " +
			"application limits answer 429 with `Retry-After`, and extreme cases are blackholed.",
		Terms: "No mirroring clause found; the compact-index guide points bulk users to rubygems.org's public data dumps.",
		Size: Size{
			Figure: "198,697 gems; no byte total published",
			Basis:  "https://rubygems.org/stats on 2026-11-15. Versions are the entries of `/versions`; the byte total is not published.",
		},
		Private: "Gemstash and Artifactory/Nexus RubyGems repositories document no change feed of their upstream. " + privateAQLNexus,
		Notes: []string{
			"A global push webhook (`gem_name=*`) exists, but it needs a RubyGems.org account and an endpoint reachable from the internet.",
		},
		Sources: []Source{
			{"RubyGems.org compact index API", "https://guides.rubygems.org/rubygems-org-compact-index-api/"},
			{"RubyGems.org API (activity, timeframe versions, webhooks)", "https://guides.rubygems.org/rubygems-org-api/"},
			{"RubyGems.org rate limits", "https://guides.rubygems.org/rubygems-org-rate-limits/"},
			{"RubyGems.org statistics", "https://rubygems.org/stats"},
		},
		Status: ImplStatus{StateImplemented, "Task 190: follows the compact index `/versions` with Range requests from the end of a stored copy (If-None-Match, Repr-Digest checked); a digest mismatch, a torn tail or another `created_at` (the monthly rewrite) fetches the whole file and diffs it against the copy. Versions from `/info/<gem>` read through the proxy, platform gems as files of their version. Feed option `url` names another compact-index base."},
	},
	{
		Type:     "composer",
		Title:    "Packagist (Composer)",
		Registry: "https://repo.packagist.org",
		Tier:     TierFeed,
		Feeds: []FeedSpec{
			{
				Name:   "metadata changes",
				URL:    "https://packagist.org/metadata/changes.json?since={since}",
				Cursor: CursorTimestamp,
				Semantics: "`since` is in units of 1/10000 s (`10000 * time()`); without it Packagist answers 400 with the current `timestamp` to " +
					"start from. Actions: `update` (re-fetch `https://repo.packagist.org/p2/{vendor}/{package}.json`, or its `~dev.json`, and require " +
					"`Last-Modified` at least the action's `time`), `delete`, and `resync` of `*` when the cursor is older than the log — \"The " +
					"changes log is kept for up to 24h\", so poll at least daily or rebuild from the package list.",
				Verified: "2026-11-15: no `since` → 400 with `timestamp` 17947827250011; `since` one hour back → 200 with `update` actions " +
					"(`phpsyntax/phpsyntax`, `cakephp/cakephp~dev`, …).",
			},
			{
				Name:      "package list",
				URL:       "https://packagist.org/packages/list.json",
				Cursor:    CursorValidator,
				Semantics: "Every package name (filterable by `vendor` and `type`): the inventory for a first sync and after a `resync`.",
				Verified:  "2026-11-15: HEAD → 200, `cache-control: public, s-maxage=300`.",
			},
		},
		RateLimits: "\"a maximum of 10 concurrent requests, or up to 20 if you only fetch static files\"; spread the load, avoid the full hour, " +
			"use HTTP/2 and `If-Modified-Since`.",
		Terms: "Packagist asks for a User-Agent with contact details (`mailto=`) so it can reach a misbehaving client before blocking its IP. " +
			"Packagist hosts metadata only: the archives are zipballs from GitHub, GitLab or Bitbucket, under their terms.",
		Size: Size{
			Figure: "481,164 packages, 6,077,934 versions (metadata only)",
			Basis:  "https://packagist.org/statistics.json on 2026-11-15. The archives live on the VCS hosts; their total is not published.",
		},
		Private: "Satis builds a static repository without a change feed. Artifactory and Nexus Composer repositories document no `changes.json`. " + privateAQLNexus,
		Sources: []Source{
			{"Packagist API documentation", "https://packagist.org/apidoc"},
			{"Packagist statistics", "https://packagist.org/statistics"},
		},
		Status: ImplStatus{StateImplemented, "Task 190: follows Packagist `metadata/changes.json` from the stored `since` (a `resync` means a new enumeration from `packages/list.json`), `~dev` documents skipped; versions from `/p2/<vendor>/<package>.json` read through the proxy, metadata older than its update retried. A repository other than Packagist needs feed option `url`, a Packagist-compatible site."},
	},
	{
		Type:     "hackage",
		Title:    "Hackage (Haskell)",
		Registry: "https://hackage.haskell.org",
		Tier:     TierFeed,
		Feeds: []FeedSpec{
			{
				Name:   "index tarball tail",
				URL:    "https://hackage.haskell.org/01-index.tar",
				Cursor: CursorOffset,
				Semantics: "Every package description and revision ever uploaded, appended in order (`.cabal` files, `package.json` with each " +
					"tarball's hashes and length, preferred versions). Fetch from the stored length with a Range request — cabal's hackage-security " +
					"does exactly that — and check the result against `snapshot.json` (TUF), which carries the index's length and hashes. The " +
					"history is never rewritten. For each new `package.json` download `/package/{name}-{version}.tar.gz`.",
				Verified: "2026-11-15: HEAD → 1,054,606,848 bytes, `accept-ranges: bytes`, last modified 21:42:02Z; `Range: bytes=-2048` → 206 ending " +
					"with the newest upload's `.cabal`; the `.tar.gz` variant is 141,083,630 bytes.",
			},
			{
				Name:      "recent uploads",
				URL:       "https://hackage.haskell.org/packages/recent.rss",
				Cursor:    CursorTimestamp,
				Partial:   true,
				Semantics: "The 20 most recent uploads (`/packages/recent/revisions.rss` for revisions).",
				Verified:  "2026-11-15: 200, \"Showing 1 - 20 most recent additions\".",
			},
		},
		RateLimits: "None documented; responses come through a CDN with `cache-control: max-age=60`.",
		Terms: "Mirrors are first-class: `mirrors.json` is a TUF-signed list (version 13, expiring 2027-06-01: hackage.fpcomplete.com and a " +
			"DreamObjects bucket), and hackage-mirror-tool syncs to S3 every few minutes.",
		Size: Size{
			Figure: "20.4 GB of package tarballs (155,731 package versions); the index is 1.05 GB",
			Basis: "The sum of the tarball lengths in the index's `package.json` entries (20,391,133,570 bytes), computed from " +
				"`01-index.tar.gz` on 2026-11-15; hackage-mirror-tool's README gave about 7.1 GiB in 2016.",
		},
		Private: "A self-hosted hackage-server serves the same index and TUF files. Artifactory and Nexus have no Hackage format.",
		Sources: []Source{
			{"Hackage API", "https://hackage.haskell.org/api"},
			{"hackage-security", "https://github.com/haskell/hackage-security"},
			{"hackage-mirror-tool", "https://github.com/haskell-hvr/hackage-mirror-tool"},
		},
		Status: ImplStatus{StateImplemented, "Task 190: follows `01-index.tar` with Range requests from the stored end (the hash of the last entry's header detects a replaced index), a change per new `package.json`, after listing `/packages/`; versions from `/package/{name}/preferred`, read from the repository (the backend serves neither JSON document), sdists in the short form clients request. Feed option `url` names a hackage-server for a static mirror."},
	},
	{
		Type:     "cpan",
		Title:    "CPAN (Perl)",
		Registry: "https://cpan.metacpan.org",
		Tier:     TierFeed,
		Feeds: []FeedSpec{
			{
				Name:   "RECENT files",
				URL:    "https://cpan.metacpan.org/RECENT-1h.json",
				Cursor: CursorTimestamp,
				Semantics: "File::Rsync::Mirror::Recent's event log: `{path, type: new|delete, epoch}` entries with unique, strictly decreasing epochs. " +
					"`RECENT-1h` covers the last hour and is merged into `6h`, `1d`, `1W`, `1M`, `1Q`, `1Y` and `Z` (everything); poll the hour file " +
					"and read a longer one when the stored epoch is older than its `minmax.min`. A changed `dirtymark` means a full re-sync. " +
					"Distribution paths are under `authors/id/`.",
				Verified: "2026-11-15: `RECENT-1h.json` (4 KB) on cpan.metacpan.org and www.cpan.org → 31 events, produced by rrrgo v0.2.6; " +
					"`RECENT-1Y.json` is 72.6 MB.",
			},
			{
				Name:    "package index",
				URL:     "https://cpan.metacpan.org/modules/02packages.details.txt.gz",
				Cursor:  CursorValidator,
				Partial: true,
				Semantics: "Every indexed package with the distribution that provides it — the latest release only: the inventory of a minimal " +
					"mirror (minicpan), not the history.",
				Verified: "2026-11-15: HEAD → 2,553,916 bytes, modified 22:17Z.",
			},
		},
		RateLimits: "MetaCPAN asks API users to \"be polite\" (search requests return at most 5,000 hits). rsync mirrors of www.cpan.org are asked " +
			"to sync \"once or twice a day\".",
		Terms: "\"We are not currently adding new public mirrors\"; private mirrors rsync from `cpan-rsync.perl.org::CPAN`, and the mirroring page " +
			"names rrr-client (the RECENT-file client) for near-instant mirroring.",
		Size: Size{
			Figure: "about 40 GB (all of CPAN); about 1 GB for the latest releases only",
			Basis:  "www.cpan.org's mirroring page (undated). BackPAN, which also keeps releases deleted from CPAN, is not included.",
		},
		Private: "minicpan (CPAN::Mini) and Pinto build static repositories with no RECENT files. Artifactory and Nexus have no CPAN format.",
		Sources: []Source{
			{"File::Rsync::Mirror::Recentfile", "https://metacpan.org/pod/File::Rsync::Mirror::Recentfile"},
			{"How to mirror CPAN", "https://www.cpan.org/misc/how-to-mirror.html"},
			{"MetaCPAN API documentation", "https://github.com/metacpan/metacpan-api/blob/master/docs/API-docs.md"},
		},
		Status: ImplStatus{StateImplemented, "Task 190: follows `RECENT-1h.json` from the stored epoch (a longer interval file when the cursor is older than its `minmax.min`; a changed `dirtymark`, or a cursor no file within the read bound reaches, means a new enumeration) after listing what `02packages.details.txt.gz` indexes; an upload is reported once its author directory's `CHECKSUMS` is rewritten, and its versions come from that `CHECKSUMS` read through the proxy. Names are `AUTHOR/Distribution`. Feed option `url` names a full mirror for a minicpan or Pinto upstream."},
	},
	{
		Type:     "julia",
		Title:    "Julia General registry (Pkg servers)",
		Registry: "https://pkg.julialang.org",
		Tier:     TierFeed,
		Feeds: []FeedSpec{
			{
				Name:   "General registry commits",
				URL:    "https://github.com/JuliaRegistries/General",
				Cursor: CursorCommit,
				Semantics: "The registry is a Git repository: a new version is a commit that adds an entry with its `git-tree-sha1` to " +
					"`{L}/{Name}/Versions.toml`. Diff the stored commit against the new head and fetch each new version from the Pkg server as " +
					"`/package/{uuid}/{tree-sha1}` (plus the artifacts it names). A Pkg server's registry list names a tree of a General commit, " +
					"so the server's state maps onto this history — but by default it lags (see the registry flavours below), so a new " +
					"version can be in Git before the Pkg server serves it.",
				Verified: "2026-11-15: `git ls-remote` → HEAD 3a25a072… (an hour later ad00b696…).",
			},
			{
				Name:   "registry snapshot (eager flavour)",
				URL:    "https://pkg.julialang.org/registries.eager",
				Cursor: CursorValidator,
				Semantics: "A Pkg server publishes two flavours of its registry list. `/registries` redirects to `/registries.conservative`, the " +
					"default, which only publishes a registry once the storage servers hold every resource in it; `/registries.eager` (or the " +
					"`Julia-Registry-Preference: eager` header) names the newest tree. Everything else is content-addressed and cacheable " +
					"forever. A new tree hash means new versions; `/registry/{uuid}/{hash}` is the whole registry as a tarball (no delta), so " +
					"without the Git history the follower diffs two snapshots.",
				Verified: "2026-11-15: `/registries` → 301 to eu-central.pkg.julialang.org, then 302 to `/registries.conservative` → tree d6419a18… " +
					"(unchanged for over 35 minutes); `/registries.eager` → d3afc365…, a newer tree.",
			},
		},
		RateLimits: "None documented. The Git feed is on github.com, whose limits for unauthenticated clients apply.",
		Terms: "None found. PkgServer.jl ships a deployment for running one's own Pkg server; the storage servers behind pkg.julialang.org " +
			"require client certificates issued by their operator.",
		Size: Size{
			Figure: "not published",
			Basis:  "Count packages and versions from the registry's `Registry.toml` and `Versions.toml`; each version is a source tarball plus the artifacts (binaries) it declares.",
		},
		Private: "PkgServer.jl speaks the same protocol, flavours included. Artifactory and Nexus have no Julia format.",
		Sources: []Source{
			{"Pkg server protocol", "https://pkgdocs.julialang.org/v1/protocol/"},
			{"Julia environment variables: JULIA_PKG_SERVER_REGISTRY_PREFERENCE", "https://docs.julialang.org/en/v1/manual/environment-variables/"},
			{"JuliaRegistries/General", "https://github.com/JuliaRegistries/General"},
			{"PkgServer.jl", "https://github.com/JuliaPackaging/PkgServer.jl"},
		},
		Status: ImplStatus{StateImplemented, "Task 190: diffs the Pkg server's registry snapshots (`/registries` in the flavour of feed option `flavor`, `conservative` or `eager`): each new registry tree is read through the proxy and its `Registry.toml` and `Versions.toml` files indexed in the state directory; versions from the stored index, package tarballs by uuid and git-tree-sha1. Package artifacts are not followed."},
	},
	{
		Type:     "bazel",
		Title:    "Bazel Central Registry (BCR)",
		Registry: "https://bcr.bazel.build",
		Tier:     TierFeed,
		Feeds: []FeedSpec{
			{
				Name:   "BCR commits",
				URL:    "https://github.com/bazelbuild/bazel-central-registry",
				Cursor: CursorCommit,
				Semantics: "bcr.bazel.build is a static tree built from this repository: a new version is a commit adding " +
					"`modules/{name}/{version}/` (`MODULE.bazel`, `source.json`) and listing it in `modules/{name}/metadata.json`. Diff the stored " +
					"commit against the new head; each new `source.json` names the source archive (mostly a GitHub release or tag archive) and its " +
					"SRI `integrity`, which is what Bazel downloads.",
				Verified: "2026-11-15: `git ls-remote` → HEAD 4410f9ba…; `bazel_registry.json` → `{\"mirrors\": []}`; `modules/rules_go/metadata.json` lists its versions.",
			},
		},
		RateLimits: "None documented for bcr.bazel.build; the Git feed and most source archives are on GitHub, whose unauthenticated limits apply.",
		Terms:      "None found. Bazel documents `mirrors` in `bazel_registry.json` and `mirror_urls` in `source.json` for mirroring source archives.",
		Size: Size{
			Figure: "metadata only; the archives live at their upstream URLs",
			Basis:  "The registry protocol stores no archives. Count: the directories under `modules/`; bytes: the archives every `source.json` names (not computed).",
		},
		Private: "A self-hosted registry is any static tree, Git repository or `file://` path with the same layout — no listing either. " +
			"Artifactory has a remote-only Bazel Modules repository; Nexus has no Bazel format.",
		Notes: []string{
			"The registry protocol has no list of modules and no feed; only the Git history enumerates it.",
		},
		Sources: []Source{
			{"Bazel registries", "https://bazel.build/external/registry"},
			{"bazelbuild/bazel-central-registry", "https://github.com/bazelbuild/bazel-central-registry"},
		},
		Status: ImplStatus{StateImplemented, "Task 190: diffs the trees of bazel-central-registry's head commits once they have settled (feed option `settle`, default 10m), one change per version directory; versions from metadata.json read through the proxy, each with MODULE.bazel, the source archive and the patches and overlay files its source.json lists. Another registry needs feed option `url`, its Git repository."},
	},
	{
		Type:     "conan",
		Title:    "ConanCenter (center2.conan.io)",
		Registry: "https://center2.conan.io",
		Tier:     TierFeed,
		Feeds: []FeedSpec{
			{
				Name:   "conan-center-index commits",
				URL:    "https://github.com/conan-io/conan-center-index",
				Cursor: CursorCommit,
				Semantics: "ConanCenter's recipes: a merged pull request changes `recipes/{name}/…`, then ConanCenter's CI exports a new recipe " +
					"revision and builds binaries for center2 (the delay is not documented). Diff the stored commit, then ask center2 for the " +
					"changed references' revisions (`/v2/conans/{name}/{version}/_/_/revisions`) until the new one appears.",
				Verified: "2026-11-15: `git ls-remote` → HEAD 6f3abb46…; `/v2/conans/zlib/1.3.1/_/_/revisions` → 200, revisions with times (latest 2025-12-09).",
			},
			{
				Name:    "recipe search",
				URL:     "https://center2.conan.io/v2/conans/search?q=*",
				Cursor:  CursorValidator,
				Partial: true,
				Semantics: "Every recipe reference (`name/version@_/_`) in one response: new versions show up, a new revision of an existing " +
					"version or new binaries do not.",
				Verified: "2026-11-15: `q=*` → 9,729 references (221 KB); `q=zlib*` → 24.",
			},
		},
		RateLimits: "None documented.",
		Terms: "No availability guarantee: Conan's documentation recommends hosting your own copy of the ConanCenter recipes and binaries you " +
			"use. center.conan.io (Conan 1) has been frozen since November 2024.",
		Size: Size{
			Figure: "9,729 recipe versions of 1,943 libraries; binaries not counted",
			Basis:  "Live search on 2026-11-15 (Conan's documentation says \"over 1500\" libraries). Revision and binary counts and bytes are not published.",
		},
		Private: "Artifactory (Conan local/remote/virtual) and Nexus (Conan proxy/hosted/group) have Conan repositories; whether their search lists " +
			"an upstream's references is not documented. Conan 2's `local-recipes-index` remote serves a clone of conan-center-index directly, " +
			"which makes the Git history the feed.",
		Sources: []Source{
			{"Conan Center will stop receiving updates for Conan 1 (2024-09-30)", "https://blog.conan.io/2024/09/30/Conan-Center-will-stop-receiving-updates-for-Conan-1.html"},
			{"Using ConanCenter (Conan 2 docs)", "https://docs.conan.io/2/devops/using_conancenter.html"},
			{"Introducing the local-recipes-index remote", "https://blog.conan.io/2024/04/23/Introducing-local-recipes-index-remote.html"},
		},
		Status: ImplStatus{StateImplemented, "Task 190: diffs the trees of conan-center-index's head commits once they have settled (feed option `settle`, default 1h), one change per recipe; versions from the remote's recipe search, each with the files of its latest recipe revision read through the proxy, binary packages per feed option `binaries` (none, all, or settings to match). Another remote needs feed option `url`, a Git repository laid out as conan-center-index."},
	},

	{
		Type:     "homebrew",
		Title:    "Homebrew (formulae.brew.sh, bottles on ghcr.io)",
		Registry: "https://formulae.brew.sh",
		Tier:     TierFeed,
		Feeds: []FeedSpec{
			{
				Name:   "homebrew-core commits",
				URL:    "https://github.com/Homebrew/homebrew-core",
				Cursor: CursorCommit,
				Semantics: "Every formula is a Ruby file `Formula/{letter}/{name}.rb` here, with a bottle block (a SHA-256 per platform) committed " +
					"once its bottles are on ghcr.io; formulae.brew.sh's JSON is generated from this repository. Diff the stored commit against the " +
					"new head and, for each changed formula, read `https://formulae.brew.sh/api/formula/{name}.json` and fetch the new bottles. " +
					"The repository is large; casks live in Homebrew/homebrew-cask (the proxy passes cask documents through and serves no cask downloads).",
				Verified: "2026-11-15: `git ls-remote` → HEAD 0d406593….",
			},
			{
				Name:   "formula and cask JSON",
				URL:    "https://formulae.brew.sh/api/formula.jws.json",
				Cursor: CursorValidator,
				Semantics: "Every formula with its current version and its bottles' URLs and SHA-256 per platform (`formula.jws.json` is the signed " +
					"form brew downloads, `formula.json` the plain one), and every cask in `cask.json`. Regenerated within minutes of a " +
					"homebrew-core change: the poll-and-diff alternative to the Git history, at 35 MB per changed poll. Only current versions are listed.",
				Verified: "2026-11-15: `formula.json` 32,238,782 bytes, `formula.jws.json` 34,929,508, `cask.json` 19,469,952, each modified minutes before the request.",
			},
		},
		RateLimits: "None documented for formulae.brew.sh; bottle downloads use anonymous ghcr.io tokens, for which no limits are published. The Git feed is on github.com, whose limits for unauthenticated clients apply.",
		Terms:      "None found.",
		Size: Size{
			Figure: "not published",
			Basis:  "The sum of the bottles for the platforms one supports: each formula has a bottle per supported macOS version and Linux; the JSON lists their URLs, not their sizes.",
		},
		Private: "Homebrew's own mirror settings (`HOMEBREW_API_DOMAIN` for the JSON, `HOMEBREW_BOTTLE_DOMAIN` for bottles) point clients at " +
			"static copies, which have no feed of their own; no Homebrew repository type is documented for Artifactory or Nexus.",
		Notes: []string{
			"Tier (a) through homebrew-core's history; formulae.brew.sh on its own is a complete index (tier b).",
		},
		Sources: []Source{
			{"Homebrew formulae JSON API", "https://formulae.brew.sh/docs/api/"},
			{"brew: Library/Homebrew/api/formula.rb (signed JSON)", "https://github.com/Homebrew/brew/blob/HEAD/Library/Homebrew/api/formula.rb"},
			{"Homebrew/homebrew-core", "https://github.com/Homebrew/homebrew-core"},
		},
		Status: ImplStatus{StateImplemented, "Task 190: diffs the Formula trees of homebrew-core's head commits once they have settled (feed option `settle`, default 30m); the current version from the formula JSON read through the proxy, one artifact per bottle (feed option `platforms` keeps some; disabled formulae are skipped). Task 191: a mirror of the JSON API is followed through its formula index, `/api/formula.json`, polled conditionally and diffed, one change per version added or rebottled; the version and its bottles from the copy of the index, at the paths the backend rewrites them to (feed option `mode`: `auto`, the default, `git` or `index`)."},
	},
	// --- (b) complete indexes to poll and diff ------------------------------------
	{
		Type:     "apt",
		Aliases:  []string{"deb"},
		Title:    "Debian / Ubuntu APT archives",
		Registry: "https://deb.debian.org/debian",
		Tier:     TierIndex,
		Feeds: []FeedSpec{
			{
				Name:   "Release and Packages indexes",
				URL:    "https://deb.debian.org/debian/dists/{suite}/InRelease",
				Cursor: CursorValidator,
				Semantics: "`InRelease` (signed) lists every index of the suite with its size and hashes; `{component}/binary-{arch}/Packages.xz` " +
					"lists every package with its `Filename`, size and SHA-256. Poll `InRelease` with a conditional request; when it changed, fetch " +
					"the changed `Packages` files (by hash, `Acquire-By-Hash: yes`) and diff. The archive is published four times a day; stable " +
					"changes only at point releases and is updated in between through `{codename}-updates` and the security archive.",
				Verified: "2026-11-15: stable `InRelease` → 140 KB, Debian 13.7 (trixie) of 2026-09-12 with `Acquire-By-Hash: yes`; " +
					"`main/binary-amd64/Packages.xz` → 9,678,380 bytes; Ubuntu's `noble/InRelease` → 200.",
			},
			{
				Name:   "index diffs (pdiffs)",
				URL:    "https://deb.debian.org/debian/dists/{suite}/{component}/binary-{arch}/Packages.diff/Index",
				Cursor: CursorValidator,
				Semantics: "Ed-style patches from earlier `Packages` files to the current one, keyed by each earlier file's SHA-256: a follower " +
					"holding a recent copy downloads a few KB instead of the whole index. Published for suites that change between point " +
					"releases (unstable, testing, the -updates suites).",
				Verified: "2026-11-15: unstable's `Packages.diff/Index` → history back to 2026-11-02, four entries a day; stable has none (404).",
			},
		},
		RateLimits: "None published for deb.debian.org.",
		Terms: "Debian's mirroring guide prescribes ftpsync over rsync from an upstream mirror (\"Do not use your own scripts, and do not just use " +
			"single-pass rsyncs\") and advises against service names that resolve to several addresses (its example is ftp.us.debian.org; the " +
			"CDN name deb.debian.org is one too). A follower that " +
			"polls one suite's `InRelease` over HTTP is a cache, not what the guide calls a mirror.",
		Size: Size{
			Figure: "Debian: 5,451 GB for every architecture, about 1,340 GB for amd64 + all + source; Ubuntu: about 3.6 TB",
			Basis:  "https://www.debian.org/mirror/size (updated daily, read 2026-11-15); Ubuntu's mirror documentation (September 2025).",
		},
		Private: "A private APT repository (aptly, Pulp, Artifactory, Nexus) publishes the same Release/Packages layout for what it holds, so the same poll applies. " + privateAQLNexus,
		Notes: []string{
			"`Packages` lists current versions only: a superseded version drops out of the index (snapshot.debian.org keeps the history), so a mirror that wants every version keeps what it fetched.",
		},
		Sources: []Source{
			{"Debian: setting up a mirror", "https://www.debian.org/mirror/ftpmirror"},
			{"Debian: mirror size", "https://www.debian.org/mirror/size"},
			{"Ubuntu release team: mirrors", "https://documentation.ubuntu.com/project/release-team/mirrors"},
		},
		Status: ImplStatus{StateImplemented, "Task 191: polls each suite's `InRelease` (or `Release`) conditionally and reads, by hash and verified, the `Packages` indexes whose SHA-256 changed, diffing a stored copy; versions and files from the index itself (dpkg order). Feed options `suites` (required), `components` (default `main`), `architectures` (default `amd64`; `all` reads `binary-all` where the Release lists it, and is skipped where it does not, as on Ubuntu), `url` (another archive root). The apt backend verifies a `.deb` only against a `Packages` file it served by name: mirrored `.deb`s are cached without that check (see the findings below)."},
	},
	{
		Type:     "yum",
		Aliases:  []string{"rpm"},
		Title:    "Fedora and RHEL-family YUM repositories",
		Registry: "https://dl.fedoraproject.org/pub/fedora/linux",
		Tier:     TierIndex,
		Feeds: []FeedSpec{
			{
				Name:   "repomd.xml and primary",
				URL:    "https://dl.fedoraproject.org/pub/fedora/linux/updates/{release}/Everything/{arch}/repodata/repomd.xml",
				Cursor: CursorValidator,
				Semantics: "`repomd.xml` has a `revision` and the location, size and checksum of `primary` (every package with its location " +
					"and checksum). Poll it; when the revision moved, fetch the new primary and diff. Current Fedora publishes primary as zstd " +
					"(`.zst`) and zchunk (`.zck`, which lets a client fetch only the changed chunks) — no gzip.",
				Verified: "2026-11-15: updates/44 x86_64 `repomd.xml` → revision 1794702405, `primary.xml.zst` 7.0 MB, `primary.xml.zck` 9.3 MB, no " +
					"`.gz`. `releases/40/Everything/x86_64/os/repodata/repomd.xml` → 404, Fedora 41's too (the release directories keep only a README): " +
					"releases past their end of life move to archives.fedoraproject.org.",
			},
			{
				Name:   "file list with times (quick-fedora-mirror)",
				URL:    "https://dl.fedoraproject.org/pub/fedora/fullfiletimelist-fedora",
				Cursor: CursorValidator,
				Semantics: "Every file of the rsync module with its time and size, rewritten as the tree changes: quick-fedora-mirror diffs it to " +
					"transfer only what changed (a whole-tree view, 207 MB).",
				Verified: "2026-11-15: HEAD → 206,844,839 bytes, last modified 08:12Z; the file starts `[Version] 2 … [Files]`.",
			},
		},
		RateLimits: "None published. The master rsync modules on dl.fedoraproject.org are restricted to tier-1 mirrors by IP; the public modules are read-only and open.",
		Terms:      "Fedora asks mirrors to use quick-fedora-mirror, pull from a tier-1 mirror and, for private mirrors, run `report_mirror` after each sync.",
		Size: Size{
			Figure: "4.7 TB for all of Fedora Linux; one release's `Everything/x86_64` tree about 250 GB, plus 145 GB of its updates",
			Basis: "`https://dl.fedoraproject.org/pub/DIRECTORY_SIZES.txt` of 2026-11-15: `/pub/fedora/linux` 4.7T, `releases/44` 734G " +
				"(`Everything/x86_64` 248G), `updates/44` 331G (`Everything/x86_64` 145G); EPEL 1002G; end-of-life releases in `/pub/archive` 32T.",
		},
		Private: "Pulp, Artifactory and Nexus YUM repositories generate repodata for what they hold, so the same poll applies. " + privateAQLNexus,
		Notes: []string{
			"Until Task 191 this proxy's yum backend decoded only gzip-compressed primaries, so against current Fedora repodata (`.zst`/`.zck` only) it recorded no package digests and served RPMs unverified. It now decodes gzip, xz and zstd primaries and reads them as a stream, one package at a time (`internal/backends/yum/stream.go`); zchunk is not decoded, and `repomd.xml` lists a `.zst` (or `.gz`) primary beside it. It records a primary's digests only once it has verified the primary against `repomd.xml` (whose signature it checks when a keyring is configured) and parsed it whole; populations run one at a time, and none while `repomd.xml` still names the primary loaded.",
		},
		Sources: []Source{
			{"Fedora infrastructure: mirroring", "https://fedoraproject.org/wiki/Infrastructure/Mirroring"},
			{"Fedora infrastructure: mirror tiering", "https://fedoraproject.org/wiki/Infrastructure/Mirroring/Tiering"},
			{"dl.fedoraproject.org directory sizes", "https://dl.fedoraproject.org/pub/DIRECTORY_SIZES.txt"},
		},
		Status: ImplStatus{StateImplemented, "Task 191: polls `repodata/repomd.xml` conditionally and, when its primary changed, streams the primary (zstd, gzip or xz; size and checksums verified) into a stored copy it diffs; versions (`[epoch:]version-release`, rpm order) and files from the primary itself. One upstream is one repository root; feed option `url` names another mirror of it."},
	},
	{
		Type:     "helm",
		Title:    "Helm chart repositories",
		Registry: "https://charts.bitnami.com/bitnami",
		Tier:     TierIndex,
		Feeds: []FeedSpec{
			{
				Name:   "repository `index.yaml`",
				URL:    "https://charts.bitnami.com/bitnami/index.yaml",
				Cursor: CursorValidator,
				Semantics: "A classic chart repository publishes one `index.yaml` with every chart version, its archive URLs and `digest`; poll it " +
					"(ETag/Last-Modified) and diff. It covers one repository — Helm has no central registry.",
				Verified: "2026-11-15: Bitnami's index redirects to `https://repo.broadcom.com/bitnami-files/index.yaml` (27.6 MB, modified " +
					"2026-11-14); prometheus-community's is 6.8 MB.",
			},
			{
				Name:    "Artifact Hub search",
				URL:     "https://artifacthub.io/api/v1/packages/search?kind=0&sort=last_updated&limit=60&offset={offset}",
				Cursor:  CursorPage,
				Partial: true,
				Semantics: "Charts of every repository listed on Artifact Hub, by `last_updated`, at most 60 per page (total in " +
					"`Pagination-Total-Count`): a way to discover repositories and new chart versions across them.",
				Verified: "2026-11-15: `limit=2` → 200, newest package `bi-stack` 0.0.4.",
			},
			{
				Name:      "Artifact Hub Helm exporter",
				URL:       "https://artifacthub.io/api/v1/helm-exporter",
				Cursor:    CursorValidator,
				Partial:   true,
				Semantics: "\"the latest version available of all charts listed in Artifact Hub\" with each repository's URL, in one document cached for an hour.",
				Verified:  "2026-11-15: 200, 2,759,297 bytes, `cache-control: max-age=3600`.",
			},
		},
		RateLimits: "Chart repositories are static files (often GitHub Pages) with no published limits; Artifact Hub documents a 429 without numbers.",
		Terms: "Per repository. Bitnami announced in 2025 that its packaged charts stay available on `docker.io/bitnamicharts` as OCI " +
			"artifacts \"but they will no longer receive updates\", and removed its free public image catalog (scheduled for 2025-09-29).",
		Size: Size{
			Figure: "per repository (Bitnami's index alone is 27.6 MB)",
			Basis:  "Helm has no central registry, so there is no total; a repository's size is the sum of the archives its `index.yaml` lists.",
		},
		Private: "ChartMuseum, Artifactory and Nexus Helm repositories serve an `index.yaml` of what they hold, so the same poll applies. " +
			"Charts in OCI registries (`oci://`) have no index and behave like the docker type (tier d).",
		Sources: []Source{
			{"Artifact Hub API (OpenAPI)", "https://raw.githubusercontent.com/artifacthub/hub/master/docs/api/openapi.yaml"},
			{"Bitnami charts: upcoming changes (issue 35164)", "https://github.com/bitnami/charts/issues/35164"},
			{"Helm: chart repository guide", "https://helm.sh/docs/topics/chart_repository/"},
		},
		Status: ImplStatus{StateImplemented, "Task 191: polls the repository's `index.yaml` conditionally (ETag/Last-Modified, redirects followed) and diffs it against a stored copy, one record per chart version (`created` left out: an index regenerated without `--merge` re-reports nothing); the index is read as a stream (one of at most 8 MiB the streaming reader does not handle is read whole with yaml.v3, a larger one is refused). A version is reported once listed for feed option `settle` (default 15m, from the poll that first saw it), so that the index the backend reads lists it too. Versions from the stored copy, each with its archive at the path the backend's rewritten index hands clients. Feed option `url` names another copy of the index; an OCI upstream (setting `oci`) cannot be followed."},
	},
	{
		Type:     "conda",
		Title:    "conda-forge (anaconda.org)",
		Registry: "https://conda.anaconda.org/conda-forge",
		Tier:     TierIndex,
		Feeds: []FeedSpec{
			{
				Name:   "repodata per subdir",
				URL:    "https://conda.anaconda.org/conda-forge/{subdir}/repodata.json.zst",
				Cursor: CursorValidator,
				Semantics: "Every package file of a subdir (`linux-64`, `noarch`, …) with its size and hashes; poll with ETag and diff. " +
					"Uncompressed, linux-64 is 468 MB and noarch 196 MB (29.6 MB as zstd).",
				Verified: "2026-11-15: HEAD noarch `repodata.json` → 196,244,999 bytes, `.zst` → 29,637,890; linux-64 → 468,076,086; all modified within the previous 30 minutes.",
			},
			{
				Name:   "sharded repodata index",
				URL:    "https://conda.anaconda.org/conda-forge/{subdir}/repodata_shards.msgpack.zst",
				Cursor: CursorValidator,
				Semantics: "CEP-16: maps each package name to the SHA-256 of its shard (`shards/{sha256}.msgpack.zst`); a changed hash means that " +
					"package changed, so a follower diffs a 1 MB index and fetches only the changed shards.",
				Verified: "2026-11-15: noarch shard index → 989,071 bytes, modified 22:29Z (the copy on fast.prefix.dev was last modified 2025-06-14).",
			},
		},
		RateLimits: "None published.",
		Terms: "conda-forge packages are free to use, including commercially. Anaconda's own `defaults` channels (repo.anaconda.com) fall under " +
			"Anaconda's terms of service, which require a paid license for larger organisations; those terms do not cover conda-forge.",
		Size: Size{
			Figure: "more than 3 TB (all subdirs; an old vendor figure)",
			Basis: "Anaconda's Package Security Manager mirroring documentation gives conda-forge 3 TB in the same sentence that gives PyPI " +
				"10 TB (51.6 TB today), and a 2021 conda-forge thread gave the same 3 TB. Exact: the sum of `size` over every subdir's repodata.",
		},
		Private: "Artifactory (Conda local/remote/virtual), Nexus (Conda proxy/hosted/group), Quetz and prefix.dev channels serve repodata for what they hold, so the same poll applies. " + privateAQLNexus,
		Notes: []string{
			"Measured on 2026-11-16: following conda-forge's six default subdirs reads 236 MB of zstd per poll that finds them all changed (about 1.6 GB of JSON, under a minute of CPU), and conda-forge changes every few minutes — about 17 GB a day at a 5-minute poll interval; `current_repodata.json` of the same subdirs is 41 MB.",
			"Incremental repodata patches (JLAP) are not served: `repodata.jlap` → 404 on 2026-11-15.",
		},
		Sources: []Source{
			{"conda: sharded repodata", "https://docs.conda.io/projects/conda/en/stable/dev-guide/deep-dives/sharded.html"},
			{"How we reduced conda's index fetch bandwidth by 99% (JLAP)", "https://conda.discourse.group/t/how-we-reduced-condas-index-fetch-bandwidth-by-99/257"},
			{"Anaconda Package Security Manager: mirrors", "https://www.anaconda.com/docs/psm/on-prem/latest/admin/mirrors"},
			{"conda-forge: total size of the conda-forge repo (2021)", "https://groups.google.com/g/conda-forge/c/AlY_u8TCjO8"},
		},
		Status: ImplStatus{StateImplemented, "Task 191: polls each followed subdir's `repodata.json.zst` (`repodata.json` where there is none, the `.zst` asked for again at every poll; a 403 counts as not found, as S3 answers) conditionally and diffs it against a stored copy, an unchanged subdir copied rather than read again, one that stops answering kept for 3 polls; a file is reported once listed for feed option `settle` (default 30m, from the poll that first saw it), so that the plain `repodata.json` the backend verifies against lists it. Versions from the stored copy, each with every file (every build, both formats) of the subdirs followed. Feed options `subdirs` (default noarch, linux-64, linux-aarch64, osx-64, osx-arm64, win-64), `index` (`repodata`, or `current`: `current_repodata.json`, the latest versions only), `settle` and `url` (another channel)."},
	},
	{
		Type:     "cran",
		Title:    "CRAN (R)",
		Registry: "https://cloud.r-project.org",
		Tier:     TierIndex,
		Feeds: []FeedSpec{
			{
				Name:   "PACKAGES index",
				URL:    "https://cloud.r-project.org/src/contrib/PACKAGES.gz",
				Cursor: CursorValidator,
				Semantics: "Every current source package with its version and MD5 sum; poll and diff. Superseded versions move to " +
					"`src/contrib/Archive/{name}/` and are listed in `src/contrib/Meta/archive.rds` (an R serialised object). Windows and macOS " +
					"binaries have a `PACKAGES` per R version.",
				Verified: "2026-11-15: `PACKAGES` 7,491,081 bytes, `PACKAGES.gz` 1,980,364 (both modified 21:42Z); `Meta/archive.rds` 5,584,516.",
			},
			{
				Name:      "packages by date",
				URL:       "https://cloud.r-project.org/web/packages/available_packages_by_date.html",
				Cursor:    CursorTimestamp,
				Partial:   true,
				Semantics: "Current packages sorted by publication date, as an HTML page.",
				Verified:  "2026-11-15: 200, 4,986,460 bytes.",
			},
		},
		RateLimits: "None published for cloud.r-project.org (sponsored by Posit). rsync mirrors sync \"at least twice a week, better every 1-2 days, but not more than twice a day.\"",
		Terms:      "Mirrors rsync from cran.r-project.org (SSH recommended) and are listed once CRAN accepts them.",
		Size: Size{
			Figure: "about 410 GB (sources, archive and binaries)",
			Basis:  "CRAN mirror HOWTO: \"The full size of CRAN was approx 410 GB on 2024-02-22\".",
		},
		Private: "Posit Package Manager, miniCRAN, Artifactory (CRAN) and Nexus (R) serve `PACKAGES` for what they hold, so the same poll applies. " + privateAQLNexus,
		Sources: []Source{
			{"CRAN mirror HOWTO", "https://cran.r-project.org/mirror-howto.html"},
			{"CRAN mirrors", "https://cran.r-project.org/mirrors.html"},
		},
		Status: ImplStatus{StateImplemented, "Task 191: polls `src/contrib/PACKAGES.gz` (`PACKAGES` where there is none, `PACKAGES.gz` asked for again at every poll; a 403 counts as not found) conditionally and diffs it against a stored copy; a version is reported once listed for feed option `settle` (default 45m, from the poll that first saw it; the version it supersedes is kept meanwhile), so that the plain `PACKAGES` the backend verifies against lists it. Each package's current version from the stored copy, with its source tarball where R downloads it. Archived versions (listed only in `Meta/archive.rds`) and Windows/macOS binaries are not followed. Feed options `settle` and `url` (another repository root)."},
	},
	{
		Type:     "hex",
		Title:    "Hex (Elixir and Erlang)",
		Registry: "https://repo.hex.pm",
		Tier:     TierIndex,
		Feeds: []FeedSpec{
			{
				Name:   "names and versions",
				URL:    "https://repo.hex.pm/names",
				Cursor: CursorValidator,
				Semantics: "Signed, gzipped protobuf: `/names` lists every public package with its `updated_at`, `/versions` every package's " +
					"versions. Poll both, diff, fetch `/packages/{name}` (the signed release list with checksums) for the names whose `updated_at` " +
					"moved, then `/tarballs/{name}-{version}.tar`. `/names` is marked as being \"for full registry sync\". Both are small (379 KB and 392 KB).",
				Verified: "2026-11-15: `/names` 378,972 bytes and `/versions` 392,124 bytes, both modified 22:36:28Z.",
			},
			{
				Name:      "packages by update time",
				URL:       "https://hex.pm/api/packages?sort=updated_at&page={page}",
				Cursor:    CursorPage,
				Semantics: "The API's listing, newest first, 100 per page.",
				Verified:  "2026-11-15: 200 with `x-ratelimit-limit: 100`.",
			},
		},
		RateLimits: "API: 100 requests per minute per IP (500 when authenticated), with `X-RateLimit-*` headers; 304 answers do not count. repo.hex.pm is CDN-served.",
		Terms: "\"The repository can be mirrored by setting up a caching proxy in front of it\"; mirrors \"do not need to be trusted\" because " +
			"the registry resources are signed. `HEX_MIRROR` selects a mirror.",
		Size: Size{
			Figure: "not published",
			Basis:  "Count packages from `/names` and releases from `/versions`; bytes are the sum of the release tarballs (not computed).",
		},
		Private: "Artifactory has Hex local/remote/virtual repositories (a remote re-signs the registry with its own key); Nexus has no Hex " +
			"format; mini_repo can mirror hex.pm; organisations' private repositories have their own `/repos/{repo}/names`.",
		Sources: []Source{
			{"Hex registry v2 specification", "https://github.com/hexpm/specifications/blob/main/registry-v2.md"},
			{"Hex repository endpoints", "https://github.com/hexpm/specifications/blob/main/endpoints.md"},
			{"Hex API (rate limits)", "https://github.com/hexpm/specifications/blob/main/apiary.apib"},
			{"Hex mirrors", "https://hex.pm/docs/mirrors"},
			{"Artifactory Hex repositories", "https://docs.jfrog.com/artifactory/docs/hex-repositories"},
		},
		Status: ImplStatus{StateImplemented, "Task 191: polls the signed `/names` and `/versions` with conditional requests and diffs `/versions`, one change per version added, retired or gone; versions and their tarballs from the copy, retired versions yanked. `/versions` must verify (hex.pm's key, which also signs its organisations' repositories; feed option `publicKey` names another, or `none`) and name the repository (`hexpm`, an organisation's own name; feed option `repository`); `/names` gives only the head time. Feed option `url` names another repository."},
	},
	{
		Type:     "maven",
		Title:    "Maven Central",
		Registry: "https://repo1.maven.org/maven2",
		Tier:     TierIndex,
		Feeds: []FeedSpec{
			{
				Name:   "Maven Indexer index",
				URL:    "https://repo1.maven.org/maven2/.index/nexus-maven-repository-index.properties",
				Cursor: CursorValidator,
				Semantics: "The full index (`nexus-maven-repository-index.gz`) and incremental chunks `nexus-maven-repository-index.{n}.gz` chained " +
					"from the properties file (`nexus.index.last-incremental`; the last 30 are kept): a follower holding chunk n fetches n+1 to " +
					"the last, otherwise the full index. Records are Lucene documents (Maven Indexer format) with groupId, artifactId, version, " +
					"packaging and SHA-1. Sonatype rebuilds the index on \"a roughly two-week cycle\", calls it \"largely a deprecated artifact\" " +
					"and limits index downloads per IP: new releases reach it weeks late, so fetch it at most once per cycle and poll the " +
					"`maven-metadata.xml` of the artifacts one depends on for timely news.",
				Verified: "2026-11-15: the properties file is dated Thu Oct 22 17:25:57 UTC 2026 (last incremental 941, chunks 912–941); the full " +
					"index is 3,351,259,806 bytes, modified 2026-10-22. A second HEAD of the full index from the same host 38 minutes later → 429 " +
					"with `retry-after: 86400`: \"Individual ip limits apply to this file.\"",
			},
			{
				Name:      "maven-metadata.xml per artifact",
				URL:       "https://repo1.maven.org/maven2/{group-path}/{artifact}/maven-metadata.xml",
				Cursor:    CursorValidator,
				Partial:   true,
				Semantics: "Every version of one artifact with `lastUpdated`: the way to follow the artifacts one depends on.",
				Verified:  "2026-11-15: `org/slf4j/slf4j-api` → latest 2.1.0-alpha1, `lastUpdated` 20260922145706.",
			},
		},
		RateLimits: "Index files have per-IP download limits (a second request for the full index within the hour was refused for 24 hours). Beyond that Sonatype " +
			"rate-limits abusive traffic patterns with 429s and blocks of \"up to a maximum of 30 days\", aimed at \"the top few percent\", " +
			"and recommends consolidating requests through a repository manager.",
		Terms: "**Full mirroring is forbidden.** The Central Repository Terms of Service (last updated 2026-03-31) list \"Attempting to download " +
			"all or large portions of the Materials stored in Central (a.k.a., scraping or mirroring any content)\" as abuse. They also introduce " +
			"tiered access (\"Consumption Tier\"): consumption \"at reasonable levels (as determined by Sonatype at its discretion)\" stays " +
			"free. Follow the artifacts you depend on, not Central.",
		Size: Size{
			Figure: "not published",
			Basis: "Sonatype publishes component counts, not storage. An undated third-party copy measured about 10 TB around 2019 " +
				"(unverified); a full copy is excluded by the terms anyway.",
		},
		Private: "Nexus and Artifactory can publish a Maven Indexer index of what they host, and are what Sonatype recommends in front of " +
			"Central (downloading Central's index once for everyone behind them). JFrog notes that Central's 429s surface as 404s through an " +
			"Artifactory remote. " + privateAQLNexus,
		Notes: []string{
			"search.maven.org's Solr API ignores a caller's `sort` (it reports `score desc,timestamp desc,g asc,a asc`), so it cannot be paged by time.",
		},
		Sources: []Source{
			{"Apache Maven: the Central index", "https://maven.apache.org/repository/central-index.html"},
			{"Maven Central: 429 errors on index files", "https://central.sonatype.org/faq/429-maven-index/"},
			{"Central Repository Terms of Service", "https://central.sonatype.org/terms.html"},
			{"Maven Central: 429 errors (rate limiting)", "https://central.sonatype.org/faq/429-error/"},
			{"JFrog: 429 rate limits from Maven Central surface as 404s", "https://jfrog.com/help/r/artifactory-429-rate-limits-from-maven-central-public-upstreams-surface-as-404s"},
		},
		Status: ImplStatus{StatePartial, "Task 191: follows a repository manager's Maven Indexer index (`<url>/.index/`): the properties file read conditionally, the chunks after the stored one applied to the stored copy while its chain lasts (a chunk gone or malformed, a full index older than the properties, or another `classifiers` selection makes it a full read), otherwise the full index streamed and diffed; releases from the stored copy, each document standing for its file and its release's POM (a POM alone for the main artifact its packaging names), classifiers per feed option `classifiers`, snapshots skipped. Maven Central itself is refused, by its host names (Google's copies too) and at every read by its index id `central` or its chain id: its terms forbid mirroring it. Feed option `url` names another index directory."},
	},
	{
		Type:     "openvsx",
		Title:    "Open VSX",
		Registry: "https://open-vsx.org",
		Tier:     TierIndex,
		Feeds: []FeedSpec{
			{
				Name:   "sitemap",
				URL:    "https://open-vsx.org/sitemap.xml",
				Cursor: CursorValidator,
				Semantics: "Every extension (`/extension/{namespace}/{name}`) with a `lastmod` date. openvsx-server's own mirror mode reads it, " +
					"asks `/api/{namespace}/{name}` for each extension and downloads the versions it lacks, deleting extensions gone upstream. " +
					"`lastmod` is a date, so re-check the extensions modified on the current day at every poll.",
				Verified: "2026-11-15: 21,414 `<url>` entries (2.6 MB, `cache-control: public, max-age=600`) — the same count as the search API's `totalSize`.",
			},
			{
				Name:      "search by timestamp",
				URL:       "https://open-vsx.org/api/-/search?sortBy=timestamp&sortOrder=desc&size=100&offset={offset}",
				Cursor:    CursorPage,
				Semantics: "Extensions by their latest version's timestamp, newest first, offset-paged.",
				Verified:  "2026-11-15: `size=2` → `totalSize` 21,414, newest published 22:42Z; `x-ratelimit-limit: 10800`.",
			},
		},
		RateLimits: "The Eclipse Foundation introduced rate limiting for open-vsx.org in 2025–2026 (tiers, observation first; no numbers " +
			"published); responses carry `x-ratelimit-limit: 10800`. Sustained or commercial-scale users are asked to get in touch.",
		Terms: "No mirroring clause beyond the Eclipse Foundation's terms of use; the server's mirror mode exists for self-hosted instances.",
		Size: Size{
			Figure: "21,414 extensions; bytes not published",
			Basis:  "Sitemap count on 2026-11-15. A full copy is every version (and target platform) of every extension's `.vsix` — not computed.",
		},
		Private: "A self-hosted openvsx-server serves the same API and sitemap and can itself mirror open-vsx.org (`ovsx.data.mirror.enabled`). " +
			"Artifactory documents a remote-only \"AI Editor Extensions\" repository type (whether it fronts Open VSX was not verified); Nexus documents no such format.",
		Notes: []string{
			"open-vsx.org sends no validators for its sitemap (checked 2026-11-16), so every poll reads it whole, plus one to three pages of the search listing by time.",
		},
		Sources: []Source{
			{"openvsx-server mirror mode (source)", "https://github.com/eclipse-openvsx/openvsx/tree/master/server/src/main/java/org/eclipse/openvsx/mirror"},
			{"Eclipse Foundation: Open VSX rate limiting (2026-02-11)", "https://blogs.eclipse.org/node/8762"},
		},
		Status: ImplStatus{StateImplemented, "Task 191: polls the sitemap (conditionally, where the server sends validators) and diffs it, one change per extension whose date moved; the search listing by time, read at every poll, adds second publications on a day (a server re-dating every extension, as one in mirror mode does, is recognised). Versions from each target platform's version listing, up to 2,000 a platform, past pre-release lines; one `.vsix` per version and platform (feed option `platforms` keeps some). Feed option `url` names another sitemap."},
	},

	// --- (c) paginated listings only ---------------------------------------------------
	{
		Type:     "dart",
		Aliases:  []string{"pub"},
		Title:    "pub.dev (Dart and Flutter)",
		Registry: "https://pub.dev",
		Tier:     TierListing,
		Feeds: []FeedSpec{
			{
				Name:   "packages by publish time",
				URL:    "https://pub.dev/api/packages?page={page}",
				Cursor: CursorPage,
				Semantics: "100 packages per page with their latest version and pubspec, most recently published first (an undocumented " +
					"endpoint that may change without notice); page until a package whose latest version is already known. " +
					"`/api/packages/{name}` lists every version with its `archive_url` and `archive_sha256`.",
				Verified: "2026-11-15: page 1 → 100 packages, the first three published at 22:29Z, 22:29Z and 22:24Z (checked through " +
					"`/api/packages/{name}`), `next_url` page 2.",
			},
			{
				Name:    "newest versions (Atom feed)",
				URL:     "https://pub.dev/feed.atom",
				Cursor:  CursorTimestamp,
				Partial: true,
				Semantics: "The 100 most recently published versions, newest first (retracted and moderated versions left out), each entry " +
					"`v{version} of {package}` with its publication time in `<updated>` and a changelog excerpt escaped for markup only " +
					"(control characters can occur). Built from a datastore query and cached for three minutes, it covers two to four hours " +
					"of publishing: a follower reads it at every poll and falls back to the listing after a longer pause.",
				Verified: "2026-11-16: 100 entries from 05:07:32Z to 07:23:56Z (2h16m, 87 packages), 80,092 bytes, `cache-control: no-store`.",
			},
			{
				Name:    "package names",
				URL:     "https://pub.dev/api/package-names",
				Cursor:  CursorValidator,
				Partial: true,
				Semantics: "Every package name (to be cached \"for at least 2 hours\"; the order may change, so diff as a set): finds new " +
					"packages, not new versions. Answers only clients that accept gzip (406 otherwise).",
				Verified: "2026-11-15: 95,662 names, 461,872 bytes gzipped.",
			},
		},
		RateLimits: "None published.",
		Terms:      "No crawling policy found; the documented API is the name list and per-package metadata, and undocumented endpoints may change or disappear without notice.",
		Size: Size{
			Figure: "95,662 packages; bytes not published",
			Basis:  "Name count on 2026-11-15; the sum of the archives is not computed.",
		},
		Private: "The hosted-repository specification v2 has no listing endpoint, so spec-only servers (unpub, OnePub) are tier (d) unless they " +
			"add one. Artifactory (Pub) and Nexus (Pub/Flutter proxy/hosted/group) support the format; a listing is not documented.",
		Notes: []string{
			"pub.dev serves its package listings (`/api/packages`, `/packages.json`) from an in-memory list on each server instance, refreshed every 15 minutes, so consecutive pages can come from instances that disagree: five requests for page 1 within ten seconds came back in three different states on 2026-11-16. A pass over the listing can skip a package at a page boundary unless the boundary is checked again later.",
		},
		Sources: []Source{
			{"pub.dev API", "https://pub.dev/help/api"},
			{"Hosted pub repository specification v2", "https://github.com/dart-lang/pub/blob/master/doc/repository-spec-v2.md"},
		},
		Status: ImplStatus{StateImplemented, "Task 191: follows the Atom feed of the 100 newest versions down to a high-water mark, and the live `/packages.json` listing where the feed does not reach back (the document of a page's last package tells where to stop; a page boundary pub.dev's instances may disagree on is kept in the cursor and looked at again 35 minutes later), by package name, versions younger than feed option `settle` held back (default 5m; 2h30m when the upstream is a server in front of pub.dev); Bootstrap lists `/api/package-names` and the feed's packages. Versions from the package document read through the proxy, retracted ones as yanked. Another pub server needs feed option `url`, a site that serves pub.dev's feed and listings."},
	},
	{
		Type:     "jsr",
		Title:    "JSR (JavaScript Registry)",
		Registry: "https://jsr.io",
		Tier:     TierListing,
		Feeds: []FeedSpec{
			{
				Name:   "package list",
				URL:    "https://api.jsr.io/packages?limit=100&page={page}",
				Cursor: CursorPage,
				Semantics: "Every package with `updatedAt` and `latestVersion`, 1–100 per page (`total` in the response). There is no sort " +
					"parameter and the order is alphabetical, so each pass reads every page and compares `updatedAt`. Versions come from " +
					"`https://jsr.io/@{scope}/{name}/meta.json` (with `createdAt`), files from `{version}_meta.json`, cacheable forever.",
				Verified: "2026-11-15: `limit=2` → `total` 23,228; `sortBy`/`sort` parameters ignored (alphabetical order).",
			},
			{
				Name:      "recent activity",
				URL:       "https://api.jsr.io/stats",
				Cursor:    CursorTimestamp,
				Partial:   true,
				Semantics: "The 10 newest packages and 10 most recently uploaded versions, cached four hours: a hint, too short and too stale to follow.",
				Verified:  "2026-11-15: `newest`, `updated`, `featured` with 10 entries each, `cache-control: public, max-age=14400`.",
			},
		},
		RateLimits: "None stated: \"If a tool is misbehaving, we may block it from using the management API.\"",
		Terms:      "JSR asks tools to read versions from `meta.json`, not from the management API.",
		Size: Size{
			Figure: "23,228 packages; bytes not published",
			Basis:  "Package total on 2026-11-15. JSR serves source files, so packages are small.",
		},
		Private: "There is no self-hosted JSR server in common use.",
		Notes: []string{
			"Measured on 2026-11-16: a full pass over the package list is 214 requests and about 11 MB, so polling every 5 minutes costs about 61,600 requests and 3.2 GB a day; an hourly poll about 5,100 requests and 260 MB.",
		},
		Sources: []Source{
			{"JSR API", "https://jsr.io/docs/api"},
			{"JSR management API (OpenAPI)", "https://api.jsr.io/.well-known/openapi"},
		},
		Status: ImplStatus{StateImplemented, "Task 191: reads every page of the management API's package list at each poll, to its first empty page, into a copy diffed against the last (a publish moves the version count, not `updatedAt`), changes by package; versions from `meta.json` and their module files from each version's manifest, read through the proxy (every package's file lists kept: a publish reads the new version's manifest only). Another upstream needs feed option `url`, an API that lists packages as api.jsr.io does."},
	},
	{
		Type:     "huggingface",
		Title:    "Hugging Face Hub",
		Registry: "https://huggingface.co",
		Tier:     TierListing,
		Feeds: []FeedSpec{
			{
				Name:   "repositories by last modification",
				URL:    "https://huggingface.co/api/models?sort=lastModified&direction=-1&limit=100",
				Cursor: CursorPage,
				Semantics: "Models (and `/api/datasets`, `/api/spaces`), most recently changed first; the next page is in the `Link` header as an " +
					"opaque keyset cursor on (`lastModified`, `_id`) that stays stable while new commits arrive. A commit to any repository bumps " +
					"its `lastModified`, so page back to the newest change of the previous pass, then read each repository's files at its revision " +
					"and download them. The maximum page size is not documented.",
				Verified: "2026-11-15: `limit=2` → newest `lastModified` 22:46:22Z, `Link: <…&cursor=eyIkb3IiOlt7Imxhc3RNb2RpZmllZCI6…>; rel=\"next\"`, " +
					"`ratelimit-policy: \"fixed window\";\"api\";q=500;w=300`.",
			},
		},
		RateLimits: "Five-minute fixed windows. Anonymous: 500 API calls, 3,000 file resolutions and 100 pages per IP; free accounts 1,000 / 5,000 / " +
			"200; paid plans more (figures of September 2025, subject to change). 429 when exceeded.",
		Terms: "\"Upgrade your account if you need elevated, large-scale access.\" Many repositories are gated (licence acceptance) or private. " +
			"The terms of service were not reviewed for a crawling clause.",
		Size: Size{
			Figure: "more than 20 PB",
			Basis:  "A lower bound: Hugging Face moved 500,000 repositories holding 20 PB to its Xet storage in 2025.",
		},
		Private: "Artifactory (Hugging Face and Machine Learning repositories) and Nexus (Hugging Face proxy) cache models and datasets for " +
			"clients; neither documents its upstream's `/api/models` listing. Hugging Face webhooks cover only the repositories or users one watches.",
		Notes: []string{
			"At the anonymous limit of 500 API calls per 5 minutes a follower must stay below 1.7 requests a second (about 3 with a free account's token); its listing, metadata and file requests all count, and so do other clients behind the same egress address.",
		},
		Sources: []Source{
			{"Hugging Face Hub API", "https://huggingface.co/docs/hub/api"},
			{"Hugging Face Hub rate limits", "https://huggingface.co/docs/hub/rate-limits"},
			{"Migrating the Hub to Xet (2025-07-15)", "https://huggingface.co/blog/migrating-the-hub-to-xet"},
		},
		Status: ImplStatus{StatePartial, "Task 191: follows the listing by last modification (`/api/models`, or datasets or spaces per feed option `kind`) for the scope feed options `author` (comma-separated, at most 32, one listing each, read in turn down to the mark's lookback window) and/or `search` name — the whole Hub is not enumerated; hf.co's listing is read at huggingface.co. The files of the commit main is at, from the metadata read through the proxy (feed option `files` keeps some; gated and private repositories are skipped unless feed option `restricted` is `include`). Feed option `url` names the listing API for an upstream that is not the Hub."},
	},
	{
		Type:     "puppet",
		Title:    "Puppet Forge",
		Registry: "https://forgeapi.puppet.com",
		Tier:     TierListing,
		Feeds: []FeedSpec{
			{
				Name:   "releases by date",
				URL:    "https://forgeapi.puppet.com/v3/releases?sort_by=release_date&limit=100&offset={offset}&with_html=false&exclude_fields=readme+changelog+license+reference",
				Cursor: CursorPage,
				Semantics: "Every module release, newest first, offset-paged (`pagination.total`, `next`); page from offset 0 until a release " +
					"already seen, overlapping pages because offsets shift as releases arrive. Each release names its `file_uri`, `file_size` and " +
					"`file_sha256`; excluding the README, changelog and licence keeps a page small.",
				Verified: "2026-11-15: `total` 54,827, newest jdowning-rbenv-4.0.0 (13:58 -0800); `limit=100` → 100 releases; modules by `latest_release` → 7,707.",
			},
		},
		RateLimits: "None documented; no rate-limit headers.",
		Terms:      "No download restrictions found; Perforce's 2025 changes concern Puppet Core and the PDK, not downloading modules from the Forge.",
		Size: Size{
			Figure: "7,707 modules, 54,827 releases; about 3 GB (estimate)",
			Basis:  "Live counts on 2026-11-15; the 100 newest releases average 58 KB (median 34 KB), times 54,827.",
		},
		Private: "Artifactory has Puppet local/remote/virtual repositories; Nexus has no Puppet format; there is no official self-hosted Forge.",
		Sources: []Source{
			{"Puppet Forge API v3", "https://forgeapi.puppet.com/"},
			{"Puppet module developer EULA FAQ (2025)", "https://puppet.com/blog/puppet-module-developer-eula-faq"},
		},
		Status: ImplStatus{StateImplemented, "Task 191: follows `/v3/releases?sort_by=release_date` down to a high-water mark and a day below it, by module name, releases younger than feed option `settle` held back (default 90m: the CDN serves module documents up to an hour old; 3h30m when the upstream is a server in front of the Forge), after enumerating the modules from the same listing sorted by module; versions from the module document read through the proxy, deleted releases as yanked, premium and login-required modules only with credentials. Feed option `url` names the Forge for an Artifactory remote."},
	},
	{
		Type:     "ansible",
		Title:    "Ansible Galaxy",
		Registry: "https://galaxy.ansible.com",
		Tier:     TierListing,
		Feeds: []FeedSpec{
			{
				Name:   "collection versions, newest first",
				URL:    "https://galaxy.ansible.com/api/v3/plugin/ansible/search/collection-versions/?order_by=-pulp_created&limit=100&offset={offset}",
				Cursor: CursorPage,
				Semantics: "Galaxy NG's search lists every collection version newest first by `pulp_created`, with `meta.count` and `links.next`; " +
					"page from offset 0 until a version already seen, overlapping pages because offsets shift. `is_highest=true` gives one row per " +
					"collection. Each version's metadata and artifact then come through the v3 API.",
				Verified: "2026-11-15: `limit=2` → `meta.count` 54,484, newest created 21:46Z; the collections index refused `ordering=-updated_at` (400, not an available choice).",
			},
		},
		RateLimits: "None documented; Galaxy sits behind Cloudflare and sent no rate-limit headers.",
		Terms: "No mirroring clause found. Red Hat requires a requirements file when Automation Hub syncs from galaxy.ansible.com, \"to prevent " +
			"customers from syncing everything in galaxy\" — a sign that full syncs are unwelcome.",
		Size: Size{
			Figure: "4,686 collections, 54,484 collection versions; 37,920 roles",
			Basis:  "Live counts on 2026-11-15. Roles are GitHub repositories, not files on Galaxy; collection bytes are not published.",
		},
		Private: "Private Automation Hub, galaxy_ng and pulp_ansible serve the same v3 API, and sync from Galaxy with a requirements file or " +
			"(pulp_ansible 0.30 and later) `sync_highest_versions`. Artifactory has Ansible local/remote/virtual repositories and Nexus an " +
			"Ansible Galaxy format; whether they answer the search endpoint is not documented.",
		Sources: []Source{
			{"pulp_ansible: collections", "https://pulpproject.org/pulp_ansible/docs/user/guides/collections/"},
			{"Automation Hub: requirements file for galaxy.ansible.com remotes (AAH-2280)", "https://issues.redhat.com/browse/AAH-2280"},
		},
		Status: ImplStatus{StateImplemented, "Task 191: follows the collection-version search (`order_by=-pulp_created`, `distribution_base_path` = the upstream's `repository`) down to a high-water mark and a day below it, versions younger than feed option `settle` held back (default 10m), after enumerating the repository's collection index; a search that lists nothing while the index lists collections fails. Versions from the versions list read from the registry (the pipeline takes no query). Roles are not followed. Feed option `url` names a Galaxy NG for an Artifactory or Nexus remote."},
	},
	{
		Type:     "terraform",
		Title:    "Terraform Registry (and the OpenTofu registry)",
		Registry: "https://registry.terraform.io",
		Tier:     TierListing,
		Feeds: []FeedSpec{
			{
				Name:   "module listing",
				URL:    "https://registry.terraform.io/v1/modules?limit=100&offset={offset}",
				Cursor: CursorPage,
				Semantics: "The documented List Modules API: every module with its latest `version` and `published_at`, offset-paged " +
					"(`meta.next_offset`), in the order the modules were created, oldest first. New modules arrive at the end, so page on from " +
					"the stored offset; a new version of an existing module does not move it, so catching those takes a pass over the whole " +
					"listing (about 250 requests at 100 per page), then `/v1/modules/{namespace}/{name}/{provider}/versions`.",
				Verified: "2026-11-15: `limit=2` → `next_offset` 2, starting with long-established modules (GoogleCloudPlatform/lb-http, " +
					"managed-instance-group); offsets 24767–24769 → the last three, published 2026-11-14 and 15 with 3 to 13 downloads, and no " +
					"`next_offset`: 24,770 modules (the website's `/v2/modules` reports 25,033).",
			},
			{
				Name:   "provider listing",
				URL:    "https://registry.terraform.io/v2/providers?page%5Bsize%5D=100&page%5Bnumber%5D={page}",
				Cursor: CursorPage,
				Semantics: "The website's undocumented JSON:API listing of every provider, alphabetical (`sort=-published-at` is refused). " +
					"Versions per provider at `/v1/providers/{namespace}/{type}/versions`; the binaries are GitHub release assets named in each " +
					"version's download document.",
				Verified: "2026-11-15: `page[size]=2` → `total-count` 7,761; `sort=-published-at` → 400 \"Invalid sort option\"; `/v1/providers?limit=2` also lists providers with their latest version.",
			},
			{
				Name:    "OpenTofu registry commits",
				URL:     "https://github.com/opentofu/registry",
				Cursor:  CursorCommit,
				Partial: true,
				Semantics: "A different registry: registry.opentofu.org is generated from this Git repository (providers and modules as JSON " +
					"files, new versions found from their GitHub releases and tags), so for an upstream pointed there its commits are a " +
					"tier-(a) feed. The binaries stay on GitHub.",
				Verified: "2026-11-15: `git ls-remote` → HEAD f871e932…; registry.opentofu.org `/v1/providers/hashicorp/random/versions` → 200 (a static file).",
			},
		},
		RateLimits: "\"Clients placing excessive load on the service might be rate-limited and receive a 429\"; no numbers.",
		Terms: "The registry's terms could not be read (a JavaScript-only page); secondary sources quote a restriction of downloads to use " +
			"\"with, or in support of, HashiCorp Terraform\" (unverified). Endpoints not in the API documentation are \"subject to change\".",
		Size: Size{
			Figure: "7,761 providers, 24,770 modules; provider binaries are on GitHub",
			Basis:  "Live counts on 2026-11-15; bytes = providers × versions × platforms × archive size (not computed). Modules are source archives from their VCS.",
		},
		Private: "The provider and module registry protocols define no listing, so a private registry is enumerable only through its own " +
			"management API, if it has one.",
		Notes: []string{
			"Tier (c), not (d): both listings enumerate everything. New modules show up at the end of the module listing; new versions of existing modules and providers only through a full pass over both listings (about 330 requests at 100 per page) and their version lists.",
			"An upstream at registry.opentofu.org can instead be followed through the OpenTofu repository's history (tier a).",
		},
		Sources: []Source{
			{"Terraform registry API", "https://developer.hashicorp.com/terraform/registry/api-docs"},
			{"Building the OpenTofu registry (2024-09-12)", "https://opentofu.org/blog/building-the-opentofu-registry/"},
			{"opentofu/registry", "https://github.com/opentofu/registry"},
		},
		Status: ImplStatus{StateNotApplicable, "no feed adapter (Task 191): the listings name only each module's and provider's latest version, so a new version surfaces only in a full pass over both listings (about 330 requests) and a version list per changed entry, and provider binaries are GitHub release assets outside the registry; full mirroring is refused, and tracked repositories pin the providers their lock files name"},
	},

	// --- (d) no practical enumeration ---------------------------------------------------
	{
		Type:     "docker",
		Title:    "Docker Hub",
		Registry: "https://registry-1.docker.io",
		Tier:     TierNone,
		Feeds: []FeedSpec{
			{
				Name:    "tags of a named repository",
				URL:     "https://registry-1.docker.io/v2/{namespace}/{repository}/tags/list?n=1000",
				Cursor:  CursorValidator,
				Partial: true,
				Semantics: "Every tag of one repository, paged by `n` and `last` (`Link: …; rel=\"next\"`); compare with the previous list and " +
					"resolve the changed tags' manifests (HEAD requests do not count as pulls). Covers only the repositories one names.",
				Verified: "2026-11-15: `library/alpine/tags/list?n=3` with an anonymous pull token → 200 and a `Link` to the next page.",
			},
			{
				Name:      "Hub search",
				URL:       "https://hub.docker.com/v2/search/repositories/?query={query}&page_size=100",
				Cursor:    CursorPage,
				Partial:   true,
				Semantics: "Search, not enumeration: repositories matching a query, with pull counts.",
				Verified:  "2026-11-15: `query=alpine` → `count` 104,570, `x-ratelimit-limit: 180`.",
			},
		},
		RateLimits: "Pulls: Docker's usage page lists 100 per 6 hours per IPv4 address or IPv6 /64 without an account, 200 for personal accounts " +
			"and unlimited for paid plans; the registry's own `ratelimit-limit` header on 2026-11-15 read `100;w=3600` (a one-hour window) for " +
			"anonymous requests over IPv6 and IPv4. Plan on the documented figure; separate abuse limits answer 429.",
		Terms: "Docker's terms (effective 2026-08-26) forbid automated access \"except as permitted by Docker\", transferring \"excessive amounts " +
			"of data\", and using the service \"to mirror or replicate content for an unauthorized commercial service\".",
		Size: Size{
			Figure: "not published",
			Basis:  "Docker Hub publishes neither a catalog nor a storage figure.",
		},
		Private: "A self-hosted registry can be enumerated: `GET /v2/_catalog` (distribution, Harbor, Artifactory, Nexus; `n`/`last` paging in " +
			"lexical order) plus `tags/list` make it tier (b), and Harbor and Quay can send a webhook on every push. GHCR and Quay.io do not list public repositories.",
		Notes: []string{
			"An anonymous token for `registry:catalog:*` is refused (400) and `/v2/_catalog` answers 401.",
		},
		Sources: []Source{
			{"Docker Hub usage and limits", "https://docs.docker.com/docker-hub/usage/"},
			{"Docker terms of service", "https://www.docker.com/legal/docker-terms-service/"},
			{"OCI distribution specification", "https://github.com/opencontainers/distribution-spec/blob/main/spec.md"},
		},
		Status: ImplStatus{StateNotStarted, planPartial},
	},
	{
		Type:     "swift",
		Title:    "Swift package registries (Tuist's public registry)",
		Registry: "https://tuist.dev/api/registry/swift",
		Tier:     TierNone,
		Feeds: []FeedSpec{
			{
				Name:    "Swift Package Index package list",
				URL:     "https://github.com/SwiftPackageIndex/PackageList",
				Cursor:  CursorCommit,
				Partial: true,
				Semantics: "The Swift Package Index's list of package repositories (`packages.json` in a Git repository), which Tuist's registry " +
					"mirrors. Map each repository to its registry identifier (`GET /identifiers?url=`) and list its releases " +
					"(`GET /{scope}/{name}`): about 10,000 requests per pass.",
				Verified: "2026-11-15: `packages.json` → 669,137 bytes; Tuist `GET /apple/swift-argument-parser` → 200 with its releases; the registry root answers 200 with an empty body.",
			},
		},
		RateLimits: "Tuist: 10,000 requests a minute without login and 100,000 with `tuist registry login` (announcement of 2025-11-26; a docs " +
			"page says 1,000 and 20,000). The registry specification lets a server answer 429 with `Retry-After`.",
		Terms: "None found beyond Tuist's announcement that the registry is open without an account.",
		Size: Size{
			Figure: "about 10,000 packages and 160,000 releases",
			Basis:  "Tuist's announcement (2025-11-26); the source archives are built from the packages' Git tags.",
		},
		Private: "The registry specification has no listing endpoint, so Artifactory's and Nexus's Swift registries cannot be enumerated through the protocol either. " + privateAQLNexus,
		Notes: []string{
			"SE-0292 defines only per-package endpoints (`/{scope}/{name}`, `/{scope}/{name}/{version}`, `/identifiers`): a registry cannot be enumerated through the protocol.",
		},
		Sources: []Source{
			{"Swift package registry service specification", "https://github.com/swiftlang/swift-package-manager/blob/main/Documentation/PackageRegistry/Registry.md"},
			{"Tuist: opening the registry (2025-11-26)", "https://tuist.dev/blog/2025/11/26/opening-registry"},
			{"SwiftPackageIndex/PackageList", "https://github.com/SwiftPackageIndex/PackageList"},
		},
		Status: ImplStatus{StateNotStarted, planPartial},
	},
	{
		Type:     "nix",
		Title:    "Nix binary cache (cache.nixos.org)",
		Registry: "https://cache.nixos.org",
		Tier:     TierNone,
		Feeds: []FeedSpec{
			{
				Name:    "channel store paths",
				URL:     "https://channels.nixos.org/{channel}/store-paths.xz",
				Cursor:  CursorValidator,
				Partial: true,
				Semantics: "The output paths of one channel release (a redirect to releases.nixos.org): diff two releases and fetch " +
					"`/{hash}.narinfo` and the NARs for the new paths and their references. Covers one channel's outputs, not the cache.",
				Verified: "2026-11-15: nixos-unstable → nixos-26.11pre1119549, 6,003,848 bytes of xz, 227,961 paths.",
			},
		},
		RateLimits: "None published; the cache is an S3 bucket behind Fastly serving about 5,700 requests a second.",
		Terms:      "None found; \"new mirroring options\" are listed as future work.",
		Size: Size{
			Figure: "636 TB, more than 1 billion objects",
			Basis:  "NixOS Foundation, July 2026 figures in its binary-cache story of 2026-09-20.",
		},
		Private: "Attic, Cachix, Harmonia and nix-serve serve the same narinfo/NAR protocol, which has no listing; a cache backed by an S3 bucket one owns can be listed through S3.",
		Notes: []string{
			"`nix-cache-info` declares `WantMassQuery: 1`; the bucket refuses anonymous listing (403) and there is no index.",
		},
		Sources: []Source{
			{"NixOS: the Nix binary cache (2026-09-20)", "https://nixos.org/blog/stories/2026/nix-binary-cache/"},
			{"NixOS Discourse: garbage collecting cache.nixos.org", "https://discourse.nixos.org/t/garbage-collecting-cache-nixos-org/74249"},
		},
		Status: ImplStatus{StateNotStarted, planPartial},
	},
	{
		Type:       "generic",
		Title:      "Generic declarative upstreams",
		Tier:       TierNone,
		RateLimits: "Whatever the upstream sets.",
		Terms:      "Whatever the upstream's terms say.",
		Size: Size{
			Figure: "operator-defined",
			Basis:  "A generic upstream serves what its routes declare.",
		},
		Private: "Artifactory remote repositories can list the far side (\"List Remote Folder Items\", off by default since 7.93) and the " +
			"Storage API lists folders for privileged users; Nexus raw repositories list hosted and cached content through the components API, " +
			"not their upstream. A plain HTTP server with directory listings can be crawled and diffed (tier b).",
		Notes: []string{
			"Nothing in a generic upstream's configuration says how to enumerate it; following one would need its own declaration (a listing URL and how to read it).",
		},
		Sources: []Source{
			{"Generic backend (this repository)", "https://github.com/blechschmidt/pullthrough-security/blob/main/docs/generic-backend.md"},
			{"Artifactory: remote list browsing", "https://jfrog.com/help/r/jfrog-artifactory-documentation/remote-list-browsing"},
			{"Nexus: components API", "https://help.sonatype.com/en/components-api.html"},
		},
		Status: ImplStatus{StateNotApplicable, "operator-defined upstream"},
	},
	{
		Type:     "git",
		Title:    "Git hosting (GitHub and other forges)",
		Registry: "https://github.com",
		Tier:     TierNone,
		Feeds: []FeedSpec{
			{
				Name:    "refs of a named repository",
				URL:     "https://github.com/{owner}/{repository}",
				Cursor:  CursorCommit,
				Partial: true,
				Semantics: "`git ls-remote` lists every ref with its commit; compare with the stored refs and fetch what moved. Covers the " +
					"repositories one names — what the commit watcher (`scanning.watch`) already does.",
				Verified: "2026-11-15: `git ls-remote https://github.com/golang/go refs/tags/go1.23.0` → 6885bad7….",
			},
			{
				Name:    "GitHub public events",
				URL:     "https://api.github.com/events?per_page=100",
				Cursor:  CursorPage,
				Partial: true,
				Semantics: "The latest 300 public events across GitHub, delayed \"anywhere from 30s to 6h\", polled with ETag at the " +
					"`X-Poll-Interval`: a sample, not a feed.",
				Verified: "2026-11-15: `per_page=2` → last page 150 (300 events), `x-poll-interval: 60`, `x-ratelimit-limit: 60` without authentication.",
			},
		},
		RateLimits: "GitHub's REST API: 60 requests an hour per IP without authentication, 5,000 with. GitHub tightened its limits for " +
			"unauthenticated traffic in 2025 without publishing numbers; unauthenticated Git and raw downloads can be throttled.",
		Terms: "Governed by GitHub's terms and Acceptable Use Policies (not reviewed for this page).",
		Size: Size{
			Figure: "not applicable",
			Basis:  "There is no registry to copy; a mirror holds the repositories one names.",
		},
		Private: "Self-hosted forges can send instance-wide events: GitLab system hooks (administrators only; by default not for a push of more " +
			"than three branches or tags) and Gitea system webhooks (\"all eligible activity on the instance\"); Bitbucket Data Center has no " +
			"built-in instance-wide webhook. On such an instance the git type is effectively tier (a).",
		Sources: []Source{
			{"GitHub REST API: events", "https://docs.github.com/en/rest/activity/events"},
			{"GitHub REST API: rate limits", "https://docs.github.com/en/rest/using-the-rest-api/rate-limits-for-the-rest-api"},
			{"GitHub changelog: updated rate limits for unauthenticated requests (2025-05-08)", "https://github.blog/changelog/2025-05-08-updated-rate-limits-for-unauthenticated-requests/"},
			{"GitLab system hooks", "https://docs.gitlab.com/administration/system_hooks/"},
			{"Gitea webhooks", "https://docs.gitea.com/usage/webhooks"},
		},
		Status: ImplStatus{StatePartial, "named repositories are followed for the commit scan: `scanning.watch`"},
	},
}
