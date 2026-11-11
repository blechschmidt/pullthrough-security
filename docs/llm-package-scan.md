# LLM package-content scan

The LLM package-content scan is an admission gate that has a language model read
the contents of a downloaded package and say whether it is **malicious**,
**suspicious** or **benign** — before a single byte of the package is served.

It complements the other content gates rather than replacing them:

| Gate | Looks at | How |
|------|----------|-----|
| [commit scanning](commit-watch.md) | the source commit a package is *believed* to come from | LLM |
| `installhooks`, `contentscan` | the artifact | deterministic patterns |
| `avscan` | the artifact | antivirus signatures |
| **`llmpkgscan`** (this page) | the artifact — the bytes that will actually run on the developer's machine | LLM, reading the unpacked files |

The artifact is the only thing that executes at install time, and it need not
match any commit. A package whose repository is clean and whose published
tarball carries an extra `postinstall` script is exactly what this gate is for.

- Package: `internal/llmpkgscan` · gate name `llmpkgscan` · config section `llmPackageScan`
- Off by default: it needs an LLM provider and costs money per distinct artifact.
- Reuses the commit scanner's provider abstraction (Claude, OpenAI / Codex-compatible).
  No second LLM client exists in the code base.

## Quick start

```yaml
llmPackageScan:
  enabled: true
  provider: claude                 # or openai | codex; empty inherits scanning.provider
  apiKey: env://ANTHROPIC_API_KEY  # secretRef, ${ENV}, enc:v1: — like every credential
  action: block                    # annotate | block | quarantine
  failMode: open                   # open | closed
  storeDir: /var/lib/pullthrough/llm-verdicts
  budget:
    enabled: true
    globalCeilingUsd: 200          # per 24h window
    tenantCeilingUsd: 25
  excludeUpstreams: [corp-npm]     # private registries whose code must not leave the network
```

If commit scanning is already configured, `llmPackageScan: {enabled: true}` is
enough: the provider, key, endpoint and deep model are inherited from
`scanning.*`. Run `pullthrough verify-config -config <file>` (or
`ptctl doctor --config <file>`) and read the warnings — they cover a missing
budget, the in-memory verdict store, the `timeout` / `server.writeTimeout`
relation, an enforcing action that fails open, and authenticated upstreams whose
packages would be sent to the provider.

Every key is documented in the generated
[configuration reference](configuration-reference.md#llmpackagescan).

## What happens on a pull

The gate runs in `serveCacheable`, after the artifact is in the cache and after
the deterministic content gates (`contentscan`, `mlguard`, `avscan`), and before
the aggregating `policyengine` / `riskscore` gates, which consume its signal. It
is deliberately the last content gate: the cheap gates go first, and anything
they refuse never costs a model call.

1. **Scope.** The upstream must not be in `excludeUpstreams`, the ecosystem must
   be in scope (`include` / `exclude`; default `npm, pip, cargo, rubygems,
   composer, nuget`), and the resource must carry a versioned coordinate.
2. **Verdict lookup.** The verdict cache is consulted under the key
   `sha256(artifact) + model + prompt version`. A hit — including every pull of an
   artifact already in the content cache — costs no model call.
3. **Scan** (cache miss). The artifact is unpacked and shown to the model; see
   below. Concurrent pulls of the same digest share one scan.
4. **Decision.** The verdict, the configured thresholds and action, and two
   deterministic cross-checks decide whether the response is the artifact or a
   `403`.

The response is held until step 4. Nothing is streamed while the scan runs.

### What counts as a package

Some versioned resources are not packages: a wheel's `METADATA` sidecar, a
`.nuspec`, a gemspec. The gate decides by content, not by a list of names:

- A resource with **no archive or compression signature** that is **not named
  like an installable archive** is left alone. No package manager installs code
  from it. It is served without `X-LLMPkgScan-*` headers and counted in
  `pullthrough_llmpkgscan_not_package_total`.
- A resource that **starts like an archive the scanner cannot unpack** (zstd, xz,
  7z, rar, a corrupt gzip, …), or that **is named like a package** (`.tgz`,
  `.whl`, `.gem`, `.crate`, `.nupkg`, …) but is not an archive, is a package that
  went unexamined: `unsupported-format`, handled by `failMode`, and reported as a
  finding. It is never passed in silence.

The decision is made per request, not per digest: the same bytes requested under
a metadata name and under a package name each get the answer their own name
calls for.

## The sandbox

The model **never executes package code** and has **no network, filesystem or
host access**. That is a property of the construction, not of a policy the model
is asked to follow:

- The artifact is unpacked by the `contentscan` archive walker into a **bounded,
  read-only tree held in memory**. Nothing is written to disk, so there is no
  path to traverse out of. Member names are sanitized into root-relative keys
  (no `..`, no absolute paths, no drive prefixes); a name that tried to escape is
  recorded as an anomaly instead.
- The model is given at most **three tools**, implemented in-process over that
  tree:

  | Tool | Arguments | Returns |
  |------|-----------|---------|
  | `list_files` | `prefix`, `offset` | paths, sizes, text/binary, role labels |
  | `read_file` | `path`, `start_line`, `max_lines` | numbered lines of one text file |
  | `grep` | `pattern` (RE2), `path_prefix`, `ignore_case` | `path:line: text` matches |

  No provider-hosted tool (code execution, web search, …) is ever declared. A
  tool name outside this set, or a path that is not a key of the tree, yields an
  error result and nothing else. `grep` uses Go's RE2 engine (linear time, no
  backtracking), with a cap on compiled pattern size and on search time.
- The tool arguments are model output and validated as such; the results are
  package content and framed as such (see the next section).

### Tools or bundle

| Mode | When | What the model gets |
|------|------|---------------------|
| **tools** | the provider supports tool use and the package does not fit the first prompt | a seed prompt (listing + the highest-priority files) plus the three tools |
| **bundle** | the provider has no tool use, `mode: bundle`, or the whole package fits the first prompt | one prompt, one answer |

`mode: auto` (the default) uses tools when it can. For an OpenAI-compatible
gateway, "can" is only discoverable by asking: if the endpoint rejects the first
tool-bearing request as a request it does not accept (HTTP 400/404/405/415/422/501)
and a single-shot scan then succeeds, the gate uses bundle mode for the next
hour and logs a warning. `mode: tools` disables that fallback; `mode: bundle`
skips the attempt.

Most small packages are settled by a **single plain completion**: when the seed
already shows every readable file in full, there is nothing for a tool to fetch.

### What the model sees first

A package can hold thousands of files and the prompt cannot. The seed is ordered
by what runs automatically, because that is where a malicious package has to put
something:

1. install scripts and lifecycle hooks (`package.json` scripts and the files they
   invoke, `setup.py`, `.pth`, `build.rs`, `extconf.rb`, NuGet `install.ps1`, …)
2. manifests (`pyproject.toml`, `Cargo.toml`, `composer.json`, `.npmrc`, …)
3. entry points (`main`, `bin`, `__init__.py`, …)
4. build files and scripts
5. ordinary source, then configuration, documentation and vendored trees

Files carrying risk signals (process execution, decoding, network access,
credential paths, obfuscation) are promoted within their band. Ranking only
orders the material — it is never a verdict, and in tool mode it hides nothing.

**Truncation is stated, never silent.** Every limit that cut something — files
beyond `maxFiles`, bytes beyond `maxUnpackedBytes`, a file longer than
`maxFileBytes`, members nested deeper than `maxDepth`, files that did not fit a
bundle — is written into the prompt in plain words ("NOT unpacked", "NOT SHOWN")
so the model can lower its confidence, and is stored with the verdict as
`coverage` and `truncated: true` so a reader knows what the verdict rests on.

## Limits

Every quantity below is controlled by whoever published the package, so each is
capped (`llmPackageScan.limits.*`, `timeout`, `maxConcurrent`):

| Limit | Default | Guards against |
|-------|---------|----------------|
| `maxArtifactBytes` | 64 MiB | scanning a prefix of something larger (an oversized artifact is not scanned at all) |
| `maxUnpackedBytes` | 256 MiB | decompression bombs (bytes) |
| `maxCompressionRatio` | 200 | decompression bombs (ratio) — also recorded as a structural anomaly |
| `maxFiles` | 5000 | archive-member bombs; a zip whose directory declares far more is not unpacked |
| `maxFileBytes` | 1 MiB | one huge file (retained text is additionally capped at 32 MiB per scan) |
| `maxDepth` | 32 | pathological nesting |
| `maxPromptBytes` | 120 KiB | prompt size |
| `maxTurns` / `maxToolCalls` | 8 / 24 | an endless investigation |
| `maxToolResultBytes` / `maxToolBytes` | 24 KiB / 256 KiB | tool output volume |
| `maxOutputTokens` / `maxTotalTokens` | 16 000 / 600 000 | token spend per scan |
| `timeout` | 2 min | wall-clock time, queueing included |
| `maxConcurrent` | 4 | memory and provider rate (each scan holds one unpacked package) |

When a budget inside the loop is spent, the next request forbids further tool
calls, which forces an answer. Scans beyond `maxConcurrent` wait in a bounded
queue (8 per slot); beyond that a pull is answered immediately as
`scanner-busy` instead of joining a line it could only time out in. One tenant
may hold at most half of the capacity (slots plus queue) at a time, so a client
requesting many distinct artifacts cannot starve every other tenant of scans.

Keep `timeout` below `server.writeTimeout` and in line with your package
managers' patience. A client that gives up does not waste the scan: it runs on
its own context, finishes, and stores its verdict for the retry.

## Prompt-injection defenses

Package contents are written by whoever published the package. They are treated
as hostile data at every step.

**In the prompt**

- The system prompt is frozen (no per-request interpolation) and states that
  package material is data to analyze, that nothing inside it can change the
  task, the verdict scale or the output format, and that text addressing "the
  AI", "the scanner" or "the reviewer" is itself evidence.
- Package material — file names, file contents, metadata, every tool result —
  appears only between two marker lines carrying a **96-bit random nonce chosen
  per scan**, after the package was published. Content cannot contain a valid
  marker, so it can neither close the data block early nor open a fake one. A
  copy of the marker word, the nonce or the canary inside content is defused
  before it is shown.
- Everything the publisher controls goes inside the markers, including the
  package name and file names. The trusted preamble carries only facts the proxy
  measured.
- File contents are shown with a line-number gutter, and characters that would
  render invisibly (zero-width, bidirectional controls) are spelled out as
  `<U+XXXX>`, so the text the model reads is the text that is there.
- Tool errors are the proxy speaking and sit outside the markers; they never
  echo a string the package or the model supplied.

**In the answer**

- The answer must be **exactly one JSON object** of a fixed shape:

  ```json
  {"verdict": "malicious|suspicious|benign", "confidence": 0.0,
   "reasons": ["…"], "evidence": [{"path": "…", "line": 0, "excerpt": "…"}]}
  ```

  Prose around it, a second object, duplicate or unknown keys, a missing verdict
  or confidence, a truncated reply, a request for a tool after the allowance was
  spent — each is a **scan error**. A scan error is never read as benign; only
  `failMode` decides what happens next.
- A canary string is planted in the system prompt. If it appears in the answer
  the model was talked into disclosing its instructions, and the answer is
  discarded (`injection-suspected`).
- Each cited location is **verified**: the proxy looks for the quoted excerpt at
  that place in the unpacked file. An unverified citation is kept but marked, and
  only verified locations are echoed to a client.

**After the answer** — two deterministic checks the content cannot argue with,
because they run in the proxy once the model has finished:

- An **injection ruleset** scans the package text for instructions to ignore
  earlier instructions, text addressed to an AI or scanner, verdict coercion,
  embedded verdict JSON, "already approved" claims, "do not flag" requests and
  forged data boundaries. A package with such text **cannot be benign**: a clean
  verdict is floored to *suspicious*.
- A **structural check** floors a benign verdict to *suspicious* when the archive
  is built to attack an extractor: a member name or link that escapes the package
  root, or a decompression bomb.

A `malicious` verdict is never read as benign, however low its confidence (see
the thresholds below), and the two checks only ever make a disposition worse.

## Verdicts, actions and fail mode

The model's verdict and confidence are read under two thresholds:

- `malicious` with confidence ≥ `maliciousThreshold` (0.7) → **malicious**
- `malicious` below it → **suspicious** (an unsure "malicious" is still a flag)
- `suspicious` with confidence ≥ `suspiciousThreshold` (0.5) → **suspicious**
- otherwise → **benign**, unless one of the deterministic checks floors it

Thresholds are applied when a verdict is read, not when it is stored, so
changing them re-evaluates stored verdicts without re-scanning.

| Disposition | `annotate` | `block` (default) | `quarantine` |
|-------------|-----------|-------------------|--------------|
| malicious | served, recorded | **403**, evicted from the cache | **403**, evicted |
| suspicious | served, recorded | served with an advisory | **403**, evicted, held for review |
| benign | served | served | served |
| unscanned | `failMode` decides: `open` serves, `closed` refuses. Nothing is evicted. | | |

A refused artifact is **quarantined**: it is removed from the content cache so
it is neither served nor retained. Its verdict stays in the verdict cache, so a
later pull re-fetches the bytes and is refused again without another model call.

### Why an artifact goes unscanned

| Code | Meaning | Caused by the artifact | Clears by itself |
|------|---------|:---:|:---:|
| `oversized` | larger than `limits.maxArtifactBytes` | ✓ | |
| `unsupported-format` | not an archive the scanner can unpack | ✓ | |
| `empty-archive` | an archive with no files | ✓ | |
| `unpack-limit` | nothing could be unpacked within the limits | ✓ | |
| `provider-refusal` | the provider's safety system declined to analyze it | ✓ | |
| `malformed-output` | the answer was not a valid verdict | ✓ | |
| `injection-suspected` | the answer disclosed the system prompt | ✓ | |
| `token-limit` | the token cap was reached before a verdict | ✓ | |
| `digest-mismatch` | the bytes read are not the bytes the cache recorded | | |
| `provider-error` | the provider call failed | | ✓ |
| `provider-unavailable` | circuit breaker open after repeated failures | | ✓ |
| `timeout` | the scan ran out of time | | ✓ |
| `scanner-busy` | every slot is taken and the queue — or the tenant's share of it — is full | | ✓ |
| `budget-exhausted` | a cost ceiling was reached | | (at window reset) |
| `artifact-unavailable` | the cached bytes could not be read | | ✓ |
| `internal-error` | a bug in the scanner (panics are contained) | | ✓ |

The distinction matters. The publisher controls the first group: an artifact
padded past the size limit, built to defeat the unpacker, or written to make the
model refuse or ramble may have been made unscannable on purpose. Under
`failMode: open` such an artifact is served **with a finding**
(`llmpkgscan/scan-incomplete`) so it never looks the same as one that was
examined and found clean. Infrastructure failures produce no package finding.

`failMode: closed` refuses every unscanned artifact with `403` and
`X-Policy-Code: llm-package-unscanned`. For the causes that clear by themselves
the response also carries `Retry-After`.

> `action: block` with `failMode: open` stops enforcing whenever the provider is
> down or the budget is spent. Preflight warns about the combination. Choose
> `closed` where serving an unscanned package is not acceptable, and accept that
> a provider outage then blocks first pulls of new artifacts.

## Verdict cache, coalescing and budget

- **Key:** `sha256(artifact bytes)` + model + prompt version. Identical bytes are
  scanned once, whatever coordinate, tenant or request they arrive under. A
  different model or a new prompt version (which also covers the tool contract,
  the output schema and the injection ruleset) re-scans rather than serving an
  answer the new rules did not produce.
- **Bound to the bytes served.** The key is the digest the cache recorded for the
  entry being served. The scanner hashes the stream it actually unpacks and
  refuses to file a verdict if the two differ (`digest-mismatch`).
- **Store:** `storeDir` persists one file per verdict (directory `0700`, files
  `0600`, atomic writes). Empty keeps verdicts in memory, bounded, and lost on
  restart — every artifact is then paid for again. `cacheTtl` expires verdicts.
- **Failures are remembered briefly** (`errorTtl`, 5 min; 20 s for causes that
  clear by themselves) so an artifact that reliably fails does not cost a scan
  per request. Budget, breaker and full-queue refusals are not remembered
  against an artifact: they say nothing about it.
- **Coalescing:** concurrent pulls of one digest share a single scan.
- **Circuit breaker:** five consecutive provider failures pause scanning for
  30 s, so an outage costs each request a fast answer instead of a full timeout.
- **Budget** (`llmPackageScan.budget`): a per-tenant ceiling and a global ceiling
  per window (default 24 h, after which usage resets), priced from the commit scanner's model
  price table (overridable under `budget.pricing`). Cache-read and cache-write
  tokens are priced at their own rates. The check happens before a scan and the
  cost is known after, so a ceiling can be overshot by the scans in flight.
  An exhausted budget is announced once per window, not once per pull.

Scanning is driven by what clients pull. **Without a ceiling, spend is bounded
only by what clients request** — anyone able to pull can request many distinct
artifacts. Set both ceilings.

## What the client sees

Served:

```
X-LLMPkgScan-Decision: clean | annotate | degraded | break-glass
X-LLMPkgScan-Verdict:  benign | suspicious | malicious | unscanned   # the gate's reading
X-LLMPkgScan-Model-Verdict: benign | suspicious | malicious          # what the model answered
X-LLMPkgScan-Confidence: 0.94        # the model's confidence in its own answer
X-LLMPkgScan-Cached: true            # verdict came from the verdict cache
X-LLMPkgScan-Truncated: true         # verdict rests on an incomplete view
X-LLMPkgScan-Code: provider-error    # unscanned only
X-LLMPkgScan-Reason: …               # anything short of a clean verdict
```

Refused (`403`), with the standard policy headers every admission refusal carries:

```
X-Policy-Decision: block
X-Policy-Code: llm-package-malicious | llm-package-suspicious | llm-package-unscanned
X-Policy-Reason: the model judged the package malicious (confidence 0.97)
X-Cache: BLOCKED
```

```json
{
  "error": "artifact blocked by LLM package-content scan policy",
  "code": "malicious", "policyCode": "llm-package-malicious", "action": "block",
  "reason": "the model judged the package malicious (confidence 0.97)",
  "ecosystem": "npm", "package": "evil-pad", "version": "1.0.0",
  "digest": "sha256:…",
  "verdict": "malicious", "modelVerdict": "malicious", "confidence": 0.97,
  "locations": [{"path": "package/scripts/setup.js", "line": 2}]
}
```

`verdict` is the gate's reading; `modelVerdict` and `confidence` are what the
model itself answered. They differ when a threshold or one of the deterministic
checks changed the reading — a package the model called benign with confidence
0.93 is still refused as `suspicious` under `quarantine` if it contains text
addressed to the scanner.

The response tells the developer what was decided and where to look. It
deliberately does **not** relay the model's free-text reasons or quoted excerpts,
and neither do response headers or notifications: those are shaped by the package
under review, and a refusal message is exactly where a hostile package would want
to put words in the proxy's mouth ("run this to allow-list the package").
Likewise, the detail behind a failed scan (a provider error message, a fragment
of a malformed answer) stays in the logs and on the admin surface; a client sees
a fixed sentence per reason code.

## Releasing a false positive

A refusal on a verdict — or on an artifact that cannot be scanned because of what
it is — opens a review in the [break-glass approval workflow](approvals.md)
(gate `llmpkgscan`). Once approved, the artifact is served with
`X-Approval-Decision: break-glass`.

A grant is **scoped to the artifact digest**. It releases exactly the bytes the
reviewer looked at and does not carry over to different bytes later served under
the same coordinate. Passing faults (provider outage, timeout, exhausted budget)
do not open reviews — they would open one per package pulled while the fault
lasts.

To stop scanning something entirely, use `exclude` (an ecosystem) or
`excludeUpstreams` (an upstream).

## Where the verdict goes

| Surface | What |
|---------|------|
| **Findings / SARIF** ([findings.md](findings.md)) | `llmpkgscan/malicious-package` (error), `llmpkgscan/suspicious-package` (warning), `llmpkgscan/scan-incomplete` (note); one result per cited file and line |
| **Dossier** | an *LLM package-content scan* section: verdict, gate reading, model and prompt version, coverage, injection indicators, the model's reasons and citations. A refusal is a blocking headline. |
| **Policy engine** | `input.llmPackageScan` (see below) |
| **Risk score** | signal `llmpkgscan`, weight `riskScore.weights.llmPackageScan` (default 0.20) |
| **Audit log** | `scan_verdict` for every fresh verdict, benign included (reason `llmpkgscan:<verdict>`), and `policy_decision` for every refusal and flagged serve (reason `llmpkgscan:<code>`). Records carry categories, digests and provenance — not the model's prose. |
| **Notifications** ([notifications.md](notifications.md)) | `llm_package_scan` for a flagged package; `cost_budget` when a ceiling is reached |
| **Metrics** ([observability.md](observability.md#llm-package-content-scan)) | `pullthrough_llmpkgscan_*`, a dashboard row and five alerts |
| **Admin API** | `GET /admin/api/llmpkgscan` (configuration without secrets, tallies, budget) and `GET /admin/api/llmpkgscan/verdicts?limit=&name=&ecosystem=&version=` |
| **Usage metering** | one `llmpkgscan` scan per fresh verdict, attributed to the tenant |

### Policy-as-code

`input.llmPackageScan` carries `scanned`, `verdict`, `confidence`, `disposition`,
`malicious`, `suspicious`, `action`, `cached`, `model`, `mode`, `truncated`,
`injection`, `injectionRules`, `structuralRisk`, `evidenceCount`,
`verifiedEvidence`, `unscanned`, `unscannedCode`, `contentAttributable`,
`findingCount`, `hasFindings`, `maxSeverity`, `risk` and `findings`. Examples:

```yaml
rules:
  # Refuse what the gate itself only flags.
  - id: no-suspicious-packages
    when: 'has(input.llmPackageScan) && input.llmPackageScan.suspicious'
    action: deny
    message: "LLM content scan flagged the package as suspicious"

  # Refuse an artifact that made itself unscannable, even under failMode: open.
  - id: no-unscannable-packages
    when: 'has(input.llmPackageScan) && input.llmPackageScan.unscanned && input.llmPackageScan.contentAttributable'
    action: deny
    message: "the package could not be examined by the LLM content scan"

  # A clean verdict that never saw the whole package is not good enough for prod.
  - id: full-coverage-in-prod
    when: 'input.tenant == "prod" && has(input.llmPackageScan) && input.llmPackageScan.truncated'
    action: deny
    message: "the LLM content scan saw only part of the package"
```

### Who may read a verdict

A verdict quotes the package: its reasons describe the code and its evidence
carries excerpts of it. For a private package that is confidential to the tenants
entitled to pull it. The read side is therefore tenant-scoped: a tenant-bound
admin identity — on the dossier and on `/api/llmpkgscan/verdicts` — is shown a
verdict only if **its own tenant has pulled those exact bytes** through the gate.
Knowing a coordinate is not enough. It is also not told which tenant's pull
triggered the scan or what the scan cost. An organization-wide identity sees
everything. (After a restart the list of tenants that pulled an artifact is
rebuilt as they pull again; until then only the scanning tenant sees its
verdict.)

Wherever reasons and excerpts are shown to an operator they are rendered inert:
text nodes in the admin UI, code spans in the Markdown dossier — a report pasted
into a ticket must not turn a package's text into links, images or markup.

## Security decisions and limits

**Package contents leave the network.** A scan sends file contents to the
configured LLM provider. For public packages that is public data. For a private
registry it is your source code. Scope the gate accordingly: `excludeUpstreams`
keeps an upstream's artifacts from ever being opened for scanning, and preflight
warns about every authenticated upstream that is not excluded. Alternatively
point `baseUrl` at a provider endpoint you are entitled to send that code to.

**It gates what the cache serves.** Like every content gate, it runs on cacheable
artifacts in the serve path. A resource a backend passes through without caching
is not inspected by any content gate, this one included.

**It is a static review, and it can be wrong.** A language model is a reviewer,
not a proof. It can miss a well-hidden payload and it can flag a legitimate
package. That is why the default action serves suspicious packages with an
advisory, why refusals can be released through review, and why this gate sits
alongside the deterministic gates instead of replacing them. Specifically:

- Binary members (native libraries, compiled objects, images) are listed with
  their kind and size but not read. Use `avscan` and `contentscan` for those.
- A verdict marked `truncated` rests on part of the package. Policy can require
  full coverage (see above).
- Bundle mode sees only what fits one prompt. Prefer a tool-capable provider.
- Evasion by format is handled conservatively rather than cleverly: an archive
  the scanner cannot unpack is *unscanned*, not *clean*, and the archive walker
  treats every tar member that carries data as a file and reports links instead
  of following them — so the scanner does not skip what an installer would
  write.

**A provider refusal is not a clean bill.** If the provider's safety system
declines to analyze a package, the gate reports `provider-refusal` — a cause the
artifact itself can trigger — and applies `failMode`. It does not retry against a
different model on its own: a package that makes a scanner decline is, if
anything, more suspect.

**The model's output is untrusted too.** It is parsed strictly, bounded,
stripped of control characters, cross-checked against the unpacked files, and
never placed in a response header, a client error body, a notification or an
audit record's free text.

**Credentials.** The API key goes through the secrets layer (`env://`, `file://`,
`vault://`, `${ENV}`, `enc:v1:`, or `PTS_LLM_PACKAGE_SCAN_API_KEY`), is redacted
from the configuration fingerprint and never appears in the gate's status.

## Operating it

- **Roll out in `annotate`.** Watch `pullthrough_llmpkgscan_verdicts_total` and
  review flagged packages before moving to `block`.
- **Persist verdicts** (`storeDir`) and **set a budget** before enabling it for a
  busy ecosystem. The first install of a large dependency tree scans every
  artifact once; afterwards almost everything is a cache hit.
- **Expect latency on first pulls.** A new artifact waits for its verdict (seconds
  to tens of seconds, bounded by `timeout`). Raise `maxConcurrent` if scans queue
  (`pullthrough_llmpkgscan_queued`), within your provider's rate limits.
- **Model choice.** The default is the provider's deep-analysis model, the same
  default the commit scanner uses; set `model` to choose another. `thinking`
  defaults on for models known to support adaptive thinking.
- **Alerts:** see [observability.md](observability.md#llm-package-scan-alerts).

## Testing

`internal/llmpkgscan/pkgscantest` provides a deterministic, offline stand-in for
a hosted model (it implements both the plain and the tool-use provider
interfaces) and builders for package archives. Only the model's judgement is
replaced: prompt construction, tool execution, output parsing and every bound
run unmodified against it. The gate's own tests, the gateway tests and the
dossier/admin tests share it.

```sh
go test ./internal/llmpkgscan/... ./internal/proxy/ ./internal/dossier/ ./internal/admin/
go test -tags fuzz -run '^$' -fuzz '^FuzzParseVerdict$' -fuzztime 30s ./internal/llmpkgscan/
```

Fuzz targets: `FuzzParseVerdict` (the verdict parser), `FuzzSafePath` (member-name
sanitization), `FuzzBuildTree` (the unpacker and tree builder) and
`FuzzToolCalls` (tool-argument handling).
