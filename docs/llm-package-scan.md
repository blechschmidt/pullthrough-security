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
- Covers **every upstream type the proxy fronts** — each package backend, OCI
  images, Hugging Face repositories, generic upstreams and Git LFS objects — in
  the format that ecosystem ships and on every path bytes take to a client. The
  per-backend record is generated from the code and checked against it:
  [llm-package-scan-coverage.md](llm-package-scan-coverage.md). The commits of
  a Git clone or fetch are the [commit scan](commit-watch.md)'s to examine; no
  gate refuses the clone itself (see [Git and Git LFS](#git-and-git-lfs)).

## Quick start

```yaml
llmPackageScan:
  enabled: true
  provider: claude                 # or openai | codex; empty inherits scanning.provider
  apiKey: env://ANTHROPIC_API_KEY  # secretRef, ${ENV}, enc:v1: — like every credential
  action: block                    # annotate | block | quarantine
  failMode: open                   # open | closed
  oversize: fail                   # fail | metadata-only (artifacts above limits.maxArtifactBytes)
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
relation, an enforcing action that fails open, authenticated upstreams whose
packages would be sent to the provider, and image or model upstreams whose
artifacts will mostly exceed the size limit under `oversize: fail`.

Every key is documented in the generated
[configuration reference](configuration-reference.md#llmpackagescan).

## What happens on a pull

The gate sits on every path an artifact's bytes take to a client, after the
deterministic content gates (`contentscan`, `mlguard`, `avscan`) and before the
aggregating `policyengine` / `riskscore` gates, which consume its signal. It is
deliberately the last content gate: the cheap gates go first, and anything they
refuse never costs a model call.

1. **Scope.** The upstream must not be in `excludeUpstreams` and its ecosystem
   must be in scope. With `include` empty that is every ecosystem the proxy
   fronts plus `git-lfs`; `exclude` removes one. (`git` is not a key of this
   gate: commits are the commit scan's — see [Git and Git LFS](#git-and-git-lfs).)
2. **Is there anything to examine?** The backend says what the request is — a
   payload, a document, or nothing in particular — and the first bytes are
   looked at. See [What is examined](#what-is-examined).
3. **Verdict lookup.** The verdict cache is consulted under the key
   `sha256(artifact) + model + prompt version`. A hit — including every pull of an
   artifact already in the content cache — costs no model call.
4. **Scan** (no verdict yet). The artifact is unpacked and shown to the model; see
   below. Concurrent pulls of the same digest share one scan.
5. **Decision.** The verdict, the configured thresholds and action, and the
   deterministic cross-checks decide whether the response is the artifact or a
   `403`.

The response is held until step 5. Nothing is streamed while the scan runs —
which is also what makes a `Range` request safe: a range is cut from an artifact
only after the gate has passed it.

### Where the gate runs

| Path to the client | Where the gate sits |
|--------------------|---------------------|
| Cacheable artifact (miss or hit) | on the cache entry, before any byte is written; a refused artifact is evicted |
| Non-cacheable response — a snapshot build, an image manifest pulled by tag, a file on a moving branch, a path the adapter does not know | the response is held in a spool file until the verdict exists and is served from the spool |
| OCI image | examined as a whole when its manifest is pulled; its blobs follow the image's verdict |
| Git LFS object | the Git backend's serve gate: every object request, hit or miss, whole or ranged |
| Cache-federation peer endpoint | nothing is scanned; a stored refusing verdict is enforced (403) |
| A miss filled from a sibling proxy, a pre-warm, an imported or restored cache entry | the same pipeline as a client pull: the gate runs when the entry is served |

The complete list, with what each path does on `HEAD`, on `Range` and above the
size limit, is in the [coverage record](llm-package-scan-coverage.md#serve-paths).

### What is examined

Whether a response holds something to examine is not decided by its name, and
not by whether it is cached. Each backend classifies what it resolves, and the
gate acts on that statement **and on the bytes**:

| The backend says | The gate |
|------------------|----------|
| **payload** — something a client installs, unpacks, builds, imports or executes | always examines it |
| **metadata** — an index, a listing, a checksum or signature sidecar | leaves it alone, once its first bytes have shown that it is not a package archive, an executable, a script or a pickle after all |
| nothing (**unclassified** — a pass-through path) | judges it from its bytes: an archive, an executable, a script or a pickle is examined, and so is content named like a package archive |

Four rules keep that from becoming a way around the gate:

- **"Metadata" is a statement about the path, and the path proves nothing.** In
  several protocols the repository's own index tells the client where to fetch
  each package (an APT `Filename:`, a yum `location`, a PyPI simple-page link).
  A hostile repository can therefore route a package through a path that reads
  as an index. So metadata is never skipped unseen: a `.deb` served at an index
  path is examined as the `.deb` it is. (The one kind of metadata that
  legitimately *is* an archive — Hackage's `01-index.tar.gz`, a Julia registry
  tarball — is declared as such by its backend, and a tar there is left alone; a
  zip, an OS package or an executable there is not.)
- **A pickle is recognized by what it does, not by its header.** The two-byte
  protocol header is optional to an unpickler: a protocol-0 pickle is plain
  ASCII and runs a command on load all the same. A stream whose opcodes import
  a callable is a pickle here, header or not.
- **"Cannot tell" is never "nothing there".** A compressed response is looked
  into (gzip, bzip2, xz, zstd, lzma) to see whether it holds text or an archive.
  One that will not show what it holds — corrupt, cut off, demanding too much
  decoder memory — is examined under every class.
- **A payload that does not unpack is unscanned, not a harmless file.**
  Extractors are more forgiving than a careful parser, so "the scanner could not
  open it" never means "the installer will not". Such an artifact is reported
  `unsupported-format` and handled by `failMode`. The exception is a payload
  that may honestly be one file: its backend says so (a POM, a `Package.swift`,
  a `conanfile.py`, a model weight file, an installer on a generic route), or it
  starts like an executable, a script or a pickle and is not named like an
  archive. That one is examined as the single file it is.

A document the gate leaves alone is served without `X-LLMPkgScan-*` headers and
counted in `pullthrough_llmpkgscan_not_package_total`. The decision is made per
request, not per digest: the same bytes requested under two paths each get the
answer their own path calls for — but a verdict already on record for those
bytes is enforced wherever they turn up.

### Every ecosystem's format

The unpacker (`internal/contentscan`, shared with the deterministic content
gate) recognizes formats by signature, never by file name, and opens what each
ecosystem ships:

- **tar** under gzip, bzip2, xz, zstd or lzma — npm, sdists, `.crate`, Helm
  charts, conda `.tar.bz2`, CRAN, CPAN, Hackage, pub, Conan, Bazel, Julia,
  Ansible, Puppet, Homebrew bottles, Terraform modules, OCI layers;
- **zip** — wheels, Go modules, `.nupkg`, jars, `.vsix`, Composer, Terraform
  providers, Swift archives — including a zip behind a prefix (a zipapp, an
  executable jar, a self-extractor), which installers unpack like any other;
- **package formats that nest an archive** — a `.gem` (`data.tar.gz`), a Hex
  package (`contents.tar.gz`), a `.conda` (`info-*.tar.zst`, `pkg-*.tar.zst`);
- **`.deb`** — the maintainer scripts and control files appear under `DEBIAN/`,
  as `dpkg-deb --raw-extract` lays them out, followed by the data files;
- **`.rpm`** (RPM 4 and RPM 6) — the scriptlets and triggers live in the header,
  not in the payload, and are shown as `RPM/scriptlets/*` and `RPM/triggers/*`
  next to a header summary and the cpio payload's files;
- **cpio**, **ar** and **NAR** (Nix);
- an **archive inside an archive**, two levels down, under `<member>!/`;
- a **single file**, plain or compressed.

Maintainer scripts, scriptlets, lifecycle hooks, build scripts and what an
image's entrypoint names are ranked first, per ecosystem. The unpackers are
tested against archives written by the real tools (`dpkg-deb`, `rpmbuild`,
`cpio`, `xz`, `zstd`, `nix-store`); the formats and what the model is shown for
each are tabulated in the [coverage record](llm-package-scan-coverage.md#artifact-formats).

Decoder memory is bounded independently of the size limits: an xz or lzma
stream may ask for at most a 64 MiB dictionary, a zstd stream for a 128 MiB
window. A stream that asks for more is refused before anything is allocated.

### Binary files

Most of what a bottle, a NAR, an OS package, a jar or a model weight file holds
is not text. A model cannot review machine code, but a binary is not opaque
either. For every binary member the model gets:

- a **description** from its header — ELF / PE / Mach-O with class, machine and
  type; JVM class; WebAssembly; pickle; safetensors; GGUF; HDF5; NumPy — and a
  note when it is packed (UPX) or has the entropy of encrypted data;
- a **strings view** it can read and search like a text file: the printable
  ASCII and UTF-16 strings, with the ones that matter first — URLs, hosts and
  IP addresses, shell commands, credential paths, the names of process and
  network functions;
- for a **pickle**, a summary written by the proxy of what it imports and calls
  when loaded (`os.system`, `subprocess.Popen`, `builtins.eval`, …), and for a
  **safetensors** file its header. These lines are marked `[proxy]`; a string
  inside the file that imitates the marker is rewritten, so the file cannot
  forge a statement by the proxy. The same holds for what the proxy quotes on
  its own lines: the imports the model-file rules flag are listed first (the
  file's author chooses their order, and two hundred harmless names in front of
  `os.system` must not push it off the list), and an imported "name" that is
  not an identifier — a sentence, the marker itself — is shown as a quoted
  literal and called out as the file's text.

Nothing is disassembled, loaded or executed. `avscan` and `mlguard` remain the
gates for signatures and for model-format rules; this is what lets the model
give a meaningful verdict on an artifact that is mostly binary.

### OCI images

An image is not one artifact: it is a manifest naming a config blob and layer
blobs, each fetched separately. What a container runs is spread across them, so
the gate examines the **image as a whole, when its manifest is pulled** (by tag
or by digest):

- `image/run.txt` — what a container started from the image executes: user,
  entrypoint, command, working directory, shell, healthcheck, `ONBUILD`
  triggers, environment, ports, volumes, labels;
- `image/history.txt` — the build steps the config records (the image's own
  claim about how it was built), numbered like the layers;
- `image/config.json`, `image/manifest.json`;
- every layer's files under `layers/NNN-<digest>/`, **top-most layer first**.
  The budgets are shared by the whole image; when they run out it is the base
  layers — which thousands of images share — that the image scan does not get
  to, and each one it did not read in full is named. The file an entrypoint or
  command names is ranked first.

Every blob is checked against the digest the manifest names for it. The verdict
is stored under the **manifest digest** — which content-addresses everything
else — as a variant of its own, so a reading of the manifest as a plain JSON
file is never served as the image's verdict.

The blobs then follow the image:

- a blob a **refusing verdict implicates** — the image's config, and each layer
  the verdict's evidence cites — is refused, whoever asks for it;
- a blob an **image scan read in full** is served without a scan of its own
  (under `oversize: metadata-only` that includes a layer cut short only by the
  size limit: a scan of its own would stop at the same byte);
- a blob **no image scan read** is examined by itself when it is pulled, with a
  budget of its own, as the piece of a root filesystem a layer is. That is a
  layer the image scan's budget did not reach — on a large image, the base
  layers — as well as one pulled by a client that got its manifest elsewhere.
  The verdict is stored under the layer's digest, so a base layer is examined
  once, however many images are built on it.

So no layer is served on the strength of an image verdict that never opened it:
padding an image with enough files to exhaust the budget above a layer does not
hide the layer, it only moves its examination to the moment it is pulled.

Three rules keep blob refusal from being turned against images that did nothing
wrong:

- **Only the implicated blobs of a refused image are refused**, never all of
  them. Images share base layers, and refusing those because one image built on
  them is malicious would let anyone take a popular base image offline by
  publishing malware on top of it.
- **A layer is implicated by evidence the proxy confirmed** — the quoted text is
  in the file the verdict cites. Unconfirmed citations count only when nothing
  inside a layer could be confirmed, and then only for a file that exists.
- **A config is refused as the config of a refused image, not as a digest.** A
  manifest can name any blob of the registry as its config, so anyone can push a
  throwaway image that names another image's config and carries something
  blatant in a layer of its own. Such a blob is implicated as a config only if
  it reads as an image config, and it is served for as long as an image the gate
  currently serves has it as *its* config. (A config pins the content of its
  layers — every runtime checks them against its diff IDs — so two images that
  share one are the same image, or one of them is a forgery no runtime starts.)
  The refused image stays refused where it matters: at its manifest, and at the
  layers its verdict cites, for which there is no such exception.

What remains is the limit of any verdict that rests on a model's citations: a
model that is led to cite a file in a layer other images share gets that layer
refused. A refusal names the image whose verdict caused it, and a break-glass
grant for that image releases its blobs.

A manifest list (image index) names other manifests and is served unexamined;
the platform manifest a client selects from it is examined when it is pulled.
An OCI artifact that is a signature, an attestation or an SBOM holds nothing to
unpack or run and is left alone; one that carries a payload (a Helm chart, a
WebAssembly module) is examined.

### Artifacts above the size limit

`limits.maxArtifactBytes` (64 MiB by default; for an image, per layer) bounds
what is scanned whole. `llmPackageScan.oversize` says what happens above it:

| `oversize` | What the gate does | What the verdict means |
|------------|--------------------|------------------------|
| `fail` (default) | nothing is read; the artifact is reported `oversized` and `failMode` decides | a verdict is always a verdict on every byte served |
| `metadata-only` | the model judges what can be established within the limits: the file inventory, the install-time scripts and manifests in the first `maxArtifactBytes`, and for an image its config, history and the listing of every layer that fits. A zip is listed in full through random access — its directory is at its end — and its members read wherever they lie | the verdict is recorded with `scope: metadata-only`, flagged `truncated`, and carries a `scan-incomplete` finding and a non-zero risk even when it found nothing |

A **malicious** metadata-only verdict is enforced like any other. A **benign**
one is evidence about what was read, never a statement about the rest; policy
can refuse it (`input.llmPackageScan.truncated`). The two are stored under
different keys: raising the limit later leads to a full scan, not to the partial
verdict being served as a complete one.

A non-cacheable response above the limit cannot be held whole and has no digest
to file a verdict under; it is always `oversized`.

### Files built to be read differently by the scanner and the installer

The gate judges what an installer will unpack. Its failure mode is therefore a
disagreement: a file the scanner reads one way and the installer another. The
unpacker closes the ones that are known:

- **A file that is two archives at once.** A zip reader starts at the end of the
  file, everything else at the beginning — so a tarball with a zip appended is a
  tarball to npm and a wheel to pip. Whatever the first bytes say, the file is
  also read as a zip from its end, and the members of that reading are listed
  under `_same-file-read-as-zip!/`. The other direction — a zip whose first
  block is also a valid tar header, which RubyGems, Hex or a container runtime
  would unpack as a tar — is listed under `_same-file-read-as-tar!/` and is
  held against the package regardless of what the model makes of its contents:
  such a file does not come about by accident. Where the second reading cannot
  be examined (an artifact over 16 MiB whose stream offers no random access),
  that is a structural anomaly too, never a clean pass.
- **A tar with a damaged header.** npm's extractor skips a header block that
  fails its checksum and installs what follows; GNU tar does the same; Python's
  and Go's stop. The unpacker reads on to the next valid header the way the
  lenient ones do, so a lifecycle script placed behind a deliberately broken
  header is in front of the model — and the damage itself is recorded as a
  structural anomaly.
- **A zip behind a prefix** is unpacked, and the prefix reported.
- A zip member is a file unless its name ends in a slash, whatever its mode
  bits claim; a tar member of any type that carries data is a file; duplicate
  member names are kept apart; links are reported, never followed.

### Git and Git LFS

A clone or fetch is not examined by this gate, and the commit scan is not
duplicated here. Commits are the [LLM commit scan](commit-watch.md)'s: it judges
the commits of the repositories it watches (`scanning.watch`) and the commits
packages were built from, and its verdicts raise findings, alert, and — through
the admission policy — refuse the *packages* built from a flagged commit. Naming
`git` in `include` has no effect, and preflight says so.

> **A clone or fetch is not refused by any verdict.** Git smart-HTTP and SSH
> traffic is served by the Git backend, which owns the connection and runs no
> admission gate; a repository that is not watched is not scanned at all when it
> is cloned through the proxy. If a `git clone` must not deliver a commit the
> scan flagged, that has to be enforced where the clone is consumed (a policy on
> the packages built from it, or a branch protection upstream) — the proxy does
> not do it today.

What a commit does not contain is the content behind a **Git LFS** pointer: the
pointer is three lines of text, and the object it stands for is downloaded
separately and lands in the checkout all the same. Those objects are examined
here, under the scope key `git-lfs` (on by default when `git.lfs.enabled` is
set). An LFS object is an opaque blob, so it is judged from its bytes: an
archive, an executable, a script or a pickle is examined; an image, a video or a
dataset is not, and costs nothing.

### Generic upstreams

A [generic upstream](generic-backend.md) serves what its operator declares.
Add `llmPackageScan` to a route's `gates` to have what it serves examined — as
an archive or as a single file (an installer script, a binary), cacheable or
not. A route without it is unclassified, and is still examined when its bytes
are an archive, an executable or a script.

### Air-gapped instances

The gate needs a provider, and behind an air gap there is none. Verdicts
therefore travel with the content: `pullthrough export` carries the verdicts on
record for the artifacts in the bundle, and `pullthrough import` files them in
the importing instance's verdict store (`llmPackageScan.storeDir`). After that
a pull behind the gap is answered from the store — a refusing verdict is
enforced, a clean one admits the artifact — without a scan.

- A verdict is something the importing instance acts on, so it is accepted only
  from a bundle whose **manifest digest was verified** against a value obtained
  out of band (`import -manifest-digest <digest or .sha256 file>`). The digest
  covers the verdicts. Without it the artifacts are imported and the verdicts
  are not; the import says so.
- A verdict already on record is never replaced by an imported one.
- The importing instance must be configured with the same `model` (a verdict's
  key includes the model and the prompt version). An artifact without an
  imported verdict is handled by `failMode`, as on any instance that cannot
  reach its provider.
- `export -no-verdicts` leaves them out.

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
| `maxArtifactBytes` | 64 MiB | scanning a prefix of something larger; above it `oversize` decides (see [above](#artifacts-above-the-size-limit)). For an image the bound is per layer |
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
| `oversized` | larger than `limits.maxArtifactBytes` under `oversize: fail` (or a non-cacheable response too large to hold) | ✓ | |
| `unsupported-format` | a payload that is not an archive the scanner can unpack, and not something that may be a single file; an image manifest that is not one | ✓ | |
| `empty-archive` | an archive with no files | ✓ | |
| `unpack-limit` | nothing could be unpacked within the limits | ✓ | |
| `provider-refusal` | the provider's safety system declined to analyze it | ✓ | |
| `malformed-output` | the answer was not a valid verdict | ✓ | |
| `injection-suspected` | the answer disclosed the system prompt | ✓ | |
| `token-limit` | the token cap was reached before a verdict | ✓ | |
| `digest-mismatch` | the bytes read are not the bytes the cache recorded; a blob of an image does not match the digest its manifest names | | |
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
X-LLMPkgScan-Decision: clean | annotate | degraded | break-glass | image
X-LLMPkgScan-Verdict:  benign | suspicious | malicious | unscanned   # the gate's reading
X-LLMPkgScan-Model-Verdict: benign | suspicious | malicious          # what the model answered
X-LLMPkgScan-Confidence: 0.94        # the model's confidence in its own answer
X-LLMPkgScan-Cached: true            # verdict came from the verdict cache
X-LLMPkgScan-Truncated: true         # verdict rests on an incomplete view
X-LLMPkgScan-Scope: metadata-only    # the artifact was above the size limit; see "oversize"
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
  "message": "artifact blocked by LLM package-content scan policy: the model judged the package malicious (confidence 0.97)",
  "code": "malicious", "policyCode": "llm-package-malicious", "action": "block",
  "reason": "the model judged the package malicious (confidence 0.97)",
  "ecosystem": "npm", "package": "evil-pad", "version": "1.0.0",
  "digest": "sha256:…",
  "verdict": "malicious", "modelVerdict": "malicious", "confidence": 0.97,
  "locations": [{"path": "package/scripts/setup.js", "line": 2}]
}
```

`X-LLMPkgScan-Decision: image` marks a blob served because an examined image
covers it. `message` repeats the error and its reason under the key Git LFS
clients print. For an image or one of its blobs, `digest` is the manifest
digest and `locations` point into `layers/NNN-<digest>/…`. A request whose
client gave up while the scan ran is answered `503` with `Retry-After`; the scan
finishes and its verdict is waiting for the retry.

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
the same coordinate. For an image the review is opened for
`<repository>@<manifest digest>` — the same coordinate for the manifest under
every tag and for each of its blobs — so one grant releases the image whole. Passing faults (provider outage, timeout, exhausted budget)
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

**It gates every serve path, not only the cache.** The deterministic content
gates run on cacheable artifacts. This one also holds a non-cacheable response
until its verdict exists, examines an image when its manifest is pulled, gates
Git LFS objects, and enforces stored verdicts on the cache-federation endpoint
(see [Where the gate runs](#where-the-gate-runs)). What remains outside it:
whatever is excluded by `exclude` or `excludeUpstreams`, and Git clones and
fetches — which no gate refuses: their commits are examined by the commit scan
for the repositories it watches, and that is all
(see [Git and Git LFS](#git-and-git-lfs)).

**A request path never contains `.` or `..`.** No client sends one; it arrives
only in an encoded spelling (`%2e%2e`), and the upstream would resolve it into a
different path than the one the backend parsed, classified and gated. Such a
request is refused with `400` for every backend, before it is resolved.

**It is a static review, and it can be wrong.** A language model is a reviewer,
not a proof. It can miss a well-hidden payload and it can flag a legitimate
package. That is why the default action serves suspicious packages with an
advisory, why refusals can be released through review, and why this gate sits
alongside the deterministic gates instead of replacing them. Specifically:

- Binary members are shown as a description and a strings view, not reviewed as
  code: logic that leaves no readable trace in a native binary is invisible to
  it. Use `avscan` and `contentscan` alongside.
- A layer or artifact above the size limit is unexamined under `oversize: fail`
  and only partly examined under `metadata-only`; both are stated on the
  verdict, never passed off as a clean bill.
- A verdict marked `truncated` rests on part of the package. Policy can require
  full coverage (see above).
- A large image is examined in pieces: the image scan covers the config and the
  layers its budget reaches, and each remaining layer is examined on its own
  when it is pulled — without the image's entrypoint next to it. Nothing is
  served unopened, but behaviour that only shows when a base layer's file is
  read together with the config of the image on top can be missed.
- Bundle mode sees only what fits one prompt. Prefer a tool-capable provider.
- A resource no backend classifies — a Git LFS object, a path an adapter does
  not name — is judged from how it begins: an archive, an executable, a script
  with an interpreter line, a pickle (with or without its protocol header) is
  examined. Source code without an interpreter line is not recognized there, and
  a pickle can be written to keep its first import out of the bytes that are
  looked at. This is the net under what nobody classified; what a backend can
  name it classifies as a payload, and a payload is examined whatever its bytes
  look like.
- Evasion by format is handled conservatively: an archive the scanner cannot
  unpack is *unscanned*, not *clean*; a file that reads as two archives is read
  both ways; a damaged tar is read the way the most tolerant extractor reads it;
  and structure with no innocent explanation (a path or link escaping the root,
  a decompression bomb, a zip that is also a tar, damage that makes extractors
  disagree) holds the package as *suspicious* whatever the model says of its
  contents. Under the default `block` action a suspicious package is served
  with an advisory; use `quarantine`, or a policy rule on
  `input.llmPackageScan.structuralRisk`, to refuse it.

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
- **Images cost one scan, plus one per layer the image scan did not reach.** The
  first pull of an image scans it as a whole; every layer its budget left
  unread is scanned when the client pulls that blob — once per distinct layer,
  so a base layer shared by a hundred images is paid for once. Raise
  `limits.maxFiles` / `maxUnpackedBytes` to have more of an image judged in one
  piece, at the price of larger prompts.
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
go test ./internal/llmpkgscan/... ./internal/contentscan/ ./internal/proxy/ ./internal/dossier/ ./internal/admin/
go test ./internal/scancoverage/ ./cmd/pullthrough/ -run 'LLMScanCoverage|EveryUpstreamType'
go test -tags fuzz -run '^$' -fuzz '^FuzzParseVerdict$' -fuzztime 30s ./internal/llmpkgscan/
go test -tags fuzz -run '^$' -fuzz '^FuzzWalkArtifact$' -fuzztime 30s ./internal/contentscan/
```

What holds the coverage in place:

- **Per format** — `TestEveryEcosystemArtifactFormatIsUnpackedAndJudged`
  (`internal/llmpkgscan`) drives the whole gate over one artifact per ecosystem
  in the format that ecosystem ships, the OS-package and Nix ones written by the
  real tools; `TestEveryDefaultEcosystemHasAFormatCase` fails when an ecosystem
  in the default scope has no such case.
- **Per backend** — every backend's `artifact_class_test.go` pins what it
  classifies as payload, metadata or neither; `TestLLMScanCoverageMatchesTheBackends`
  (`cmd/pullthrough`) resolves every example path of the
  [coverage record](llm-package-scan-coverage.md) against the real backend; and
  `TestEveryUpstreamTypeHasAnLLMScanCoverageEntry` fails when an upstream type
  the configuration accepts has no entry — a backend added later cannot opt out
  of the scan by omission.
- **Per serve path** — `internal/proxy/llmpkgscan_paths_test.go` covers the
  non-cacheable path, images and their blobs, `Range`, Git LFS, the peer
  endpoint, a peer-filled miss, a pre-warm and an imported cache entry.
- **Per blob rule** — `internal/llmpkgscan/blobs_test.go` is written as the
  attacks the blob index must withstand: a layer hidden under padding, another
  image's config (or layer) named as the config of a throwaway malicious image,
  an archive named as a config to have it marked examined, a layer's verdict
  reused for the same bytes read as a package.
- **Parser differentials** — `internal/contentscan/polyglot_test.go` and
  `internal/llmpkgscan/polyglot_test.go` build the files meant to make scanner
  and installer disagree.

Fuzz targets: `FuzzParseVerdict` (the verdict parser), `FuzzSafePath` (member-name
sanitization), `FuzzBuildTree` (the unpacker and tree builder), `FuzzToolCalls`
(tool-argument handling) and, in `internal/contentscan`, `FuzzWalkArtifact`
(every container format).
