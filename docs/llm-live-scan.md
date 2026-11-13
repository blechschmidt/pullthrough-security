# Known malware against a real model (live LLM scan)

The [LLM package-content scan](llm-package-scan.md) and the LLM commit scan
([commit-watch.md](commit-watch.md)) are tested in two ways. The
[ecosystem suite](llm-package-scan.md#testing) proves the *wiring* — that every
upstream type's artifacts reach the model and that a verdict is enforced — with a
stand-in model. This page is about the other question: **does a real model, shown
a real attack, say so?**

`internal/e2e/livescan` answers it with a corpus of **reconstructions of publicly
documented supply-chain attacks** — the Trivy compromise and the TeamPCP campaign
that followed it (the poisoned `trivy-action`, LiteLLM, telnyx), ctx, ultralytics,
event-stream, ua-parser-js, s1ngularity (nx), GlassWorm, the PHP git-server backdoor
and the tj-actions/changed-files compromise, listed [below](#the-corpus) with their
sources. Each is pulled through the **real `pullthrough` binary** as
the ecosystem's own client would, with a **real model** behind the LLM gates:

- the **malicious release** must be **refused** — `403`, `X-Policy-Code:
  llm-package-malicious`, because the model said *malicious* — and must **stay
  refused** on a second pull without another model call;
- the **last clean release** of the same package must be **served, byte for byte**
  (a scanner that cries wolf is as useless as one that sleeps);
- the **attacker's commit** must be judged malicious by the commit scan and the
  ordinary commit before it must not.

It costs model calls and needs a credential, so it is **not part of the default
CI**: a [workflow](#ci) prepared for it stays switched off until a repository
variable and a secret exist. Everything it relies on besides the model runs on
every push with a fake model ([`TestKnownMalwareHermetic`](#running-it)), so the
switched-off job cannot rot.

## What it proves, and what it does not

- It proves what *this model, this prompt and this gate* did with *these
  reconstructions* on the day of a run. The report names the model; a new model or
  a new prompt version is a reason to run it again.
- A model may recognise a famous attack by name — the reports show it saying so
  ("this is the known flatmap-stream backdoor"). The corpus therefore shows what
  happens when a *known* attack recurs, and that the model's reasons rest on what
  the code does; it does not measure how a *new* attack with the same behaviour
  fares. A disguised variant of each sample (identifiers, file names and marker
  strings changed) would, and is the obvious next extension.
- The LLM scan is the **only** content gate in these runs: every deterministic gate
  that would also catch some of these samples (install-hook analysis, static
  content analysis, the malware feed, …) is switched off, so a refusal can only be
  the model's verdict. In a deployment those gates are in front of the model.
- It does not show that the *real* malware would be caught: the samples are
  reconstructions, [defanged](#how-the-corpus-stays-inert), smaller than the
  originals, and written so that a reader sees what the attackers' code did. What
  real campaigns add — much larger bundles, compiled payloads, encrypted blobs the
  model cannot read — is not in them. Where an original hid its payload that
  well, the fixture keeps the *loader* a reviewer would still see.
- Git commits are judged by the commit scan ([commit-watch.md](commit-watch.md)).
  A flagged commit raises findings and alerts and gets the packages built from it
  refused; **a clone or fetch of it is not refused by a verdict**
  ([coverage record](llm-package-scan-coverage.md)). The suite
  asserts the verdict, not an enforcement the product does not have.

## The corpus

<!-- BEGIN GENERATED: corpus (go test ./internal/e2e/livescan -run TestDocsCorpusSectionIsCurrent -update) -->

| Sample | Published | Served as | Campaign |
|---|---|---|---|
| [`flatmap-stream-0.1.1`](#flatmap-stream-011) | 2018-10-05 | npm tarball on the `npm` upstream | `event-stream-2018` |
| [`php-src-zerodium`](#php-src-zerodium) | 2021-03-28 | Git commits of `php/php-src`, read by the commit scan | `php-git-compromise-2021` |
| [`ua-parser-js-0.7.29`](#ua-parser-js-0729) | 2021-10-22 | npm tarball on the `npm` upstream | `ua-parser-js-2021` |
| [`ctx-0.2.6`](#ctx-026) | 2022-05-21 | Python source distribution on the `pip` upstream | `ctx-account-takeover-2022` |
| [`ultralytics-8.3.41`](#ultralytics-8341) | 2024-12-04 | Python wheel on the `pip` upstream | `ultralytics-ci-poisoning-2024` |
| [`tj-actions-changed-files`](#tj-actions-changed-files) | 2025-03-14 | Git commits of `tj-actions/changed-files`, read by the commit scan | `github-actions-2025-03` |
| [`nx-21.5.0`](#nx-2150) | 2025-08-26 | npm tarball on the `npm` upstream | `s1ngularity-2025` |
| [`glassworm-codejoy-1.8.3`](#glassworm-codejoy-183) | 2025-10-17 | VS Code extension (`.vsix`) on the `openvsx` upstream | `glassworm-2025` |
| [`trivy-action-teampcp`](#trivy-action-teampcp) | 2026-03-19 | Git commits of `aquasecurity/trivy-action`, read by the commit scan | `teampcp-trivy-2026` |
| [`litellm-1.82.8`](#litellm-1828) | 2026-03-24 | Python wheel on the `pip` upstream | `teampcp-trivy-2026` |
| [`telnyx-4.87.2`](#telnyx-4872) | 2026-03-27 | Python wheel on the `pip` upstream | `teampcp-trivy-2026` |

### `flatmap-stream-0.1.1`

**flatmap-stream 0.1.1 (npm): wallet-targeted loader slipped into event-stream's dependencies**

| | |
|---|---|
| Published | 2018-10-05 (campaign `event-stream-2018`) |
| Served as | npm tarball on the `npm` upstream |
| Malicious release | `flatmap-stream` 0.1.1 |
| Control | `flatmap-stream` 0.1.0 (the last clean release; it must be served) |
| Techniques | `maintainer-handover`, `dependency-injection`, `minified-code-injection`, `registry-repo-mismatch`, `hex-encoded-strings`, `environment-keyed-decryption`, `targeted-payload`, `build-time-injection` |
| Indicators | `2e2f746573742f64617461`, `6e706d5f7061636b6167655f6465736372697074696f6e`, `6372656174654465636970686572` |

What the real attack did: event-stream, a stream utility with roughly 1.5 to 2 million downloads a week (reports differ), got a new maintainer in 2018: its author gave publish rights to the GitHub user right9ctrl, who had emailed offering to take it over. On 2018-09-09 that account added a dependency on flatmap-stream, with the caret range ^0.1.0, in event-stream 3.3.6. flatmap-stream 0.1.0 was clean; 0.1.1, published on 2018-10-05 (Snyk, Arvanitis et al. and the registry listing agree), fell inside the range, so every fresh install of event-stream pulled it in. The code was not in the readable index.js or in the project's GitHub repository: it was appended to the published, minified index.min.js, and the data it used shipped in test/data.js, a file that looked like a test fixture and was also missing from GitHub. The appended loader, its strings hex-encoded, read the npm_package_description variable npm sets for the package being built, used it as the AES-256 key for the first entry of test/data.js, compiled the result with module._compile and called it with the second entry, all inside a try/catch that swallowed every failure. Brute-forcing published package descriptions found the one that decrypted it, "A Secure Bitcoin Wallet", Copay's. In Copay release builds the next stage patched a dependency of the app so that a third stage ran inside the wallet, checked the balances and, above 100 BTC or 1000 BCH, sent account data and private keys to a collection server (Copay 5.0.2 to 5.1.0 shipped with it). The release was live for about seven weeks. A Node 11 deprecation warning for crypto.createDecipher (nodemon issue, 2018-10-29) led a user to open event-stream issue 116 on 2018-11-20, and npm removed flatmap-stream and event-stream 3.3.6 on 2018-11-26.

What the fixture keeps and changes: index.min.js is the clean minified stream with the first-stage loader appended, in the form the es-incident analysis prints it (F5 walks through the same code): an immediately invoked function in a try block with an empty catch, a helper e() that hex-decodes every string, the hex-encoded "./test/data" required, the npm_package_description lookup on process.env, createDecipher("aes256", ...) over the first entry, a new module built from module.constructor, _compile, and a call to its export with the second entry. The string table (entries 2 to 9 of the array: hex-encoded crypto, env, npm_package_description, aes256, createDecipher, _compile, hex, utf8) sits in test/data.js as in the original. Entries 0 and 1, which held the encrypted second and third stages, are short random hex stand-ins that cannot decrypt to anything under any key; nothing of those stages (the release-build injector, the wallet harvester, the collection server) is reproduced. The file set (index.js, index.min.js, package.json, perf-test.js, README.md, LICENSE.txt, test/data.js) is the real 0.1.1's as listed in Jayden Seric's evidence archive; index.js, perf-test.js, the README and the license are small stand-ins (a flat-mapping through stream) and index.min.js is a hand-minified copy of index.js. The main field of package.json is index.min.js, an assumption: the loader can only run if that file is the entry point, and no source read for this sample prints the field. The 0.1.0 control has the same files without the appended loader and without test/data.js.

Public analyses it is built from:

- <https://blog.npmjs.org/post/180565383195/details-about-the-event-stream-incident>
- <https://snyk.io/blog/a-post-mortem-of-the-malicious-event-stream-backdoor/>
- <https://github.com/dominictarr/event-stream/issues/116>
- <https://es-incident.github.io/payloads.html>
- <https://www.f5.com/company/blog/reverse-engineering-by-example-flatmap-stream-payload-a>
- <https://github.com/advisories/GHSA-9x64-5r7x-2q53>
- <https://github.com/bitpay/wallet/issues/9346>
- <https://jaydenseric.com/blog/event-stream-compromise>
- <https://libraries.io/npm/flatmap-stream>

### `php-src-zerodium`

**php/php-src (PHP): '[skip-ci] Fix typo' commit in Rasmus Lerdorf's name adds a User-Agentt eval backdoor**

| | |
|---|---|
| Published | 2021-03-28 (campaign `php-git-compromise-2021`) |
| Served as | Git commits of `php/php-src`, read by the commit scan |
| Malicious release | the commit `[skip-ci] Fix typo Fixes minor typo. Signed-off-by: Rasmus Lerdorf <rasmus@example.invalid>` (Rasmus Lerdorf <rasmus@example.invalid>) |
| Control | the commit `[skip-ci] Fix typo in a comment` (an ordinary change that must not be flagged) |
| Techniques | `git-server-compromise`, `identity-spoofing`, `innocuous-commit-message`, `forged-signoff`, `backdoor`, `magic-string-trigger`, `eval-of-request-data` |
| Indicators | `HTTP_USER_AGENTT`, `REMOVETHIS` |

What the real attack did: On 2021-03-28 two commits were pushed to the master branch of php/php-src (PHP 8.1-dev) on PHP's self-hosted git.php.net. The first, c730aa26 at 03:57 UTC (parent 92aeda52), was authored and committed as Rasmus Lerdorf with the title "[skip-ci] Fix typo", the body "Fixes minor typo." and a Signed-off-by line for him. Nikita Popov caught it in routine post-commit review within hours, reverted it at 09:16 UTC ("This looks like the result of a compromised git account") and revoked Rasmus's commit access. At 16:15 UTC a second commit, 2b0f239b, appeared in Nikita Popov's own name as Revert "Revert "[skip-ci] Fix typo"" and re-applied the change; Levi Morrison reverted it at 17:53 UTC. Both added the same 11 lines to php_zlib_output_compression_start() in ext/zlib/zlib.c: if the $_SERVER entry HTTP_USER_AGENTT (a request header named User-Agentt, with a doubled t so that a real User-Agent never matched) contained the string "zerodium", the value without its first eight characters was passed to zend_eval_string() as PHP code, under the name "REMOVETHIS: sold to zerodium, mid 2017" - remote code execution on any server running that tree. The commits were on master only and no PHP release carried them. PHP first took the pushes for a compromise of the git.php.net server, because they had bypassed its gitolite; its April 6 update withdrew that: the logs show HTTPS pushes through git-http-backend behind Apache Digest authentication against the master.php.net user database, authenticated as the accounts rasmus and nikic after about ten failed attempts, and that database, which kept unsalted MD5 password hashes, may have leaked. git.php.net was retired, GitHub became the canonical host and every php.net password was reset. The attacker is unidentified; Zerodium's CEO said the company had nothing to do with it.

What the fixture keeps and changes: The repository is a small stand-in for php-src: ext/zlib/zlib.c keeps the function the real commits changed, php_zlib_output_compression_start(), the neighbouring php_zlib_output_encoding() that reads HTTP_ACCEPT_ENCODING from $_SERVER, and the RINIT hook, with php_zlib.h and a README; it is a fragment and cannot be built. The attacker's commit adds the 11 lines as the GitHub commit view shows them (indentation set to the file's tabs) - a lookup of HTTP_USER_AGENTT in the _SERVER array, strstr for "zerodium", zend_eval_string on the string from its ninth character with the name "REMOVETHIS: sold to zerodium, mid 2017", inside zend_try - at the same place in the same function, with the real title and body, Signed-off-by line included, under the impersonated author's name. What changes: the e-mail addresses are defanged (example.invalid); the suite fixes the author dates, so the commit has a hash of its own; the second commit (the Revert of the Revert under Nikita Popov's name, the same 11 lines) is not modelled; and the control is an invented typo fix in a comment of the same file, under the same kind of title, by an invented author, so that the title alone cannot decide the verdict.

Public analyses it is built from:

- <https://news-web.php.net/php.internals/113838>
- <https://externals.io/message/113981>
- <https://github.com/php/php-src/commit/c730aa26bd52829a49f2ad284b181b7e82a68d7d>
- <https://github.com/php/php-src/commit/046827a7e867bb0e655923c75c25a20d06e3aa8b>
- <https://github.com/php/php-src/commit/2b0f239b211c7544ebc7a4cd2c977a5b7a11ed8a>
- <https://php.watch/news/2021/03/git-php-net-hack>
- <https://php.watch/news/news/2021/04/php-src-attack>
- <https://www.bleepingcomputer.com/news/security/phps-git-server-hacked-to-add-backdoors-to-php-source-code/>
- <https://www.csoonline.com/article/3613593/php-backdoor-attempt-shows-need-for-better-code-authenticity-verification.html>

### `ua-parser-js-0.7.29`

**ua-parser-js 0.7.29 (npm): preinstall hook drops a Monero miner and a password stealer**

| | |
|---|---|
| Published | 2021-10-22 (campaign `ua-parser-js-2021`) |
| Served as | npm tarball on the `npm` upstream |
| Malicious release | `ua-parser-js` 0.7.29 |
| Control | `ua-parser-js` 0.7.28 (the last clean release; it must be served) |
| Techniques | `account-takeover`, `install-hook`, `platform-dispatch`, `geo-fencing`, `download-and-execute`, `cryptominer`, `credential-stealer-dll`, `living-off-the-land` |
| Indicators | `jsextension`, `citationsherbe.at`, `start /B node preinstall.js`, `regsvr32.exe -s create.dll` |

What the real attack did: ua-parser-js, a user-agent parsing library with about 7 million weekly downloads (reports differ: up to 8 million), was released three times on 2021-10-22 from its maintainer's hijacked npm account: 0.7.29, 0.8.0 and 1.0.0. The maintainer first noticed his inbox flooded with spam from hundreds of websites and could only deprecate the versions, not unpublish them; they stayed downloadable for about four hours (Rapid7: roughly 12:15 to 16:16-16:26 UTC) until 0.7.30, 0.8.1 and 1.0.1 replaced them. By the Mend diff of 0.7.28 to 0.7.29 the release changed the version, added one package.json line, "preinstall": "start /B node preinstall.js & node preinstall.js", and added three files. preinstall.js switched on process.platform: Windows ran preinstall.bat through cmd.exe, Linux ran preinstall.sh through bash, macOS got nothing. preinstall.sh asked a geolocation service for the country and exited for Russia, Ukraine, Belarus and Kazakhstan; otherwise it fetched a file named jsextension from a server addressed by IP (curl, then wget) and ran it: an XMRig Monero miner pointed at the MineXMR pool with the attacker's wallet (CloudSEK: capped at about 50% of the CPU). preinstall.bat did the same for jsextension.exe (curl, wget, then certutil), started it unless tasklist showed it running, and also fetched sdd.dll from a second host, saved it as create.dll and ran regsvr32.exe -s create.dll: a password stealer that Mandiant found consistent with DanaBot (Sophos: possibly a DanaBot variant). The hijack was noticed within hours through the spam flood and GitHub issue 536. Mandiant tracks the actor as UNC3379 and ties it to a 2021-10-14 test package and the 2021-11-04 coa and rc hijacks (single source).

What the fixture keeps and changes: package.json differs from the clean 0.7.28 by the version and one added line, the preinstall hook, as in the Mend diff; src/ua-parser.js is the same in both variants (the diff lists no change to it), so it still says 0.7.28. preinstall.js follows the dispatch Mandiant prints (cmd.exe /c preinstall.bat, /bin/bash preinstall.sh, nothing for macOS). preinstall.sh and preinstall.bat keep the sequence Mandiant, Sophos and CERT-EU describe: the geolocation lookup and the RU/UA/BY/KZ exit (Linux only), an already-running check, curl with a wget fallback (certutil as the last resort on Windows, as in the command line a victim posted in issue 536), the miner started in the background with pool, wallet and CPU-cap arguments, and the DLL fetched as sdd.dll, saved as create.dll and registered with regsvr32 -s. Every endpoint is defanged: the geolocation service, the DLL host and the mining pool end in .invalid, and the download server, a bare IP in the original, is an address from 203.0.113.0/24. The wallet is a digit sequence that is not a valid Monero address. No miner binary or DLL exists in the tree, and each download targets an unresolvable address. The miner's argument list is an XMRig command line matching what the sources describe (pool, TLS, keep-alive, wallet, about 50% CPU), because the exact flags were only visible in screenshots. The chmod +x and the pgrep check in preinstall.sh are not printed in the sources read, they are assumed from the described flow (a downloaded file is not executable; the Windows script has the equivalent tasklist check). src/ua-parser.js, the readme and the license are small stand-ins for the real library.

Public analyses it is built from:

- <https://github.com/advisories/GHSA-pjwm-rvh2-c87w>
- <https://github.com/faisalman/ua-parser-js/issues/536>
- <https://cloud.google.com/blog/topics/threat-intelligence/supply-chain-node-js>
- <https://www.sophos.com/en-us/blog/node-poisoning-hijacked-package-delivers-coin-miner-and-credential-stealing-backdoor>
- <https://www.cert.europa.eu/publications/security-advisories/2021-057/>
- <https://www.rapid7.com/blog/post/2021/10/25/npm-library-ua-parser-js-hijacked-what-you-need-to-know/>
- <https://my.diffend.io/npm/ua-parser-js/0.7.28/0.7.29>
- <https://cloudsek.com/threatintelligence/poisoned-library-package-used-to-install-crypto-mining-and-password-stealing-malware>

### `ctx-0.2.6`

**ctx 0.2.6 (PyPI): hijacked package exfiltrating environment variables**

| | |
|---|---|
| Published | 2022-05-21 (campaign `ctx-account-takeover-2022`) |
| Served as | Python source distribution on the `pip` upstream |
| Malicious release | `ctx` 0.2.6 |
| Control | `ctx` 0.1.2 (the last clean release; it must be served) |
| Techniques | `account-takeover`, `runtime-import`, `credential-theft`, `env-exfiltration`, `base64-encoding` |
| Indicators | `anti-theft-web`, `sendRequest` |

What the real attack did: ctx, a small dictionary-with-attribute-access helper last released in 2014, was taken over on 2022-05-14 after its maintainer's e-mail domain expired: the attacker registered the domain, reset the PyPI password (the account had no MFA) and over a week published 18 malicious files (0.1.2-1 … 0.2.6) before PyPI removed them on 2022-05-24, about 27,000 downloads later. Their Ctx constructor called sendRequest(), which joined every environment variable's value, base64-encoded the result and sent it in the path of a GET request to a Heroku app (an earlier variant collected the AWS key pair and the host name). The same actor hijacked the PHP package phpass the same way.

What the fixture keeps and changes: ctx.py follows the PyPI incident report's verbatim excerpt: a Ctx dict subclass whose __init__ calls sendRequest(), which concatenates every value of os.environ, base64-encodes it and appends it to the GET URL; the AWS key pair lookup of the earlier variant is folded in. The exfiltration host is defanged (".invalid" appended). The rest of the module is a small stand-in for the original helper.

Public analyses it is built from:

- <https://python-security.readthedocs.io/pypi-vuln/index-2022-05-24-ctx-domain-takeover.html>
- <https://isc.sans.edu/diary/28678>
- <https://www.sonatype.com/blog/pypi-package-ctx-compromised-are-you-at-risk>
- <https://www.bleepingcomputer.com/news/security/popular-python-and-php-libraries-hijacked-to-steal-aws-keys/>

### `ultralytics-8.3.41`

**ultralytics 8.3.41 (PyPI): XMRig cryptominer launched when a YOLO model is created**

| | |
|---|---|
| Published | 2024-12-04 (campaign `ultralytics-ci-poisoning-2024`) |
| Served as | Python wheel on the `pip` upstream |
| Malicious release | `ultralytics` 8.3.41 |
| Control | `ultralytics` 8.3.40 (the last clean release; it must be served) |
| Techniques | `ci-cache-poisoning`, `runtime-trigger`, `cryptominer`, `download-and-execute`, `process-hiding` |
| Indicators | `ultralytics_runner`, `safe_run`, `consrensys` |

What the real attack did: The popular computer-vision library ultralytics (YOLO) published 8.3.41 on 2024-12-04 and 8.3.42 the next day from its own, Trusted-Publishing release workflow, with valid Sigstore attestations: an attacker had injected a shell command through a pull-request branch name into a pull_request_target workflow, stolen the GitHub Actions cache token and most likely poisoned the pip cache the release job restored. The injected code was never in the repository. Creating a YOLO model downloaded an XMRig miner to /tmp/ultralytics_runner (fetched as a Git blob through the GitHub API, a new gitApi mode of safe_download), started it detached with setsid and its output discarded, pointed at a mining pool, and deleted the file. 8.3.45 and 8.3.46, pushed later with a leaked API token, exfiltrated the environment and ran XMRig straight from the package's __init__.py.

What the fixture keeps and changes: models/yolo/model.py and utils/downloads.py follow HiddenLayer's excerpts of 8.3.41: the platform check in YOLO.__init__ choosing a Git blob ID per operating system, safe_download(..., file="/tmp/ultralytics_runner", gitApi=True), and safe_run(), which chmods the file, starts it with the wallet, pool and -k arguments under setsid with all output discarded, and removes it. The pool host and the GitHub API host are defanged (".invalid"), the wallet and blob IDs are random stand-ins of the same form, and the rest of the library is a small stand-in for the real one.

Public analyses it is built from:

- <https://www.hiddenlayer.com/research/ultralytics-python-package-compromise-deploys-cryptominer>
- <https://blog.pypi.org/posts/2024-12-11-ultralytics-attack-analysis/>
- <https://blog.yossarian.net/2024/12/06/zizmor-ultralytics-injection>
- <https://github.com/ultralytics/ultralytics/issues/18027>
- <https://www.reversinglabs.com/blog/compromised-ultralytics-pypi-package-delivers-crypto-coinminer>

### `tj-actions-changed-files`

**tj-actions/changed-files (GitHub Action): bot-spoofed commit makes dist/index.js fetch and run a runner-memory dumper**

| | |
|---|---|
| Published | 2025-03-14 (campaign `github-actions-2025-03`) |
| Served as | Git commits of `tj-actions/changed-files`, read by the commit scan |
| Malicious release | the commit `chore(deps): lock file maintenance (#2460)` ("renovate[bot]" <"29139614+renovate[bot]"@users.noreply.github.com>) |
| Control | the commit `chore(deps): update dependency @types/node to v22.13.10 (#2459)` (an ordinary change that must not be flagged) |
| Techniques | `stolen-token`, `imposter-commit`, `bot-identity-spoofing`, `tag-repointing`, `dist-bundle-injection`, `download-and-execute`, `runner-memory-scrape`, `secrets-in-logs` |
| Indicators | `updateFeatures`, `/tmp/run.sh` |

What the real attack did: On 2025-03-14 an attacker holding the Personal Access Token of the @tj-actions-bot account put commit 0e58ed8 into tj-actions/changed-files, a GitHub Action used by more than 23,000 repositories, and at 16:57 UTC moved almost every version tag (v1.0.0 up to v45.0.7) to it, so workflows that referenced a tag such as @v35 ran it. The commit was authored as renovate[bot] with the title "chore(deps): lock file maintenance (#2460)" and carried no signature (the real bot was not compromised). It changed only the bundled dist/index.js (which the repository marks -diff, so git show prints "Binary files differ" for it), adding a function updateFeatures(token) that runs bash through @actions/exec on a base64 string decoded into /tmp/run.sh. On Linux runners that script fetched memdump.py from a GitHub gist and ran it with sudo python3; memdump.py found the Runner.Worker process and read its memory through /proc/<pid>/maps and /proc/<pid>/mem, and the shell kept the {"value":...,"isSecret":true} entries and printed them, base64-encoded twice, into the workflow log, where the log of a public repository showed them to anyone. StepSecurity saw no exfiltration to a server of the attacker's. Wiz and Unit 42 trace the token theft to the compromise of reviewdog/action-setup@v1 on 2025-03-11 (CVE-2025-30154), which the maintainers' tj-actions/eslint-changed-files workflow ran with that token; the maintainers said GitHub could not determine how it leaked. Reports differ on how the commit got in (an orphan commit the tags were moved to, or a push to a Renovate pull request branch that auto-merged) and on when the first malicious commit was made (March 12 per Sysdig and Orca, between March 10 and 14 per Unit 42). StepSecurity's Harden-Runner flagged the unexpected request to gist.githubusercontent.com, issue #2463 was opened the same day, and GitHub took the repository down on March 15 and restored it without the commit. The attack is tracked as CVE-2025-30066 and fixed in 46.0.1.

What the fixture keeps and changes: dist/index.js is a small ncc-style bundle (module table, __nccwpck_require__) around a stand-in run(); the real file is over 2 MB. As in the real commit, only that file changes. The commit adds async function updateFeatures(token), which calls exec.getExecOutput('bash', ['-c', ...], {ignoreReturnCode: true, silent: true}) on "echo <base64> \| base64 -d > /tmp/run.sh && bash /tmp/run.sh" and writes the output to the log with core.info (after Snyk's reconstruction and the Aqua and Oasis descriptions), and calls it from run(); the real commit has since been deleted and the text sources do not say where its call sat, so here it follows the inputs. The base64 decodes to the script StepSecurity printed: the Linux guard, curl of memdump.py piped to sudo python3, tr -d '\0', grep -aoE for the isSecret entries, sort -u, base64 -w 0 twice, echo $B64_BLOB, else exit 0. The gist host is defanged (gist.githubusercontent.com.invalid) and the gist path is a placeholder; memdump.py, the memory scrape itself, was never part of the commit and is not reproduced. The suite fixes the commit times, and the rest of the repository (action.yml, src/, package.json, README) is a small stand-in. The repository's .gitattributes line (dist/** -diff) is kept: it made git show print "Binary files differ" for the real commit, so a scanner that reads diffs with the repository's attributes honoured sees no content at all. The commit scan now reads diffs with attributes switched off (internal/scan/watch, attr.tree), and this sample is its regression test. The control is an invented dependency bump under the same bot identity.

Public analyses it is built from:

- <https://www.stepsecurity.io/blog/harden-runner-detection-tj-actions-changed-files-action-is-compromised>
- <https://unit42.paloaltonetworks.com/github-actions-supply-chain-attack/>
- <https://github.com/advisories/GHSA-mrrh-fwg8-r2c3>
- <https://github.com/tj-actions/changed-files/issues/2463>
- <https://github.com/tj-actions/changed-files/issues/2464>
- <https://snyk.io/blog/reconstructing-tj-actions-changed-files-github-actions-compromise>
- <https://www.aquasec.com/blog/github-action-tj-actions-changed-files-compromised/>
- <https://www.wiz.io/blog/github-action-tj-actions-changed-files-supply-chain-attack-cve-2025-30066>
- <https://semgrep.dev/blog/2025/popular-github-action-tj-actionschanged-files-is-compromised/>
- <https://www.cisa.gov/news-events/alerts/2025/03/18/supply-chain-compromise-third-party-github-action-cve-2025-30066>

### `nx-21.5.0`

**nx 21.5.0 (npm): s1ngularity postinstall script drives AI coding CLIs and posts stolen tokens to a new GitHub repo**

| | |
|---|---|
| Published | 2025-08-26 (campaign `s1ngularity-2025`) |
| Served as | npm tarball on the `npm` upstream |
| Malicious release | `nx` 21.5.0 |
| Control | `nx` 21.4.1 (the last clean release; it must be served) |
| Techniques | `ci-compromise`, `publish-token-theft`, `install-hook`, `ai-cli-abuse`, `credential-theft`, `github-repo-exfiltration`, `triple-base64`, `shell-rc-sabotage` |
| Indicators | `node telemetry.js`, `s1ngularity-repository`, `/tmp/inventory.txt`, `--dangerously-skip-permissions` |

What the real attack did: On 2025-08-26 an attacker holding a stolen npm publish token pushed eight malicious nx releases straight to npm, without provenance: 21.5.0 at 22:32 UTC, then 20.9.0, 20.10.0, 21.6.0, 20.11.0, 21.7.0, 21.8.0 and 20.12.0 up to 00:37 UTC, plus malicious releases of seven plugin packages (@nx/devkit, @nx/js, @nx/node, @nx/workspace, @nx/eslint, @nx/key, @nx/enterprise-cloud). The last clean nx was 21.4.1 (2025-08-22). The token came from a pull_request_target workflow that put a PR title into a shell step (merged 2025-08-21): on 2025-08-24 a PR (the maintainers believe against an outdated branch that still had the workflow) made it run publish.yml from the attacker's commit, which posted the token to a webhook. In package.json the malicious releases changed postinstall from `node ./bin/post-install \|\| exit 0` to `node telemetry.js`, a new root-level script (the Nx Console VS Code extension also ran it, by installing nx@latest). telemetry.js exited on Windows; looked for the claude, gemini and q (Amazon Q) CLIs and ran each with a permission-bypass flag (--dangerously-skip-permissions, --yolo, --trust-all-tools) and a prompt asking it to write the paths of wallet-, key- and secret-like files to /tmp/inventory.txt; collected the environment, `gh auth token` (kept if it began gho_ or ghp_) and, when `npm whoami` worked, ~/.npmrc; read every file the inventory listed; appended `sudo shutdown -h 0` to ~/.bashrc and ~/.zshrc; and, given a GitHub token, created a public repository named s1ngularity-repository in the victim's account and committed everything to it as results.b64 (JSON, base64-encoded three times). Some later releases reworded the prompt and suffixed the repository -0 or -1; reports quote several wordings, and the one used here is the one Wiz and StepSecurity give for 21.5.0. A community issue (nrwl/nx#32522) came at 00:30 UTC, StepSecurity's runtime monitoring flagged the install-time api.github.com calls, npm removed the versions at 02:44 UTC and GitHub hid the repositories at about 09:00 UTC. Wiz counted more than 1,700 users with leaked secrets, and the leaked GitHub tokens fed a second phase that made victims' private repositories public.

What the fixture keeps and changes: telemetry.js follows StepSecurity's full copy of the 21.5.0 script (the diff screenshots in the Nx advisory, of 21.7.0, show the same structure and the package.json change): a root-level file run by postinstall, the Windows exit, the `which` probes for claude, gemini and q with their three permission-bypass flags and the "Recursively search local paths" prompt word for word as Wiz and StepSecurity quote it for 21.5.0, the gh auth token and ~/.npmrc collection, the inventory read-back, and the public s1ngularity-repository that receives results.b64 (commit message "Creation."). Changes: the GitHub API host is api.github.invalid and the link recorded for the new repository points at github.invalid; forceAppendAgentLine() keeps its name, its target list and its call site but writes nothing (the original appended `sudo shutdown -h 0` to ~/.bashrc and ~/.zshrc). The local steps (CLI probes and runs, token and ~/.npmrc reads) are kept as published, so only the upload cannot leave the machine. The control leaves out the real 21.4.1's own postinstall (`node ./bin/post-install \|\| exit 0`, a local set-up script) and so carries no install hook. The rest of the package is a small stand-in for the real one, which has 1,352 files.

Public analyses it is built from:

- <https://github.com/nrwl/nx/security/advisories/GHSA-cxm3-wv7p-598c>
- <https://www.stepsecurity.io/blog/supply-chain-security-alert-popular-nx-build-system-package-compromised-with-data-stealing-malware>
- <https://www.wiz.io/blog/s1ngularity-supply-chain-attack>
- <https://www.wiz.io/blog/s1ngularitys-aftermath>
- <https://snyk.io/blog/weaponizing-ai-coding-agents-for-malware-in-the-nx-malicious-package/>

### `glassworm-codejoy-1.8.3`

**codejoy.codejoy-vscode-extension 1.8.3 (Open VSX): GlassWorm loader hidden in invisible Unicode characters**

| | |
|---|---|
| Published | 2025-10-17 (campaign `glassworm-2025`) |
| Served as | VS Code extension (`.vsix`) on the `openvsx` upstream |
| Malicious release | `codejoy.codejoy-vscode-extension` 1.8.3 |
| Control | `codejoy.codejoy-vscode-extension` 1.8.2 (the last clean release; it must be served) |
| Techniques | `publisher-compromise`, `invisible-unicode`, `eval-loader`, `blockchain-c2`, `credential-theft`, `remote-access` |
| Indicators | `w >= 0xFE00 && w <= 0xFE0F`, `w >= 0xE0100 && w <= 0xE01EF`, `eval(Buffer.from(s(` |

What the real attack did: GlassWorm, named by Koi Security, was first seen on Open VSX on 2025-10-17: new versions of a handful of extensions were published from their real publishers' accounts (Eclipse says through publish tokens leaked in public repositories, which Wiz had reported; Koi says compromised developer accounts). Koi's risk engine flagged codejoy.codejoy-vscode-extension first: 1.8.3 and 1.8.4 were the malicious CodeJoy releases, between the clean 1.8.2 (2025-10-16) and 1.8.5 (2025-10-20). The JavaScript carried its loader as a run of thousands of invisible characters inside what looks like an empty template literal: Unicode variation selectors (U+FE00-FE0F and U+E0100-E01EF, 256 values, one per byte; Endor Labs counted 6,492 in the sample it decoded) that a short function mapped back to bytes and passed to eval. The decoded stage polled the Solana blockchain for the newest transaction memo of a hard-coded wallet; the memo's JSON held a base64 link to the next stage on a plain IP address (a Google Calendar event title was a backup), which came back AES-encrypted with its key and IV in the HTTP response headers. That stage stole npm, GitHub, Open VSX and Git credentials, went for cryptocurrency wallet extensions (49 per Koi, more than 70 per Endor) and, Koi says, used the stolen tokens to publish further extensions; a last module added a SOCKS proxy, hidden VNC and peer-to-peer control channels. Koi's analysis began on 2025-10-18; Open VSX removed the extensions, revoked or rotated the tokens and called the incident contained on 2025-10-21. Reports differ: Koi counted about 35,800 downloads and called GlassWorm a self-propagating worm, while Eclipse says bots inflated the downloads and that nothing spread by itself beyond the stolen credentials.

What the fixture keeps and changes: extension.js carries the loader as Aikido and OpenSourceMalware quote it for the later npm, GitHub and Open VSX waves, with the mapping Koi and Endor describe for the first one: a short function turns each variation selector back into a byte (U+FE00-FE0F to 0-15, U+E0100-E01EF to 16-255, anything else dropped) and the bytes, read as UTF-8, go to eval, from a template literal that shows as empty. The run is 1,163 characters, not the 6,492 Endor counted, because it decodes to a short stage that can do nothing: it keeps the call shape Koi shows (getSignaturesForAddress(WALLET, { limit: 1000 }), the memo filter and regular expression, atob on the memo's base64 link) but answers from a table inside the script, with a wallet string that is not a valid address, so the only address it builds is under next.invalid, which fetch can never reach. Dropped: the RPC lookup, the AES step with key and IV from the response headers, the calendar fallback, the stealer and the remote-access module. Endor reports that the first-wave run decodes to Base64 text that is decoded again before eval; here it decodes straight to the script. The activation cooldown and the OS-specific native decoders Endor describes are not reproduced. The rest of the extension (a status bar item and two commands) is a small stand-in; its manifest fields (main, activationEvents, engines.vscode, the two commands) follow the real clean 1.8.2. The generic corpus checks cannot see inside the run, so internal/e2e/livescan/corpus_glassworm_test.go decodes it and holds it to the same rules.

Public analyses it is built from:

- <https://www.paloaltonetworks.com/blog/security-operations/glassworm-first-self-propagating-worm-using-invisible-code-hits-openvsx-marketplace/>
- <https://www.endorlabs.com/learn/invisible-threats-glassworm-unicode-vscode>
- <https://blogs.eclipse.org/post/mika%C3%ABl-barbero/open-vsx-security-update-october-2025>
- <https://www.truesec.com/hub/blog/glassworm-self-propagating-vscode-extension>
- <https://thehackernews.com/2025/10/self-spreading-glassworm-infects-vs.html>
- <https://www.aikido.dev/blog/glassworm-returns-unicode-attack-github-npm-vscode>
- <https://opensourcemalware.com/blog/glassworm-invades-github-npm-open-vsx-and-vs-code>
- <https://fluidattacks.com/blog/glassworm-vs-code-extensions-supply-chain-attack>

### `trivy-action-teampcp`

**aquasecurity/trivy-action (TeamPCP): force-pushed tag runs a CI credential stealer**

| | |
|---|---|
| Published | 2026-03-19 (campaign `teampcp-trivy-2026`) |
| Served as | Git commits of `aquasecurity/trivy-action`, read by the commit scan |
| Malicious release | the commit `Upgrade trivy to v0.53.0 (#369)` (Maintainer <maintainer@example.invalid>) |
| Control | the commit `docs: note the v0.53.0 bump in the README (#370)` (an ordinary change that must not be flagged) |
| Techniques | `ci-compromise`, `imposter-commit`, `credential-theft`, `runner-memory-scrape`, `openssl-exfiltration`, `github-repo-exfil-fallback` |
| Indicators | `TeamPCP Cloud stealer`, `tpcp-docs`, `scan.aquasecurtiy` |

What the real attack did: On 2026-03-19 the TeamPCP actor force-pushed about 75 of the 76 version tags of the trivy-action GitHub Action (0.0.1 … 0.34.2; only 0.35.0 stayed clean) to new, unsigned commits that sat on the current master tree and replaced one file, entrypoint.sh, copying each original commit's author, dates and message. The injected top of entrypoint.sh collected the CI runner's secrets — environment of the runner processes, SSH and cloud and Kubernetes and registry credentials, and on hosted runners the referenced secrets scraped from the runner worker's memory — encrypted them with a session key wrapped by an embedded RSA public key, and POSTed the bundle to a look-alike host, falling back to creating a public "tpcp-docs" repo under the caller's token; the real scan ran afterwards, so jobs still passed. The same campaign hit setup-trivy, poisoned Trivy's own release (v0.69.4) and spread to Checkmarx and LiteLLM.

What the fixture keeps and changes: entrypoint.sh follows Socket's and Snyk's description of the injected code: the collect loop over the runner processes, the grep for env/ssh material, the openssl session-key + RSA-OAEP wrap, the curl POST that checks the HTTP code, and the tpcp-docs GitHub fallback — ending in the "## TeamPCP Cloud stealer" line the harvester carried. The runner-worker memory scrape is named and gated as in the original but is NOT reproduced as working code (a comment stands where the /proc/<pid>/mem extractor was). The exfiltration host and the GitHub API host are defanged (".invalid"), the embedded key is a freshly generated throwaway, and the commit shape (unsigned, one file, an old date on a new parent) is what the scanner is meant to notice.

Public analyses it is built from:

- <https://socket.dev/blog/trivy-under-attack-again-github-actions-compromise>
- <https://github.com/aquasecurity/trivy/security/advisories/GHSA-69fq-xp46-6x23>
- <https://www.wiz.io/blog/teampcp-attack-kics-github-action>
- <https://www.stepsecurity.io/blog/trivy-compromised-a-second-time---malicious-v0-69-4-release>
- <https://kudelskisecurity.com/research/investigating-two-variants-of-the-trivy-supply-chain-compromise>

### `litellm-1.82.8`

**litellm 1.82.8 (PyPI): .pth file runs a credential stealer at every interpreter start**

| | |
|---|---|
| Published | 2026-03-24 (campaign `teampcp-trivy-2026`) |
| Served as | Python wheel on the `pip` upstream |
| Malicious release | `litellm` 1.82.8 |
| Control | `litellm` 1.82.6 (the last clean release; it must be served) |
| Techniques | `account-takeover`, `pth-startup-execution`, `persistence-systemd`, `credential-theft`, `c2-poller` |
| Indicators | `litellm_init`, `sysmon.py`, `pglog` |

What the real attack did: On 2026-03-24 the TeamPCP actor published litellm 1.82.7 and 1.82.8 to PyPI from the hijacked maintainer account (the project's own CI had run the poisoned Trivy v0.69.4). 1.82.7 hid the payload in proxy_server.py, run on import; 1.82.8 added litellm_init.pth, a one-line file at the site-packages root that Python's site module executes at every interpreter start — pip included — so the stealer ran even when litellm was never imported. It collected environment variables, SSH keys, cloud and Kubernetes credentials and .env files, encrypted them with a session key wrapped by an embedded RSA key, exfiltrated the bundle, and installed a ~/.config systemd user poller (sysmon.py) that fetched and ran further payloads from a C2. A bug — each child reprocessed the .pth and forked again — is what got it noticed. The Docker image was not affected.

What the fixture keeps and changes: litellm_init.pth is the single import line a .pth runs at startup, launching _bootstrap.py detached. _bootstrap.py collects the environment and credential files, encrypts them with openssl (session key + RSA-OAEP wrap, embedded throwaway key), POSTs the bundle to a defanged host, and writes a systemd user unit plus sysmon.py — the 300s-then-3000s poller that downloads a URL to /tmp/pglog and runs it, skipping youtube.com, recording the last URL in /tmp/.pg_state — all matching Kudelski's and StepSecurity's description. Every endpoint (exfil host, C2) is defanged (".invalid"), and the payload is readable rather than the original's double-base64 blob. The rest of litellm is a small stand-in for the real library.

Public analyses it is built from:

- <https://docs.litellm.ai/blog/security-update-march-2026>
- <https://labs.boostsecurity.io/articles/teampcp-litellm-supply-chain-compromise/>
- <https://www.truesec.com/hub/blog/malicious-pypi-package-litellm-supply-chain-compromise>
- <https://futuresearch.ai/blog/litellm-pypi-supply-chain-attack/>
- <https://kudelskisecurity.com/research/investigating-two-variants-of-the-trivy-supply-chain-compromise>

### `telnyx-4.87.2`

**telnyx 4.87.2 (PyPI): import-time loader takes its second stage out of the audio frames of a WAV file**

| | |
|---|---|
| Published | 2026-03-27 (campaign `teampcp-trivy-2026`) |
| Served as | Python wheel on the `pip` upstream |
| Malicious release | `telnyx` 4.87.2 |
| Control | `telnyx` 4.87.0 (the last clean release; it must be served) |
| Techniques | `stolen-publishing-token`, `import-time-execution`, `audio-steganography`, `base64-xor-decoding`, `fileless-execution`, `credential-theft`, `rsa-aes-exfiltration`, `startup-folder-persistence` |
| Indicators | `FetchAudio`, `bXNidWlsZC5leGU=` |

What the real attack did: On 2026-03-27 the TeamPCP actor published telnyx 4.87.1 (03:51 UTC) and 4.87.2 (04:07 UTC per Endor Labs) to PyPI, the official Python SDK of the Telnyx telephony platform, using a stolen publishing token: neither release has a commit, tag or GitHub release, the project used no Trusted Publisher, and how the token leaked is not established (Endor Labs suspects the litellm compromise three days earlier). PyPI quarantined both by 10:13 UTC (Telnyx, GHSA-955r-262c-33jc; Phoenix Security says about 07:00, reports differ). Only telnyx/_client.py changed, and nothing runs at install time: importing telnyx calls setup() (Windows) and FetchAudio() (Linux and macOS). 4.87.1 spelled the first call Setup(), a NameError that stopped it, so 4.87.2 is the complete version. Each path downloads a "WAV" from a raw IP over plain HTTP on port 8080 (ringtone.wav or hangup.wav, Mozilla/5.0 User-Agent), reads its frames with the wave module, base64-decodes them and XORs everything after the first 8 bytes with those 8 bytes. On Linux and macOS the result, a 332-line credential harvester, is piped to a fresh python process; its output is AES-256-CBC encrypted, the key wrapped with the same RSA-4096 key as in litellm, and POSTed as tpcp.tar.gz with an X-Filename header. Endor Labs lists SSH keys, cloud and Kubernetes credentials, .env files and secrets-manager contents as the loot, Socket calls it only a data harvester, and reports differ on Linux persistence (Endor Labs and Phoenix Security: an audiomon systemd user service; Socket: none). On Windows the decoded bytes are a PE dropped as msbuild.exe in the Startup folder, with a hidden msbuild.exe.lock allowing one download per 12 hours. Endor Labs found it by diffing the wheels against the v4.87.0 tag and reported it in GitHub issue #235.

What the fixture keeps and changes: telnyx/_client.py follows the descriptions of Socket, SafeDep, StepSecurity, Endor Labs and Phoenix Security: extra standard-library imports at the top (os twice), a _d() base64 string helper, the _p blob between __all__ and the class, setup() and FetchAudio() after the class, and the two bare calls at the bottom in that order. setup() returns unless on Windows and passes APPDATA, the Startup path, msbuild.exe and the URL through _d(); it keeps the 43200 second lock (attrib +h), the msbuild.exe.tmp staging file and creationflags 0x08000000. FetchAudio() returns on Windows and otherwise starts _p in a detached interpreter (start_new_session) with its output discarded. The frame extraction is the one the analyses quote (readframes, b64decode, an 8-byte key). _p is not the original 4,428-character blob but a short stage written from the descriptions: it fetches ringtone.wav, decodes it, pipes the result to "python -", then encrypts and POSTs what comes back, with the truncated throwaway RSA key of the litellm sample. The harvester and the PE were never in the wheel (they sit in the WAV on the C2) and are not reproduced. The C2 is the documentation address 203.0.113.7:8080, a raw IP over HTTP as in the original. 4.87.1's Setup() typo is not modelled, and as in the real wheels only _client.py differs from 4.87.0 (_version.py still says 4.87.0). The rest of the SDK is a tiny stand-in for the generated client (the real _client.py has about 7,800 lines). The second indicator is the base64 of "msbuild.exe", which the loader decodes at run time.

Public analyses it is built from:

- <https://telnyx.com/resources/telnyx-python-sdk-supply-chain-security-notice-march-2026>
- <https://osv.dev/vulnerability/GHSA-955r-262c-33jc>
- <https://socket.dev/blog/telnyx-python-sdk-compromised>
- <https://endorlabs.com/learn/teampcp-strikes-again-telnyx-compromised-three-days-after-litellm>
- <https://safedep.io/malicious-telnyx-pypi-compromise/>
- <https://www.stepsecurity.io/blog/teampcp-plants-wav-steganography-credential-stealer-in-telnyx-pypi-package>
- <https://www.trendmicro.com/en/research/26/c/teampcp-telnyx-attack-marks-a-shift-in-tactics.html>
- <https://phoenix.security/teampcp-telnyx-pypi-supply-chain-wav-steganography-windows-persistence/>

<!-- END GENERATED: corpus -->

## How a run works

```
 corpus (txtar)  ──►  artifacts built the way each ecosystem ships them
                          npm tarball · wheel · sdist · .vsix · Git history
                                   │
 stub registries (loopback) ◄──────┘   one per upstream type, serving the metadata a client
                                       reads and the artifact; Git commits live in a local repository
        ▲
        │ upstream fetch (egress guard: loopback only)
 pullthrough (the real binary, the LLM scans the only content gate)
        ▲                     │ Messages API
        │ client requests     ▼
 the suite             model route ── API key ──► the Anthropic API
                                  └── token ───► loopback Claude Code bridge ──► claude -p
```

1. The suite builds each sample's two variants — the malicious release and the
   last clean one — into the artifact format of its ecosystem and serves them from
   stub registries on loopback.
2. It writes a proxy configuration (`failMode: closed`, `action: block`, every
   other content gate off, egress limited to loopback), starts the real binary and
   waits for `/readyz`.
3. It makes the requests the ecosystem's client makes (an npm packument and
   tarball, a PyPI simple page and wheel, an Open VSX extension download, …). Each
   request waits for the verdict, so the pulls run side by side.
4. It reads the verdicts back through the admin API and judges each result; a
   second pull of every refused artifact checks that the block holds and — on the
   Claude Code route, where the bridge counts the package scan's completions —
   that the cached verdict answers it without a model call.
5. For commit samples the proxy's commit watcher mirrors a local repository and
   scans its history; the suite reads the verdicts of the attacker's commit and of
   the control commit.
6. It writes `live-llm-scan-report.{md,json}` to `PT_TEST_REPORT_DIR`: per sample the
   pull, the verdict, the model's reasons and the evidence the proxy
   **verified** against the unpacked files, and a table of every model call (model,
   tokens, time, list-price equivalent cost).

A malicious variant **passes** when it is refused *as malicious*. Refused because
the model gave no verdict (`llm-package-unscanned`, e.g. the provider declined to
read it) is *blocked* — only `failMode: closed` stopped it — but it is not a
detection: it fails, unless the sample lists the model under `modelsMayRefuse`, in
which case it passes with a note, and the report says so (see [what the runs
found](#what-the-first-live-runs-found)). A malicious commit passes when the commit
scan judged it malicious; if only the deep stage was declined by the provider's
safeguards it passes with a note, any other failure of the scan does not.

## The model route and the credential

The suite takes the first credential it finds:

| Credential | Route | Package scan mode |
|---|---|---|
| `ANTHROPIC_API_KEY` | The gates call the Anthropic API directly, as in a deployment. | the default (`auto`: tools, with the model reading files through three read-only tools) |
| `CLAUDE_CODE_OAUTH_TOKEN` (`claude setup-token`) | Through the **Claude Code bridge** below. | `bundle` (the package material in the first and only message) |
| `PT_LIVESCAN_CLAUDE_CREDENTIALS=<path to a Claude Code .credentials.json>` | Like the token above, using the OAuth access token of a Claude Code login on the same machine. It is read, never refreshed (a refresh would rotate the login of the session that owns the file), and the run refuses to start when it expires within three times the call timeout. | `bundle` |

### The Claude Code bridge

A Claude subscription token is issued for Claude Code and Claude.ai; Anthropic's
[legal and compliance page](https://code.claude.com/docs/en/legal-and-compliance)
does not allow using such a token in any other tool or service. So **the proxy
never holds one.** The
suite starts a loopback server that speaks the Messages API and answers each
request by running Claude Code itself, non-interactively:

```
claude -p --output-format stream-json --verbose --model <the proxy's model>
       --system-prompt-file <the proxy's system prompt> --tools ""
       --strict-mcp-config --mcp-config '{"mcpServers":{}}'
       --disable-slash-commands --safe-mode --no-session-persistence
```

with the proxy's user message on standard input. The token is used by Claude Code
and by nothing else; the model is given the proxy's system prompt and user message,
in the Claude Code wrapper (which adds a preface of its own, so the answers are the
same kind as the API's but not guaranteed identical). Package content is hostile
input, so every call runs

- with **no tools at all** and no MCP servers, slash commands, skills, hooks,
  `CLAUDE.md` or plugins of the user's;
- in a fresh `HOME`, configuration directory and (empty) working directory per call,
  with an environment of `PATH`, the locale and the credential — nothing else of
  the test process's — and with Claude Code's **@-mention attachments switched
  off** (`CLAUDE_CODE_DISABLE_ATTACHMENTS`, `CLAUDE_CODE_DISABLE_FILE_MENTIONS`):
  left on, the CLI reads a file named by `@/path` in the user message — package
  content — and shows it to the model, tools or no tools. Every live run proves it
  for the CLI in use with a canary file (see [what the runs
  taught](#what-the-runs-taught));
- and **checked, not assumed**: the CLI's own `init` event lists the session's tools
  and MCP servers, and a call whose session had any — or whose init event is
  missing, doubled or lacks the lists — is answered with an error and its text
  discarded. The report's call table has a column for it.
- Whatever the CLI or the model says is scrubbed of the credential before it is cut,
  kept or sent on; the proxy and the report never hold it.

What the bridge cannot do is offer the proxy's own tools (`list_files`,
`read_file`, `grep`): Claude Code runs its own agent loop and cannot hand a tool
call back. A tool request is answered with `400`, and the suite configures
`mode: bundle`. Tool mode is exercised against the API when an API key exists.

The bridge reports what the API reports. In particular a provider **refusal**
(`stop_reason: refusal`, which Claude Code renders as an error result) is passed
on as `200`, no content, `stop_reason: refusal` with its policy category — so the
gate sees a terminal `provider-refusal`, not a transport failure that would be
retried.

## Running it

```sh
# The machinery, with a fake model and no credential (free; ~10 s plus building the proxy). It also runs
# in CI, in the `integration` job, on every push.
make test-live-llm-scan-hermetic

# The whole corpus against a real model.
ANTHROPIC_API_KEY=… make test-live-llm-scan
CLAUDE_CODE_OAUTH_TOKEN=… make test-live-llm-scan                      # needs `claude` on PATH
PT_LIVESCAN_CLAUDE_CREDENTIALS=$CLAUDE_CONFIG_DIR/.credentials.json make test-live-llm-scan

# A selection.
make test-live-llm-scan LIVESCAN_SAMPLES="litellm-1.82.8 trivy-action-teampcp"
```

Always set `PT_TEST_REPORT_DIR` to a directory of your own for the report
(otherwise it lands in the run's work directory, kept only on failure).

| Variable | Meaning |
|---|---|
| `ANTHROPIC_API_KEY`, `CLAUDE_CODE_OAUTH_TOKEN`, `PT_LIVESCAN_CLAUDE_CREDENTIALS` | The credential, in that order of preference. |
| `PT_LIVESCAN_SAMPLES` | Space- or comma-separated sample ids; empty is the whole corpus. |
| `PT_LIVESCAN_MODEL` | The package scan's model (default: the proxy's, `claude-opus-4-8`). `PT_LIVESCAN_TRIAGE_MODEL` / `PT_LIVESCAN_DEEP_MODEL` the commit scan's. |
| `PT_LIVESCAN_EFFORT` | Claude Code's `--effort` on the bridge route. |
| `PT_LIVESCAN_MODE` | The package scan's mode against the API (`auto`, `tools`, `bundle`). |
| `PT_LIVESCAN_TIMEOUT` | The time allowed for one scan: the package scan's `timeout`, the commit scan's, one Claude Code call and the clients' timeouts (the wait for the commit verdicts is three times it); default 10 minutes. |
| `PT_LIVESCAN_PARALLEL` | Pulls in flight (default 3). |
| `PT_LIVESCAN_PROXY_BIN` | A prebuilt proxy binary (default: built by the test). |
| `PT_LIVESCAN_WORKDIR` | Keep the run's files (configuration, proxy log, verdict stores, commit repositories) here. It must be an empty directory: the files of an earlier run would answer this one without a model call. |
| `PT_LIVESCAN_CLAUDE_BIN` | The `claude` executable for the bridge route. |

## CI

**Always on.** The fixtures' invariants (`TestCorpus*`: every URL a fixture names
is unresolvable, the artifacts build deterministically, the sources are cited),
the bridge's tests (isolation, error mapping, the proxy's own provider reading its
answers) and the hermetic suite run in the ordinary test and `integration` jobs
on every push and pull request.

**Switched off.** `.github/workflows/live-llm-scan.yml` runs the real thing. Its
job runs only when the repository **variable** `LIVE_LLM_SCAN_ENABLED` is `true`;
until then every trigger — a push touching the scanners or the corpus, the weekly
schedule, a manual dispatch — ends in a skipped job, and no secret is read.

### Switching it on

1. Create a credential **for this purpose** — not a developer's login:
   - a subscription token: run `claude setup-token` and store its output as the
     repository secret `CLAUDE_CODE_OAUTH_TOKEN`; or
   - an API key from a workspace with a spend limit, as `ANTHROPIC_API_KEY`
     (the API key wins when both exist, and runs the gates in tool mode, as a
     deployment does).

   ```sh
   gh secret set CLAUDE_CODE_OAUTH_TOKEN --repo blechschmidt/pullthrough-security
   ```
2. Consider putting the secret in an *environment* (`live-llm-scan`) with required
   reviewers and a `main`-only deployment-branch rule, and adding `environment:
   live-llm-scan` to the job: then every run needs an approval. The workflow
   itself already runs only on `main` (`if: … github.ref == 'refs/heads/main'`), so
   a branch that carries edited tests cannot be dispatched with the secret.
3. Switch the gate on:

   ```sh
   gh variable set LIVE_LLM_SCAN_ENABLED --body true --repo blechschmidt/pullthrough-security
   gh workflow run live-llm-scan.yml --repo blechschmidt/pullthrough-security   # a first run by hand
   ```

Turning it off again is deleting the variable. The workflow never runs for pull
requests: they would hand the credential to whoever can edit the workflow or the
tests. A run takes a few minutes (2 on the first runs); the report is the job summary and the
`live-llm-scan-report` artifact, and a failing run also uploads the workspace
(proxy log and configuration, verdict stores; no credential is in them).

## What the first live runs found

All runs were made on 13 November 2026 with the Claude Code login of the machine
(Claude Code 2.1.319, bundle mode). The proxy's default models are
`claude-opus-4-8` for the package scan and the commit scan's deep stage and
`claude-haiku-4-5` for the commit scan's triage. The full report of each run is in
the CI artifact format (`live-llm-scan-report.{md,json}`).

### The corpus, against the proxy's default models

Every malicious release was refused on the model's malicious verdict, every
control was served, every attacker commit was flagged and every control commit
was not (2 min 0 s, including the isolation canary; the Trivy commit's deep stage was
declined by the provider and its triage verdict held, see finding 4).

| Sample | Control | Malicious release |
|---|---|---|
| `ctx-0.2.6` | 200; verdict benign 0.95 | 403 `llm-package-malicious`; verdict malicious 1.00 |
| `flatmap-stream-0.1.1` | 200; verdict benign 0.95 | 403 `llm-package-malicious`; verdict malicious 1.00 |
| `glassworm-codejoy-1.8.3` | 200; verdict benign 0.95 | 403 `llm-package-malicious`; verdict malicious 0.98 |
| `litellm-1.82.8` | 200; verdict benign 0.78 | 403 `llm-package-malicious`; verdict malicious 0.99 |
| `nx-21.5.0` | 200; verdict benign 0.95 | 403 `llm-package-malicious`; verdict malicious 0.99 |
| `telnyx-4.87.2` | 200; verdict benign 0.95 | 403 `llm-package-malicious`; verdict malicious 1.00 |
| `ua-parser-js-0.7.29` | 200; verdict benign 0.96 | 403 `llm-package-malicious`; verdict malicious 0.99 |
| `ultralytics-8.3.41` | 200; verdict benign 0.95 | 403 `llm-package-malicious`; verdict malicious 1.00 |

| Commit sample | Control commit | Attacker commit | Deep stage |
|---|---|---|---|
| `php-src-zerodium` | malicious=False, risk 0 | malicious=True, risk 99 | ok |
| `tj-actions-changed-files` | malicious=False, risk 1 | malicious=True, risk 99 | ok |
| `trivy-action-teampcp` | malicious=False, risk 0 | malicious=True, risk 98 | refused |

30 model calls, 157517 input and 19512 output tokens, list-price equivalent USD 1.23.

### The same corpus, with `claude-sonnet-5-5` as the package model and the commit scan's deep model

Triage stayed `claude-haiku-4-5`. Same outcome (1 min 46 s). One control, `litellm`
1.82.6, drew a *suspicious* verdict (0.50–0.55 in the two runs of it) — served,
because under `action: block` a suspicious verdict only annotates, but the closest
to a false positive of any run; the report notes it.

| Sample | Control | Malicious release |
|---|---|---|
| `ctx-0.2.6` | 200; verdict benign 0.93 | 403 `llm-package-malicious`; verdict malicious 0.93 |
| `flatmap-stream-0.1.1` | 200; verdict benign 0.90 | 403 `llm-package-malicious`; verdict malicious 0.98 |
| `glassworm-codejoy-1.8.3` | 200; verdict benign 0.93 | 403 `llm-package-malicious`; verdict malicious 0.97 |
| `litellm-1.82.8` | 200; verdict suspicious 0.50 | 403 `llm-package-malicious`; verdict malicious 0.99 |
| `nx-21.5.0` | 200; verdict benign 0.90 | 403 `llm-package-malicious`; verdict malicious 0.98 |
| `telnyx-4.87.2` | 200; verdict benign 0.90 | 403 `llm-package-malicious`; verdict malicious 0.98 |
| `ua-parser-js-0.7.29` | 200; verdict benign 0.93 | 403 `llm-package-malicious`; verdict malicious 0.99 |
| `ultralytics-8.3.41` | 200; verdict benign 0.90 | 403 `llm-package-malicious`; verdict malicious 0.97 |

| Commit sample | Control commit | Attacker commit | Deep stage |
|---|---|---|---|
| `php-src-zerodium` | malicious=False, risk 0 | malicious=True, risk 98 | ok |
| `tj-actions-changed-files` | malicious=False, risk 2 | malicious=True, risk 97 | ok |
| `trivy-action-teampcp` | malicious=False, risk 5 | malicious=True, risk 100 | ok |

29 model calls, 148596 input and 17894 output tokens, list-price equivalent USD 0.50.

### What the runs taught

Getting to those two green runs took six findings. Five are defects the suite or
its review exposed, now fixed; one is a property of the providers' safeguards that a
deployment has to plan for.

1. **A model can leave the confidence out of a correct verdict.** In an early run
   Opus 4.8 answered a malicious package with `{"verdict": "malicious", "reasons":
   […], "evidence": […]}` and no `confidence`. The verdict contract required one,
   so the answer was *malformed* — an unscanned package, which `failMode: open`
   serves. `ParseVerdict` now reads a `malicious` verdict without a confidence as an
   unqualified one (confidence 1, stored as `confidenceUnstated`), and holds it to
   `failMode: closed` where the rejection it replaces refused, so the reading is
   never weaker than before. A `suspicious` or `benign` verdict without the number
   stays malformed ([llm-package-scan.md](llm-package-scan.md#verdict-schema)).
2. **Raw hidden characters made a provider decline to read a package — GlassWorm
   was not detected.** The GlassWorm extension hides its loader in a run of about
   1,160 variation selectors. Opus 4.8 answered the package with
   `stop_reason: refusal` three times out of three (category `bio`: the
   provider's classifier, firing on the run, not on anything biological), so the
   gate had no verdict: `failMode: closed` refused the package without one
   (`llm-package-unscanned`, `provider-refusal`), and under the default
   `failMode: open` it would have been **served**. `claude-sonnet-5-5` read the
   same package and judged it malicious. The scanner already promised to write
   invisible characters out, but its list lacked the variation selectors, tag and
   private-use characters this attack is built from. Now a run of eight or more
   hidden code points is shown as one marker —
   `<hidden run of 1163 code points, U+FE0A..U+E016D>` — which tells the model what
   it is looking at, keeps the raw characters from the provider and no longer cuts
   the loader's tail off behind the run. With the marker Opus 4.8 judges the
   package malicious (five runs out of five). `PromptVersion` is now 3, so
   verdicts given under the old rendering are recomputed.
3. **The commit scan could not see a change in a file marked `-diff`.**
   tj-actions/changed-files was compromised through `dist/index.js`, which its
   `.gitattributes` marks `dist/** -diff`. With attributes honoured — a bare
   mirror does since git 2.41 — `git show` prints "Binary files differ" for it,
   and the model is told *binary file; contents omitted*: the scanner saw nothing
   of the attack. The watcher now reads diffs with attributes switched off
   (`attr.tree` pointing at the empty tree), so git's own content test decides
   what is binary ([commit-watch.md](commit-watch.md)). The sample keeps the real
   `.gitattributes` line, and fails without the fix.
4. **A provider's safeguards can decline the deep stage of a commit scan.** Opus
   4.8 answered the deep analysis of the Trivy/TeamPCP stealer commit with
   `stop_reason: refusal` (category `cyber`) in six of seven attempts of the
   default configuration; `claude-sonnet-5-5` did not refuse it (two attempts out of
   two). Nothing was lost: the triage model had already flagged the commit
   (malicious, risk 99–100), and the commit pipeline keeps the triage verdict when
   the deep stage cannot answer and records the degradation (`deep analysis
   failed: … refused by safety system`). The suite counts that as a pass **with a
   note**, and the report's *Deep stage* column says `refused`.

   A package has no cheaper first stage: a refusal there is `provider-refusal`,
   an *unscanned* artifact, never a benign one — `failMode: closed` refuses it,
   `failMode: open` serves it with the `llmpkgscan/scan-incomplete` finding, and a
   policy rule can refuse content-caused unscanned artifacts under either mode
   ([why an artifact goes unscanned](llm-package-scan.md#why-an-artifact-goes-unscanned)).
   A deployment that scans real malware should expect refusals, choose its fail
   mode and model with them in mind, and watch `pullthrough_llmpkgscan_unscanned_total{code="provider-refusal"}`.
   Anthropic's [Cyber Verification
   Program](https://support.claude.com/en/articles/14604842-real-time-cyber-safeguards-on-claude)
   (Defense Access: malware analysis, vulnerability triage) is the provider's
   route to adjusted safeguards for security work; it is for the verifying
   organisation's own use. A sample that a model is known to decline can be
   listed under `modelsMayRefuse` in its header: with that model a package
   blocked without a verdict passes with a note; with any other it fails, since a
   new refusal is a regression.
5. **Claude Code renders a refusal as an error.** Its result event says
   `is_error: true`, with the provider's explanation as text; only the stop reason
   identifies it. The bridge first reported that as a `502`, which the commit
   scanner retried four times per attempt; it now passes it on as the API sends
   it, a terminal refusal (`TestBridgeRefusalIsTerminalForTheProxysProvider`).
6. **Claude Code reads files named in the prompt.** A review of the bridge found
   (in the CLI's own strings) that Claude Code expands `@path` mentions in the
   prompt — attaching the file before the model answers, `--tools ""` or not. The
   user message is package content, so a package could name the credentials file of
   whoever runs the suite and have the model quote it into its reasons. A canary
   confirmed it on the real CLI: an `@`-mentioned file came back in the answer.
   The bridge now switches the feature off in the child's environment, and every
   live run starts with the same canary (a random file, an `@` mention, an
   assertion that it is not echoed), so a CLI version that ignored the switches
   would fail the run.

The suite itself was fixed on the way: a run of commit samples alone had no
upstream registry, so `/readyz` never turned green (it now gets an idle one), and
the commit repositories were named after the sample id — which put an attack's
name in the prompt of every commit scan (they are now named like the real
repositories, `owner/name.git`).

## How the corpus stays inert

The samples are reconstructions, not the malware: this repository is public and
a scanner's test data must not be a payload.

- Each fixture is a **txtar** archive, so its tree is not installable or
  runnable as it sits in the repository; the suite builds the artifacts in
  memory.
- **Every network endpoint of the malicious code is unresolvable**: a `.invalid`
  host (RFC 6761) or an address from the documentation blocks (RFC 5737) — also
  the legitimate services the attackers abused (GitHub's API, webhook services,
  registries, blockchain endpoints). `TestCorpusIsDefanged` checks every URL and
  every IP of every file, including text hidden in base64.
- **No payload blobs**: where an original shipped megabytes of bundled code or an
  encrypted stage, the fixture keeps the part a reviewer reads — the loader, the
  trigger, the exfiltration routine — and a stand-in for the rest. Wallet
  addresses, keys and tokens are obviously invalid placeholders; destructive code
  is a stub behind the same call site.
- The `reconstruction` note of every sample says what it keeps and what it
  changes; the sources it was built from are listed.

## Adding a sample

1. Research the attack: at least three independent public analyses, and what the
   real release did, when, and how it was found.
2. Write `internal/e2e/livescan/testdata/corpus/<id>.txtar`: the YAML header
   (see the existing samples), then `shared/`, `benign/` and `malicious/` files.
   The malicious tree keeps what a reviewer saw and is inert (endpoints defanged,
   no payload); the benign variant is the clean predecessor, a control the
   scanner must not flag. Do not put words like "malicious" or "payload" into
   the files — the header is the place for explanations.
3. Choose 2–4 `indicators`: strings that occur only in the malicious variant (the
   hermetic suite's stand-in model keys on them).
4. `go test ./internal/e2e/livescan -run TestDocsCorpusSectionIsCurrent -update`
   regenerates the section above; `make test-live-llm-scan-hermetic` and
   `make test-live-llm-scan LIVESCAN_SAMPLES=<id>` run it.
