# Reachability-aware vulnerability prioritization

The vulnerability-scanning gate ([SBOM/OSV](configuration.md),
`internal/vulnscan`) resolves every cached artifact's components against a
vulnerability database and admits, warns, or blocks on the findings'
severity/CVSS. Many of those findings sit in code the artifact never reaches: a
transitive module the package does not import, or a declared dependency no
source file references. **Reachability analysis** statically determines whether
each vulnerable package is actually imported on a reachable path from the
consuming artifact, annotates every finding with a `reachable` / `unreachable` /
`unknown` attribute, and lets policy **downgrade** or **suppress** the findings
that are provably out of reach — without weakening the gate against reachable
issues.

Where [VEX](vex.md) captures an *operator/vendor* assertion of
non-exploitability, reachability is derived automatically from the artifact's own
source. The two compose: reachability runs first, and an authoritative VEX
statement always overrides the heuristic reachability verdict.

## Verdicts

| Verdict | Meaning |
|---------|---------|
| **reachable** | The vulnerable module/package is imported by the artifact's own source (or the finding is on the artifact itself). Definitive. |
| **unreachable** | The artifact's source was fully analyzed and the vulnerable module/package is **not** imported by any of the artifact's packages (a flattened transitive requirement, or a declared-but-unused dependency). |
| **unknown** | The analysis was incomplete or ambiguous — the conservative default. |

The analysis is **sound in one direction and fully deterministic**: a finding is
only ever marked `unreachable` when the source was located and parsed *and* the
vulnerable coordinate is provably not imported. Every ambiguous case — no source
available (metadata-only pull), an unsupported ecosystem, an unparseable archive,
a dynamic `require()`/`import()` the analysis cannot resolve, or a dependency
declared *direct* whose import could not be confirmed — defaults to `unknown` and
gates exactly as it would without reachability analysis.

> **Scope.** Reachability is computed at **import granularity from the consuming
> artifact's first-party code**. An `unreachable` finding means the artifact's
> own packages do not import the vulnerable module; it may still be exploitable
> through a *direct dependency's* code, which this analysis does not inspect.
> That is why the default action only annotates — operators opt in to
> downgrade/suppress.

## Supported ecosystems

| Ecosystem | How reachability is determined |
|-----------|-------------------------------|
| **Go** (`go`) | `go.mod` require directives supply the direct/indirect classification (the `// indirect` marker, maintained by `go mod tidy`, authoritatively records a module no package imports directly); every `.go` file in the module zip is parsed (imports-only) for its import paths. A module is **reachable** when a source file imports it (by exact path or sub-package prefix), **unreachable** when it is an indirect requirement no source imports, and **unknown** when it is a direct requirement whose import could not be observed. |
| **npm** (`npm`) | `package.json` supplies the declared dependency set (runtime/optional/peer); every `.js`/`.mjs`/`.cjs`/`.ts`/`.tsx`/`.jsx`/`.cts`/`.mts` source file is scanned for static `require()` / `import` / `import()` / re-export specifiers. A package is **reachable** when a source file imports it, **unreachable** when it is declared but no source imports it, and **unknown** when a dynamic (non-literal) `require()`/`import()` anywhere in the sources prevents a sound conclusion. |
| **Python** (`pip`) | The wheel (`*.dist-info/METADATA`) or sdist (`PKG-INFO`, `requirements.txt`, `setup.py` `install_requires`, `pyproject.toml` dependencies, egg-info `requires.txt`) supplies the declared `Requires-Dist` set, PEP 503-normalized; every `.py`/`.pyi` file is scanned for `import`/`from … import` statements (top-level module, relative imports skipped), and `top_level.txt`/package directories record the modules the artifact itself provides. A distribution is **reachable** when a source file imports its module (matched by the advisory's declared import path when present, else the PEP 503 name with separators mapped to `_`), **unreachable** when it is a declared dependency no source imports, and **unknown** when a dynamic `importlib.import_module`/`__import__` with a non-literal argument prevents a sound conclusion or no source was analyzed. |
| **Java / Maven** (`maven`) | The embedded `pom.xml` (`META-INF/maven/**/pom.xml`) supplies the declared `groupId:artifactId` dependency set; every `.java` source file is parsed for its `package`/`import` declarations and `.class` entries record the packages the jar itself provides. A coordinate is **reachable** when a source file imports a class under the advisory's declared affected package (when present) or the dependency's `groupId` namespace, **unreachable** when it is a declared dependency whose packages no source imports, and **unknown** when reflective loading (`Class.forName`/`loadClass` with a non-literal argument) prevents a sound conclusion or only compiled bytecode (no source) was available. |

All other ecosystems annotate every finding `unknown` (and therefore gate
unchanged). Background CVE re-scans (which re-resolve from the stored SBOM
without re-reading artifact content) also annotate `unknown` — reachability is
computed on the serve-path scan where the artifact bytes are available.

## Where the verdict flows

- **Per-finding attribute** — `reachability` on each `Vulnerability`, visible in
  the scan report and the admin SBOM/vuln surfaces.
- **Risk-scoring engine** (`internal/riskscore`) — the vulnerability signal's
  explainable detail surfaces the reachable/unreachable/unknown counts; because a
  downgrade/suppress lowers the scan counts before scoring, the composite score
  already reflects it.
- **SARIF export** (`internal/findings`) — every vulnerability result carries a
  `reachability` property; a policy-suppressed unreachable finding is emitted as
  a SARIF **suppression** (level `note`) so CI does not fail on it.
- **Policy-as-code** (`internal/policyengine`) — the `vuln` document exposes
  `reachabilityEnabled`, `reachableCount`, `unreachableCount`,
  `reachUnknownCount`, `reachSuppressed`, `reachDowngraded`, and a per-finding
  `reachability`, so a rule can require (for example) that a blocking critical be
  reachable.

## Configuration

```yaml
vulnerabilities:
  enabled: true
  failSeverity: high
  action: block
  reachability:
    enabled: true            # off by default
    unreachableAction: downgrade  # annotate | downgrade | suppress
```

| Setting | Type | Default | Meaning |
|---------|------|---------|---------|
| `vulnerabilities.reachability.enabled` | bool | `false` | Turn on reachability analysis and annotation. When off, findings carry no reachability attribute and gate exactly as before. |
| `vulnerabilities.reachability.unreachableAction` | string | `annotate` | How a finding **proven unreachable** is treated. Reachable and unknown findings are never altered. |

`unreachableAction` values:

- **`annotate`** (default) — record the `reachability` attribute only; the
  finding gates at its full severity. Safe to enable everywhere: it adds the
  signal without changing any admission decision.
- **`downgrade`** — lower an unreachable finding's qualitative severity by one
  bucket (`critical`→`high`→`medium`→`low`→`none`) for gating and the report
  counts. CVSS-based gating (`failCvss`) is unaffected.
- **`suppress`** — exclude an unreachable finding from gating entirely (it is
  retained in the report and emitted as a SARIF suppression for transparency,
  like a VEX `not_affected` adjudication).

Because the analysis defaults every uncertain case to `unknown`, enabling
`downgrade`/`suppress` can only relax the gate for findings that are *provably*
unreachable from the artifact's own code; nothing ambiguous is ever cleared.
