# Configuration reference (generated)

<!-- GENERATED FILE — DO NOT EDIT.
     Regenerate with `make config-reference-gen`.
     Source of truth: internal/config (struct tags + Default()). -->

This reference is generated from the configuration struct definitions and
their compiled-in defaults, so it always matches the running code. Every
setting is shown with its YAML path, type, and default value. Everything is
off by default: a minimal config (a `server` address, a `cache`, and one or
more `upstreams`) runs the proxy as a plain caching mirror.

For prose, examples, and value-substitution rules (`${ENV}`, `enc:v1:`,
`PTS_*`), see [configuration.md](configuration.md).

Validate a candidate config before rollout with `pullthrough verify-config
-config <file>` or `ptctl config validate <file>`.

## `server`

| Setting | Type | Default |
|---------|------|---------|
| `server.httpAddr` | string | `:8080` |
| `server.publicUrl` | string | — |
| `server.sshAddr` | string | — |
| `server.readTimeout` | duration | 30s |
| `server.writeTimeout` | duration | 5m0s |
| `server.shutdownTimeout` | duration | 30s |
| `server.tlsCertFile` | string | — |
| `server.tlsKeyFile` | string | — |
| `server.intercept.enabled` | bool | false |
| `server.intercept.listenAddr` | string | — |
| `server.intercept.caCertFile` | string | — |
| `server.intercept.caKeyFile` | string | — |
| `server.intercept.generateCa` | bool | false |
| `server.intercept.caOrganization` | string | — |
| `server.intercept.caCommonName` | string | — |
| `server.intercept.leafTtl` | duration | 0s |
| `server.intercept.certCacheSize` | int | 0 |
| `server.intercept.hosts` | map[string]string | {} |
| `server.intercept.passthroughUnmatched` | bool | false |
| `server.intercept.allowPlainHttp` | bool | false |
| `server.registry.enabled` | bool | — |
| `server.registry.defaultUpstream` | string | — |

## `logging`

| Setting | Type | Default |
|---------|------|---------|
| `logging.level` | string | `info` |
| `logging.format` | string | `json` |
| `logging.addSource` | bool | false |

## `cache`

| Setting | Type | Default |
|---------|------|---------|
| `cache.backend` | string | `memory` |
| `cache.dir` | string | `/var/lib/pullthrough/cache` |
| `cache.s3.endpoint` | string | — |
| `cache.s3.region` | string | — |
| `cache.s3.bucket` | string | — |
| `cache.s3.prefix` | string | — |
| `cache.s3.accessKeyId` | string | — |
| `cache.s3.secretAccessKey` | string | — |
| `cache.s3.sessionToken` | string | — |
| `cache.s3.usePathStyle` | bool | false |
| `cache.s3.insecureSkipVerify` | bool | false |
| `cache.s3.maxRetries` | int | 0 |
| `cache.s3.spoolDir` | string | — |
| `cache.s3.sharedMode` | bool | — |
| `cache.maxSizeBytes` | int | 0 |
| `cache.ttl` | duration | 0s |
| `cache.sealed` | bool | false |
| `cache.integrity.verifyOnServe` | bool | true |
| `cache.integrity.notifySeverity` | string | `critical` |
| `cache.compression.enabled` | bool | false |
| `cache.compression.codec` | string | `zstd` |
| `cache.compression.level` | int | 3 |
| `cache.compression.minSizeBytes` | int | 256 |
| `cache.compression.dedup` | bool | false |
| `cache.compression.spoolDir` | string | — |
| `cache.encryption.enabled` | bool | false |
| `cache.encryption.keyId` | string | — |
| `cache.encryption.keyRef` | string | — |
| `cache.encryption.keyEncoding` | string | — |
| `cache.encryption.previousKeys[].keyId` | string | — |
| `cache.encryption.previousKeys[].keyRef` | string | — |
| `cache.encryption.previousKeys[].keyEncoding` | string | — |
| `cache.encryption.frameSizeBytes` | int | 0 |
| `cache.tiering.enabled` | bool | false |
| `cache.tiering.cold.backend` | string | — |
| `cache.tiering.cold.dir` | string | — |
| `cache.tiering.cold.s3.endpoint` | string | — |
| `cache.tiering.cold.s3.region` | string | — |
| `cache.tiering.cold.s3.bucket` | string | — |
| `cache.tiering.cold.s3.prefix` | string | — |
| `cache.tiering.cold.s3.accessKeyId` | string | — |
| `cache.tiering.cold.s3.secretAccessKey` | string | — |
| `cache.tiering.cold.s3.sessionToken` | string | — |
| `cache.tiering.cold.s3.usePathStyle` | bool | false |
| `cache.tiering.cold.s3.insecureSkipVerify` | bool | false |
| `cache.tiering.cold.s3.maxRetries` | int | 0 |
| `cache.tiering.cold.s3.spoolDir` | string | — |
| `cache.tiering.cold.s3.sharedMode` | bool | — |
| `cache.tiering.promoteOnRead` | bool | — |
| `cache.tiering.demoteAfterIdle` | duration | 24h0m0s |
| `cache.tiering.hotMaxBytes` | int | 0 |
| `cache.tiering.minAccessesToStayHot` | int | 0 |
| `cache.tiering.sweepInterval` | duration | 10m0s |

## `outbound`

| Setting | Type | Default |
|---------|------|---------|
| `outbound.userAgent` | string | — |
| `outbound.dialTimeout` | duration | 0s |
| `outbound.responseHeaderTimeout` | duration | 0s |
| `outbound.idleConnTimeout` | duration | 0s |
| `outbound.tlsHandshakeTimeout` | duration | 0s |
| `outbound.maxIdleConns` | int | 0 |
| `outbound.maxIdleConnsPerHost` | int | 0 |
| `outbound.maxConnsPerHost` | int | 0 |
| `outbound.keepAlive` | duration | 0s |
| `outbound.expectContinueTimeout` | duration | 0s |
| `outbound.disableKeepAlives` | bool | false |
| `outbound.disableHTTP2` | bool | false |
| `outbound.tls.caCertFile` | string | — |
| `outbound.tls.insecureSkipVerify` | bool | false |
| `outbound.tls.minVersion` | string | — |
| `outbound.tls.pins` | []string | [] |
| `outbound.tls.pinReportOnly` | bool | false |

## `egress`

| Setting | Type | Default |
|---------|------|---------|
| `egress.enabled` | bool | true |
| `egress.httpsOnly` | bool | true |
| `egress.allowedSchemes` | []string | [] |
| `egress.allowlist` | []string | [] |
| `egress.blockPrivateNetworks` | bool | true |
| `egress.allowedDestinationCidrs` | []string | [] |
| `egress.followRedirects` | bool | true |
| `egress.maxRedirects` | int | 5 |
| `egress.tenants.<string>.allowlist` | []string | — |
| `egress.tenants.<string>.httpsOnly` | bool | — |

## `upstreams`

| Setting | Type | Default |
|---------|------|---------|
| `upstreams.<string>.type` | string | — |
| `upstreams.<string>.url` | string | — |
| `upstreams.<string>.credentials.username` | string | — |
| `upstreams.<string>.credentials.password` | string | — |
| `upstreams.<string>.credentials.token` | string | — |
| `upstreams.<string>.tls.caCertFile` | string | — |
| `upstreams.<string>.tls.insecureSkipVerify` | bool | — |
| `upstreams.<string>.tls.minVersion` | string | — |
| `upstreams.<string>.tls.pins` | []string | — |
| `upstreams.<string>.tls.pinReportOnly` | bool | — |
| `upstreams.<string>.enabled` | bool | — |
| `upstreams.<string>.mirrors[].id` | string | — |
| `upstreams.<string>.mirrors[].url` | string | — |
| `upstreams.<string>.mirrors[].credentials.username` | string | — |
| `upstreams.<string>.mirrors[].credentials.password` | string | — |
| `upstreams.<string>.mirrors[].credentials.token` | string | — |
| `upstreams.<string>.mirrors[].tls.caCertFile` | string | — |
| `upstreams.<string>.mirrors[].tls.insecureSkipVerify` | bool | — |
| `upstreams.<string>.mirrors[].tls.minVersion` | string | — |
| `upstreams.<string>.mirrors[].tls.pins` | []string | — |
| `upstreams.<string>.mirrors[].tls.pinReportOnly` | bool | — |
| `upstreams.<string>.failover.failureThreshold` | int | — |
| `upstreams.<string>.failover.successThreshold` | int | — |
| `upstreams.<string>.failover.openTimeout` | duration | — |
| `upstreams.<string>.failover.halfOpenMaxProbes` | int | — |
| `upstreams.<string>.failover.probe.enabled` | bool | — |
| `upstreams.<string>.failover.probe.interval` | duration | — |
| `upstreams.<string>.failover.probe.timeout` | duration | — |
| `upstreams.<string>.failover.probe.path` | string | — |
| `upstreams.<string>.settings` | map[string]string | {} |
| `upstreams.<string>.generic.routes[].name` | string | — |
| `upstreams.<string>.generic.routes[].match` | string | — |
| `upstreams.<string>.generic.routes[].cacheable` | bool | — |
| `upstreams.<string>.generic.routes[].rewrite` | bool | — |
| `upstreams.<string>.generic.routes[].verify.algorithm` | string | — |
| `upstreams.<string>.generic.routes[].verify.source` | string | — |
| `upstreams.<string>.generic.routes[].verify.sidecarSuffix` | string | — |
| `upstreams.<string>.generic.routes[].verify.sidecarReplacesExtension` | bool | — |
| `upstreams.<string>.generic.routes[].verify.digestGroup` | int | — |
| `upstreams.<string>.generic.routes[].verify.failOpen` | bool | — |
| `upstreams.<string>.generic.routes[].gates` | []string | — |
| `upstreams.<string>.generic.routes[].mediaType` | string | — |
| `upstreams.<string>.generic.publicBaseURL` | string | — |
| `upstreams.<string>.generic.maxRewriteBytes` | int | — |

## `git`

| Setting | Type | Default |
|---------|------|---------|
| `git.mirrorDir` | string | — |
| `git.refreshInterval` | duration | 0s |
| `git.fetchTimeout` | duration | 0s |
| `git.infoRefsTtl` | duration | 0s |
| `git.gitBinary` | string | — |
| `git.ssh.hostKeyFile` | string | — |
| `git.ssh.authorizedKeysFile` | string | — |
| `git.ssh.authorizedKeys` | []string | [] |
| `git.ssh.noClientAuth` | bool | false |
| `git.lfs.enabled` | bool | false |
| `git.lfs.maxObjectBytes` | int | 0 |
| `git.lfs.scanMaxBytes` | int | 0 |
| `git.lfs.blockOnFindings` | bool | false |

## `scanning`

| Setting | Type | Default |
|---------|------|---------|
| `scanning.enabled` | bool | false |
| `scanning.provider` | string | `none` |
| `scanning.model` | string | — |
| `scanning.apiKey` | string | — |
| `scanning.baseUrl` | string | — |
| `scanning.apiVersion` | string | — |
| `scanning.reasoningEffort` | string | — |
| `scanning.timeout` | duration | 0s |
| `scanning.failOn` | string | `high` |
| `scanning.commit.triageModel` | string | — |
| `scanning.commit.deepModel` | string | — |
| `scanning.commit.escalateAtScore` | int | 0 |
| `scanning.commit.maxDiffTokens` | int | 0 |
| `scanning.commit.maxChunks` | int | 0 |
| `scanning.commit.maxRetries` | int | 0 |
| `scanning.commit.workers` | int | 0 |
| `scanning.commit.queueSize` | int | 0 |
| `scanning.commit.storeDir` | string | — |
| `scanning.commit.injectionRiskFloor` | int | 0 |
| `scanning.commit.retentionTtl` | duration | 0s |
| `scanning.commit.retentionInterval` | duration | 0s |
| `scanning.commit.consensus[].provider` | string | — |
| `scanning.commit.consensus[].model` | string | — |
| `scanning.commit.consensus[].apiKey` | string | — |
| `scanning.commit.consensus[].baseUrl` | string | — |
| `scanning.commit.quorum` | int | 0 |
| `scanning.commit.budget.enabled` | bool | false |
| `scanning.commit.budget.defaultCeilingUsd` | float | 0 |
| `scanning.commit.budget.tenantCeilingsUsd` | map[string]float | {} |
| `scanning.commit.budget.window` | duration | 0s |
| `scanning.commit.budget.failOpen` | bool | false |
| `scanning.commit.budget.pricing.<string>.inputPerMTok` | float | — |
| `scanning.commit.budget.pricing.<string>.outputPerMTok` | float | — |
| `scanning.secrets.enabled` | bool | — |
| `scanning.secrets.disableBuiltinRules` | bool | false |
| `scanning.secrets.rules[].id` | string | — |
| `scanning.secrets.rules[].description` | string | — |
| `scanning.secrets.rules[].severity` | string | — |
| `scanning.secrets.rules[].pattern` | string | — |
| `scanning.secrets.rules[].group` | int | — |
| `scanning.secrets.rules[].keywords` | []string | — |
| `scanning.secrets.rules[].minEntropy` | float | — |
| `scanning.secrets.entropy.enabled` | bool | — |
| `scanning.secrets.entropy.minLength` | int | 0 |
| `scanning.secrets.entropy.maxLength` | int | 0 |
| `scanning.secrets.entropy.base64Entropy` | float | 0 |
| `scanning.secrets.entropy.hexEntropy` | float | 0 |
| `scanning.secrets.entropy.severity` | string | — |
| `scanning.secrets.allowlist.disableBuiltins` | bool | false |
| `scanning.secrets.allowlist.paths` | []string | [] |
| `scanning.secrets.allowlist.patterns` | []string | [] |
| `scanning.secrets.allowlist.stopWords` | []string | [] |
| `scanning.secrets.allowlist.fingerprints` | []string | [] |
| `scanning.secrets.revealPrefix` | int | 0 |
| `scanning.secrets.maxFindingsPerFile` | int | 0 |
| `scanning.actions.enabled` | bool | — |
| `scanning.actions.failSeverity` | string | `high` |
| `scanning.actions.warnSeverity` | string | `medium` |
| `scanning.actions.action` | string | `block` |
| `scanning.actions.requirePinning` | bool | — |
| `scanning.actions.allowedOwners` | []string | [] |
| `scanning.actions.maxFindings` | int | 200 |
| `scanning.actions.tenants.<string>.failSeverity` | string | — |
| `scanning.actions.tenants.<string>.warnSeverity` | string | — |
| `scanning.actions.tenants.<string>.action` | string | — |
| `scanning.watch.enabled` | bool | false |
| `scanning.watch.stateDir` | string | — |
| `scanning.watch.mirrorDir` | string | — |
| `scanning.watch.pollInterval` | duration | 0s |
| `scanning.watch.maxCommitsPerScan` | int | 0 |
| `scanning.watch.backfill` | bool | false |
| `scanning.watch.webhookSecret` | string | — |
| `scanning.watch.webhookPath` | string | — |
| `scanning.watch.allowUnconfiguredWebhooks` | bool | false |
| `scanning.watch.repos[].name` | string | — |
| `scanning.watch.repos[].url` | string | — |
| `scanning.watch.repos[].branches` | []string | — |
| `scanning.watch.repos[].fullName` | string | — |
| `scanning.watch.repos[].username` | string | — |
| `scanning.watch.repos[].token` | string | — |

## `provenance`

| Setting | Type | Default |
|---------|------|---------|
| `provenance.enabled` | bool | false |
| `provenance.requireAttested` | bool | false |
| `provenance.githubToken` | string | — |
| `provenance.githubApiBase` | string | — |
| `provenance.storeDir` | string | — |
| `provenance.trustRootsFile` | string | — |
| `provenance.useSystemTrustRoots` | bool | false |
| `provenance.pins[].ecosystem` | string | — |
| `provenance.pins[].name` | string | — |
| `provenance.pins[].version` | string | — |
| `provenance.pins[].repository` | string | — |
| `provenance.pins[].commit` | string | — |

## `provgraph`

| Setting | Type | Default |
|---------|------|---------|
| `provgraph.enabled` | bool | true |

## `policy`

| Setting | Type | Default |
|---------|------|---------|
| `policy.enabled` | bool | false |
| `policy.failClosed` | bool | false |
| `policy.default.blockAtRiskScore` | int | 0 |
| `policy.default.warnAtRiskScore` | int | 0 |
| `policy.default.blockMalicious` | bool | false |
| `policy.default.onMissingProvenance` | string | — |
| `policy.default.onMissingScan` | string | — |
| `policy.default.requireSignature` | bool | false |
| `policy.default.requireAttested` | bool | false |
| `policy.default.minConfidence` | string | — |
| `policy.default.onLowConfidence` | string | — |
| `policy.default.allowlist` | []string | [] |
| `policy.default.denylist` | []string | [] |
| `policy.ecosystems.<string>.blockAtRiskScore` | int | — |
| `policy.ecosystems.<string>.warnAtRiskScore` | int | — |
| `policy.ecosystems.<string>.blockMalicious` | bool | — |
| `policy.ecosystems.<string>.onMissingProvenance` | string | — |
| `policy.ecosystems.<string>.onMissingScan` | string | — |
| `policy.ecosystems.<string>.requireSignature` | bool | — |
| `policy.ecosystems.<string>.requireAttested` | bool | — |
| `policy.ecosystems.<string>.minConfidence` | string | — |
| `policy.ecosystems.<string>.onLowConfidence` | string | — |
| `policy.ecosystems.<string>.allowlist` | []string | — |
| `policy.ecosystems.<string>.denylist` | []string | — |

## `policyEngine`

| Setting | Type | Default |
|---------|------|---------|
| `policyEngine.enabled` | bool | false |
| `policyEngine.dir` | string | — |
| `policyEngine.mode` | string | — |
| `policyEngine.defaultAction` | string | — |
| `policyEngine.includeDefaultBundle` | bool | — |
| `policyEngine.reloadInterval` | duration | 0s |

## `vulnerabilities`

| Setting | Type | Default |
|---------|------|---------|
| `vulnerabilities.enabled` | bool | false |
| `vulnerabilities.scanner` | string | — |
| `vulnerabilities.osvBaseUrl` | string | — |
| `vulnerabilities.cacheTtl` | duration | 0s |
| `vulnerabilities.cacheMaxEntries` | int | 0 |
| `vulnerabilities.timeout` | duration | 0s |
| `vulnerabilities.offline` | bool | false |
| `vulnerabilities.action` | string | — |
| `vulnerabilities.failSeverity` | string | — |
| `vulnerabilities.failCvss` | float | 0 |
| `vulnerabilities.warnSeverity` | string | — |
| `vulnerabilities.failOnError` | bool | false |
| `vulnerabilities.ignoreIds` | []string | [] |
| `vulnerabilities.rescanInterval` | duration | 0s |
| `vulnerabilities.rescanWorkers` | int | 0 |
| `vulnerabilities.vex.enabled` | bool | false |
| `vulnerabilities.vex.dir` | string | — |
| `vulnerabilities.vex.fetchUrl` | string | — |
| `vulnerabilities.vex.export.enabled` | bool | false |
| `vulnerabilities.vex.export.author` | string | — |
| `vulnerabilities.vex.export.idNamespace` | string | — |
| `vulnerabilities.vex.export.signingKey` | string | — |
| `vulnerabilities.vex.export.signingKeyFile` | string | — |
| `vulnerabilities.reachability.enabled` | bool | false |
| `vulnerabilities.reachability.unreachableAction` | string | — |

## `license`

| Setting | Type | Default |
|---------|------|---------|
| `license.enabled` | bool | false |
| `license.allow` | []string | [] |
| `license.deny` | []string | [] |
| `license.review` | []string | [] |
| `license.allowExceptions` | []string | [] |
| `license.unknown` | string | — |
| `license.default` | string | — |
| `license.action` | string | — |
| `license.reviewAction` | string | — |
| `license.driftAction` | string | — |
| `license.tenants.<string>.allow` | []string | — |
| `license.tenants.<string>.deny` | []string | — |
| `license.tenants.<string>.review` | []string | — |
| `license.tenants.<string>.allowExceptions` | []string | — |
| `license.tenants.<string>.unknown` | string | — |
| `license.tenants.<string>.default` | string | — |
| `license.tenants.<string>.action` | string | — |
| `license.tenants.<string>.reviewAction` | string | — |
| `license.tenants.<string>.driftAction` | string | — |
| `license.driftDetection` | bool | false |
| `license.driftMaxEvents` | int | 0 |

## `nameguard`

| Setting | Type | Default |
|---------|------|---------|
| `nameguard.enabled` | bool | false |
| `nameguard.internalNamespaces` | map[string][]string | {} |
| `nameguard.popularNames` | map[string][]string | {} |
| `nameguard.allowlist` | map[string][]string | {} |
| `nameguard.disableBuiltins` | bool | false |
| `nameguard.distanceThreshold` | int | 0 |
| `nameguard.minNameLength` | int | 0 |
| `nameguard.action` | string | — |
| `nameguard.failSeverity` | string | — |
| `nameguard.warnSeverity` | string | — |
| `nameguard.detectHomoglyphs` | bool | — |

## `malfeed`

| Setting | Type | Default |
|---------|------|---------|
| `malfeed.enabled` | bool | true |
| `malfeed.sources[].url` | string | — |
| `malfeed.sources[].name` | string | — |
| `malfeed.refreshInterval` | duration | 6h0m0s |
| `malfeed.staleAfter` | duration | 24h0m0s |
| `malfeed.failClosed` | bool | false |
| `malfeed.timeout` | duration | 0s |
| `malfeed.bundlePath` | string | — |
| `malfeed.bundlePublicKeyFile` | string | — |

## `maturity`

| Setting | Type | Default |
|---------|------|---------|
| `maturity.enabled` | bool | true |
| `maturity.defaultCooldown` | duration | 0s |
| `maturity.ecosystems` | map[string]duration | {} |
| `maturity.tenants.<string>.defaultCooldown` | duration | — |
| `maturity.tenants.<string>.ecosystems` | map[string]duration | {} |
| `maturity.tenants.<string>.allowlist` | []string | — |
| `maturity.allowlist` | []string | [] |
| `maturity.failClosedOnUnknown` | bool | false |
| `maturity.timeout` | duration | 10s |
| `maturity.cacheTTL` | duration | 6h0m0s |
| `maturity.negativeCacheTTL` | duration | 15m0s |
| `maturity.cacheSize` | int | 4096 |
| `maturity.userAgent` | string | — |
| `maturity.baseURLs` | map[string]string | {} |

## `continuity`

| Setting | Type | Default |
|---------|------|---------|
| `continuity.enabled` | bool | true |
| `continuity.defaultDisposition` | string | `observe` |
| `continuity.ecosystems` | map[string]string | {} |
| `continuity.tenants.<string>.disposition` | string | — |
| `continuity.tenants.<string>.ecosystems` | map[string]string | {} |
| `continuity.tenants.<string>.cooldown` | duration | — |
| `continuity.tenants.<string>.allowlist` | []string | — |
| `continuity.cooldown` | duration | 168h0m0s |
| `continuity.allowlist` | []string | [] |
| `continuity.storePath` | string | — |
| `continuity.timeout` | duration | 10s |
| `continuity.cacheTTL` | duration | 1h0m0s |
| `continuity.negativeCacheTTL` | duration | 15m0s |
| `continuity.cacheSize` | int | 4096 |
| `continuity.maxRecords` | int | 50000 |
| `continuity.userAgent` | string | — |
| `continuity.baseURLs` | map[string]string | {} |

## `depfirewall`

| Setting | Type | Default |
|---------|------|---------|
| `depfirewall.enabled` | bool | false |
| `depfirewall.defaultAction` | string | `allow` |
| `depfirewall.rules[].ecosystem` | string | — |
| `depfirewall.rules[].name` | string | — |
| `depfirewall.rules[].pinned` | []string | — |
| `depfirewall.rules[].ranges` | []string | — |
| `depfirewall.rules[].minVersion` | string | — |
| `depfirewall.rules[].denied` | []string | — |
| `depfirewall.rules[].note` | string | — |
| `depfirewall.tenants.<string>.defaultAction` | string | — |
| `depfirewall.tenants.<string>.rules[].ecosystem` | string | — |
| `depfirewall.tenants.<string>.rules[].name` | string | — |
| `depfirewall.tenants.<string>.rules[].pinned` | []string | — |
| `depfirewall.tenants.<string>.rules[].ranges` | []string | — |
| `depfirewall.tenants.<string>.rules[].minVersion` | string | — |
| `depfirewall.tenants.<string>.rules[].denied` | []string | — |
| `depfirewall.tenants.<string>.rules[].note` | string | — |

## `installHooks`

| Setting | Type | Default |
|---------|------|---------|
| `installHooks.enabled` | bool | true |
| `installHooks.failSeverity` | string | `high` |
| `installHooks.warnSeverity` | string | `medium` |
| `installHooks.action` | string | `block` |
| `installHooks.disabledRules` | []string | [] |
| `installHooks.rules[].id` | string | — |
| `installHooks.rules[].title` | string | — |
| `installHooks.rules[].severity` | string | — |
| `installHooks.rules[].pattern` | string | — |
| `installHooks.maxFindingsPerHook` | int | 50 |
| `installHooks.tenants.<string>.failSeverity` | string | — |
| `installHooks.tenants.<string>.warnSeverity` | string | — |
| `installHooks.tenants.<string>.action` | string | — |

## `mlGuard`

| Setting | Type | Default |
|---------|------|---------|
| `mlGuard.enabled` | bool | true |
| `mlGuard.failSeverity` | string | `high` |
| `mlGuard.warnSeverity` | string | `medium` |
| `mlGuard.action` | string | `block` |
| `mlGuard.preferSafetensors` | bool | — |
| `mlGuard.maxScanBytes` | int | 268435456 |
| `mlGuard.maxZipEntries` | int | 64 |
| `mlGuard.tenants.<string>.failSeverity` | string | — |
| `mlGuard.tenants.<string>.warnSeverity` | string | — |
| `mlGuard.tenants.<string>.action` | string | — |

## `avScan`

| Setting | Type | Default |
|---------|------|---------|
| `avScan.enabled` | bool | false |
| `avScan.engine` | string | `clamav` |
| `avScan.address` | string | — |
| `avScan.action` | string | `quarantine` |
| `avScan.maxScanBytes` | int | 134217728 |
| `avScan.timeout` | duration | 1m0s |
| `avScan.failOpen` | bool | — |

## `contentScan`

| Setting | Type | Default |
|---------|------|---------|
| `contentScan.enabled` | bool | true |
| `contentScan.action` | string | `annotate` |
| `contentScan.failSeverity` | string | `high` |
| `contentScan.ecosystems` | []string | [] |
| `contentScan.detectEntropy` | bool | — |
| `contentScan.detectBinary` | bool | — |
| `contentScan.detectJavaScript` | bool | — |
| `contentScan.detectDynamicExec` | bool | — |
| `contentScan.detectSecrets` | bool | — |
| `contentScan.entropyThreshold` | float | 0 |
| `contentScan.minEntropyBlobBytes` | int | 0 |
| `contentScan.maxArchiveBytes` | int | 0 |
| `contentScan.maxFileBytes` | int | 0 |
| `contentScan.maxFiles` | int | 0 |
| `contentScan.maxScanBytesPerFile` | int | 0 |
| `contentScan.maxFindings` | int | 0 |
| `contentScan.maxFindingsPerFile` | int | 0 |
| `contentScan.timeout` | duration | 0s |

## `llmPackageScan`

| Setting | Type | Default |
|---------|------|---------|
| `llmPackageScan.enabled` | bool | false |
| `llmPackageScan.provider` | string | — |
| `llmPackageScan.model` | string | — |
| `llmPackageScan.apiKey` | string | — |
| `llmPackageScan.baseUrl` | string | — |
| `llmPackageScan.apiVersion` | string | — |
| `llmPackageScan.reasoningEffort` | string | — |
| `llmPackageScan.mode` | string | `auto` |
| `llmPackageScan.thinking` | bool | — |
| `llmPackageScan.action` | string | `block` |
| `llmPackageScan.failMode` | string | `open` |
| `llmPackageScan.oversize` | string | `fail` |
| `llmPackageScan.maliciousThreshold` | float | 0.7 |
| `llmPackageScan.suspiciousThreshold` | float | 0.5 |
| `llmPackageScan.timeout` | duration | 2m0s |
| `llmPackageScan.requestTimeout` | duration | 0s |
| `llmPackageScan.maxRetries` | int | 1 |
| `llmPackageScan.maxConcurrent` | int | 4 |
| `llmPackageScan.include` | []string | [] |
| `llmPackageScan.exclude` | []string | [] |
| `llmPackageScan.excludeUpstreams` | []string | [] |
| `llmPackageScan.storeDir` | string | — |
| `llmPackageScan.cacheTtl` | duration | 0s |
| `llmPackageScan.errorTtl` | duration | 5m0s |
| `llmPackageScan.limits.maxArtifactBytes` | int | 67108864 |
| `llmPackageScan.limits.maxUnpackedBytes` | int | 268435456 |
| `llmPackageScan.limits.maxFileBytes` | int | 1048576 |
| `llmPackageScan.limits.maxFiles` | int | 5000 |
| `llmPackageScan.limits.maxDepth` | int | 32 |
| `llmPackageScan.limits.maxCompressionRatio` | float | 200 |
| `llmPackageScan.limits.maxPromptBytes` | int | 122880 |
| `llmPackageScan.limits.maxToolResultBytes` | int | 24576 |
| `llmPackageScan.limits.maxToolBytes` | int | 262144 |
| `llmPackageScan.limits.maxTurns` | int | 8 |
| `llmPackageScan.limits.maxToolCalls` | int | 24 |
| `llmPackageScan.limits.maxOutputTokens` | int | 16000 |
| `llmPackageScan.limits.maxTotalTokens` | int | 600000 |
| `llmPackageScan.budget.enabled` | bool | false |
| `llmPackageScan.budget.globalCeilingUsd` | float | 0 |
| `llmPackageScan.budget.tenantCeilingUsd` | float | 0 |
| `llmPackageScan.budget.tenantCeilingsUsd` | map[string]float | {} |
| `llmPackageScan.budget.window` | duration | 24h0m0s |
| `llmPackageScan.budget.pricing.<string>.inputPerMTok` | float | — |
| `llmPackageScan.budget.pricing.<string>.outputPerMTok` | float | — |

## `sigverify`

| Setting | Type | Default |
|---------|------|---------|
| `sigverify.enabled` | bool | false |
| `sigverify.ecosystems` | []string | [] |
| `sigverify.action` | string | — |
| `sigverify.failSeverity` | string | — |
| `sigverify.warnSeverity` | string | — |
| `sigverify.requireSignature` | bool | false |
| `sigverify.requireAttestation` | bool | false |
| `sigverify.requireRekorProof` | bool | false |
| `sigverify.failOnError` | bool | false |
| `sigverify.trustRootsFile` | string | — |
| `sigverify.useSystemTrustRoots` | bool | false |
| `sigverify.rekorKeyFiles` | []string | [] |
| `sigverify.keys[].name` | string | — |
| `sigverify.keys[].file` | string | — |
| `sigverify.keys[].pem` | string | — |
| `sigverify.identities[].issuer` | string | — |
| `sigverify.identities[].subjectPattern` | string | — |
| `sigverify.npmRegistryUrl` | string | — |
| `sigverify.pypiUrl` | string | — |
| `sigverify.offline` | bool | false |
| `sigverify.trustBundleFile` | string | — |
| `sigverify.trustBundleDigest` | string | — |
| `sigverify.cacheTtl` | duration | 0s |
| `sigverify.cacheMaxEntries` | int | 0 |
| `sigverify.pqc.enabled` | bool | false |
| `sigverify.pqc.policy` | string | — |

## `notifications`

| Setting | Type | Default |
|---------|------|---------|
| `notifications.enabled` | bool | false |
| `notifications.workers` | int | 0 |
| `notifications.queueSize` | int | 0 |
| `notifications.maxRetries` | int | 0 |
| `notifications.retryBaseDelay` | duration | 0s |
| `notifications.retryMaxDelay` | duration | 0s |
| `notifications.timeout` | duration | 0s |
| `notifications.minSeverity` | string | — |
| `notifications.redactFields` | []string | [] |
| `notifications.sinks[].name` | string | — |
| `notifications.sinks[].kind` | string | — |
| `notifications.sinks[].url` | string | — |
| `notifications.sinks[].headers` | map[string]string | {} |
| `notifications.sinks[].channel` | string | — |
| `notifications.sinks[].username` | string | — |
| `notifications.sinks[].iconEmoji` | string | — |
| `notifications.sinks[].insecureSkipVerify` | bool | — |
| `notifications.routes[].sinks` | []string | — |
| `notifications.routes[].eventTypes` | []string | — |
| `notifications.routes[].minSeverity` | string | — |

## `rateLimit`

| Setting | Type | Default |
|---------|------|---------|
| `rateLimit.enabled` | bool | false |
| `rateLimit.global.rps` | float | 0 |
| `rateLimit.global.burst` | int | 0 |
| `rateLimit.global.maxConcurrent` | int | 0 |
| `rateLimit.global.byteQuota` | int | 0 |
| `rateLimit.global.window` | duration | 0s |
| `rateLimit.default.rps` | float | 0 |
| `rateLimit.default.burst` | int | 0 |
| `rateLimit.default.maxConcurrent` | int | 0 |
| `rateLimit.default.byteQuota` | int | 0 |
| `rateLimit.default.window` | duration | 0s |
| `rateLimit.shared` | bool | false |

## `coalesce`

| Setting | Type | Default |
|---------|------|---------|
| `coalesce.enabled` | bool | true |
| `coalesce.negativeTtl` | duration | 30s |
| `coalesce.maxNegativeEntries` | int | 0 |
| `coalesce.maxInflight` | int | 0 |
| `coalesce.backoff5xxBase` | duration | 1s |
| `coalesce.backoff5xxMax` | duration | 5s |

## `cacheGc`

| Setting | Type | Default |
|---------|------|---------|
| `cacheGc.enabled` | bool | true |
| `cacheGc.interval` | duration | 1h0m0s |
| `cacheGc.capacityBytes` | int | 0 |
| `cacheGc.highWatermarkPct` | float | 0.9 |
| `cacheGc.lowWatermarkPct` | float | 0.7 |
| `cacheGc.policy` | string | `lru` |
| `cacheGc.defaultTtl` | duration | 0s |
| `cacheGc.tenantTtls` | map[string]duration | {} |
| `cacheGc.minIdle` | duration | 1m0s |
| `cacheGc.maxDeletesPerRun` | int | 0 |
| `cacheGc.allowEvictPinned` | bool | false |
| `cacheGc.dryRun` | bool | false |

## `observability`

| Setting | Type | Default |
|---------|------|---------|
| `observability.metrics` | bool | true |
| `observability.metricsPath` | string | `/metrics` |
| `observability.admin` | bool | true |
| `observability.adminPathPrefix` | string | `/admin` |
| `observability.adminToken` | string | — |
| `observability.portal` | bool | false |
| `observability.portalPathPrefix` | string | — |
| `observability.mcp` | bool | true |
| `observability.mcpMaxDetailItems` | int | 0 |
| `observability.grpc` | bool | false |
| `observability.grpcMaxDetailItems` | int | 0 |
| `observability.profiling` | bool | false |
| `observability.profilingBlockRate` | int | 0 |
| `observability.profilingMutexFraction` | int | 0 |

## `adminAuth`

| Setting | Type | Default |
|---------|------|---------|
| `adminAuth.enabled` | bool | false |
| `adminAuth.oidc.enabled` | bool | false |
| `adminAuth.oidc.issuer` | string | — |
| `adminAuth.oidc.clientId` | string | — |
| `adminAuth.oidc.clientSecret` | string | — |
| `adminAuth.oidc.redirectUrl` | string | — |
| `adminAuth.oidc.scopes` | []string | [] |
| `adminAuth.oidc.audience` | string | — |
| `adminAuth.oidc.discoveryUrl` | string | — |
| `adminAuth.oidc.authorizationEndpoint` | string | — |
| `adminAuth.oidc.tokenEndpoint` | string | — |
| `adminAuth.oidc.endSessionEndpoint` | string | — |
| `adminAuth.oidc.jwksUrl` | string | — |
| `adminAuth.oidc.jwks` | string | — |
| `adminAuth.oidc.subjectClaim` | string | — |
| `adminAuth.oidc.groupsClaim` | string | — |
| `adminAuth.oidc.tenantClaim` | string | — |
| `adminAuth.oidc.jwksCacheTtl` | duration | 0s |
| `adminAuth.oidc.leeway` | duration | 0s |
| `adminAuth.staticTokens[].name` | string | — |
| `adminAuth.staticTokens[].tenant` | string | — |
| `adminAuth.staticTokens[].roles` | []string | — |
| `adminAuth.staticTokens[].token` | string | — |
| `adminAuth.staticTokens[].tokenHash` | string | — |
| `adminAuth.allowLegacyToken` | bool | — |
| `adminAuth.sessionKey` | string | — |
| `adminAuth.sessionTtl` | duration | 0s |
| `adminAuth.cookieName` | string | — |
| `adminAuth.insecureCookies` | bool | false |
| `adminAuth.roleBindings` | map[string]string | {} |
| `adminAuth.defaultRole` | string | — |

## `tracing`

| Setting | Type | Default |
|---------|------|---------|
| `tracing.enabled` | bool | false |
| `tracing.endpoint` | string | — |
| `tracing.insecure` | bool | false |
| `tracing.tlsSkipVerify` | bool | false |
| `tracing.serviceName` | string | `pullthrough` |
| `tracing.serviceVersion` | string | — |
| `tracing.environment` | string | — |
| `tracing.samplerRatio` | float | 1 |
| `tracing.resourceAttributes` | map[string]string | {} |
| `tracing.headers` | map[string]string | {} |
| `tracing.timeout` | duration | 10s |
| `tracing.batchTimeout` | duration | 5s |
| `tracing.maxQueueSize` | int | 2048 |
| `tracing.maxBatchSize` | int | 512 |

## `telemetry`

| Setting | Type | Default |
|---------|------|---------|
| `telemetry.otlpLogs.enabled` | bool | false |
| `telemetry.otlpLogs.endpoint` | string | — |
| `telemetry.otlpLogs.insecure` | bool | false |
| `telemetry.otlpLogs.tlsSkipVerify` | bool | false |
| `telemetry.otlpLogs.serviceName` | string | — |
| `telemetry.otlpLogs.environment` | string | — |
| `telemetry.otlpLogs.tenant` | string | — |
| `telemetry.otlpLogs.resourceAttributes` | map[string]string | {} |
| `telemetry.otlpLogs.headers` | map[string]string | {} |
| `telemetry.otlpLogs.minLevel` | string | — |
| `telemetry.otlpLogs.timeout` | duration | 0s |
| `telemetry.otlpLogs.batchTimeout` | duration | 0s |
| `telemetry.otlpLogs.maxQueueSize` | int | 0 |
| `telemetry.otlpLogs.maxBatchSize` | int | 0 |
| `telemetry.otlpLogs.maxRetries` | int | 0 |
| `telemetry.otlpLogs.retryBaseDelay` | duration | 0s |
| `telemetry.otlpLogs.retryMaxDelay` | duration | 0s |
| `telemetry.otlpLogs.spillFile` | string | — |
| `telemetry.otlpLogs.spillMaxBytes` | int | 0 |

## `compliance`

| Setting | Type | Default |
|---------|------|---------|
| `compliance.enabled` | bool | true |
| `compliance.interval` | duration | 0s |
| `compliance.maxAuditSealAge` | duration | 0s |
| `compliance.signingKey` | string | — |
| `compliance.signingKeyFile` | string | — |
| `compliance.controls.<string>.disabled` | bool | — |
| `compliance.controls.<string>.required` | bool | — |
| `compliance.controls.<string>.weight` | float | — |
| `compliance.controls.<string>.passThreshold` | float | — |
| `compliance.controls.<string>.warnThreshold` | float | — |

## `riskScore`

| Setting | Type | Default |
|---------|------|---------|
| `riskScore.enabled` | bool | true |
| `riskScore.historySize` | int | 0 |
| `riskScore.thresholdBand` | string | — |
| `riskScore.thresholdAction` | string | — |
| `riskScore.weights.vulnerability` | float | 0 |
| `riskScore.weights.signature` | float | 0 |
| `riskScore.weights.license` | float | 0 |
| `riskScore.weights.nameguard` | float | 0 |
| `riskScore.weights.secret` | float | 0 |
| `riskScore.weights.provenance` | float | 0 |
| `riskScore.weights.quarantine` | float | 0 |
| `riskScore.weights.installHooks` | float | 0 |
| `riskScore.weights.repoHealth` | float | 0 |
| `riskScore.weights.llmPackageScan` | float | 0 |
| `riskScore.bands.medium` | int | 0 |
| `riskScore.bands.high` | int | 0 |
| `riskScore.bands.critical` | int | 0 |
| `riskScore.tenants.<string>.weights.vulnerability` | float | — |
| `riskScore.tenants.<string>.weights.signature` | float | — |
| `riskScore.tenants.<string>.weights.license` | float | — |
| `riskScore.tenants.<string>.weights.nameguard` | float | — |
| `riskScore.tenants.<string>.weights.secret` | float | — |
| `riskScore.tenants.<string>.weights.provenance` | float | — |
| `riskScore.tenants.<string>.weights.quarantine` | float | — |
| `riskScore.tenants.<string>.weights.installHooks` | float | — |
| `riskScore.tenants.<string>.weights.repoHealth` | float | — |
| `riskScore.tenants.<string>.weights.llmPackageScan` | float | — |
| `riskScore.tenants.<string>.bands.medium` | int | — |
| `riskScore.tenants.<string>.bands.high` | int | — |
| `riskScore.tenants.<string>.bands.critical` | int | — |
| `riskScore.tenants.<string>.thresholdBand` | string | — |
| `riskScore.tenants.<string>.thresholdAction` | string | — |

## `repoScore`

| Setting | Type | Default |
|---------|------|---------|
| `repoScore.enabled` | bool | false |
| `repoScore.cacheDir` | string | — |
| `repoScore.allowFetch` | bool | false |
| `repoScore.window` | int | 0 |
| `repoScore.cloneDepth` | int | 0 |
| `repoScore.cacheTtl` | duration | 0s |
| `repoScore.fetchTimeout` | duration | 0s |
| `repoScore.analyzeTimeout` | duration | 0s |
| `repoScore.gitBinary` | string | — |
| `repoScore.weights.branchProtection` | float | 0 |
| `repoScore.weights.signedCommits` | float | 0 |
| `repoScore.weights.ci` | float | 0 |
| `repoScore.weights.securityPolicy` | float | 0 |
| `repoScore.weights.maintainers` | float | 0 |
| `repoScore.weights.activity` | float | 0 |
| `repoScore.weights.depAutomation` | float | 0 |
| `repoScore.tenants.<string>.weights.branchProtection` | float | — |
| `repoScore.tenants.<string>.weights.signedCommits` | float | — |
| `repoScore.tenants.<string>.weights.ci` | float | — |
| `repoScore.tenants.<string>.weights.securityPolicy` | float | — |
| `repoScore.tenants.<string>.weights.maintainers` | float | — |
| `repoScore.tenants.<string>.weights.activity` | float | — |
| `repoScore.tenants.<string>.weights.depAutomation` | float | — |

## `sbomDiff`

| Setting | Type | Default |
|---------|------|---------|
| `sbomDiff.enabled` | bool | true |
| `sbomDiff.historySize` | int | 16 |
| `sbomDiff.maxCoordinates` | int | 4096 |
| `sbomDiff.action` | string | `warn` |
| `sbomDiff.warnThreshold` | float | 0 |
| `sbomDiff.blockThreshold` | float | 0 |
| `sbomDiff.significantThreshold` | float | 0 |
| `sbomDiff.weights.perAddedDep` | float | 0 |
| `sbomDiff.weights.perNewNamespace` | float | 0 |
| `sbomDiff.weights.perVersionBump` | float | 0 |
| `sbomDiff.weights.perRemovedDep` | float | 0 |
| `sbomDiff.weights.newLicenseAllow` | float | 0 |
| `sbomDiff.weights.newLicenseReview` | float | 0 |
| `sbomDiff.weights.newLicenseDeny` | float | 0 |
| `sbomDiff.weights.vulnCritical` | float | 0 |
| `sbomDiff.weights.vulnHigh` | float | 0 |
| `sbomDiff.weights.vulnMedium` | float | 0 |
| `sbomDiff.weights.vulnLow` | float | 0 |

## `remediation`

| Setting | Type | Default |
|---------|------|---------|
| `remediation.enabled` | bool | true |
| `remediation.maxCandidates` | int | 25 |
| `remediation.includePrerelease` | bool | false |
| `remediation.userAgent` | string | — |
| `remediation.baseURLs` | map[string]string | {} |

## `rebuildVerify`

| Setting | Type | Default |
|---------|------|---------|
| `rebuildVerify.enabled` | bool | true |
| `rebuildVerify.mode` | string | `observe` |
| `rebuildVerify.async` | bool | — |
| `rebuildVerify.maxConcurrent` | int | 2 |
| `rebuildVerify.buildTimeout` | duration | 0s |
| `rebuildVerify.cacheSize` | int | 4096 |
| `rebuildVerify.recentSize` | int | 100 |
| `rebuildVerify.repoCacheDir` | string | — |
| `rebuildVerify.gitBinary` | string | — |
| `rebuildVerify.allowFetch` | bool | false |
| `rebuildVerify.cloneDepth` | int | 0 |
| `rebuildVerify.fetchTimeout` | duration | 0s |
| `rebuildVerify.tenants.<string>.mode` | string | — |

## `buildProv`

| Setting | Type | Default |
|---------|------|---------|
| `buildProv.enabled` | bool | true |
| `buildProv.mode` | string | `observe` |
| `buildProv.action` | string | `quarantine` |
| `buildProv.failSeverity` | string | `high` |
| `buildProv.warnSeverity` | string | `medium` |
| `buildProv.requireProvenance` | bool | false |
| `buildProv.requireTrustedSource` | bool | false |
| `buildProv.failOnError` | bool | false |
| `buildProv.npmRegistryUrl` | string | — |
| `buildProv.githubApiUrl` | string | — |
| `buildProv.githubToken` | string | — |
| `buildProv.enableGithubSource` | bool | false |
| `buildProv.gitlabApiUrl` | string | — |
| `buildProv.gitlabHost` | string | — |
| `buildProv.gitlabToken` | string | — |
| `buildProv.enableGitlabSource` | bool | false |
| `buildProv.bitbucketApiUrl` | string | — |
| `buildProv.bitbucketHost` | string | — |
| `buildProv.bitbucketToken` | string | — |
| `buildProv.enableBitbucketSource` | bool | false |
| `buildProv.forges[].name` | string | — |
| `buildProv.forges[].trustRootsFile` | string | — |
| `buildProv.forges[].useSystemTrustRoots` | bool | — |
| `buildProv.forges[].trustBundlePath` | string | — |
| `buildProv.forges[].trustBundleDigest` | string | — |
| `buildProv.forges[].rekorKeyFiles` | []string | — |
| `buildProv.forges[].identities[].issuer` | string | — |
| `buildProv.forges[].identities[].subjectPattern` | string | — |
| `buildProv.timeout` | duration | 0s |
| `buildProv.cacheTtl` | duration | 0s |
| `buildProv.cacheSize` | int | 1024 |
| `buildProv.trustBundlePath` | string | — |
| `buildProv.trustBundleDigest` | string | — |
| `buildProv.offline` | bool | false |
| `buildProv.identities[].issuer` | string | — |
| `buildProv.identities[].subjectPattern` | string | — |
| `buildProv.tenants.<string>.mode` | string | — |
| `buildProv.tenants.<string>.requireProvenance` | bool | — |

## `pypiAttestation`

| Setting | Type | Default |
|---------|------|---------|
| `pypiAttestation.enabled` | bool | true |
| `pypiAttestation.action` | string | `annotate` |
| `pypiAttestation.failSeverity` | string | `high` |
| `pypiAttestation.warnSeverity` | string | `medium` |
| `pypiAttestation.requireAttestation` | bool | false |
| `pypiAttestation.requireTrustedPublisher` | bool | false |
| `pypiAttestation.requireInclusionProof` | bool | false |
| `pypiAttestation.failOnError` | bool | false |
| `pypiAttestation.indexUrl` | string | — |
| `pypiAttestation.integrityUrl` | string | — |
| `pypiAttestation.timeout` | duration | 0s |
| `pypiAttestation.cacheTtl` | duration | 0s |
| `pypiAttestation.cacheSize` | int | 1024 |
| `pypiAttestation.trustBundlePath` | string | — |
| `pypiAttestation.trustBundleDigest` | string | — |
| `pypiAttestation.trustRootsFile` | string | — |
| `pypiAttestation.rekorKeyFiles` | []string | [] |
| `pypiAttestation.offline` | bool | false |
| `pypiAttestation.identities[].issuer` | string | — |
| `pypiAttestation.identities[].subjectPattern` | string | — |
| `pypiAttestation.tenants.<string>.action` | string | — |

## `snapshot`

| Setting | Type | Default |
|---------|------|---------|
| `snapshot.enabled` | bool | false |
| `snapshot.dir` | string | — |
| `snapshot.maxLiveEntries` | int | 0 |
| `snapshot.maxSnapshots` | int | 0 |
| `snapshot.scheduleInterval` | duration | 0s |
| `snapshot.freezeEnforce` | bool | false |

## `lockdown`

| Setting | Type | Default |
|---------|------|---------|
| `lockdown.enabled` | bool | false |
| `lockdown.storePath` | string | — |
| `lockdown.defaultTtl` | duration | 0s |
| `lockdown.maxTtl` | duration | 0s |

## `admissionWebhook`

| Setting | Type | Default |
|---------|------|---------|
| `admissionWebhook.enabled` | bool | false |
| `admissionWebhook.addr` | string | — |
| `admissionWebhook.path` | string | — |
| `admissionWebhook.healthPath` | string | — |
| `admissionWebhook.readyPath` | string | — |
| `admissionWebhook.tlsCertFile` | string | — |
| `admissionWebhook.tlsKeyFile` | string | — |
| `admissionWebhook.clientCaFile` | string | — |
| `admissionWebhook.failurePolicy` | string | — |
| `admissionWebhook.blockAction` | string | — |
| `admissionWebhook.warnAction` | string | — |
| `admissionWebhook.unknownAction` | string | — |
| `admissionWebhook.minRiskScoreToDeny` | int | 0 |
| `admissionWebhook.enforceLockdown` | bool | — |
| `admissionWebhook.defaultEcosystem` | string | — |
| `admissionWebhook.tenant` | string | — |
| `admissionWebhook.stripRegistryHost` | bool | — |
| `admissionWebhook.ignoreNamespaces` | []string | [] |
| `admissionWebhook.ignoreImages` | []string | [] |
| `admissionWebhook.annotateWarnings` | bool | — |
| `admissionWebhook.timeout` | duration | 0s |
| `admissionWebhook.dossier.url` | string | — |
| `admissionWebhook.dossier.token` | string | — |
| `admissionWebhook.dossier.caCertFile` | string | — |
| `admissionWebhook.dossier.insecureSkipVerify` | bool | false |
| `admissionWebhook.dossier.timeout` | duration | 0s |

## `gitops`

| Setting | Type | Default |
|---------|------|---------|
| `gitops.enabled` | bool | false |
| `gitops.mode` | string | — |
| `gitops.interval` | duration | 0s |
| `gitops.storePath` | string | — |
| `gitops.failClosed` | bool | false |
| `gitops.source.type` | string | — |
| `gitops.source.path` | string | — |
| `gitops.source.git.url` | string | — |
| `gitops.source.git.ref` | string | — |
| `gitops.source.git.workDir` | string | — |
| `gitops.verify.publicKey` | string | — |
| `gitops.verify.publicKeyFile` | string | — |
| `gitops.verify.expectedDigest` | string | — |

## `extensions`

| Setting | Type | Default |
|---------|------|---------|
| `extensions.enabled` | bool | true |
| `extensions.defaults.timeoutMs` | int | 0 |
| `extensions.defaults.memoryBytes` | int | 0 |
| `extensions.defaults.fuel` | int | 0 |
| `extensions.defaults.maxOutputBytes` | int | 0 |
| `extensions.modules[].name` | string | — |
| `extensions.modules[].path` | string | — |
| `extensions.modules[].tenants` | []string | — |
| `extensions.modules[].failClosed` | bool | — |
| `extensions.modules[].limits.timeoutMs` | int | — |
| `extensions.modules[].limits.memoryBytes` | int | — |
| `extensions.modules[].limits.fuel` | int | — |
| `extensions.modules[].limits.maxOutputBytes` | int | — |

## `findings`

| Setting | Type | Default |
|---------|------|---------|
| `findings.enabled` | bool | true |
| `findings.maxEntries` | int | 0 |
| `findings.dedup` | bool | — |
| `findings.suppressionTrail` | bool | — |
| `findings.maxSuppressions` | int | 0 |

## `attest`

| Setting | Type | Default |
|---------|------|---------|
| `attest.enabled` | bool | true |
| `attest.maxEntries` | int | 0 |
| `attest.attesterId` | string | — |
| `attest.instance` | string | — |
| `attest.signingKey` | string | — |
| `attest.signingKeyFile` | string | — |

## `transparency`

| Setting | Type | Default |
|---------|------|---------|
| `transparency.rekor.enabled` | bool | false |
| `transparency.rekor.url` | string | `https://rekor.sigstore.dev` |
| `transparency.rekor.submit` | bool | false |
| `transparency.rekor.requireInclusionProof` | bool | false |
| `transparency.rekor.timeout` | duration | 15s |
| `transparency.rekor.publicKeyFiles` | []string | [] |

## `anomaly`

| Setting | Type | Default |
|---------|------|---------|
| `anomaly.enabled` | bool | true |
| `anomaly.window` | duration | 0s |
| `anomaly.warnLevel` | string | — |
| `anomaly.blockLevel` | string | — |
| `anomaly.thresholds.fanoutWarn` | int | 0 |
| `anomaly.thresholds.fanoutHigh` | int | 0 |
| `anomaly.thresholds.newNamespaceWarn` | int | 0 |
| `anomaly.thresholds.newNamespaceHigh` | int | 0 |
| `anomaly.thresholds.offHoursWarn` | int | 0 |
| `anomaly.thresholds.offHoursHigh` | int | 0 |
| `anomaly.thresholds.enumerationWarn` | int | 0 |
| `anomaly.thresholds.enumerationHigh` | int | 0 |
| `anomaly.thresholds.egressZWarn` | float | 0 |
| `anomaly.thresholds.egressZHigh` | float | 0 |
| `anomaly.offHoursStart` | int | 20 |
| `anomaly.offHoursEnd` | int | 6 |
| `anomaly.timezone` | string | — |
| `anomaly.historySize` | int | 0 |
| `anomaly.alertCooldown` | duration | 0s |
| `anomaly.maxScopes` | int | 0 |
| `anomaly.tenants.<string>.thresholds.fanoutWarn` | int | — |
| `anomaly.tenants.<string>.thresholds.fanoutHigh` | int | — |
| `anomaly.tenants.<string>.thresholds.newNamespaceWarn` | int | — |
| `anomaly.tenants.<string>.thresholds.newNamespaceHigh` | int | — |
| `anomaly.tenants.<string>.thresholds.offHoursWarn` | int | — |
| `anomaly.tenants.<string>.thresholds.offHoursHigh` | int | — |
| `anomaly.tenants.<string>.thresholds.enumerationWarn` | int | — |
| `anomaly.tenants.<string>.thresholds.enumerationHigh` | int | — |
| `anomaly.tenants.<string>.thresholds.egressZWarn` | float | — |
| `anomaly.tenants.<string>.thresholds.egressZHigh` | float | — |
| `anomaly.tenants.<string>.warnLevel` | string | — |
| `anomaly.tenants.<string>.blockLevel` | string | — |

## `approvals`

| Setting | Type | Default |
|---------|------|---------|
| `approvals.enabled` | bool | false |
| `approvals.requiredApprovers` | int | 1 |
| `approvals.grantTtl` | duration | 1h0m0s |
| `approvals.requestTtl` | duration | 72h0m0s |
| `approvals.sweepInterval` | duration | 1m0s |
| `approvals.maxRequests` | int | 0 |
| `approvals.storePath` | string | — |

## `metering`

| Setting | Type | Default |
|---------|------|---------|
| `metering.enabled` | bool | false |
| `metering.retentionHours` | int | 0 |
| `metering.rollupInterval` | duration | 0s |
| `metering.statePath` | string | — |
| `metering.defaultScanCostMicros` | int | 0 |
| `metering.scanCostMicros` | map[string]int | {} |
| `metering.budgets.<string>.maxBytes` | int | — |
| `metering.budgets.<string>.maxScanCostMicros` | int | — |

## `secrets`

| Setting | Type | Default |
|---------|------|---------|
| `secrets.keyEnv` | string | — |
| `secrets.keyFile` | string | — |
| `secrets.passphrase` | string | — |
| `secrets.salt` | string | — |
| `secrets.vault.enabled` | bool | false |
| `secrets.vault.address` | string | — |
| `secrets.vault.namespace` | string | — |
| `secrets.vault.kvMount` | string | — |
| `secrets.vault.authMethod` | string | — |
| `secrets.vault.token` | string | — |
| `secrets.vault.roleId` | string | — |
| `secrets.vault.secretId` | string | — |
| `secrets.vault.approleMount` | string | — |
| `secrets.vault.refreshInterval` | duration | 0s |
| `secrets.vault.requestTimeout` | duration | 0s |
| `secrets.vault.caCertFile` | string | — |
| `secrets.vault.tlsSkipVerify` | bool | false |

## `auth`

| Setting | Type | Default |
|---------|------|---------|
| `auth.enabled` | bool | false |
| `auth.allowAnonymous` | bool | false |
| `auth.anonymousTeam` | string | — |
| `auth.anonymousRoles` | []string | [] |
| `auth.cacheNamespacing` | bool | false |
| `auth.tokens[].name` | string | — |
| `auth.tokens[].team` | string | — |
| `auth.tokens[].roles` | []string | — |
| `auth.tokens[].token` | string | — |
| `auth.tokens[].tokenHash` | string | — |
| `auth.roles[].name` | string | — |
| `auth.roles[].ecosystems` | []string | — |
| `auth.roles[].upstreams` | []string | — |
| `auth.teams.<string>.quota.maxRequests` | int | — |
| `auth.teams.<string>.quota.maxBytes` | int | — |
| `auth.teams.<string>.quota.window` | duration | — |
| `auth.teams.<string>.rateLimit.rps` | float | — |
| `auth.teams.<string>.rateLimit.burst` | int | — |
| `auth.teams.<string>.rateLimit.maxConcurrent` | int | — |
| `auth.teams.<string>.rateLimit.byteQuota` | int | — |
| `auth.teams.<string>.rateLimit.window` | duration | — |
| `auth.defaultQuota.maxRequests` | int | 0 |
| `auth.defaultQuota.maxBytes` | int | 0 |
| `auth.defaultQuota.window` | duration | 0s |
| `auth.oidc.enabled` | bool | false |
| `auth.oidc.issuer` | string | — |
| `auth.oidc.audience` | string | — |
| `auth.oidc.jwksUrl` | string | — |
| `auth.oidc.jwks` | string | — |
| `auth.oidc.subjectClaim` | string | — |
| `auth.oidc.teamClaim` | string | — |
| `auth.oidc.rolesClaim` | string | — |
| `auth.oidc.roleMap` | map[string]string | {} |
| `auth.oidc.jwksCacheTtl` | duration | 0s |
| `auth.oidc.leeway` | duration | 0s |

## `clientAuth`

| Setting | Type | Default |
|---------|------|---------|
| `clientAuth.mtls.enabled` | bool | false |
| `clientAuth.mtls.required` | bool | false |
| `clientAuth.mtls.trustBundle` | string | — |
| `clientAuth.mtls.trustBundleFormat` | string | — |
| `clientAuth.mtls.trustDomain` | string | — |
| `clientAuth.mtls.allowedTrustDomains` | []string | [] |
| `clientAuth.mtls.reloadInterval` | duration | 0s |
| `clientAuth.mtls.expiryWarning` | duration | 0s |
| `clientAuth.mtls.defaultTenant` | string | — |
| `clientAuth.mtls.rules[].pattern` | string | — |
| `clientAuth.mtls.rules[].tenant` | string | — |
| `clientAuth.mtls.rules[].roles` | []string | — |
| `clientAuth.mtls.tenantOverrides` | map[string][]object | {} |

## `audit`

| Setting | Type | Default |
|---------|------|---------|
| `audit.enabled` | bool | false |
| `audit.file` | string | — |
| `audit.hmacKey` | string | — |
| `audit.hmacKeyEnv` | string | — |
| `audit.transparency.disabled` | bool | false |
| `audit.transparency.origin` | string | — |
| `audit.transparency.checkpointFile` | string | — |
| `audit.transparency.sealEvery` | int | 0 |
| `audit.transparency.sealInterval` | duration | 0s |
| `audit.transparency.signingKeyFile` | string | — |
| `audit.transparency.signingKey` | string | — |

## `backup`

| Setting | Type | Default |
|---------|------|---------|
| `backup.dir` | string | — |
| `backup.interval` | duration | 0s |
| `backup.retain` | int | 0 |
| `backup.encrypt` | bool | false |
| `backup.passphrase` | string | — |
| `backup.keyFile` | string | — |
| `backup.includeCache` | bool | — |
| `backup.alertAfter` | duration | 0s |

## `simReplay`

| Setting | Type | Default |
|---------|------|---------|
| `simReplay.enabled` | bool | true |
| `simReplay.capacity` | int | 0 |
| `simReplay.sampleRate` | int | 0 |
| `simReplay.redact` | bool | — |

## `coordination`

| Setting | Type | Default |
|---------|------|---------|
| `coordination.enabled` | bool | false |
| `coordination.mode` | string | `memory` |
| `coordination.nodeId` | string | — |
| `coordination.leaseTtl` | duration | 30s |
| `coordination.renewInterval` | duration | 10s |
| `coordination.retryInterval` | duration | 10s |
| `coordination.jobTtls` | map[string]duration | {} |
| `coordination.s3.endpoint` | string | — |
| `coordination.s3.region` | string | — |
| `coordination.s3.bucket` | string | — |
| `coordination.s3.prefix` | string | — |
| `coordination.s3.accessKeyId` | string | — |
| `coordination.s3.secretAccessKey` | string | — |
| `coordination.s3.sessionToken` | string | — |
| `coordination.s3.usePathStyle` | bool | false |
| `coordination.s3.insecureSkipVerify` | bool | false |
| `coordination.s3.maxRetries` | int | 0 |
| `coordination.dir` | string | — |

## `fips`

| Setting | Type | Default |
|---------|------|---------|
| `fips.enabled` | bool | false |
| `fips.requireModule` | bool | — |

## `siem`

| Setting | Type | Default |
|---------|------|---------|
| `siem.enabled` | bool | false |
| `siem.queueSize` | int | 0 |
| `siem.batchSize` | int | 0 |
| `siem.batchTimeout` | duration | 0s |
| `siem.maxRetries` | int | 0 |
| `siem.retryBaseDelay` | duration | 0s |
| `siem.retryMaxDelay` | duration | 0s |
| `siem.timeout` | duration | 0s |
| `siem.minSeverity` | string | — |
| `siem.forwardAudit` | bool | — |
| `siem.forwardFindings` | bool | — |
| `siem.spill.enabled` | bool | false |
| `siem.spill.file` | string | — |
| `siem.spill.maxBytes` | int | 0 |
| `siem.ocsf.schemaVersion` | string | — |
| `siem.ocsf.classMap` | map[string]string | {} |
| `siem.ocsf.productName` | string | — |
| `siem.ocsf.vendorName` | string | — |
| `siem.sinks[].name` | string | — |
| `siem.sinks[].kind` | string | — |
| `siem.sinks[].url` | string | — |
| `siem.sinks[].token` | string | — |
| `siem.sinks[].authHeader` | string | — |
| `siem.sinks[].authScheme` | string | — |
| `siem.sinks[].index` | string | — |
| `siem.sinks[].source` | string | — |
| `siem.sinks[].sourceType` | string | — |
| `siem.sinks[].host` | string | — |
| `siem.sinks[].headers` | map[string]string | {} |
| `siem.sinks[].address` | string | — |
| `siem.sinks[].network` | string | — |
| `siem.sinks[].facility` | int | — |
| `siem.sinks[].hostname` | string | — |
| `siem.sinks[].appName` | string | — |
| `siem.sinks[].vendor` | string | — |
| `siem.sinks[].product` | string | — |
| `siem.sinks[].version` | string | — |
| `siem.sinks[].tls.insecureSkipVerify` | bool | — |
| `siem.sinks[].tls.caFile` | string | — |
| `siem.sinks[].tls.serverName` | string | — |
| `siem.sinks[].tls.minVersion` | string | — |

## `prewarm`

| Setting | Type | Default |
|---------|------|---------|
| `prewarm.enabled` | bool | false |
| `prewarm.interval` | duration | 0s |
| `prewarm.offPeakStart` | string | — |
| `prewarm.offPeakEnd` | string | — |
| `prewarm.offPeakTimezone` | string | — |
| `prewarm.maxConcurrency` | int | 0 |
| `prewarm.maxPerCycle` | int | 0 |
| `prewarm.ratePerMinute` | int | 0 |
| `prewarm.minPulls` | int | 0 |
| `prewarm.recencyWindow` | duration | 0s |
| `prewarm.patchLookahead` | int | 0 |
| `prewarm.predictMinor` | bool | false |
| `prewarm.transitiveDeps` | bool | false |
| `prewarm.historySize` | int | 0 |
| `prewarm.historyPath` | string | — |

## `cacheFed`

| Setting | Type | Default |
|---------|------|---------|
| `cacheFed.enabled` | bool | false |
| `cacheFed.serve` | bool | — |
| `cacheFed.peers[].name` | string | — |
| `cacheFed.peers[].url` | string | — |
| `cacheFed.auth.secretRef` | string | — |
| `cacheFed.maxPeerFanout` | int | 2 |
| `cacheFed.peerTimeout` | duration | 3s |
| `cacheFed.hedgeDelay` | duration | 150ms |
| `cacheFed.requireDigest` | bool | — |
| `cacheFed.failureThreshold` | int | 3 |
| `cacheFed.successThreshold` | int | 2 |
| `cacheFed.openTimeout` | duration | 30s |
| `cacheFed.halfOpenMaxProbes` | int | 1 |

## `sbomExport`

| Setting | Type | Default |
|---------|------|---------|
| `sbomExport.enabled` | bool | false |
| `sbomExport.includeFindings` | bool | — |
| `sbomExport.minSeverity` | string | — |
| `sbomExport.interval` | duration | 0s |
| `sbomExport.maxRetries` | int | 3 |
| `sbomExport.retryBaseDelay` | duration | 500ms |
| `sbomExport.retryMaxDelay` | duration | 30s |
| `sbomExport.timeout` | duration | 30s |
| `sbomExport.dependencyTrack.enabled` | bool | false |
| `sbomExport.dependencyTrack.url` | string | — |
| `sbomExport.dependencyTrack.apiKey` | string | — |
| `sbomExport.dependencyTrack.autoCreate` | bool | — |
| `sbomExport.dependencyTrack.parentProject` | string | — |
| `sbomExport.dependencyTrack.tlsSkipVerify` | bool | false |
| `sbomExport.guac.enabled` | bool | false |
| `sbomExport.guac.url` | string | — |
| `sbomExport.guac.token` | string | — |
| `sbomExport.guac.documentType` | string | — |
| `sbomExport.guac.tlsSkipVerify` | bool | false |

## `keyRotation`

| Setting | Type | Default |
|---------|------|---------|
| `keyRotation.enabled` | bool | true |
| `keyRotation.scanInterval` | duration | 6h0m0s |
| `keyRotation.warnThreshold` | duration | 336h0m0s |
| `keyRotation.criticalThreshold` | duration | 72h0m0s |
| `keyRotation.overlapWindow` | duration | 24h0m0s |
| `keyRotation.certificates[].id` | string | — |
| `keyRotation.certificates[].path` | string | — |
| `keyRotation.certificates[].kind` | string | — |
| `keyRotation.certificates[].description` | string | — |
| `keyRotation.policies[].material` | string | — |
| `keyRotation.policies[].rotateEvery` | duration | — |

## `webauthn`

| Setting | Type | Default |
|---------|------|---------|
| `webauthn.enabled` | bool | false |
| `webauthn.enforce` | bool | — |
| `webauthn.rpId` | string | — |
| `webauthn.rpName` | string | — |
| `webauthn.origins` | []string | [] |
| `webauthn.requireUserVerification` | bool | — |
| `webauthn.challengeTtl` | duration | 0s |
| `webauthn.stepUpTtl` | duration | 0s |
| `webauthn.allowUnverifiedAttestation` | bool | — |
| `webauthn.protectedActions` | []string | [] |
| `webauthn.storePath` | string | — |

