# Documentation

Operator and user documentation for `pullthrough-security`, an enterprise
pull-through proxy focused on software supply-chain security.

## Start here

| If you want to… | Read |
|-----------------|------|
| Understand how the proxy works end to end | [architecture.md](architecture.md) |
| Point your tooling at the proxy (pip, npm, cargo, go, nuget, docker, git) | [clients.md](clients.md) |
| Onboard an ecosystem with no dedicated backend (declarative YAML, no code) | [generic-backend.md](generic-backend.md) |
| Choose explicit sources vs. transparent TLS interception (MITM forward proxy) | [intercept-mode.md](intercept-mode.md) |
| Serve big artifacts with Range/resumable downloads & bounded memory | [range-streaming.md](range-streaming.md) |
| Onboard fast with the client CLI (generate config, self-test, inspect) | [client-cli.md](client-cli.md) |
| Configure the proxy (every field) | [configuration.md](configuration.md) |
| Understand scanning, provenance & policy | [security-model.md](security-model.md) |
| Continuously scan watched Git repos for risky commits (webhook/polling) | [commit-watch.md](commit-watch.md) |
| Verify cosign signatures & SLSA attestations | [sigverify.md](sigverify.md) |
| Verify the proxy binary itself (signed, reproducible, provenance-attested release + `ptctl verify-self`) | [self-release.md](self-release.md) |
| Suppress non-exploitable CVEs with VEX (OpenVEX/CSAF) | [vex.md](vex.md) |
| Down-rank CVEs in unreachable code (Go/npm/Python/Java reachability) | [reachability.md](reachability.md) |
| Enforce license compliance (SPDX allow/deny/review, drift) | [licenses.md](licenses.md) |
| Pin versions / enforce a lockfile allowlist (dependency firewall) | [dependency-firewall.md](dependency-firewall.md) |
| Snapshot/freeze the served dependency state & instant-rollback an incident | [snapshots.md](snapshots.md) |
| Instantly tighten posture during an incident (freeze/strict/block kill-switch) | [lockdown.md](lockdown.md) |
| Enforce supply-chain verdicts on Pod images in Kubernetes (admission webhook) | [admission-webhook.md](admission-webhook.md) |
| Review quarantines & grant time-boxed break-glass exceptions | [approvals.md](approvals.md) |
| Block SSRF / restrict outbound egress (allowlist, private-range, rebinding) | [egress-ssrf.md](egress-ssrf.md) |
| Lock down access (auth, RBAC, tenancy, audit) | [access-control-and-audit.md](access-control-and-audit.md) |
| Run a FIPS 140-3 approved crypto mode & build variant (regulated deployments) | [fips-compliance.md](fips-compliance.md) |
| Secure the admin UI/API with SSO (OIDC/OAuth2) & RBAC | [admin-sso-rbac.md](admin-sso-rbac.md) |
| Require a FIDO2 passkey step-up for the most sensitive admin actions | [webauthn-stepup.md](webauthn-stepup.md) |
| Authenticate workloads with SPIFFE/SVID mTLS (SPIRE, mesh) | [spiffe-mtls.md](spiffe-mtls.md) |
| Alert on security events (webhooks, Slack) | [notifications.md](notifications.md) |
| Stream audit events & gate findings to a SIEM (Splunk HEC, syslog/CEF) | [siem.md](siem.md) |
| Decorate PRs / fail CI with unified SARIF findings | [findings.md](findings.md) |
| Test policy/risk changes against real traffic before rollout | [simreplay.md](simreplay.md) |
| Add custom admission gates with sandboxed WASM modules | [extensions.md](extensions.md) |
| Score the health of a package's source repository (Scorecard-style) | [reposcore.md](reposcore.md) |
| See what changed (deps/licenses/vulns) between two versions of a package | [sbom-diff.md](sbom-diff.md) |
| Know what the proxy defends against (and not) | [threat-model.md](threat-model.md) |
| Measure gate efficacy with synthetic attacks (red-team suite) | [redteam.md](redteam.md) |
| Run it in production (ops, monitoring, incidents) | [runbook.md](runbook.md) |
| Respond to an incident step-by-step (quarantine, kill-switch, DR, key rotation, malware hit) | [incident-response-playbook.md](incident-response-playbook.md) |
| Monitor it (metrics, Grafana dashboards, Prometheus alerts) | [observability.md](observability.md) |
| Benchmark, load-test & profile it (percentiles, throughput, pprof) | [performance.md](performance.md) |
| Watch a real-time SOC view (cross-gate verdicts, posture, live feed) | [secops.md](secops.md) |
| Tour the admin dashboard tab by tab (annotated screenshots) | [admin-ui-walkthrough.md](admin-ui-walkthrough.md) |
| Meet the UI accessibility baseline (WCAG 2.1 AA, keyboard, dark mode) | [accessibility.md](accessibility.md) |
| Ask cross-cutting questions across subsystems (federated query API) | [query-api.md](query-api.md) |
| Give AI agents read-only security context (MCP server) | [mcp-server.md](mcp-server.md) |
| Consume the security data model over gRPC / Connect (gRPC-Web, HTTP-JSON) | [grpc-api.md](grpc-api.md) |
| Trace it (OpenTelemetry, OTLP, Jaeger/Tempo) | [tracing.md](tracing.md) |
| Operate disconnected (pre-warm, export/import, sealed mode) | [air-gapped.md](air-gapped.md) |
| Back up & restore for disaster recovery (RPO/RTO) | [backup-restore.md](backup-restore.md) |
| Scale out with a shared cache (HA, multi-replica) | [ha-shared-cache.md](ha-shared-cache.md) |
| Encrypt the cache at rest (AES-256-GCM envelope, KEK rotation) | [cache-encryption.md](cache-encryption.md) |
| Coordinate scheduled jobs across replicas (leader election) | [coordination.md](coordination.md) |
| Deploy it (Docker, Helm, Kubernetes) | [../deploy/README.md](../deploy/README.md) |
| Know which OS/CPU architectures are supported (amd64, arm64) & how they're tested | [platforms.md](platforms.md) |
| Test & fuzz it (unit, integration, parser fuzzing) | [testing.md](testing.md) |
| See every ecosystem's real package manager install through the proxy (CI-verified client configurations) | [ecosystem-tests.md](ecosystem-tests.md) · [reference](ecosystem-tests-reference.md) |
| Measure coverage & gate regressions (per-package, critical floors) | [coverage.md](coverage.md) |
| Measure test fault-detection & gate test-quality regressions (mutation testing) | [mutation-testing.md](mutation-testing.md) |

## By audience

**Developers / CI consumers** — you just need to fetch packages through the
proxy: [clients.md](clients.md). For one-command onboarding (generate your
config, self-test connectivity, inspect an artifact's verdict), use the client
CLI: [client-cli.md](client-cli.md).

**Platform / security operators** — you run and secure the proxy:
[architecture.md](architecture.md) → [configuration.md](configuration.md) →
[security-model.md](security-model.md) →
[access-control-and-audit.md](access-control-and-audit.md) →
[threat-model.md](threat-model.md) → [runbook.md](runbook.md) →
[../deploy/README.md](../deploy/README.md).

The canonical configuration template, fully annotated, is
[`../configs/config.example.yaml`](../configs/config.example.yaml).
