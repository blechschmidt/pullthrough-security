# Makefile for the pull-through security proxy.

# Allow Go to be located outside the default PATH (common in CI images).
export PATH := /usr/local/go/bin:$(PATH)

BINARY      := pullthrough
CLIENT      := ptctl
PKG         := github.com/blechschmidt/pullthrough-security
CMD         := ./cmd/pullthrough
CLIENT_CMD  := ./cmd/ptctl
BIN_DIR     := bin
VERSION     ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS     := -X main.version=$(VERSION)

# Container image coordinates and chart location.
IMAGE_REPO  ?= ghcr.io/blechschmidt/pullthrough-security
IMAGE_TAG   ?= $(VERSION)
IMAGE       := $(IMAGE_REPO):$(IMAGE_TAG)
HELM_CHART  := deploy/helm/pullthrough

GO          ?= go
GOFLAGS     ?=

.DEFAULT_GOAL := build

.PHONY: all
all: tidy fmt vet test build

.PHONY: tidy
tidy: ## Sync go.mod/go.sum
	$(GO) mod tidy

.PHONY: fmt
fmt: ## Format all Go sources
	$(GO) fmt ./...

.PHONY: vet
vet: ## Run go vet static checks
	$(GO) vet ./...

.PHONY: test
test: ## Run the test suite
	$(GO) test $(GOFLAGS) ./...

.PHONY: test-integration
test-integration: ## Run integration tests (needs MinIO/Git fixtures; see docs)
	$(GO) test -tags integration $(GOFLAGS) ./...

# --- Download log: which package was downloaded from which address (Task 176) --
#
# The integration suite of the admin console's download log, with the Rust and
# Go ecosystems: the real `cargo` and `go` clients fetch packages from stub
# registries through the real proxy binary, every client machine from its own
# source address; the log is asserted through the admin API. Hermetic (loopback
# only). A missing package manager falls back to a scripted client unless
# PT_DOWNLOADLOG_CLIENTS=real. See docs/download-log.md.
.PHONY: test-download-log
test-download-log: ## Download-log integration suite: real cargo & go through the proxy, one address per client (hermetic)
	$(GO) test -tags integration -count=1 -v ./internal/e2e/downloadlog/

# --- LLM package-content scan, every ecosystem end to end (Task 175) ---------
#
# For every upstream type the configuration accepts, the real `pullthrough`
# binary — started from a configuration file with llmPackageScan enabled —
# pulls packages in that ecosystem's own format from a stub registry, while a
# mock LLM endpoint (Anthropic and OpenAI wire formats) stands in for the model:
# a benign package is served and the model saw its marker file; a flagged one
# is refused (403), quarantined, recorded as a finding and in the audit log;
# verdicts are reused across pulls and restarts; failMode closed/open with a
# provider error and a timeout; a prompt injection inside the package does not
# turn the verdict. Git rows: LFS objects, and the commit scan still gating the
# packages built from a flagged commit. Writes the ecosystem × scenario matrix
# (llm-package-scan-matrix.{md,json}) to PT_TEST_REPORT_DIR and fails when an
# upstream type has no fully passing row. Hermetic (loopback only, no LLM API).
#
#   make test-llm-package-scan                                  # every ecosystem
#   make test-llm-package-scan PKGSCAN_ECOSYSTEMS="npm docker"   # a selection
PKGSCAN_ECOSYSTEMS ?=
.PHONY: test-llm-package-scan
test-llm-package-scan: ## LLM package-scan e2e suite: every ecosystem through the real proxy with a mock LLM (hermetic)
	PT_PKGSCAN_ECOSYSTEMS="$(PKGSCAN_ECOSYSTEMS)" $(GO) test -tags integration -count=1 -v ./internal/e2e/pkgscan/

# --- Personal cache links: who downloaded what (Task 177) ---------------------
#
# The integration suite of personal cache links: two users sign in at an OpenID
# Connect identity provider (a real one in miniature: discovery, authorization
# code with PKCE, RS256 ID tokens), get a personal link each, and install a
# package with the real `npm`, `pip`, `cargo` and `go` — configured with the
# snippet the links page hands out — through the real proxy binary. The suite
# asserts through the admin API that the download log tells the two users apart
# although both ran on one machine, that a revoked link stops working (on a
# second replica too), and that no link's token is in anything the proxy wrote
# or sent upstream. Hermetic (loopback only). A missing package manager is
# skipped unless PT_USERLINKS_CLIENTS=real. See docs/user-links.md.
.PHONY: test-user-links
test-user-links: ## Personal-links integration suite: OIDC sign-in, real npm/pip/cargo/go through personal links (hermetic)
	$(GO) test -tags integration -count=1 -v ./internal/e2e/userlinks/

# --- Ecosystem tests: real package managers through the proxy (Task 170) -----
#
# For every supported ecosystem, run the ecosystem's REAL client (npm, pip,
# cargo, go, dotnet, mvn, docker, helm, bundler, composer, terraform, conan,
# conda, apt-get, dnf, git, mix, bazel, julia, cpanm, R, dart pub, ovsx, nix,
# deno, cabal, brew, ansible-galaxy, r10k, huggingface_hub) — configured to use
# the pull-through proxy — against the
# real proxy binary and the real upstream registry, with a mock LLM scanning the
# packages' source commits: a good package installs (and re-installs from the
# cache), a bad package is refused. Needs Docker and network access; each client
# runs in its ecosystem's official image, so no other toolchain is required.
# See docs/ecosystem-tests.md.
#
#   make test-ecosystems                       # every ecosystem
#   make test-ecosystems ECOSYSTEMS="npm pip"  # a selection
#   make test-ecosystems ECOSYSTEMS=npm ECOTEST_KEEP=1 ECOTEST_WORKDIR=/tmp/eco
#
# CGO is disabled so the test binary is statically linked: it is re-executed
# inside every client image as the loopback forwarder that makes the proxy the
# only thing a (network-less) client container can reach.
ECOSYSTEMS ?=

.PHONY: test-ecosystems
test-ecosystems: ## Run each ecosystem's real package manager through the proxy (needs Docker); ECOSYSTEMS="npm pip" selects
	CGO_ENABLED=0 ECOTEST_ECOSYSTEMS="$(ECOSYSTEMS)" $(GO) test -tags ecosystem -count=1 -v -timeout 360m \
		-run '^TestEcosystems$$' ./internal/ecotest/

.PHONY: test-ecosystems-list
test-ecosystems-list: ## List the ecosystems the real-package-manager suite covers
	@CGO_ENABLED=0 $(GO) test -tags ecosystem -c -o $(BIN_DIR)/ecotest.test ./internal/ecotest && \
		ECOTEST_LIST=1 $(BIN_DIR)/ecotest.test

# --- Client lab: the client guide, executed (Task 171) -------------------------
#
# Every client configuration docs/clients/ prints is run by a script in
# scripts/client-lab/clients with the REAL client against the real proxy, served
# as https://proxy.example.com with a private CA — without access control, with a
# required token, and with an anonymous role — on a network where the proxy is
# the only host the client can reach and every name it looks up is recorded (a
# client that tries to go around the proxy fails its run). Needs Docker, openssl
# and network access. See docs/client-lab.md.
#
#   make client-lab                          # everything (takes a while)
#   make client-lab CLIENTS="npm yarn pnpm"  # a selection
#   make client-lab-report                   # write the result table into docs/client-lab.md
#                                            # (refused while a script is missing, failing
#                                            # or changed since it ran)
#   make client-lab-down
#
# `go test ./internal/clientguide/` (part of `make test`) holds the guide to
# these scripts: every line of a snippet marked as verified must be a line the
# script it names executes — and the result table to the scripts as they are: a
# script that was edited has to be run again.
CLIENTS ?=
CLIENT_LAB := scripts/client-lab/lab.sh

.PHONY: client-lab
client-lab: ## Run the client guide's configurations with the real clients (needs Docker); CLIENTS="npm pip" selects
	$(CLIENT_LAB) up
	@if [ -n "$(CLIENTS)" ]; then \
		rc=0; for c in $(CLIENTS); do $(CLIENT_LAB) run "$$c" || rc=1; done; exit $$rc; \
	else \
		$(CLIENT_LAB) all; \
	fi

.PHONY: client-lab-report
client-lab-report: ## Write the client lab's result table into docs/client-lab.md
	@$(CLIENT_LAB) document

.PHONY: client-lab-down
client-lab-down: ## Stop the client lab's proxies and remove its networks
	$(CLIENT_LAB) down

# --- Coverage guard (Task 117) ----------------------------------------------
#
# `covguard` runs the suite with coverage, aggregates per-package + total
# statement coverage, and fails when total coverage drops beyond a threshold or
# a critical package falls under its floor — the coverage analogue of
# `perfguard`. The committed baseline lives at coverage/coverage-baseline.json.
COVGUARD        := $(BIN_DIR)/$(CLIENT)
COV_ALLOWED_DROP ?= 1.0

.PHONY: covguard
covguard: build-client ## Measure coverage and fail on a regression vs coverage/coverage-baseline.json
	$(COVGUARD) covguard --allowed-drop $(COV_ALLOWED_DROP) --go "$(GO)" \
		--json-out coverage/coverage-report.json --md-out coverage/coverage-summary.md

.PHONY: covguard-baseline
covguard-baseline: build-client ## Re-seed the committed coverage baseline from the current suite
	$(COVGUARD) covguard --update-baseline --go "$(GO)"

.PHONY: coverage-html
coverage-html: ## Write coverage.out and render an HTML coverage report
	$(GO) test ./... -coverprofile=coverage.out -covermode=set
	$(GO) tool cover -html=coverage.out

# --- Mutation-testing / test-quality gate (Task 157) ------------------------
#
# `mutguard` measures the *fault-detection* strength of the unit suite for the
# highest-risk admission-gate packages: it seeds behavior-changing mutants
# (flipped comparisons/logical operators, swapped boolean constants, negated
# conditions, …) into their source, recompiles and reruns each package's tests,
# and reports the mutation score (killed / (killed+survived)). It is the
# fault-detection analogue of `covguard` — where coverage asks "did a test run
# this line?", mutation testing asks "would a test *fail* if the line were
# wrong?". The committed per-package baseline + critical floors live at
# mutation/mutation-baseline.json; the run is seeded so CI is deterministic.
MUTGUARD           := $(BIN_DIR)/$(CLIENT)
MUT_PACKAGES       ?=
MUT_MAX_PER_PACKAGE ?= 60
MUT_SEED           ?= 1
MUT_ALLOWED_DROP   ?= 2.0

.PHONY: mutation
mutation: build-client ## Run mutation testing and fail on a regression vs mutation/mutation-baseline.json
	$(MUTGUARD) mutguard --allowed-drop $(MUT_ALLOWED_DROP) --seed $(MUT_SEED) \
		--max-per-package $(MUT_MAX_PER_PACKAGE) --go "$(GO)" \
		$(if $(MUT_PACKAGES),--packages "$(MUT_PACKAGES)",) \
		--json-out mutation/mutation-report.json --md-out mutation/mutation-summary.md

.PHONY: mutation-baseline
mutation-baseline: build-client ## Re-seed the committed mutation-score baseline from the current suite
	$(MUTGUARD) mutguard --update-baseline --seed $(MUT_SEED) \
		--max-per-package $(MUT_MAX_PER_PACKAGE) --go "$(GO)" \
		$(if $(MUT_PACKAGES),--packages "$(MUT_PACKAGES)",)

.PHONY: redteam
redteam: ## Run the supply-chain attack red-team / gate-efficacy suite (Task 76)
	$(GO) test $(GOFLAGS) ./internal/redteam/...

.PHONY: chaos
chaos: ## Run the chaos / fault-injection resilience suite (Task 98)
	$(GO) test $(GOFLAGS) ./internal/chaos/...

.PHONY: resilience-matrix
resilience-matrix: ## Regenerate docs/resilience-matrix.md from the chaos catalog
	$(GO) run ./internal/chaos/internal/matrixgen > docs/resilience-matrix.md

# --- Fuzzing ----------------------------------------------------------------
#
# Native Go fuzz targets (testing.F) harden the proxy's untrusted-input parsers
# against malicious upstream registries: package-manager index/metadata, OCI
# manifests, SBOM/VEX/CSAF ingestion, SPDX license expressions, known-malicious
# feed records, and signed offline bundles. They live in
# `_test.go` files gated behind the `fuzz` build tag (mirroring the `integration`
# convention) so the default `make test` stays fast and deterministic.
#
# FUZZTIME bounds each target. The default keeps `make fuzz` quick for local use;
# CI runs a long, scheduled job with a larger value (see docs/testing.md).
FUZZTIME ?= 20s

# Every fuzz target, as "<package>:<FuzzFunc>". `go test -fuzz` runs one target
# per package, so each is invoked individually.
FUZZ_TARGETS := \
	internal/license:FuzzParseExpression \
	internal/backends/pkgmgr:FuzzApplyRules \
	internal/backends/pkgmgr:FuzzRewriteCargoConfig \
	internal/backends/pkgmgr:FuzzMaybeGunzip \
	internal/backends/pkgmgr:FuzzPipNameVersion \
	internal/backends/pkgmgr:FuzzClassify \
	internal/backends/docker:FuzzParseReference \
	internal/backends/docker:FuzzParseDigest \
	internal/backends/maven:FuzzClassify \
	internal/backends/maven:FuzzParsePOM \
	internal/backends/maven:FuzzParseMetadata \
	internal/backends/maven:FuzzParseChecksumValue \
	internal/backends/rubygems:FuzzClassify \
	internal/backends/rubygems:FuzzParseInfo \
	internal/backends/composer:FuzzClassify \
	internal/backends/composer:FuzzParseMetadata \
	internal/backends/composer:FuzzParseRoot \
	internal/backends/helm:FuzzClassify \
	internal/backends/helm:FuzzParseIndex \
	internal/backends/terraform:FuzzClassify \
	internal/backends/terraform:FuzzParseTerraformGet \
	internal/backends/terraform:FuzzParseProviderPackage \
	internal/backends/terraform:FuzzParseSHASUMS \
	internal/backends/conan:FuzzClassify \
	internal/backends/conan:FuzzParseManifest \
	internal/backends/conan:FuzzHeaderMD5 \
	internal/backends/swift:FuzzClassify \
	internal/backends/swift:FuzzParseReleaseMetadata \
	internal/backends/dart:FuzzClassify \
	internal/backends/dart:FuzzParseVersionList \
	internal/backends/dart:FuzzRewriteArchiveURLs \
	internal/backends/conda:FuzzClassify \
	internal/backends/conda:FuzzRepodataChecksum \
	internal/backends/cran:FuzzClassify \
	internal/backends/cran:FuzzParsePackages \
	internal/backends/hex:FuzzClassify \
	internal/backends/hex:FuzzParsePackageResource \
	internal/backends/bazel:FuzzClassify \
	internal/backends/bazel:FuzzParseSource \
	internal/backends/bazel:FuzzParseIntegrity \
	internal/backends/bazel:FuzzArchiveFileName \
	internal/vulnscan:FuzzExtract \
	internal/vulnscan:FuzzParseVEX \
	internal/vulnscan:FuzzParseGoRequires \
	internal/vulnscan:FuzzParseNuspec \
	internal/vulnscan:FuzzOSVRecord \
	internal/vulnscan:FuzzParseCVSSBaseScore \
	internal/sigverify:FuzzOCIManifest \
	internal/buildprov:FuzzParseAttestations \
	internal/findings:FuzzFindingsSARIF \
	internal/attestbundle:FuzzVerifyEnvelope \
	internal/malfeed:FuzzParseOSVStream \
	internal/malfeed:FuzzImportBundle \
	internal/spiffe:FuzzParseID \
	internal/spiffe:FuzzParseTrustBundle \
	internal/extension:FuzzHostInputRoundTrip \
	internal/extension:FuzzParseVerdict \
	internal/installhooks:FuzzParsePackageJSONScripts \
	internal/installhooks:FuzzParseGemspecMetadata \
	internal/installhooks:FuzzParseCargoBuildField \
	internal/installhooks:FuzzParsePyprojectBuildBackend \
	internal/installhooks:FuzzExtractHooks \
	internal/actionpin:FuzzParseContent \
	internal/actionpin:FuzzClassify \
	internal/actionpin:FuzzParseUsesValue \
	internal/contentscan:FuzzAssess \
	internal/contentscan:FuzzWalkArchive \
	internal/contentscan:FuzzWalkArtifact \
	internal/contentscan:FuzzObfuscatedJS \
	internal/contentscan:FuzzScanExecLine \
	internal/contentscan:FuzzSynthesizeAddedPatch \
	internal/llmpkgscan:FuzzParseVerdict \
	internal/llmpkgscan:FuzzSafePath \
	internal/llmpkgscan:FuzzBuildTree \
	internal/llmpkgscan:FuzzToolCalls \
	internal/clientip:FuzzResolve \
	internal/clientip:FuzzForgedPrefixCannotMoveTheClient \
	internal/downloadlog:FuzzClean \
	internal/downloadlog:FuzzGlobMatch \
	internal/downloadlog:FuzzQueryFromValues \
	internal/downloadlog:FuzzWriteCSV \
	internal/downloadlog:FuzzLoad \
	internal/repos/locate:FuzzParseSimplePage \
	internal/repos/locate:FuzzLocateDocker \
	internal/repos/locate:FuzzLocatePaths \
	internal/repos/locate:FuzzCheckerModuleZip \
	internal/repos/locate:FuzzParseNPMPackument \
	internal/repos/locate:FuzzParseCargoIndex \
	internal/repos/locate:FuzzGoModRequires \
	internal/repos:FuzzUpdaterInputs \
	internal/git:FuzzFetchSniffer \
	internal/git:FuzzDescribeDownload \
	internal/git:FuzzAsksForNothingButRefs \
	internal/userlinks:FuzzWellFormed \
	internal/userlinks:FuzzCleanText \
	internal/userlinks:FuzzDecodeCookie \
	internal/userlinks:FuzzLoadLink \
	internal/proxy:FuzzLinkRewriter \
	internal/proxy:FuzzRedactPersonalPath \
	internal/git:FuzzParseTree \
	internal/versions:FuzzNpm \
	internal/versions:FuzzCargo \
	internal/versions:FuzzPip \
	internal/versions:FuzzGo \
	internal/versions:FuzzNuGet \
	internal/versions:FuzzMaven \
	internal/versions:FuzzRubyGems \
	internal/repos/update:FuzzNpmLockUpdate \
	internal/repos/update:FuzzRequirementsUpdate \
	internal/repos/update:FuzzCargoLockUpdate \
	internal/repos/update:FuzzGoModUpdate \
	internal/repos/update:FuzzJSONScanner \
	internal/lockfiles:FuzzPackageLock \
	internal/lockfiles:FuzzNpmShrinkwrap \
	internal/lockfiles:FuzzYarnLock \
	internal/lockfiles:FuzzPnpmLock \
	internal/lockfiles:FuzzRequirementsTxt \
	internal/lockfiles:FuzzPipfileLock \
	internal/lockfiles:FuzzPoetryLock \
	internal/lockfiles:FuzzUVLock \
	internal/lockfiles:FuzzPDMLock \
	internal/lockfiles:FuzzCargoLock \
	internal/lockfiles:FuzzGoMod \
	internal/lockfiles:FuzzGoSum \
	internal/lockfiles:FuzzNuGetLock \
	internal/lockfiles:FuzzGradleLock \
	internal/lockfiles:FuzzPOM \
	internal/lockfiles:FuzzGemfileLock \
	internal/lockfiles:FuzzComposerLock \
	internal/lockfiles:FuzzDockerfile \
	internal/lockfiles:FuzzCompose \
	internal/lockfiles:FuzzGitmodules \
	internal/lockfiles:FuzzCondaLock \
	internal/lockfiles:FuzzCondaExplicit \
	internal/lockfiles:FuzzPixiLock \
	internal/lockfiles:FuzzRenvLock \
	internal/lockfiles:FuzzMixLock \
	internal/lockfiles:FuzzPackageResolved \
	internal/lockfiles:FuzzPubspecLock \
	internal/lockfiles:FuzzJuliaManifest \
	internal/lockfiles:FuzzModuleBazelLock \
	internal/lockfiles:FuzzFlakeLock \
	internal/lockfiles:FuzzTerraformLock \
	internal/lockfiles:FuzzTerraformModules \
	internal/lockfiles:FuzzTerraformOverrides \
	internal/lockfiles:FuzzTerraformMerge \
	internal/lockfiles:FuzzConanLock \
	internal/lockfiles:FuzzCpanfileSnapshot \
	internal/lockfiles:FuzzCabalFreeze \
	internal/lockfiles:FuzzStackLock \
	internal/lockfiles:FuzzDenoLock \
	internal/lockfiles:FuzzChartLock \
	internal/lockfiles:FuzzRequirementsLock \
	internal/lockfiles:FuzzBrewfileLock \
	internal/lockfiles:FuzzAnsibleRequirements \
	internal/lockfiles:FuzzPuppetfile \
	internal/lockfiles:FuzzHCL \
	internal/lockfiles:FuzzGitConfig \
	internal/lockfiles:FuzzElixirTerms \
	internal/lockfiles:FuzzTOML \
	internal/lockfiles:FuzzProxyMapping \
	internal/lockfiles:FuzzNPMRequirements \
	internal/lockfiles:FuzzCargoManifests \
	internal/lockfiles:FuzzPythonRequirements \
	internal/lockfiles:FuzzOverrides

# The targets can be split into FUZZ_SHARDS slices, FUZZ_SHARD (0-based)
# selecting one: target i belongs to shard i mod FUZZ_SHARDS. The nightly CI
# job runs the slices in parallel — one after another, the targets take longer
# than a CI job may run.
FUZZ_SHARDS ?= 1
FUZZ_SHARD ?= 0

.PHONY: fuzz
fuzz: ## Fuzz every parser target for FUZZTIME each (e.g. make fuzz FUZZTIME=2m; FUZZ_SHARDS=4 FUZZ_SHARD=1 runs a quarter)
	@set -e; i=0; for t in $(FUZZ_TARGETS); do \
		if [ $$((i % $(FUZZ_SHARDS))) -eq $(FUZZ_SHARD) ]; then \
			pkg=$${t%%:*}; fn=$${t##*:}; \
			echo "==> fuzzing $$fn ($$pkg) for $(FUZZTIME)"; \
			$(GO) test -tags fuzz -run='^$$' -fuzz="^$$fn$$" -fuzztime=$(FUZZTIME) ./$$pkg/; \
		fi; \
		i=$$((i + 1)); \
	done

.PHONY: fuzz-seed
fuzz-seed: ## Replay all fuzz seed corpora as fast regression tests (no fuzzing)
	$(GO) test -tags fuzz $(GOFLAGS) ./...

.PHONY: extension-fixtures
extension-fixtures: ## Rebuild the WASM extension-gate fixtures from their Go sources (needs Go 1.24+)
	internal/extension/testdata/build.sh

.PHONY: build
build: ## Build the proxy and client (ptctl) binaries into $(BIN_DIR)
	mkdir -p $(BIN_DIR)
	$(GO) build -ldflags "$(LDFLAGS)" -o $(BIN_DIR)/$(BINARY) $(CMD)
	$(GO) build -ldflags "$(LDFLAGS)" -o $(BIN_DIR)/$(CLIENT) $(CLIENT_CMD)

.PHONY: build-client
build-client: ## Build only the client CLI (ptctl) into $(BIN_DIR)
	mkdir -p $(BIN_DIR)
	$(GO) build -ldflags "$(LDFLAGS)" -o $(BIN_DIR)/$(CLIENT) $(CLIENT_CMD)

# --- FIPS 140-3 build variant (Task 120) ------------------------------------
#
# The FIPS variant links Go's FIPS 140-3 Cryptographic Module (GOFIPS140) and
# carries the `fips` build tag so the binary self-reports its crypto build
# variant. Run the resulting binary with GODEBUG=fips140=on (baked in as the
# default by GOFIPS140) to activate the module, or GODEBUG=fips140=only to make
# any non-approved primitive fail. Pair with `fips.enabled: true` in config so
# startup fails fast if the module is not active. See docs/fips-compliance.md.
GOFIPS140 ?= latest

.PHONY: build-fips
build-fips: ## Build the FIPS 140-3 variant (GOFIPS140 + `fips` tag) into $(BIN_DIR)
	mkdir -p $(BIN_DIR)
	GOFIPS140=$(GOFIPS140) $(GO) build -tags fips -ldflags "$(LDFLAGS)" -o $(BIN_DIR)/$(BINARY)-fips $(CMD)
	GOFIPS140=$(GOFIPS140) $(GO) build -tags fips -ldflags "$(LDFLAGS)" -o $(BIN_DIR)/$(CLIENT)-fips $(CLIENT_CMD)

.PHONY: test-fips
test-fips: ## Run the suite under the FIPS module (GOFIPS140 build + GODEBUG=fips140=on)
	GOFIPS140=$(GOFIPS140) GODEBUG=fips140=on $(GO) test -tags fips $(GOFLAGS) ./...

# --- Self-releasing signed artifacts (Task 135) -----------------------------
#
# A reproducible, provenance-attested, signed release of the proxy's *own*
# binaries — closing the "trust the tool that enforces trust" gap. The build
# itself is delegated to scripts/release-build.sh (shared verbatim with the
# release CI workflow) so a locally reproduced binary is bit-for-bit identical
# to the published one. SBOM generation, SLSA provenance attestation, cosign
# keyless signing, and image signing happen in CI (they need syft/cosign and an
# OIDC identity); the targets below cover the deterministic build, the
# reproducibility proof, the checksums manifest, and a local verify-self smoke
# test. See docs/self-release.md.
DIST_DIR          ?= dist
RELEASE_PLATFORMS ?= linux/amd64 linux/arm64
# Pin to the installed toolchain locally; CI pins the exact Go version via
# setup-go honoring the go.mod `go` directive.
export GOTOOLCHAIN ?= local

.PHONY: release
release: ## Reproducibly build the standard release binaries + checksums into $(DIST_DIR)
	scripts/release-build.sh standard "$(VERSION)" "$(DIST_DIR)" $(RELEASE_PLATFORMS)

.PHONY: release-fips
release-fips: ## Reproducibly build the FIPS 140-3 release binaries + checksums into $(DIST_DIR)-fips
	scripts/release-build.sh fips "$(VERSION)" "$(DIST_DIR)-fips" $(RELEASE_PLATFORMS)

.PHONY: release-repro-check
release-repro-check: ## Prove the standard release build is reproducible (build twice, compare digests)
	scripts/release-repro-check.sh standard "$(VERSION)" $(RELEASE_PLATFORMS)

.PHONY: release-repro-check-fips
release-repro-check-fips: ## Prove the FIPS release build is reproducible (build twice, compare digests)
	scripts/release-repro-check.sh fips "$(VERSION)" $(RELEASE_PLATFORMS)

.PHONY: release-sbom
release-sbom: ## Generate a CycloneDX SBOM per released binary into $(DIST_DIR) (needs syft)
	@command -v syft >/dev/null 2>&1 || { echo "syft not found; install anchore/syft to generate SBOMs"; exit 1; }
	@for b in $(DIST_DIR)/pullthrough* $(DIST_DIR)/ptctl*; do \
		case "$$b" in *.sbom.*|*.json|*SHA256SUMS*) continue;; esac; \
		[ -f "$$b" ] || continue; \
		echo "==> SBOM for $$b"; \
		syft "$$b" -o cyclonedx-json="$$b.sbom.cdx.json"; \
	done

.PHONY: release-verify
release-verify: build-client ## Smoke-test verify-self against the built release directory
	$(BIN_DIR)/$(CLIENT) verify-self --release-dir "$(DIST_DIR)" --binary "$$(ls $(DIST_DIR)/ptctl-* 2>/dev/null | head -1)"

.PHONY: run
run: ## Build and run with configs/config.example.yaml
	$(GO) run $(CMD) -config configs/config.example.yaml

.PHONY: clean
clean: ## Remove build artifacts
	rm -rf $(BIN_DIR)

# --- Containers & deployment ------------------------------------------------

# Platforms the multi-arch container image is built for. Mirrors the release
# workflow and the published-platform matrix in docs/platforms.md.
IMAGE_PLATFORMS ?= linux/amd64,linux/arm64

.PHONY: docker-build
docker-build: ## Build the container image for the host arch ($(IMAGE))
	docker build --build-arg VERSION=$(VERSION) -t $(IMAGE) .

.PHONY: docker-buildx
docker-buildx: ## Build the multi-arch image ($(IMAGE_PLATFORMS)) into the local build cache
	docker buildx build --build-arg VERSION=$(VERSION) \
		--platform $(IMAGE_PLATFORMS) -t $(IMAGE) .

.PHONY: docker-buildx-push
docker-buildx-push: ## Build and push the multi-arch image manifest ($(IMAGE_PLATFORMS))
	docker buildx build --build-arg VERSION=$(VERSION) \
		--platform $(IMAGE_PLATFORMS) --provenance=mode=max --sbom=true \
		-t $(IMAGE) --push .

.PHONY: docker-push
docker-push: ## Push the container image to the registry
	docker push $(IMAGE)

.PHONY: compose-up
compose-up: ## Start the local dev stack (proxy + cache volume)
	docker compose up --build

.PHONY: compose-up-extras
compose-up-extras: ## Start the dev stack incl. Postgres + MinIO
	docker compose --profile extras up --build

.PHONY: compose-up-monitoring
compose-up-monitoring: ## Start the dev stack incl. Prometheus + Grafana
	docker compose --profile monitoring up --build

.PHONY: compose-up-tracing
compose-up-tracing: ## Start the dev stack incl. OpenTelemetry Collector + Jaeger
	docker compose --profile tracing up --build

.PHONY: compose-down
compose-down: ## Stop the local dev stack
	docker compose down

.PHONY: observability-gen
observability-gen: ## Regenerate dashboards/PrometheusRule and re-sync vendored copies
	python3 deploy/observability/grafana/gen_dashboards.py
	python3 deploy/observability/gen_prometheusrule.py
	cp deploy/observability/prometheus/alerts.yaml deploy/helm/pullthrough/files/alerts.yaml
	cp deploy/observability/grafana/dashboards/*.json deploy/helm/pullthrough/dashboards/
	$(MAKE) observability-validate

.PHONY: observability-validate
observability-validate: ## Check dashboards/alerts reference only metrics the code exposes
	python3 deploy/observability/validate.py

.PHONY: proto-gen
proto-gen: ## Regenerate the committed gRPC/Connect Go stubs from proto/ (Task 159; dev-only, not run at build time)
	./scripts/proto-gen.sh

.PHONY: config-reference-gen
config-reference-gen: ## Regenerate docs/configuration-reference.md from the config structs
	$(GO) run ./cmd/gen-config-reference -o docs/configuration-reference.md

.PHONY: config-reference-check
config-reference-check: ## Fail if docs/configuration-reference.md is stale vs the config structs
	$(GO) run ./cmd/gen-config-reference -check -o docs/configuration-reference.md

.PHONY: gate-reference-gen
gate-reference-gen: ## Regenerate docs/gates-reference.md from the admission-gate catalog
	$(GO) run ./cmd/gen-gate-reference -o docs/gates-reference.md

.PHONY: gate-reference-check
gate-reference-check: ## Fail if docs/gates-reference.md is stale vs the gate catalog
	$(GO) run ./cmd/gen-gate-reference -check -o docs/gates-reference.md

.PHONY: ecosystem-reference-gen
ecosystem-reference-gen: ## Regenerate docs/ecosystem-tests-reference.md from the ecosystem test catalog
	$(GO) run ./cmd/gen-ecosystem-reference -o docs/ecosystem-tests-reference.md

.PHONY: ecosystem-reference-check
ecosystem-reference-check: ## Fail if docs/ecosystem-tests-reference.md is stale vs the ecosystem test catalog
	$(GO) run ./cmd/gen-ecosystem-reference -check -o docs/ecosystem-tests-reference.md

.PHONY: llmscan-coverage-gen
llmscan-coverage-gen: ## Regenerate docs/llm-package-scan-coverage.md from the LLM-scan coverage catalog
	$(GO) run ./cmd/gen-llmscan-coverage -o docs/llm-package-scan-coverage.md

.PHONY: llmscan-coverage-check
llmscan-coverage-check: ## Fail if docs/llm-package-scan-coverage.md is stale vs the coverage catalog
	$(GO) run ./cmd/gen-llmscan-coverage -check -o docs/llm-package-scan-coverage.md

.PHONY: lockfile-reference-gen
lockfile-reference-gen: ## Regenerate the format tables of docs/lockfiles.md from the lock-file scanner's tables
	$(GO) run ./cmd/gen-lockfile-reference -o docs/lockfiles.md

.PHONY: lockfile-reference-check
lockfile-reference-check: ## Fail if the format tables of docs/lockfiles.md are stale vs the lock-file scanner
	$(GO) run ./cmd/gen-lockfile-reference -check -o docs/lockfiles.md

.PHONY: config-validate
config-validate: ## Validate a config file: make config-validate CONFIG=path/to/config.yaml
	$(GO) run $(CMD) verify-config -config $(CONFIG)

.PHONY: helm-lint
helm-lint: ## Lint the Helm chart with the CI values
	helm lint $(HELM_CHART) --values $(HELM_CHART)/ci/ct-values.yaml

.PHONY: helm-template
helm-template: ## Render the Helm chart to stdout
	helm template pullthrough $(HELM_CHART) --values $(HELM_CHART)/ci/ct-values.yaml

.PHONY: k8s-render
k8s-render: ## Render the raw kustomize manifests to stdout
	kubectl kustomize deploy/k8s

.PHONY: help
help: ## Show this help
	@grep -hE '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-12s\033[0m %s\n", $$1, $$2}'
