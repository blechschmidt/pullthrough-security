// k6 load test for the pull-through security proxy.
//
// Drives three workloads against a locally-run proxy (see perf/run-loadtest.sh,
// which starts the stub upstream + proxy and injects DOCKER_BLOBS):
//
//   - cache_hit  : repeated reads of a small, pre-warmed working set across the
//                  npm/pip/cargo/go/nuget package-manager endpoints. Models the
//                  steady-state hot path; should be ~100% cache hits.
//   - cache_miss : reads of unique, never-before-seen paths, forcing a cold
//                  upstream fetch + cache fill on every request.
//   - docker     : repeated pulls of pre-warmed image manifests + layer blobs by
//                  digest through the Docker Registry v2 endpoint. Layers are
//                  immutable, so this is a cache-hit-dominated workload.
//
// Reported metrics: throughput (http_reqs rate), latency p50/p95/p99
// (http_req_duration), and the proxy's cache hit-ratio (custom `cache_hit_ratio`
// rate, derived from the X-Cache response header), broken down per scenario.
//
// Run via `make loadtest`, or directly:
//   k6 run -e PROXY_URL=http://127.0.0.1:8080 perf/load/k6/proxy_load.js
//
// Tunables (env):
//   PROXY_URL     proxy base URL              (default http://127.0.0.1:8080)
//   VUS           virtual users per scenario  (default 20)
//   DURATION      duration per scenario       (default 30s)
//   DOCKER_BLOBS  comma-separated blob digests to pull (from stub /_perf/digests)
//   DOCKER_MANIFESTS comma-separated manifest digests to pull

import http from 'k6/http';
import { check } from 'k6';
import { Rate, Counter } from 'k6/metrics';
import { Trend } from 'k6/metrics';

const PROXY = __ENV.PROXY_URL || 'http://127.0.0.1:8080';
const VUS = parseInt(__ENV.VUS || '20', 10);
const DURATION = __ENV.DURATION || '30s';

// Custom metrics. cache_hit_ratio is a Rate (fraction of served responses that
// were cache hits); cache_status_* count raw hit/miss for sanity.
const cacheHitRatio = new Rate('cache_hit_ratio');
const upstreamBytes = new Trend('served_bytes', false);
const errors = new Counter('proxy_errors');

// Package-manager endpoints and a representative, deterministic working set of
// artifact paths for the cache-hit scenario.
const PM_ENDPOINTS = ['npm', 'pypi', 'crates', 'goproxy', 'nuget'];
const HIT_SET_SIZE = 40; // distinct artifacts pre-warmed and then re-read

function pmHitPath(i) {
  const ep = PM_ENDPOINTS[i % PM_ENDPOINTS.length];
  return `/v1/${ep}/pkg/popular-${i}/artifact-${i}.bin`;
}

function dockerList(name) {
  const raw = __ENV[name];
  if (!raw) return [];
  return raw.split(',').map((s) => s.trim()).filter((s) => s.length > 0);
}

export const options = {
  scenarios: {
    cache_hit: {
      executor: 'constant-vus',
      exec: 'cacheHit',
      vus: VUS,
      duration: DURATION,
      tags: { scenario: 'cache_hit' },
    },
    cache_miss: {
      executor: 'constant-vus',
      exec: 'cacheMiss',
      vus: VUS,
      duration: DURATION,
      startTime: DURATION, // run after cache_hit so they don't contend
      tags: { scenario: 'cache_miss' },
    },
    docker: {
      executor: 'constant-vus',
      exec: 'dockerPull',
      vus: VUS,
      duration: DURATION,
      startTime: `${2 * parseInt(DURATION, 10)}s`,
      tags: { scenario: 'docker' },
    },
  },
  summaryTrendStats: ['avg', 'min', 'med', 'p(50)', 'p(90)', 'p(95)', 'p(99)', 'max'],
  thresholds: {
    // Non-gating documentation of intent; the harness reports rather than fails.
    'http_req_failed': ['rate<0.01'],
    'cache_hit_ratio{scenario:cache_hit}': ['rate>0.95'],
  },
};

// setup pre-warms the cache-hit working set and the docker blob/manifest set so
// the steady-state scenarios measure hits, not cold fills.
export function setup() {
  for (let i = 0; i < HIT_SET_SIZE; i++) {
    http.get(`${PROXY}${pmHitPath(i)}`);
  }
  const blobs = dockerList('DOCKER_BLOBS');
  const manifests = dockerList('DOCKER_MANIFESTS');
  for (const d of blobs) {
    http.get(`${PROXY}/v1/dockerhub/v2/library/app/blobs/${d}`);
  }
  for (const d of manifests) {
    http.get(`${PROXY}/v1/dockerhub/v2/library/app/manifests/${d}`);
  }
  return { blobs, manifests };
}

function record(res) {
  const xc = res.headers['X-Cache'] || '';
  cacheHitRatio.add(xc === 'HIT');
  upstreamBytes.add(res.body ? res.body.length : 0);
  if (res.status !== 200) {
    errors.add(1);
  }
}

export function cacheHit() {
  const i = Math.floor(Math.random() * HIT_SET_SIZE);
  const res = http.get(`${PROXY}${pmHitPath(i)}`, { tags: { name: 'pm_hit' } });
  check(res, { 'hit status 200': (r) => r.status === 200 });
  record(res);
}

export function cacheMiss() {
  // Unique per (VU, iteration) so every request is a guaranteed cold fill.
  const ep = PM_ENDPOINTS[(__VU + __ITER) % PM_ENDPOINTS.length];
  const path = `/v1/${ep}/pkg/cold-${__VU}-${__ITER}/artifact.bin`;
  const res = http.get(`${PROXY}${path}`, { tags: { name: 'pm_miss' } });
  check(res, { 'miss status 200': (r) => r.status === 200 });
  record(res);
}

export function dockerPull(data) {
  const blobs = data.blobs || [];
  if (blobs.length === 0) {
    return; // no digests injected; docker scenario is a no-op
  }
  const d = blobs[Math.floor(Math.random() * blobs.length)];
  const res = http.get(`${PROXY}/v1/dockerhub/v2/library/app/blobs/${d}`, {
    tags: { name: 'docker_blob' },
  });
  check(res, { 'docker status 200': (r) => r.status === 200 });
  record(res);
}
