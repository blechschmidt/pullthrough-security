#!/usr/bin/env python3
"""Generator for the pull-through proxy's Grafana dashboards.

Run from anywhere; writes versioned dashboard JSON into ./dashboards next to
this script. Keeping the dashboards generated guarantees consistent datasource
templating, panel layout, and the shared header across all four boards, and
makes it a one-line change to re-tune a query. The emitted JSON is plain
Grafana dashboard model (schemaVersion 39, Grafana >= 10) and is both
file-provisionable and importable via the UI.

    python3 gen_dashboards.py
"""
import json
import os

DS = "${datasource}"  # dashboard datasource template variable
SCHEMA_VERSION = 39

# Bump when the dashboards change in a backwards-incompatible way for operators.
BUNDLE_VERSION = "1.0.0"


def ds():
    return {"type": "prometheus", "uid": DS}


def grid(x, y, w, h):
    return {"x": x, "y": y, "w": w, "h": h}


def target(expr, legend=None, instant=False):
    t = {
        "datasource": ds(),
        "expr": expr,
        "refId": "A",
        "instant": instant,
    }
    if legend is not None:
        t["legendFormat"] = legend
    return t


def _targets(spec):
    out = []
    for i, s in enumerate(spec):
        t = target(s[0], s[1] if len(s) > 1 else None)
        t["refId"] = chr(ord("A") + i)
        out.append(t)
    return out


def timeseries(title, gp, targets, unit="short", desc="", stack=False, fill=10, decimals=None):
    fieldcfg = {
        "defaults": {
            "unit": unit,
            "custom": {
                "drawStyle": "line",
                "fillOpacity": fill,
                "showPoints": "never",
                "lineWidth": 1,
                "stacking": {"mode": "normal" if stack else "none", "group": "A"},
            },
        },
        "overrides": [],
    }
    if decimals is not None:
        fieldcfg["defaults"]["decimals"] = decimals
    return {
        "type": "timeseries",
        "title": title,
        "description": desc,
        "datasource": ds(),
        "gridPos": gp,
        "fieldConfig": fieldcfg,
        "options": {
            "legend": {"displayMode": "table", "placement": "bottom", "calcs": ["last", "max"]},
            "tooltip": {"mode": "multi", "sort": "desc"},
        },
        "targets": _targets(targets),
    }


def stat(title, gp, targets, unit="short", desc="", thresholds=None, color_mode="value", text_mode="auto", decimals=None):
    steps = thresholds or [{"color": "green", "value": None}]
    defaults = {
        "unit": unit,
        "thresholds": {"mode": "absolute", "steps": steps},
        "color": {"mode": "thresholds"},
    }
    if decimals is not None:
        defaults["decimals"] = decimals
    return {
        "type": "stat",
        "title": title,
        "description": desc,
        "datasource": ds(),
        "gridPos": gp,
        "fieldConfig": {"defaults": defaults, "overrides": []},
        "options": {
            "colorMode": color_mode,
            "graphMode": "area",
            "justifyMode": "auto",
            "textMode": text_mode,
            "reduceOptions": {"calcs": ["lastNotNull"], "fields": "", "values": False},
        },
        "targets": _targets(targets),
    }


def gauge(title, gp, targets, unit="percentunit", desc="", thresholds=None, mn=0, mx=1):
    steps = thresholds or [{"color": "red", "value": None}, {"color": "yellow", "value": 0.5}, {"color": "green", "value": 0.8}]
    return {
        "type": "gauge",
        "title": title,
        "description": desc,
        "datasource": ds(),
        "gridPos": gp,
        "fieldConfig": {
            "defaults": {
                "unit": unit,
                "min": mn,
                "max": mx,
                "thresholds": {"mode": "absolute", "steps": steps},
            },
            "overrides": [],
        },
        "options": {"reduceOptions": {"calcs": ["lastNotNull"], "fields": "", "values": False}, "showThresholdLabels": False, "showThresholdMarkers": True},
        "targets": _targets(targets),
    }


def row(title, y):
    return {"type": "row", "title": title, "collapsed": False, "gridPos": grid(0, y, 24, 1), "panels": []}


def dashboard(uid, title, desc, tags, panels):
    return {
        "__inputs": [
            {
                "name": "DS_PROMETHEUS",
                "label": "Prometheus",
                "description": "Prometheus datasource scraping the pull-through proxy",
                "type": "datasource",
                "pluginId": "prometheus",
                "pluginName": "Prometheus",
            }
        ],
        "__requires": [
            {"type": "grafana", "id": "grafana", "name": "Grafana", "version": "10.0.0"},
            {"type": "datasource", "id": "prometheus", "name": "Prometheus", "version": "1.0.0"},
        ],
        "annotations": {"list": [{
            "builtIn": 1,
            "datasource": {"type": "grafana", "uid": "-- Grafana --"},
            "enable": True,
            "hide": True,
            "iconColor": "rgba(0, 211, 255, 1)",
            "name": "Annotations & Alerts",
            "type": "dashboard",
        }]},
        "editable": True,
        "fiscalYearStartMonth": 0,
        "graphTooltip": 1,
        "id": None,
        "links": [],
        "liveNow": False,
        "panels": panels,
        "refresh": "30s",
        "schemaVersion": SCHEMA_VERSION,
        "tags": tags,
        "templating": {"list": [
            {
                "current": {},
                "hide": 0,
                "includeAll": False,
                "label": "Datasource",
                "name": "datasource",
                "options": [],
                "query": "prometheus",
                "refresh": 1,
                "regex": "",
                "type": "datasource",
            },
            {
                "current": {"selected": False, "text": "All", "value": "$__all"},
                "datasource": ds(),
                "definition": "label_values(pullthrough_requests_total, job)",
                "hide": 0,
                "includeAll": True,
                "allValue": ".*",
                "label": "Job",
                "multi": True,
                "name": "job",
                "options": [],
                "query": {"query": "label_values(pullthrough_requests_total, job)", "refId": "job"},
                "refresh": 2,
                "regex": "",
                "sort": 1,
                "type": "query",
            },
        ]},
        "time": {"from": "now-6h", "to": "now"},
        "timepicker": {},
        "timezone": "",
        "title": title,
        "description": desc,
        "uid": uid,
        "version": 1,
        "weekStart": "",
    }


# Layout helper: place panels left-to-right, 2 per row of height h starting at y.
def lay(panels_specs, y0=1, h=8, cols=2):
    w = 24 // cols
    out = []
    for i, mk in enumerate(panels_specs):
        col = i % cols
        rowi = i // cols
        gp = grid(col * w, y0 + rowi * h, w, h)
        out.append(mk(gp))
    return out, y0 + ((len(panels_specs) + cols - 1) // cols) * h


def build_cache():
    panels = []
    panels.append(row("Overview", 0))
    top = [
        lambda gp: gauge("Cache hit ratio", gp, [("avg(pullthrough_cache_hit_ratio)", "hit ratio")],
                         desc="Live hit ratio over all reads (0..1)."),
        lambda gp: stat("Cache hits/s", gp, [("sum(rate(pullthrough_cache_hits_total[5m]))", "hits/s")], unit="ops",
                        thresholds=[{"color": "green", "value": None}]),
        lambda gp: stat("Cache misses/s", gp, [("sum(rate(pullthrough_cache_misses_total[5m]))", "misses/s")], unit="ops",
                        thresholds=[{"color": "blue", "value": None}]),
        lambda gp: stat("Cache errors/s", gp, [("sum(rate(pullthrough_cache_errors_total[5m]))", "errors/s")], unit="ops",
                        color_mode="background",
                        thresholds=[{"color": "green", "value": None}, {"color": "yellow", "value": 0.05}, {"color": "red", "value": 1}]),
    ]
    p, y = lay(top, y0=1, h=6, cols=4)
    panels += p
    panels.append(row("Throughput", y))
    mid = [
        lambda gp: timeseries("Hits vs misses (rate)", gp,
                              [("sum(rate(pullthrough_cache_hits_total[5m]))", "hits"),
                               ("sum(rate(pullthrough_cache_misses_total[5m]))", "misses")], unit="ops",
                              desc="Read throughput split by hit/miss."),
        lambda gp: timeseries("Hit ratio (trend)", gp,
                              [("avg(pullthrough_cache_hit_ratio)", "hit ratio")], unit="percentunit", fill=20,
                              decimals=3),
        lambda gp: timeseries("Upstream loads & coalesced fills", gp,
                              [("sum(rate(pullthrough_cache_loads_total[5m]))", "loads"),
                               ("sum(rate(pullthrough_cache_coalesced_total[5m]))", "coalesced")], unit="ops",
                              desc="Cache fills from upstream and concurrent loads merged into an in-flight fetch."),
        lambda gp: timeseries("Cache I/O bytes", gp,
                              [("sum(rate(pullthrough_cache_written_bytes_total[5m]))", "written/s"),
                               ("sum(rate(pullthrough_cache_served_bytes_total[5m]))", "served/s")], unit="Bps"),
    ]
    p, y = lay(mid, y0=y + 1, h=8, cols=2)
    panels += p
    panels.append(row("Lifecycle & errors", y))
    bot = [
        lambda gp: timeseries("Evictions & expirations", gp,
                              [("sum(rate(pullthrough_cache_evictions_total[5m]))", "evictions (LRU)"),
                               ("sum(rate(pullthrough_cache_expired_total[5m]))", "expired (TTL)")], unit="ops"),
        lambda gp: timeseries("Cache backend errors", gp,
                              [("sum(rate(pullthrough_cache_errors_total[5m]))", "errors/s")], unit="ops",
                              desc="Non-miss store failures. For the S3/object-storage backend, sustained errors indicate bucket I/O, auth, or connectivity problems.",
                              fill=20),
    ]
    p, y = lay(bot, y0=y + 1, h=8, cols=2)
    panels += p
    return dashboard("pullthrough-cache", "Pull-through · Cache Performance",
                     "Cache hit/miss ratio, throughput, fills, eviction/expiry, and backend (incl. S3) errors.",
                     ["pullthrough", "cache"], panels)


def build_security():
    panels = []
    panels.append(row("Supply-chain posture", 0))
    top = [
        lambda gp: stat("Blocked (vuln, 1h)", gp, [("sum(increase(pullthrough_vuln_blocked_total[1h]))", "blocked")],
                        color_mode="background", thresholds=[{"color": "green", "value": None}, {"color": "orange", "value": 1}]),
        lambda gp: stat("Quarantined artifacts", gp, [("sum(pullthrough_quarantined_artifacts)", "held")],
                        color_mode="background", thresholds=[{"color": "green", "value": None}, {"color": "orange", "value": 1}]),
        lambda gp: stat("Sig-gate blocked (1h)", gp, [("sum(increase(pullthrough_sigverify_blocked_total[1h]))", "blocked")],
                        color_mode="background", thresholds=[{"color": "green", "value": None}, {"color": "red", "value": 1}]),
        lambda gp: stat("Dep-confusion (1h)", gp, [("sum(increase(pullthrough_nameguard_dependency_confusion_total[1h]))", "found")],
                        color_mode="background", thresholds=[{"color": "green", "value": None}, {"color": "red", "value": 1}]),
    ]
    p, y = lay(top, y0=1, h=5, cols=4)
    panels += p

    panels.append(row("Compliance scorecard", y))
    comp = [
        lambda gp: gauge("Overall compliance score", gp,
                         [("pullthrough_compliance_score", "score")], unit="percentunit",
                         desc="Weighted posture score across applicable controls (Task 35)."),
        lambda gp: stat("SLSA build level (est.)", gp,
                        [("pullthrough_compliance_slsa_build_level", "level")], unit="short",
                        color_mode="background",
                        thresholds=[{"color": "red", "value": None}, {"color": "orange", "value": 1}, {"color": "green", "value": 2}]),
        lambda gp: stat("Failing controls", gp,
                        [("pullthrough_compliance_controls_failing", "failing")], unit="short",
                        color_mode="background",
                        thresholds=[{"color": "green", "value": None}, {"color": "red", "value": 1}]),
        lambda gp: stat("Warning controls", gp,
                        [("pullthrough_compliance_controls_warning", "warning")], unit="short",
                        color_mode="background",
                        thresholds=[{"color": "green", "value": None}, {"color": "orange", "value": 1}]),
    ]
    p, y = lay(comp, y0=y + 1, h=5, cols=4)
    panels += p
    comp2 = [
        lambda gp: timeseries("Per-control score (trend)", gp,
                              [("pullthrough_compliance_control_score", "{{control}}")], unit="percentunit",
                              decimals=2, desc="Per-control posture coverage over time; a downward step is a posture regression."),
        lambda gp: timeseries("Per-control pass (1=pass)", gp,
                              [("pullthrough_compliance_control_pass", "{{control}}")], unit="short",
                              desc="1 while a control is fully passing, 0 otherwise."),
    ]
    p, y = lay(comp2, y0=y + 1, h=8, cols=2)
    panels += p

    panels.append(row("Vulnerability gate", y))
    vuln = [
        lambda gp: timeseries("Vulnerabilities found by severity (rate)", gp,
                              [("sum(rate(pullthrough_vulnerabilities_critical_total[10m]))", "critical"),
                               ("sum(rate(pullthrough_vulnerabilities_high_total[10m]))", "high"),
                               ("sum(rate(pullthrough_vulnerabilities_medium_total[10m]))", "medium"),
                               ("sum(rate(pullthrough_vulnerabilities_low_total[10m]))", "low")], unit="ops", stack=True),
        lambda gp: timeseries("Gate decisions (rate)", gp,
                              [("sum(rate(pullthrough_vuln_blocked_total[10m]))", "blocked"),
                               ("sum(rate(pullthrough_vuln_warned_total[10m]))", "warned"),
                               ("sum(rate(pullthrough_vuln_quarantined_total[10m]))", "quarantined")], unit="ops"),
        lambda gp: timeseries("Scan backend health", gp,
                              [("sum(rate(pullthrough_vuln_scans_total[10m]))", "scans"),
                               ("sum(rate(pullthrough_vuln_scan_errors_total[10m]))", "errors"),
                               ("sum(rate(pullthrough_vuln_offline_fallbacks_total[10m]))", "offline fallbacks")], unit="ops",
                              desc="Errors or offline fallbacks mean verdicts may not reflect the latest CVE database."),
        lambda gp: timeseries("CVE-drift re-scan & quarantine", gp,
                              [("sum(rate(pullthrough_rescans_total[10m]))", "rescans"),
                               ("sum(increase(pullthrough_newly_vulnerable_total[1h]))", "newly vulnerable (1h)"),
                               ("sum(pullthrough_quarantined_artifacts)", "currently quarantined")], unit="short",
                              desc="Continuous revalidation of cached artifacts against new CVEs (Task 18)."),
    ]
    p, y = lay(vuln, y0=y + 1, h=8, cols=2)
    panels += p

    panels.append(row("Signature & attestation verification", y))
    sig = [
        lambda gp: timeseries("Verification outcomes (rate)", gp,
                              [("sum(rate(pullthrough_sigverify_verified_total[10m]))", "verified"),
                               ("sum(rate(pullthrough_sigverify_unsigned_total[10m]))", "unsigned"),
                               ("sum(rate(pullthrough_sigverify_blocked_total[10m]))", "blocked"),
                               ("sum(rate(pullthrough_sigverify_warned_total[10m]))", "warned")], unit="ops"),
        lambda gp: timeseries("Signatures / attestations / Rekor", gp,
                              [("sum(rate(pullthrough_sigverify_signatures_checked_total[10m]))", "signatures"),
                               ("sum(rate(pullthrough_sigverify_attestations_parsed_total[10m]))", "attestations"),
                               ("sum(rate(pullthrough_sigverify_rekor_verified_total[10m]))", "rekor-verified"),
                               ("sum(rate(pullthrough_sigverify_errors_total[10m]))", "errors")], unit="ops"),
    ]
    p, y = lay(sig, y0=y + 1, h=8, cols=2)
    panels += p

    panels.append(row("Name guard (typosquat & dependency confusion)", y))
    ng = [
        lambda gp: timeseries("Findings by type (rate)", gp,
                              [("sum(rate(pullthrough_nameguard_typosquat_total[10m]))", "typosquat"),
                               ("sum(rate(pullthrough_nameguard_dependency_confusion_total[10m]))", "dependency-confusion"),
                               ("sum(rate(pullthrough_nameguard_homoglyph_total[10m]))", "homoglyph"),
                               ("sum(rate(pullthrough_nameguard_namespace_mismatch_total[10m]))", "namespace-mismatch"),
                               ("sum(rate(pullthrough_nameguard_new_package_total[10m]))", "new-package")], unit="ops"),
        lambda gp: timeseries("Inspected vs flagged/blocked (rate)", gp,
                              [("sum(rate(pullthrough_nameguard_inspected_total[10m]))", "inspected"),
                               ("sum(rate(pullthrough_nameguard_flagged_total[10m]))", "flagged"),
                               ("sum(rate(pullthrough_nameguard_blocked_total[10m]))", "blocked"),
                               ("sum(rate(pullthrough_nameguard_warned_total[10m]))", "warned")], unit="ops"),
    ]
    p, y = lay(ng, y0=y + 1, h=8, cols=2)
    panels += p
    return dashboard("pullthrough-supply-chain", "Pull-through · Supply-chain Security",
                     "Vulnerability gate, CVE-drift re-scan/quarantine, signature/attestation verification, and name-guard posture.",
                     ["pullthrough", "security", "supply-chain"], panels)


def build_upstream():
    panels = []
    panels.append(row("Traffic & errors", 0))
    top = [
        lambda gp: stat("Request rate", gp, [("sum(rate(pullthrough_requests_total[5m]))", "req/s")], unit="reqps",
                        thresholds=[{"color": "green", "value": None}]),
        lambda gp: stat("5xx ratio", gp,
                        [("sum(rate(pullthrough_requests_total{code=~\"5..\"}[5m])) / clamp_min(sum(rate(pullthrough_requests_total[5m])),0.001)", "5xx")],
                        unit="percentunit", color_mode="background",
                        thresholds=[{"color": "green", "value": None}, {"color": "yellow", "value": 0.01}, {"color": "red", "value": 0.05}]),
        lambda gp: stat("Upstream errors/s", gp, [("sum(rate(pullthrough_upstream_errors_total[5m]))", "errors/s")], unit="ops",
                        color_mode="background", thresholds=[{"color": "green", "value": None}, {"color": "red", "value": 0.1}]),
        lambda gp: stat("Bytes served/s", gp, [("sum(rate(pullthrough_served_bytes_total[5m]))", "B/s")], unit="Bps",
                        thresholds=[{"color": "green", "value": None}]),
    ]
    p, y = lay(top, y0=1, h=5, cols=4)
    panels += p

    panels.append(row("Upstream latency", y))
    lat = [
        lambda gp: timeseries("Upstream latency p50/p95/p99 (by backend)", gp,
                              [("histogram_quantile(0.50, sum by (le,backend) (rate(pullthrough_upstream_request_duration_seconds_bucket[5m])))", "p50 {{backend}}"),
                               ("histogram_quantile(0.95, sum by (le,backend) (rate(pullthrough_upstream_request_duration_seconds_bucket[5m])))", "p95 {{backend}}"),
                               ("histogram_quantile(0.99, sum by (le,backend) (rate(pullthrough_upstream_request_duration_seconds_bucket[5m])))", "p99 {{backend}}")],
                              unit="s"),
        lambda gp: timeseries("Avg upstream latency (by backend)", gp,
                              [("sum by (backend) (rate(pullthrough_upstream_request_duration_seconds_sum[5m])) / clamp_min(sum by (backend) (rate(pullthrough_upstream_request_duration_seconds_count[5m])),0.001)", "{{backend}}")],
                              unit="s"),
    ]
    p, y = lay(lat, y0=y + 1, h=8, cols=2)
    panels += p

    panels.append(row("By backend & status", y))
    bk = [
        lambda gp: timeseries("Request rate by backend", gp,
                              [("sum by (backend) (rate(pullthrough_requests_total[5m]))", "{{backend}}")], unit="reqps", stack=True),
        lambda gp: timeseries("Request rate by status code", gp,
                              [("sum by (code) (rate(pullthrough_requests_total[5m]))", "{{code}}")], unit="reqps", stack=True),
        lambda gp: timeseries("Upstream errors by backend", gp,
                              [("sum by (backend) (rate(pullthrough_upstream_errors_total[5m]))", "{{backend}}")], unit="ops"),
        lambda gp: timeseries("Upstream error ratio by backend", gp,
                              [("sum by (backend) (rate(pullthrough_upstream_errors_total[5m])) / clamp_min(sum by (backend) (rate(pullthrough_upstream_request_duration_seconds_count[5m])),0.001)", "{{backend}}")],
                              unit="percentunit", desc="Failed upstream fetches as a fraction of attempts. Drives the UpstreamOutage alert."),
    ]
    p, y = lay(bk, y0=y + 1, h=8, cols=2)
    panels += p

    panels.append(row("Admission policy", y))
    pol = [
        lambda gp: timeseries("Policy decisions (rate)", gp,
                              [("sum by (action) (rate(pullthrough_policy_decisions_total[5m]))", "{{action}}")], unit="ops", stack=True),
        lambda gp: timeseries("Policy decisions by ecosystem", gp,
                              [("sum by (ecosystem) (rate(pullthrough_policy_decisions_total[5m]))", "{{ecosystem}}")], unit="ops", stack=True),
    ]
    p, y = lay(pol, y0=y + 1, h=8, cols=2)
    panels += p

    # Outbound connection-pool health (Task 130): reuse rate, dial latency, and
    # pool footprint. Low reuse / rising dials is connection churn — the same
    # regression the perfguard conn-reuse scenario guards against in CI.
    panels.append(row("Upstream connection pool", y))
    conn_top = [
        lambda gp: stat("Connection reuse rate", gp,
                        [("sum(rate(pullthrough_upstream_conn_reused_total[5m])) / clamp_min(sum(rate(pullthrough_upstream_conn_acquired_total[5m])),0.001)", "reuse")],
                        unit="percentunit", color_mode="background",
                        desc="Fraction of upstream connection acquisitions served from the keep-alive pool rather than a fresh dial. Low values mean connection churn.",
                        thresholds=[{"color": "red", "value": None}, {"color": "yellow", "value": 0.5}, {"color": "green", "value": 0.8}]),
        lambda gp: stat("New dials/s", gp,
                        [("sum(rate(pullthrough_upstream_conn_dials_total[5m]))", "dials/s")], unit="ops",
                        desc="New outbound connections dialed per second — the raw connection-churn signal.",
                        thresholds=[{"color": "green", "value": None}]),
        lambda gp: stat("Avg dial latency", gp,
                        [("sum(rate(pullthrough_upstream_conn_dial_duration_seconds_sum[5m])) / clamp_min(sum(rate(pullthrough_upstream_conn_dial_duration_seconds_count[5m])),0.001)", "dial")],
                        unit="s",
                        desc="Average time to establish a new outbound connection (TCP+TLS handshake).",
                        thresholds=[{"color": "green", "value": None}, {"color": "yellow", "value": 0.25}, {"color": "red", "value": 1}]),
        lambda gp: stat("Open connections", gp,
                        [("sum(pullthrough_upstream_conn_open)", "open")], unit="short",
                        desc="Outbound connections currently open across all upstream clients (active plus idle).",
                        thresholds=[{"color": "green", "value": None}]),
    ]
    p, y = lay(conn_top, y0=y + 1, h=5, cols=4)
    panels += p

    conn = [
        lambda gp: timeseries("Connection acquisitions vs dials (rate)", gp,
                              [("sum(rate(pullthrough_upstream_conn_acquired_total[5m]))", "acquired/s"),
                               ("sum(rate(pullthrough_upstream_conn_reused_total[5m]))", "reused/s"),
                               ("sum(rate(pullthrough_upstream_conn_dials_total[5m]))", "dialed/s")],
                              unit="ops",
                              desc="Acquisitions handed to requests, of which reuses came from the pool; dials are new connections. A healthy pool keeps dials far below acquisitions."),
        lambda gp: timeseries("Connection pool footprint", gp,
                              [("sum(pullthrough_upstream_conn_open)", "open"),
                               ("sum(pullthrough_upstream_conn_idle)", "idle")],
                              unit="short",
                              desc="Open connections and, of those, how many are currently parked idle in the keep-alive pool."),
    ]
    p, y = lay(conn, y0=y + 1, h=8, cols=2)
    panels += p

    return dashboard("pullthrough-upstream", "Pull-through · Upstream Latency & Errors",
                     "Request rate, status codes, upstream fetch latency quantiles and error ratios per backend, and admission-policy decisions.",
                     ["pullthrough", "upstream", "latency"], panels)


def build_tenant():
    panels = []
    panels.append(row("Rate-limit overview", 0))
    top = [
        lambda gp: stat("Allowed/s", gp, [("sum(rate(pullthrough_ratelimit_allowed_total[5m]))", "allowed/s")], unit="ops",
                        thresholds=[{"color": "green", "value": None}]),
        lambda gp: stat("Throttled/s", gp, [("sum(rate(pullthrough_ratelimit_throttled_total[5m]))", "throttled/s")], unit="ops",
                        color_mode="background", thresholds=[{"color": "green", "value": None}, {"color": "yellow", "value": 0.1}, {"color": "red", "value": 1}]),
        lambda gp: stat("Throttle ratio", gp,
                        [("sum(rate(pullthrough_ratelimit_throttled_total[5m])) / clamp_min(sum(rate(pullthrough_ratelimit_allowed_total[5m]) + rate(pullthrough_ratelimit_throttled_total[5m])),0.001)", "ratio")],
                        unit="percentunit", color_mode="background",
                        thresholds=[{"color": "green", "value": None}, {"color": "yellow", "value": 0.1}, {"color": "red", "value": 0.2}]),
        lambda gp: stat("In-flight (global)", gp, [("sum(pullthrough_ratelimit_concurrent_inflight)", "in-flight")], unit="short",
                        thresholds=[{"color": "green", "value": None}]),
    ]
    p, y = lay(top, y0=1, h=5, cols=4)
    panels += p

    panels.append(row("Throttling", y))
    th = [
        lambda gp: timeseries("Throttled by reason (rate)", gp,
                              [("sum by (reason) (rate(pullthrough_ratelimit_throttled_by_reason_total[5m]))", "{{reason}}")], unit="ops",
                              desc="rps = request-rate cap, concurrency = in-flight cap, bytes = byte-quota exhaustion."),
        lambda gp: timeseries("Allowed vs throttled (rate)", gp,
                              [("sum(rate(pullthrough_ratelimit_allowed_total[5m]))", "allowed"),
                               ("sum(rate(pullthrough_ratelimit_throttled_total[5m]))", "throttled")], unit="ops"),
    ]
    p, y = lay(th, y0=y + 1, h=8, cols=2)
    panels += p

    panels.append(row("Per-tenant usage", y))
    pt = [
        lambda gp: timeseries("Concurrent in-flight by tenant", gp,
                              [("sum by (tenant) (pullthrough_ratelimit_concurrent_inflight)", "{{tenant}}")], unit="short",
                              desc="Live pulls held against the concurrency cap, per tenant."),
        lambda gp: timeseries("Byte-quota usage by tenant", gp,
                              [("sum by (tenant) (pullthrough_ratelimit_bytes_used)", "{{tenant}}")], unit="bytes",
                              desc="Bytes consumed in the current quota window, per tenant. Approaching the configured quota triggers byte throttling."),
        lambda gp: timeseries("Request rate by backend (traffic mix)", gp,
                              [("sum by (backend) (rate(pullthrough_requests_total[5m]))", "{{backend}}")], unit="reqps", stack=True),
        lambda gp: timeseries("Bytes served by backend", gp,
                              [("sum by (backend) (rate(pullthrough_served_bytes_total[5m]))", "{{backend}}")], unit="Bps", stack=True),
    ]
    p, y = lay(pt, y0=y + 1, h=8, cols=2)
    panels += p

    panels.append(row("Notifications", y))
    nt = [
        lambda gp: timeseries("Notifications by sink (rate)", gp,
                              [("sum by (sink) (rate(pullthrough_notifications_sent_total[5m]))", "sent {{sink}}"),
                               ("sum by (sink) (rate(pullthrough_notifications_failed_total[5m]))", "failed {{sink}}"),
                               ("sum by (sink) (rate(pullthrough_notifications_dropped_total[5m]))", "dropped {{sink}}")], unit="ops"),
        lambda gp: stat("Notify queue depth", gp, [("sum(pullthrough_notifications_queue_depth)", "queued")], unit="short",
                        color_mode="value", thresholds=[{"color": "green", "value": None}, {"color": "yellow", "value": 50}, {"color": "red", "value": 500}]),
    ]
    p, y = lay(nt, y0=y + 1, h=8, cols=2)
    panels += p
    return dashboard("pullthrough-tenant", "Pull-through · Per-tenant Traffic & Limits",
                     "Rate-limit allow/throttle, per-tenant concurrency and byte-quota usage, traffic mix, and notification delivery.",
                     ["pullthrough", "tenant", "ratelimit"], panels)


def main():
    here = os.path.dirname(os.path.abspath(__file__))
    outdir = os.path.join(here, "dashboards")
    os.makedirs(outdir, exist_ok=True)
    boards = {
        "cache-performance.json": build_cache(),
        "supply-chain-security.json": build_security(),
        "upstream-latency-errors.json": build_upstream(),
        "per-tenant-traffic.json": build_tenant(),
    }
    for fname, model in boards.items():
        model["tags"] = sorted(set(model["tags"] + ["bundle-v" + BUNDLE_VERSION]))
        with open(os.path.join(outdir, fname), "w") as f:
            json.dump(model, f, indent=2, sort_keys=False)
            f.write("\n")
        print("wrote", fname)


if __name__ == "__main__":
    main()
