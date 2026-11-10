"use strict";
/*
 * Pullthrough admin dashboard.
 *
 * A small, dependency-free single-page app over the admin JSON API. It is
 * deliberately framework-free: the proxy embeds these assets and serves them
 * from memory, so there is no build step. All subsystems are optional, so every
 * view degrades gracefully when its backing data is absent.
 *
 * Security note: values returned by the API (cache keys, origins, commit SHAs,
 * policy reasons) are treated as untrusted and only ever assigned via
 * textContent / DOM construction, never interpolated into innerHTML.
 */
(function () {
  // --- tiny DOM helpers -----------------------------------------------------
  const $ = (sel, root = document) => root.querySelector(sel);
  const $$ = (sel, root = document) => Array.from(root.querySelectorAll(sel));

  /** el("tag.class#id", {attrs}, ...children) */
  function el(spec, attrs, ...children) {
    const [tagAndId, ...classes] = spec.split(".");
    const [tag, id] = tagAndId.split("#");
    const node = document.createElement(tag || "div");
    if (id) node.id = id;
    if (classes.length) node.className = classes.join(" ");
    if (attrs) {
      for (const [k, v] of Object.entries(attrs)) {
        if (v == null || v === false) continue;
        if (k === "text") node.textContent = v;
        else if (k === "html") node.innerHTML = v; // only for trusted, static markup
        else if (k.startsWith("on") && typeof v === "function") node.addEventListener(k.slice(2), v);
        else node.setAttribute(k, v === true ? "" : String(v));
      }
    }
    for (const c of children.flat()) {
      if (c == null) continue;
      node.appendChild(typeof c === "string" ? document.createTextNode(c) : c);
    }
    return node;
  }

  function clear(node) {
    while (node.firstChild) node.removeChild(node.firstChild);
    return node;
  }

  // --- formatting -----------------------------------------------------------
  function fmtBytes(n) {
    if (n == null) return "—";
    if (n < 1024) return `${n} B`;
    const units = ["KB", "MB", "GB", "TB"];
    let v = n / 1024, i = 0;
    while (v >= 1024 && i < units.length - 1) { v /= 1024; i++; }
    return `${v.toFixed(v < 10 ? 1 : 0)} ${units[i]}`;
  }

  function fmtTime(s) {
    if (!s) return "—";
    const d = new Date(s);
    if (isNaN(d.getTime()) || d.getFullYear() < 2) return "—";
    const diff = (Date.now() - d.getTime()) / 1000;
    if (diff >= 0 && diff < 60) return "just now";
    if (diff >= 0 && diff < 3600) return `${Math.floor(diff / 60)}m ago`;
    if (diff >= 0 && diff < 86400) return `${Math.floor(diff / 3600)}h ago`;
    return d.toLocaleString();
  }

  function fmtPct(r) {
    return `${(Math.max(0, Math.min(1, r || 0)) * 100).toFixed(1)}%`;
  }

  function shortSha(sha) {
    return sha && sha.length > 12 ? sha.slice(0, 12) : (sha || "");
  }

  // --- API client -----------------------------------------------------------
  const api = {
    token: sessionStorage.getItem("pt_admin_token") || "",
    headers() {
      return this.token ? { Authorization: "Bearer " + this.token } : {};
    },
    async request(method, path, body, stepUpToken) {
      const opts = { method, headers: this.headers() };
      if (stepUpToken) {
        opts.headers = { ...opts.headers, "X-StepUp-Token": stepUpToken };
      }
      if (body !== undefined) {
        opts.headers = { ...opts.headers, "Content-Type": "application/json" };
        opts.body = JSON.stringify(body);
      }
      const res = await fetch("api/" + path, opts);
      if (res.status === 401) {
        // WebAuthn/passkey step-up (Task 161): the server signals that this
        // sensitive action needs a fresh assertion. Run the ceremony once and
        // retry with the minted token (never loop: only when we have none yet).
        if (!stepUpToken && res.headers.get("X-StepUp-Required") === "webauthn") {
          const token = await webauthnStepUp("/api/" + path);
          return this.request(method, path, body, token);
        }
        if (this.handleUnauthorized(res)) throw new Error("redirecting to sign in…");
        const t = window.prompt("This admin API requires a token. Enter the admin bearer token:");
        if (t) {
          this.token = t.trim();
          sessionStorage.setItem("pt_admin_token", this.token);
          return this.request(method, path, body); // retry once with the new token
        }
        throw new Error("authentication required");
      }
      if (res.status === 403) {
        let msg = "your role does not permit this action";
        try { const j = await res.json(); if (j && j.error) msg = j.error; } catch (_) {}
        throw new Error(msg);
      }
      if (!res.ok) {
        let msg = `request failed (${res.status})`;
        try { const j = await res.json(); if (j && j.error) msg = j.error; } catch (_) {}
        throw new Error(msg);
      }
      return res.status === 204 ? null : res.json();
    },
    get(path) { return this.request("GET", path); },
    del(path) { return this.request("DELETE", path); },
    post(path, body) { return this.request("POST", path, body); },
    // postRaw POSTs a raw (non-JSON) body such as an uploaded lockfile, returning
    // the parsed JSON response. It reuses the bearer-token headers but sends the
    // body verbatim with a plain text content type.
    async postRaw(path, text) {
      const opts = { method: "POST", headers: { ...this.headers(), "Content-Type": "text/plain" }, body: text };
      const res = await fetch("api/" + path, opts);
      if (!res.ok) {
        let msg = `request failed (${res.status})`;
        try { const j = await res.json(); if (j && j.error) msg = j.error; } catch (_) {}
        throw new Error(msg);
      }
      return res.status === 204 ? null : res.json();
    },
    // raw fetches a non-JSON resource (e.g. the HTML report) with auth, returning
    // the response text, prompting for a token on 401 just like request().
    async raw(path) {
      const res = await fetch("api/" + path, { method: "GET", headers: this.headers() });
      if (res.status === 401) {
        if (this.handleUnauthorized(res)) throw new Error("redirecting to sign in…");
        const t = window.prompt("This admin API requires a token. Enter the admin bearer token:");
        if (t) {
          this.token = t.trim();
          sessionStorage.setItem("pt_admin_token", this.token);
          return this.raw(path);
        }
        throw new Error("authentication required");
      }
      if (!res.ok) throw new Error(`request failed (${res.status})`);
      return res.text();
    },
    // handleUnauthorized navigates to the SSO login endpoint when the server
    // advertises one (OIDC mode). Returns true if a redirect was initiated.
    handleUnauthorized(res) {
      const loginUrl = res.headers.get("X-Login-URL");
      if (loginUrl) {
        const ret = encodeURIComponent(location.pathname + location.search + location.hash);
        location.assign(loginUrl + (loginUrl.includes("?") ? "&" : "?") + "return=" + ret);
        return true;
      }
      return false;
    },
  };

  // --- toast + drawer -------------------------------------------------------
  let toastTimer = null;
  function toast(msg, bad) {
    const t = $("#toast");
    t.textContent = msg;
    t.className = "toast" + (bad ? " bad" : "");
    t.hidden = false;
    clearTimeout(toastTimer);
    toastTimer = setTimeout(() => { t.hidden = true; }, 3200);
  }

  let drawerReturnFocus = null;
  function openDrawer(title, bodyNode) {
    // Remember what had focus so we can restore it when the dialog closes
    // (WCAG 2.4.3 Focus Order; expected behaviour for modal dialogs).
    drawerReturnFocus = document.activeElement;
    $("#drawer-title").textContent = title;
    clear($("#drawer-body")).appendChild(bodyNode);
    $("#drawer").hidden = false;
    $("#overlay").hidden = false;
    $("#drawer-close").focus();
  }
  function closeDrawer() {
    const wasOpen = !$("#drawer").hidden;
    $("#drawer").hidden = true;
    $("#overlay").hidden = true;
    if (wasOpen && drawerReturnFocus && typeof drawerReturnFocus.focus === "function") {
      drawerReturnFocus.focus();
    }
    drawerReturnFocus = null;
  }

  // Keep Tab focus inside the open drawer dialog so keyboard users cannot
  // wander into the inert page behind it (modal focus trap).
  function focusables(root) {
    return $$("a[href],button:not([disabled]),input:not([disabled]),select:not([disabled]),textarea:not([disabled]),[tabindex]:not([tabindex='-1'])", root)
      .filter((n) => n.offsetParent !== null || n === document.activeElement);
  }
  function trapDrawerTab(e) {
    if (e.key !== "Tab") return;
    const drawer = $("#drawer");
    if (drawer.hidden) return;
    const items = focusables(drawer);
    if (!items.length) return;
    const first = items[0], last = items[items.length - 1];
    if (e.shiftKey && document.activeElement === first) { e.preventDefault(); last.focus(); }
    else if (!e.shiftKey && document.activeElement === last) { e.preventDefault(); first.focus(); }
    else if (!drawer.contains(document.activeElement)) { e.preventDefault(); first.focus(); }
  }

  function kv(pairs) {
    const dl = el("dl.kv");
    for (const [k, v] of pairs) {
      if (v == null || v === "" || v === false) continue;
      dl.appendChild(el("dt", { text: k }));
      const dd = el("dd");
      if (v instanceof Node) dd.appendChild(v); else dd.textContent = String(v);
      dl.appendChild(dd);
    }
    return dl;
  }

  function emptyRow(table, cols, msg) {
    return el("tr", null, el("td", { colspan: cols }, el("div.empty", { text: msg })));
  }

  // --- severity / risk widgets ---------------------------------------------
  function sevBadge(sev) {
    const s = (sev || "info").toLowerCase();
    return el("span.badge.sev-" + s, { text: s });
  }

  function riskWidget(score) {
    const pct = Math.max(0, Math.min(100, score || 0));
    const color = pct >= 70 ? "var(--crit)" : pct >= 40 ? "var(--warn)" : "var(--ok)";
    const bar = el("span.risk-bar", null, el("i"));
    bar.firstChild.style.width = pct + "%";
    bar.firstChild.style.background = color;
    return el("span.risk", null, String(score == null ? "—" : score), bar);
  }

  function verdictPill(malicious) {
    return malicious
      ? el("span.pill.bad", { text: "malicious" })
      : el("span.pill.ok", { text: "clean" });
  }

  // --- view registry --------------------------------------------------------
  const views = {};
  let currentView = "overview";

  function setView(name) {
    // Tear down the SOC live stream + poller when navigating away from it.
    if (currentView === "secops" && name !== "secops") secopsDisconnectStream();
    currentView = name;
    $$(".tab").forEach((t) => {
      const sel = t.dataset.view === name;
      t.setAttribute("aria-selected", sel ? "true" : "false");
      // Roving tabindex: only the active tab is in the document tab order, so
      // Tab moves from the tablist straight into the panel (WAI-ARIA tabs
      // pattern); Arrow/Home/End move between tabs.
      t.setAttribute("tabindex", sel ? "0" : "-1");
    });
    $$(".view").forEach((v) => { v.hidden = v.id !== "view-" + name; });
    if (views[name]) views[name]().catch((e) => toast(e.message, true));
  }

  // Wire the ARIA tabs/tabpanels relationships once, as progressive
  // enhancement, so the static markup stays terse: each tab points at its
  // panel (aria-controls) and each panel is named by and linked back to its
  // tab (role=tabpanel + aria-labelledby). Panels are focusable so keyboard
  // users land in content after leaving the tablist.
  function wireTabsAria() {
    $$(".tab").forEach((t) => {
      const name = t.dataset.view;
      const panel = $("#view-" + name);
      if (!t.id) t.id = "tab-" + name;
      if (panel) {
        t.setAttribute("aria-controls", panel.id);
        panel.setAttribute("role", "tabpanel");
        panel.setAttribute("aria-labelledby", t.id);
        if (!panel.hasAttribute("tabindex")) panel.setAttribute("tabindex", "0");
      }
    });
  }

  // --- Overview -------------------------------------------------------------
  views.overview = async function () {
    const grid = clear($("#stat-grid"));
    const data = await api.get("overview");

    function stat(label, value, sub) {
      return el("div.stat", null,
        el("div.label", { text: label }),
        el("div.value", value instanceof Node ? null : { text: String(value) }, value instanceof Node ? value : null),
        sub ? el("div.sub", { text: sub }) : null);
    }

    const cards = [];
    if (data.cache) {
      const c = data.cache;
      cards.push(stat("Cache hit ratio", fmtPct(c.hitRatio), `${c.hits} hits · ${c.misses} misses`));
      cards.push(stat("Bytes served", fmtBytes(c.bytesServed), `${fmtBytes(c.bytesWritten)} written`));
    }
    cards.push(stat("Cached artifacts", data.cacheEntryCount ?? 0, fmtBytes(data.cacheTotalBytes) + " on disk"));
    if (data.scan) {
      const s = data.scan;
      cards.push(stat("Commits scanned", s.total ?? 0,
        `${s.malicious || 0} malicious · ${s.queueDepth || 0} queued`));
    }
    if (data.cache) {
      cards.push(stat("Cache loads", data.cache.loads ?? 0,
        `${data.cache.evictions || 0} evicted · ${data.cache.expired || 0} expired`));
      if (data.cache.errors) cards.push(stat("Cache errors", data.cache.errors));
    }
    cards.forEach((c) => grid.appendChild(c));

    const list = clear($("#backend-list"));
    const backends = data.backends || [];
    if (!backends.length) {
      list.appendChild(el("span.muted", { text: "No backends registered." }));
    } else {
      backends.forEach((b) => list.appendChild(el("span.chip", { text: b })));
    }
  };

  // --- Federated query console ----------------------------------------------
  const QUERY_EXAMPLE = JSON.stringify({
    tenant: "",
    select: ["coordinate", "riskBand", "downstreamPaths", "signatureVerified", "vulnTotal", "lastVerdict"],
    where: {
      and: [
        { field: "blockAdjacent", op: "eq", value: true },
        { field: "signatureVerified", op: "eq", value: false },
        { field: "downstreamPaths", op: "gt", value: 5 },
      ],
    },
    orderBy: [{ field: "downstreamPaths", desc: true }],
    limit: 50,
  }, null, 2);

  let queryWired = false;
  views.query = async function () {
    const input = $("#query-input");
    if (queryWired) return;
    queryWired = true;
    input.value = QUERY_EXAMPLE;
    $("#query-run").addEventListener("click", () => runFederatedQuery());
    $("#query-schema").addEventListener("click", () => loadQuerySchema().catch((e) => toast(e.message, true)));
    $("#query-example").addEventListener("click", () => { input.value = QUERY_EXAMPLE; });
    input.addEventListener("keydown", (e) => {
      if ((e.metaKey || e.ctrlKey) && e.key === "Enter") { e.preventDefault(); runFederatedQuery(); }
    });
  };

  async function runFederatedQuery() {
    const meta = $("#query-meta");
    const head = clear($("#query-head"));
    const body = clear($("#query-body"));
    let q;
    try { q = JSON.parse($("#query-input").value); }
    catch (e) { toast("invalid query JSON: " + e.message, true); return; }
    let res;
    try { res = await api.post("query", q); }
    catch (e) { meta.textContent = "error: " + e.message; toast(e.message, true); return; }
    const fields = res.fields || [];
    fields.forEach((f) => head.appendChild(el("th", { scope: "col", text: f })));
    if (!res.rows || !res.rows.length) {
      body.appendChild(emptyRow($("#query-table"), Math.max(1, fields.length), "No matching coordinates."));
    } else {
      res.rows.forEach((row) => {
        const tr = el("tr");
        fields.forEach((f) => tr.appendChild(el("td", { text: queryCell(row[f]) })));
        body.appendChild(tr);
      });
    }
    const trunc = res.truncated ? " · truncated" : "";
    meta.textContent = `${res.returned}/${res.total} rows · cost ${res.cost} · scanned ${res.scanned}${trunc}`;
  }

  function queryCell(v) {
    if (v == null) return "";
    if (Array.isArray(v)) return v.join(", ");
    return String(v);
  }

  async function loadQuerySchema() {
    const panel = clear($("#query-schema-panel"));
    const s = await api.get("query/schema");
    const srcs = Object.entries(s.sources || {}).filter(([, v]) => v).map(([k]) => k);
    panel.appendChild(el("div.muted", { text: `sources: ${srcs.join(", ") || "none"} · default ${s.defaultLimit} · max ${s.maxLimit}` }));
    const tbl = el("table");
    const tb = el("tbody");
    (s.fields || []).forEach((f) => {
      tb.appendChild(el("tr", null,
        el("td", null, el("code", { text: f.name })),
        el("td.muted", { text: f.kind }),
        el("td.muted", { text: (f.operators || []).join(" ") })));
    });
    tbl.appendChild(tb);
    panel.appendChild(tbl);
  }

  // --- Forensic incident timeline (Task 77) ---------------------------------
  let timelineWired = false;
  views.timeline = async function () {
    if (timelineWired) return;
    timelineWired = true;
    $("#timeline-run").addEventListener("click", () => runTimeline().catch((e) => toast(e.message, true)));
    $("#timeline-export").addEventListener("click", () => exportTimeline().catch((e) => toast(e.message, true)));
    ["#timeline-coordinate", "#timeline-tenant", "#timeline-identity", "#timeline-incident"].forEach((id) => {
      $(id).addEventListener("keydown", (e) => { if (e.key === "Enter") { e.preventDefault(); runTimeline().catch((err) => toast(err.message, true)); } });
    });
  };

  function timelineParams() {
    const p = new URLSearchParams();
    const coord = $("#timeline-coordinate").value.trim();
    const tenant = $("#timeline-tenant").value.trim();
    const identity = $("#timeline-identity").value.trim();
    const incident = $("#timeline-incident").value.trim();
    if (coord) p.set("coordinate", coord);
    if (tenant) p.set("tenant", tenant);
    if (identity) p.set("identity", identity);
    if (incident) p.set("incident", incident);
    if (!coord && !tenant && !identity && !incident) p.set("all", "true");
    return p;
  }

  async function runTimeline() {
    const meta = $("#timeline-meta");
    const body = clear($("#timeline-body"));
    meta.textContent = "reconstructing…";
    let res;
    try { res = await api.get("timeline?" + timelineParams().toString()); }
    catch (e) { meta.textContent = "error: " + e.message; throw e; }
    if (!res.events || !res.events.length) {
      body.appendChild(emptyRow($("#timeline-table"), 8, "No correlated events for this scope."));
      meta.textContent = "0 events";
      return;
    }
    res.events.forEach((ev) => {
      const src = (ev.corroborated && ev.corroborated.length > 1) ? ev.corroborated.join("+") : ev.source;
      let proofCell;
      if (ev.proof && ev.proof.auditSeq) {
        if (ev.proof.path) {
          proofCell = el("td", null, el("a", { href: ev.proof.path.replace(/^\//, ""), target: "_blank", rel: "noopener", text: "seq " + ev.proof.auditSeq }));
        } else {
          proofCell = el("td.muted", { text: "seq " + ev.proof.auditSeq });
        }
      } else {
        proofCell = el("td.muted", { text: "—" });
      }
      const decClass = ev.decision === "block" ? "bad" : (ev.decision === "warn" ? "warn" : "");
      body.appendChild(el("tr", null,
        el("td", null, el("span.mono.muted", { text: fmtTime(ev.time) })),
        el("td", null, el("span.mono", { text: src })),
        el("td", null, el("span.muted", { text: ev.category || "" })),
        el("td", null, el("span" + (decClass ? "." + decClass : ""), { text: ev.decision || "—" })),
        el("td", null, el("span.truncate", { title: ev.actor || "", text: ev.actor || "—" })),
        el("td", null, el("span.mono.truncate", { title: ev.coordinate || "", text: ev.coordinate || "—" })),
        el("td", null, el("span.truncate", { title: ev.summary || "", text: ev.summary || ev.kind || "—" })),
        proofCell));
    });
    const trunc = res.truncated ? " · truncated (raise limit)" : "";
    const srcs = Object.entries(res.sources || {}).filter(([, v]) => v).map(([k]) => k);
    meta.textContent = `${res.returned}/${res.total} events · sources: ${srcs.join(", ") || "none"}${trunc}`;
  }

  async function exportTimeline() {
    const p = timelineParams();
    p.set("format", "md");
    const md = await api.raw("timeline?" + p.toString());
    const blob = new Blob([md], { type: "text/markdown" });
    const url = URL.createObjectURL(blob);
    const a = el("a", { href: url, download: "incident-timeline.md" });
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
    toast("Markdown forensic report downloaded");
  }

  // --- Per-coordinate security dossier / 360 view (Task 87) -----------------
  let dossierWired = false;
  views.dossier = async function () {
    if (dossierWired) return;
    dossierWired = true;
    $("#dossier-run").addEventListener("click", () => runDossier().catch((e) => toast(e.message, true)));
    $("#dossier-export").addEventListener("click", () => exportDossier().catch((e) => toast(e.message, true)));
    ["#dossier-ecosystem", "#dossier-coordinate", "#dossier-tenant"].forEach((id) => {
      $(id).addEventListener("keydown", (e) => { if (e.key === "Enter") { e.preventDefault(); runDossier().catch((err) => toast(err.message, true)); } });
    });
  };

  function dossierParams() {
    const p = new URLSearchParams();
    const eco = $("#dossier-ecosystem").value.trim();
    const coord = $("#dossier-coordinate").value.trim();
    const tenant = $("#dossier-tenant").value.trim();
    if (eco) p.set("ecosystem", eco);
    if (coord) p.set("coordinate", coord);
    if (tenant) p.set("tenant", tenant);
    return p;
  }

  async function runDossier() {
    const meta = $("#dossier-meta");
    const card = clear($("#dossier-card"));
    if (!$("#dossier-coordinate").value.trim()) { meta.textContent = "enter a coordinate"; return; }
    meta.textContent = "assembling…";
    let d;
    try { d = await api.get("dossier?" + dossierParams().toString()); }
    catch (e) { meta.textContent = "error: " + e.message; throw e; }
    renderDossier(card, d);
    const on = (d.sources || []).filter((s) => s.status !== "disabled").length;
    meta.textContent = `${on} sources consulted${d.partial ? " · PARTIAL" : ""}`;
  }

  async function exportDossier() {
    if (!$("#dossier-coordinate").value.trim()) { toast("enter a coordinate first", true); return; }
    const p = dossierParams();
    p.set("format", "md");
    const md = await api.raw("dossier?" + p.toString());
    const blob = new Blob([md], { type: "text/markdown" });
    const url = URL.createObjectURL(blob);
    const a = el("a", { href: url, download: "security-dossier.md" });
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
    toast("Markdown dossier downloaded");
  }

  function dossierVerdictClass(v) {
    return v === "block" ? "bad" : (v === "warn" ? "warn" : (v === "admit" ? "ok" : "muted"));
  }

  function dossierKV(label, value) {
    return el("div.stat", null,
      el("div.label", { text: label }),
      el("div.value", value instanceof Node ? null : { text: value == null ? "—" : String(value) }, value instanceof Node ? value : null));
  }

  function dossierSection(title, rows) {
    const kept = rows.filter(Boolean);
    if (!kept.length) return null;
    return el("div.card", null, el("h3", { text: title }), el("div.stat-grid", null, kept));
  }

  function renderDossier(root, d) {
    const h = d.headline || {};
    const coord = (d.ecosystem ? d.ecosystem + "/" : "") + (d.coordinate || "");

    // Headline banner.
    const reasons = (h.reasons || []).map((r) => el("li", { text: r }));
    root.appendChild(el("div.card", null,
      el("div", { style: "display:flex;align-items:center;gap:.6rem;flex-wrap:wrap" },
        el("span.badge." + dossierVerdictClass(h.verdict), { text: (h.verdict || "unknown").toUpperCase() }),
        el("strong.mono", { text: coord }),
        h.riskBand ? el("span.muted", { text: `risk ${h.riskScore} (${h.riskBand})` }) : null,
        d.partial ? el("span.badge.warn", { text: "PARTIAL" }) : null),
      h.summary ? el("p", { text: h.summary }) : null,
      reasons.length ? el("ul", null, reasons) : null));

    // Identity.
    root.appendChild(dossierSection("Identity", [
      dossierKV("Tenant", d.tenant || "—"),
      dossierKV("Digest", d.digest ? shortSha(d.digest) : "—"),
      dossierKV("Backend", d.backend || "—"),
    ]));

    if (d.provenance) {
      const p = d.provenance;
      root.appendChild(dossierSection("Provenance & source", [
        dossierKV("Source commit", p.sourceCommit ? shortSha(p.sourceCommit) : "—"),
        dossierKV("Repository", p.repositoryUrl || "—"),
        dossierKV("Provenance verified", p.provenanceVerified ? "yes" : "no"),
        p.provenanceMismatch ? dossierKV("Source mismatch", el("span.bad", { text: "yes" })) : null,
        dossierKV("Downstream", `${p.directDependents} direct / ${p.downstreamPaths} paths`),
      ]));
    }

    if (d.risk) {
      const r = d.risk;
      root.appendChild(dossierSection("Risk", [
        dossierKV("Score", `${r.score} / 100 (${r.band})`),
        dossierKV("Action", r.block ? "block" : (r.warn ? "warn" : "allow")),
        r.summary ? dossierKV("Summary", r.summary) : null,
      ]));
    }

    if (d.vulnerabilities) {
      const v = d.vulnerabilities;
      root.appendChild(dossierSection("Vulnerabilities", [
        dossierKV("Total", `${v.total} (${v.critical}C / ${v.high}H / ${v.medium}M / ${v.low}L)`),
        dossierKV("Max severity", `${v.maxSeverity || "—"} (CVSS ${(v.maxCvss || 0).toFixed(1)})`),
        dossierKV("Quarantined", v.quarantined ? el("span.bad", { text: "yes" }) : "no"),
        v.vexSuppressed ? dossierKV("VEX-suppressed", v.vexSuppressed) : null,
      ]));
    }

    if (d.license) {
      root.appendChild(dossierSection("License", [
        dossierKV("Disposition", d.license.disposition),
        dossierKV("Licenses", (d.license.licenses || []).join(", ") || "—"),
      ]));
    }

    if (d.signature) {
      root.appendChild(dossierSection("Signature & attestation", [
        dossierKV("Status", d.signature.status),
        dossierKV("Verified signature", d.signature.verifiedSignature ? "yes" : "no"),
        dossierKV("Verified attestation", d.signature.verifiedAttestation ? "yes" : "no"),
      ]));
    }

    if (d.reproducibleBuild) {
      root.appendChild(dossierSection("Reproducible build", [
        dossierKV("Verdict", d.reproducibleBuild.verdict),
        d.reproducibleBuild.reason ? dossierKV("Reason", d.reproducibleBuild.reason) : null,
      ]));
    }

    if (d.sbomDrift) {
      const s = d.sbomDrift;
      root.appendChild(dossierSection("SBOM drift", [
        dossierKV("Drift score", `${(s.driftScore || 0).toFixed(1)} / 100${s.significant ? " (significant)" : ""}`),
        dossierKV("Range", `${s.fromVersion || "—"} → ${s.toVersion || "—"}`),
        dossierKV("Changes", `${s.addedDeps} added / ${s.removedDeps} removed · ${s.newVulnerabilities} new vulns`),
      ]));
    }

    if (d.suggestedFix) {
      const sf = d.suggestedFix;
      const rows = [
        dossierKV("Status", sf.status || "—"),
      ];
      if (sf.recommendedVersion) {
        rows.push(dossierKV("Upgrade to", sf.recommendedVersion));
      }
      if (sf.fixDescription) {
        rows.push(dossierKV("Advice", sf.fixDescription));
      }
      rows.push(dossierKV("Delta", `${sf.resolved} resolved · ${sf.residual} residual · ${sf.introduced} introduced`));
      if ((sf.resolvedFindings || []).length) {
        rows.push(dossierKV("Resolves", sf.resolvedFindings.join(", ")));
      }
      root.appendChild(dossierSection("Suggested fix", rows));
    }

    if (d.approvals) {
      root.appendChild(dossierSection("Approvals & break-glass", [
        dossierKV("Active grants", d.approvals.active),
        dossierKV("Pending reviews", d.approvals.pending),
      ]));
    }

    // Findings table.
    if (d.findings && (d.findings.items || []).length) {
      const f = d.findings;
      const tb = el("tbody");
      f.items.forEach((it) => {
        const sev = (it.severity || "").toLowerCase();
        const sevClass = sev === "critical" || sev === "high" ? "bad" : (sev === "medium" ? "warn" : "");
        tb.appendChild(el("tr", null,
          el("td", null, el("span" + (sevClass ? "." + sevClass : ""), { text: it.severity || "—" })),
          el("td", null, el("span.mono", { text: it.gate })),
          el("td", null, el("span.mono.muted", { text: it.ruleId || "—" })),
          el("td", null, el("span.truncate", { title: it.title || "", text: (it.title || "—") + (it.suppressed ? " (suppressed)" : "") }))));
      });
      root.appendChild(el("div.card", null,
        el("h3", { text: `Findings — ${f.total} (${f.blocking} blocking, worst ${f.worstSeverity || "—"})` }),
        el("div.table-wrap", null, el("table", null,
          el("thead", null, el("tr", null,
            el("th", { scope: "col", text: "Severity" }), el("th", { scope: "col", text: "Gate" }),
            el("th", { scope: "col", text: "Rule" }), el("th", { scope: "col", text: "Title" }))),
          tb))));
    }

    // Timeline.
    if (d.timeline && (d.timeline.events || []).length) {
      const t = d.timeline;
      const tb = el("tbody");
      t.events.forEach((ev) => {
        tb.appendChild(el("tr", null,
          el("td", null, el("span.mono.muted", { text: fmtTime(ev.time) })),
          el("td", null, el("span.mono", { text: ev.source })),
          el("td", null, el("span.muted", { text: ev.category || "" })),
          el("td", null, el("span", { text: ev.decision || "—" })),
          el("td", null, el("span.truncate", { title: ev.summary || "", text: ev.summary || "—" })),
          el("td", null, el("span.mono.muted", { text: ev.auditSeq ? "seq " + ev.auditSeq : "—" }))));
      });
      root.appendChild(el("div.card", null,
        el("h3", { text: `Correlated timeline — ${t.returned}/${t.total}${t.provable ? " · Merkle-provable" : ""}` }),
        el("div.table-wrap", null, el("table", null,
          el("thead", null, el("tr", null,
            el("th", { scope: "col", text: "Time (UTC)" }), el("th", { scope: "col", text: "Source" }),
            el("th", { scope: "col", text: "Category" }), el("th", { scope: "col", text: "Decision" }),
            el("th", { scope: "col", text: "Summary" }), el("th", { scope: "col", text: "Proof" }))),
          tb))));
    }

    // Suppression history (Task 165).
    if (d.suppressionHistory && (d.suppressionHistory.items || []).length) {
      const s = d.suppressionHistory;
      const tb = el("tbody");
      s.items.forEach((it) => {
        tb.appendChild(el("tr", null,
          el("td", null, el("span.mono", { text: it.mechanism })),
          el("td", null, el("span.mono.muted", { text: it.actor || "—" })),
          el("td", null, el("span.muted", { text: it.category || "—" })),
          el("td", null, el("span.mono", { text: it.identifier || it.ruleId || "—" })),
          el("td", null, el("span.truncate", { title: it.justification || "", text: it.justification || "—" }))));
      });
      const mech = s.byMechanism || {};
      const mechSummary = Object.keys(mech).sort().map((k) => `${k}: ${mech[k]}`).join(" · ");
      root.appendChild(el("div.card", null,
        el("h3", { text: `Suppression history — ${s.total}${mechSummary ? " (" + mechSummary + ")" : ""}` }),
        el("div.table-wrap", null, el("table", null,
          el("thead", null, el("tr", null,
            el("th", { scope: "col", text: "Mechanism" }), el("th", { scope: "col", text: "Actor" }),
            el("th", { scope: "col", text: "Category" }), el("th", { scope: "col", text: "Identifier" }),
            el("th", { scope: "col", text: "Justification" }))),
          tb))));
    }

    // Source coverage.
    const srcRows = (d.sources || []).slice().sort((a, b) => a.source.localeCompare(b.source)).map((s) => {
      const cls = s.status === "ok" ? "ok" : (s.status === "timeout" || s.status === "error" ? "bad" : "muted");
      return el("span.badge." + cls, { title: s.detail || "", text: `${s.source}: ${s.status}` });
    });
    root.appendChild(el("div.card", null, el("h3", { text: "Source coverage" }),
      el("div", { style: "display:flex;gap:.4rem;flex-wrap:wrap" }, srcRows)));
  }

  // --- Usage / chargeback (Task 84) -----------------------------------------
  let meteringWired = false;
  views.metering = async function () {
    if (!meteringWired) {
      meteringWired = true;
      $("#metering-run").addEventListener("click", () => runMetering().catch((e) => toast(e.message, true)));
      $("#metering-csv").addEventListener("click", () => exportMetering("csv", "usage.csv", "text/csv").catch((e) => toast(e.message, true)));
      $("#metering-md").addEventListener("click", () => exportMetering("markdown", "usage.md", "text/markdown").catch((e) => toast(e.message, true)));
      $("#metering-tenant").addEventListener("keydown", (e) => { if (e.key === "Enter") { e.preventDefault(); runMetering().catch((err) => toast(err.message, true)); } });
    }
    await runMetering();
  };

  function meteringParams() {
    const p = new URLSearchParams();
    const tenant = $("#metering-tenant").value.trim();
    const gran = $("#metering-granularity").value;
    if (tenant) p.set("tenant", tenant);
    if (gran) p.set("granularity", gran);
    return p;
  }

  function fmtCost(micros) {
    return (Number(micros || 0) / 1e6).toFixed(4);
  }

  async function runMetering() {
    const meta = $("#metering-meta");
    const totals = clear($("#metering-totals-body"));
    const rows = clear($("#metering-rows-body"));
    meta.textContent = "loading…";
    let rep;
    try { rep = await api.get("metering/usage?" + meteringParams().toString()); }
    catch (e) { meta.textContent = "error: " + e.message; throw e; }

    if (!rep.totals || !rep.totals.length) {
      totals.appendChild(emptyRow($("#metering-totals-table"), 9, "No usage recorded in the selected range."));
    } else {
      rep.totals.forEach((t) => {
        totals.appendChild(el("tr", null,
          el("td", null, el("span.mono", { text: t.tenant })),
          el("td.num", { text: String(t.requests || 0) }),
          el("td.num", { text: fmtBytes(t.bytesCacheHit || 0) }),
          el("td.num", { text: fmtBytes(t.bytesUpstream || 0) }),
          el("td.num", { text: fmtBytes(t.storageBytes || 0) }),
          el("td.num", { text: String(t.scanInvocations || 0) }),
          el("td.num", { text: fmtCost(t.scanCostMicros) }),
          el("td.num", { text: String(t.blocked || 0) }),
          el("td.num", { text: String(t.quarantined || 0) })));
      });
      const g = rep.grand || {};
      totals.appendChild(el("tr", null,
        el("td", null, el("strong", { text: "grand total" })),
        el("td.num", null, el("strong", { text: String(g.requests || 0) })),
        el("td.num", { text: fmtBytes(g.bytesCacheHit || 0) }),
        el("td.num", { text: fmtBytes(g.bytesUpstream || 0) }),
        el("td.num", { text: fmtBytes(g.storageBytes || 0) }),
        el("td.num", { text: String(g.scanInvocations || 0) }),
        el("td.num", { text: fmtCost(g.scanCostMicros) }),
        el("td.num", { text: String(g.blocked || 0) }),
        el("td.num", { text: String(g.quarantined || 0) })));
    }

    if (!rep.rows || !rep.rows.length) {
      rows.appendChild(emptyRow($("#metering-rows-table"), 7, "No periods in range."));
    } else {
      rep.rows.forEach((row) => {
        rows.appendChild(el("tr", null,
          el("td", null, el("span.mono", { text: row.tenant })),
          el("td", null, el("span.mono.muted", { text: row.periodStart })),
          el("td.num", { text: String(row.requests || 0) }),
          el("td.num", { text: fmtBytes((row.bytesCacheHit || 0) + (row.bytesUpstream || 0)) }),
          el("td.num", { text: String(row.scanInvocations || 0) }),
          el("td.num", { text: fmtCost(row.scanCostMicros) }),
          el("td.num", { text: String(row.blocked || 0) })));
      });
    }
    meta.textContent = `${rep.granularity} · ${rep.totals ? rep.totals.length : 0} tenant(s) · ${rep.rows ? rep.rows.length : 0} period(s)`;
  }

  async function exportMetering(format, filename, mime) {
    const p = meteringParams();
    p.set("format", format);
    const text = await api.raw("metering/usage?" + p.toString());
    const blob = new Blob([text], { type: mime });
    const url = URL.createObjectURL(blob);
    const a = el("a", { href: url, download: filename });
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
    toast(format.toUpperCase() + " chargeback report downloaded");
  }

  // --- Cache ----------------------------------------------------------------
  let cacheQueryTimer = null;
  views.cache = async function () {
    const q = $("#cache-search").value.trim();
    const body = clear($("#cache-body"));
    const data = await api.get("cache?q=" + encodeURIComponent(q));
    $("#cache-count").textContent =
      data.total ? `${data.returned} of ${data.total} entries` : "No entries";

    if (!data.items || !data.items.length) {
      body.appendChild(emptyRow($("#cache-table"), 6, q ? "No entries match your filter." : "The cache is empty."));
      return;
    }
    for (const item of data.items) {
      const del = el("button.btn.btn-sm.btn-danger", { type: "button", title: "Delete from cache", text: "Delete" });
      del.addEventListener("click", async (ev) => {
        ev.stopPropagation();
        if (!window.confirm("Evict this artifact from the cache?")) return;
        try {
          await api.del("cache/entry?key=" + encodeURIComponent(item.key));
          toast("Cache entry evicted");
          views.cache();
        } catch (e) { toast(e.message, true); }
      });
      const row = el("tr.clickable", { tabindex: "0", role: "button" },
        el("td", null, el("span.mono.truncate", { title: item.key, text: item.key })),
        el("td", null, el("span.truncate.muted", { title: item.origin || "", text: item.origin || "—" })),
        el("td.num", { text: fmtBytes(item.size) }),
        el("td", null, el("span.muted", { text: item.contentType || "—" })),
        el("td", null, el("span.muted", { text: fmtTime(item.modTime) })),
        el("td.num", null, del));
      const open = () => showCacheEntry(item);
      row.addEventListener("click", open);
      row.addEventListener("keydown", (e) => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); open(); } });
      body.appendChild(row);
    }
  };

  function showCacheEntry(item) {
    const pairs = [
      ["Key", el("span.mono", { text: item.key })],
      ["Origin", item.origin],
      ["Size", fmtBytes(item.size)],
      ["Content type", item.contentType],
      ["ETag", item.etag],
      ["Modified", fmtTime(item.modTime)],
    ];
    const body = el("div", null, kv(pairs));
    if (item.metadata && Object.keys(item.metadata).length) {
      body.appendChild(el("h3", { text: "Metadata" }));
      body.appendChild(el("pre", { text: JSON.stringify(item.metadata, null, 2) }));
    }
    openDrawer("Cached artifact", body);
  }

  // --- Scans ----------------------------------------------------------------
  views.scans = async function () {
    const body = clear($("#scan-body"));
    const data = await api.get("scans");
    if (!data.enabled) {
      $("#scan-count").textContent = "Commit scanning is disabled.";
      body.appendChild(emptyRow($("#scan-table"), 6, "Commit scanning is not enabled."));
      return;
    }
    $("#scan-count").textContent =
      `${data.returned} of ${data.total} verdicts · ${data.queueDepth || 0} queued`;
    if (!data.items || !data.items.length) {
      body.appendChild(emptyRow($("#scan-table"), 6, "No commits have been scanned yet."));
      return;
    }
    for (const v of data.items) {
      const row = el("tr.clickable", { tabindex: "0", role: "button" },
        el("td", null, el("span.mono", { title: v.sha, text: shortSha(v.sha) })),
        el("td.num", null, riskWidget(v.riskScore)),
        el("td", null, sevBadge(v.highestSeverity)),
        el("td.num", { text: v.findings ?? 0 }),
        el("td", null, verdictPill(v.malicious)),
        el("td", null, el("span.muted", { text: fmtTime(v.scannedAt) })));
      const open = () => showScanEntry(v.sha);
      row.addEventListener("click", open);
      row.addEventListener("keydown", (e) => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); open(); } });
      body.appendChild(row);
    }
  };

  async function showScanEntry(sha) {
    let v;
    try {
      v = await api.get("scans/entry?sha=" + encodeURIComponent(sha));
    } catch (e) { toast(e.message, true); return; }
    const head = kv([
      ["Commit", el("span.mono", { text: v.sha })],
      ["Repository", v.repositoryUrl || v.repository],
      ["Risk", riskWidget(v.riskScore)],
      ["Severity", sevBadge(v.highestSeverity || (v.findings && v.findings.length ? "high" : "info"))],
      ["Verdict", verdictPill(v.malicious)],
      ["Provider", v.provider],
      ["Scanned", fmtTime(v.scannedAt)],
    ]);
    const body = el("div", null, head);
    if (v.summary) body.appendChild(el("p", { text: v.summary }));
    const findings = v.findings || [];
    body.appendChild(el("h3", { text: `Findings (${findings.length})` }));
    if (!findings.length) {
      body.appendChild(el("p.muted", { text: "No findings recorded for this commit." }));
    } else {
      for (const f of findings) {
        const card = el("div.finding", null,
          el("div.meta", null, sevBadge(f.severity), f.ruleId ? el("span.muted", { text: f.ruleId }) : null),
          el("h4", { text: f.title || f.ruleId || "Finding" }));
        if (f.detail) card.appendChild(el("p", { text: f.detail }));
        if (f.location) card.appendChild(el("p.muted.mono", { text: f.location }));
        body.appendChild(card);
      }
    }
    openDrawer("Commit scan verdict", body);
  }

  // --- Provenance -----------------------------------------------------------
  views.provenance = async function () {
    const out = clear($("#prov-result"));
    let data;
    try {
      data = await api.get("provenance/links");
    } catch (e) { out.appendChild(el("p.muted", { text: e.message })); return; }
    if (!data.enabled) {
      out.appendChild(el("p.muted", { text: "Provenance association is disabled. Enable it to browse package → commit links." }));
      return;
    }
    out.appendChild(el("h3", { text: `Established associations (${data.total || 0})` }));
    if (!data.items || !data.items.length) {
      out.appendChild(el("p.muted", { text: "No package → commit associations have been recorded yet." }));
      return;
    }
    const table = el("table");
    table.appendChild(el("thead", null, el("tr", null,
      el("th", { text: "Package" }), el("th", { text: "Source" }),
      el("th", { text: "Confidence" }), el("th", { text: "Risk" }))));
    const tbody = el("tbody");
    for (const l of data.items) {
      const name = [l.name, l.version].filter(Boolean).join("@") || l.digest || "—";
      const risk = l.verdict ? riskWidget(l.verdict.riskScore) : el("span.muted", { text: "—" });
      const row = el("tr.clickable", { tabindex: "0", role: "button" },
        el("td", null, el("span.mono.truncate", { title: name, text: name })),
        el("td", null, el("span.truncate.muted", { title: l.repositoryUrl || "", text: l.repositoryUrl || "—" })),
        el("td", null, confidenceBadge(l)),
        el("td", null, risk));
      row.addEventListener("click", () => showProvenance(l));
      row.addEventListener("keydown", (e) => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); showProvenance(l); } });
      tbody.appendChild(row);
    }
    table.appendChild(tbody);
    out.appendChild(el("div.table-wrap", null, table));
  };

  function confidenceBadge(l) {
    if (l.attested) return el("span.pill.ok", { text: "attested" });
    if (l.signatureVerified) return el("span.pill", { text: "signed" });
    return el("span.pill", { text: l.confidence || "claimed" });
  }

  function showProvenance(l) {
    const pairs = [
      ["Ecosystem", l.ecosystem],
      ["Name", l.name],
      ["Version", l.version],
      ["Digest", l.digest ? el("span.mono", { text: l.digest }) : null],
      ["Repository", l.repositoryUrl],
      ["Commit", l.commitSha ? el("span.mono", { text: l.commitSha }) : null],
      ["Builder", l.builderId],
      ["Confidence", l.confidence],
      ["Resolver", l.resolver],
      ["Predicate", l.predicateType],
      ["Signer", l.signerIdentity],
      ["Signature verified", l.signatureVerified ? "yes" : "no"],
      ["Trust chain", l.chainTrusted ? "trusted" : "untrusted"],
      ["Attested", l.attested ? `yes (${fmtBytes(l.attestationSize)})` : "no"],
    ];
    const body = el("div", null, kv(pairs));
    if (l.verdict) {
      body.appendChild(el("h3", { text: "Source commit risk" }));
      body.appendChild(kv([
        ["Commit", el("span.mono", { text: l.verdict.sha })],
        ["Risk", riskWidget(l.verdict.riskScore)],
        ["Severity", sevBadge(l.verdict.highestSeverity)],
        ["Findings", l.verdict.findings],
        ["Verdict", verdictPill(l.verdict.malicious)],
      ]));
    }
    openDrawer("Provenance association", body);
  }

  async function resolveProvenance(form) {
    const out = clear($("#prov-result"));
    const params = new URLSearchParams();
    ["ecosystem", "name", "version", "digest"].forEach((k) => {
      const v = form.elements[k].value.trim();
      if (v) params.set(k, v);
    });
    if (!params.get("name") && !params.get("digest")) {
      out.appendChild(el("p.muted", { text: "Provide at least a name or a digest to resolve." }));
      return;
    }
    out.appendChild(el("p.muted", { text: "Resolving…" }));
    try {
      const link = await api.get("provenance?" + params.toString());
      clear(out);
      out.appendChild(el("button.btn.btn-sm", { type: "button", text: "← Back to associations", onclick: () => views.provenance() }));
      const body = el("div", { style: "margin-top:.8rem" });
      showProvenanceInto(body, link);
      out.appendChild(body);
    } catch (e) {
      clear(out);
      out.appendChild(el("div.panel", null, el("p", { text: e.message })));
    }
  }

  function showProvenanceInto(node, l) {
    node.appendChild(el("h3", { text: [l.name, l.version].filter(Boolean).join("@") || l.digest || "Result" }));
    const pairs = [
      ["Repository", l.repositoryUrl],
      ["Commit", l.commitSha ? el("span.mono", { text: l.commitSha }) : null],
      ["Confidence", l.confidence],
      ["Resolver", l.resolver],
      ["Signature verified", l.signatureVerified ? "yes" : "no"],
      ["Attested", l.attested ? "yes" : "no"],
    ];
    node.appendChild(kv(pairs));
    if (l.verdict) {
      node.appendChild(el("h3", { text: "Source commit risk" }));
      node.appendChild(kv([
        ["Risk", riskWidget(l.verdict.riskScore)],
        ["Verdict", verdictPill(l.verdict.malicious)],
        ["Findings", l.verdict.findings],
      ]));
    }
  }

  // --- Compliance -----------------------------------------------------------
  function statusPill(status) {
    const s = (status || "na").toLowerCase();
    const cls = s === "pass" ? "ok" : s === "fail" ? "bad" : s === "warn" ? "warn" : "";
    return el("span.pill" + (cls ? "." + cls : ""), { text: s });
  }

  views.compliance = async function () {
    const cards = clear($("#compliance-cards"));
    const body = clear($("#compliance-body"));
    const meta = $("#compliance-meta");
    let data;
    try {
      data = await api.get("compliance");
    } catch (e) { meta.textContent = e.message; return; }

    if (data && data.enabled === false) {
      meta.textContent = "Compliance scorecard is disabled.";
      body.appendChild(emptyRow($("#compliance-table"), 5, "Enable compliance.enabled to compute the audit scorecard."));
      return;
    }

    meta.textContent = `Generated ${fmtTime(data.generatedAt)}` + (data.version ? ` · ${data.version}` : "");

    function stat(label, value, sub, cls) {
      return el("div.stat" + (cls ? "." + cls : ""), null,
        el("div.label", { text: label }),
        el("div.value", value instanceof Node ? null : { text: String(value) }, value instanceof Node ? value : null),
        sub ? el("div.sub", { text: sub }) : null);
    }
    const sum = data.summary || {};
    cards.appendChild(stat("Overall", el("span", null, statusPill(data.status), document.createTextNode(" " + fmtPct(data.score))),
      `grade ${data.grade}`));
    if (data.slsa) cards.appendChild(stat("SLSA (estimated)", data.slsa.track || "—", data.slsa.rationale || ""));
    cards.appendChild(stat("Controls", `${sum.pass || 0} passing`,
      `${sum.warn || 0} warn · ${sum.fail || 0} fail · ${sum.na || 0} n/a`));

    const controls = data.controls || [];
    if (!controls.length) {
      body.appendChild(emptyRow($("#compliance-table"), 5, "No controls evaluated."));
      return;
    }
    for (const c of controls) {
      const score = c.status === "na" ? "—" : fmtPct(c.score);
      body.appendChild(el("tr", null,
        el("td", null, statusPill(c.status)),
        el("td", null, el("strong", { text: c.title || c.id }), el("div", null, el("span.muted.mono", { text: c.id }))),
        el("td.num", { text: score }),
        el("td", null, el("span.muted", { text: (c.frameworks || []).join(", ") || "—" })),
        el("td", null, el("span.muted", { text: c.detail || "" }))));
    }
  };

  async function recomputeCompliance() {
    try {
      await api.post("compliance/refresh");
      toast("Compliance scorecard recomputed");
      views.compliance();
    } catch (e) { toast(e.message, true); }
  }

  async function exportCompliance() {
    try {
      const report = await api.get("compliance/export");
      const blob = new Blob([JSON.stringify(report, null, 2)], { type: "application/json" });
      downloadBlob(blob, "compliance-report.json");
      toast(report.signature ? "Signed report downloaded" : "Report downloaded (unsigned)");
    } catch (e) { toast(e.message, true); }
  }

  async function openComplianceHTML() {
    try {
      const html = await api.raw("compliance/report.html");
      const blob = new Blob([html], { type: "text/html" });
      const url = URL.createObjectURL(blob);
      window.open(url, "_blank", "noopener");
      setTimeout(() => URL.revokeObjectURL(url), 60000);
    } catch (e) { toast(e.message, true); }
  }

  function downloadBlob(blob, filename) {
    const url = URL.createObjectURL(blob);
    const a = el("a", { href: url, download: filename });
    document.body.appendChild(a);
    a.click();
    a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 10000);
  }

  // --- Curated compliance policy presets (Task 88) --------------------------
  let presetsLoaded = false;

  views.presets = async function () {
    const sel = $("#preset-select");
    if (!presetsLoaded) {
      const data = await api.get("presets");
      clear(sel);
      for (const p of data.presets || []) {
        sel.appendChild(el("option", { value: p.name },
          `${p.name} — ${p.title} (v${p.version})`));
      }
      presetsLoaded = true;
      $("#preset-preview").addEventListener("click", () => previewPreset().catch((e) => toast(e.message, true)));
      $("#preset-apply").addEventListener("click", () => applyPreset().catch((e) => toast(e.message, true)));
    }
    // Render the diff for the currently-selected preset on view entry.
    if (sel.value) await previewPreset();
  };

  async function previewPreset() {
    const name = $("#preset-select").value;
    if (!name) return;
    const meta = $("#preset-meta");
    meta.textContent = "loading…";
    let res;
    try { res = await api.get("presets/diff?name=" + encodeURIComponent(name)); }
    catch (e) { meta.textContent = "error: " + e.message; throw e; }
    renderPresetDiff(res.diff);
  }

  function renderPresetDiff(d) {
    const summary = clear($("#preset-summary"));
    const valid = !d.validation || d.validation.ok;
    summary.appendChild(el("div.stat-grid", null,
      el("div.stat", null, el("div.label", { text: "Standard" }), el("div.value", { text: d.standard || "—" })),
      el("div.stat", null, el("div.label", { text: "Changes" }),
        el("div.value", { text: String(d.changed || 0) }), el("div.sub", { text: (d.unchanged || 0) + " unchanged" })),
      el("div.stat", null, el("div.label", { text: "Projected config" }),
        el("div.value", null, el("span.pill." + (valid ? "ok" : "bad"), { text: valid ? "valid" : "INVALID" }))),
      el("div.stat", null, el("div.label", { text: "Controls satisfied" }),
        el("div.value", { text: (d.controls || []).join(", ") || "—" }))));
    $("#preset-meta").textContent = `${d.title} v${d.version}`;

    const body = clear($("#preset-body"));
    for (const s of d.settings || []) {
      body.appendChild(el("tr", null,
        el("td", null, s.changed ? el("span.pill.warn", { text: "~" }) : el("span.muted", { text: "·" })),
        el("td", null, el("code", { text: s.path })),
        el("td", null, el("span.muted", { text: s.current })),
        el("td", null, el("strong", { text: s.proposed })),
        el("td", null, el("span.muted", { text: s.clause || "" }))));
    }
  }

  async function applyPreset() {
    const name = $("#preset-select").value;
    if (!name) { toast("select a preset first", true); return; }
    if (!confirm(`Apply preset "${name}"? This rewrites the proxy's on-disk configuration across multiple gates. The previous config is backed up and the change is recorded in the audit log.`)) return;
    let result;
    try { result = await api.post("presets/apply", { name, confirm: true }); }
    catch (e) { toast(e.message, true); throw e; }
    toast(`Applied ${result.preset} v${result.version}: ${result.changed} setting(s) changed`);
    if (result.diff) renderPresetDiff(result.diff);
  }

  // --- Risk score -----------------------------------------------------------
  function bandPill(band) {
    const b = (band || "low").toLowerCase();
    const cls = b === "critical" || b === "high" ? "bad" : b === "medium" ? "warn" : "ok";
    return el("span.pill." + cls, { text: b });
  }

  function riskDecisionPill(a) {
    if (a.block) return el("span.pill.bad", { text: "block" });
    if (a.warn) return el("span.pill.warn", { text: "warn" });
    return el("span.muted", { text: "—" });
  }

  function riskDrivers(contribs) {
    const ranked = (contribs || []).slice().sort((x, y) => (y.points || 0) - (x.points || 0));
    const parts = ranked.filter((c) => (c.points || 0) > 0).slice(0, 3)
      .map((c) => `${c.signal} +${(c.points || 0).toFixed(1)}`);
    return parts.length ? parts.join(", ") : "all signals clean";
  }

  function showRiskAssessment(a) {
    const body = el("div");
    body.appendChild(el("div.stat-grid", null,
      el("div.stat", null, el("div.label", { text: "Score" }), el("div.value", null, riskWidget(a.score))),
      el("div.stat", null, el("div.label", { text: "Band" }), el("div.value", null, bandPill(a.band))),
      el("div.stat", null, el("div.label", { text: "Decision" }), el("div.value", null, riskDecisionPill(a)))));
    body.appendChild(kv([
      ["Artifact", a.artifact && (a.artifact.coordinate || a.artifact.name)],
      ["Ecosystem", a.artifact && a.artifact.ecosystem],
      ["Tenant", a.tenant],
      ["Threshold", `${a.thresholdAction} above ${a.thresholdBand}`],
      ["Summary", a.summary],
      ["Scored", fmtTime(a.scoredAt)],
    ]));

    body.appendChild(el("h2", { text: "Explainable breakdown", style: "margin-top:1.1rem" }));
    const table = el("table");
    table.appendChild(el("thead", null, el("tr", null,
      el("th", { text: "Signal" }), el("th.num", { text: "Sub-score" }),
      el("th.num", { text: "Weight" }), el("th.num", { text: "Points" }), el("th", { text: "Raw" }))));
    const tb = el("tbody");
    for (const c of a.contributions || []) {
      tb.appendChild(el("tr", null,
        el("td", null, el("strong", { text: c.signal })),
        el("td.num", { text: (c.subscore != null ? c.subscore.toFixed(2) : "—") }),
        el("td.num", { text: (c.normalizedWeight != null ? (c.normalizedWeight * 100).toFixed(0) + "%" : "—") }),
        el("td.num", { text: "+" + (c.points || 0).toFixed(1) }),
        el("td", null, el("span.muted", { text: c.raw || "" }))));
    }
    table.appendChild(tb);
    body.appendChild(el("div.table-wrap", null, table));
    if ((a.skipped || []).length) {
      body.appendChild(el("p.muted", { text: "Not evaluated: " + a.skipped.join(", "), style: "margin-top:.6rem" }));
    }
    openDrawer("Risk assessment", body);
  }

  views.riskscore = async function () {
    const cards = clear($("#riskscore-cards"));
    const body = clear($("#riskscore-body"));
    const meta = $("#riskscore-meta");
    let data;
    try {
      data = await api.get("riskscore");
    } catch (e) { meta.textContent = e.message; return; }

    if (data && data.enabled === false) {
      meta.textContent = "Unified risk scoring is disabled.";
      body.appendChild(emptyRow($("#riskscore-table"), 6, "Enable riskScore.enabled to compute composite risk scores."));
      return;
    }

    const thr = data.threshold || {};
    meta.textContent = `${data.totalScored || 0} scored · threshold: ${thr.action || "off"} above ${thr.band || "—"}`;

    function stat(label, value, sub) {
      return el("div.stat", null,
        el("div.label", { text: label }),
        el("div.value", value instanceof Node ? null : { text: String(value) }, value instanceof Node ? value : null),
        sub ? el("div.sub", { text: sub }) : null);
    }
    const byBand = data.byBand || {};
    cards.appendChild(stat("Total scored", data.totalScored || 0,
      `${data.blocked || 0} blocked · ${data.warned || 0} warned`));
    cards.appendChild(stat("Critical / High", el("span", null,
      bandPill("critical"), document.createTextNode(" " + (byBand.critical || 0) + " · "),
      bandPill("high"), document.createTextNode(" " + (byBand.high || 0)))));
    cards.appendChild(stat("Medium / Low", el("span", null,
      bandPill("medium"), document.createTextNode(" " + (byBand.medium || 0) + " · "),
      bandPill("low"), document.createTextNode(" " + (byBand.low || 0)))));
    cards.appendChild(stat("Threshold crossings", data.crossings || 0));

    const recent = data.recent || [];
    if (!recent.length) {
      body.appendChild(emptyRow($("#riskscore-table"), 6, "No artifacts scored yet."));
      return;
    }
    for (const a of recent) {
      const row = el("tr", null,
        el("td", null, bandPill(a.band)),
        el("td.num", null, riskWidget(a.score)),
        el("td", null, el("span.mono.truncate", {
          title: (a.artifact && a.artifact.coordinate) || "",
          text: (a.artifact && (a.artifact.coordinate || a.artifact.name)) || "—",
        })),
        el("td", null, riskDecisionPill(a)),
        el("td", null, el("span.muted", { text: riskDrivers(a.contributions) })),
        el("td", null, el("span.muted", { text: fmtTime(a.scoredAt) })));
      row.style.cursor = "pointer";
      row.addEventListener("click", () => showRiskAssessment(a));
      body.appendChild(row);
    }
  };

  // --- Source-repository health (Task 63) ---------------------------------
  views.reposcore = async function () {
    const cards = clear($("#reposcore-cards"));
    const body = clear($("#reposcore-body"));
    const meta = $("#reposcore-meta");
    let data;
    try {
      data = await api.get("reposcore");
    } catch (e) { meta.textContent = e.message; return; }

    if (data && data.enabled === false) {
      meta.textContent = "Source-repository health scoring is disabled.";
      body.appendChild(emptyRow($("#reposcore-table"), 5, "Enable repoScore.enabled to derive OpenSSF Scorecard-style signals."));
      return;
    }

    meta.textContent = `${data.evaluated || 0} evaluated · ${data.resolved || 0} resolved · ${data.unresolved || 0} unresolved · avg health ${data.avgHealth || 0}/100`;

    function stat(label, value, sub) {
      return el("div.stat", null,
        el("div.label", { text: label }),
        el("div.value", value instanceof Node ? null : { text: String(value) }, value instanceof Node ? value : null),
        sub ? el("div.sub", { text: sub }) : null);
    }
    const byGrade = data.byGrade || {};
    cards.appendChild(stat("Resolved repos", data.resolved || 0,
      `${data.unresolved || 0} unresolved · ${data.errors || 0} errors`));
    cards.appendChild(stat("Average health", (data.avgHealth || 0) + "/100"));
    cards.appendChild(stat("Grades A–C", `${byGrade.A || 0} · ${byGrade.B || 0} · ${byGrade.C || 0}`, "A · B · C"));
    cards.appendChild(stat("Grades D–F", `${byGrade.D || 0} · ${byGrade.F || 0}`, "D · F"));

    const recent = data.recent || [];
    if (!recent.length) {
      body.appendChild(emptyRow($("#reposcore-table"), 5, "No repositories scored yet."));
      return;
    }
    for (const r of recent) {
      const weak = (r.weak || []).join(", ");
      const health = r.resolved ? riskWidget(r.health) : el("span.muted", { text: "—" });
      const row = el("tr", null,
        el("td", null, el("span.mono.truncate", { title: r.repositoryUrl || "", text: r.repositoryUrl || "—" })),
        el("td.num", null, health),
        el("td", null, el("span.muted", { text: r.resolved ? (r.grade || "—") : "unresolved" })),
        el("td", null, el("span.muted", { text: weak || (r.resolved ? "—" : (r.error || "")) })),
        el("td", null, el("span.muted", { text: fmtTime(r.evaluatedAt) })));
      body.appendChild(row);
    }
  };

  // --- SBOM diff & dependency drift (Task 64) ------------------------------
  views.sbomdiff = async function () {
    const cards = clear($("#sbomdiff-cards"));
    const body = clear($("#sbomdiff-body"));
    const meta = $("#sbomdiff-meta");
    let data;
    try {
      data = await api.get("sbomdiff");
    } catch (e) { meta.textContent = e.message; return; }

    const m = (data && data.metrics) || {};
    if (m.enabled === false) {
      meta.textContent = "SBOM diff / dependency-drift subsystem is disabled.";
      body.appendChild(emptyRow($("#sbomdiff-table"), 6, "Enable sbomDiff.enabled to track per-coordinate dependency drift."));
      return;
    }
    meta.textContent = `${m.observed || 0} observed · ${m.compared || 0} compared · ${m.significant || 0} significant · action ${m.action || "warn"}`;

    function stat(label, value, sub) {
      return el("div.stat", null,
        el("div.label", { text: label }),
        el("div.value", { text: String(value) }),
        sub ? el("div.sub", { text: sub }) : null);
    }
    cards.appendChild(stat("Coordinates tracked", m.coordinates || 0, `history ${m.historySize || 0}/version`));
    cards.appendChild(stat("Significant drifts", m.significant || 0, `${m.compared || 0} compared`));
    cards.appendChild(stat("Warn / Block / Quar.", `${m.warned || 0} · ${m.blocked || 0} · ${m.quarantined || 0}`));
    cards.appendChild(stat("Thresholds", `${m.warnThreshold || 0} / ${m.significantThreshold || 0} / ${m.blockThreshold || 0}`, "warn / sig / block"));

    // On-demand diff runner.
    const run = $("#sbomdiff-run");
    if (run) {
      run.onclick = async function () {
        const eco = ($("#sbomdiff-eco").value || "").trim();
        const pkg = ($("#sbomdiff-pkg").value || "").trim();
        const tenant = ($("#sbomdiff-tenant").value || "").trim();
        const from = ($("#sbomdiff-from").value || "").trim();
        const to = ($("#sbomdiff-to").value || "").trim();
        const out = $("#sbomdiff-report");
        if (!eco || !pkg) { out.textContent = "ecosystem and package are required"; return; }
        const q = new URLSearchParams({ ecosystem: eco, package: pkg, format: "md" });
        if (tenant) q.set("tenant", tenant);
        if (from) q.set("from", from);
        if (to) q.set("to", to);
        try {
          out.textContent = await api.raw("sbomdiff/diff?" + q.toString());
        } catch (e) { out.textContent = e.message; }
      };
    }

    const recent = m.recentDrifts || [];
    if (!recent.length) {
      body.appendChild(emptyRow($("#sbomdiff-table"), 6, "No significant drift recorded yet."));
      return;
    }
    for (const r of recent) {
      const row = el("tr", null,
        el("td", null, el("span.muted", { text: r.ecosystem || "—" })),
        el("td", null, el("span.mono.truncate", { title: r.coordinate || "", text: r.coordinate || "—" })),
        el("td", null, el("span.mono", { text: `${r.fromVersion || "?"} → ${r.toVersion || "?"}` })),
        el("td.num", null, riskWidget(r.driftScore)),
        el("td", null, el("span.muted", { text: r.action || "—" })),
        el("td", null, el("span.muted", { text: `${r.addedDeps || 0} / ${r.newVulnerabilities || 0} / ${r.newLicenses || 0} / ${r.newNamespaces || 0}` })));
      body.appendChild(row);
    }
  };

  // --- WASM extension gates ------------------------------------------------
  function fmtBytes(n) {
    n = Number(n) || 0;
    if (n >= 1 << 20) return (n / (1 << 20)).toFixed(0) + "MiB";
    if (n >= 1 << 10) return (n / (1 << 10)).toFixed(0) + "KiB";
    return n + "B";
  }
  views.extensions = async function () {
    const cards = clear($("#extensions-cards"));
    const body = clear($("#extensions-body"));
    const meta = $("#extensions-meta");
    let data;
    try {
      data = await api.get("extensions");
    } catch (e) { meta.textContent = e.message; return; }

    if (data && data.enabled === false) {
      meta.textContent = "WASM extension gates are disabled.";
      body.appendChild(emptyRow($("#extensions-table"), 7, "Enable extensions and configure modules to add custom admission gates."));
      return;
    }
    const mods = (data && data.modules) || [];
    meta.textContent = `${mods.length} module(s) · ABI v${data.abiVersion}`;

    function stat(label, value, sub) {
      return el("div.stat", null,
        el("div.label", { text: label }),
        el("div.value", { text: String(value) }),
        sub ? el("div.sub", { text: sub }) : null);
    }
    let loaded = 0, totalInv = 0, totalBlock = 0;
    for (const m of mods) {
      if (m.loaded) loaded++;
      totalInv += m.invocations || 0;
      totalBlock += m.block || 0;
    }
    cards.appendChild(stat("Modules loaded", `${loaded} / ${mods.length}`));
    cards.appendChild(stat("Invocations", totalInv));
    cards.appendChild(stat("Blocks", totalBlock));

    if (!mods.length) {
      body.appendChild(emptyRow($("#extensions-table"), 7, "No extension modules configured."));
      return;
    }
    for (const m of mods) {
      const status = m.loaded
        ? el("span.pill.ok", { text: "loaded" })
        : el("span.pill.bad", { text: "not loaded", title: m.loadError || "" });
      const limits = `${m.timeoutMs}ms · ${fmtBytes(m.memoryBytes)}` + (m.fuel ? ` · fuel ${m.fuel}` : "");
      const row = el("tr", null,
        el("td", null, el("span.mono", { text: m.name })),
        el("td", null, status),
        el("td", null, el("span.muted", { text: m.failClosed ? "fail-closed" : "fail-open" })),
        el("td", null, el("span.muted", { text: limits })),
        el("td.num", { text: String(m.invocations || 0) }),
        el("td", null, el("span.muted", { text: `${m.allow || 0} / ${m.warn || 0} / ${m.block || 0}` })),
        el("td", null, el("span.muted", { text: `${m.timeouts || 0} / ${m.fuelExhausted || 0} / ${m.errors || 0}` })));
      body.appendChild(row);
    }
  };

  // --- Behavioral anomaly detection ----------------------------------------
  function levelPill(level) {
    const l = (level || "none").toLowerCase();
    if (l === "none") return el("span.muted", { text: "none" });
    const cls = l === "high" ? "bad" : l === "medium" ? "warn" : "ok";
    return el("span.pill." + cls, { text: l });
  }

  function anomalyActionPill(action) {
    const a = (action || "observe").toLowerCase();
    if (a === "block") return el("span.pill.bad", { text: "block" });
    if (a === "warn") return el("span.pill.warn", { text: "warn" });
    return el("span.muted", { text: "observe" });
  }

  function anomalyDetectors(detectors) {
    const triggered = (detectors || []).filter((d) => d.triggered)
      .sort((x, y) => (y.score || 0) - (x.score || 0));
    if (!triggered.length) return el("span.muted", { text: "—" });
    return el("span", null, ...triggered.slice(0, 4).map((d) =>
      el("span.chip", { text: `${d.detector} ${(d.value || 0)}`, title: d.detail || "" })));
  }

  function scopeLabel(s) {
    if (s.tenant && s.identity) return `${s.tenant} / ${s.identity}`;
    return s.identity || s.tenant || s.scope || "—";
  }

  views.anomaly = async function () {
    const cards = clear($("#anomaly-cards"));
    const scopesBody = clear($("#anomaly-scopes-body"));
    const triggersBody = clear($("#anomaly-triggers-body"));
    const meta = $("#anomaly-meta");
    let data;
    try {
      data = await api.get("anomaly");
    } catch (e) { meta.textContent = e.message; return; }

    if (data && data.enabled === false) {
      meta.textContent = "Behavioral anomaly detection is disabled.";
      scopesBody.appendChild(emptyRow($("#anomaly-scopes-table"), 6, "Enable anomaly.enabled to watch the pull stream."));
      triggersBody.appendChild(emptyRow($("#anomaly-triggers-table"), 6, "—"));
      return;
    }

    const thr = data.threshold || {};
    const blockTxt = thr.blockLevel && thr.blockLevel !== "none" ? `block ≥ ${thr.blockLevel}` : "soft-block off";
    meta.textContent = `${data.observed || 0} observed · window ${data.window || "—"} · warn ≥ ${thr.warnLevel || "—"} · ${blockTxt}`;

    function stat(label, value, sub) {
      return el("div.stat", null,
        el("div.label", { text: label }),
        el("div.value", value instanceof Node ? null : { text: String(value) }, value instanceof Node ? value : null),
        sub ? el("div.sub", { text: sub }) : null);
    }
    const byLevel = data.byLevel || {};
    cards.appendChild(stat("Observations", data.observed || 0, `${data.trackedScopes || 0} scopes tracked`));
    cards.appendChild(stat("Alerts", data.alerts || 0, `${data.softBlocks || 0} soft-blocks`));
    cards.appendChild(stat("High / Medium", el("span", null,
      levelPill("high"), document.createTextNode(" " + (byLevel.high || 0) + " · "),
      levelPill("medium"), document.createTextNode(" " + (byLevel.medium || 0)))));
    const trig = data.triggersByType || {};
    const topDet = Object.keys(trig).sort((a, b) => (trig[b] || 0) - (trig[a] || 0))[0];
    cards.appendChild(stat("Top detector", topDet ? topDet : "—", topDet ? `${trig[topDet]} triggers` : "no triggers"));

    const scopes = (data.scopes || []).filter((s) => (s.level || "none") !== "none");
    if (!scopes.length) {
      scopesBody.appendChild(emptyRow($("#anomaly-scopes-table"), 6, "No scopes are currently anomalous."));
    } else {
      for (const s of scopes) {
        scopesBody.appendChild(el("tr", null,
          el("td", null, levelPill(s.level)),
          el("td.num", null, el("span", { text: String(Math.round(s.score || 0)) })),
          el("td", null, el("span.mono.truncate", { title: s.scope || "", text: scopeLabel(s) })),
          el("td", null, anomalyActionPill(s.action)),
          el("td", null, anomalyDetectors(s.detectors)),
          el("td", null, el("span.muted", { text: fmtTime(s.updatedAt) }))));
      }
    }

    const recent = data.recent || [];
    if (!recent.length) {
      triggersBody.appendChild(emptyRow($("#anomaly-triggers-table"), 6, "No triggers recorded yet."));
    } else {
      for (const t of recent) {
        triggersBody.appendChild(el("tr", null,
          el("td", null, levelPill(t.level)),
          el("td.num", null, el("span", { text: String(Math.round(t.score || 0)) })),
          el("td", null, el("span.mono.truncate", { title: t.scope || "", text: t.scope || "—" })),
          el("td", null, t.detector ? el("span.chip", { text: t.detector }) : el("span.muted", { text: "—" })),
          el("td", null, el("span.muted.truncate", { title: t.summary || "", text: t.summary || "" })),
          el("td", null, el("span.muted", { text: fmtTime(t.at) }))));
      }
    }
  };

  // --- Maturity (release-maturity / version cooldown) -----------------------
  function fmtDurSecs(s) {
    s = Math.max(0, Math.round(Number(s) || 0));
    if (s < 60) return `${s}s`;
    if (s < 3600) return `${Math.floor(s / 60)}m ${s % 60}s`;
    if (s < 86400) return `${Math.floor(s / 3600)}h ${Math.floor((s % 3600) / 60)}m`;
    return `${Math.floor(s / 86400)}d ${Math.floor((s % 86400) / 3600)}h`;
  }

  views.maturity = async function () {
    const cards = clear($("#maturity-cards"));
    const body = clear($("#maturity-body"));
    const meta = $("#maturity-meta");
    let data;
    try {
      data = await api.get("maturity");
    } catch (e) { meta.textContent = e.message; return; }

    if (data && data.enabled === false) {
      meta.textContent = "Release-maturity (version-cooldown) gate is disabled.";
      body.appendChild(emptyRow($("#maturity-table"), 7, "Set maturity.defaultCooldown (or a per-ecosystem cooldown) to enable."));
      return;
    }

    const defc = data.defaultCooldownSeconds || 0;
    const failTxt = data.failClosedOnUnknown ? "fail-closed on unknown" : "fail-open on unknown";
    meta.textContent = `default cooldown ${defc > 0 ? fmtDurSecs(defc) : "off"} · ${failTxt} · ${data.tenantOverrides || 0} tenant overrides · ${data.allowlistSize || 0} allowlisted`;

    function stat(label, value, sub) {
      return el("div.stat", null,
        el("div.label", { text: label }),
        el("div.value", { text: String(value) }),
        sub ? el("div.sub", { text: sub }) : null);
    }
    cards.appendChild(stat("Cooling now", data.coolingNow || 0, "versions held in cooldown"));
    cards.appendChild(stat("Cooldown blocks", data.blocks || 0, `${data.checks || 0} checks`));
    cards.appendChild(stat("Allowlisted", data.allowlisted || 0, "bypassed cooldown"));
    cards.appendChild(stat("Unknown publish time", data.unknown || 0, data.failClosedOnUnknown ? "blocked (fail-closed)" : "admitted (fail-open)"));

    const cooling = data.cooling || [];
    if (!cooling.length) {
      body.appendChild(emptyRow($("#maturity-table"), 7, "No versions are currently cooling."));
      return;
    }
    for (const c of cooling) {
      body.appendChild(el("tr", null,
        el("td", null, el("span.chip", { text: c.ecosystem || "—" })),
        el("td", null, el("span.mono.truncate", { title: c.name || "", text: c.name || "—" })),
        el("td", null, el("span.mono", { text: c.version || "—" })),
        el("td", null, el("span.muted", { text: c.tenant || "—" })),
        el("td", null, el("span.muted", { text: fmtTime(c.publishedAt) })),
        el("td.num", null, el("span", { text: fmtDurSecs(c.remainingSeconds) })),
        el("td", null, el("span.muted", { text: fmtTime(c.availableAt) }))));
    }
  };

  // --- Continuity (maintainer/publisher monitoring) -------------------------
  views.continuity = async function () {
    const cards = clear($("#continuity-cards"));
    const body = clear($("#continuity-body"));
    const meta = $("#continuity-meta");
    let data;
    try {
      data = await api.get("continuity");
    } catch (e) { meta.textContent = e.message; return; }

    if (data && data.enabled === false) {
      meta.textContent = "Maintainer/publisher continuity gate is disabled.";
      body.appendChild(emptyRow($("#continuity-table"), 7, "Set continuity.enabled to monitor ownership changes."));
      return;
    }

    const disp = data.defaultDisposition || "observe";
    const cd = data.cooldownSeconds || 0;
    meta.textContent = `default disposition ${disp} · trust cooldown ${cd > 0 ? fmtDurSecs(cd) : "off"} · ${data.knownCoordinates || 0} known packages · ${data.tenantOverrides || 0} tenant overrides · ${data.allowlistSize || 0} allowlisted`;

    function stat(label, value, sub) {
      return el("div.stat", null,
        el("div.label", { text: label }),
        el("div.value", { text: String(value) }),
        sub ? el("div.sub", { text: sub }) : null);
    }
    cards.appendChild(stat("Maintainer drifts", data.drifts || 0, `${data.checks || 0} checks`));
    cards.appendChild(stat("Blocked", data.blocks || 0, "drift under block disposition"));
    cards.appendChild(stat("First-use (TOFU)", data.firstUse || 0, `${data.knownCoordinates || 0} known packages`));
    cards.appendChild(stat("Untrusted now", data.pendingNow || 0, "new maintainers in cooldown"));

    const pending = data.pending || [];
    if (!pending.length) {
      body.appendChild(emptyRow($("#continuity-table"), 7, "No maintainer drift is currently in cooldown."));
      return;
    }
    for (const p of pending) {
      body.appendChild(el("tr", null,
        el("td", null, el("span.chip", { text: p.ecosystem || "—" })),
        el("td", null, el("span.mono.truncate", { title: p.name || "", text: p.name || "—" })),
        el("td", null, el("span.mono", { text: p.lastVersion || "—" })),
        el("td", null, el("span.mono.truncate", { title: (p.pending || []).join(", "), text: (p.pending || []).join(", ") || "—" })),
        el("td.num", null, el("span", { text: String(p.trustedCount || 0) })),
        el("td.num", null, el("span", { text: fmtDurSecs(p.remainingSeconds) })),
        el("td", null, el("span.muted", { text: fmtTime(p.firstSeen) }))));
    }
  };

  // --- Egress / SSRF guard --------------------------------------------------
  views.egress = async function () {
    const cards = clear($("#egress-cards"));
    const reasonBody = clear($("#egress-reason-body"));
    const recentBody = clear($("#egress-recent-body"));
    const allowChips = clear($("#egress-allowlist"));
    const meta = $("#egress-meta");
    let data;
    try {
      data = await api.get("egress");
    } catch (e) { meta.textContent = e.message; return; }

    if (!data || data.enabled === false) {
      meta.textContent = "The SSRF / outbound-egress guard is disabled.";
      reasonBody.appendChild(emptyRow($("#egress-reason-table"), 2, "Set egress.enabled to harden outbound fetches."));
      return;
    }
    const p = data.policy || {};
    const schemes = (p.allowedSchemes && p.allowedSchemes.length) ? p.allowedSchemes.join(",") : (p.httpsOnly ? "https" : "https,http");
    meta.textContent = `schemes ${schemes} · ${p.allowlistEnforced ? "host allowlist enforced" : "no host allowlist"} · ${p.blockPrivateNetworks ? "private ranges blocked" : "private ranges allowed"} · redirects ${p.followRedirects ? "follow ≤ " + p.maxRedirects : "off"}`;

    function stat(label, value, sub) {
      return el("div.stat", null,
        el("div.label", { text: label }),
        el("div.value", { text: String(value) }),
        sub ? el("div.sub", { text: sub }) : null);
    }
    cards.appendChild(stat("Blocked", p.blocked || 0, `${p.checked || 0} checks`));
    cards.appendChild(stat("Allowed", p.allowed || 0, "permitted fetches"));
    cards.appendChild(stat("Allowlist entries", (p.allowlist || []).length, p.allowlistEnforced ? "deny-by-default" : "advisory"));
    cards.appendChild(stat("Exceptions", (p.allowedDestinationCidrs || []).length, "private-range exceptions"));

    for (const entry of (p.allowlist || [])) {
      const del = el("button.btn.btn-sm", { text: entry + " ✕", title: "Remove " + entry, type: "button" });
      del.addEventListener("click", async () => {
        try { await egressAllowlist("remove", entry); } catch (e) { toast(e.message, true); }
      });
      allowChips.appendChild(del);
    }
    if (!(p.allowlist || []).length) {
      allowChips.appendChild(el("span.muted", { text: "No host allowlist — only scheme and IP-range floors apply." }));
    }

    const byReason = p.blockedByReason || {};
    const reasons = Object.keys(byReason).filter((k) => byReason[k] > 0).sort((a, b) => byReason[b] - byReason[a]);
    if (!reasons.length) {
      reasonBody.appendChild(emptyRow($("#egress-reason-table"), 2, "No egress blocks recorded."));
    } else {
      for (const r of reasons) {
        reasonBody.appendChild(el("tr", null,
          el("td", null, el("span.chip", { text: r })),
          el("td.num", null, el("span", { text: String(byReason[r]) }))));
      }
    }

    const recent = p.recent || [];
    if (!recent.length) {
      recentBody.appendChild(emptyRow($("#egress-recent-table"), 5, "No recent blocks."));
    } else {
      for (let i = recent.length - 1; i >= 0; i--) {
        const b = recent[i];
        recentBody.appendChild(el("tr", null,
          el("td", null, el("span.muted", { text: fmtTime(b.time) })),
          el("td", null, el("span.chip", { text: b.reason || "—" })),
          el("td", null, el("span.muted", { text: b.tenant || "—" })),
          el("td", null, el("span.mono.truncate", { title: b.host || "", text: b.host || "—" })),
          el("td", null, el("span.mono.truncate", { title: b.url || "", text: b.url || "—" }))));
      }
    }
  };

  async function egressTest() {
    const url = ($("#egress-test-url").value || "").trim();
    const out = $("#egress-test-result");
    if (!url) { out.textContent = "Enter a URL to evaluate."; return; }
    let res;
    try {
      res = await api.post("egress/test", { url });
    } catch (e) { out.textContent = e.message; return; }
    if (res.allowed) {
      out.textContent = `✓ ${res.url} would be ALLOWED (scheme + host checks; resolved IP is re-checked at connect).`;
    } else {
      out.textContent = `✗ ${res.url} would be BLOCKED — ${res.reason}: ${res.detail || ""}`;
    }
  }

  async function egressAllowlist(action, entryArg) {
    const entry = (entryArg !== undefined ? entryArg : ($("#egress-allow-entry").value || "")).trim();
    if (!entry) { toast("Enter an allowlist entry.", true); return; }
    await api.post("egress/allowlist", { action, entry });
    if (action === "add") $("#egress-allow-entry").value = "";
    toast(action === "add" ? `Added ${entry}` : `Removed ${entry}`);
    await views.egress();
  }

  // --- Dependency firewall (version-pinning & allowlist enforcement) --------
  function depfirewallTenant() {
    const v = ($("#depfirewall-tenant").value || "").trim();
    return v;
  }

  views.depfirewall = async function () {
    const cards = clear($("#depfirewall-cards"));
    const body = clear($("#depfirewall-body"));
    const meta = $("#depfirewall-meta");
    const tenant = depfirewallTenant();
    let data;
    try {
      data = await api.get("depfirewall" + (tenant ? "?tenant=" + encodeURIComponent(tenant) : ""));
    } catch (e) { meta.textContent = e.message; return; }

    if (data && data.enabled === false) {
      meta.textContent = "Dependency firewall is disabled.";
      body.appendChild(emptyRow($("#depfirewall-table"), 8, "Set depfirewall.enabled to enforce version policy."));
      return;
    }

    meta.textContent = `default ${data.defaultAction || "allow"} · ${data.globalRules || 0} global rules · ${data.tenantPolicies || 0} tenant policies (${data.tenantRules || 0} tenant rules)`;

    function stat(label, value, sub) {
      return el("div.stat", null,
        el("div.label", { text: label }),
        el("div.value", { text: String(value) }),
        sub ? el("div.sub", { text: sub }) : null);
    }
    cards.appendChild(stat("Blocks", data.blocks || 0, `${data.checks || 0} checks`));
    cards.appendChild(stat("Allowed", data.allowed || 0, "approved by a rule"));
    cards.appendChild(stat("Global rules", data.globalRules || 0, "all-tenant policy"));
    cards.appendChild(stat("Default action", data.defaultAction || "allow", "for ungoverned coords"));

    const rules = data.rules || [];
    if (!rules.length) {
      body.appendChild(emptyRow($("#depfirewall-table"), 8, "No rules configured. Import a lockfile or add a rule via the API."));
      return;
    }
    const join = (a) => (a && a.length ? a.join(", ") : "—");
    for (const r of rules) {
      body.appendChild(el("tr", null,
        el("td", null, el("span.muted", { text: r.tenant || "global" })),
        el("td", null, el("span.chip", { text: r.ecosystem || "—" })),
        el("td", null, el("span.mono.truncate", { title: r.name || "", text: r.name || "—" })),
        el("td", null, el("span.mono", { text: join(r.pinned) })),
        el("td", null, el("span.mono", { text: join(r.ranges) })),
        el("td", null, el("span.mono", { text: r.minVersion || "—" })),
        el("td", null, el("span.mono", { text: join(r.denied) })),
        el("td", null, el("span.muted", { text: r.source || "—" }))));
    }
  };

  async function importDepfirewallLockfile() {
    const metaEl = $("#depfirewall-import-meta");
    const text = ($("#depfirewall-lockfile").value || "").trim();
    if (!text) { metaEl.textContent = "Paste lockfile content first."; return; }
    const tenant = depfirewallTenant();
    const format = $("#depfirewall-format").value || "auto";
    const mode = $("#depfirewall-replace").checked ? "replace" : "merge";
    const qs = new URLSearchParams({ format, mode });
    if (tenant) qs.set("tenant", tenant);
    try {
      const res = await api.postRaw("depfirewall/import?" + qs.toString(), text);
      metaEl.textContent = `imported ${res.rulesImported} rules (${res.versions} versions) from ${res.format}${res.replaced ? " (replaced)" : ""}`;
      await views.depfirewall();
    } catch (e) { metaEl.textContent = e.message; }
  }

  // --- Organization dependency snapshots / freeze / instant rollback --------
  const shortId = (id) => (id || "").replace(/^sha256:/, "").slice(0, 12) || "—";

  views.snapshots = async function () {
    const cards = clear($("#snapshots-cards"));
    const body = clear($("#snapshots-body"));
    const meta = $("#snapshots-meta");
    let data;
    try {
      data = await api.get("snapshots");
    } catch (e) { meta.textContent = e.message; return; }

    const fr = data.freeze || {};
    const m = data.metrics || {};
    meta.textContent = fr.active
      ? `FROZEN to ${shortId(fr.snapshotId)} (${fr.mode || "block"}${fr.rollback ? ", rollback" : ""}) · ${fr.setSize || 0} coords`
      : "not frozen";

    function stat(label, value, sub) {
      return el("div.stat", null,
        el("div.label", { text: label }),
        el("div.value", { text: String(value) }),
        sub ? el("div.sub", { text: sub }) : null);
    }
    cards.appendChild(stat("Snapshots", m.Snapshots || 0, `${m.LiveEntries || 0} live coords`));
    cards.appendChild(stat("Freeze", fr.active ? "active" : "off", fr.active ? (fr.mode || "block") : "—"));
    cards.appendChild(stat("Captured", m.Taken || 0, "on-demand + scheduled"));
    cards.appendChild(stat("Rollbacks", m.Rollbacks || 0, `${m.GateBlocked || 0} gate blocks`));

    const snaps = data.snapshots || [];
    if (!snaps.length) {
      body.appendChild(emptyRow($("#snapshots-table"), 8, "No snapshots captured yet. Click “Capture snapshot” to take one."));
      return;
    }
    for (const s of snaps) {
      const actions = el("div", null);
      const freezeBtn = el("button.btn", { text: "Freeze" });
      freezeBtn.addEventListener("click", () => freezeSnapshot(s.id));
      const goodBtn = el("button.btn", { text: s.good ? "Mark bad" : "Mark good" });
      goodBtn.addEventListener("click", () => markGoodSnapshot(s.id, !s.good));
      actions.appendChild(freezeBtn);
      actions.appendChild(goodBtn);
      body.appendChild(el("tr", null,
        el("td", null, el("span.mono", { title: s.id, text: shortId(s.id) })),
        el("td", null, el("span", { text: s.name || "—" })),
        el("td", null, el("span.muted", { text: s.createdAt ? new Date(s.createdAt).toLocaleString() : "—" })),
        el("td", null, el("span", { text: String(s.entryCount || 0) })),
        el("td", null, el("span.chip", { text: s.good ? "good" : "—" })),
        el("td", null, el("span.chip", { text: s.signed ? "signed" : "unsigned" })),
        el("td", null, el("span.chip", { text: s.frozen ? "FROZEN" : "—" })),
        el("td", null, actions)));
    }
  };

  async function createSnapshot() {
    const name = ($("#snapshots-name").value || "").trim();
    try {
      const s = await api.post("snapshots/create", { name });
      toast("Snapshot captured: " + shortId(s.id));
      await views.snapshots();
    } catch (e) { toast(e.message, true); }
  }

  async function freezeSnapshot(id) {
    if (!window.confirm("Freeze the entire organization to snapshot " + shortId(id) + "? Pulls outside the frozen set will be blocked.")) return;
    try {
      await api.post("snapshots/freeze", { id, mode: "block", enforceDigest: true, reason: "frozen via admin UI" });
      toast("Organization frozen to " + shortId(id));
      await views.snapshots();
    } catch (e) { toast(e.message, true); }
  }

  async function unfreezeSnapshot() {
    try {
      await api.post("snapshots/unfreeze", {});
      toast("Freeze lifted");
      await views.snapshots();
    } catch (e) { toast(e.message, true); }
  }

  async function rollbackSnapshot() {
    if (!window.confirm("Instant rollback: pin the organization back to the last-known-good snapshot? This forces all clients to the previously-served safe digests.")) return;
    try {
      const res = await api.post("snapshots/rollback", { reason: "instant rollback via admin UI" });
      toast("Rolled back to " + shortId(res.freeze && res.freeze.snapshotId));
      await views.snapshots();
    } catch (e) { toast(e.message, true); }
  }

  async function markGoodSnapshot(id, good) {
    try {
      await api.post("snapshots/markgood", { id, good });
      await views.snapshots();
    } catch (e) { toast(e.message, true); }
  }

  async function runSnapshotDiff() {
    const from = ($("#snapshots-diff-from").value || "").trim();
    const to = ($("#snapshots-diff-to").value || "").trim();
    const out = $("#snapshots-diff-out");
    if (!from || !to) { out.textContent = "Enter both a from and a to snapshot id."; return; }
    try {
      out.textContent = await api.raw("snapshots/diff?format=md&from=" + encodeURIComponent(from) + "&to=" + encodeURIComponent(to));
    } catch (e) { out.textContent = e.message; }
  }

  // --- Install-script / lifecycle-hook risk analysis ------------------------
  views.installhooks = async function () {
    const cards = clear($("#installhooks-cards"));
    const body = clear($("#installhooks-body"));
    const meta = $("#installhooks-meta");
    let data;
    try {
      data = await api.get("installhooks");
    } catch (e) { meta.textContent = e.message; return; }

    if (data && data.enabled === false) {
      meta.textContent = "Install-hook analysis gate is disabled.";
      body.appendChild(emptyRow($("#installhooks-table"), 4, "Set installHooks.enabled to score package install scripts."));
      return;
    }

    const warn = data.warnSeverity ? `warn ≥ ${data.warnSeverity}` : "warnings off";
    meta.textContent = `${data.action || "block"} ≥ ${data.failSeverity || "high"} · ${warn} · ${(data.rules || []).length} rules · ${data.tenantOverrides || 0} tenant overrides`;

    function stat(label, value, sub) {
      return el("div.stat", null,
        el("div.label", { text: label }),
        el("div.value", { text: String(value) }),
        sub ? el("div.sub", { text: sub }) : null);
    }
    cards.appendChild(stat("Scanned", data.scanned || 0, "artifacts inspected"));
    cards.appendChild(stat("Hooks found", data.hooksFound || 0, "install/lifecycle hooks"));
    cards.appendChild(stat("Flagged", data.flaggedArtifacts || 0, `${data.findingsTotal || 0} findings`));
    cards.appendChild(stat("Blocked", data.blocked || 0, `${data.warned || 0} warned`));

    const rules = data.rules || [];
    if (!rules.length) {
      body.appendChild(emptyRow($("#installhooks-table"), 4, "No detection rules active."));
      return;
    }
    for (const r of rules) {
      body.appendChild(el("tr", null,
        el("td", null, el("span.mono", { text: r.id || "—" })),
        el("td", null, el("span", { text: r.title || "" })),
        el("td", null, el("span.chip", { text: r.severity || "—" })),
        el("td.num", null, el("span", { text: String(r.findings || 0) }))));
    }
  };

  // --- Reproducible Builds (rebuild-from-source verification) ---------------
  views.rebuildverify = async function () {
    const cards = clear($("#rebuildverify-cards"));
    const body = clear($("#rebuildverify-body"));
    const meta = $("#rebuildverify-meta");
    let data;
    try {
      data = await api.get("rebuildverify?limit=100");
    } catch (e) { meta.textContent = e.message; return; }

    if (data && data.enabled === false) {
      meta.textContent = "Reproducible-build verification subsystem is disabled.";
      body.appendChild(emptyRow($("#rebuildverify-table"), 6, "Set rebuildVerify.enabled to rebuild artifacts from source and compare digests."));
      return;
    }

    const builders = (data.builders || []).join(", ") || "none";
    meta.textContent = `mode ${data.mode || "observe"} · ${data.async ? "async" : "sync"} · builders: ${builders} · ${data.inFlight || 0} in-flight · cache ${data.cacheSize || 0}`;

    function stat(label, value, sub) {
      return el("div.stat", null,
        el("div.label", { text: label }),
        el("div.value", { text: String(value) }),
        sub ? el("div.sub", { text: sub }) : null);
    }
    cards.appendChild(stat("Verifications", data.verifications || 0, `${data.buildsRun || 0} builds run`));
    cards.appendChild(stat("Reproducible", data.reproducible || 0, "digest matched source"));
    cards.appendChild(stat("Mismatch", data.mismatch || 0, "DOES NOT match source"));
    cards.appendChild(stat("Unsupported / Unattested", `${data.unsupported || 0} · ${data.unattested || 0}`, `${data.buildErrors || 0} build errors`));

    const recent = data.recent || [];
    if (!recent.length) {
      body.appendChild(emptyRow($("#rebuildverify-table"), 6, "No verifications recorded yet."));
      return;
    }
    for (const r of recent) {
      const verdict = r.verdict || "—";
      const chipCls = verdict === "mismatch" ? "chip danger" : (verdict === "reproducible" ? "chip ok" : "chip");
      const commit = (r.commitSha || "").slice(0, 12);
      body.appendChild(el("tr", null,
        el("td", null, el("span.muted", { text: r.ecosystem || "—" })),
        el("td", null, el("span.mono.truncate", { title: r.coordinate || "", text: r.coordinate || "—" })),
        el("td", null, el("span." + chipCls.replace(" ", "."), { text: verdict })),
        el("td", null, el("span.mono", { text: commit || "—" })),
        el("td", null, el("span", { text: r.builder || "—" })),
        el("td", null, el("span.muted.truncate", { title: r.reason || "", text: r.reason || "" }))));
    }
  };

  views.buildprov = async function () {
    const cards = clear($("#buildprov-cards"));
    const body = clear($("#buildprov-body"));
    const meta = $("#buildprov-meta");
    let data;
    try {
      data = await api.get("buildprov?limit=100");
    } catch (e) { meta.textContent = e.message; return; }

    if (data && data.enabled === false) {
      meta.textContent = "Inbound build-provenance verification subsystem is disabled.";
      body.appendChild(emptyRow($("#buildprov-table"), 6, "Set buildProv.enabled to verify npm/GitHub build provenance and cross-check the source commit."));
      return;
    }

    const trust = data.trustRootsConfigured ? `${data.identitiesConfigured || 0} identities` : "no trust roots";
    meta.textContent = `mode ${data.mode || "observe"} · action ${data.action || "quarantine"} · ${trust} · ${data.requireProvenance ? "provenance required" : "provenance optional"} · cache ${data.cacheEntries || 0}`;

    function stat(label, value, sub) {
      return el("div.stat", null,
        el("div.label", { text: label }),
        el("div.value", { text: String(value) }),
        sub ? el("div.sub", { text: sub }) : null);
    }
    cards.appendChild(stat("Verifications", data.verifications || 0, `${data.present || 0} with provenance`));
    cards.appendChild(stat("Verified", data.verified || 0, `${data.sourceVerified || 0} source-verified`));
    cards.appendChild(stat("Source mismatch", data.mismatch || 0, "PROVEN ≠ CLAIMED source"));
    cards.appendChild(stat("Blocked / Warned", `${(data.blocked || 0) + (data.quarantined || 0)} · ${data.warned || 0}`, `${data.errors || 0} errors`));

    const recent = data.recent || [];
    if (!recent.length) {
      body.appendChild(emptyRow($("#buildprov-table"), 6, "No verifications recorded yet."));
      return;
    }
    function src(repo, commit) {
      const c = (commit || "").slice(0, 12);
      if (repo && c) return repo.replace(/^https?:\/\//, "") + "@" + c;
      if (repo) return repo.replace(/^https?:\/\//, "");
      if (c) return c;
      return "—";
    }
    for (const r of recent) {
      const art = r.artifact || {};
      const claim = art.claim || {};
      const coord = (art.name || "") + (art.version ? "@" + art.version : "");
      let outcome = "no provenance";
      let chip = "chip";
      if (r.mismatch) { outcome = "mismatch"; chip = "chip danger"; }
      else if (r.sourceVerified) { outcome = "source-verified"; chip = "chip ok"; }
      else if (r.verified) { outcome = "verified"; chip = "chip ok"; }
      else if (r.present) { outcome = "unverified"; chip = "chip warn"; }
      body.appendChild(el("tr", null,
        el("td", null, el("span.muted", { text: (art.ecosystem) || "—" })),
        el("td", null, el("span.mono.truncate", { title: coord, text: coord || "—" })),
        el("td", null, el("span." + chip.replace(" ", "."), { text: outcome })),
        el("td", null, el("span.mono.truncate", { title: src(r.repositoryUrl, r.commitSha), text: src(r.repositoryUrl, r.commitSha) })),
        el("td", null, el("span.mono.truncate", { title: src(claim.repositoryUrl, claim.commitSha), text: src(claim.repositoryUrl, claim.commitSha) })),
        el("td", null, el("span.muted.truncate", { title: r.workflowRef || "", text: r.workflowRef || "—" }))));
    }
  };

  // --- Emergency lockdown / global kill-switch (Task 74) --------------------
  function lockdownModeLabel(mode) {
    return { freeze: "FREEZE", strict: "STRICT", block: "TARGETED BLOCK" }[mode] || String(mode || "").toUpperCase();
  }

  function fmtRemaining(secs) {
    if (secs == null || secs < 0) return "no expiry";
    secs = Math.round(secs);
    const h = Math.floor(secs / 3600), m = Math.floor((secs % 3600) / 60), s = secs % 60;
    if (h) return `${h}h ${m}m`;
    if (m) return `${m}m ${s}s`;
    return `${s}s`;
  }

  views.lockdown = async function () {
    const meta = $("#lockdown-meta");
    const statusPanel = clear($("#lockdown-status"));
    let data;
    try {
      data = await api.get("lockdown");
    } catch (e) { meta.textContent = e.message; return; }

    const st = data.status || {};
    const m = data.metrics || {};
    meta.textContent = `${m.Engagements || 0} engaged · ${m.Blocks || 0} blocks · ${m.FreezeFetchBlocks || 0} fetch blocks · ${m.Expirations || 0} expired`;

    if (!st.active) {
      statusPanel.appendChild(el("div.empty", { text: "No active lockdown. The proxy is operating with its normal admission posture." }));
    } else {
      const rows = [];
      rows.push(el("tr", null, el("th", { text: "Mode" }), el("td", null, el("span.pill.bad", { text: lockdownModeLabel(st.mode) }))));
      rows.push(el("tr", null, el("th", { text: "Incident" }), el("td", { text: st.incidentId || "—" })));
      rows.push(el("tr", null, el("th", { text: "Reason" }), el("td", { text: st.reason || "—" })));
      rows.push(el("tr", null, el("th", { text: "Operator" }), el("td", { text: st.operator || "—" })));
      rows.push(el("tr", null, el("th", { text: "Engaged" }), el("td", { text: st.engagedAt ? new Date(st.engagedAt).toLocaleString() : "—" })));
      rows.push(el("tr", null, el("th", { text: "Expires" }), el("td", { text: st.expiresAt ? `${new Date(st.expiresAt).toLocaleString()} (${fmtRemaining(st.secondsRemaining)} left)` : "no expiry" })));
      if (st.targets && st.targets.length) {
        const coords = st.targets.map((t) => (t.ecosystem ? t.ecosystem + ":" : "") + t.name + (t.version ? "@" + t.version : "")).join(", ");
        rows.push(el("tr", null, el("th", { text: "Targets" }), el("td", { text: coords })));
      }
      statusPanel.appendChild(el("h2", { text: "Active lockdown" }));
      statusPanel.appendChild(el("table.lockdown-kv", null, el("tbody", null, ...rows)));
    }

    const modeSel = $("#lockdown-mode");
    const targetsRow = $("#lockdown-targets-row");
    if (modeSel && targetsRow) {
      const sync = () => { targetsRow.hidden = modeSel.value !== "block"; };
      modeSel.onchange = sync;
      sync();
    }
  };

  views.gitops = async function () {
    const meta = $("#gitops-meta");
    const statusPanel = clear($("#gitops-status"));
    let data;
    try {
      data = await api.get("gitops");
    } catch (e) { meta.textContent = e.message; return; }

    const st = data.status || {};
    const m = data.metrics || {};
    meta.textContent = `${m.Reconciles || 0} reconciles · ${m.Applies || 0} applied · ${m.Rollbacks || 0} rolled back · ${m.VerifyFailures || 0} verify-fail`;

    const stateLabel = st.driftDetected ? "DRIFT" : (st.inSync ? "IN SYNC" : "UNKNOWN");
    const statePill = st.driftDetected ? "span.pill.warn" : (st.inSync ? "span.pill.ok" : "span.pill");
    const rows = [];
    rows.push(el("tr", null, el("th", { text: "State" }), el("td", null, el(statePill, { text: stateLabel }))));
    rows.push(el("tr", null, el("th", { text: "Mode" }), el("td", { text: st.mode || "—" })));
    rows.push(el("tr", null, el("th", { text: "Source" }), el("td", { text: st.source || "—" })));
    rows.push(el("tr", null, el("th", { text: "Interval" }), el("td", { text: st.interval || "—" })));
    if (st.keyId) rows.push(el("tr", null, el("th", { text: "Verify key" }), el("td", { text: st.keyId })));
    rows.push(el("tr", null, el("th", { text: "Last sync" }), el("td", { text: st.lastSyncAt ? `${new Date(st.lastSyncAt).toLocaleString()} (${st.lastOutcome || "—"})` : "never" })));
    if (st.lastRevision) rows.push(el("tr", null, el("th", { text: "Revision" }), el("td", { text: st.lastRevision })));
    if (st.lastError) rows.push(el("tr", null, el("th", { text: "Error" }), el("td", null, el("span.pill.bad", { text: st.lastError }))));
    if (st.lastApplied) rows.push(el("tr", null, el("th", { text: "Last applied" }), el("td", { text: `${st.lastApplied.revision} (${st.lastApplied.changed} change(s)) by ${st.lastApplied.by || "—"}` })));
    if (st.pending) rows.push(el("tr", null, el("th", { text: "Pending approval" }), el("td", null, el("span.pill.warn", { text: `${st.pending.revision} (${st.pending.changed} change(s)) request=${st.pending.requestId || "—"}` }))));
    if (st.configDrift && st.configDrift.drifted) rows.push(el("tr", null, el("th", { text: "Config drift" }), el("td", null, el("span.pill.warn", { text: "on-disk config differs from running process — reload pending" }))));
    statusPanel.appendChild(el("h2", { text: "Reconciliation status" }));
    statusPanel.appendChild(el("table.lockdown-kv", null, el("tbody", null, ...rows)));

    const previewPanel = $("#gitops-preview");
    const previewBody = clear($("#gitops-preview-body"));
    const changed = (st.preview && st.preview.settings ? st.preview.settings.filter((s) => s.changed) : []);
    if (changed.length) {
      previewPanel.hidden = false;
      for (const s of changed) {
        previewBody.appendChild(el("tr", null,
          el("td", null, el("span.pill.warn", { text: "Δ" })),
          el("td", { text: s.path }),
          el("td", { text: s.current }),
          el("td", { text: s.proposed })));
      }
      if (st.preview.blastRadius) {
        const b = st.preview.blastRadius;
        previewPanel.appendChild(el("p.muted", { text: `Blast radius: ${b.changed}/${b.total} captured pulls change outcome (${b.nowBlocked} now-blocked, ${b.nowAdmitted} now-admitted, ${b.bandShifts} band shifts).` }));
      }
    } else {
      previewPanel.hidden = true;
    }

    const histPanel = $("#gitops-history");
    const histBody = clear($("#gitops-history-body"));
    const hist = (st.history || []).slice().reverse();
    if (hist.length) {
      histPanel.hidden = false;
      for (const h of hist) {
        histBody.appendChild(el("tr", null,
          el("td", { text: h.revision }),
          el("td", { text: String(h.changed) }),
          el("td", { text: h.by || "—" }),
          el("td", { text: h.appliedAt ? new Date(h.appliedAt).toLocaleString() : "—" })));
      }
    } else {
      histPanel.hidden = true;
    }
  };

  async function gitopsSyncAction() {
    try {
      const res = await api.post("gitops/sync", {});
      const o = res.outcome || {};
      let msg = `Sync: ${o.result}`;
      if (o.applied) msg += " — applied (takes effect on reload)";
      else if (o.pending) msg += " — pending approval";
      else if (o.inSync) msg += " — already in sync";
      toast(msg);
      await views.gitops();
    } catch (e) { toast(e.message, true); }
  }

  async function gitopsRollbackAction() {
    const reason = window.prompt("Reason for rolling back to the last-known-good config (recorded to the audit log):");
    if (reason === null) return;
    if (!reason.trim()) { toast("a reason is required to roll back", true); return; }
    try {
      const res = await api.post("gitops/rollback", { reason: reason.trim() });
      const r = res.rollback || {};
      toast(`Rolled back ${r.rolledBackFrom || ""} → ${r.restoredTo || ""}`);
      await views.gitops();
    } catch (e) { toast(e.message, true); }
  }

  async function engageLockdown() {
    const mode = ($("#lockdown-mode").value || "").trim();
    const incidentId = ($("#lockdown-incident").value || "").trim();
    const reason = ($("#lockdown-reason").value || "").trim();
    const ttl = ($("#lockdown-ttl").value || "").trim();
    if (!incidentId || !reason) { toast("incident ID and reason are required", true); return; }
    const body = { mode, incidentId, reason, ttl };
    if (mode === "block") {
      const raw = ($("#lockdown-targets").value || "").trim();
      const targets = raw.split(",").map((s) => s.trim()).filter(Boolean).map((coord) => {
        let eco = "", version = "", name = coord;
        const c = name.indexOf(":");
        if (c >= 0) { eco = name.slice(0, c).trim(); name = name.slice(c + 1); }
        const at = name.lastIndexOf("@");
        if (at > 0) { version = name.slice(at + 1).trim(); name = name.slice(0, at); }
        return { ecosystem: eco, name: name.trim(), version };
      });
      if (!targets.length) { toast("block mode requires at least one target coordinate", true); return; }
      body.targets = targets;
    }
    if (!window.confirm(`Engage a ${lockdownModeLabel(mode)} lockdown org-wide? This changes what every client may pull.`)) return;
    try {
      await api.post("lockdown/engage", body);
      toast(`Lockdown engaged: ${lockdownModeLabel(mode)}`);
      await views.lockdown();
      refreshIncidentBanner();
    } catch (e) { toast(e.message, true); }
  }

  async function clearLockdownAction() {
    const reason = ($("#lockdown-clear-reason").value || "").trim();
    if (!reason) { toast("a reason is required to clear the lockdown", true); return; }
    try {
      await api.post("lockdown/clear", { reason });
      toast("Lockdown cleared");
      await views.lockdown();
      refreshIncidentBanner();
    } catch (e) { toast(e.message, true); }
  }

  // refreshIncidentBanner polls the lockdown status and shows a prominent banner
  // across every tab while a lockdown is active. A no-op when the control is
  // disabled (the endpoint 404s).
  async function refreshIncidentBanner() {
    const banner = $("#incident-banner");
    if (!banner) return;
    try {
      const res = await fetch("api/lockdown", { cache: "no-store", headers: api.headers() });
      if (!res.ok) { banner.hidden = true; return; }
      const data = await res.json();
      const st = (data && data.status) || {};
      if (!st.active) { banner.hidden = true; return; }
      const where = st.targets && st.targets.length ? ` · ${st.targets.length} coordinate(s) denied` : "";
      banner.textContent = `⛔ EMERGENCY LOCKDOWN ACTIVE — ${lockdownModeLabel(st.mode)} · incident ${st.incidentId || "?"} · ${fmtRemaining(st.secondsRemaining)} left${where} — ${st.reason || ""}`;
      banner.hidden = false;
    } catch (_) { banner.hidden = true; }
  }

  // --- Approvals (quarantine review / break-glass) --------------------------
  views.approvals = async function () {
    const cards = clear($("#approvals-cards"));
    const body = clear($("#approvals-body"));
    const meta = $("#approvals-meta");
    const status = ($("#approvals-filter") && $("#approvals-filter").value) || "pending";
    let data;
    try {
      data = await api.get("approvals?status=" + encodeURIComponent(status) + "&limit=200");
    } catch (e) { meta.textContent = e.message; return; }

    if (!data || data.enabled === false) {
      meta.textContent = "Quarantine-review / break-glass workflow is disabled.";
      body.appendChild(emptyRow($("#approvals-table"), 8, "Enable approvals.enabled to let operators grant time-boxed exceptions."));
      return;
    }

    const s = data.snapshot || {};
    const avg = s.avgTimeToApprovalSeconds ? Math.round(s.avgTimeToApprovalSeconds) + "s" : "—";
    meta.textContent = `${s.open || 0} open · ${s.activeGrants || 0} active grants · ${s.requiredApprovers || 1} approver(s) required`;

    function stat(label, value, sub) {
      return el("div.stat", null,
        el("div.label", { text: label }),
        el("div.value", { text: String(value) }),
        sub ? el("div.sub", { text: sub }) : null);
    }
    cards.appendChild(stat("Open reviews", s.open || 0, `${s.requestsTotal || 0} opened total`));
    cards.appendChild(stat("Active grants", s.activeGrants || 0, `${s.breakGlassServesTotal || 0} break-glass serves`));
    cards.appendChild(stat("Approved / Denied", (s.approvedTotal || 0) + " / " + (s.deniedTotal || 0), `${s.expiredTotal || 0} expired`));
    cards.appendChild(stat("Avg time-to-approval", avg));

    const items = data.items || [];
    if (!items.length) {
      body.appendChild(emptyRow($("#approvals-table"), 8, "No requests for this filter."));
      return;
    }
    for (const req of items) {
      const approvers = (req.approvers || []).map((a) => a.subject).join(", ");
      const need = s.requiredApprovers || 1;
      const have = (req.approvers || []).length;
      const actions = el("td", null);
      if (req.status === "pending") {
        const approveBtn = el("button.btn.btn-sm", { type: "button", text: have + 1 >= need ? "Approve & grant" : `Vote (${have}/${need})` });
        const denyBtn = el("button.btn.btn-sm", { type: "button", text: "Deny" });
        approveBtn.addEventListener("click", () => decideApproval("approve", req));
        denyBtn.addEventListener("click", () => decideApproval("deny", req));
        actions.appendChild(el("div.button-group", null, approveBtn, denyBtn));
      } else {
        actions.appendChild(el("span.muted", { text: "—" }));
      }
      body.appendChild(el("tr", null,
        el("td", null, approvalStatusPill(req.status)),
        el("td", null, el("span.chip", { text: req.gate || "—" })),
        el("td", null, el("span.muted", { text: req.tenant || "—" })),
        el("td", null, el("span.mono.truncate", { title: req.coordinate || "", text: req.coordinate || "—" })),
        el("td", null, el("span.muted.truncate", { title: req.reason || "", text: req.reason || "" })),
        el("td", null, el("span.muted.truncate", { title: approvers, text: approvers || "—" })),
        el("td", null, el("span.muted", { text: fmtTime(req.updatedAt) })),
        actions));
    }
  };

  // approvalStatusPill renders a colored status chip mirroring the level pills.
  function approvalStatusPill(status) {
    const cls = { pending: "warn", approved: "ok", denied: "bad", expired: "muted" }[status] || "muted";
    return el("span.pill." + cls, { text: status || "—" });
  }

  // decideApproval prompts for the deciding operator's identity and a required
  // justification, then submits the approve/deny decision.
  async function decideApproval(action, req) {
    const verb = action === "approve" ? "approve" : "deny";
    const approver = window.prompt(`Your approver identity (required) to ${verb} ${req.coordinate}:`);
    if (!approver || !approver.trim()) return;
    const justification = window.prompt("Justification (required):");
    if (!justification || !justification.trim()) { toast("a justification is required", true); return; }
    const payload = { id: req.id, approver: approver.trim(), justification: justification.trim() };
    if (action === "approve") {
      const dur = window.prompt("Grant duration in seconds (blank for the configured default):", "");
      if (dur && /^\d+$/.test(dur.trim())) payload.durationSeconds = parseInt(dur.trim(), 10);
    }
    try {
      const out = await api.post("approvals/" + action, payload);
      toast(action === "approve"
        ? (out.status === "approved" ? "Break-glass grant issued" : "Approval vote recorded")
        : "Block confirmed (denied)");
      views.approvals();
    } catch (e) { toast(e.message, true); }
  }

  // --- Security Operations (SOC) -------------------------------------------
  // Maps an owning-gate key (from the read-model) to the dashboard tab that owns
  // its detail view, for feed drill-down. Gates without a dedicated tab are left
  // unmapped (no link rendered).
  const SECOPS_GATE_TAB = {
    policyengine: "policy",
    secretscan: "scans",
    provenance: "provenance",
    riskscore: "riskscore",
    anomaly: "anomaly",
    approvals: "approvals",
    cache: "cache",
    extensions: "extensions",
  };

  // secopsStream tracks the live SSE connection and feed state across renders.
  const secopsStream = { ctrl: null, gen: 0, paused: false, poll: null, rows: 0 };
  const SECOPS_FEED_MAX = 120;

  function outcomePill(outcome) {
    const o = (outcome || "warn").toLowerCase();
    const cls = o === "block" ? "bad" : o === "admit" ? "ok" : "warn";
    return el("span.pill." + cls, { text: o });
  }

  function secopsSevBadge(sev) {
    const s = (sev || "info").toLowerCase();
    return el("span.badge.sev-" + s, { text: s });
  }

  // secopsBars renders a labeled horizontal bar chart from [{key,value}] into host.
  function secopsBars(host, counts, opts) {
    clear(host);
    const items = counts || [];
    if (!items.length) { host.appendChild(el("span.muted", { text: "No activity in the window." })); return; }
    const max = items.reduce((m, c) => Math.max(m, c.value || 0), 0) || 1;
    const tone = (opts && opts.tone) || null;
    for (const c of items) {
      const pct = Math.max(2, Math.round(((c.value || 0) / max) * 100));
      const label = (opts && opts.label) ? opts.label(c.key) : c.key;
      const bar = el("div.bar-fill" + (tone && tone(c.key) ? "." + tone(c.key) : ""), { style: `width:${pct}%` });
      host.appendChild(el("div.bar-row", null,
        el("span.bar-label.truncate", { title: c.key, text: label || "—" }),
        el("div.bar-track", null, bar),
        el("span.bar-val", { text: String(c.value || 0) })));
    }
  }

  function renderSecopsAggregates(data) {
    const cards = clear($("#secops-cards"));
    const win = data.window || {};
    const posture = data.posture || {};
    const subs = data.subsystems || {};
    const meta = $("#secops-meta");

    const mins = Math.round((data.windowSeconds || 3600) / 60);
    const blocks = win.blocks || 0, warns = win.warns || 0, admits = win.admits || 0;
    const total = win.total || 0;

    function stat(label, value, sub, cls) {
      return el("div.stat" + (cls ? "." + cls : ""), null,
        el("div.label", { text: label }),
        el("div.value", value instanceof Node ? null : { text: String(value) }, value instanceof Node ? value : null),
        sub ? el("div.sub", { text: sub }) : null);
    }

    cards.appendChild(stat("Notable verdicts", total, `last ${mins} min`));
    cards.appendChild(stat("Blocks", blocks, `${warns} warns · ${admits} overrides`, blocks > 0 ? "bad" : null));
    const appr = posture.approvals;
    cards.appendChild(stat("Approval backlog", appr ? appr.open : "—",
      appr ? `${appr.activeGrants || 0} active grants` : "approvals disabled", appr && appr.open > 0 ? "warn" : null));
    const anom = posture.anomaly;
    cards.appendChild(stat("Active anomalies", anom ? anom.active : "—",
      anom ? `${anom.blocked || 0} soft-blocked` : "anomaly disabled", anom && anom.blocked > 0 ? "bad" : null));
    const risk = posture.risk;
    if (risk) {
      const crit = bandValue(risk.byBand, "critical"), high = bandValue(risk.byBand, "high");
      cards.appendChild(stat("Risk crit / high", crit + " / " + high,
        `${risk.totalScored || 0} scored · ${risk.blocked || 0} blocked`, crit > 0 ? "bad" : null));
    }
    const find = posture.findings;
    if (find) {
      cards.appendChild(stat("Findings artifacts", find.artifacts || 0, `${find.withBlocking || 0} with blocking`,
        find.withBlocking > 0 ? "warn" : null));
    }

    // Outcome split bar.
    const obar = clear($("#secops-outcome"));
    const seg = (cls, n, title) => n > 0 ? el("div.seg." + cls, { style: `flex:${n}`, title: `${title}: ${n}` },
      el("span", { text: n >= total * 0.08 ? String(n) : "" })) : null;
    if (total > 0) {
      for (const s of [seg("bad", blocks, "blocks"), seg("warn", warns, "warns"), seg("ok", admits, "admits/overrides")]) {
        if (s) obar.appendChild(s);
      }
    }

    secopsBars($("#secops-by-gate"), win.byGate, { tone: gateTone });
    secopsBars($("#secops-by-subject"), win.bySubject);
    secopsBars($("#secops-by-severity"), win.bySeverity);

    renderSecopsPosture(posture);

    const disabled = Object.keys(subs).filter((k) => !subs[k]);
    meta.textContent = total === 0
      ? `No notable verdicts in the last ${mins} min.` + (disabled.length ? ` Disabled: ${disabled.join(", ")}.` : "")
      : `${total} verdict(s) in ${mins} min` + (disabled.length ? ` · disabled: ${disabled.join(", ")}` : "");
  }

  function bandValue(bands, key) {
    const b = (bands || []).find((c) => c.key === key);
    return b ? (b.value || 0) : 0;
  }

  function gateTone(gate) {
    return SECOPS_GATE_TAB[gate] ? "linkish" : null;
  }

  function renderSecopsPosture(posture) {
    const host = clear($("#secops-posture"));
    const rows = [];
    const risk = posture.risk;
    if (risk) {
      const bands = (risk.byBand || []).map((b) => `${b.key}: ${b.value}`).join(" · ");
      rows.push(["Risk bands", bands || "—"]);
    }
    const find = posture.findings;
    if (find && (find.byGate || []).length) {
      rows.push(["Findings by gate", find.byGate.slice(0, 5).map((c) => `${c.key} ${c.value}`).join(", ")]);
    }
    const anom = posture.anomaly;
    if (anom && (anom.top || []).length) {
      const top = anom.top.slice(0, 3).map((s) => `${s.scope} (${s.level})`).join(", ");
      rows.push(["Top anomalous scopes", top]);
    }
    const appr = posture.approvals;
    if (appr && (appr.oldest || []).length) {
      rows.push(["Oldest pending review", appr.oldest[0].coordinate + " · " + (appr.oldest[0].gate || "")]);
    }
    if (!rows.length) { host.appendChild(el("span.muted", { text: "No posture signals from enabled subsystems." })); return; }
    host.appendChild(kv(rows));
  }

  // secopsFeedRow builds one live-feed table row with drill-down to the owning tab.
  function secopsFeedRow(ev) {
    const artifact = ev.artifact || ev.subject || "—";
    const tab = SECOPS_GATE_TAB[ev.gate];
    const gateCell = tab
      ? el("a.chip.linkish", { href: "#", title: "Open " + tab + " tab",
          onclick: (e) => { e.preventDefault(); setView(tab); } }, ev.gate)
      : el("span.chip", { text: ev.gate || "—" });
    return el("tr", null,
      el("td", null, el("span.muted", { text: fmtTime(ev.time) })),
      el("td", null, outcomePill(ev.outcome)),
      el("td", null, gateCell),
      el("td", null, secopsSevBadge(ev.severity)),
      el("td", null, el("span.truncate", { title: ev.summary || ev.title || "", text: ev.title || "—" })),
      el("td", null, el("span.mono.truncate", { title: artifact, text: artifact })),
      el("td", null, ev.type ? el("span.muted", { text: ev.type }) : null));
  }

  function seedSecopsFeed(recent) {
    const body = clear($("#secops-feed-body"));
    const items = recent || [];
    if (!items.length) {
      body.appendChild(emptyRow($("#secops-feed-table"), 7, "No notable verdicts yet. New events stream in live."));
      secopsStream.rows = 0;
      return;
    }
    for (const ev of items) body.appendChild(secopsFeedRow(ev));
    secopsStream.rows = items.length;
  }

  // pushSecopsEvent prepends a live-streamed event to the feed, trimming the tail.
  function pushSecopsEvent(ev) {
    const body = $("#secops-feed-body");
    if (!body) return;
    // Clear the placeholder empty-row on the first live event.
    if (secopsStream.rows === 0) clear(body);
    body.insertBefore(secopsFeedRow(ev), body.firstChild);
    secopsStream.rows++;
    while (secopsStream.rows > SECOPS_FEED_MAX && body.lastChild) {
      body.removeChild(body.lastChild);
      secopsStream.rows--;
    }
    flashStreamPill();
  }

  let streamFlashTimer = null;
  function flashStreamPill() {
    const pill = $("#secops-stream-pill");
    if (!pill) return;
    pill.classList.add("flash");
    clearTimeout(streamFlashTimer);
    streamFlashTimer = setTimeout(() => pill.classList.remove("flash"), 400);
  }

  function setStreamPill(state) {
    const pill = $("#secops-stream-pill");
    if (!pill) return;
    const map = { live: ["ok", "live"], off: ["", "paused"], connecting: ["warn", "connecting…"], error: ["bad", "stream error"] };
    const [cls, txt] = map[state] || map.off;
    pill.className = "pill" + (cls ? " " + cls : "");
    pill.textContent = "stream: " + txt;
  }

  // secopsConnectStream opens the SSE feed via fetch (so the admin bearer token /
  // SSO cookie is sent, which EventSource cannot do for token auth) and parses the
  // event stream incrementally. It reconnects with a short backoff while the view
  // is active and the feed is not paused.
  async function secopsConnectStream() {
    if (secopsStream.paused) { setStreamPill("off"); return; }
    secopsStream.gen++;
    const gen = secopsStream.gen;
    if (secopsStream.ctrl) { try { secopsStream.ctrl.abort(); } catch (_) {} }
    const ctrl = new AbortController();
    secopsStream.ctrl = ctrl;
    setStreamPill("connecting");
    try {
      const res = await fetch("api/secops/stream", { headers: api.headers(), signal: ctrl.signal, cache: "no-store" });
      if (res.status === 401 || res.status === 403) { setStreamPill("error"); return; }
      if (!res.ok || !res.body) { setStreamPill("error"); scheduleStreamReconnect(gen); return; }
      setStreamPill("live");
      const reader = res.body.getReader();
      const dec = new TextDecoder();
      let buf = "";
      while (true) {
        const { value, done } = await reader.read();
        if (done) break;
        if (gen !== secopsStream.gen) { try { ctrl.abort(); } catch (_) {} return; }
        buf += dec.decode(value, { stream: true });
        let idx;
        while ((idx = buf.indexOf("\n\n")) >= 0) {
          const frame = buf.slice(0, idx);
          buf = buf.slice(idx + 2);
          handleSecopsFrame(frame);
        }
      }
      // Stream ended (server closed); reconnect if still current.
      if (gen === secopsStream.gen && !secopsStream.paused) scheduleStreamReconnect(gen);
    } catch (e) {
      if (ctrl.signal.aborted || gen !== secopsStream.gen) return; // intentional teardown
      setStreamPill("error");
      scheduleStreamReconnect(gen);
    }
  }

  function scheduleStreamReconnect(gen) {
    setTimeout(() => {
      if (gen === secopsStream.gen && currentView === "secops" && !secopsStream.paused) secopsConnectStream();
    }, 5000);
  }

  function handleSecopsFrame(frame) {
    let data = null;
    for (const line of frame.split("\n")) {
      if (line.startsWith("data:")) data = (data == null ? "" : data + "\n") + line.slice(5).trim();
    }
    if (data == null) return; // comment/heartbeat frame
    try { pushSecopsEvent(JSON.parse(data)); } catch (_) {}
  }

  function secopsDisconnectStream() {
    secopsStream.gen++; // invalidate any in-flight reader loop
    if (secopsStream.ctrl) { try { secopsStream.ctrl.abort(); } catch (_) {} secopsStream.ctrl = null; }
    if (secopsStream.poll) { clearInterval(secopsStream.poll); secopsStream.poll = null; }
    setStreamPill("off");
  }

  views.secops = async function () {
    const meta = $("#secops-meta");
    let data;
    try {
      data = await api.get("secops/summary");
    } catch (e) {
      meta.textContent = e.message;
      clear($("#secops-cards"));
      seedSecopsFeed([]);
      return;
    }
    renderSecopsAggregates(data);
    seedSecopsFeed(data.recent);

    // Short-poll the aggregates so the top-line stays near-real-time without
    // re-seeding the live feed (SSE owns the feed once connected).
    if (secopsStream.poll) clearInterval(secopsStream.poll);
    secopsStream.poll = setInterval(async () => {
      if (currentView !== "secops") return;
      try { renderSecopsAggregates(await api.get("secops/summary")); } catch (_) {}
    }, 15000);

    // Open (or re-open) the live verdict stream.
    if (!secopsStream.paused) secopsConnectStream();
    else setStreamPill("off");
  };

  // --- WebAuthn / passkey step-up (Task 161) --------------------------------

  // bufToB64url encodes an ArrayBuffer/typed array as unpadded base64url.
  function bufToB64url(buf) {
    const bytes = new Uint8Array(buf);
    let s = "";
    for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
    return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  }

  // b64urlToBuf decodes unpadded base64url into a Uint8Array.
  function b64urlToBuf(s) {
    s = s.replace(/-/g, "+").replace(/_/g, "/");
    while (s.length % 4) s += "=";
    const bin = atob(s);
    const bytes = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
    return bytes;
  }

  function webauthnSupported() {
    return typeof window.PublicKeyCredential !== "undefined" && navigator.credentials;
  }

  // webauthnEnroll runs a full registration ceremony: fetch options, invoke the
  // authenticator, and post the attestation back for verification + storage.
  async function webauthnEnroll(label) {
    if (!webauthnSupported()) throw new Error("this browser does not support WebAuthn/passkeys");
    const opt = await api.post("webauthn/register/begin", {});
    const publicKey = {
      challenge: b64urlToBuf(opt.challenge),
      rp: { id: opt.rpId, name: opt.rpName || "Pullthrough Admin" },
      user: {
        id: b64urlToBuf(opt.userId),
        name: opt.userName || "admin",
        displayName: opt.userName || "admin",
      },
      pubKeyCredParams: (opt.pubKeyCredParams || []).map((p) => ({ type: p.type, alg: p.alg })),
      timeout: opt.timeoutMs || 120000,
      attestation: opt.attestation || "direct",
      authenticatorSelection: { userVerification: opt.userVerification || "preferred" },
      excludeCredentials: (opt.excludeCredentials || []).map((id) => ({ type: "public-key", id: b64urlToBuf(id) })),
    };
    const cred = await navigator.credentials.create({ publicKey });
    if (!cred) throw new Error("passkey enrolment was cancelled");
    const resp = cred.response;
    const body = {
      label: label || "",
      clientDataJSON: bufToB64url(resp.clientDataJSON),
      attestationObject: bufToB64url(resp.attestationObject),
      transports: typeof resp.getTransports === "function" ? resp.getTransports() : [],
    };
    return api.post("webauthn/register/finish", body);
  }

  // webauthnStepUp runs an assertion ceremony bound to action and returns the
  // minted step-up token. It is called transparently from api.request when the
  // server demands step-up, and directly by the "test" button.
  async function webauthnStepUp(action) {
    if (!webauthnSupported()) throw new Error("this browser does not support WebAuthn/passkeys");
    const opt = await api.post("webauthn/assert/begin", { action: action || "" });
    const publicKey = {
      challenge: b64urlToBuf(opt.challenge),
      rpId: opt.rpId,
      timeout: opt.timeoutMs || 120000,
      userVerification: opt.userVerification || "preferred",
      allowCredentials: (opt.allowCredentials || []).map((id) => ({ type: "public-key", id: b64urlToBuf(id) })),
    };
    const assertion = await navigator.credentials.get({ publicKey });
    if (!assertion) throw new Error("passkey step-up was cancelled");
    const resp = assertion.response;
    const body = {
      credentialId: bufToB64url(assertion.rawId),
      clientDataJSON: bufToB64url(resp.clientDataJSON),
      authenticatorData: bufToB64url(resp.authenticatorData),
      signature: bufToB64url(resp.signature),
      userHandle: resp.userHandle ? bufToB64url(resp.userHandle) : "",
    };
    const out = await api.post("webauthn/assert/finish", body);
    return out.token;
  }

  views.passkeys = async function () {
    const meta = $("#passkeys-meta");
    const statusPanel = clear($("#passkeys-status"));
    const body = clear($("#passkeys-body"));
    let data;
    try {
      data = await api.get("webauthn");
    } catch (e) { meta.textContent = e.message; return; }

    if (!data.enabled) {
      meta.textContent = "disabled";
      statusPanel.appendChild(el("div.empty", { text: "WebAuthn/passkey step-up is not enabled on this proxy (set webauthn.enabled in the configuration)." }));
      return;
    }
    const supported = webauthnSupported();
    meta.textContent = `${data.enforcing ? "enforcing" : "advisory"} · rp=${data.rpId} · ${data.totalCredentials || 0} credential(s) across ${data.enrolledSubjects || 0} identity(ies)`;

    const rows = [];
    rows.push(el("tr", null, el("th", { text: "Status" }), el("td", null, el(data.enforcing ? "span.pill.ok" : "span.pill.warn", { text: data.enforcing ? "ENFORCING" : "ADVISORY (not gating)" }))));
    rows.push(el("tr", null, el("th", { text: "Relying Party" }), el("td", { text: `${data.rpName || ""} (${data.rpId})` })));
    rows.push(el("tr", null, el("th", { text: "User verification" }), el("td", { text: data.requireUserVerification ? "required" : "preferred" })));
    rows.push(el("tr", null, el("th", { text: "Step-up freshness" }), el("td", { text: `${data.stepUpTtlSeconds || 0}s` })));
    if (data.protectedActions && data.protectedActions.length) {
      rows.push(el("tr", null, el("th", { text: "Protected actions" }), el("td", { text: data.protectedActions.join(", ") })));
    }
    if (!supported) {
      rows.push(el("tr", null, el("th", { text: "Browser" }), el("td", null, el("span.pill.bad", { text: "this browser does not support WebAuthn" }))));
    }
    statusPanel.appendChild(el("h2", { text: "Step-up configuration" }));
    statusPanel.appendChild(el("table.lockdown-kv", null, el("tbody", null, ...rows)));

    const creds = data.credentials || [];
    if (!creds.length) {
      body.appendChild(el("tr", null, el("td", { colspan: "6" }, el("span.muted", { text: "No passkeys enrolled yet. Enroll one to perform the protected actions." }))));
    }
    for (const c of creds) {
      const att = c.attestationVerified ? el("span.pill.ok", { text: c.attestationFormat || "verified" }) : el("span.pill.warn", { text: (c.attestationFormat || "none") + " (unverified)" });
      const remove = el("button.btn.btn-sm", { text: "Remove" });
      remove.addEventListener("click", async () => {
        if (!window.confirm(`Remove passkey "${c.label}"?`)) return;
        try {
          await api.del("webauthn/credential?id=" + encodeURIComponent(c.id));
          toast("passkey removed");
          views.passkeys().catch((e) => toast(e.message, true));
        } catch (e) { toast(e.message, true); }
      });
      body.appendChild(el("tr", null,
        el("td", { text: c.label || "passkey" }),
        el("td", null, att),
        el("td", { text: String(c.signCount || 0) }),
        el("td", { text: c.createdAt ? new Date(c.createdAt).toLocaleString() : "—" }),
        el("td", { text: c.lastUsed ? new Date(c.lastUsed).toLocaleString() : "never" }),
        el("td", null, remove)));
    }

    const enrollBtn = $("#passkey-enroll");
    if (enrollBtn) enrollBtn.disabled = !supported;
    const testBtn = $("#passkey-test");
    if (testBtn) testBtn.disabled = !supported || !creds.length;
  };

  async function enrollPasskeyAction() {
    const msg = $("#passkey-enroll-msg");
    const label = ($("#passkey-label").value || "").trim();
    msg.textContent = "waiting for the authenticator…";
    try {
      const view = await webauthnEnroll(label);
      msg.textContent = "";
      toast(`passkey "${view.label}" enrolled`);
      $("#passkey-label").value = "";
      views.passkeys().catch((e) => toast(e.message, true));
    } catch (e) {
      msg.textContent = "";
      toast(e.message || "enrolment failed", true);
    }
  }

  async function testStepUpAction() {
    const msg = $("#passkey-test-msg");
    msg.textContent = "waiting for the authenticator…";
    try {
      const token = await webauthnStepUp("");
      msg.textContent = "";
      toast(token ? "step-up assertion verified ✓" : "step-up completed", false);
    } catch (e) {
      msg.textContent = "";
      toast(e.message || "step-up failed", true);
    }
  }

  // --- Policy ---------------------------------------------------------------
  views.policy = async function () {
    const panel = clear($("#policy-panel"));
    const info = await api.get("policy");
    panel.appendChild(el("h2", { text: "Effective configuration" }));
    panel.appendChild(kv([
      ["Version", info.version],
      ["Cache backend", info.cacheBackend],
      ["Scanning", info.scanningEnabled ? `enabled (${info.scanProvider || "?"})` : "disabled"],
      ["Scan fail-on", info.scanFailOn],
      ["Provenance", info.provenanceEnabled ? "enabled" : "disabled"],
      ["Require attested", info.provenanceRequireAttested ? "yes" : "no"],
    ]));

    const ups = info.upstreams || [];
    panel.appendChild(el("h2", { text: `Upstreams (${ups.length})`, style: "margin-top:1.1rem" }));
    if (!ups.length) {
      panel.appendChild(el("p.muted", { text: "No upstreams configured." }));
      return;
    }
    const table = el("table");
    table.appendChild(el("thead", null, el("tr", null,
      el("th", { text: "Name" }), el("th", { text: "Type" }), el("th", { text: "URL" }))));
    const tbody = el("tbody");
    ups.forEach((u) => tbody.appendChild(el("tr", null,
      el("td", { text: u.name }),
      el("td", null, el("span.chip", { text: u.type })),
      el("td", null, el("span.mono.truncate", { title: u.url, text: u.url })))));
    table.appendChild(tbody);
    panel.appendChild(el("div.table-wrap", null, table));
  };

  // --- health ---------------------------------------------------------------
  async function refreshHealth() {
    const pill = $("#health-pill");
    try {
      const res = await fetch("/healthz", { cache: "no-store" });
      if (res.ok) { pill.textContent = "healthy"; pill.className = "pill ok"; }
      else { pill.textContent = "degraded"; pill.className = "pill bad"; }
    } catch (_) {
      pill.textContent = "unreachable"; pill.className = "pill bad";
    }
  }

  // refreshWhoami fetches the current admin identity (SSO/RBAC, Task 51) and
  // renders an identity chip + sign-out link. It is a no-op when the auth
  // endpoint is absent (older deployments without adminAuth wired).
  async function refreshWhoami() {
    const chip = $("#whoami");
    const signout = $("#signout");
    if (!chip) return;
    try {
      const res = await fetch("auth/userinfo", { cache: "no-store", headers: api.headers() });
      if (!res.ok) return;
      const info = await res.json();
      if (info.authenticated) {
        const roles = (info.roles || []).join(", ") || "no roles";
        chip.textContent = info.subject + " · " + roles;
        chip.className = "pill ok";
        chip.hidden = false;
        if (signout && info.logoutUrl) { signout.href = info.logoutUrl; signout.hidden = false; }
      } else if (info.oidcEnabled && info.loginUrl) {
        chip.textContent = "sign in";
        chip.className = "pill";
        chip.hidden = false;
        chip.style.cursor = "pointer";
        chip.onclick = () => {
          const ret = encodeURIComponent(location.pathname + location.search);
          location.assign(info.loginUrl + (info.loginUrl.includes("?") ? "&" : "?") + "return=" + ret);
        };
      }
    } catch (_) { /* auth endpoint not present; ignore */ }
  }

  // --- wiring ---------------------------------------------------------------
  function refresh() {
    refreshHealth();
    refreshWhoami();
    refreshIncidentBanner();
    setView(currentView);
  }

  function init() {
    wireTabsAria();
    $$(".tab").forEach((tab) => {
      tab.addEventListener("click", () => setView(tab.dataset.view));
    });
    // Keyboard navigation across the tablist (WAI-ARIA tabs pattern):
    // Arrow keys move and activate the adjacent tab, Home/End jump to the ends.
    const tabs = $$(".tab");
    tabs.forEach((tab, i) => {
      tab.addEventListener("keydown", (e) => {
        let j = null;
        if (e.key === "ArrowRight" || e.key === "ArrowDown") j = (i + 1) % tabs.length;
        else if (e.key === "ArrowLeft" || e.key === "ArrowUp") j = (i - 1 + tabs.length) % tabs.length;
        else if (e.key === "Home") j = 0;
        else if (e.key === "End") j = tabs.length - 1;
        if (j != null) { e.preventDefault(); tabs[j].focus(); setView(tabs[j].dataset.view); }
      });
    });

    $("#refresh").addEventListener("click", refresh);
    $("#drawer-close").addEventListener("click", closeDrawer);
    $("#overlay").addEventListener("click", closeDrawer);

    const cacheSearch = $("#cache-search");
    if (cacheSearch) {
      cacheSearch.addEventListener("input", () => {
        clearTimeout(cacheQueryTimer);
        cacheQueryTimer = setTimeout(() => views.cache().catch((e) => toast(e.message, true)), 200);
      });
    }

    const scanLookup = $("#scan-lookup");
    const scanSha = $("#scan-sha");
    if (scanLookup && scanSha) {
      const go = () => { const v = scanSha.value.trim(); if (v) showScanEntry(v); };
      scanLookup.addEventListener("click", go);
      scanSha.addEventListener("keydown", (e) => { if (e.key === "Enter") { e.preventDefault(); go(); } });
    }

    const provForm = $("#prov-form");
    if (provForm) {
      provForm.addEventListener("submit", (e) => { e.preventDefault(); resolveProvenance(provForm); });
    }

    const compRefresh = $("#compliance-refresh");
    if (compRefresh) compRefresh.addEventListener("click", recomputeCompliance);
    const compExport = $("#compliance-export");
    if (compExport) compExport.addEventListener("click", exportCompliance);
    const compHTML = $("#compliance-html");
    if (compHTML) compHTML.addEventListener("click", (e) => { e.preventDefault(); openComplianceHTML(); });

    const extReload = $("#extensions-reload");
    if (extReload) extReload.addEventListener("click", async () => {
      try {
        const r = await api.post("extensions/reload");
        toast(r && r.reloaded ? "Extension modules reloaded" : ("Reload error: " + ((r && r.error) || "unknown")), !(r && r.reloaded));
      } catch (e) { toast(e.message, true); }
      views.extensions().catch((e) => toast(e.message, true));
    });

    const matRefresh = $("#maturity-refresh");
    if (matRefresh) matRefresh.addEventListener("click", () => views.maturity().catch((e) => toast(e.message, true)));

    const contRefresh = $("#continuity-refresh");
    if (contRefresh) contRefresh.addEventListener("click", () => views.continuity().catch((e) => toast(e.message, true)));

    const egrRefresh = $("#egress-refresh");
    if (egrRefresh) egrRefresh.addEventListener("click", () => views.egress().catch((e) => toast(e.message, true)));
    const egrTest = $("#egress-test-btn");
    if (egrTest) egrTest.addEventListener("click", () => egressTest().catch((e) => toast(e.message, true)));
    const egrTestUrl = $("#egress-test-url");
    if (egrTestUrl) egrTestUrl.addEventListener("keydown", (e) => { if (e.key === "Enter") { e.preventDefault(); egressTest().catch((err) => toast(err.message, true)); } });
    const egrAllowAdd = $("#egress-allow-add");
    if (egrAllowAdd) egrAllowAdd.addEventListener("click", () => egressAllowlist("add").catch((e) => toast(e.message, true)));

    const dfwRefresh = $("#depfirewall-refresh");
    if (dfwRefresh) dfwRefresh.addEventListener("click", () => views.depfirewall().catch((e) => toast(e.message, true)));
    const dfwLoad = $("#depfirewall-load");
    if (dfwLoad) dfwLoad.addEventListener("click", () => views.depfirewall().catch((e) => toast(e.message, true)));
    const dfwImport = $("#depfirewall-import");
    if (dfwImport) dfwImport.addEventListener("click", () => importDepfirewallLockfile().catch((e) => toast(e.message, true)));

    const snapRefresh = $("#snapshots-refresh");
    if (snapRefresh) snapRefresh.addEventListener("click", () => views.snapshots().catch((e) => toast(e.message, true)));
    const snapCreate = $("#snapshots-create");
    if (snapCreate) snapCreate.addEventListener("click", () => createSnapshot());
    const snapRollback = $("#snapshots-rollback");
    if (snapRollback) snapRollback.addEventListener("click", () => rollbackSnapshot());
    const snapUnfreeze = $("#snapshots-unfreeze");
    if (snapUnfreeze) snapUnfreeze.addEventListener("click", () => unfreezeSnapshot());
    const snapDiff = $("#snapshots-diff-run");
    if (snapDiff) snapDiff.addEventListener("click", () => runSnapshotDiff());

    const ihRefresh = $("#installhooks-refresh");
    if (ihRefresh) ihRefresh.addEventListener("click", () => views.installhooks().catch((e) => toast(e.message, true)));

    const rbvRefresh = $("#rebuildverify-refresh");
    if (rbvRefresh) rbvRefresh.addEventListener("click", () => views.rebuildverify().catch((e) => toast(e.message, true)));
    const bpvRefresh = $("#buildprov-refresh");
    if (bpvRefresh) bpvRefresh.addEventListener("click", () => views.buildprov().catch((e) => toast(e.message, true)));

    const apprRefresh = $("#approvals-refresh");
    if (apprRefresh) apprRefresh.addEventListener("click", () => views.approvals().catch((e) => toast(e.message, true)));
    const apprFilter = $("#approvals-filter");
    if (apprFilter) apprFilter.addEventListener("change", () => views.approvals().catch((e) => toast(e.message, true)));

    const secopsRefresh = $("#secops-refresh");
    if (secopsRefresh) secopsRefresh.addEventListener("click", () => views.secops().catch((e) => toast(e.message, true)));
    const secopsToggle = $("#secops-stream-toggle");
    if (secopsToggle) secopsToggle.addEventListener("click", () => {
      secopsStream.paused = !secopsStream.paused;
      secopsToggle.textContent = secopsStream.paused ? "Resume live feed" : "Pause live feed";
      secopsToggle.setAttribute("aria-pressed", secopsStream.paused ? "true" : "false");
      if (secopsStream.paused) { secopsDisconnectStream(); }
      else if (currentView === "secops") { secopsConnectStream(); }
    });

    document.addEventListener("keydown", (e) => {
      if (e.key === "Escape") closeDrawer();
      trapDrawerTab(e);
      // "r" refreshes, unless the user is typing in a field or the modal
      // drawer is open (where Tab/typing should stay local to the dialog).
      const typing = /^(INPUT|TEXTAREA|SELECT)$/.test(document.activeElement && document.activeElement.tagName);
      if (e.key === "r" && !typing && !e.metaKey && !e.ctrlKey && $("#drawer").hidden) { e.preventDefault(); refresh(); }
    });

    const ldRefresh = $("#lockdown-refresh");
    if (ldRefresh) ldRefresh.addEventListener("click", () => views.lockdown().catch((e) => toast(e.message, true)));
    const ldEngage = $("#lockdown-engage");
    if (ldEngage) ldEngage.addEventListener("click", engageLockdown);
    const ldClear = $("#lockdown-clear");
    if (ldClear) ldClear.addEventListener("click", clearLockdownAction);

    const pkRefresh = $("#passkeys-refresh");
    if (pkRefresh) pkRefresh.addEventListener("click", () => views.passkeys().catch((e) => toast(e.message, true)));
    const pkEnroll = $("#passkey-enroll");
    if (pkEnroll) pkEnroll.addEventListener("click", () => enrollPasskeyAction());
    const pkTest = $("#passkey-test");
    if (pkTest) pkTest.addEventListener("click", () => testStepUpAction());

    const goRefresh = $("#gitops-refresh");
    if (goRefresh) goRefresh.addEventListener("click", () => views.gitops().catch((e) => toast(e.message, true)));
    const goSync = $("#gitops-sync");
    if (goSync) goSync.addEventListener("click", gitopsSyncAction);
    const goRollback = $("#gitops-rollback");
    if (goRollback) goRollback.addEventListener("click", gitopsRollbackAction);

    refreshHealth();
    refreshWhoami();
    refreshIncidentBanner();
    setView("overview");
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init);
  } else {
    init();
  }
})();
