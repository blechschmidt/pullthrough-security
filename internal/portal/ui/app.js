"use strict";
// Tenant self-service security portal — a dependency-free single-page app.
// Every fetch hits /api/portal/*, which hard-scopes responses to the caller's
// own tenant on the server; this script never sends a tenant parameter.

(function () {
  // Derive the UI + API base from our own path: the page is served at
  // <uiPrefix>/ (e.g. /portal/), and the API lives at /api<uiPrefix>.
  let p = location.pathname.replace(/\/index\.html$/, "/").replace(/\/+$/, "");
  const UI = p || "/portal";
  const API = "/api" + UI;

  const $ = (s) => document.querySelector(s);
  const $$ = (s) => Array.from(document.querySelectorAll(s));

  function el(tag, attrs, ...kids) {
    const m = tag.split(".");
    const node = document.createElement(m[0] || "div");
    if (m.length > 1) node.className = m.slice(1).join(" ");
    if (attrs) {
      for (const k in attrs) {
        if (k === "text") node.textContent = attrs[k];
        else if (k === "html") node.innerHTML = attrs[k];
        else if (attrs[k] != null) node.setAttribute(k, attrs[k]);
      }
    }
    for (const kid of kids) {
      if (kid == null) continue;
      node.appendChild(typeof kid === "string" ? document.createTextNode(kid) : kid);
    }
    return node;
  }
  const clear = (n) => { while (n.firstChild) n.removeChild(n.firstChild); return n; };

  function toast(msg, err) {
    const t = el("div.toast" + (err ? ".err" : ""), { text: msg });
    document.body.appendChild(t);
    setTimeout(() => t.remove(), 3500);
  }

  async function getJSON(path) {
    const res = await fetch(API + path, { headers: { Accept: "application/json" }, credentials: "same-origin" });
    if (res.status === 401) {
      const loginURL = res.headers.get("X-Login-URL");
      throw Object.assign(new Error("Please sign in."), { auth: true, loginURL });
    }
    if (!res.ok) {
      let m = "request failed (" + res.status + ")";
      try { const j = await res.json(); if (j && j.error) m = j.error; } catch (_) {}
      throw new Error(m);
    }
    return res.json();
  }

  const pill = (decision) => el("span.pill." + decision, { text: decision });
  const statusPill = (st) => el("span.pill." + st, { text: st });
  const stat = (n, l, s) => el("div.stat", null, el("div.n", { text: String(n) }), el("div.l", { text: l }), s ? el("div.s", { text: s }) : null);
  const artifactLabel = (v) => v.coordinate || (v.name ? (v.name + (v.version ? "@" + v.version : "")) : "—");

  // --- views ----------------------------------------------------------------
  const views = {};

  views.overview = async function () {
    const data = await getJSON("/summary");
    $("#ov-tenant").textContent = data.tenant || "your tenant";
    const cards = clear($("#ov-cards"));
    const v = data.verdicts || {};
    cards.appendChild(stat(v.total || 0, "Recent verdicts", (v.block || 0) + " blocked · " + (v.warn || 0) + " warned"));
    cards.appendChild(stat(v.admit || 0, "Admitted", "served from your pulls"));
    cards.appendChild(stat((data.quarantine && data.quarantine.open) || 0, "Awaiting approval", "break-glass requests"));
    const f = data.findings || {};
    cards.appendChild(stat(f.findings || 0, "Open findings", (f.coordinates || 0) + " artifacts"));
  };

  views.verdicts = async function () {
    const data = await getJSON("/verdicts");
    $("#verdicts-meta").textContent = data.enabled
      ? (data.total + " recent verdict(s) for " + data.tenant)
      : "Risk scoring is not enabled.";
    const body = clear($("#verdicts-body"));
    if (!data.verdicts.length) {
      body.appendChild(el("tr", null, el("td", { colspan: "6", class: "muted" }, "No verdicts recorded yet for your tenant.")));
      return;
    }
    for (const v of data.verdicts) {
      const row = el("tr.row-link", null,
        el("td", null, pill(v.decision)),
        el("td", null, el("span.mono", { text: artifactLabel(v) })),
        el("td", { class: "num" }, String(v.score)),
        el("td", null, v.band || "—"),
        el("td", null, el("span.muted", { text: (v.drivers && v.drivers.join(", ")) || v.summary || "—" })),
        el("td", null, el("span.muted", { text: fmtTime(v.scoredAt) })));
      row.addEventListener("click", () => { setView("lookup"); $("#lookup-input").value = artifactLabel(v); lookup(); });
      body.appendChild(row);
    }
  };

  views.lookup = async function () {
    // Rendered on demand via lookup(); nothing to preload.
  };

  async function lookup() {
    const coord = $("#lookup-input").value.trim();
    const out = clear($("#lookup-result"));
    if (!coord) { out.appendChild(el("p.muted", { text: "Enter a package coordinate above." })); return; }
    let data;
    try { data = await getJSON("/coordinate?coordinate=" + encodeURIComponent(coord)); }
    catch (e) { out.appendChild(el("p.muted", { text: e.message })); return; }

    if (!data.found) {
      out.appendChild(el("div.banner.ok", { text: "No risk verdict, finding, or quarantine record for " + coord + " under your tenant. If you have not pulled it yet, it has not been evaluated." }));
      return;
    }

    out.appendChild(el("div.banner." + (data.blocked ? "block" : "ok"), {
      text: data.blocked ? (coord + " is blocked for your tenant. See the findings and remediation below.") : (coord + " is allowed. Details below.")
    }));

    if (data.verdict) {
      const v = data.verdict;
      const panel = el("div.panel", null, el("h2", { text: "Risk verdict" }));
      panel.appendChild(el("p", null, pill(v.decision), " ", el("span.mono", { text: "score " + v.score + " / band " + (v.band || "—") })));
      if (v.summary) panel.appendChild(el("p.muted", { text: v.summary }));
      if (v.drivers && v.drivers.length) panel.appendChild(el("p.muted", { text: "Top drivers: " + v.drivers.join(", ") }));
      out.appendChild(panel);
    }

    const fp = el("div.panel", null, el("h2", { text: "Findings (" + data.findings.length + ")" }));
    if (!data.findings.length) {
      fp.appendChild(el("p.muted", { text: "No gate findings recorded." }));
    } else {
      for (const f of data.findings) {
        const card = el("div.finding", null,
          el("div.t", { text: f.title || f.ruleId }),
          el("div.meta", { text: [f.gate, f.severity, f.suppressed ? "suppressed" : null].filter(Boolean).join(" · ") }));
        if (f.message) card.appendChild(el("div.muted", { text: f.message }));
        if (f.remediation) card.appendChild(el("div.rem", null, el("b", { text: "What to do: " }), f.remediation,
          f.helpUri ? el("span", null, " (", el("a", { href: f.helpUri, target: "_blank", rel: "noopener", text: "docs" }), ")") : null));
        fp.appendChild(card);
      }
    }
    out.appendChild(fp);

    // Break-glass guidance.
    const bg = data.breakGlass || {};
    const bgp = el("div.panel", null, el("h2", { text: "Need this package? (break-glass)" }), el("p.muted", { text: bg.guidance || "" }));
    if (bg.available) {
      bgp.appendChild(el("p", null, "An approval request already exists: ",
        el("span.mono", { text: bg.requestId }), " ", statusPill(bg.status || "pending"),
        bg.gate ? el("span.muted", { text: "  (gate: " + bg.gate + ")" }) : null));
    }
    out.appendChild(bgp);

    // Downloads.
    const dl = el("div.panel", null, el("h2", { text: "Downloads" }));
    dl.appendChild(el("p", null,
      el("a.btn.ghost", { href: API + "/findings/sarif?package=" + encodeURIComponent(coord) }, "Download SARIF")));
    if (data.attestation && data.attestation.available) {
      dl.appendChild(el("p", null, el("a.btn.ghost", { href: data.attestation.url }, "Download attestation (DSSE)")));
    } else {
      dl.appendChild(el("p.muted", { text: "No attestation bundle recorded for this artifact." }));
    }
    out.appendChild(dl);
  }

  views.quarantine = async function () {
    const data = await getJSON("/quarantine");
    $("#quarantine-meta").textContent = data.enabled
      ? (data.total + " quarantine/break-glass item(s) for " + data.tenant)
      : "The approval workflow is not enabled.";
    const body = clear($("#quarantine-body"));
    if (!data.items.length) {
      body.appendChild(el("tr", null, el("td", { colspan: "5", class: "muted" }, "Nothing in quarantine for your tenant.")));
      return;
    }
    for (const it of data.items) {
      body.appendChild(el("tr", null,
        el("td", null, statusPill(it.status)),
        el("td", null, el("span.mono", { text: it.coordinate || "—" })),
        el("td", null, it.gate || "—"),
        el("td", null, el("span.muted", { text: it.reason || "—" })),
        el("td", null, el("span.muted", { text: it.guidance || "" }))));
    }
  };

  views.onboarding = async function () {
    const data = await getJSON("/onboarding");
    $("#onboarding-meta").textContent = "Point your tools at " + (data.proxyUrl || "the proxy") +
      ". Replace ${PULLTHROUGH_TOKEN} with your own access token (its team determines the tenant).";
    const list = clear($("#onboarding-list"));
    if (!data.snippets.length) {
      list.appendChild(el("p.muted", { text: "No backends are configured." }));
      return;
    }
    for (const s of data.snippets) {
      const panel = el("div.panel", null, el("h2", { text: s.title }));
      for (const n of (s.notes || [])) panel.appendChild(el("p.muted", { text: n }));
      if (s.body) panel.appendChild(el("pre.code", { text: s.body }));
      list.appendChild(panel);
    }
  };

  function fmtTime(s) {
    if (!s) return "—";
    const d = new Date(s);
    return isNaN(d) ? s : d.toLocaleString();
  }

  let currentView = "overview";
  function setView(name) {
    currentView = name;
    $$("#tabs .tab").forEach((t) => {
      const sel = t.dataset.view === name;
      t.setAttribute("aria-selected", sel ? "true" : "false");
      // Roving tabindex (WAI-ARIA tabs pattern): only the active tab is tabbable.
      t.setAttribute("tabindex", sel ? "0" : "-1");
    });
    $$(".view").forEach((v) => { v.hidden = v.id !== "view-" + name; });
    if (views[name]) views[name]().catch((e) => {
      if (e.auth) { showGate("Sign in required", e.message, e.loginURL); return; }
      toast(e.message, true);
    });
  }

  function showGate(title, msg, loginURL) {
    $("#tabs").hidden = true;
    $$(".view").forEach((v) => (v.hidden = true));
    const g = $("#gate"); g.hidden = false;
    $("#gate-title").textContent = title;
    $("#gate-msg").textContent = msg || "";
    const gl = $("#gate-login");
    if (loginURL) { gl.hidden = false; gl.href = loginURL; } else { gl.hidden = true; }
  }

  function showApp() {
    $("#gate").hidden = true;
    $("#tabs").hidden = false;
    setView("overview");
  }

  // Wire ARIA tabs/tabpanels relationships + keyboard navigation once.
  function wireTabs() {
    const tabs = $$("#tabs .tab");
    tabs.forEach((t, i) => {
      const name = t.dataset.view;
      const panel = $("#view-" + name);
      if (!t.id) t.id = "tab-" + name;
      if (panel) {
        t.setAttribute("aria-controls", panel.id);
        panel.setAttribute("role", "tabpanel");
        panel.setAttribute("aria-labelledby", t.id);
        if (!panel.hasAttribute("tabindex")) panel.setAttribute("tabindex", "0");
      }
      t.setAttribute("tabindex", t.getAttribute("aria-selected") === "true" ? "0" : "-1");
      t.addEventListener("click", () => setView(name));
      t.addEventListener("keydown", (e) => {
        let j = null;
        if (e.key === "ArrowRight" || e.key === "ArrowDown") j = (i + 1) % tabs.length;
        else if (e.key === "ArrowLeft" || e.key === "ArrowUp") j = (i - 1 + tabs.length) % tabs.length;
        else if (e.key === "Home") j = 0;
        else if (e.key === "End") j = tabs.length - 1;
        if (j != null) { e.preventDefault(); tabs[j].focus(); setView(tabs[j].dataset.view); }
      });
    });
  }

  async function boot() {
    wireTabs();
    $("#lookup-go").addEventListener("click", lookup);
    $("#lookup-input").addEventListener("keydown", (e) => { if (e.key === "Enter") lookup(); });

    let info;
    try { info = await getJSON("/userinfo"); }
    catch (e) { showGate("Portal unavailable", e.message); return; }

    if (!info.authenticated) {
      const link = $("#login-link");
      if (info.loginUrl) { link.hidden = false; link.href = info.loginUrl; }
      showGate("Sign in", info.reason || "Sign in to continue.", info.loginUrl);
      return;
    }
    $("#who").innerHTML = "";
    $("#who").appendChild(el("span", null, "Signed in as ", el("b", { text: info.subject || "you" })));
    if (!info.canView) {
      showGate("Access not available", info.reason || "You cannot view the portal.");
      return;
    }
    const tag = $("#tenant-tag");
    tag.hidden = false; tag.textContent = "tenant: " + info.tenant;
    showApp();
  }

  boot();
})();
