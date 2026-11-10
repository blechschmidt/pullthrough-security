/*
 * graph.js — a small, dependency-free force-directed renderer for the
 * supply-chain provenance graph (Task 33).
 *
 * It fetches the whole graph from the admin API (GET api/provgraph/export),
 * runs a lightweight spring/repulsion layout on a <canvas>, and lets an
 * operator highlight the blast radius of a CVE or commit (GET
 * api/provgraph/blast). Everything API-returned (names, SHAs, identities) is
 * placed via canvas text or textContent — never innerHTML — so untrusted
 * upstream strings cannot inject markup.
 */
(() => {
  "use strict";

  // --- API client (shares the dashboard's bearer-token convention) ----------
  const api = {
    token: sessionStorage.getItem("pt_admin_token") || "",
    headers() { return this.token ? { Authorization: "Bearer " + this.token } : {}; },
    async get(path) {
      const res = await fetch("api/" + path, { headers: this.headers(), cache: "no-store" });
      if (res.status === 401) {
        const t = window.prompt("This admin API requires a token. Enter the admin bearer token:");
        if (t) {
          this.token = t.trim();
          sessionStorage.setItem("pt_admin_token", this.token);
          return this.get(path);
        }
        throw new Error("unauthorized");
      }
      if (!res.ok) throw new Error("HTTP " + res.status);
      return res.json();
    },
  };

  // --- node/edge styling ----------------------------------------------------
  const KINDS = {
    package: { color: "#64748b", label: "Package", r: 6 },
    version: { color: "#2563eb", label: "Version (artifact)", r: 7 },
    commit:  { color: "#16a34a", label: "Commit", r: 7 },
    cve:     { color: "#dc2626", label: "CVE", r: 8 },
    signer:  { color: "#9333ea", label: "Signer", r: 7 },
  };
  const EDGE_LABELS = {
    "has-version": "package → version",
    "depends-on": "version → dependency",
    "built-from-commit": "version → commit",
    "affected-by-cve": "version → CVE",
    "signed-by": "version → signer",
  };
  const EDGE_COLOR = "#334155";
  const HIGHLIGHT = "#f59e0b";

  // --- state ----------------------------------------------------------------
  const canvas = document.getElementById("graph-canvas");
  const ctx = canvas.getContext("2d");
  const tip = document.getElementById("node-tip");
  let nodes = [];           // {id, kind, label, attrs, x, y, vx, vy}
  let edges = [];           // {from, to, kind, a, b}
  let byId = new Map();
  let highlighted = new Set();
  let highlightSeed = null;
  let hover = null;
  let width = 0, height = 0, dpr = 1;

  function resize() {
    const wrap = canvas.parentElement;
    dpr = window.devicePixelRatio || 1;
    width = wrap.clientWidth;
    height = wrap.clientHeight;
    canvas.width = Math.max(1, Math.floor(width * dpr));
    canvas.height = Math.max(1, Math.floor(height * dpr));
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
  }

  function seedLayout() {
    // Place nodes on a circle so the simulation starts from a spread-out state.
    const cx = width / 2, cy = height / 2;
    const radius = Math.min(width, height) * 0.4;
    nodes.forEach((n, i) => {
      const a = (i / Math.max(1, nodes.length)) * Math.PI * 2;
      n.x = cx + Math.cos(a) * radius * (0.6 + 0.4 * Math.random());
      n.y = cy + Math.sin(a) * radius * (0.6 + 0.4 * Math.random());
      n.vx = 0; n.vy = 0;
    });
  }

  // One Fruchterman-Reingold-style step: O(n^2) repulsion + spring attraction.
  function step() {
    const k = Math.sqrt((width * height) / Math.max(1, nodes.length)) * 0.55;
    const cx = width / 2, cy = height / 2;
    for (let i = 0; i < nodes.length; i++) {
      const a = nodes[i];
      let fx = 0, fy = 0;
      for (let j = 0; j < nodes.length; j++) {
        if (i === j) continue;
        const b = nodes[j];
        let dx = a.x - b.x, dy = a.y - b.y;
        let d2 = dx * dx + dy * dy;
        if (d2 < 0.01) { dx = Math.random() - 0.5; dy = Math.random() - 0.5; d2 = 0.01; }
        const d = Math.sqrt(d2);
        const rep = (k * k) / d;
        fx += (dx / d) * rep;
        fy += (dy / d) * rep;
      }
      // Mild gravity toward the center keeps disconnected components on-screen.
      fx += (cx - a.x) * 0.012;
      fy += (cy - a.y) * 0.012;
      a.fx = fx; a.fy = fy;
    }
    for (const e of edges) {
      const a = e.a, b = e.b;
      if (!a || !b) continue;
      const dx = a.x - b.x, dy = a.y - b.y;
      const d = Math.sqrt(dx * dx + dy * dy) || 0.01;
      const att = (d * d) / k;
      const ux = (dx / d) * att, uy = (dy / d) * att;
      a.fx -= ux; a.fy -= uy;
      b.fx += ux; b.fy += uy;
    }
    const damp = 0.85, maxStep = 18;
    for (const n of nodes) {
      n.vx = (n.vx + n.fx) * damp;
      n.vy = (n.vy + n.fy) * damp;
      n.vx = Math.max(-maxStep, Math.min(maxStep, n.vx));
      n.vy = Math.max(-maxStep, Math.min(maxStep, n.vy));
      n.x += n.vx * 0.02;
      n.y += n.vy * 0.02;
      n.x = Math.max(12, Math.min(width - 12, n.x));
      n.y = Math.max(12, Math.min(height - 12, n.y));
    }
  }

  function draw() {
    ctx.clearRect(0, 0, width, height);
    // Edges first.
    ctx.lineWidth = 1;
    for (const e of edges) {
      if (!e.a || !e.b) continue;
      const hot = highlighted.size && highlighted.has(e.from) && highlighted.has(e.to);
      ctx.strokeStyle = hot ? HIGHLIGHT : EDGE_COLOR;
      ctx.globalAlpha = highlighted.size && !hot ? 0.25 : 0.7;
      ctx.beginPath();
      ctx.moveTo(e.a.x, e.a.y);
      ctx.lineTo(e.b.x, e.b.y);
      ctx.stroke();
    }
    ctx.globalAlpha = 1;
    // Nodes.
    for (const n of nodes) {
      const style = KINDS[n.kind] || { color: "#888", r: 6 };
      const hot = highlighted.has(n.id);
      const dim = highlighted.size && !hot;
      ctx.globalAlpha = dim ? 0.3 : 1;
      ctx.beginPath();
      ctx.arc(n.x, n.y, style.r + (hot ? 2 : 0), 0, Math.PI * 2);
      ctx.fillStyle = hot ? HIGHLIGHT : style.color;
      ctx.fill();
      if (n.id === highlightSeed) {
        ctx.lineWidth = 2.5; ctx.strokeStyle = "#fff"; ctx.stroke();
      }
      // Label only versions/commits/CVEs to avoid clutter, and the hovered node.
      if (!dim && (n === hover || n.kind === "cve" || n.kind === "commit")) {
        ctx.globalAlpha = 1;
        ctx.fillStyle = "#cbd5e1";
        ctx.font = "11px system-ui, sans-serif";
        ctx.fillText(n.label, n.x + style.r + 3, n.y + 3);
      }
    }
    ctx.globalAlpha = 1;
  }

  let frames = 0;
  function loop() {
    if (frames < 400) { step(); frames++; }
    draw();
    requestAnimationFrame(loop);
  }

  function nodeAt(px, py) {
    for (let i = nodes.length - 1; i >= 0; i--) {
      const n = nodes[i];
      const r = (KINDS[n.kind] || { r: 6 }).r + 4;
      const dx = px - n.x, dy = py - n.y;
      if (dx * dx + dy * dy <= r * r) return n;
    }
    return null;
  }

  // --- data loading ---------------------------------------------------------
  async function load() {
    const doc = await api.get("provgraph/export");
    nodes = (doc.nodes || []).map((n) => ({ ...n, x: 0, y: 0, vx: 0, vy: 0 }));
    byId = new Map(nodes.map((n) => [n.id, n]));
    edges = (doc.edges || []).map((e) => ({ ...e, a: byId.get(e.from), b: byId.get(e.to) }));
    const s = doc.stats || {};
    document.getElementById("graph-stats").textContent =
      `${s.nodes || nodes.length} nodes · ${s.edges || edges.length} edges`;
    resize();
    seedLayout();
    frames = 0;
  }

  // --- blast-radius highlight ----------------------------------------------
  async function showImpact(id) {
    const result = document.getElementById("impact-result");
    result.classList.remove("muted");
    if (!id) { clearImpact(); return; }
    let data;
    try {
      data = await api.get("provgraph/blast?id=" + encodeURIComponent(id));
    } catch (err) {
      result.textContent = "Query failed: " + err.message;
      return;
    }
    highlighted = new Set();
    highlightSeed = data.seedId || null;
    if (highlightSeed) highlighted.add(highlightSeed);
    const arts = data.artifacts || [];
    for (const a of arts) {
      highlighted.add(a.id);
      // Pull the affected version's package node into the highlight too.
      const v = byId.get(a.id);
      if (v) {
        for (const e of edges) {
          if (e.kind === "has-version" && e.to === a.id) highlighted.add(e.from);
        }
      }
    }
    renderImpact(result, data);
  }

  function renderImpact(result, data) {
    result.textContent = "";
    if (!data.found) {
      result.textContent = "No cached artifact is affected by " + (data.seed || "that seed") + ".";
      return;
    }
    const head = document.createElement("div");
    head.textContent = `${data.total} affected (${data.direct} direct) · seed ${data.seedKind}: ${data.seed}`;
    result.appendChild(head);
    const ul = document.createElement("ul");
    for (const a of (data.artifacts || []).slice(0, 100)) {
      const li = document.createElement("li");
      const tag = a.direct ? "direct" : "hop " + a.distance;
      li.textContent = `${a.name}${a.version ? "@" + a.version : ""} (${tag})`;
      ul.appendChild(li);
    }
    result.appendChild(ul);
  }

  function clearImpact() {
    highlighted = new Set();
    highlightSeed = null;
    const result = document.getElementById("impact-result");
    result.classList.add("muted");
    result.textContent = "Highlight cleared.";
  }

  // --- legends --------------------------------------------------------------
  function buildLegends() {
    const legend = document.getElementById("legend");
    legend.textContent = "";
    for (const k of Object.keys(KINDS)) {
      const row = document.createElement("div");
      row.className = "legend-row";
      const dot = document.createElement("span");
      dot.className = "legend-dot";
      dot.style.background = KINDS[k].color;
      const txt = document.createElement("span");
      txt.textContent = KINDS[k].label;
      row.appendChild(dot); row.appendChild(txt);
      legend.appendChild(row);
    }
    const el = document.getElementById("edge-legend");
    el.textContent = "";
    for (const k of Object.keys(EDGE_LABELS)) {
      const row = document.createElement("div");
      row.textContent = k + " — " + EDGE_LABELS[k];
      el.appendChild(row);
    }
  }

  // --- events ---------------------------------------------------------------
  canvas.addEventListener("mousemove", (ev) => {
    const rect = canvas.getBoundingClientRect();
    hover = nodeAt(ev.clientX - rect.left, ev.clientY - rect.top);
    if (hover) {
      tip.style.display = "block";
      tip.style.left = (ev.clientX - rect.left + 12) + "px";
      tip.style.top = (ev.clientY - rect.top + 12) + "px";
      tip.textContent = "";
      const b = document.createElement("b");
      b.textContent = hover.label;
      tip.appendChild(b);
      const kind = document.createElement("div");
      kind.className = "muted";
      kind.textContent = hover.kind;
      tip.appendChild(kind);
      for (const key of ["repositoryUrl", "severity", "cvss", "confidence", "digest", "issuer"]) {
        if (hover.attrs && hover.attrs[key]) {
          const d = document.createElement("div");
          d.textContent = key + ": " + hover.attrs[key];
          tip.appendChild(d);
        }
      }
    } else {
      tip.style.display = "none";
    }
  });
  canvas.addEventListener("mouseleave", () => { tip.style.display = "none"; hover = null; });

  document.getElementById("impact-form").addEventListener("submit", (ev) => {
    ev.preventDefault();
    showImpact(document.getElementById("impact-id").value.trim());
  });
  document.getElementById("impact-clear").addEventListener("click", clearImpact);
  document.getElementById("reset-view").addEventListener("click", () => { resize(); seedLayout(); frames = 0; });
  window.addEventListener("resize", () => { resize(); });

  buildLegends();
  load().then(() => loop()).catch((err) => {
    document.getElementById("graph-stats").textContent = "error: " + err.message;
  });
})();
