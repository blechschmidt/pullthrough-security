// The self-service page for personal cache links (Task 177). No framework, no
// build step, no inline script or style: the page's Content-Security-Policy
// admits only this file and the stylesheet next to it.
(function () {
  "use strict";

  const $ = (sel, root) => (root || document).querySelector(sel);

  // el("td.sub", {title: "…", text: "…"}, child, …) builds an element. Text is
  // always set as text, never as markup: names and labels come from an identity
  // provider and from other people's keyboards.
  function el(spec, attrs) {
    const parts = spec.split(".");
    const node = document.createElement(parts[0] || "div");
    if (parts.length > 1) node.className = parts.slice(1).join(" ");
    if (attrs) {
      for (const key of Object.keys(attrs)) {
        const value = attrs[key];
        if (value === null || value === undefined || value === false) continue;
        if (key === "text") node.textContent = value;
        else node.setAttribute(key, value === true ? "" : value);
      }
    }
    for (let i = 2; i < arguments.length; i++) {
      const child = arguments[i];
      if (child === null || child === undefined) continue;
      node.appendChild(typeof child === "string" ? document.createTextNode(child) : child);
    }
    return node;
  }

  function clear(node) {
    while (node.firstChild) node.removeChild(node.firstChild);
    return node;
  }

  // The API. Every request that changes something carries a header a page of
  // another origin cannot make the browser send.
  async function api(method, path, body) {
    const init = { method, credentials: "same-origin", headers: { Accept: "application/json" } };
    if (method !== "GET") {
      init.headers["X-Pullthrough-Links"] = "1";
      init.headers["Content-Type"] = "application/json";
      init.body = JSON.stringify(body || {});
    }
    const resp = await fetch(path, init);
    if (resp.status === 204) return null;
    let data = null;
    try { data = await resp.json(); } catch (e) { /* not JSON: reported below */ }
    if (!resp.ok) {
      const err = new Error((data && data.error) || ("the request failed (" + resp.status + ")"));
      err.status = resp.status;
      throw err;
    }
    return data;
  }

  let statusTimer = null;
  function say(message, isError) {
    const box = $("#status");
    if (statusTimer) clearTimeout(statusTimer);
    box.textContent = message || "";
    box.className = "status" + (message ? " show" : "") + (isError ? " err" : "");
    if (message && !isError) statusTimer = setTimeout(() => say(""), 6000);
  }

  function fmtTime(iso) {
    if (!iso) return "";
    const d = new Date(iso);
    return isNaN(d) ? iso : d.toLocaleString();
  }

  function fmtAge(iso) {
    if (!iso) return "";
    const secs = Math.round((Date.now() - new Date(iso).getTime()) / 1000);
    if (isNaN(secs)) return iso;
    if (secs < 0) {
      const ahead = -secs;
      if (ahead < 3600) return "in " + Math.max(1, Math.round(ahead / 60)) + " min";
      if (ahead < 172800) return "in " + Math.round(ahead / 3600) + " h";
      return "in " + Math.round(ahead / 86400) + " days";
    }
    if (secs < 90) return "just now";
    if (secs < 3600) return Math.round(secs / 60) + " min ago";
    if (secs < 172800) return Math.round(secs / 3600) + " h ago";
    return Math.round(secs / 86400) + " days ago";
  }

  async function copyFrom(id) {
    const field = document.getElementById(id);
    const text = field.value !== undefined ? field.value : field.textContent;
    try {
      await navigator.clipboard.writeText(text);
      say("Copied.");
    } catch (e) {
      // No clipboard access (an insecure origin, a denied permission): select
      // the text so that Ctrl+C does it.
      if (field.select) { field.focus(); field.select(); }
      say("Press Ctrl+C to copy.");
    }
  }

  let session = null;
  let created = null; // the response that carried the new link; kept only in memory

  function renderGate(title, text, showSignIn) {
    $("#gate").hidden = false;
    $("#app").hidden = true;
    $("#gate-title").textContent = title;
    $("#gate-text").textContent = text;
    $("#sign-in").hidden = !showSignIn;
    $("#sign-out").hidden = true;
    $("#who").textContent = "";
  }

  function ttlOptions(maxSeconds) {
    const select = clear($("#new-ttl"));
    const day = 86400;
    const choices = [[7, "in 7 days"], [30, "in 30 days"], [90, "in 90 days"], [365, "in a year"]];
    const maxDays = maxSeconds ? Math.floor(maxSeconds / day) : 0;
    const longest = maxSeconds
      ? (maxDays >= 1 ? "in " + maxDays + " days (the longest allowed)" : "as late as allowed")
      : "never";
    for (const [days, label] of choices) {
      if (maxSeconds && days >= maxDays) continue;
      select.appendChild(el("option", { value: String(days), text: label }));
    }
    select.appendChild(el("option", { value: "0", text: longest, selected: true }));
  }

  function renderApp() {
    $("#gate").hidden = true;
    $("#app").hidden = false;
    $("#sign-out").hidden = false;
    const u = session.user || {};
    $("#who").textContent = (u.name ? u.name + " · " : "") + (u.subject || "") + (u.team ? " · " + u.team : "");
    $("#example-url").textContent = session.publicUrl + session.pathPrefix + "/ptl1…/v1/<source>/";
    ttlOptions(session.linkTtlSeconds);
    $("#new-limit").textContent = session.maxLinks
      ? "You can have up to " + session.maxLinks + " working links at a time."
      : "";
  }

  function statePill(link) {
    const title = link.state === "revoked"
      ? ("revoked " + fmtTime(link.revokedAt) + (link.revokedBy ? " by " + link.revokedBy : "") + (link.revokeReason ? " — " + link.revokeReason : ""))
      : "";
    return el("span.pill." + link.state, { text: link.state, title: title || null });
  }

  function renderLinks(links) {
    const body = clear($("#links-body"));
    const working = links.filter((l) => l.state === "active").length;
    $("#links-count").textContent = links.length ? "(" + working + " working)" : "";
    if (!links.length) {
      body.appendChild(el("tr", null, el("td.muted", { colspan: "6", text: "You have no links yet. Create one above." })));
      return;
    }
    for (const link of links) {
      const name = link.label || "(unnamed)";
      const used = link.lastUsedAt
        ? el("td", { title: fmtTime(link.lastUsedAt) }, fmtAge(link.lastUsedAt),
            el("span.sub", { text: "from " + (link.lastAddr || "?") + (link.lastAgent ? " · " + link.lastAgent : "") }))
        : el("td.muted", { text: "never" });
      const actions = el("td");
      if (link.state === "active") {
        const btn = el("button.btn.danger", { type: "button", text: "Revoke", "aria-label": "Revoke the link " + name });
        btn.addEventListener("click", () => revoke(link, btn));
        actions.appendChild(btn);
      }
      body.appendChild(el("tr", null,
        el("td", null, name,
          el("span.sub.mono", { text: "id " + link.id, title: "how the administrators' download log names this link" }),
          link.issuedBy ? el("span.sub", { text: "issued by " + link.issuedBy }) : null),
        el("td", null, statePill(link)),
        el("td", { title: fmtTime(link.createdAt) }, fmtAge(link.createdAt),
          link.createdFrom ? el("span.sub", { text: "from " + link.createdFrom }) : null),
        el("td", { title: fmtTime(link.expiresAt) }, link.expiresAt ? fmtAge(link.expiresAt) : "never"),
        used,
        actions));
    }
  }

  async function loadLinks() {
    const data = await api("GET", "api/links");
    renderLinks(data.links || []);
  }

  async function revoke(link, button) {
    const name = link.label || link.id;
    if (!window.confirm('Revoke the link "' + name + '"? Whatever uses it stops working at once.')) return;
    button.disabled = true;
    try {
      await api("POST", "api/links/revoke", { id: link.id });
      say('The link "' + name + '" is revoked.');
      await loadLinks();
    } catch (e) {
      button.disabled = false;
      handleError(e);
    }
  }

  function snippetCard(snippet, index) {
    const id = "snippet-" + index;
    const head = el("div.head", null, el("h3", { text: snippet.title + (snippet.file ? " — " + snippet.file : "") }));
    const card = el("div.snippet", null, head);
    if (snippet.body) {
      const copy = el("button.btn.ghost", { type: "button", text: "Copy", "aria-label": "Copy the configuration: " + snippet.title });
      copy.addEventListener("click", () => copyFrom(id));
      head.appendChild(copy);
      card.appendChild(el("pre", { id: id, tabindex: "0", text: snippet.body }));
    }
    if (snippet.notes && snippet.notes.length) {
      const list = el("ul");
      for (const note of snippet.notes) list.appendChild(el("li", { text: note }));
      card.appendChild(list);
    }
    return card;
  }

  function renderCreatedUpstream() {
    if (!created) return;
    const name = $("#created-upstream").value;
    const up = (created.upstreams || []).find((u) => u.name === name);
    const box = clear($("#created-snippets"));
    if (!up) {
      $("#created-url").value = "";
      return;
    }
    const asToken = $("#created-mode").value === "token" && up.tokenSnippets;
    $("#created-url").value = asToken ? created.token : up.url;
    document.querySelector('label[for="created-url"]').textContent = asToken
      ? "Your access token (the password; any user name)"
      : "Address for this source";
    const snippets = (asToken ? up.tokenSnippets : up.snippets) || [];
    snippets.forEach((s, i) => box.appendChild(snippetCard(s, i)));
  }

  function renderCreated() {
    const section = $("#created");
    if (!created) {
      section.hidden = true;
      $("#created-base").value = "";
      $("#created-url").value = "";
      clear($("#created-snippets"));
      return;
    }
    $("#created-base").value = created.baseUrl;
    const select = clear($("#created-upstream"));
    const ups = created.upstreams || [];
    for (const up of ups) select.appendChild(el("option", { value: up.name, text: up.name + " (" + up.type + ")" }));
    $("#created-mode").value = "url";
    $("#created-mode-field").hidden = !ups.some((u) => u.tokenSnippets && u.tokenSnippets.length);
    section.hidden = false;
    renderCreatedUpstream();
    section.focus();
    section.scrollIntoView({ block: "start" });
  }

  async function createLink(ev) {
    ev.preventDefault();
    const submit = $("#new-submit");
    submit.disabled = true;
    try {
      created = await api("POST", "api/links", {
        label: $("#new-label").value.trim(),
        ttlDays: parseInt($("#new-ttl").value, 10) || 0,
      });
      $("#new-label").value = "";
      renderCreated();
      await loadLinks();
    } catch (e) {
      handleError(e);
    } finally {
      submit.disabled = false;
    }
  }

  function handleError(e) {
    if (e && e.status === 401) {
      session = null;
      created = null;
      renderCreated();
      renderGate("Your session has ended", "Sign in again to manage your links. The links you created keep working.", true);
      return;
    }
    say((e && e.message) || "Something went wrong.", true);
  }

  async function signOut() {
    try { await api("POST", "logout"); } catch (e) { /* the cookie may already be gone */ }
    session = null;
    created = null;
    renderCreated();
    renderGate("Signed out", "The links you created keep working.", true);
  }

  async function start() {
    $("#new-form").addEventListener("submit", createLink);
    $("#sign-out").addEventListener("click", signOut);
    $("#created-upstream").addEventListener("change", renderCreatedUpstream);
    $("#created-mode").addEventListener("change", renderCreatedUpstream);
    $("#created-done").addEventListener("click", () => { created = null; renderCreated(); say("The link is hidden. It keeps working."); });
    document.addEventListener("click", (ev) => {
      const target = ev.target.closest && ev.target.closest("[data-copy]");
      if (target) copyFrom(target.getAttribute("data-copy"));
    });
    // A link must not outlive the tab in the browser's page cache.
    window.addEventListener("pagehide", () => { created = null; renderCreated(); });

    try {
      session = await api("GET", "api/session");
    } catch (e) {
      renderGate("The page could not be loaded", (e && e.message) || "", false);
      return;
    }
    if (!session.authenticated) {
      if (session.signInEnabled) {
        renderGate("Sign in to get your personal cache links",
          "You sign in with your organization account. Downloads through your links are then recorded under your name.", true);
      } else {
        renderGate("Sign-in is not configured",
          "This proxy has no identity provider for cache users. Ask your administrator for a personal link.", false);
      }
      return;
    }
    renderApp();
    try { await loadLinks(); } catch (e) { handleError(e); }
  }

  start();
})();
