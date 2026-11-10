# Admin UI & portal accessibility baseline (WCAG 2.1 AA)

This document is the accessibility baseline for every embedded web surface the
proxy ships:

- the **admin dashboard** (`internal/admin/ui/`) — the SPA shell, the real-time
  **Security Operations (SOC)** view, the **dossier 360 view**, the forensic
  **timeline**, the federated **query** console and the supply-chain **graph**
  page (`graph.html`);
- the **tenant self-service portal** (`internal/portal/ui/`).

The target conformance level is **WCAG 2.1 AA**. All assets are dependency-free,
zero-build HTML/CSS/JS embedded in the binary, so the baseline is enforced by a
plain `go test` (see [Automated checking](#automated-checking)) — no browser or
Node toolchain is required in CI.

## Structure & landmarks (1.3.1, 2.4.1)

- Each page declares `<html lang="en">` and `<meta name="color-scheme">`.
- One `<main id="main">` landmark per page; `<header>` (banner) and `<nav>`
  landmarks are present and every `<nav>` carries an `aria-label`.
- A **skip link** (`.skip-link`, first focusable element) jumps to `#main`. It is
  visually hidden until focused, then painted with the solid-accent token.
- Data tables use `<thead>`/`<th scope="col">`; icon-only headers carry a
  `visually-hidden` label.

## Tabs (WAI-ARIA tabs pattern) (2.1.1, 4.1.2)

The section switcher is a real tablist:

- The container is `role="tablist"` with an `aria-label`; each button is
  `role="tab"` with `aria-selected`.
- At runtime the app wires `aria-controls` → the panel, and each view section
  becomes `role="tabpanel"` + `aria-labelledby` (its tab) + `tabindex="0"` so a
  keyboard user lands in content after leaving the tablist.
- **Roving tabindex**: only the active tab is in the Tab order (`tabindex="0"`);
  the rest are `tabindex="-1"`.

| Key | Action |
|-----|--------|
| `Tab` | Move from the active tab into the panel / out of the tablist |
| `←` `→` / `↑` `↓` | Move to and activate the adjacent tab |
| `Home` / `End` | Jump to the first / last tab |

## Modal drawer (2.1.2, 2.4.3)

The detail drawer is `role="dialog" aria-modal="true" aria-labelledby`:

- Opening moves focus to the close button and **remembers the opener**.
- `Tab`/`Shift+Tab` are **trapped** inside the drawer (focus cannot reach the
  inert page behind it).
- `Escape` closes it; closing **restores focus** to the element that opened it.
- The global `r` refresh shortcut is suppressed while the drawer is open.

## Form controls (1.3.1, 3.3.2, 4.1.2)

Every `<input>`, `<select>` and `<textarea>` has a programmatic name — a wrapping
or `for=`-associated `<label>`, or an `aria-label` where a visible label would be
redundant. Placeholders are **never** relied on as the sole label. The automated
check fails the build if any control lacks a name.

## Live regions (4.1.3)

Real-time surfaces announce politely without flooding the screen reader:

- The SOC **stream status** pill and **summary meta** are `role="status"
  aria-live="polite"`; the Pause/Resume control exposes `aria-pressed`. The
  high-frequency verdict rows themselves are *not* a live region (that would be
  far too chatty) — the rolling counts summarise them instead.
- Health/identity pills, provenance results and inline results that update
  asynchronously use `aria-live="polite"`.

## Visible focus (2.4.7)

A global `:focus-visible { outline: 2px solid var(--accent); outline-offset: 2px }`
gives every interactive element a clear, theme-aware focus ring. `:focus-visible`
(not `:focus`) means pointer clicks don't paint a ring, but keyboard/AT focus
always does.

## Colour & contrast (1.4.3, 1.4.11), light + dark

Both UIs support light and dark themes via `prefers-color-scheme`. The vivid
status colours (`--ok`/`--warn`/`--crit`, `--accent`) are used only for
decorative fills, bars and borders. Two derived token families keep text and
white-on-colour fills at ≥ 4.5:1 in **both** themes:

- `--*-ink` — status colour rendered **as text** on a light/tinted surface.
  Darkened in the light theme (where the vivid hue fails), tracks the vivid hue
  in the dark theme (where it passes).
- `--*-solid` / `--accent-solid` — mid-dark fills that carry **white text**
  (primary buttons, skip link, incident banner, SOC outcome bar, error toast),
  fixed across themes.

Representative measured ratios (light theme on white/tint; the dark theme is
equal or better):

| Pairing | Token | Ratio | Pass |
|---------|-------|-------|------|
| Body text on background | `--text` on `--bg` | ~13:1 | ✓ |
| Muted text on surface | `--muted` on `--surface` | ~5.0:1 | ✓ |
| "ok" text on tint | `--ok-ink` #15803d | ~5.0:1 | ✓ |
| "warn" text on tint | `--warn-ink` #b45309 | ~4.8:1 | ✓ |
| "crit" text on tint | `--crit-ink` #b91c1c | ~6.5:1 | ✓ |
| White on primary fill | on `--accent-solid` #2563eb | ~5.2:1 | ✓ |
| White on SOC "ok" segment | on `--ok-solid` #15803d | ~5.0:1 | ✓ |

The vivid `--ok` (#16a34a, ~3.3:1), `--warn` (#d97706, ~3.2:1) and dark-theme
`--accent` (#5b8cff, ~3.2:1 with white) **fail** as text/white-on-fill, which is
why they are confined to decorative use and the ink/solid tokens exist.

## Motion (2.3.3)

A global `@media (prefers-reduced-motion: reduce)` rule collapses **every**
animation and transition (view fade, drawer slide, toast, and the SOC
live-feed flash on real-time events) to a ~0ms duration — durations stay
non-zero so any `animationend`/`transitionend` listeners still fire.

## Automated checking

`internal/uiaudit` is a dependency-free, static accessibility linter — an
"axe-core equivalent" for the structural/name/landmark/keyboard/motion rules
that are verifiable from markup. It runs against the embedded `embed.FS`:

```sh
# Gate the embedded admin + portal assets (runs in CI):
go test ./internal/admin/ ./internal/portal/ -run Accessibility -v

# The linter's own fixtures (clean doc, violation doc, label heuristics):
go test ./internal/uiaudit/
```

Rules enforced at **error** severity (fail the build): `html-has-lang`,
`has-main-landmark`, `landmark-labeled`, `tablist-present`, `tab-aria-selected`,
`control-has-name`, `button-has-name`, `dialog-name`, `image-alt`, `skip-link`,
`focus-visible`, `reduced-motion`. Advisory **warn** rules: `tab-aria-controls`
(wired at runtime), `dialog-modal`, `canvas-has-alt`, `link-has-name`,
`anchor-target`.

### Optional: deep axe-core audit of a running instance

The static linter does not render the DOM, so dynamic ARIA wiring and composited
colour-contrast are not re-verified in CI. For a full audit, point axe-core at a
running proxy (which does execute the JS):

```sh
# with the admin UI enabled and reachable at http://localhost:8080/admin/
npx @axe-core/cli http://localhost:8080/admin/ --tags wcag2a,wcag2aa
npx @axe-core/cli http://localhost:8080/portal/ --tags wcag2a,wcag2aa
```

## Known limitations

- The supply-chain **graph** canvas is an interactive pointer visualisation. It
  exposes a text alternative (`role="img"` + `aria-label` + fallback content),
  and the same relationships are fully queryable via the keyboard-accessible
  *Impact analysis* panel and the *Query* tab, but the node/edge canvas itself is
  not keyboard-navigable. This is an accepted, documented equivalent-facilitation.
- Composited colour-contrast (status colours over `color-mix` tints) is verified
  by hand (table above), not by the static linter.
