# Console - ggo-kea-dhcp web UI design system

This document is the **authoritative contract** for the appliance web UI. Every
page, component, and live fragment is held to it. If a change can't be expressed
in the tokens/components/conventions below, the design system is extended *here
first*, then used - not worked around with one-off inline styles.

> **For reviewers / future sessions:** before adding UI, read §3 (principles),
> §8 (component catalog), and §11 (conventions). The fastest way to violate the
> design is to reach for a hard-coded color, a shadow/gradient, an `@import`, or
> a remote asset. Don't. The grep gates in §12 will catch it.

---

## 1. What this is

A control plane for Green-GO broadcast intercom hardware: a Kea DHCP4 server on a
Raspberry Pi, configured by a single operator over a LAN, often offline. The
screen is a **control surface**, not a marketing page - but it should feel like a
**modern 2025 product**, not a legacy router admin. Aesthetic direction:
**Linear / Vercel** - airy, high-contrast, crisp type, soft radius + subtle
elevation, purposeful micro-motion. Workflows are **rethought for modern UX**, not
ported from the old UI (e.g. in-field password reveal + live validation, guided
setup with live subnet preview, live dashboard/lease views).

## 2. Stack

| Concern | Choice | Notes |
|---|---|---|
| Rendering | **templ** (`github.com/a-h/templ` v0.3.1020) | type-safe Go components; `templ generate` before `go build` |
| Interactivity + live | **Datastar v1** (runtime `datastar.js` v1.0.2; Go SDK `datastar-go` v1.2.2) | declarative `data-*`; SSE for live updates |
| Icons | **Lucide** (`lucide-static` v1.18.0) | genuine SVGs, curated set, embedded + inlined; see §11 |
| Fonts | **Inter** + **JetBrains Mono** | self-hosted subset `.woff2`, embedded |

**Offline-first is non-negotiable.** Every asset (Datastar runtime, fonts, CSS,
icons) is `//go:embed`-ed under `internal/web/static/` and served same-origin.
**No CDN, no `@import`, no Google Fonts, no runtime network fetch.**

**Datastar v1 API note.** v1 renamed the pre-1.0 events: use `PatchElements` /
`PatchSignals` (Go SDK), not `MergeFragments` / `MergeSignals`. Detect a Datastar
request server-side via the `Datastar-Request: true` header (`isDatastar(r)` - the
new-stack analogue of the retired `isHTMX`). Useful SDK helpers: `sse.Redirect`,
`sse.PatchElementTempl` (patch a templ component directly as a fragment).

## 3. Principles

1. **Density first** - compact tables/tiles, 13–14px body, no hero whitespace.
2. **Refined depth (modern minimal - Linear/Vercel direction)** - soft radius
   (`--r-sm/md/lg` = 6/10/14) and **subtle elevation**: `--shadow-sm` on cards,
   tiles and inputs; `--shadow-lg` on overlays (dialogs, toasts). 1px borders
   still carry structure. A subtle backdrop blur on the **sticky header** and the
   **dialog backdrop** is on-brand. What stays forbidden: **heavy glassmorphism on
   content surfaces, gradients, and neon glow** (the old "poppy, AI-generated"
   look). Depth is quiet, not decorative.
3. **Color is semantic, never decorative** - green = brand/primary/healthy; amber
   = warn; red = error/danger; everything else greyscale. No gradient text, no
   purple labels, no rainbow bars.
4. **Mono for machine data** - every IP / MAC / CIDR / VLAN / Option-82 id in
   tabular mono so columns align and digits don't jiggle on a live refresh.
5. **Predictable, server-driven layout** - sticky header → single capped content
   column; fragments merge into stable regions; no reflow on update.
6. **State always legible & live** - lifecycle badge in the header; per-resource
   state as badge/dot **plus text**, never color alone, never glow; updates push
   in instantly.
7. **Offline-honest** - no runtime network dependency.
8. **Calm motion** - motion only explains a state change, ≤150ms, suppressed
   under `prefers-reduced-motion`.
9. **Touch-first on mobile** - the appliance is configured from phones and tablets
   as often as laptops. On a coarse pointer, interactive targets are **≥44×44px**
   (controls grow via `@media (pointer:coarse)`), tap spacing opens up so adjacent
   controls aren't mis-hit, and nothing critical hides behind hover (hover is a
   progressive enhancement, never the only affordance - every hover cue has a
   persistent equivalent). The `<details>` nav, dialogs, and toasts are all
   thumb-reachable and dismissable by tap. Density (§Principle 1) is the *default*,
   not an excuse for sub-44px touch targets.

## 4. Theme & color tokens

**Mechanism (system-default, user-override, no-FOUC).** Truth is `data-theme` on
`<html>`: absent → follow OS via `@media (prefers-color-scheme)`; `="light"` /
`="dark"` → explicit override; persisted in `localStorage["ggo-theme"]`. A tiny
inline `<head>` script sets the attribute **before** the stylesheet loads (no
flash), independent of Datastar. The header toggle cycles **OS → light → dark →
OS** (monitor / sun / moon). `<html>` is never fragment-merged, so the theme
survives every live update.

All tokens are CSS custom properties on `:root`. **`static/style.css` is the
authoritative source for exact values** - the palette was modernized to the
Linear/Vercel direction (cleaner neutrals; light `--bg:#fff`, dark `--bg:#08090a`;
surfaces `--surface` / `--surface-2` / `--surface-3`; elevation `--shadow-sm/md/lg`;
radius `--r-sm/md/lg` = 6/10/14; `--accent-ring` for focus glows). The table below
captures the brand/semantic *intent*; trust style.css for the current hexes.
Targets: text ≥ 4.5:1, UI/borders ≥ 3:1 (WCAG AA).

| Token | Light | Dark |
|---|---|---|
| `--bg` | `#f4f5f7` | `#0e1116` |
| `--surface` | `#ffffff` | `#161b22` |
| `--surface-raised` | `#fafbfc` | `#1c232c` |
| `--surface-sunken` | `#eef0f3` | `#0e1218` |
| `--border` / `--border-strong` | `#d6dae0` / `#b7bec7` | `#2b333d` / `#3a444f` |
| `--text` / `--text-secondary` / `--text-muted` | `#1b2027` / `#5a626d` / `#828a95` | `#e6e9ee` / `#a3acb9` / `#727c89` |
| `--accent` / `-hover` / `-active` | `#007d00` / `#006a00` / `#005700` | `#3fb950` / `#4cc85e` / `#36a046` |
| `--accent-tint` / `--accent-on` | `#e6f2e6` / `#ffffff` | `#13351a` / `#0b1f0e` |
| `--ok` / `-tint` / `-border` | `#1d7a33` / `#e4f3e7` / `#aedab8` | `#3fb950` / `#13351a` / `#235c2c` |
| `--warn` / `-tint` / `-border` | `#9a6400` / `#fbf0d9` / `#e4c682` | `#d9a531` / `#3a2e10` / `#5e4a1c` |
| `--err` / `-tint` / `-border` | `#c0291f` / `#fbe7e5` / `#e6a9a3` | `#f0524a` / `#3a1714` / `#6e2b26` |
| `--focus-ring` | `#1a73e8` | `#58a6ff` |

**Brand divergence (the only one).** The literal brand `#007d00` passes AA for
white-on-green only in light mode. Dark mode uses `#3fb950` with **dark** label
text (`--accent-on: #0b1f0e`). Markup is identical; only the token values differ.
The focus ring is blue (not green) so a focused green button's ring is visible.

## 5. Typography

Two self-hosted subset faces, `font-display:swap`, system fallback:
- **UI sans: Inter** 400/500/600 - strong at 13–14px, true tabular figures.
- **Mono: JetBrains Mono** 400/500 - unambiguous `0/O 1/l/I`; for all machine data.

Scale (base 16px): card title 16/600; `h3` 14/600 uppercase `.04em`; body 14/400/1.5;
table cell 13 (data cells mono); `th` 12/600 uppercase `--text-secondary`; label
13/500 `--text-secondary` (no uppercase, no color accent); help 12; tile value
28/600; code 13 mono; badge 11/600. `font-feature-settings:"tnum" 1` on body so
all figures are tabular (live numbers don't reflow).

## 6. Spacing / radius / elevation / motion

- Spacing `--sp-1..6` = 4 / 8 / 12 / 16 / 24 / 32px (4px base).
- **Card padding 16px**, margin-bottom 24px (the biggest density change vs the old UI).
- Radius `--r-sm` 4 / `--r-md` 6 / `--r-full` (dots, pills).
- One `--shadow-overlay`, overlays only. **No shadows on cards/tiles/inputs.**
- Motion `--dur-fast` 100ms / `--dur` 150ms / `--ease cubic-bezier(.2,0,0,1)`. No
  page-wide fade. `prefers-reduced-motion` neutralizes all transitions/animations.

## 7. Responsive

Sticky full-width header + centered column: `.container{max-width:1200px;margin:0
auto;padding:24px 16px}`.

| Viewport | Behavior |
|---|---|
| mobile 360–599 | 1 col; nav → native `<details>` menu; tiles stack; tables → h-scroll |
| tablet 600–1023 | tiles 2-up; forms 2-up; nav inline |
| **laptop 1024–1599 (target)** | tiles 3-up; full inline nav |
| large ≥1920 | **cap at 1200** - don't go fluid |

**Tables on mobile = horizontal scroll, never stacked cards.** DHCP rows are
column-relational (IP↔MAC↔port); stacking kills cross-column scan. Use
`overflow-x:auto`, a `min-width` on the table, sticky-left first column (IP), and
search. Only metric **tiles** stack/grid; tables never do.

**Touch sizing (Principle 9).** A global `@media (pointer:coarse)` block in
`style.css` raises control heights to ≥44px (`.btn`, `.form-control`, `.nav-link`,
`.theme-toggle`, `summary`, table row tap targets) and widens spacing. This keys
off pointer type, not viewport width, so a touchscreen laptop also gets touch
sizing while a small mouse-driven window does not. Row action buttons in dense
tables use `.btn-sm` on desktop but still clear 44px on coarse pointers.

## 8. Component catalog

Token-driven classes (defined in `static/style.css`). Shared focus ring via
`:where(a,button,input,select,textarea,summary,[tabindex]):focus-visible`.

- **`.btn`** (32px) + `-primary` (accent fill, `--accent-on` text), `-secondary`
  (surface + `--border-strong`), `-danger` (**outline** `--err`), `.btn-sm`
  (24px). Solid red is `.btn-danger-solid` and is used **only** for the confirm
  button *inside* a destructive dialog. No gradient/glow/lift. (Controls grow to
  ≥44px on coarse pointers - §Principle 9.)
- **`.card`** - surface, 1px border, `--r-md`, 16px pad, **no shadow**;
  `.card-title` 16/600 + optional leading dot/16px icon.
- **`table`** dense - sticky `th` (uppercase 12px), 8×12 pad, subtle zebra, hover
  `--accent-tint`; data cells mono+tnum; mobile first-cell sticky-left.
- **`.form-label` / `.form-control`** (32px, `--surface-raised`, `--border-strong`,
  focus ring + border, `aria-invalid`→`--err`). Select chevron is an inline
  `data:` SVG, never a remote url.
- **`.badge`** `-ok / -warn / -err / -info / neutral` + `.badge-class` (neutral
  mono; device classes are **not** per-type colored). Lifecycle: FACTORY /
  ONBOARDING = warn, CONFIGURING = info, ACTIVE = ok.
- **`.status-dot`** `.ok / .warn / .err` + idle (no glow).
- **`.switch`** - flat toggle (`<label class="switch"><input type="checkbox"><span
  class="track">/<span class="thumb">`); accent when checked, no glow. For boolean
  config (e.g. enable WiFi). A plain checkbox is fine where a switch is overkill.
- **`.meter`** green fill on sunken track → `.warn` amber ≥80% → `.err` red ≥95%;
  pair with `role="progressbar"` + aria values.
- **`.tile`** - left-aligned greyscale 28px value + leading status dot (meaning
  comes from the dot). Uplink "Offline" = neutral grey, **not red** (expected on
  an isolated net).
- **`.alert`** `-info / -warn / -err` strips (left border + icon carry status).
- **`.toast`** - flat, left-border + icon carries status, `aria-live`; 5s
  auto-dismiss (errors persist).
- **`dialog`** - native `<dialog>.showModal()` (free focus-trap/Escape),
  `::backdrop` dim; structure `.dialog-head` / `.dialog-body` / `.dialog-foot`
  (footer right-aligns actions). Used for scope-edit + pin-confirm.
- **`.empty`** - icon + title + hint (no leases, no learnable ports, empty scope list).
- **header / nav** - flat, no blur/gradient; `.nav-link[aria-current="page"]` →
  accent + tint (server is the source of truth for the active link);
  `.theme-toggle` 32×32 icon button.

## 9. Live & non-blocking state

The core behavior: **the operator never refreshes and is never frozen.**

- **Scope of "live" = read-only reflection, never live-apply.** The channel pushes
  *observed system state* (server→operator). It does **not** apply form inputs as
  you type. All config forms (wizard, scope-edit dialog, settings) are **staged** -
  nothing touches the system until an explicit Apply/Submit. In-form reactivity
  (CIDR auto-calc, show/hide fields, add/remove scope cards) is **pure client-side
  Datastar signals**, zero backend calls.
- **Channel.** A hidden element opens `GET /sse/live` on load. The Go SSE hub
  (`internal/web/live.go`) pushes `PatchElements` to **stable region ids**:
  `#state-badge`, `#dash-tiles`, `#pool-table`, `#leases-body`, `#learnable-body`,
  `#link-status`. **Each fragment is rendered by the same templ partial used for
  first paint**, so live and initial markup cannot drift.
- **Event sources.** Lifecycle/link/uplink/pool transitions publish from
  `reconcileActive` / `beginApply` / `finishApply` / settings / reset (event-driven,
  instant). Kea-derived lists refresh on a 3–5s server ticker **only while a client
  is connected**, pushed **only on change** (per-region hash). Idle clients cost nothing.
- **Non-blocking actions.** Every mutating control (`@post`/`@delete`) uses
  `data-indicator` for a localized in-flight spinner; the rest of the page stays
  interactive. The server responds immediately; results arrive as merges.
- **Transport.** SSE is plain HTTP/1.1; Datastar streams over fetch (not native
  `EventSource`), so it works on a bare `http://` origin - **no TLS/Caddy required**.

## 10. Accessibility (pre-merge checklist)

Landmarks (`header` / `nav[aria-label]` / `main`); every input has `<label for>`
(no placeholder-as-label); shared `:focus-visible` ring; `aria-current` nav;
`aria-live` toast + live regions (assertive for errors); native `<dialog>`
focus-trap + `aria-labelledby` + return focus on close; AA contrast (§4); **color
independence** (every status has text/icon, never color alone); reduced-motion
honored; **touch targets ≥44×44 on coarse pointers** (≥24×24 minimum on fine
pointers, per §Principle 9); fully keyboard-operable (including the `<details>` menu).

## 11. Conventions

- **Icons:** genuine **Lucide** (`lucide-static` v1.18.0), embedded under
  `views/icons/*.svg` and rendered inline via `@Icon("name")` (Go `Icon(name)`
  reads the embedded SVG). Inline - not a JS loader - so icons render correctly
  inside SSE-merged fragments with no re-hydration. Size/color via CSS (`.lucide`
  is `16px`/`currentColor`; override per context, e.g. `.theme-toggle .lucide`).
  The set is **curated for this UI's needs**, not inherited from the old front-end;
  add an icon by dropping its official `lucide-static` SVG into `views/icons/`.
  No icon font, no remote sprite, no hand-authored paths.
- **Machine data:** wrap every IP/MAC/CIDR/VLAN/Option-82 id in `.mono` (or a `<td>`
  using the mono cell rule). Never render machine data in the sans face.
- **Stable region ids:** any element a live fragment targets has a fixed id (§9
  list). A partial component renders both the page slot and the SSE fragment.
- **CSRF:** the session token is in `<meta name="csrf-token">` and on `PageData`.
  Authenticated Datastar actions carry it (`X-CSRF-Token` header or the `csrf_token`
  form field); the server validates exactly as before. Login is CSRF-exempt
  (no session yet; SameSite=Strict cookie is the mitigation).
- **No inline `style=`** except genuinely dynamic values (e.g. a meter width
  percentage). Everything else is a class.
- **View models** live in `package views` and import nothing from `internal/web`
  (dependency points web → views only).
- **Datastar syntax (v1.0.2 - wrong form fails SILENTLY):** keyed plugins use a
  **COLON**, not a hyphen: `data-on:click`, `data-on:submit`,
  `data-on:input__debounce.300ms`, `data-attr:type`, `data-attr:disabled`,
  `data-class:active`, `data-indicator:busy`. `data-on-click` (hyphen) is read as
  a nonexistent plugin and ignored. No-key plugins take a value/object:
  `data-bind="pw"`, `data-signals="{…}"`, `data-show="$x"`, `data-text="$x"`,
  `data-style="{width: …}"`, `data-class="{met: $x}"`. Call page globals as
  `window.fn(...)`. Mirrored in the `datastar-v1-syntax-gotchas` memory.

## 12. Anti-patterns / gates

Forbidden (the old "poppy, AI-generated" look): **heavy glassmorphism on content
surfaces**, gradients, **neon glow** / colored box-shadow, gradient or purple
text, color-only status, hard-coded hex outside the token block, and **any remote
asset**. (Allowed and on-brand: subtle elevation shadows on cards/overlays, and a
light backdrop blur on the sticky header + dialog backdrop only.)

Pre-merge greps (should be empty / near-empty):
```
# remote assets (the embedded Lucide SVGs' xmlns="http://www.w3.org/..." is a
# namespace identifier, never fetched - exclude it):
grep -rn 'https://\|http://\|//fonts\|cdn\.\|@import\|googleapis' internal/web/views internal/web/static/style.css | grep -v w3.org
grep -rn 'style="' internal/web/views --include='*.templ'   # only dynamic values (meter width, etc.) allowed
grep -rn 'blur(\|gradient\|box-shadow.*glow\|text-shadow' internal/web/static/style.css
# Datastar keyed plugins written with a hyphen instead of a colon (must be empty):
grep -rnE 'data-(on|attr|class|bind|indicator|ref|computed)-[a-z]' internal/web/views --include='*.templ'
```

Verification per phase: `templ generate && go build -mod=vendor . && go vet
-mod=vendor ./... && go test -mod=vendor ./...`. The appliance binary is **never
run on the dev machine**; live/browser/Pi checks are flagged for the operator.
