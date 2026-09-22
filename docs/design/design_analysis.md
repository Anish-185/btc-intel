# btc-intel — design analysis (Stage 1)

What the investigator console should look like, and where every decision came
from. Nothing here is built yet: this document and `web/src/styles/tokens.css`
are the whole of Stage 1.

Sources studied:

- **A.** supermemory.ai — `/`, `/product`, `/research`, `/blog`, inspected live
  in the browser with computed styles read out of the page.
- **B.** the reference images in `~/front/`.
- **C.** the earlier ideathon frontend (`~/ideathon-split/sideeffect2cure/frontend`),
  for design patterns only.

Screenshots taken for reference live in `docs/design/screens/`. They are
reference material for this analysis, not assets: nothing from them ships in
`web/`.

---

## A. supermemory.ai

### A.1 What the site actually is

A research-paper layout wearing a product site's clothes. A fixed left rail
holds a lowercase wordmark, a plain vertical nav and an **"ON THIS PAGE"**
anchor list whose active item is marked with a short blue rule. To its right,
one 640px column of prose, figures, tables and stat panels on white. No cards
with shadows, no gradients as decoration, no hero illustration. Colour appears
in exactly three places: the accent blue, the duotone media block, and the
tinted "ours" column in a benchmark table.

The tone is *measured*: it shows numbers with their units and their method
underneath ("DATASET / RETRIEVAL / JUDGE"), and it writes "Figure 1." captions.
That is the part worth taking for a forensics console, where an unhedged number
is a liability.

### A.2 Type

One superfamily, two roles. **Geist** for prose, **Geist Mono** for every piece
of data, label and code. The split is the site's strongest single idea: if a
thing is measured, it is set in mono.

Computed values read off the live pages:

| role | family | size | weight | line-height | letter-spacing |
| --- | --- | --- | --- | --- | --- |
| h1 / statement | Geist | 40px | 400 | 44.8px (1.12) | −1.2px (−0.03em) |
| h2 | Geist | 28px | 400 | 33.6px (1.2) | −0.7px |
| h3 | Geist | 17px | 500 | 22.1px (1.3) | 0 |
| body | Geist | 16px | 400 | 1.65 | 0 |
| stat numeral | Geist **Mono** | 44px | 400 | 1.0 | −2.64px (−0.06em) |
| table head | Geist Mono | 10px | 500 | — | +0.4px, uppercase |
| table cell | Geist Mono | 14px | 600 | — | tabular-nums, right-aligned |

Headings are **regular weight, not bold** — the hierarchy is carried by size and
negative tracking. Body measure is capped at 600px (`--measure-body`), the
column at 640px (`--col-w`), the left rail 208px with a 108px gutter.

### A.3 Colour

Their tokens, verbatim from `:root`:

```
--paper #f4f4f6   --warm #fafafa    --warmwhite #fffbf5
--ink   #0b1015   --ink-86 #0b1015db --ink-68 #0b1015ad --ink-60 #0b101599 --ink-45 #0b101573
--rule  #dfdfdf
--blue  #0562ef   --blue-deep #0450c8 --blue-press #033a9a --on-blue #f4f8ff
--blue-7 #0562ef12 --blue-11 #0562ef1c   (7% / 11% washes)
--live  #00c763   --tick #9ec6f7   --link-start #0042af  --link-frame #0562ef66
```

Four observations that matter more than the hex values:

1. **Text is one ink at four alphas**, not four greys. Everything stays in the
   same colour family as the page darkens.
2. **One accent with a job.** Blue means "interactive or ours". It is never
   decorative, and never means severity — they have no severity scale.
3. **The washes are how emphasis is done.** `blue-7` behind a table column is
   the entire "this is our result" treatment.
4. **There is no dark theme.** The only dark surface on the site is the duotone
   media block. So the dark field our brief asks for has no precedent to copy —
   we build it ourselves (see §B).

### A.4 Layout, borders, radius

- Left rail 208px, gutter 108px, content column 640px, full panel width ~600px
  beyond the measure for figures and tables.
- Hairlines everywhere: **0.625px** computed (a sub-pixel hairline), `#dfdfdf`.
  Dotted rules separate the nav from the anchor list.
- **Radius is effectively zero.** Buttons, panels, tables, chips — all square.
  The only rounded things are the blog's tag pills.
- Spacing is a named set, not a scale: `--sp-section 64`, `--sp-para 24`,
  `--sp-col-top 56`, `--sp-rule-head 28`, `--sp-head-content 18`,
  `--sp-beat-para 14`. Everything lands on 2px multiples; most on 4.

### A.5 Component patterns worth taking

- **Stat block** — small sans title, mono uppercase sub-label
  ("PER QUERY, ON PRODUCTION TRAFFIC"), then a 44px mono numeral with the unit
  set small and muted beside it: `187`+`ms`, `1T`+`+`, `100k`+`+`, `#1`. The
  unit never shares the numeral's size.
- **Compact numeric table** — mono uppercase heads at 10px; a muted two/three
  letter code in a left gutter (`SSU`, `SSA`, `KU`); label column left, all
  numbers right with tabular figures; the column being argued for gets a 7%
  blue wash; a footer strip of small labelled cells stating dataset, retrieval
  and judge. This is the template for our alert queue.
- **Buttons** — primary is solid blue with a mono uppercase tracked label and a
  separate leading icon cell. Secondary is a pale blue-tinted rectangle with
  **corner tick marks** instead of a full border, and a trailing `↗`.
- **Links** carry `↗` for external and `→` for internal-forward; inline
  reference markers are small boxed superscripts.
- **Section eyebrow** — mono uppercase, muted, above the statement.
- **Figure panel** — dotted-grid background, diagram, then
  *"Figure 1. Raw data enters…"* caption in muted small text.
- **Anchor sub-nav** with a blue rule on the active item and tiny tick marks for
  the rest.
- **Blockquote** — left blue rule, prose with bolded numbers, attribution line.

### A.6 Motion

The site runs **Astro view transitions** (`astro-view-transitions-enabled`), so
navigation crossfades rather than repaints. Its own tokens:

```
--dur-press .12s  --dur-hover .2s  --dur-cta .36s  --dur-link .4s  --dur-reveal .9s
--ease          cubic-bezier(.2, 0, 0, 1)
--ease-out      cubic-bezier(.22, 1, .36, 1)
--ease-hover    cubic-bezier(.25, .1, .25, 1)
--ease-standard cubic-bezier(.4, 0, .2, 1)
--ease-cta      cubic-bezier(.23, 1, .32, 1)
--spring-36     linear(…)   /* a sampled spring for one CTA */
```

Reveal-on-scroll is a `.block` → `.block.is-visible` class flip animating
**opacity and translate only**, 0.3s on `ease-standard`. Below-fold content sits
at low opacity until it enters. Hover states are colour-only; nothing moves.

The brief's `cubic-bezier(0.22, 1, 0.36, 1)` is exactly their `--ease-out`, so
our motion tokens and theirs agree already.

### A.7 Character, in one line

Editorial restraint: lowercase wordmark, one ink, one accent, square corners,
hairlines, mono for anything measured, and whitespace doing the work that
borders would do elsewhere.

---

## B. The reference images in `~/front/`

| image | what it contributes |
| --- | --- |
| `Pasted image.png` — dot-matrix world map, white on black | The **ambient field**: a procedural dot/dither grid on a dark ground. Our IP-origin story is geographic; this is the honest way to render it without a map library. |
| `_ (1).jpeg` — dithered blue sky, hairline grid, one red cell | The single most useful reference. A quiet field of noise with **one cell marked in red** is exactly "one anomaly in ordinary traffic". Sets the ambient header *and* the rule that red appears once. |
| `Found on Cosmos.jpeg` — white halftone flower on a blue grid | Halftone/ASCII texture as image. Confirms: texture comes from glyphs and grids, never from photographs. |
| `_ (2).jpeg`, `_ (4).jpeg` — globes built from circled glyphs | **Braille/ASCII art as data visual.** Directly informs the braille risk meter and the ASCII field: characters as pixels. |
| `_ (3).jpeg` — white figures linked by lines on blue | The link-analysis graph as a *flat, high-contrast field*. Nodes are glyphs, edges are hairlines, no depth, no glow. |
| `Réseaux.jpeg` — blue node-link hairball on white | A warning, not a model: an unfiltered graph is unreadable. Our graph must cap nodes, dim non-neighbours and default to a small hop radius. |
| `_.jpeg` — fingerprint; `pressure print.jpeg` — inked footprint on grid | The **forensic register**: evidence is a trace on a grid, printed, dense, monochrome. Justifies the lab-notebook tone over a "security dashboard" tone. |
| `Timeless and powerful.jpeg` — dithered hands on klein blue | Blue as a full-bleed ground with white dither. Our dark field panel's temperature. |
| `screenshot-2026-09-08_12-23-02.png` — older supermemory home | The **numeral-ASCII band**: digits 0–9 as halftone across a blue band. Also a dotted page frame and a `$ npx …` command pill. |
| `screenshot-2026-09-08_17-01-14/17-38-12.png` — hero media | The memory-graph-on-a-field the brief describes: duotone blue ground, **warm amber tiles** linked by faint hairlines. Amber against blue is the contrast pair we reuse for risk. |
| `screenshot-2026-09-22_17-15-16.png` — blue isometric bust | Not used. A mascot illustration is the one thing a forensics console should not have. |
| `Poplr Inc_ - Allan Revah.gif`, `technology wallpaper.jpeg`, `Home _ X.jpeg` | General motion/texture mood; nothing specific taken. |

### Conflicts between B and A, and how they resolve

1. **Dark, saturated fields (B) vs. an all-light page (A).**
   Resolution: the page is light like A; the **graph and the home header are
   dark field panels** like B. The field is a *place*, not a theme — it means
   "this is network space, not document space", and it stays dark in both
   themes, as the brief asks.

2. **Photographic duotone (B) vs. no external assets (hard rules).**
   Resolution: every field is **drawn procedurally** — canvas dither, SVG
   glyph grids, braille characters. No photos ship. This also keeps the bundle
   small and the app offline.

3. **Saturated klein blue everywhere (B) vs. one restrained accent (A).**
   Resolution: A wins for the interface. The saturated blue is confined to the
   dark field panels, where it is the ground rather than an accent.

4. **Amber as a highlight (B) vs. blue-only emphasis (A).**
   Resolution: amber is promoted to a **meaning**, not a highlight — it is the
   middle of the risk ramp and the caution marker. Nothing warm appears except
   to signal risk or caution.

5. **The hairball (`Réseaux`) vs. legibility.**
   Resolution: hop radius defaults to 2, node cap with a visible "+N more",
   non-neighbours dim on hover.

---

## C. The earlier ideathon frontend

Located at `~/ideathon-split/sideeffect2cure/frontend`. Note: **two candidate
folders exist** — `~/ideathon` and `~/ideathon-split`. They are byte-identical
in `frontend/src` and sit on the same commit (`e76e221`), so no choice was
needed; `~/ideathon-split` was read. There is no `~/ideathon-frontend`.

Taken (design only):

- **`.frame--railed`** — full-height hairline rails drawn as pseudo-elements so
  they never join the layout. This is how a column becomes a physical object.
- **`.label`** — mono, 11px, 500, `letter-spacing: .16em`, uppercase, faint.
- **`.bracket`** — corner tick marks drawn as eight tiny gradients on one
  element. Reproduces A's secondary-button frame with no extra DOM.
- **`.btn`** — mono uppercase tracked labels; colour-only hover; 180ms.
- **`.digit-art`** — a numeral texture band: mono at 8px, `line-height: .72`,
  `white-space: pre`, masked so it fades out rather than ending on an edge.
- **`.tabular`**, **`.id-chip`** — tabular figures; a sunk mono chip for ids.
- **`.reveal` / `.is-in`** — opacity + 18px translate, 700ms, staggered by
  80ms, with a `prefers-reduced-motion` block that zeroes all of it.
- **Graph node look** — a node is a *labelled plate*, not a bubble; dimming is
  `opacity: .16` so the graph's shape survives; a traced node gets an accent
  border and a soft ring.
- **`.fade-mask-*`** — mask-image gradients to fade a field into the page.

Explicitly **not** taken: its Tailwind v4 dependency and `@theme` block, its
routes, API layer, state, copy, colour values and domain vocabulary. We keep
plain CSS custom properties instead of Tailwind — the brief asks for a
`tokens.css`, and a console this size does not need a utility framework.

---

## btc-intel design system

### The brief in one paragraph

btc-intel is an **offline case console for a Bitcoin forensics analyst**. Its
job is triage: which cases deserve the next hour, what the evidence for each
actually says, and what an analyst may and may not conclude from it. The
product's ethical spine — *leads are not attributions* — has to be visible in
the design, not just in the copy. So: evidence blue and attribution amber never
touch; the leads section is a different surface from the reasons; and every
confidence claim carries its own qualifier.

### Where we deliberately differ from supermemory

| axis | supermemory | btc-intel | why |
| --- | --- | --- | --- |
| accent | `#0562ef` bright cyan-blue | `#1b44d8` deeper cobalt-indigo | Their blue is their identity; ours is a different value with a different job, and it holds AA on white at small mono sizes. |
| accent's meaning | brand + interactive + "ours" | **evidence and interaction only** — never severity | A forensic console needs a severity language the brand colour must not pollute. |
| severity | none | a four-step risk ramp, each step with a label and a braille glyph | Colour alone cannot carry a legal judgement. |
| themes | light only | light **and** dark, plus a field surface that is dark in both | Analysts work night shifts; the graph reads better on a field. |
| typeface | Geist / Geist Mono | IBM Plex Sans / IBM Plex Mono | Same two-role logic, our own voice. See fonts below. |
| density | essay | console: 15px body, 34px row, 8px cell padding | Different job. |

### Fonts

**IBM Plex Sans** and **IBM Plex Mono**, SIL Open Font License 1.1, bundled
locally via `@fontsource/ibm-plex-sans` and `@fontsource/ibm-plex-mono` — no
Google Fonts, no CDN links, per the hard rules.

Substitution note: supermemory uses **Geist / Geist Mono**, which is itself
OFL-licensed and could have been used legally. We chose not to — using the
reference's exact typeface is the difference between inspired-by and
indistinguishable-from. Plex is the closest open family with the right
character for the job: a neo-grotesk with slightly humanist detailing, drawn by
IBM for technical documentation, with a mono cut that has genuinely good
tabular figures and covers the Braille Patterns block we lean on. Weights
bundled: sans 400/500/600, mono 400/500/600, plus mono italic for figure
captions and units.

### Colour tokens

Ink is one colour at four alphas, as on the reference site. Every pair below is
checked for WCAG AA (≥4.5:1 body, ≥3:1 for ≥18.66px/bold and for UI edges); the
check script lives beside the tokens and every pair passes; the alphas and
the dark hairline above are the values that check pushed us to, not the ones
first written.

**Light**

```
--paper        #f4f5f7    page ground
--surface      #ffffff    panels, table bodies
--sunk         #ecedf1    chips, wells, table head
--field        #070b18    dark panels — same in both themes
--ink          #0b1016    primary text
--ink-soft     #0b1016b8  secondary prose             (72%)
--ink-muted    #0b10169e  labels, units               (62%)
--ink-faint    #0b10167a  disabled, tick marks        (48%)
--rule         #dcdfe6    hairlines
--rule-soft    #e9ebf0    inner hairlines
--evidence     #1b44d8    accent: links, focus, "ours"
--evidence-hi  #2b56f0    hover
--evidence-lo  #142f9e    press
--evidence-w7  #1b44d812  7% wash
--evidence-w12 #1b44d81f  12% wash
--on-evidence  #f5f7ff    text on the accent
```

**Dark**

```
--paper        #0a0e17   --surface   #111723   --sunk #070b12   --field #05080f
--ink          #e9edf5   --ink-soft  #e9edf5c4 --ink-muted #e9edf58f --ink-faint #e9edf55c
--rule         #252e3e   --rule-soft #1a2230
--evidence     #7e9dff   --evidence-hi #9db4ff --evidence-lo #5c7ff0
--evidence-w7  #7e9dff14 --evidence-w12 #7e9dff24  --on-evidence #061026
```

### The risk scale

Four levels, thresholds from `config.yaml`'s `thresholds` block (low < 0.3,
medium < 0.6, high < 0.8, critical ≥ 0.8). **Never colour alone**: every risk
appears as `glyph + LABEL + number`, and the meter itself is drawn in braille
characters, so it survives greyscale, colour-blindness and a printed PDF.

| level | glyph | label | light text / chip | dark text / chip |
| --- | --- | --- | --- | --- |
| low | `⠂` | LOW | `#3d4d63` on `#eceef3` | `#9aa8bf` on `#151c28` |
| medium | `⠶` | MEDIUM | `#845200` on `#faf0da` | `#e3b25c` on `#241c0d` |
| high | `⣤` | HIGH | `#ad3f1a` on `#fbe9df` | `#ff8f61` on `#2a150e` |
| critical | `⣿` | CRITICAL | `#8e1426` on `#fadde1` | `#ff7186` on `#2b1017` |

The meter is eight braille cells filled proportionally
(`⣿⣿⣿⣤⠂⠂⠂⠂` = 0.44), set in Plex Mono at the row's font size, coloured by
level, with the numeric score beside it in tabular figures. It reads as a bar,
copies as text, and needs no SVG.

### Other semantic colours

- **confirmed** `#186b45` light / `#5fc794` dark — an analyst's verdict, not a
  severity.
- **false positive** uses `--ink-muted`: dismissing an alert is not an alarm.
- **caution** (`low_confidence_origin`) `#845200` / `#e3b25c` with a `⚠` glyph
  and the words "low confidence" — the same amber as medium risk, because it
  means the same thing: *do not lean on this*.
- **Graph node families** — wallet `#7e9dff`, transaction `#97a3b8`, IP
  `#e3b25c`, taint path `#ff8f61`. Declared once, not per theme: they sit on
  `--field`, which does not change when the page does.
- **IP class badges are categories, not severities**, so they stay neutral: a
  sunk chip, mono, with a two-letter code and the full name —
  `RS residential`, `TX tor exit`, `HV hosting/vpn`, `RL relay`. Only
  "anonymized entry point" adds the caution outline.

### Type scale

| token | size / line-height | family | use |
| --- | --- | --- | --- |
| `--fs-display` | 34 / 1.12, −0.02em | sans 400 | page statement |
| `--fs-h1` | 26 / 1.2, −0.015em | sans 400 | page title |
| `--fs-h2` | 20 / 1.3 | sans 500 | section |
| `--fs-h3` | 16 / 1.4 | sans 600 | panel title |
| `--fs-body` | 15 / 1.6 | sans 400 | prose, reasons |
| `--fs-small` | 13 / 1.5 | sans 400 | secondary prose |
| `--fs-data` | 13 / 1.4 | mono 500, tabular | table cells, scores |
| `--fs-label` | 10.5 / 1.2, +0.12em, uppercase | mono 500 | column heads, eyebrows |
| `--fs-stat` | 44 / 1.0, −0.04em | mono 400 | stat numerals |
| `--fs-stat-lg` | 64 / 1.0, −0.045em | mono 400 | home header figure |

Reading measure 640px; console content max 1160px; left rail 208px.

### Spacing, radius, borders, elevation

- Space scale on a 4px base: `2 4 8 12 16 24 32 48 64 96`.
- Radius: `0` for data surfaces (tables, chips, the field panel edge), `2px`
  for buttons, inputs and toasts. Nothing larger. Square is the house style.
- Borders: `1px` hairline `--rule`; `1.5px` `--evidence` for an active or
  traced element; `--rule-soft` for hairlines inside a panel.
- Elevation: **no drop shadows in light.** Depth is hairlines and the sunk
  surface. The command palette and toasts get one soft shadow because they
  float over the page; the dark field gets an inset hairline ring instead.

### Motion tokens

```
--dur-1 150ms  press, chip swaps
--dur-2 200ms  hover, dim
--dur-3 280ms  route crossfade, sort FLIP
--dur-4 400ms  gauge draw, count-up, field entrance
--stagger 40ms
--ease-out      cubic-bezier(.22, 1, .36, 1)   default
--ease-standard cubic-bezier(.4, 0, .2, 1)     layout
--ease-exit     cubic-bezier(.4, 0, 1, 1)
```

Only `transform` and `opacity` animate. `prefers-reduced-motion: reduce` zeroes
every duration, cancels the ambient field and the marching-ants dashes, and
makes state changes instant. Full per-animation table comes in Stage 3's
`motion_spec.md`.

### Component inventory

**Shell** — left rail (wordmark `btc-intel`, nav, "ON THIS PAGE" anchor list),
content column, theme toggle, command palette (⌘/Ctrl-K), toast stack.

**Data** — stat block; braille risk meter; alert table (sticky mono head, 34px
rows, tabular figures, left gutter code, keyboard rows); sort control; filter
bar (min-score, pattern type); pattern-type bar chart (hand-rolled SVG);
degraded-mode notice; skeleton shimmer.

**Case** — entity header (id chip + risk gauge); reason prose; evidence list
(txid / wallet / IP rows, each copyable); **investigative leads panel** (visibly
separate surface: sunk ground, its own heading, IP class badge, confidence,
caution marker, and the words "associated with"); taint path strip; graph field
panel; "Show propagation" action on transaction nodes; export-PDF button.

**Primitives** — button (primary solid / ghost with corner ticks / quiet);
chip; id chip; badge; segmented control; figure caption; footnote marker;
hairline rule; rails; ASCII/braille field (canvas).

### The one bold thing

Everything above is deliberately quiet so that a single idea can carry the
product's character: **evidence rendered as characters**. Risk meters in braille
cells, the home header as a procedural ASCII/dither field with one anomalous
cell burning amber, taint paths as `⟶` chains of mono id chips. It is cheap to
draw, it prints, it copies into a case note as text, and no other forensics
dashboard looks like it.

---

## Stage 1 deliverables

- `docs/design/design_analysis.md` — this file.
- `docs/design/screens/` — six annotated reference captures from source A.
- `web/src/styles/tokens.css` — every token above, light and dark, plus the
  risk scale and motion tokens.
- `web/src/styles/contrast-check.mjs` — the WCAG check for every token pair,
  run with `node contrast-check.mjs`.
