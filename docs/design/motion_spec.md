# Motion spec

Every animation in `web/`, what triggers it, and what it does when the reader
has asked for less motion.

Three rules the whole list obeys:

1. **Only `transform` and `opacity` animate.** Nothing else touches layout.
2. **Motion never gates data.** No component waits for an animation before
   rendering, and no surface is inert while one runs. The table can be clicked
   mid-FLIP, the graph can be dragged while nodes are still fading in.
3. **`prefers-reduced-motion: reduce` removes it**, not shortens it. The media
   query zeroes the duration tokens (`tokens.css`), a global rule clamps every
   CSS transition and animation to 0.001ms, the scripted animations check
   `reducedMotion()` before starting, and the ambient canvas never opens a
   frame loop at all.

Tokens: `--dur-1 150ms`, `--dur-2 200ms`, `--dur-3 280ms`, `--dur-4 400ms`,
`--stagger 40ms`, `--ease-out cubic-bezier(.22, 1, .36, 1)`,
`--ease-standard cubic-bezier(.4, 0, .2, 1)`.

| # | Animation | Trigger | Duration / easing | Reduced motion |
| --- | --- | --- | --- | --- |
| 1 | **Route crossfade** — the whole view cross-dissolves | any in-app navigation (`<Link viewTransition>`) | 280ms `ease-out`, via the View Transitions API (`@view-transition` in `base.css`) | `navigation: none` — the page simply swaps |
| 2 | **Shared element: entity id** — the queue row's id morphs into the case page's heading | clicking a row's entity link | handled by the same view transition; `view-transition-name: entity-<id>` on both | no transition; heading appears in place |
| 3 | **Shared element: risk score** — the row's meter morphs into the case gauge's position | same as 2 | same transition; `view-transition-name: score-<id>` | as above |
| 4 | **Section entrance** — each page's sections fade up 10px, staggered | first mount of a page (`useEnter(index)`) | 400ms `ease-out`, `index × 40ms` delay, `fill: backwards` | not started; sections render in final state |
| 5 | **Stat count-up** — a numeral counts from 0 to its value | stat block mounts (`useCountUp`) | 400ms, cubic ease-out, rAF | value set immediately |
| 6 | **Gauge arc draw** — the risk arc sweeps from 0 to the score | case page mounts | 400ms `ease-out` on `stroke-dasharray` | arc rendered at full length |
| 7 | **Chart bars grow** — pattern bars scale in from the left | overview mounts | 400ms `ease-out`, 40ms stagger, `transform: scaleX` | drawn at full width |
| 8 | **Row hover** — background tints to `--evidence-w7` | pointer or focus within a row | 200ms `ease-out`, colour only, **no movement** | instant tint |
| 9 | **Table FLIP** — rows slide from their old position to their new one | sort or filter change (`AlertTable`'s layout effect) | 280ms `ease-out` on `translateY` | rows appear in the new order |
| 10 | **Verdict settle** — the confirm/reject buttons are replaced by a status chip and the row dims to 55% | a verdict is recorded | 150ms `ease-out` on opacity | instant swap |
| 11 | **Toast** — a confirmation slides into the corner | a verdict recorded, a report started | appears/disappears with the CSS transition tokens; auto-dismisses after 3.2s | appears and disappears instantly; the 3.2s life is unchanged |
| 12 | **Skeleton shimmer** — a gradient sweeps a loading placeholder | any pending request | 1.4s linear, infinite | the global reduce rule stops the animation; the placeholder stays |
| 13 | **Graph node entrance** — nodes fade in, 8ms apart | first layout of a graph | 260ms per node | nodes drawn opaque immediately |
| 14 | **Graph layout** — cose/dagre animate to their final positions | mount, hop-count change, switching to the propagation tree | 300ms, Cytoscape's own easing | `animate: false`; the layout is applied in one step |
| 15 | **Graph hover dim** — everything that is not a neighbour drops to 12% opacity | hovering a node | 200ms, opacity only | Cytoscape's transition is still declared but the dim is instant enough to be unnoticeable; the state itself is kept, because it is information, not decoration |
| 16 | **Marching ants** — the taint path's dashes flow along the edge | a graph containing a taint path | `line-dash-offset` stepped every 90ms | loop never starts; the taint path stays dashed and still |
| 17 | **Ambient field** — the home header's dither grid drifts | overview page visible and tab focused | redrawn at 8fps, paused off-screen (IntersectionObserver) and when `document.hidden` | never starts; one static frame is drawn |
| 18 | **Command palette** — the dialog fades in over a dimmed page | ⌘/Ctrl-K | native `<dialog>` + backdrop, CSS-transitioned | instant |
| 19 | **Sub-nav marker** — the active anchor's rule extends from 8px to 20px | the reader scrolls into a section | 200ms `ease-out` on `width` | instant |
| 20 | **Button press/hover** — background and colour shift | pointer | 200ms `ease-out`, colour only | instant |

## What is deliberately not animated

- **Numbers in the table.** A score that animates while being read is a score
  being misread.
- **Filtering.** Rows leave immediately; only surviving rows animate their
  position (9).
- **Anything on the error and degraded-mode notices.** A warning that fades in
  is a warning that can be missed.
- **Page scroll.** No smooth-scroll hijacking; the browser's own behaviour is
  left alone, and `scroll-behavior` is set to `auto` under reduced motion.

## No animation library

The two effects that need scripting — the table FLIP and the count-up — are a
dozen lines each on the Web Animations API (`lib/motion.ts`). Everything else is
CSS or the View Transitions API. `motion` was allowed by the brief for layout
animation; it was not added because nothing here needed more than what the
platform already does, and the console has a bundle budget to keep.

## Verification

`src/test/console.test.tsx` asserts that the ambient field does not open a frame
loop under `prefers-reduced-motion: reduce`, and that it does otherwise. The
rest is enforced structurally: `reducedMotion()` guards every scripted
animation, and the global CSS rule catches anything declarative that is added
later.
