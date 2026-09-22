# btc-intel web

The investigator console: alert triage, case detail and link analysis over the
`api/` backend. React + TypeScript + Vite, no UI framework, no CSS framework,
nothing fetched from the network at runtime.

```sh
npm install
npm run dev        # http://localhost:5173
```

The dev server expects the API at `http://127.0.0.1:8000`:

```sh
cd ..
.venv/bin/python -m uvicorn api.app:app --host 127.0.0.1 --port 8000
```

If there is nothing to look at yet, produce a case first:

```sh
python -m generator.main --n-actors 200 --n-transactions 1200 --output data/raw --formats csv
python -m ingest.pipeline
python -m fusion.pipeline
```

## Environment

| variable | default | meaning |
| --- | --- | --- |
| `VITE_API_BASE` | empty — same origin | Where the API lives. Production serves `web/dist` and the API from one origin, so the default is correct there and nothing needs setting. |

In development the API runs on another port *and* its paths (`/alerts`,
`/entities`) are also the console's own routes, so `.env.development` sets
`VITE_API_BASE=/api` and `vite.config.ts` proxies that prefix to the backend,
stripping it on the way through. Copy `.env.example` to `.env.local` to point a
build somewhere else.

## Build

```sh
npm run build          # -> web/dist, static
npm run preview        # serve the build locally
npm run check:offline  # fails if dist would fetch anything external
npm run check:contrast # WCAG AA check over the design tokens
npm test               # vitest
```

`npm run build` writes a plain static `dist/` — `index.html`, hashed JS/CSS and
locally bundled fonts. Serve it from FastAPI, nginx, or a USB stick; there is
no server-side rendering and no runtime configuration to inject.

Current size: **95 KB gzipped** for the initial load, plus a **176 KB gzipped**
graph chunk that loads only when a case page is opened.

## Layout

```
src/
  api/          client.ts, types.ts — every call the console makes, typed
  lib/          risk, formatting, theme, motion primitives, token reads
  components/   shell, table, graph, leads, small shared pieces
  pages/        Home, Alerts, Entity, Transaction
  styles/       tokens.css (the design system), base.css (the components)
  test/         setup, fixtures, console.test.tsx
```

`styles/tokens.css` is the source of truth for colour, type, spacing and
motion; it is documented in `docs/design/design_analysis.md`. Nothing outside
that file invents a colour or a duration.

## Things worth knowing before changing it

- **Risk is never colour alone.** Every score is drawn as braille cells + the
  number + the word (`⣿⣿⣿⣤⠂⠂⠂⠂ 0.44 medium`). It survives greyscale, printing
  and copy-paste into a case note. If you add a risk surface, keep all three.
- **Leads are not reasons.** IP correlation lives in its own panel, on its own
  surface, worded "associated with". It must not migrate into the evidence or
  the risk explanation — that is the product's central claim about what it does
  and does not assert. There is a test for it.
- **The field is a place, not a theme.** The graph and the home header stay dark
  in both light and dark themes.
- **Motion never gates data.** Every animation is transform/opacity only and the
  content is interactive throughout. `prefers-reduced-motion` turns all of it
  off, including the ambient canvas. See `docs/design/motion_spec.md`.
- **Offline is a requirement, not a preference.** No CDN links, no Google
  Fonts, no remote images. `npm run check:offline` enforces it after a build.
