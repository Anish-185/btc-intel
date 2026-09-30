# Assets and credits

Everything the console draws, it draws itself, with one exception: the dot
pictures on the home page and the stage banners are traced from reference
images (below). There are no icon sets and no remote assets of any kind.

## Fonts

| family | licence | source | how it ships |
| --- | --- | --- | --- |
| IBM Plex Sans | SIL Open Font License 1.1 | `@fontsource/ibm-plex-sans` | bundled into `dist/assets/` at build time |
| IBM Plex Mono | SIL Open Font License 1.1 | `@fontsource/ibm-plex-mono` | bundled into `dist/assets/` at build time |
| Inter Tight | SIL Open Font License 1.1 | `@fontsource-variable/inter-tight` | bundled into `dist/assets/` at build time; headings only |

No `<link>` to Google Fonts or any other CDN. The OFL text ships inside the
npm packages under `node_modules/@fontsource/*/LICENSE`.

Substitution note: the design language is inspired by supermemory.ai, which
sets Geist / Geist Mono. We use IBM Plex instead — see
`docs/design/design_analysis.md` for why. None of supermemory's name, wordmark,
copy, icons, illustrations or code is used here.

## Imagery

| what | how it is made |
| --- | --- |
| Ambient header field | drawn procedurally on a `<canvas>` in `src/components/AmbientField.tsx` — a value-noise dither grid with a few marked cells. No image file. |
| Dot pictures (`public/art/*.png`) | small greyscale ink maps made by `scripts/build-art.sh` from the team's reference sheet (`~/front`), then drawn as dots, squares or hex glyphs by `src/components/DotArt.tsx`. Sources: two images the team generated (the Ashoka capital, used for `capital.png`, and a botanical sheet, unused), and several collected from Pinterest-style boards (hands, fingerprint, footprint, networks, globes, clouds, dotted map, pixel flower, binary rain). The team has confirmed these may be used in this project. To swap any of them, run the script on a directory with the same file names. |
| Wordmark | a CSS `clip-path` polygon in `styles/base.css`. |
| Favicon | an inline SVG data URI in `index.html`. |
| Risk meters | Braille Patterns characters (U+2800…U+28FF) set in IBM Plex Mono. |
| Risk gauge | inline SVG, drawn in `src/components/Gauge.tsx`. |
| Pattern chart | plain `div`s and CSS, in `src/pages/Case.tsx`. |
| Link-analysis graph | Cytoscape.js canvas rendering of data from our own API. |

## Third-party code

| package | licence |
| --- | --- |
| react, react-dom | MIT |
| react-router-dom | MIT |
| cytoscape | MIT |
| cytoscape-dagre, dagre | MIT |
| vite, @vitejs/plugin-react | MIT |
| vitest, @testing-library/* | MIT |

## Reference material (not shipped)

`docs/design/screens/` holds screenshots of supermemory.ai taken while writing
the design analysis. They are reference for that document only: they are not
imported by the app, not in `dist/`, and nothing from them is reproduced in the
product.
