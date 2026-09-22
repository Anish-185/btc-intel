/**
 * WCAG contrast check for tokens.css.  node contrast-check.mjs
 *
 * Reads the token values straight out of the stylesheet, so it fails if a
 * colour is edited there and not re-checked. Alpha inks are composited over
 * their theme's surface before measuring, which is what the eye sees.
 *
 * AA thresholds: 4.5 for body text, 3.0 for >=18.66px or bold text and for
 * non-text edges (borders, focus rings, chart marks).
 */
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

const css = readFileSync(new URL("./tokens.css", import.meta.url), "utf8");

/** Token values from one block of the stylesheet. */
function block(selector) {
  const start = css.indexOf(selector);
  if (start < 0) throw new Error(`no block for ${selector}`);
  const open = css.indexOf("{", start);
  const body = css.slice(open + 1, css.indexOf("\n}", open));
  const out = {};
  for (const [, name, value] of body.matchAll(/(--[\w-]+):\s*([^;]+);/g)) {
    out[name] = value.trim();
  }
  return out;
}

const light = block(":root {");
const dark = { ...light, ...block('[data-theme="dark"] {') };

const hex = (value) => {
  const m = /^#([0-9a-f]{6})([0-9a-f]{2})?$/i.exec(value);
  if (!m) return null;
  const n = parseInt(m[1], 16);
  return [n >> 16, (n >> 8) & 255, n & 255, m[2] ? parseInt(m[2], 16) / 255 : 1];
};

const resolve = (theme, token) => {
  let value = theme[token] ?? token;
  while (value.startsWith("var(")) value = theme[value.slice(4, -1)];
  const rgba = hex(value);
  if (!rgba) throw new Error(`not a colour: ${token} = ${value}`);
  return rgba;
};

const over = ([r, g, b, a], [br, bg, bb]) => [
  r * a + br * (1 - a),
  g * a + bg * (1 - a),
  b * a + bb * (1 - a),
  1,
];

const luminance = ([r, g, b]) =>
  [r, g, b]
    .map((c) => c / 255)
    .map((c) => (c <= 0.03928 ? c / 12.92 : ((c + 0.055) / 1.055) ** 2.4))
    .reduce((sum, c, i) => sum + c * [0.2126, 0.7152, 0.0722][i], 0);

const ratio = (fg, bg) => {
  const [a, b] = [luminance(fg), luminance(bg)].sort((x, y) => y - x);
  return (a + 0.05) / (b + 0.05);
};

/** [foreground, background, minimum, what it is] */
const PAIRS = [
  ["--ink", "--paper", 4.5, "body on page"],
  ["--ink", "--surface", 4.5, "body on panel"],
  ["--ink", "--sunk", 4.5, "body on well"],
  ["--ink-soft", "--surface", 4.5, "secondary prose"],
  ["--ink-muted", "--surface", 4.5, "labels, units"],
  ["--ink-muted", "--sunk", 4.5, "labels in a well"],
  ["--ink-faint", "--surface", 3.0, "tick marks (non-text)"],
  ["--rule", "--surface", 1.2, "hairline (decorative floor)"],
  ["--evidence", "--surface", 4.5, "links"],
  ["--evidence", "--paper", 4.5, "links on page"],
  ["--evidence", "--sunk", 4.5, "links in a well"],
  ["--on-evidence", "--evidence", 4.5, "text on primary button"],
  ["--evidence", "--evidence-w12", 4.5, "accent on its own wash"],
  ["--confirmed", "--confirmed-bg", 4.5, "confirmed chip"],
  ["--confirmed", "--surface", 4.5, "confirmed text"],
  ["--caution", "--caution-bg", 4.5, "caution chip"],
  ["--caution", "--surface", 4.5, "caution text"],
  ["--risk-low", "--risk-low-bg", 4.5, "risk chip: low"],
  ["--risk-medium", "--risk-medium-bg", 4.5, "risk chip: medium"],
  ["--risk-high", "--risk-high-bg", 4.5, "risk chip: high"],
  ["--risk-critical", "--risk-critical-bg", 4.5, "risk chip: critical"],
  ["--risk-low", "--surface", 4.5, "risk meter on panel: low"],
  ["--risk-medium", "--surface", 4.5, "risk meter on panel: medium"],
  ["--risk-high", "--surface", 4.5, "risk meter on panel: high"],
  ["--risk-critical", "--surface", 4.5, "risk meter on panel: critical"],
  ["--field-ink", "--field", 4.5, "text on the field"],
  ["--field-muted", "--field", 4.5, "labels on the field"],
  ["--node-wallet", "--field", 3.0, "graph node: wallet"],
  ["--node-transaction", "--field", 3.0, "graph node: transaction"],
  ["--node-ip", "--field", 3.0, "graph node: ip"],
  ["--node-taint", "--field", 3.0, "graph node: taint path"],
  ["--evidence", "--surface", 3.0, "focus ring"],
];

let failures = 0;
for (const [name, theme] of [
  ["light", light],
  ["dark", dark],
]) {
  console.log(`\n${name}`);
  for (const [fg, bg, min, what] of PAIRS) {
    const ground = resolve(theme, bg);
    const base = ground[3] === 1 ? ground : over(ground, resolve(theme, "--surface"));
    const value = ratio(over(resolve(theme, fg), base), base);
    const ok = value >= min;
    if (!ok) failures += 1;
    console.log(
      `  ${ok ? "ok  " : "FAIL"} ${value.toFixed(2).padStart(5)} (min ${min})  ${what}`,
    );
  }
}

console.log(failures ? `\n${failures} pair(s) below AA` : "\nall pairs pass AA");
process.exit(failures ? 1 : 0);
