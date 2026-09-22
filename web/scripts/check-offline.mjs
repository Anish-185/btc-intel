/** Fails the build if anything in dist/ would reach the network.
 *
 *  The console ships into an air-gapped environment: a font from a CDN or an
 *  analytics beacon is not a performance problem there, it is a broken page.
 *  Run after `npm run build`.
 *
 *  What counts as a failure is a URL the browser would actually *fetch*: an
 *  href or src attribute, a CSS url(), a fetch/import call. Library licence
 *  banners, error-message links and XML namespaces are strings that no code
 *  requests; they are listed rather than failed, so the list is reviewable
 *  instead of silently allowed. */
import { readdirSync, readFileSync, statSync } from "node:fs";
import { join } from "node:path";

const DIST = new URL("../dist/", import.meta.url).pathname;
const TEXT = /\.(html|js|css|map|json|svg|txt)$/;

/** A URL in one of these positions is a request the browser will make. */
const FETCHING = [
  /\b(?:src|href|action|poster|data|srcset)\s*=\s*["\']?(https?:\/\/[^"\'\s>]+)/gi,
  /url\(\s*["\']?(https?:\/\/[^"\')\s]+)/gi,
  /\b(?:fetch|importScripts|import)\(\s*["\`\'](https?:\/\/[^"\`\']+)/gi,
  /new\s+(?:Worker|EventSource|WebSocket)\(\s*["\`\'](https?:\/\/[^"\`\']+)/gi,
];

const ANY_URL = /https?:\/\/[^\s"\'`)\\<>]+/g;

function* files(dir) {
  for (const entry of readdirSync(dir)) {
    const path = join(dir, entry);
    if (statSync(path).isDirectory()) yield* files(path);
    else yield path;
  }
}

const requests = [];
const strings = new Map();

for (const path of files(DIST)) {
  if (!TEXT.test(path)) continue;
  const name = path.replace(DIST, "");
  const text = readFileSync(path, "utf8");

  for (const rule of FETCHING) {
    for (const match of text.matchAll(rule)) {
      const url = match[1];
      if (/^https?:\/\/(localhost|127\.0\.0\.1)/.test(url)) continue;
      requests.push(`${name}: ${url.slice(0, 140)}`);
    }
  }

  for (const [url] of text.matchAll(ANY_URL)) {
    const key = url.slice(0, 90);
    strings.set(key, (strings.get(key) ?? 0) + 1);
  }
}

if (strings.size) {
  console.log("URLs present as strings only (no request is made for these):");
  for (const [url, count] of [...strings].sort()) console.log(`  ${String(count).padStart(2)}x  ${url}`);
}

if (requests.length) {
  console.error("\nExternal resources the browser WOULD load:");
  for (const line of requests) console.error(`  ${line}`);
  console.error(`\n${requests.length} external request(s) — the build is not offline-safe`);
  process.exit(1);
}

console.log("\nno external requests in dist — offline-safe");
