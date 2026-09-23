import { execSync } from "node:child_process";
import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

/** The commit this bundle was built from, compiled in as a constant.
 *
 *  The console compares it with what /version reports; a mismatch means the
 *  page and the server are not the same build, which is how a demo ends up
 *  showing yesterday's behaviour with today's UI. BTC_INTEL_COMMIT wins, for
 *  a build without a .git directory. */
const commit = (() => {
  if (process.env.BTC_INTEL_COMMIT) return process.env.BTC_INTEL_COMMIT.trim().slice(0, 7);
  try {
    return execSync("git rev-parse --short=7 HEAD", { encoding: "utf8" }).trim();
  } catch {
    return "unknown";
  }
})();

// The API is same-origin in production (FastAPI serves web/dist), so the dev
// server proxies instead of hard-coding a base URL anywhere in the app.
export default defineConfig({
  plugins: [react()],
  // The console is served from /app/, not from /. The API's own paths are
  // /alerts, /entities/… and /custody — which are also the console's routes —
  // so sharing an origin at the root would mean a hard refresh on the alert
  // queue returned JSON. A prefix costs one line and removes the whole class
  // of collision. The router reads it back from import.meta.env.BASE_URL.
  base: "/app/",
  define: { __APP_COMMIT__: JSON.stringify(commit) },
  server: {
    // In dev the API lives on another port, and its paths (/alerts, /entities)
    // are also the console's own routes — so the calls are namespaced under
    // /api and the prefix is stripped on the way through. VITE_API_BASE in
    // .env.development matches. In production there is no proxy and no prefix:
    // FastAPI serves the built files and the API from one origin.
    proxy: {
      "/api": {
        target: "http://127.0.0.1:8000",
        changeOrigin: false,
        rewrite: (path: string) => path.replace(/^\/api/, ""),
      },
    },
  },
  build: {
    rollupOptions: {
      output: {
        // The graph engine is the heavy dependency and only the entity page
        // needs it; keep it out of the initial download.
        manualChunks: {
          graph: [
            "cytoscape",
            "cytoscape-dagre",
            "cytoscape-fcose",
            "cytoscape-expand-collapse",
            "cytoscape-popper",
            "cytoscape-cxtmenu",
            "tippy.js",
            "@popperjs/core",
          ],
        },
      },
    },
  },
  test: {
    environment: "jsdom",
    setupFiles: ["src/test/setup.ts"],
    globals: true,
    css: false,
  },
} as never);
