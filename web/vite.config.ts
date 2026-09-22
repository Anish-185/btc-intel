import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// The API is same-origin in production (FastAPI serves web/dist), so the dev
// server proxies instead of hard-coding a base URL anywhere in the app.
export default defineConfig({
  plugins: [react()],
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
