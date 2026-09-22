/// <reference types="vite/client" />

/** The commit this bundle was built from — see vite.config.ts. */
declare const __APP_COMMIT__: string;

declare module "cytoscape-dagre" {
  import type { Ext } from "cytoscape";
  const extension: Ext;
  export default extension;
}

declare module "cytoscape-fcose" {
  import type { Ext } from "cytoscape";
  const extension: Ext;
  export default extension;
}

declare module "cytoscape-expand-collapse" {
  import type { Ext } from "cytoscape";
  const extension: Ext;
  export default extension;
}

declare module "cytoscape-cxtmenu" {
  import type { Ext } from "cytoscape";
  const extension: Ext;
  export default extension;
}
