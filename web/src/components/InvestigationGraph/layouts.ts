/** Four ways to look at the same evidence.
 *
 *  Each answers a different question, which is why the toggle exists rather
 *  than one clever layout: force shows structure, the flow tree shows where
 *  money went, radial shows how far from here something is, and the timeline
 *  shows what happened in what order.
 */
import type { Core, LayoutOptions, NodeSingular } from "cytoscape";
import { timelinePositions, type EdgeData, type NodeData } from "./model";

export type LayoutName = "force" | "flow" | "radial" | "timeline";

export const LAYOUT_LABELS: Record<LayoutName, string> = {
  force: "force",
  flow: "flow tree",
  radial: "radial",
  timeline: "timeline",
};

export const LAYOUT_HINTS: Record<LayoutName, string> = {
  force: "structure — what is connected to what",
  flow: "money flow — the selected wallet is the root",
  radial: "distance — rings are hops from the selection",
  timeline: "sequence — time left to right, entity by row",
};

export function layoutFor(
  name: LayoutName,
  cy: Core,
  options: { root?: string | null; animate: boolean } = { animate: true },
): LayoutOptions {
  const animate = options.animate;
  const common = { animate, animationDuration: 300, fit: true, padding: 28 };

  if (name === "flow") {
    return {
      name: "dagre",
      rankDir: "LR",
      nodeSep: 26,
      rankSep: 70,
      ...common,
    } as unknown as LayoutOptions;
  }

  if (name === "radial") {
    const root = options.root;
    return {
      name: "concentric",
      concentric: (node: NodeSingular) => {
        if (root && node.id() === root) return 100;
        const depth = node.data("depth") as number | undefined;
        if (depth != null) return 100 - depth;
        return root ? 100 - Math.min(hops(cy, root, node.id()), 9) : 50;
      },
      levelWidth: () => 1,
      minNodeSpacing: 34,
      ...common,
    } as unknown as LayoutOptions;
  }

  if (name === "timeline") {
    const width = cy.width() || 900;
    const height = cy.height() || 520;
    const positions = timelinePositions(
      cy.nodes().map((n) => ({ data: n.data() as NodeData })),
      cy.edges().map((e) => ({ data: e.data() as EdgeData })),
      width,
      height,
    );
    return {
      name: "preset",
      positions: (node: NodeSingular) => positions[node.id()] ?? { x: 40, y: height / 2 },
      ...common,
    } as unknown as LayoutOptions;
  }

  return {
    name: "fcose",
    quality: "default",
    randomize: false,
    nodeSeparation: 90,
    idealEdgeLength: 90,
    nodeRepulsion: 6000,
    ...common,
  } as unknown as LayoutOptions;
}

/** Run a layout, and fit only when fitting is what the reader asked for.
 *
 *  Two rules, learned the hard way:
 *
 *    * Cytoscape's own `fit` option is honoured by some layouts and ignored by
 *      others depending on how they finish, which shows up as a graph drawn
 *      small in a corner. Fitting on `layoutstop` is one line and always true.
 *    * Fitting is only ever right for a *whole-graph* layout — the first one,
 *      and an explicit switch. Fitting after an expansion yanks the view away
 *      from what the analyst was looking at to accommodate nodes they have not
 *      read yet, which is how a graph tool loses someone's place.
 */
export function runLayout(cy: Core, options: LayoutOptions, fit: (() => void) | false): void {
  const run = cy.layout(options);
  if (fit) run.one("layoutstop", fit);
  run.run();
}


/** Graph distance, capped — only used to rank rings when no depth is known. */
function hops(cy: Core, from: string, to: string): number {
  const source = cy.getElementById(from);
  if (source.empty()) return 9;
  const result = cy.elements().bfs({ roots: source, directed: false });
  const path = result.path as unknown as { id: () => string }[];
  const index = path.findIndex((element) => element.id() === to);
  return index < 0 ? 9 : Math.floor(index / 2);
}

/** Lay out only what just arrived.
 *
 *  Everything already on screen is locked first, so an expansion adds to the
 *  picture the investigator has built instead of rearranging it under them —
 *  the single most common way a graph tool loses someone's place.
 */
export function layoutNewOnly(cy: Core, newIds: string[], animate: boolean): void {
  if (!newIds.length) return;
  let fresh = cy.collection();
  for (const id of newIds) {
    const element = cy.getElementById(id);
    if (element.nonempty()) fresh = fresh.union(element);
  }
  if (fresh.empty()) return;
  const existing = cy.nodes().difference(fresh.nodes());
  existing.lock();
  const neighbourhood = fresh.union(fresh.connectedEdges()).union(fresh.neighborhood());
  neighbourhood
    .layout({
      name: "fcose",
      quality: "default",
      randomize: false,
      animate,
      animationDuration: 260,
      fit: false,
      nodeSeparation: 80,
      idealEdgeLength: 80,
    } as unknown as LayoutOptions)
    .run();
  existing.unlock();
}
