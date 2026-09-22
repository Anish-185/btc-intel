/** The graph's data rules, kept out of the component so they can be checked.
 *
 *  Nothing here touches Cytoscape or the DOM: given elements, it returns
 *  elements. That is what makes "did simplifying connectors sum the amounts
 *  correctly" a question a test can answer.
 */
import type { ElementDefinition } from "cytoscape";

export type NodeType = "wallet" | "transaction" | "ip" | "aggregate" | "cluster";

export interface NodeData {
  id: string;
  type: NodeType;
  label?: string;
  risk?: number;
  alerted?: boolean;
  entity_id?: string;
  parent?: string;
  depth?: number;
  country?: string;
  asn?: number | null;
  /** aggregate nodes only */
  remaining?: number;
  source_node?: string;
  next_offset?: number;
  [key: string]: unknown;
}

export interface EdgeData {
  id: string;
  source: string;
  target: string;
  amount: number;
  ts?: string | null;
  type?: string;
  /** set by aggregation */
  txCount?: number;
  txids?: string[];
  confidence?: number;
  [key: string]: unknown;
}

export interface GraphPayload {
  nodes: { data: NodeData }[];
  edges: { data: EdgeData }[];
}

export const EMPTY: GraphPayload = { nodes: [], edges: [] };

/** Above this many neighbours a node is a supernode and gets batched. */
export const SUPERNODE_NEIGHBOURS = 50;
/** How many of them are drawn before the rest become one "+N more" node. */
export const SUPERNODE_VISIBLE = 20;
/** Past this the browser is the bottleneck, not the investigator. */
export const MAX_VISIBLE_NODES = 1000;

// --- colour and weight ----------------------------------------------------
/** Risk as a colour ramp, read off the design tokens at runtime.
 *
 *  Cytoscape paints to a canvas and never sees CSS custom properties, so the
 *  stops are resolved to literal colours. Colour is never the only signal:
 *  every node also carries its shape, and flagged nodes carry an outline.
 */
const STOPS: [number, string][] = [
  [0.0, "--risk-node-none"],
  [0.3, "--risk-node-medium"],
  [0.6, "--risk-node-high"],
  [0.8, "--risk-node-critical"],
];

const FALLBACK: Record<string, string> = {
  "--risk-node-none": "#5fc794",
  "--risk-node-medium": "#e3b25c",
  "--risk-node-high": "#ff8f61",
  "--risk-node-critical": "#ff7186",
  "--node-wallet": "#7e9dff",
  "--node-transaction": "#97a3b8",
  "--node-ip": "#e3b25c",
  "--node-taint": "#ff8f61",
  "--field": "#070b18",
  "--field-ink": "#dce6ff",
  "--field-muted": "#7f9bd8",
  "--field-rule": "#16224a",
};

export function riskColour(score: number | undefined, read = readToken): string {
  const value = Math.min(Math.max(score ?? 0, 0), 1);
  let chosen = STOPS[0];
  for (const stop of STOPS) if (value >= stop[0]) chosen = stop;
  return read(chosen[1]);
}

export function readToken(name: string): string {
  if (typeof document === "undefined") return FALLBACK[name] ?? "#888888";
  const value = getComputedStyle(document.documentElement).getPropertyValue(name).trim();
  return value || FALLBACK[name] || "#888888";
}

/** Edge width on a log scale: a 50 BTC flow should look heavier than a 0.5 BTC
 *  one without being a hundred times heavier, which no screen can show. */
export function edgeWidth(amount: number): number {
  const btc = Math.max(amount, 0);
  return Math.min(1 + Math.log10(1 + btc * 100) * 1.6, 9);
}

// --- connector simplification --------------------------------------------
/** Hide the transaction diamonds and join the wallets they connect.
 *
 *  This is a *lossy* view and the UI says so: a transaction with three inputs
 *  and four outputs becomes twelve wallet-to-wallet edges that no single
 *  payment ever made. Each aggregated edge therefore carries how many
 *  transactions it stands for and which ones, so the claim stays checkable,
 *  and the amount is the value that actually moved out of the transaction on
 *  that side — an input wallet is credited with the outputs it helped fund,
 *  split by its share of the inputs.
 */
export function simplifyConnectors(elements: ElementDefinition[]): ElementDefinition[] {
  const nodes = new Map<string, ElementDefinition>();
  const edgesIn = new Map<string, { from: string; amount: number }[]>();
  const edgesOut = new Map<string, { to: string; amount: number; ts?: string | null }[]>();

  for (const element of elements) {
    const data = element.data as NodeData & Partial<EdgeData>;
    if (data.source == null || data.target == null) {
      nodes.set(String(data.id), element);
      continue;
    }
    const source = String(data.source);
    const target = String(data.target);
    const sourceType = nodeType(nodes, elements, source);
    const targetType = nodeType(nodes, elements, target);
    if (targetType === "transaction") {
      const list = edgesIn.get(target) ?? [];
      list.push({ from: source, amount: data.amount ?? 0 });
      edgesIn.set(target, list);
    } else if (sourceType === "transaction") {
      const list = edgesOut.get(source) ?? [];
      list.push({ to: target, amount: data.amount ?? 0, ts: data.ts });
      edgesOut.set(source, list);
    }
  }

  const kept: ElementDefinition[] = [];
  for (const [id, element] of nodes) {
    if ((element.data as NodeData).type === "transaction") continue;
    kept.push(element);
    void id;
  }

  const merged = new Map<string, EdgeData>();
  for (const [txid, inputs] of edgesIn) {
    const outputs = edgesOut.get(txid) ?? [];
    const inputTotal = inputs.reduce((sum, i) => sum + i.amount, 0) || 1;
    for (const input of inputs) {
      const share = input.amount / inputTotal;
      for (const output of outputs) {
        const key = `${input.from}->${output.to}`;
        const existing = merged.get(key);
        const amount = output.amount * share;
        if (existing) {
          existing.amount += amount;
          existing.txCount = (existing.txCount ?? 0) + 1;
          existing.txids = [...(existing.txids ?? []), txid];
        } else {
          merged.set(key, {
            id: `agg:${key}`,
            source: input.from,
            target: output.to,
            amount,
            ts: output.ts,
            type: "aggregated",
            txCount: 1,
            txids: [txid],
          });
        }
      }
    }
  }

  for (const edge of merged.values()) {
    edge.amount = round8(edge.amount);
    kept.push({ data: edge });
  }
  return kept;
}

function nodeType(
  known: Map<string, ElementDefinition>,
  all: ElementDefinition[],
  id: string,
): NodeType | undefined {
  const found =
    known.get(id) ??
    all.find((e) => {
      const data = e.data as NodeData & Partial<EdgeData>;
      return data.source == null && data.id === id;
    });
  return found ? ((found.data as NodeData).type as NodeType) : undefined;
}

export const round8 = (value: number) => Math.round(value * 1e8) / 1e8;

// --- supernode batching ---------------------------------------------------
/** Keep the biggest `visible` neighbours and stand the rest behind one node.
 *
 *  Drawing four thousand edges is not a view, it is a blue smear. The "+N
 *  more" node is honest about what is missing and loads the next page when
 *  clicked.
 */
export function capNeighbours(
  payload: GraphPayload,
  sourceId: string,
  remaining: number,
  nextOffset: number,
  visible = SUPERNODE_VISIBLE,
): ElementDefinition[] {
  const elements: ElementDefinition[] = [];
  const keptNodes = payload.nodes.slice(0, visible + 1 + visible * 2);
  for (const node of keptNodes) elements.push({ data: { ...node.data } });
  const ids = new Set<string>(keptNodes.map((n) => n.data.id));
  for (const edge of payload.edges) {
    if (ids.has(edge.data.source) && ids.has(edge.data.target)) {
      elements.push({ data: { ...edge.data } });
    }
  }
  if (remaining > 0) {
    const aggregateId = `more:${sourceId}:${nextOffset}`;
    elements.push({
      data: {
        id: aggregateId,
        type: "aggregate",
        label: `+${remaining} more`,
        remaining,
        source_node: sourceId,
        next_offset: nextOffset,
      },
    });
    elements.push({
      data: {
        id: `edge:${aggregateId}`,
        source: sourceId,
        target: aggregateId,
        amount: 0,
        type: "aggregate",
      },
    });
  }
  return elements;
}

// --- filtering ------------------------------------------------------------
export interface Filters {
  types: Record<Exclude<NodeType, "cluster">, boolean>;
  minRisk: number;
  minAmount: number;
  /** epoch ms, or null for "no bound" */
  from: number | null;
  to: number | null;
  minClusterSize: number;
}

export const DEFAULT_FILTERS: Filters = {
  types: { wallet: true, transaction: true, ip: true, aggregate: true },
  minRisk: 0,
  minAmount: 0,
  from: null,
  to: null,
  minClusterSize: 0,
};

/** True if the node survives the filters. Edges are hidden when either end is. */
export function nodeVisible(data: NodeData, filters: Filters): boolean {
  const type = (data.type ?? "wallet") as Exclude<NodeType, "cluster">;
  if (filters.types[type] === false) return false;
  if (data.type === "wallet" && (data.risk ?? 0) < filters.minRisk) return false;
  return true;
}

export function edgeVisible(data: EdgeData, filters: Filters): boolean {
  if ((data.amount ?? 0) < filters.minAmount) return false;
  const ts = data.ts ? Date.parse(data.ts) : null;
  if (ts != null && filters.from != null && ts < filters.from) return false;
  if (ts != null && filters.to != null && ts > filters.to) return false;
  return true;
}

// --- timeline -------------------------------------------------------------
/** Positions for the timeline layout: time left to right, entity by band.
 *
 *  A peeling chain is a diagonal staircase here and a layering fan is a burst
 *  in one column, which is the shape an investigator is actually looking for.
 */
export function timelinePositions(
  elements: { data: NodeData }[],
  edges: { data: EdgeData }[],
  width: number,
  height: number,
): Record<string, { x: number; y: number }> {
  const timeOf = new Map<string, number>();
  for (const edge of edges) {
    if (!edge.data.ts) continue;
    const ts = Date.parse(edge.data.ts);
    if (Number.isNaN(ts)) continue;
    for (const end of [edge.data.source, edge.data.target]) {
      const current = timeOf.get(end);
      if (current == null || ts < current) timeOf.set(end, ts);
    }
  }
  const times = [...timeOf.values()];
  const min = times.length ? Math.min(...times) : 0;
  const max = times.length ? Math.max(...times) : 1;
  const span = max - min || 1;

  const bands = new Map<string, number>();
  for (const node of elements) {
    const band = node.data.entity_id ?? node.data.parent ?? node.data.type ?? "other";
    if (!bands.has(String(band))) bands.set(String(band), bands.size);
  }
  const bandHeight = height / Math.max(bands.size, 1);

  const positions: Record<string, { x: number; y: number }> = {};
  for (const node of elements) {
    const band = String(node.data.entity_id ?? node.data.parent ?? node.data.type ?? "other");
    const ts = timeOf.get(node.data.id);
    const x = ts == null ? 40 : 60 + ((ts - min) / span) * Math.max(width - 120, 200);
    const row = bands.get(band) ?? 0;
    // A small deterministic jitter inside the band so identical timestamps do
    // not stack into one dot.
    const jitter = (hash(node.data.id) % 30) - 15;
    positions[node.data.id] = { x, y: bandHeight * (row + 0.5) + jitter };
  }
  return positions;
}

function hash(value: string): number {
  let out = 0;
  for (let i = 0; i < value.length; i += 1) out = (out * 31 + value.charCodeAt(i)) | 0;
  return Math.abs(out);
}

// --- misc -----------------------------------------------------------------
export const shortId = (value: string, head = 8, tail = 4) =>
  value.length <= head + tail + 1 ? value : `${value.slice(0, head)}…${value.slice(-tail)}`;

/** Elements arriving from the API, deduplicated against what is on screen. */
export function newElements(
  payload: GraphPayload,
  has: (id: string) => boolean,
): ElementDefinition[] {
  const out: ElementDefinition[] = [];
  for (const node of payload.nodes) if (!has(node.data.id)) out.push({ data: { ...node.data } });
  for (const edge of payload.edges) if (!has(edge.data.id)) out.push({ data: { ...edge.data } });
  return out;
}
