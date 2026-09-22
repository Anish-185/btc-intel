/** The investigation graph's rules, checked where they can be checked.
 *
 *  Cytoscape needs a canvas and a layout engine, neither of which jsdom has,
 *  so the instance is replaced with a recorder: what elements were added, and
 *  which layout was asked for. Everything that is arithmetic — aggregating
 *  connectors, capping a supernode, filtering — is a pure function and is
 *  tested directly, on a fixture small enough to verify by hand.
 */
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";

import {
  DEFAULT_FILTERS,
  capNeighbours,
  edgeVisible,
  edgeWidth,
  nodeVisible,
  simplifyConnectors,
  timelinePositions,
  type EdgeData,
  type GraphPayload,
} from "./model";

// --- the recorder ---------------------------------------------------------
const added: unknown[][] = [];
const layouts: string[] = [];

function makeFakeCy() {
  const elements: { data: Record<string, unknown> }[] = [];
  const emptyCollection = {
    empty: () => true,
    nonempty: () => false,
    forEach: () => {},
    map: () => [],
    remove: () => {},
    union: () => emptyCollection,
    difference: () => emptyCollection,
    addClass: () => emptyCollection,
    removeClass: () => emptyCollection,
    toggleClass: () => emptyCollection,
    unselect: () => emptyCollection,
    lock: () => emptyCollection,
    unlock: () => emptyCollection,
    style: () => emptyCollection,
    length: 0,
    layout: () => ({ run: () => {}, one: () => {} }),
    boundingBox: () => ({ x1: 0, y1: 0, w: 10, h: 10 }),
    connectedEdges: () => emptyCollection,
    neighborhood: () => emptyCollection,
    closedNeighborhood: () => emptyCollection,
  };
  const collection = {
    ...emptyCollection,
    empty: () => false,
    nonempty: () => true,
    length: elements.length,
  };
  return {
    add: (els: unknown) => {
      const list = Array.isArray(els) ? els : [els];
      added.push(list);
      elements.push(...(list as { data: Record<string, unknown> }[]));
      return collection;
    },
    batch: (fn: () => void) => fn(),
    elements: () => ({ ...emptyCollection, map: () => elements.map((e) => ({ data: e.data })) }),
    nodes: () => ({ ...emptyCollection, length: elements.length, map: () => [] }),
    edges: () => emptyCollection,
    $: () => emptyCollection,
    collection: () => emptyCollection,
    getElementById: () => emptyCollection,
    on: () => {},
    layout: (options: { name: string }) => {
      layouts.push(options.name);
      return { run: () => {}, one: () => {} };
    },
    fit: () => {},
    width: () => 800,
    height: () => 500,
    zoom: () => 1,
    animate: () => {},
    png: () => "data:image/png;base64,AA==",
    destroy: () => {},
    expandCollapse: () => {},
    cxtmenu: () => {},
    removeClass: () => {},
  };
}

vi.mock("cytoscape", () => {
  const factory = () => makeFakeCy();
  (factory as unknown as { use: () => void }).use = () => {};
  return { default: factory };
});
vi.mock("cytoscape-fcose", () => ({ default: () => {} }));
vi.mock("cytoscape-dagre", () => ({ default: () => {} }));
vi.mock("cytoscape-expand-collapse", () => ({ default: () => {} }));
vi.mock("cytoscape-cxtmenu", () => ({ default: () => {} }));
vi.mock("cytoscape-popper", () => ({ default: () => () => {} }));
vi.mock("tippy.js", () => ({ default: () => ({ show: () => {}, destroy: () => {} }) }));

// Imported after the mocks so the component sees them.
const { InvestigationGraph } = await import("./InvestigationGraph");

const FIXTURE: GraphPayload = {
  nodes: [
    { data: { id: "W1", type: "wallet", label: "W1", risk: 0.9, alerted: true } },
    { data: { id: "tx1", type: "transaction", label: "tx1" } },
    { data: { id: "W2", type: "wallet", label: "W2", risk: 0.1, alerted: false } },
    { data: { id: "1.2.3.4", type: "ip", label: "1.2.3.4 IN", country: "IN" } },
  ],
  edges: [
    { data: { id: "e1", source: "W1", target: "tx1", amount: 1.5, ts: "2026-01-01T00:00:00Z" } },
    { data: { id: "e2", source: "tx1", target: "W2", amount: 1.4, ts: "2026-01-01T00:00:00Z" } },
    { data: { id: "e3", source: "1.2.3.4", target: "tx1", amount: 0, type: "broadcast" } },
  ],
};

beforeEach(() => {
  added.length = 0;
  layouts.length = 0;
});

const mount = () =>
  render(
    <MemoryRouter>
      <InvestigationGraph initial={FIXTURE} focusId="W1" />
    </MemoryRouter>,
  );

describe("the graph renders what it was given", () => {
  it("adds every node and edge from the fixture", async () => {
    mount();
    const flat = added.flat() as { data: { id: string } }[];
    const ids = new Set(flat.map((element) => element.data.id));
    expect(ids).toEqual(new Set(["W1", "tx1", "W2", "1.2.3.4", "e1", "e2", "e3"]));
  });

  it("keeps the transaction as its own node rather than joining the wallets", () => {
    mount();
    const flat = added.flat() as { data: { id: string; type?: string } }[];
    expect(flat.find((e) => e.data.id === "tx1")?.data.type).toBe("transaction");
    const edges = flat.filter((e) => "source" in e.data);
    expect(edges).toHaveLength(3);
  });

  it("shows the legend and the canvas", () => {
    mount();
    expect(screen.getByTestId("graph-canvas")).toBeInTheDocument();
    expect(screen.getByLabelText("Legend")).toBeInTheDocument();
  });
});

describe("the layout toggle", () => {
  it("switches the layout that is run", async () => {
    mount();
    layouts.length = 0;

    await userEvent.click(screen.getByRole("button", { name: "flow tree" }));
    expect(layouts).toContain("dagre");

    layouts.length = 0;
    await userEvent.click(screen.getByRole("button", { name: "radial" }));
    expect(layouts).toContain("concentric");

    layouts.length = 0;
    await userEvent.click(screen.getByRole("button", { name: "timeline" }));
    expect(layouts).toContain("preset");

    layouts.length = 0;
    await userEvent.click(screen.getByRole("button", { name: "force" }));
    expect(layouts).toContain("fcose");
  });

  it("marks the current layout for assistive technology", async () => {
    mount();
    await userEvent.click(screen.getByRole("button", { name: "radial" }));
    expect(screen.getByRole("button", { name: "radial" })).toHaveAttribute("aria-pressed", "true");
    expect(screen.getByRole("button", { name: "force" })).toHaveAttribute("aria-pressed", "false");
  });
});

// --- simplify connectors, verified by hand --------------------------------
/**
 * Three transactions, chosen so every interesting case appears once:
 *
 *   t1: A(1.0) ─────────────► X(0.6), Y(0.3)     one input, two outputs
 *   t2: A(0.5), B(0.5) ─────► X(0.9)             two inputs, one output
 *   t3: B(2.0) ─────────────► X(1.9)             a second A/B→X payment
 *
 * An input wallet is credited with each output in proportion to its share of
 * that transaction's inputs, so:
 *
 *   A→X = 0.6 (all of t1's X output) + 0.45 (half of t2's) = 1.05, 2 txs
 *   A→Y = 0.3                                               = 0.30, 1 tx
 *   B→X = 0.45 (half of t2's) + 1.9 (all of t3's)           = 2.35, 2 txs
 */
const THREE_TX = [
  { data: { id: "A", type: "wallet" } },
  { data: { id: "B", type: "wallet" } },
  { data: { id: "X", type: "wallet" } },
  { data: { id: "Y", type: "wallet" } },
  { data: { id: "t1", type: "transaction" } },
  { data: { id: "t2", type: "transaction" } },
  { data: { id: "t3", type: "transaction" } },
  { data: { id: "i1", source: "A", target: "t1", amount: 1.0 } },
  { data: { id: "o1", source: "t1", target: "X", amount: 0.6, ts: "2026-01-01T00:00:00Z" } },
  { data: { id: "o2", source: "t1", target: "Y", amount: 0.3 } },
  { data: { id: "i2", source: "A", target: "t2", amount: 0.5 } },
  { data: { id: "i3", source: "B", target: "t2", amount: 0.5 } },
  { data: { id: "o3", source: "t2", target: "X", amount: 0.9 } },
  { data: { id: "i4", source: "B", target: "t3", amount: 2.0 } },
  { data: { id: "o4", source: "t3", target: "X", amount: 1.9 } },
];

describe("simplify connectors", () => {
  const result = simplifyConnectors(THREE_TX as never);
  const edges = result
    .map((element) => element.data as EdgeData)
    .filter((data) => data.source != null);
  const find = (source: string, target: string) =>
    edges.find((edge) => edge.source === source && edge.target === target);

  it("drops the transaction nodes and keeps the wallets", () => {
    const nodes = result.map((e) => e.data as { id: string; type?: string }).filter((d) => !("source" in d));
    expect(nodes.map((n) => n.id).sort()).toEqual(["A", "B", "X", "Y"]);
  });

  it("sums the amounts by the input's share of each transaction", () => {
    expect(find("A", "X")?.amount).toBeCloseTo(1.05, 8);
    expect(find("A", "Y")?.amount).toBeCloseTo(0.3, 8);
    expect(find("B", "X")?.amount).toBeCloseTo(2.35, 8);
    expect(find("B", "Y")).toBeUndefined();
  });

  it("says how many transactions each line stands for, and which", () => {
    expect(find("A", "X")?.txCount).toBe(2);
    expect(find("A", "X")?.txids).toEqual(["t1", "t2"]);
    expect(find("A", "Y")?.txCount).toBe(1);
    expect(find("B", "X")?.txids).toEqual(["t2", "t3"]);
  });

  it("conserves value: every output is credited exactly once", () => {
    const total = edges.reduce((sum, edge) => sum + edge.amount, 0);
    expect(total).toBeCloseTo(0.6 + 0.3 + 0.9 + 1.9, 8);
  });
});

// --- supernodes, filters, scales ------------------------------------------
describe("supernode batching", () => {
  const page: GraphPayload = {
    nodes: Array.from({ length: 21 }, (_, i) => ({
      data: { id: `n${i}`, type: "wallet" as const },
    })),
    edges: Array.from({ length: 20 }, (_, i) => ({
      data: { id: `e${i}`, source: "n0", target: `n${i + 1}`, amount: 1 },
    })),
  };

  it("stands the rest behind one node that knows where to continue", () => {
    const elements = capNeighbours(page, "n0", 40, 20);
    const aggregate = elements.find((el) => (el.data as { type?: string }).type === "aggregate");
    expect(aggregate?.data).toMatchObject({
      label: "+40 more",
      remaining: 40,
      source_node: "n0",
      next_offset: 20,
    });
    expect(elements.some((el) => (el.data as { target?: string }).target === aggregate?.data?.id)).toBe(
      true,
    );
  });

  it("adds nothing when the page was the last one", () => {
    const elements = capNeighbours(page, "n0", 0, 20);
    expect(elements.some((el) => (el.data as { type?: string }).type === "aggregate")).toBe(false);
  });
});

describe("filters", () => {
  it("hides a node type when it is switched off", () => {
    const filters = { ...DEFAULT_FILTERS, types: { ...DEFAULT_FILTERS.types, ip: false } };
    expect(nodeVisible({ id: "a", type: "ip" }, filters)).toBe(false);
    expect(nodeVisible({ id: "b", type: "wallet" }, filters)).toBe(true);
  });

  it("applies the minimum risk to wallets only", () => {
    const filters = { ...DEFAULT_FILTERS, minRisk: 0.5 };
    expect(nodeVisible({ id: "a", type: "wallet", risk: 0.2 }, filters)).toBe(false);
    expect(nodeVisible({ id: "b", type: "wallet", risk: 0.8 }, filters)).toBe(true);
    expect(nodeVisible({ id: "t", type: "transaction" }, filters)).toBe(true);
  });

  it("applies amount and time bounds to edges", () => {
    const edge: EdgeData = { id: "e", source: "a", target: "b", amount: 0.5, ts: "2026-02-01T00:00:00Z" };
    expect(edgeVisible(edge, { ...DEFAULT_FILTERS, minAmount: 1 })).toBe(false);
    expect(edgeVisible(edge, { ...DEFAULT_FILTERS, minAmount: 0.1 })).toBe(true);
    expect(edgeVisible(edge, { ...DEFAULT_FILTERS, from: Date.parse("2026-03-01") })).toBe(false);
    expect(edgeVisible(edge, { ...DEFAULT_FILTERS, to: Date.parse("2026-03-01") })).toBe(true);
  });
});

describe("scales", () => {
  it("grows edge width with amount, on a log scale, bounded", () => {
    expect(edgeWidth(0)).toBeCloseTo(1, 5);
    expect(edgeWidth(0.01)).toBeLessThan(edgeWidth(1));
    expect(edgeWidth(1)).toBeLessThan(edgeWidth(100));
    expect(edgeWidth(1_000_000)).toBeLessThanOrEqual(9);
  });

  it("puts earlier transactions to the left on the timeline", () => {
    const nodes = [
      { data: { id: "a", type: "wallet" as const, entity_id: "E1" } },
      { data: { id: "b", type: "wallet" as const, entity_id: "E1" } },
    ];
    const edges = [
      { data: { id: "e1", source: "a", target: "a", amount: 1, ts: "2026-01-01T00:00:00Z" } },
      { data: { id: "e2", source: "b", target: "b", amount: 1, ts: "2026-06-01T00:00:00Z" } },
    ];
    const positions = timelinePositions(nodes, edges, 900, 400);
    expect(positions.a.x).toBeLessThan(positions.b.x);
  });
});
