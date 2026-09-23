/** The investigation graph.
 *
 *  One surface where an analyst builds a picture of a case: expand what looks
 *  interesting, trace where money went, ask whether two wallets are connected
 *  at all, and keep the result.
 *
 *  Three commitments run through the whole component:
 *
 *    1. **The graph never lies about structure.** Wallets are joined through
 *       transaction nodes, because that is what the chain says. The one view
 *       that draws wallet-to-wallet edges (simplify connectors) says on every
 *       edge how many transactions it stands for.
 *    2. **The picture the analyst built is theirs.** Expanding adds nodes and
 *       lays out only the new ones; nothing already placed moves. Hiding,
 *       expanding and tracing are undoable.
 *    3. **Nothing is silently omitted.** Supernodes show a "+N more" node,
 *       pruned branches are counted, and hitting the node cap raises a banner
 *       instead of quietly dropping the rest.
 */
import { useCallback, useEffect, useRef, useState } from "react";
import { useNavigate } from "react-router-dom";
import type { Core, ElementDefinition, NodeSingular } from "cytoscape";

import { graphApi } from "./api";
import {
  DEFAULT_FILTERS,
  MAX_VISIBLE_NODES,
  SUPERNODE_VISIBLE,
  capNeighbours,
  edgeVisible,
  newElements,
  nodeVisible,
  simplifyConnectors,
  type EdgeData,
  type Filters,
  type GraphPayload,
  type NodeData,
} from "./model";
import { formatId } from "../../lib/formatId";
import { layoutFor, layoutNewOnly, runLayout, type LayoutName } from "./layouts";
import { useGraphInstance, type GraphHandlers } from "./useGraphInstance";
import { download, toPngBlob, toSvg } from "./svgExport";
import { Toolbar, type Mode, type TraceSettings } from "./Toolbar";
import { SidePanel } from "./SidePanel";
import { Legend } from "./Legend";
import { reducedMotion } from "../../lib/motion";
import "./graph.css";

export interface InvestigationGraphProps {
  /** What the view opens with — usually an entity's neighbourhood. */
  initial?: GraphPayload;
  /** The node the investigation starts from. */
  focusId?: string | null;
  /** Entity ids on the taint path, drawn with moving dashes. */
  taintPath?: string[];
  /** Node ids to ring — what a red-team run injected, for instance. */
  highlight?: string[];
  height?: number;
  /** Restore a saved investigation instead of `initial`. */
  investigationId?: string;
  onNotice?: (message: string) => void;
}

interface Action {
  label: string;
  undo: () => void;
  redo: () => void;
}

export function InvestigationGraph({
  initial,
  focusId = null,
  taintPath = [],
  highlight = [],
  height = 560,
  investigationId,
  onNotice,
}: InvestigationGraphProps) {
  const navigate = useNavigate();
  const [layout, setLayout] = useState<LayoutName>("force");
  const [mode, setMode] = useState<Mode>("browse");
  const [simplify, setSimplify] = useState(false);
  const [selected, setSelected] = useState<NodeData | null>(null);
  const [filters, setFilters] = useState<Filters>(DEFAULT_FILTERS);
  const [trace, setTrace] = useState<TraceSettings>({
    direction: "forward",
    maxHops: 4,
    minAmount: 0,
  });
  const [busy, setBusy] = useState(false);
  const [banner, setBanner] = useState<string | null>(null);
  const [pruned, setPruned] = useState(0);
  const [showPruned, setShowPruned] = useState(false);
  const [stack, setStack] = useState<{ past: Action[]; future: Action[] }>({
    past: [],
    future: [],
  });

  const pathPick = useRef<string[]>([]);
  const trueElements = useRef<ElementDefinition[]>([]);
  const animate = !reducedMotion();

  const notify = useCallback(
    (message: string) => (onNotice ? onNotice(message) : setBanner(message)),
    [onNotice],
  );

  const handlers = useRef<GraphHandlers>({} as GraphHandlers);
  const [ready, setReady] = useState(false);
  const { container, cyRef, fitter } = useGraphInstance(handlers, () => setReady(true));
  /** A whole-graph layout is allowed to reframe the view. An expansion is not. */
  const fitView = useCallback(() => fitter.current?.fit(), [fitter]);

  // --- adding and removing ------------------------------------------------
  const pushAction = useCallback((action: Action) => {
    setStack((s) => ({ past: [...s.past.slice(-49), action], future: [] }));
  }, []);

  const addElements = useCallback(
    (cy: Core, elements: ElementDefinition[], options: { layout?: boolean } = {}) => {
      const dataOf = (el: ElementDefinition) => el.data as NodeData & Partial<EdgeData>;
      // Every element enters the graph here, so this is where labels are cut
      // down to something a canvas can show. The id keeps the full value.
      elements = elements.map((el) => (dataOf(el).source ? el : { ...el, data: labelled(dataOf(el)) }));
      const fresh = elements.filter((el) => cy.getElementById(String(dataOf(el).id)).empty());
      if (!fresh.length) return [];
      const room = MAX_VISIBLE_NODES - cy.nodes().length;
      const nodes = fresh.filter((el) => !("source" in dataOf(el)));
      let accepted = fresh;
      if (nodes.length > room) {
        const keep = new Set(nodes.slice(0, Math.max(room, 0)).map((el) => String(dataOf(el).id)));
        accepted = fresh.filter((el) => {
          const data = dataOf(el);
          return "source" in data
            ? keep.has(String(data.source)) && keep.has(String(data.target))
            : keep.has(String(data.id));
        });
        notify(
          `Node cap reached (${MAX_VISIBLE_NODES}). ${nodes.length - Math.max(room, 0)} nodes were ` +
            "not drawn — narrow the view with filters, a smaller hop count or a minimum amount.",
        );
      }
      cy.batch(() => cy.add(accepted));
      trueElements.current = cy.elements().map((el) => ({ data: el.data() }));
      if (options.layout) {
        runLayout(cy, layoutFor(layout, cy, { root: focusId, animate }), fitView);
      }
      return accepted.map((el) => String(dataOf(el).id));
    },
    // `layout` and `focusId` are read when called, not captured for the instance
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [layout, focusId, animate, notify, fitView],
  );

  const expand = useCallback(
    async (id: string, offset = 0) => {
      const cy = cyRef.current;
      if (!cy) return;
      setBusy(true);
      try {
        const page = await graphApi.neighbors(id, { limit: SUPERNODE_VISIBLE, offset });
        const elements =
          page.has_more || page.remaining > 0
            ? capNeighbours(page, id, page.remaining, offset + page.returned)
            : newElements(page, (nodeId) => !cy.getElementById(nodeId).empty());
        // A stale "+N more" node is replaced by the next page's one.
        cy.getElementById(`more:${id}:${offset}`).remove();
        const added = addElements(cy, elements);
        if (added.length) {
          layoutNewOnly(cy, added, animate);
          pushAction({
            label: `expand ${id}`,
            undo: () => added.forEach((nodeId) => cy.getElementById(nodeId).remove()),
            redo: () => void expand(id, offset),
          });
        } else if (page.total === 0) {
          notify("Nothing else connects to this node in the loaded dataset.");
        }
      } catch (error) {
        notify(`Could not expand: ${(error as Error).message}`);
      } finally {
        setBusy(false);
      }
    },
    [addElements, animate, cyRef, notify, pushAction],
  );

  const runTrace = useCallback(
    async (id: string, direction: "forward" | "backward") => {
      const cy = cyRef.current;
      if (!cy) return;
      setBusy(true);
      try {
        const result = await graphApi.trace(id, {
          direction,
          maxHops: trace.maxHops,
          minAmount: showPruned ? 0 : trace.minAmount,
        });
        const before = cy.elements().map((el) => ({ data: el.data() }));
        cy.batch(() => {
          cy.elements().remove();
          cy.add(toElements(result));
        });
        trueElements.current = cy.elements().map((el) => ({ data: el.data() }));
        setPruned(result.pruned_edges);
        setLayout("flow");
        runLayout(cy, layoutFor("flow", cy, { root: id, animate }), fitView);
        pushAction({
          label: `trace ${direction} from ${id}`,
          undo: () => {
            cy.batch(() => {
              cy.elements().remove();
              cy.add(before);
            });
            runLayout(cy, layoutFor("force", cy, { animate }), fitView);
          },
          redo: () => void runTrace(id, direction),
        });
        notify(
          `Traced ${result.wallets} wallets ${direction} from this one` +
            (result.pruned_edges ? `, ${result.pruned_edges} branches pruned by amount.` : "."),
        );
      } catch (error) {
        notify(`Could not trace: ${(error as Error).message}`);
      } finally {
        setBusy(false);
      }
    },
    [animate, cyRef, notify, pushAction, showPruned, trace.maxHops, trace.minAmount],
  );

  const findPath = useCallback(
    async (from: string, to: string) => {
      const cy = cyRef.current;
      if (!cy) return;
      setBusy(true);
      try {
        const result = await graphApi.path(from, to);
        addElements(cy, toElements(result));
        const onPath = new Set(result.path);
        cy.batch(() => {
          cy.elements().addClass("dim");
          for (const id of result.path) cy.getElementById(id).removeClass("dim").addClass("highlight");
          for (const edge of result.edges) {
            cy.getElementById(edge.data.id).removeClass("dim").addClass("highlight");
          }
        });
        notify(`${result.hops} steps from ${from} to ${to}. Everything else is faded.`);
        void onPath;
      } catch (error) {
        notify((error as Error).message);
      } finally {
        setBusy(false);
        setMode("browse");
        pathPick.current = [];
      }
    },
    [addElements, cyRef, notify],
  );

  const markTaintSeed = useCallback(
    async (id: string) => {
      const cy = cyRef.current;
      if (!cy) return;
      setBusy(true);
      try {
        const result = await graphApi.taint(id);
        const scores = new Map(result.tainted.map((row) => [row.entity_id, row.score]));
        cy.batch(() => {
          cy.nodes().forEach((node) => {
            const entity = node.data("entity_id") as string | undefined;
            if (entity && scores.has(entity)) node.addClass("highlight");
          });
        });
        notify(
          `${result.tainted.length} entities would inherit taint from this seed. ${result.caveat}`,
        );
      } catch (error) {
        notify(`Could not compute taint: ${(error as Error).message}`);
      } finally {
        setBusy(false);
      }
    },
    [cyRef, notify],
  );

  const hide = useCallback(
    (id: string) => {
      const cy = cyRef.current;
      if (!cy) return;
      const element = cy.getElementById(id);
      if (element.empty()) return;
      const snapshot = element.union(element.connectedEdges()).map((el) => ({ data: el.data() }));
      element.remove();
      setSelected(null);
      pushAction({
        label: `hide ${id}`,
        undo: () => cy.add(snapshot),
        redo: () => cy.getElementById(id).remove(),
      });
    },
    [cyRef, pushAction],
  );

  const pin = useCallback(
    (id: string) => {
      const cy = cyRef.current;
      if (!cy) return;
      const node = cy.getElementById(id) as NodeSingular;
      if (node.empty()) return;
      const pinned = node.hasClass("pinned");
      if (pinned) {
        node.removeClass("pinned").unlock();
      } else {
        node.addClass("pinned").lock();
      }
    },
    [cyRef],
  );

  // --- handlers the instance calls ---------------------------------------
  handlers.current = {
    onSelect: setSelected,
    onExpand: (id) => void expand(id),
    onTrace: (id, direction) => void runTrace(id, direction),
    onHide: hide,
    onPin: pin,
    onTaintSeed: (id) => void markTaintSeed(id),
    onOpenEntity: (data) =>
      navigate(`/entities/${encodeURIComponent(String(data.entity_id ?? data.id))}`),
    onCopy: (value) => {
      navigator.clipboard?.writeText(value);
      notify("Copied to the clipboard.");
    },
    onPathPick: (id) => {
      if (mode !== "path") return;
      pathPick.current = [...pathPick.current, id].slice(-2);
      if (pathPick.current.length === 2) {
        void findPath(pathPick.current[0], pathPick.current[1]);
      } else {
        notify("Now pick the second node.");
      }
    },
    onAggregate: (data) => {
      if (data.source_node) void expand(String(data.source_node), Number(data.next_offset ?? 0));
    },
  };

  // --- reactions ----------------------------------------------------------
  useEffect(() => {
    const cy = cyRef.current;
    if (!ready || !cy || !initial) return;
    addElements(cy, toElements(initial), { layout: true });
    // The opening view is set once; expanding from here is the analyst's.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [ready, initial]);

  useEffect(() => {
    const cy = cyRef.current;
    if (!cy) return;
    runLayout(cy, layoutFor(layout, cy, { root: focusId ?? selected?.id ?? null, animate }), fitView);
    // Re-laying out on selection change would move the graph under the reader.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [layout]);

  useEffect(() => {
    const cy = cyRef.current;
    if (!cy || !highlight.length) return;
    // ponytail: rings what is on the canvas now — a node pulled in by a later
    // expansion is not re-checked. Move this into addElements if that matters.
    for (const id of highlight) cy.getElementById(id).addClass("highlight");
  }, [cyRef, highlight, initial, ready]);

  useEffect(() => {
    const cy = cyRef.current;
    if (!cy || !taintPath.length) return;
    const onPath = new Set(taintPath);
    cy.edges().forEach((edge) => {
      const source = edge.source().data("entity_id") ?? edge.source().id();
      const target = edge.target().data("entity_id") ?? edge.target().id();
      if (onPath.has(source) && onPath.has(target)) edge.addClass("taint");
    });
  }, [cyRef, taintPath]);

  // Marching ants on the taint path, and only there.
  useEffect(() => {
    if (reducedMotion()) return;
    let offset = 0;
    const timer = setInterval(() => {
      const cy = cyRef.current;
      if (!cy || document.hidden) return;
      offset = (offset - 1) % 12;
      cy.edges(".taint").style("line-dash-offset", offset);
    }, 90);
    return () => clearInterval(timer);
  }, [cyRef]);

  // Filters: styling, not removal, so undo has something to come back to.
  useEffect(() => {
    const cy = cyRef.current;
    if (!cy) return;
    cy.batch(() => {
      cy.nodes().forEach((node) => {
        const data = node.data() as NodeData;
        const clusterSize = (node.isParent() ? node.children().length : 0) || 0;
        const hidden =
          !nodeVisible(data, filters) ||
          (node.isParent() && clusterSize < filters.minClusterSize);
        node.toggleClass("hidden", hidden);
      });
      cy.edges().forEach((edge) => {
        const data = edge.data() as EdgeData;
        const hidden =
          !edgeVisible(data, filters) ||
          edge.source().hasClass("hidden") ||
          edge.target().hasClass("hidden");
        edge.toggleClass("hidden", hidden);
      });
    });
  }, [cyRef, filters]);

  // Simplify connectors: swap the elements, keep the originals to come back to.
  useEffect(() => {
    const cy = cyRef.current;
    if (!cy) return;
    if (simplify) {
      trueElements.current = cy.elements().map((el) => ({ data: el.data() }));
      const aggregated = simplifyConnectors(trueElements.current).map((el) => ({
        data: {
          ...el.data,
          aggregateLabel:
            (el.data as EdgeData).txCount != null
              ? `${(el.data as EdgeData).amount.toFixed(4)} · ${(el.data as EdgeData).txCount} tx`
              : undefined,
        },
      }));
      cy.batch(() => {
        cy.elements().remove();
        cy.add(aggregated as ElementDefinition[]);
      });
    } else if (trueElements.current.length) {
      cy.batch(() => {
        cy.elements().remove();
        cy.add(trueElements.current);
      });
    }
    runLayout(cy, layoutFor(layout, cy, { root: focusId, animate }), fitView);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [simplify]);

  // Keyboard: Esc clears, F fits, Delete hides.
  useEffect(() => {
    const onKey = (event: KeyboardEvent) => {
      const cy = cyRef.current;
      if (!cy) return;
      const typing = ["INPUT", "SELECT", "TEXTAREA"].includes(
        (event.target as HTMLElement)?.tagName,
      );
      if (typing) return;
      if (event.key === "Escape") {
        cy.elements().removeClass("dim").removeClass("highlight");
        cy.$(":selected").unselect();
        setSelected(null);
        setMode("browse");
        pathPick.current = [];
      } else if (event.key.toLowerCase() === "f") {
        fitView();
      } else if (event.key === "Delete" || event.key === "Backspace") {
        const chosen = cy.$("node:selected");
        if (chosen.nonempty()) {
          event.preventDefault();
          chosen.forEach((node) => hide(node.id()));
        }
      }
    };
    addEventListener("keydown", onKey);
    return () => removeEventListener("keydown", onKey);
  }, [cyRef, fitView, hide]);

  // Restore a saved investigation.
  useEffect(() => {
    if (!investigationId) return;
    const cy = cyRef.current;
    if (!cy) return;
    const controller = new AbortController();
    graphApi
      .load(investigationId, controller.signal)
      .then((record) => {
        const state = record.state as {
          elements?: ElementDefinition[];
          positions?: Record<string, { x: number; y: number }>;
          filters?: Filters;
          layout?: LayoutName;
          pinned?: string[];
        };
        cy.batch(() => {
          cy.elements().remove();
          cy.add(state.elements ?? []);
          for (const [id, position] of Object.entries(state.positions ?? {})) {
            cy.getElementById(id).position(position);
          }
          for (const id of state.pinned ?? []) cy.getElementById(id).addClass("pinned").lock();
        });
        if (state.filters) setFilters(state.filters);
        if (state.layout) setLayout(state.layout);
        fitView();
        notify(`Restored "${record.name}".`);
      })
      .catch((error: Error) => notify(`Could not load that investigation: ${error.message}`));
    return () => controller.abort();
  }, [cyRef, investigationId, notify]);

  // --- toolbar actions ----------------------------------------------------
  const search = useCallback(
    (query: string) => {
      const cy = cyRef.current;
      if (!cy) return;
      const value = query.trim().toLowerCase();
      cy.elements().removeClass("highlight");
      if (!value) return;
      const matches = cy.nodes().filter((node) => node.id().toLowerCase().includes(value));
      if (matches.empty()) return;
      matches.addClass("highlight");
      cy.animate({ center: { eles: matches }, zoom: Math.max(cy.zoom(), 1) }, { duration: animate ? 250 : 0 });
    },
    [animate, cyRef],
  );

  const exportView = useCallback(
    (kind: "png" | "svg") => {
      const cy = cyRef.current;
      if (!cy) return;
      const stamp = new Date().toISOString().slice(0, 19).replace(/[:T]/g, "-");
      if (kind === "png") {
        download(toPngBlob(cy), `btc-intel-graph-${stamp}.png`, "image/png");
      } else {
        download(
          toSvg(cy, { caption: `btc-intel · ${cy.nodes().length} nodes · ${stamp} UTC` }),
          `btc-intel-graph-${stamp}.svg`,
        );
      }
    },
    [cyRef],
  );

  const save = useCallback(async () => {
    const cy = cyRef.current;
    if (!cy) return;
    const state = {
      elements: cy.elements().map((el) => ({ data: el.data() })),
      positions: Object.fromEntries(cy.nodes().map((node) => [node.id(), node.position()])),
      pinned: cy.nodes(".pinned").map((node) => node.id()),
      filters,
      layout,
    };
    try {
      const saved = await graphApi.save(
        focusId ? `Investigation from ${focusId}` : "Investigation",
        state,
      );
      notify(`Saved as ${saved.id}. Reopen it with ?investigation=${saved.id}.`);
    } catch (error) {
      notify(`Could not save: ${(error as Error).message}`);
    }
  }, [cyRef, filters, focusId, layout, notify]);

  const undo = useCallback(() => {
    setStack((s) => {
      const action = s.past.at(-1);
      if (!action) return s;
      action.undo();
      return { past: s.past.slice(0, -1), future: [action, ...s.future] };
    });
  }, []);

  const redo = useCallback(() => {
    setStack((s) => {
      const action = s.future[0];
      if (!action) return s;
      action.redo();
      return { past: [...s.past, action], future: s.future.slice(1) };
    });
  }, []);

  const nodeCount = cyRef.current?.nodes().length ?? 0;
  const capReached = nodeCount >= MAX_VISIBLE_NODES;

  return (
    <div className="investigation-graph field-panel" style={{ minHeight: height }}>
      <Toolbar
        layout={layout}
        onLayout={setLayout}
        mode={mode}
        onMode={(next) => {
          setMode(next);
          pathPick.current = [];
          if (next === "path") notify("Pick two nodes to show the path between them.");
        }}
        simplify={simplify}
        onSimplify={setSimplify}
        trace={trace}
        onTrace={setTrace}
        onSearch={search}
        onFit={fitView}
        onUndo={undo}
        onRedo={redo}
        canUndo={stack.past.length > 0}
        canRedo={stack.future.length > 0}
        onExport={exportView}
        onSave={() => void save()}
        filters={filters}
        onFilters={setFilters}
        showPruned={showPruned}
        onShowPruned={setShowPruned}
        prunedCount={pruned}
        busy={busy}
      />

      {(banner || capReached) && (
        <p className="graph-banner" role="status">
          <span aria-hidden="true">⚠</span> {banner ?? `Showing the first ${MAX_VISIBLE_NODES} nodes.`}
          <button type="button" className="btn btn-quiet field-btn" onClick={() => setBanner(null)}>
            dismiss
          </button>
        </p>
      )}

      <div className="graph-stage">
        <div ref={container} className="graph-canvas" style={{ height }} data-testid="graph-canvas" />
        <Legend />
        {selected && (
          <SidePanel
            node={selected}
            pinned={cyRef.current?.getElementById(selected.id).hasClass("pinned") ?? false}
            onClose={() => setSelected(null)}
            onExpand={(id) => void expand(id)}
            onTrace={(id, direction) => void runTrace(id, direction)}
            onHide={hide}
            onPin={pin}
            onTaintSeed={(id) => void markTaintSeed(id)}
            onCopy={(value) => handlers.current.onCopy(value)}
          />
        )}
      </div>
    </div>
  );
}

/** The on-canvas label.
 *
 *  Shortened here rather than in the API: the full value is the node's id, so
 *  the tooltip, the side panel and every export still carry it, while the
 *  canvas stays readable. An IP is short enough to print whole and is the one
 *  identifier an investigator reads at a glance. */
export function labelled(data: NodeData): NodeData {
  return {
    ...data,
    label:
      data.type === "ip" || data.type === "aggregate"
        ? (data.label ?? data.id)
        : formatId(String(data.label ?? data.id)),
  };
}

/** API payload → Cytoscape elements. */
export function toElements(payload: GraphPayload): ElementDefinition[] {
  const nodes = payload.nodes.map((node) => ({ data: labelled(node.data) }));
  const ids = new Set(nodes.map((n) => n.data.id));
  const edges = payload.edges
    .filter((edge) => ids.has(edge.data.source) && ids.has(edge.data.target))
    .map((edge) => ({
      data: {
        ...edge.data,
        confidenceLabel:
          edge.data.confidence != null ? `${(edge.data.confidence * 100).toFixed(0)}%` : undefined,
      },
    }));
  return [...nodes, ...edges] as ElementDefinition[];
}
