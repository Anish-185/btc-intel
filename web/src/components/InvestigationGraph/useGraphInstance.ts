/** Creates the Cytoscape instance and wires everything that is not React:
 *  extensions, tooltips, the context menu, cluster expand/collapse, and the
 *  pointer and keyboard gestures.
 *
 *  The component above owns *what* the graph shows; this owns *how it is
 *  driven*. Handlers arrive in a ref so the menu and the event bindings always
 *  call the current ones without the instance being torn down on every render.
 */
import { useEffect, useRef, type MutableRefObject } from "react";
import cytoscape, { type Core, type EdgeSingular, type NodeSingular } from "cytoscape";
import fcose from "cytoscape-fcose";
import dagre from "cytoscape-dagre";
import expandCollapse from "cytoscape-expand-collapse";
import popper from "cytoscape-popper";
import cxtmenu from "cytoscape-cxtmenu";
import tippy, { type Instance as TippyInstance } from "tippy.js";

import { createFitter, type Fitter } from "./fit";
import { graphStyle } from "./style";
import { readToken, type EdgeData, type NodeData } from "./model";
import { formatId } from "../../lib/formatId";

/** Tippy needs a real DOM element; cytoscape-popper gives it a virtual rect. */
function tippyFactory(ref: { getBoundingClientRect: () => DOMRect }, content: HTMLElement) {
  const holder = document.createElement("div");
  return tippy(holder, {
    getReferenceClientRect: ref.getBoundingClientRect as () => DOMRect,
    trigger: "manual",
    content,
    arrow: true,
    placement: "top",
    hideOnClick: false,
    theme: "btc-intel",
    appendTo: document.body,
  });
}

let registered = false;
function registerExtensions() {
  if (registered) return;
  registered = true;
  cytoscape.use(fcose);
  cytoscape.use(dagre);
  cytoscape.use(expandCollapse);
  cytoscape.use(popper(tippyFactory as never));
  cytoscape.use(cxtmenu);
}

export interface GraphHandlers {
  onSelect: (data: NodeData | null) => void;
  onExpand: (id: string) => void;
  onTrace: (id: string, direction: "forward" | "backward") => void;
  onHide: (id: string) => void;
  onPin: (id: string) => void;
  onTaintSeed: (id: string) => void;
  onOpenEntity: (data: NodeData) => void;
  onCopy: (value: string) => void;
  onPathPick: (id: string) => void;
  onAggregate: (data: NodeData) => void;
}

/** The tooltip body for a node or an edge. Built as DOM rather than a string
 *  so nothing an address or a label contains can become markup. */
function tooltipFor(element: NodeSingular | EdgeSingular): HTMLElement {
  const box = document.createElement("div");
  box.className = "graph-tip";
  const rows: [string, string][] = [];

  if (element.isNode()) {
    const data = element.data() as NodeData;
    rows.push(["type", String(data.type)]);
    rows.push([data.type === "ip" ? "address" : "id", String(data.id)]);
    if (data.type === "wallet") {
      rows.push(["risk", (data.risk ?? 0).toFixed(3)]);
      rows.push(["alerted", data.alerted ? "yes" : "no"]);
      if (data.entity_id) rows.push(["entity", formatId(String(data.entity_id), { head: 12, tail: 6 })]);
    }
    if (data.type === "ip" && data.country) rows.push(["country", String(data.country)]);
    if (data.type === "aggregate") rows.push(["hidden neighbours", String(data.remaining ?? 0)]);
  } else {
    const data = element.data() as EdgeData;
    rows.push(["amount", `${(data.amount ?? 0).toFixed(8)} BTC`]);
    if (data.ts) rows.push(["time", String(data.ts).replace("T", " ").replace("+00:00", " UTC")]);
    if (data.txCount) rows.push(["transactions", String(data.txCount)]);
    const txid = data.txids?.[0] ?? (element.target().data("type") === "transaction"
      ? element.target().id()
      : element.source().data("type") === "transaction"
        ? element.source().id()
        : null);
    if (txid) rows.push(["txid", formatId(String(txid), { head: 10, tail: 6 })]);
    if (data.type === "broadcast") rows.push(["link", "probabilistic — broadcast observation"]);
  }

  for (const [label, value] of rows) {
    const row = document.createElement("div");
    const key = document.createElement("span");
    key.className = "graph-tip-key";
    key.textContent = label;
    const val = document.createElement("span");
    val.textContent = value;
    row.append(key, val);
    box.append(row);
  }
  return box;
}

export function useGraphInstance(
  handlers: MutableRefObject<GraphHandlers>,
  onReady: (cy: Core) => void,
) {
  const container = useRef<HTMLDivElement>(null);
  const cyRef = useRef<Core | null>(null);
  const fitter = useRef<Fitter | null>(null);
  const tip = useRef<TippyInstance | null>(null);

  useEffect(() => {
    registerExtensions();
    const host = container.current;
    if (!host) return;

    const cy = cytoscape({
      container: host,
      style: graphStyle(),
      elements: [],
      wheelSensitivity: 0.2,
      minZoom: 0.1,
      maxZoom: 4,
      boxSelectionEnabled: true,
    });
    cyRef.current = cy;
    fitter.current = createFitter(cy, host);

    // Entity clusters collapse to one node and open again.
    (cy as never as { expandCollapse: (o: object) => void }).expandCollapse({
      layoutBy: null,
      fisheye: false,
      animate: false,
      undoable: false,
      cueEnabled: true,
      expandCollapseCuePosition: "top-left",
      expandCollapseCueSize: 10,
      expandCollapseCueLineSize: 8,
    });

    const showTip = (element: NodeSingular | EdgeSingular) => {
      tip.current?.destroy();
      const instance = (
        element as never as { popper: (o: object) => TippyInstance }
      ).popper({ content: () => tooltipFor(element) });
      tip.current = instance;
      instance.show();
    };
    const hideTip = () => {
      tip.current?.destroy();
      tip.current = null;
    };

    cy.on("mouseover", "node, edge", (event) => showTip(event.target));
    cy.on("mouseout", "node, edge", hideTip);
    cy.on("pan zoom drag", hideTip);

    // Hovering a node fades everything that is not its neighbourhood, with
    // opacity rather than removal so the shape of the graph survives.
    cy.on("mouseover", "node", (event) => {
      const node = event.target as NodeSingular;
      cy.elements().difference(node.closedNeighborhood()).addClass("dim");
    });
    cy.on("mouseout", "node", () => cy.elements().removeClass("dim"));

    cy.on("tap", "node", (event) => {
      const node = event.target as NodeSingular;
      const data = node.data() as NodeData;
      if (data.type === "aggregate") {
        handlers.current.onAggregate(data);
        return;
      }
      handlers.current.onPathPick(node.id());
      handlers.current.onSelect(data);
    });
    cy.on("tap", (event) => {
      if (event.target === cy) handlers.current.onSelect(null);
    });
    cy.on("dbltap", "node", (event) => handlers.current.onExpand((event.target as NodeSingular).id()));

    // Right-click, or a long press on a tablet.
    (cy as never as { cxtmenu: (o: object) => void }).cxtmenu({
      selector: "node",
      menuRadius: 92,
      openMenuEvents: "cxttapstart taphold",
      fillColor: readToken("--field-rule"),
      activeFillColor: readToken("--node-wallet"),
      itemColor: readToken("--field-ink"),
      itemTextShadowColor: "transparent",
      commands: [
        { content: "expand", select: (el: NodeSingular) => handlers.current.onExpand(el.id()) },
        {
          content: "trace →",
          select: (el: NodeSingular) => handlers.current.onTrace(el.id(), "forward"),
        },
        {
          content: "trace ←",
          select: (el: NodeSingular) => handlers.current.onTrace(el.id(), "backward"),
        },
        { content: "hide", select: (el: NodeSingular) => handlers.current.onHide(el.id()) },
        { content: "pin", select: (el: NodeSingular) => handlers.current.onPin(el.id()) },
        {
          content: "taint seed",
          select: (el: NodeSingular) => handlers.current.onTaintSeed(el.id()),
        },
        {
          content: "open case",
          select: (el: NodeSingular) => handlers.current.onOpenEntity(el.data() as NodeData),
        },
        { content: "copy", select: (el: NodeSingular) => handlers.current.onCopy(el.id()) },
      ],
    });

    // A graph is hard to debug from the outside; in dev the instance is
    // reachable from the console. Never in a production build.
    if (import.meta.env?.DEV) (window as unknown as { __cy?: Core }).__cy = cy;

    onReady(cy);
    return () => {
      hideTip();
      fitter.current?.dispose();
      fitter.current = null;
      cy.destroy();
      cyRef.current = null;
    };
    // The instance is built once; handlers are read through the ref.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  return { container, cyRef, fitter };
}
