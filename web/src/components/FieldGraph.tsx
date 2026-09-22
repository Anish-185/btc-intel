/** The link-analysis surface: a Cytoscape graph on the dark field.
 *
 *  Reusable on purpose — the entity subgraph and a transaction's propagation
 *  tree are the same component with different elements and a different layout,
 *  and anything added later (a cluster view, a timeline) should be a third
 *  caller rather than a second component.
 *
 *  Readability rules, in order of importance:
 *    1. a node is a labelled dot whose colour says what kind of thing it is;
 *    2. the taint path is the only thing that moves;
 *    3. hovering dims everything that is not a neighbour, using opacity, so
 *       the shape of the graph survives the dimming.
 */
import { useEffect, useRef } from "react";
import cytoscape, { type Core, type ElementDefinition, type LayoutOptions } from "cytoscape";
import dagre from "cytoscape-dagre";
import { reducedMotion } from "../lib/motion";
import { token } from "../lib/tokens";

cytoscape.use(dagre);

export interface FieldGraphProps {
  elements: ElementDefinition[];
  layout: LayoutOptions;
  /** Node ids on the taint path; their edges get the moving dashes. */
  taintPath?: string[];
  height?: number;
  onNodeTap?: (node: { id: string; type?: string; label?: string }) => void;
  onReady?: (cy: Core) => void;
}

const fieldStyle = (): cytoscape.StylesheetJson => [
  {
    selector: "node",
    style: {
      "background-color": "data(colour)",
      width: "data(size)",
      height: "data(size)",
      label: "data(label)",
      color: token("--field-ink", "#dce6ff"),
      "font-family": "IBM Plex Mono, ui-monospace, monospace",
      "font-size": 8,
      "text-valign": "bottom",
      "text-margin-y": 4,
      "text-opacity": 0.75,
      "text-background-color": "#070b18",
      "text-background-opacity": 0.75,
      "text-background-padding": "2",
      "overlay-opacity": 0,
      "transition-property": "opacity, border-width",
      "transition-duration": 200,
    },
  },
  {
    selector: "node[?focus]",
    style: {
      "border-color": "#ffffff",
      "border-width": 1.5,
      "text-opacity": 1,
      "font-size": 9,
    },
  },
  {
    selector: "edge",
    style: {
      width: 1,
      "line-color": token("--field-rule", "#16224a"),
      "curve-style": "bezier",
      "target-arrow-shape": "triangle",
      "target-arrow-color": token("--field-rule", "#16224a"),
      "arrow-scale": 0.5,
      "transition-property": "opacity",
      "transition-duration": 200,
    },
  },
  {
    selector: "edge.taint",
    style: {
      width: 1.6,
      "line-color": token("--node-taint", "#ff8f61"),
      "target-arrow-color": token("--node-taint", "#ff8f61"),
      "line-style": "dashed",
      "line-dash-pattern": [6, 4],
    },
  },
  { selector: ".dim", style: { opacity: 0.12 } },
  { selector: ".hovered", style: { "border-color": "#ffffff", "border-width": 1.5 } },
];

export function FieldGraph({
  elements,
  layout,
  taintPath = [],
  height = 420,
  onNodeTap,
  onReady,
}: FieldGraphProps) {
  const host = useRef<HTMLDivElement>(null);
  const core = useRef<Core | null>(null);

  useEffect(() => {
    const container = host.current;
    if (!container) return;

    const cy = cytoscape({
      container,
      elements,
      style: fieldStyle(),
      wheelSensitivity: 0.2,
      maxZoom: 3,
      minZoom: 0.2,
    });
    core.current = cy;

    const taint = new Set(taintPath);
    cy.edges().forEach((edge) => {
      if (taint.has(edge.source().id()) && taint.has(edge.target().id())) {
        edge.addClass("taint");
      }
    });

    // Fit after the layout settles: the container has its real size by then,
    // and a graph drawn outside its panel is worse than no graph.
    const run = cy.layout({
      ...layout,
      animate: !reducedMotion(),
      animationDuration: 300,
      fit: true,
      padding: 28,
    } as LayoutOptions);
    run.one("layoutstop", () => cy.fit(undefined, 28));
    run.run();

    const refit = () => cy.fit(undefined, 28);
    const resize = new ResizeObserver(refit);
    resize.observe(container);

    // Entrance: nodes fade and scale in once, after the first layout settles.
    if (!reducedMotion()) {
      cy.nodes().forEach((node, i) => {
        node.style("opacity", 0);
        setTimeout(() => node.animate({ style: { opacity: 1 } }, { duration: 260 }), i * 8);
      });
    }

    cy.on("mouseover", "node", (event) => {
      const node = event.target;
      const keep = node.closedNeighborhood();
      cy.elements().difference(keep).addClass("dim");
      node.addClass("hovered");
    });
    cy.on("mouseout", "node", () => {
      cy.elements().removeClass("dim").removeClass("hovered");
    });
    cy.on("tap", "node", (event) => {
      const data = event.target.data();
      onNodeTap?.({ id: data.id, type: data.type, label: data.label });
    });

    onReady?.(cy);
    return () => {
      resize.disconnect();
      cy.destroy();
      core.current = null;
    };
  }, [elements, layout, taintPath, onNodeTap, onReady]);

  // Marching ants on the taint path only, and only when motion is welcome.
  useEffect(() => {
    if (reducedMotion()) return;
    let offset = 0;
    const timer = setInterval(() => {
      const cy = core.current;
      if (!cy || document.hidden) return;
      offset = (offset - 1) % 10;
      cy.edges(".taint").style("line-dash-offset", offset);
    }, 90);
    return () => clearInterval(timer);
  }, []);

  return <div ref={host} style={{ height, width: "100%" }} data-testid="field-graph" />;
}
