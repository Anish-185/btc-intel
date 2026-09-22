/** The graph's stylesheet.
 *
 *  Shape says what a thing is, colour says how risky it is, and width says how
 *  much moved. Those three channels are independent on purpose: an
 *  investigator reading a printout in greyscale still has shape and width.
 */
import type { EdgeSingular, NodeSingular, StylesheetJson } from "cytoscape";
import { edgeWidth, readToken, riskColour } from "./model";

export function graphStyle(): StylesheetJson {
  const ink = readToken("--field-ink");
  const muted = readToken("--field-muted");
  const rule = readToken("--field-rule");
  const taint = readToken("--node-taint");

  return [
    {
      selector: "node",
      style: {
        label: "data(label)",
        color: ink,
        "font-family": "IBM Plex Mono, ui-monospace, monospace",
        "font-size": 9,
        "text-valign": "bottom",
        "text-margin-y": 5,
        "text-opacity": 0.8,
        "text-background-color": readToken("--field"),
        "text-background-opacity": 0.72,
        "text-background-padding": "2",
        "overlay-opacity": 0,
        "border-width": 0,
        "transition-property": "opacity, border-width, background-color",
        "transition-duration": 200,
      },
    },
    {
      // Wallets: circles, filled by risk.
      selector: 'node[type = "wallet"]',
      style: {
        shape: "ellipse",
        width: 18,
        height: 18,
        "background-color": (node: NodeSingular) => riskColour(node.data("risk") as number),
      },
    },
    {
      // Flagged by an engine: a red ring, so risk is not colour alone.
      selector: 'node[type = "wallet"][?alerted]',
      style: {
        "border-width": 2.5,
        "border-color": readToken("--risk-node-critical"),
        "border-opacity": 0.9,
      },
    },
    {
      // Transactions: small diamonds. They are connectors, not subjects.
      selector: 'node[type = "transaction"]',
      style: {
        shape: "diamond",
        width: 11,
        height: 11,
        "background-color": readToken("--node-transaction"),
        "font-size": 8,
        "text-opacity": 0.55,
      },
    },
    {
      selector: 'node[type = "ip"]',
      style: {
        shape: "hexagon",
        width: 16,
        height: 14,
        "background-color": readToken("--node-ip"),
      },
    },
    {
      selector: 'node[type = "aggregate"]',
      style: {
        shape: "round-rectangle",
        width: 54,
        height: 20,
        "background-color": rule,
        "border-width": 1,
        "border-color": muted,
        "font-size": 9,
        "text-valign": "center",
        "text-margin-y": 0,
        "text-background-opacity": 0,
        color: ink,
      },
    },
    {
      // Entity clusters: a compound box around wallets one entity owns.
      selector: "$node > node",
      style: {
        "background-color": rule,
        "background-opacity": 0.35,
        "border-width": 1,
        "border-color": muted,
        "border-opacity": 0.5,
        shape: "round-rectangle",
        padding: "14px",
        "text-valign": "top",
        "text-halign": "center",
        "font-size": 9,
        color: muted,
        "text-margin-y": -4,
      },
    },
    {
      selector: "edge",
      style: {
        width: (edge: EdgeSingular) => edgeWidth(edge.data("amount") as number),
        "line-color": rule,
        "line-opacity": 0.9,
        "curve-style": "bezier",
        "target-arrow-shape": "triangle",
        "target-arrow-color": rule,
        "arrow-scale": 0.6,
        "transition-property": "opacity, line-color, width",
        "transition-duration": 200,
      },
    },
    {
      // IP links are probabilistic, and dashes say so.
      selector: 'edge[type = "broadcast"]',
      style: {
        "line-style": "dashed",
        "line-dash-pattern": [4, 4],
        "line-color": readToken("--node-ip"),
        "target-arrow-color": readToken("--node-ip"),
        width: 1,
        label: "data(confidenceLabel)",
        "font-size": 8,
        color: muted,
        "text-background-opacity": 0,
      },
    },
    {
      selector: 'edge[type = "aggregate"]',
      style: { "line-style": "dotted", "line-color": muted, width: 1, "arrow-scale": 0.4 },
    },
    {
      selector: 'edge[type = "aggregated"]',
      style: { label: "data(aggregateLabel)", "font-size": 8, color: muted, "text-rotation": "autorotate" },
    },
    {
      selector: "edge.taint",
      style: {
        width: 3,
        "line-color": taint,
        "target-arrow-color": taint,
        "line-style": "dashed",
        "line-dash-pattern": [7, 5],
      },
    },
    { selector: "node.pinned", style: { "border-width": 2, "border-color": ink, "border-style": "double" } },
    { selector: ".dim", style: { opacity: 0.1 } },
    { selector: ".highlight", style: { "border-width": 3, "border-color": ink, "border-opacity": 1 } },
    {
      selector: "edge.highlight",
      style: { "line-color": ink, "target-arrow-color": ink, width: 3.5, opacity: 1 },
    },
    { selector: "node:selected", style: { "border-width": 3, "border-color": ink } },
    { selector: ".hidden", style: { display: "none" } },
  ];
}
