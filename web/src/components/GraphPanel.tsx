/** The entity's neighbourhood, and — one tap away — how a transaction in it
 *  spread across the network.
 *
 *  Two views, one surface. The subgraph answers "who is this connected to";
 *  the propagation tree answers "where did this broadcast come from", which is
 *  a different question with a different confidence attached to it, so the
 *  panel says which one you are looking at and never mixes them. */
import { useCallback, useMemo, useState } from "react";
import type { ElementDefinition, LayoutOptions } from "cytoscape";
import { api } from "../api/client";
import type { EntityGraph, Propagation } from "../api/types";
import { ipClass, truncateId } from "../lib/format";
import { token } from "../lib/tokens";
import { FieldGraph } from "./FieldGraph";
import { Chip } from "./ui";

const nodeColour = (type: string) =>
  token(
    type === "wallet"
      ? "--node-wallet"
      : type === "ip"
        ? "--node-ip"
        : "--node-transaction",
  );

const roleColour = (role: string) =>
  token(
    role === "origin"
      ? "--node-taint"
      : role === "runner_up"
        ? "--node-ip"
        : "--node-transaction",
  );

/** Node size carries risk: the entity under investigation and its own wallets
 *  are drawn larger than the surroundings they touch. */
function toElements(graph: EntityGraph, riskScore: number): ElementDefinition[] {
  const base = 12 + Math.round(riskScore * 8);
  return [
    ...graph.elements.nodes.map(({ data }) => ({
      data: {
        ...data,
        colour: nodeColour(String(data.type)),
        size: data.is_focus ? base : data.type === "transaction" ? 6 : 9,
        focus: data.is_focus ? 1 : 0,
        label: data.type === "ip" ? String(data.label) : truncateId(String(data.label ?? data.id), 6, 4),
      },
    })),
    ...graph.elements.edges.map(({ data }) => ({ data })),
  ];
}

function propagationElements(tree: Propagation): ElementDefinition[] {
  return [
    ...tree.elements.nodes.map(({ data }) => ({
      data: {
        ...data,
        colour: roleColour(String(data.role)),
        size: data.role === "origin" ? 14 : data.role === "runner_up" ? 10 : 7,
        focus: data.role === "origin" ? 1 : 0,
      },
    })),
    ...tree.elements.edges.map(({ data }) => ({ data })),
  ];
}

export function GraphPanel({
  graph,
  taintPath,
  riskScore,
}: {
  graph: EntityGraph;
  taintPath: string[];
  riskScore: number;
}) {
  const [tree, setTree] = useState<Propagation | null>(null);
  const [selected, setSelected] = useState<{ id: string; type?: string } | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const elements = useMemo(
    () => (tree ? propagationElements(tree) : toElements(graph, riskScore)),
    [tree, graph, riskScore],
  );

  const layout = useMemo<LayoutOptions>(
    () =>
      tree
        ? (// Wide separation on purpose: these labels are full IP
            // addresses and they must not overlap.
            { name: "dagre", rankDir: "TB", nodeSep: 86, rankSep: 64 } as unknown as LayoutOptions)
        : ({ name: "cose", idealEdgeLength: 70, nodeRepulsion: 9000, padding: 24 } as unknown as LayoutOptions),
    [tree],
  );

  const onNodeTap = useCallback((node: { id: string; type?: string }) => {
    setSelected(node);
  }, []);

  const showPropagation = async (txid: string) => {
    setLoading(true);
    setError(null);
    try {
      setTree(await api.propagation(txid));
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="field-panel">
      <div className="field-toolbar">
        <span className="label">
          {tree ? "propagation tree" : `neighbourhood · ${graph.hops} hops`}
        </span>
        {tree ? (
          <>
            <span className="mono" style={{ fontSize: "var(--fs-small)" }}>
              {truncateId(tree.txid, 10, 6)}
            </span>
            <button type="button" className="btn btn-ghost bracket field-btn" onClick={() => setTree(null)}>
              Back to neighbourhood
            </button>
          </>
        ) : selected?.type === "transaction" ? (
          <button
            type="button"
            className="btn btn-ghost bracket field-btn"
            disabled={loading}
            onClick={() => showPropagation(selected.id)}
          >
            {loading ? "Loading…" : `Show propagation · ${truncateId(selected.id, 8, 4)}`}
          </button>
        ) : (
          <span className="label">select a transaction node to trace its broadcast</span>
        )}
        {graph.truncated && !tree && <Chip title="The neighbourhood was capped for legibility">capped</Chip>}
      </div>

      <FieldGraph
        elements={elements}
        layout={layout}
        taintPath={tree ? [] : taintPath}
        onNodeTap={onNodeTap}
      />

      {tree ? (
        <div className="field-legend">
          <span>
            <i className="legend-swatch" style={{ background: "var(--node-taint)" }} /> estimated origin
          </span>
          <span>
            <i className="legend-swatch" style={{ background: "var(--node-ip)" }} /> runner-up
          </span>
          <span>
            <i className="legend-swatch" style={{ background: "var(--node-transaction)" }} /> relay hop
          </span>
          <span>
            {ipClass(tree.ip_class).label} · confidence {tree.confidence.toFixed(2)}
            {tree.low_confidence_origin && " · ⚠ low confidence origin"}
            {tree.anonymized_entry_point && " · ⚠ anonymized entry point"}
          </span>
        </div>
      ) : (
        <div className="field-legend">
          <span>
            <i className="legend-swatch" style={{ background: "var(--node-wallet)" }} /> wallet ·{" "}
            {graph.counts.wallets}
          </span>
          <span>
            <i className="legend-swatch" style={{ background: "var(--node-transaction)" }} /> transaction ·{" "}
            {graph.counts.transactions}
          </span>
          <span>
            <i className="legend-swatch" style={{ background: "var(--node-ip)" }} /> ip · {graph.counts.ips}
          </span>
          {taintPath.length > 1 && (
            <span>
              <i className="legend-swatch" style={{ background: "var(--node-taint)" }} /> taint path
            </span>
          )}
        </div>
      )}

      {error && (
        <p className="field-legend" role="alert">
          Could not load the propagation tree: {error}
        </p>
      )}
      {tree?.caveat && <p className="field-legend">{tree.caveat}</p>}
    </div>
  );
}
