/** What the selected node is, in the order an investigator reads it.
 *
 *  The panel deliberately repeats the case page's language: the reason comes
 *  from fusion/explain.py through the entity endpoint, and IP associations are
 *  worded "associated with", never "belongs to".
 */
import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { api } from "../../api/client";
import type { EntityDetail } from "../../api/types";
import { formatId } from "../../lib/formatId";
import { RiskMeter } from "../ui";
import type { NodeData } from "./model";

export function SidePanel({
  node,
  onClose,
  onExpand,
  onTrace,
  onHide,
  onPin,
  onTaintSeed,
  onCopy,
  pinned,
}: {
  node: NodeData;
  onClose: () => void;
  onExpand: (id: string) => void;
  onTrace: (id: string, direction: "forward" | "backward") => void;
  onHide: (id: string) => void;
  onPin: (id: string) => void;
  onTaintSeed: (id: string) => void;
  onCopy: (value: string) => void;
  pinned: boolean;
}) {
  const [detail, setDetail] = useState<EntityDetail | null>(null);
  const [error, setError] = useState<string | null>(null);
  const entityId = (node.entity_id as string | undefined) ?? node.id;

  useEffect(() => {
    setDetail(null);
    setError(null);
    if (node.type !== "wallet") return;
    const controller = new AbortController();
    api
      .entity(entityId, controller.signal)
      .then(setDetail)
      .catch((e: Error) => {
        if (!controller.signal.aborted) setError(e.message);
      });
    return () => controller.abort();
  }, [entityId, node.type]);

  return (
    <aside className="graph-side" aria-label="Selected node">
      <div className="graph-side-head">
        <p className="label">{node.type}</p>
        <button type="button" className="btn btn-quiet" onClick={onClose} aria-label="Close panel">
          ✕
        </button>
      </div>

      <p className="mono graph-side-id" title={node.id}>
        {formatId(node.id, { head: 18, tail: 8 })}
      </p>

      {node.type === "wallet" && (
        <div className="graph-side-risk">
          <RiskMeter score={Number(node.risk ?? 0)} cells={8} />
          {!node.alerted && <p className="muted">No engine flagged this wallet.</p>}
        </div>
      )}

      {node.type === "ip" && (
        <p className="soft">
          Broadcast address{node.country ? `, seen in ${node.country}` : ""}
          {node.asn ? ` (ASN ${node.asn})` : ""}. Links from here are{" "}
          <strong>associated with</strong> the transactions they broadcast — an association to
          investigate, not an attribution.
        </p>
      )}

      {node.type === "transaction" && (
        <p className="soft">
          A transaction, drawn as a connector: the wallets on either side are joined through it,
          never directly to each other.
        </p>
      )}

      {error && <p className="muted">Could not load the case: {error}</p>}

      {detail && (
        <>
          <p className="label graph-side-label">reason</p>
          <p className="soft">{detail.reason ?? "No alert was raised for this entity."}</p>

          {detail.evidence.length > 0 && (
            <>
              <p className="label graph-side-label">evidence</p>
              <ul className="graph-side-list">
                {detail.evidence.slice(0, 6).map((item) => (
                  <li key={item} className="mono" title={item}>
                    {formatId(item, { head: 14, tail: 6 })}
                  </li>
                ))}
              </ul>
            </>
          )}

          <Link className="btn btn-ghost bracket graph-side-open" to={`/entities/${encodeURIComponent(entityId)}`}>
            Open the full case →
          </Link>
        </>
      )}

      {/* Every action the right-click menu offers is here too: a radial menu
          needs a held mouse button, which rules out keyboard users and is
          awkward on a tablet. */}
      <div className="graph-side-actions">
        <button type="button" className="btn btn-quiet" onClick={() => onExpand(node.id)}>
          expand
        </button>
        {node.type === "wallet" && (
          <>
            <button type="button" className="btn btn-quiet" onClick={() => onTrace(node.id, "forward")}>
              trace →
            </button>
            <button type="button" className="btn btn-quiet" onClick={() => onTrace(node.id, "backward")}>
              trace ←
            </button>
            <button
              type="button"
              className="btn btn-quiet"
              title="Recompute taint as if this wallet were on the watchlist. Hypothetical: nothing is stored."
              onClick={() => onTaintSeed(node.id)}
            >
              taint seed
            </button>
          </>
        )}
        <button
          type="button"
          className="btn btn-quiet"
          aria-pressed={pinned}
          title="Hold this node in place while the layout moves everything else"
          onClick={() => onPin(node.id)}
        >
          {pinned ? "unpin" : "pin"}
        </button>
        <button type="button" className="btn btn-quiet" onClick={() => onCopy(node.id)}>
          copy
        </button>
        <button type="button" className="btn btn-quiet" onClick={() => onHide(node.id)}>
          hide
        </button>
      </div>
    </aside>
  );
}
