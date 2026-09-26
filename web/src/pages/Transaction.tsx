/** One transaction's broadcast: where it was seen, and the best guess at
 *  where it started — with the size of that guess stated plainly. */
import { Suspense, lazy, useMemo } from "react";
import { Link, useParams } from "react-router-dom";
import type { ElementDefinition, LayoutOptions } from "cytoscape";
import { api } from "../api/client";
import { useApi } from "../lib/useApi";
import { ipClass } from "../lib/format";
import { formatId } from "../lib/formatId";
import { token } from "../lib/tokens";
import { Chip, ErrorNote, Label, SkeletonRows, ValidityChip, validityLabel } from "../components/ui";
import type { Answer, Propagation } from "../api/types";
import { Shell } from "../components/Shell";
import { FingerprintPanel } from "../components/Fingerprint";

const FieldGraph = lazy(() =>
  import("../components/FieldGraph").then((m) => ({ default: m.FieldGraph })),
);

const roleColour = (role: string) =>
  token(
    role === "origin"
      ? "--node-taint"
      : role === "runner_up"
        ? "--node-ip"
        : "--node-transaction",
  );

export function Transaction() {
  const { txid = "" } = useParams();
  const { data, error, loading } = useApi((signal) => api.propagation(txid, signal), [txid]);

  const elements = useMemo<ElementDefinition[]>(
    () =>
      data
        ? [
            ...data.elements.nodes.map(({ data: node }) => ({
              data: {
                ...node,
                colour: roleColour(String(node.role)),
                size: node.role === "origin" ? 14 : node.role === "runner_up" ? 10 : 7,
                focus: node.role === "origin" ? 1 : 0,
              },
            })),
            ...data.elements.edges.map(({ data: edge }) => ({ data: edge })),
          ]
        : [],
    [data],
  );

  const layout = useMemo<LayoutOptions>(
    () => (// Wide separation on purpose: these labels are full IP
            // addresses and they must not overlap.
            { name: "dagre", rankDir: "TB", nodeSep: 86, rankSep: 64 }) as unknown as LayoutOptions,
    [],
  );

  return (
    <Shell>
      <section className="section">
        <div className="section-head">
          <div>
            <Label>transaction</Label>
            <h1 className="mono" title={txid} style={{ marginTop: "var(--sp-2)" }}>
              {formatId(txid, { head: 24, tail: 10 })}
            </h1>
          </div>
          {data && (
            <span style={{ display: "flex", gap: "var(--sp-2)", flexWrap: "wrap" }}>
              <Chip>{data.estimator}</Chip>
              <Chip>{data.n_observations} observations</Chip>
              <ValidityChip validity={data.validity} />
              {data.low_confidence_origin && <Chip tone="caution">⚠ low confidence origin</Chip>}
              {data.anonymized_entry_point && <Chip tone="caution">⚠ anonymized entry point</Chip>}
            </span>
          )}
        </div>

        {error ? (
          <ErrorNote error={error} />
        ) : loading || !data ? (
          <SkeletonRows rows={4} />
        ) : (
          <>
            <div className="stat-grid" style={{ marginBottom: "var(--sp-4)" }}>
              <OriginStat data={data} />
              <div className="stat">
                <h3>Confidence</h3>
                <Label>{data.calibration_basis}</Label>
                <p className="stat-value" style={{ fontSize: "1.75rem" }}>
                  {data.confidence.toFixed(2)}
                </p>
              </div>
              <div className="stat">
                <h3>Attribution confidence</h3>
                <Label>what correlation may treat as evidence</Label>
                <p className="stat-value" style={{ fontSize: "1.75rem" }}>
                  {data.attribution_confidence.toFixed(2)}
                </p>
              </div>
              <div className="stat">
                <h3>Validity</h3>
                <Label>{validityLabel(data.validity)}</Label>
                <ul className="soft" style={{ marginTop: "var(--sp-3)", fontSize: "var(--fs-small)" }}>
                  {data.validity.evidence.map((line) => (
                    <li key={line}>{line}</li>
                  ))}
                </ul>
              </div>
            </div>

            <div className="field-panel">
              <div className="field-toolbar">
                <span className="label">observed propagation</span>
                {data.runner_ups.length > 0 && (
                  <span className="label">
                    runner-ups:{" "}
                    {data.runner_ups.map((r, i) => (
                      <span key={r.ip}>
                        {i > 0 && ", "}
                        <Link to={peerLink(r.ip)}>{r.ip}</Link>
                      </span>
                    ))}
                  </span>
                )}
              </div>
              <Suspense fallback={<div style={{ height: 420 }} aria-busy="true" />}>
                <FieldGraph elements={elements} layout={layout} height={420} />
              </Suspense>
              <p className="field-legend">{data.caveat}</p>
            </div>
          </>
        )}
        <TxFingerprintBlock txid={txid} />
        <CaptureOrigins txid={txid} />
      </section>
    </Shell>
  );
}

/** How the transaction was built; absent when the served dataset has no
 *  structure for it (a capture-only txid). */
function TxFingerprintBlock({ txid }: { txid: string }) {
  const { data, error } = useApi((signal) => api.fingerprint(txid, signal), [txid]);
  if (error || !data) return null;
  return (
    <div className="stat-grid" style={{ marginTop: "var(--sp-5)" }}>
      <FingerprintPanel answer={data} />
    </div>
  );
}

const peerLink = (peer: string) => `/peers/${encodeURIComponent(peer)}`;

/** The origination model's answer, once per capture this txid was seen in —
 *  the same answers a peer profile's "originated" lists. */
function CaptureOrigins({ txid }: { txid: string }) {
  const { data, error } = useApi((signal) => api.origination(txid, signal), [txid]);
  if (error || !data || data.captures.length === 0) return null;
  return (
    <div style={{ marginTop: "var(--sp-5)" }}>
      <h2>Origination model, per capture</h2>
      <div className="table-wrap">
        <table className="data">
          <thead>
            <tr>
              <th>Capture · observer</th>
              <th>Origin</th>
              <th>Validity</th>
              <th className="num">Probability</th>
            </tr>
          </thead>
          <tbody>
            {data.captures.map((c) => (
              <tr key={c.capture_id}>
                <td className="soft">
                  {c.capture_id} · {c.observer} · {c.provenance}
                </td>
                <td>
                  {c.answer ? (
                    <AnswerCell answer={c.answer} />
                  ) : (
                    <span className="soft">withheld: {c.abstention_reason}</span>
                  )}
                </td>
                <td>
                  <ValidityChip validity={c.validity} />
                </td>
                <td className="num" title={c.calibration_basis}>{c.probability.toFixed(2)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

function AnswerCell({ answer }: { answer: Answer }) {
  if (answer.kind === "onion_identity") {
    return (
      <>
        onion identity <Link className="mono" to={peerLink(answer.onion!)}>{answer.onion}</Link>
      </>
    );
  }
  const prefix = answer.kind === "broadcasting_peer"
    ? "broadcasting peer (input ownership not attributable) "
    : "peer ";
  return (
    <>
      {prefix}
      <Link className="mono" to={peerLink(answer.ip!)}>{answer.ip}</Link>
    </>
  );
}

/** The origin, shaped by what it may claim. A QUALIFIED answer is never shown
 *  as an IP attribution: an onion identity has no IP class, and a CoinJoin's
 *  broadcaster says in words that the inputs' owners are not attributable. */
function OriginStat({ data }: { data: Propagation }) {
  const { answer } = data;
  const big = { marginTop: "var(--sp-3)", fontSize: "var(--fs-h2)" } as const;
  if (answer === null) {
    return (
      <div className="stat">
        <h3>Origin withheld</h3>
        <Label>{validityLabel(data.validity)}</Label>
        <p className="num" style={big}>—</p>
      </div>
    );
  }
  if (answer.kind === "onion_identity") {
    return (
      <div className="stat">
        <h3>Onion identity</h3>
        <Label>Tor hidden service · not for IP-level follow-up</Label>
        <p className="mono" style={{ ...big, fontSize: "var(--fs-body)", wordBreak: "break-all" }}>
          <Link to={peerLink(answer.onion!)}>{answer.onion}</Link>
        </p>
      </div>
    );
  }
  if (answer.kind === "broadcasting_peer") {
    return (
      <div className="stat">
        <h3>Broadcasting peer</h3>
        <Label>CoinJoin · input ownership not attributable</Label>
        <p className="num" style={big}><Link to={peerLink(answer.ip!)}>{answer.ip}</Link></p>
      </div>
    );
  }
  return (
    <div className="stat">
      <h3>Estimated origin</h3>
      <Label>{ipClass(data.ip_class).label}</Label>
      <p className="num" style={big}><Link to={peerLink(answer.ip!)}>{answer.ip}</Link></p>
    </div>
  );
}
