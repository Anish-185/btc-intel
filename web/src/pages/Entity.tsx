/** One case, in the order an investigator reads it: how risky, why, on what
 *  evidence, connected to what — and only then, separately, which addresses it
 *  was seen broadcasting from. */
import { Suspense, lazy, useState } from "react";
import { Link, useParams } from "react-router-dom";
import { api } from "../api/client";
import { useApi } from "../lib/useApi";
import { useEnter } from "../lib/motion";
import { cssName } from "../components/AlertTable";
import { patternLabel } from "../lib/format";
import { formatId } from "../lib/formatId";
import { Gauge } from "../components/Gauge";
import { EvidenceList } from "../components/EvidenceList";
import { LeadsPanel } from "../components/LeadsPanel";
import { FingerprintHidden, FingerprintSplit } from "../components/Fingerprint";
import { Chip, CopyValue, ErrorNote, Label, SkeletonRows } from "../components/ui";
import { Shell } from "../components/Shell";
import { useToast } from "../components/Toasts";

// The graph engine is the heaviest thing the console loads, and only this page
// needs it.
const GraphPanel = lazy(() =>
  import("../components/GraphPanel").then((m) => ({ default: m.GraphPanel })),
);

const ANCHORS = [
  { id: "summary", label: "Summary" },
  { id: "reason", label: "Reason" },
  { id: "evidence", label: "Evidence" },
  { id: "graph", label: "Link analysis" },
  { id: "leads", label: "Investigative leads" },
  { id: "fingerprints", label: "Construction fingerprints" },
];

const SIGNALS: [keyof NonNullable<ReturnType<typeof scoresOf>>, string][] = [
  ["rule_score", "rules"],
  ["anomaly_score", "anomaly"],
  ["gnn_score", "gnn"],
  ["taint_score", "taint"],
];

const scoresOf = (s: Record<string, number | null> | undefined) => s;

export function Entity() {
  const { id = "" } = useParams();
  const toast = useToast();
  const [hops, setHops] = useState(2);
  const detail = useApi((signal) => api.entity(id, signal), [id]);
  const graph = useApi((signal) => api.entityGraph(id, hops, signal), [id, hops]);

  const summary = useEnter<HTMLElement>(0);
  const reason = useEnter<HTMLElement>(1);
  const evidence = useEnter<HTMLElement>(2);

  if (detail.error) {
    return (
      <Shell>
        <ErrorNote error={detail.error} />
      </Shell>
    );
  }

  const data = detail.data;
  const score = data?.scores.risk_score ?? 0;

  return (
    <Shell anchors={ANCHORS}>
      <section className="section" id="summary" ref={summary}>
        <div className="entity-head">
          <div>
            <Label>{data?.entity_type === "wallet" ? "single wallet" : "wallet cluster"}</Label>
            <h1
              className="mono"
              style={{ marginTop: "var(--sp-2)", viewTransitionName: `entity-${cssName(id)}` }}
              title={id}
            >
              {formatId(id, { head: 20, tail: 8 })}
            </h1>
            <p className="stack" style={{ gap: "var(--sp-2)", marginTop: "var(--sp-3)" }}>
              <span style={{ display: "flex", flexWrap: "wrap", gap: "var(--sp-2)" }}>
                {data?.pattern_types.map((pattern) => (
                  <Chip key={pattern}>{patternLabel(pattern)}</Chip>
                ))}
                {data?.flag && <Chip tone="caution">⚠ {data.flag}</Chip>}
                {data && !data.alerted && <Chip>not alerted</Chip>}
              </span>
              <span className="soft" style={{ fontSize: "var(--fs-small)" }}>
                {data ? `${data.wallets.length} wallet${data.wallets.length === 1 ? "" : "s"}` : "—"}
                {data?.scores.top_signal ? ` · strongest signal: ${data.scores.top_signal}` : ""}
              </span>
            </p>
          </div>

          <div style={{ display: "flex", alignItems: "center", gap: "var(--sp-4)" }}>
            <span style={{ viewTransitionName: `score-${cssName(id)}` }}>
              <Gauge score={score} />
            </span>
            <a
              className="btn btn-ghost bracket"
              href={api.reportUrl(id)}
              onClick={() => toast("Case report downloading")}
            >
              Export case report ↓
            </a>
          </div>
        </div>

        {data && (
          <div className="stat-grid" style={{ marginTop: "var(--sp-5)" }}>
            {SIGNALS.map(([key, label]) => (
              <div className="stat" key={String(key)}>
                <h3>{label}</h3>
                <Label>engine score</Label>
                <p className="stat-value" style={{ fontSize: "1.5rem" }}>
                  {(data.scores[key as keyof typeof data.scores] as number | null)?.toFixed(3) ?? "—"}
                </p>
              </div>
            ))}
          </div>
        )}
      </section>

      <section className="section" id="reason" ref={reason}>
        <div className="section-head">
          <h2>Reason</h2>
          <span className="label">why this entity is in the queue</span>
        </div>
        {detail.loading ? (
          <SkeletonRows rows={2} />
        ) : (
          <div className="measure stack" style={{ gap: "var(--sp-3)" }}>
            <p>{data?.reason ?? "No alert was raised for this entity."}</p>
            {data?.taint_path && data.taint_path.length > 1 && (
              <p className="taint-path">
                <span className="label">taint path</span>
                {data.taint_path.map((step, i) => (
                  <span key={`${step}-${i}`}>
                    {i > 0 && <span aria-hidden="true"> ⟶ </span>}
                    <span className="id-chip" title={step}>
                      {formatId(step)}
                    </span>
                  </span>
                ))}
              </p>
            )}
            {data?.caveat && <p className="muted" style={{ fontSize: "var(--fs-small)" }}>{data.caveat}</p>}
          </div>
        )}
      </section>

      <section className="section" id="evidence" ref={evidence}>
        <div className="section-head">
          <h2>Evidence</h2>
          <span className="label">{data?.evidence.length ?? 0} items</span>
        </div>
        {detail.loading ? <SkeletonRows rows={4} /> : <EvidenceList items={data?.evidence ?? []} />}
      </section>

      <section className="section" id="graph">
        <div className="section-head">
          <h2>Link analysis</h2>
          <span className="field" style={{ gap: "var(--sp-2)" }}>
            <Link
              className="btn btn-ghost bracket"
              to={`/investigate?focus=${encodeURIComponent(id)}`}
              viewTransition
            >
              Investigate →
            </Link>
            <span className="label">hops</span>
            {[1, 2, 3].map((n) => (
              <button
                key={n}
                type="button"
                className="btn btn-quiet"
                aria-pressed={hops === n}
                onClick={() => setHops(n)}
              >
                {n}
              </button>
            ))}
          </span>
        </div>
        {graph.error ? (
          <ErrorNote error={graph.error} />
        ) : graph.loading || !graph.data ? (
          <div className="field-panel" style={{ height: 420 }} aria-busy="true" />
        ) : (
          <Suspense fallback={<div className="field-panel" style={{ height: 420 }} aria-busy="true" />}>
            <GraphPanel graph={graph.data} taintPath={data?.taint_path ?? []} riskScore={score} />
          </Suspense>
        )}
      </section>

      <section className="section" id="leads">
        <LeadsPanel leads={data?.leads ?? []} />
      </section>

      {data?.fingerprints && (
        <section className="section" id="fingerprints">
          <div className="section-head">
            <h2>Construction fingerprints</h2>
            <span className="label">how this cluster's spends were built · not which software, not who</span>
          </div>
          {data.fingerprints.console_display ? (
            <FingerprintSplit dist={data.fingerprints} empty="No spend of these wallets in the data." />
          ) : (
            <FingerprintHidden />
          )}
          <p className="soft" style={{ marginTop: "var(--sp-2)" }}>
            Cluster confidence{" "}
            <span className="num">{data.fingerprints.cluster_confidence.toFixed(2)}</span> —{" "}
            {data.fingerprints.note}.
          </p>
          {data.fingerprints.conflicts.length > 0 && (
            <ul className="soft" style={{ fontSize: "var(--fs-small)" }}>
              {data.fingerprints.conflicts.map((c) => (
                <li key={`${c.txid}-${c.heuristic}`}>
                  {c.heuristic.replace(/_/g, " ")} merge in{" "}
                  <Link className="mono" to={`/tx/${c.txid}`}>{formatId(c.txid)}</Link> joins wallets
                  spent by {Object.keys(c.fingerprints).join(" and ")} constructions
                </li>
              ))}
            </ul>
          )}
        </section>
      )}

      {data && (
        <section className="section">
          <div className="section-head">
            <h2>Wallets</h2>
            <span className="label">addresses in this cluster</span>
          </div>
          <div className="evidence-list">
            {data.wallets.slice(0, 40).map((wallet) => (
              <div className="evidence-item" key={wallet}>
                <span className="label">wallet</span>
                <span className="value" title={wallet}>
                  {formatId(wallet, { head: 24, tail: 10 })}
                </span>
                <CopyValue value={wallet} />
              </div>
            ))}
          </div>
          {data.wallets.length > 40 && (
            <p className="muted" style={{ marginTop: "var(--sp-2)", fontSize: "var(--fs-small)" }}>
              Showing 40 of {data.wallets.length}. The case report carries the full list.
            </p>
          )}
        </section>
      )}
    </Shell>
  );
}
