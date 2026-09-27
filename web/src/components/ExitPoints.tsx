/** "Trace to cash-out": where a seed's funds went, ranked against clusters
 *  tagged exchange/VASP (analysis/exit_point.py). A lead, not proof of who
 *  controls a cluster; untagged sinks are never named as services. */
import { useState } from "react";
import { Link } from "react-router-dom";
import { api } from "../api/client";
import type { ExitPoints, ExitTrace } from "../api/types";
import { formatId } from "../lib/formatId";
import { Chip, ErrorNote, Label, Notice } from "./ui";

const pct = (x: number) => `${(x * 100).toFixed(1)}%`;

function TraceBody({ trace, many }: { trace: ExitTrace; many: boolean }) {
  const mixes = Object.entries(trace.mixes).flatMap(([model, list]) =>
    list.map((m) => ({ model, ...m })),
  );
  return (
    <div style={{ marginTop: "var(--sp-3)" }}>
      {many && <Label>from member cluster {formatId(trace.seed)}</Label>}
      <p className="soft" style={{ fontSize: "var(--fs-small)" }}>
        seed outflow <span className="num">{trace.seed_amount.toFixed(4)}</span> BTC
      </p>
      {trace.candidates.length ? (
        <table className="data" aria-label="Cash-out candidates">
          <thead>
            <tr>
              <th>#</th>
              <th>cluster</th>
              <th>tag</th>
              <th className="num">haircut share</th>
              <th className="num">poison BTC</th>
              <th className="num">path confidence</th>
            </tr>
          </thead>
          <tbody>
            {trace.candidates.map((c) => (
              <tr key={c.entity_id}>
                <td className="num">{c.rank}</td>
                <td>
                  <Link className="mono" to={`/entities/${encodeURIComponent(c.entity_id)}`}>
                    {formatId(c.entity_id)}
                  </Link>
                </td>
                <td>
                  {c.tags.map((t) => (
                    <span key={t.label}>
                      {t.label} <span className="soft">({t.source}, {t.collected})</span>{" "}
                      {t.simulated && <Chip tone="caution">simulated</Chip>}
                    </span>
                  ))}
                  {c.conflict && <Chip tone="caution">conflicting tags</Chip>}
                </td>
                <td className="num">{pct(c.models.haircut.share)}</td>
                <td className="num">{c.models.poison.amount.toFixed(4)}</td>
                <td className="num">{c.models.haircut.path_confidence.toFixed(3)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      ) : (
        <p className="soft">No cluster tagged exchange/VASP was reached.</p>
      )}
      {mixes.map((m) => (
        <p key={`${m.model}-${m.from}-${m.txids[0]}`} className="soft">
          {m.model}: funds entered a CoinJoin from {formatId(m.from)} ({m.value.toFixed(4)} BTC).
          Not traced past the mix.
        </p>
      ))}
      {trace.sinks.length > 0 && (
        <p className="soft" style={{ fontSize: "var(--fs-small)" }}>
          Untagged sinks (kept traced value; not named as services):{" "}
          {trace.sinks.map((s) => `${formatId(s.entity_id)} ${pct(s.share_kept)}`).join(" · ")}
        </p>
      )}
    </div>
  );
}

export function ExitPointsBody({ data }: { data: ExitPoints }) {
  return (
    <>
      <p className="soft" style={{ fontSize: "var(--fs-small)" }}>
        {data.statement} {data.note}
      </p>
      {data.simulated_tags && (
        <Notice title="simulated tags">
          The tags behind these candidates come from a simulated bundle derived from generator
          ground truth. They are not intelligence.
        </Notice>
      )}
      {data.traces.map((t) => (
        <TraceBody key={t.seed} trace={t} many={data.traces.length > 1} />
      ))}
      <p style={{ marginTop: "var(--sp-3)" }}>
        <a className="btn btn-quiet" href={api.exitPacketUrl(data.kind, data.subject)}>
          investigator packet (PDF)
        </a>
      </p>
    </>
  );
}

export function ExitPointsSection({ kind, subject }: { kind: "entity" | "actor"; subject: string }) {
  const [data, setData] = useState<ExitPoints | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [running, setRunning] = useState(false);
  const run = async () => {
    setRunning(true);
    setError(null);
    try {
      setData(await api.exitPoints(kind, subject));
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setRunning(false);
    }
  };
  return (
    <section className="section" id="cash-out" aria-label="Trace to cash-out">
      <div className="section-head">
        <h2>Trace to cash-out</h2>
        <button type="button" className="btn" onClick={run} disabled={running}>
          {running ? "tracing" : data ? "trace again" : "trace to cash-out"}
        </button>
      </div>
      {error && <ErrorNote error={error} />}
      {data && <ExitPointsBody data={data} />}
    </section>
  );
}
