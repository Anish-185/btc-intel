/** Red team: let someone in the room attack the system while it is running.
 *
 *  A judge picks a typology, sets its parameters, and injects it into the
 *  dataset the detectors have already been run over. The page then shows what
 *  happened — including, and especially, when nothing happened. A miss is
 *  reported with every engine's score against the threshold it did not clear,
 *  because a detection demo where the detector cannot lose is not a demo.
 */
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { Link } from "react-router-dom";
import {
  redteamApi,
  type Injection,
  type RunEvent,
  type RunResult,
  type Scoreboard,
} from "../api/redteam";
import { ErrorNote, Label, Notice, RiskMeter, SkeletonRows } from "../components/ui";
import { Shell } from "../components/Shell";
import { useToast } from "../components/Toasts";
import { useApi } from "../lib/useApi";
import { formatId, patternLabel, score3 } from "../lib/format";

const ANCHORS = [
  { id: "inject", label: "Injection" },
  { id: "result", label: "Result" },
  { id: "scoreboard", label: "Scoreboard" },
];

/** Enough to draw the form before /redteam/typologies answers — the endpoint
 *  supplies the labels and the plain-English description. */
const TYPOLOGIES = ["ransomware_collector", "peel_chain", "layering", "coinjoin",
  "same_actor_cluster"];
const BROADCASTS = ["residential", "tor_exit", "hosting", "relay_heavy"];

const asOptions = (ids: string[]) => ids.map((id) => ({ id, label: patternLabel(id) }));

const DEFAULTS: Injection = {
  typology: "ransomware_collector",
  hops: 4,
  total_btc: 2,
  window_hours: 24,
  wallets: 8,
  broadcast: "residential",
};

const pick = <T,>(values: T[]): T => values[Math.floor(Math.random() * values.length)];
const between = (low: number, high: number, step = 1) =>
  Math.round((low + Math.random() * (high - low)) / step) * step;

/** Everything randomised, within the ranges the endpoint accepts. */
const surprise = (): Injection => ({
  typology: pick(TYPOLOGIES),
  hops: between(2, 8),
  total_btc: between(0.5, 20, 0.5),
  window_hours: between(1, 72),
  wallets: between(4, 30),
  broadcast: pick(BROADCASTS),
});

export function RedTeam() {
  const toast = useToast();
  const options = useApi((signal) => redteamApi.typologies(signal), []);
  const [form, setForm] = useState<Injection>(DEFAULTS);
  const [events, setEvents] = useState<RunEvent[]>([]);
  const [running, setRunning] = useState(false);
  const [result, setResult] = useState<RunResult | null>(null);
  const [failure, setFailure] = useState<string | null>(null);
  const [board, setBoard] = useState<Scoreboard | null>(null);
  const close = useRef<(() => void) | null>(null);

  const refreshBoard = useCallback(() => {
    redteamApi.scoreboard().then(setBoard, () => undefined);
  }, []);
  useEffect(() => {
    refreshBoard();
    return () => close.current?.();
  }, [refreshBoard]);

  const set = <K extends keyof Injection>(key: K, value: Injection[K]) =>
    setForm((f) => ({ ...f, [key]: value }));

  const start = async () => {
    setRunning(true);
    setEvents([]);
    setResult(null);
    setFailure(null);
    try {
      const { run_id } = await redteamApi.start(form);
      close.current = redteamApi.watch(run_id, (event) => {
        setEvents((list) => [...list, event]);
        if (event.type === "done" || event.type === "failed") {
          close.current?.();
          redteamApi.get(run_id).then(
            (run) => {
              setResult(run.result);
              setFailure(run.error);
              setRunning(false);
              refreshBoard();
              toast(
                run.error
                  ? `Run failed: ${run.error}`
                  : run.result?.detected
                    ? `Caught it in ${run.result.time_to_detect}s`
                    : `Not detected — the attack got through in ${run.result?.time_to_detect}s`,
              );
            },
            (error: Error) => {
              setFailure(error.message);
              setRunning(false);
            },
          );
        }
      });
    } catch (error) {
      setFailure((error as Error).message);
      setRunning(false);
    }
  };

  const reset = async () => {
    try {
      const done = await redteamApi.reset();
      setResult(null);
      setEvents([]);
      refreshBoard();
      toast(
        done.hashes_match
          ? `Dataset restored — ${done.restored.length} files, hashes match`
          : "Dataset restored, but the hashes do not match the snapshot",
      );
    } catch (error) {
      toast(`Could not reset: ${(error as Error).message}`);
    }
  };

  const about = useMemo(
    () => options.data?.typologies.find((t) => t.id === form.typology),
    [options.data, form.typology],
  );
  // Each typology reads a different subset of the controls; the endpoint says
  // which, so a control that would do nothing is disabled rather than lying.
  const uses = (control: string) => !about || about.uses.includes(control);
  const broadcastAbout = useMemo(
    () => options.data?.broadcast.find((b) => b.id === form.broadcast),
    [options.data, form.broadcast],
  );

  return (
    <Shell anchors={ANCHORS}>
      <section className="section" id="inject">
        <div className="section-head">
          <div>
            <Label>red team</Label>
            <h1 style={{ marginTop: "var(--sp-2)" }}>Inject an attack</h1>
          </div>
          <button type="button" className="btn btn-quiet" onClick={reset} disabled={running}>
            Reset dataset
          </button>
        </div>

        <p className="soft measure">
          Plant a laundering pattern in the dataset the detectors have already run over, then
          watch the stack re-run over it. Nothing is retrained: the GNN and the stacker score by
          inference, so what you see is the detector that exists.
        </p>

        {options.error && <ErrorNote error={options.error} />}

        <div className="filters" style={{ alignItems: "flex-end" }}>
          <label className="field">
            <span className="label">Typology</span>
            <select
              value={form.typology}
              onChange={(e) => set("typology", e.target.value)}
              disabled={running}
            >
              {(options.data?.typologies ?? asOptions(TYPOLOGIES)).map((t) => (
                <option key={t.id} value={t.id}>
                  {t.label}
                </option>
              ))}
            </select>
          </label>

          <label className="field">
            <span className="label">Hops · {form.hops}</span>
            <input
              type="range"
              min={2}
              max={8}
              step={1}
              value={form.hops}
              disabled={running || !uses("hops")}
              onChange={(e) => set("hops", Number(e.target.value))}
            />
          </label>

          <label className="field">
            <span className="label">Total BTC</span>
            <input
              type="number"
              min={0.01}
              max={10000}
              step={0.5}
              value={form.total_btc}
              disabled={running || !uses("total_btc")}
              onChange={(e) => set("total_btc", Number(e.target.value))}
            />
          </label>

          <label className="field">
            <span className="label">Window (hours)</span>
            <input
              type="number"
              min={1}
              max={720}
              step={1}
              value={form.window_hours}
              disabled={running || !uses("window_hours")}
              onChange={(e) => set("window_hours", Number(e.target.value))}
            />
          </label>

          <label className="field">
            <span className="label">Wallets</span>
            <input
              type="number"
              min={2}
              max={60}
              step={1}
              value={form.wallets}
              disabled={running || !uses("wallets")}
              onChange={(e) => set("wallets", Number(e.target.value))}
            />
          </label>

          <label className="field">
            <span className="label">Broadcast over</span>
            <select
              value={form.broadcast}
              onChange={(e) => set("broadcast", e.target.value)}
              disabled={running}
            >
              {(options.data?.broadcast ?? asOptions(BROADCASTS)).map((b) => (
                <option key={b.id} value={b.id}>
                  {b.label}
                </option>
              ))}
            </select>
          </label>
        </div>

        {(about || broadcastAbout) && (
          <p className="muted measure" style={{ fontSize: "var(--fs-small)" }}>
            {about?.about}
            {about && broadcastAbout ? " · " : ""}
            {broadcastAbout?.about}
          </p>
        )}

        <div className="stack" style={{ flexDirection: "row", gap: "var(--sp-2)", flexWrap: "wrap" }}>
          <button type="button" className="btn btn-primary" onClick={start} disabled={running}>
            {running ? "Running…" : "Inject and re-run"}
          </button>
          <button
            type="button"
            className="btn btn-ghost"
            onClick={() => setForm(surprise())}
            disabled={running}
          >
            Surprise me
          </button>
        </div>

        {events.length > 0 && (
          <div className="well" aria-live="polite">
            <p className="label">Progress</p>
            <table className="data">
              <tbody>
                {events
                  .filter((e) => e.type === "stage")
                  .map((event, i) => (
                    <tr key={`${event.name}-${i}`}>
                      <td className="mono">{event.name}</td>
                      <td className="soft">{event.detail ?? ""}</td>
                      <td className="num">
                        {event.seconds != null ? `${event.seconds.toFixed(2)}s` : ""}
                      </td>
                      <td className="num muted">{event.elapsed.toFixed(2)}s</td>
                    </tr>
                  ))}
              </tbody>
            </table>
          </div>
        )}
      </section>

      <section className="section" id="result">
        <div className="section-head">
          <h2>Result</h2>
          {result && (
            <span className="label">
              {result.transactions} transactions · {result.wallet_count} wallets · seed{" "}
              {result.seed}
            </span>
          )}
        </div>

        {failure ? (
          <ErrorNote error={failure} />
        ) : running && !result ? (
          <SkeletonRows rows={4} />
        ) : !result ? (
          <p className="soft measure">Nothing injected yet.</p>
        ) : result.detected ? (
          <Detected result={result} />
        ) : (
          <Missed result={result} />
        )}

        {result && <Origin result={result} />}
      </section>

      <section className="section" id="scoreboard">
        <div className="section-head">
          <h2>Scoreboard</h2>
          <span className="label">
            {board
              ? `${board.detected} of ${board.total} caught${
                  board.detection_rate == null ? "" : ` · ${Math.round(board.detection_rate * 100)}%`
                }`
              : "loading"}
          </span>
        </div>
        <Board board={board} />
      </section>
    </Shell>
  );
}

/** Caught: say where, why, and what the network side made of it. */
function Detected({ result }: { result: RunResult }) {
  const alert = result.alerts[0];
  const wallets = result.wallets.slice(0, 40).join(",");
  return (
    <>
      <Notice title="Detected">
        The injected {patternLabel(result.requested_typology)} raised{" "}
        {result.alerts.length === 1 ? "an alert" : `${result.alerts.length} alerts`} in{" "}
        {result.time_to_detect}s, against a threshold of {score3(result.threshold)}.
      </Notice>
      <div className="table-wrap">
        <table className="data">
          <thead>
            <tr>
              <th>Entity</th>
              <th>Risk</th>
              <th>Reason</th>
              <th />
            </tr>
          </thead>
          <tbody>
            {result.alerts.map((row) => (
              <tr key={row.entity_id}>
                <td className="mono" title={row.entity_id}>
                  {formatId(row.entity_id)}
                </td>
                <td>
                  <RiskMeter score={row.risk_score} />
                </td>
                <td className="reason-cell">{row.reason}</td>
                <td>
                  <Link to={`/entities/${encodeURIComponent(row.entity_id)}`} viewTransition>
                    Open case →
                  </Link>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      {alert && (
        <p>
          <Link
            className="btn btn-ghost"
            to={`/investigate?focus=${encodeURIComponent(alert.entity_id)}&highlight=${encodeURIComponent(wallets)}`}
            viewTransition
          >
            Show the injected wallets in the graph →
          </Link>
        </p>
      )}
    </>
  );
}

/** Missed: the honest half. Every engine's number against the bar it did not
 *  clear, so the room can argue with it. */
function Missed({ result }: { result: RunResult }) {
  return (
    <>
      <Notice title="Not detected">
        The injected {patternLabel(result.requested_typology)} did not raise an alert. It produced{" "}
        {result.entities.length} {result.entities.length === 1 ? "entity" : "entities"}, none of
        which reached the {score3(result.threshold)} alert threshold. Every engine's score is
        below — this is a result to discuss, not a failure to hide.
      </Notice>
      <div className="table-wrap">
        <table className="data">
          <thead>
            <tr>
              <th>Entity</th>
              <th className="num">Rules</th>
              <th className="num">Anomaly</th>
              <th className="num">GNN</th>
              <th className="num">Taint</th>
              <th className="num">Fused</th>
              <th className="num">Short of</th>
            </tr>
          </thead>
          <tbody>
            {result.entity_scores.map((row) => (
              <tr key={row.entity_id}>
                <td className="mono" title={row.entity_id}>
                  {formatId(row.entity_id)}
                </td>
                <td className="num">{score3(row.rule_score)}</td>
                <td className="num">{score3(row.anomaly_score)}</td>
                <td className="num">{score3(row.gnn_score)}</td>
                <td className="num">{score3(row.taint_score)}</td>
                <td className="num">{score3(row.risk_score)}</td>
                <td className="num">{score3(result.threshold - row.risk_score)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </>
  );
}

/** Whether origin estimation found the IP the injection actually broadcast
 *  from, and at what rank. A null rank is a property of the evidence. */
function Origin({ result }: { result: RunResult }) {
  const { origin } = result;
  return (
    <>
      <h3 style={{ marginTop: "var(--sp-5)" }}>Origin estimation</h3>
      <p className="soft measure">
        {origin.best_rank === 1
          ? "The estimator named the true origin IP outright."
          : origin.best_rank
            ? `The true origin IP appeared at rank ${origin.best_rank} among the candidates.`
            : "The true origin IP never appeared in the observed hops — no estimator can rank what was never seen."}{" "}
        {origin.named_exactly} of {origin.transactions} injected broadcasts named exactly.
      </p>
      <div className="table-wrap">
        <table className="data">
          <thead>
            <tr>
              <th>Transaction</th>
              <th>True origin</th>
              <th>Estimated</th>
              <th>Class</th>
              <th className="num">Confidence</th>
              <th className="num">Rank</th>
            </tr>
          </thead>
          <tbody>
            {origin.detail.map((row) => (
              <tr key={row.txid}>
                <td className="mono" title={row.txid}>
                  <Link to={`/tx/${encodeURIComponent(row.txid)}`} viewTransition>
                    {formatId(row.txid)}
                  </Link>
                </td>
                <td className="mono">{row.true_origin_ip}</td>
                <td className="mono">{row.estimated_origin_ip ?? "—"}</td>
                <td className="soft">{row.ip_class.replace(/_/g, " ")}</td>
                <td className="num">{score3(row.confidence)}</td>
                <td className="num">{row.rank ?? (row.observed ? "—" : "not observed")}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <p className="muted" style={{ fontSize: "var(--fs-small)" }}>{origin.caveat}</p>
    </>
  );
}

function Board({ board }: { board: Scoreboard | null }) {
  if (!board) return <SkeletonRows rows={3} />;
  if (!board.runs.length) return <p className="soft">No runs this session yet.</p>;
  return (
    <>
      <div className="table-wrap">
        <table className="data">
          <thead>
            <tr>
              <th>Typology</th>
              <th>Parameters</th>
              <th>Broadcast</th>
              <th>Detected</th>
              <th className="num">Time to detect</th>
              <th className="num">Origin rank</th>
            </tr>
          </thead>
          <tbody>
            {board.runs.map((run) => (
              <tr key={run.run_id}>
                <td>{patternLabel(run.typology)}</td>
                <td className="soft">
                  {run.params.hops} hops · {run.params.total_btc} BTC · {run.params.wallets}{" "}
                  wallets · {run.params.window_hours}h
                </td>
                <td className="soft">{run.params.broadcast.replace(/_/g, " ")}</td>
                <td>
                  {run.status !== "done"
                    ? run.status
                    : run.detected
                      ? "yes"
                      : "no"}
                </td>
                <td className="num">
                  {run.time_to_detect == null ? "—" : `${run.time_to_detect.toFixed(2)}s`}
                </td>
                <td className="num">{run.origin_rank ?? "—"}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      <h3 style={{ marginTop: "var(--sp-5)" }}>Detection rate per typology</h3>
      <div className="table-wrap">
        <table className="data">
          <thead>
            <tr>
              <th>Typology</th>
              <th className="num">Runs</th>
              <th className="num">Detected</th>
              <th className="num">Rate</th>
            </tr>
          </thead>
          <tbody>
            {Object.entries(board.by_typology).map(([typology, row]) => (
              <tr key={typology}>
                <td>{patternLabel(typology)}</td>
                <td className="num">{row.runs}</td>
                <td className="num">{row.detected}</td>
                <td className="num">
                  {row.detection_rate == null ? "—" : `${Math.round(row.detection_rate * 100)}%`}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </>
  );
}
