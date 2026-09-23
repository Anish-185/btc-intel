/** Live monitoring: traffic arriving, and what the system made of it.
 *
 *  The rest of the console looks at a dataset that has already been analysed.
 *  This page is the other half of the problem — metadata keeps coming, and an
 *  analyst wants to know within seconds whether any of it matters.
 *
 *  Everything on screen is an event the API pushed: a file appearing, the rows
 *  it contributed, the alerts it raised. Nothing is polled into existence, so
 *  a quiet feed is genuinely quiet rather than uncertain.
 */
import { useCallback, useEffect, useRef, useState } from "react";
import { Link } from "react-router-dom";
import {
  monitorApi,
  type FeedEvent,
  type MonitorStatus,
} from "../api/monitor";
import { ErrorNote, Label, Notice, RiskMeter, SkeletonRows, Stat } from "../components/ui";
import { Shell } from "../components/Shell";
import { useToast } from "../components/Toasts";
import { formatId, patternLabel } from "../lib/format";

const ANCHORS = [
  { id: "watch", label: "The watch" },
  { id: "feed", label: "Arrivals" },
];

/** Newest first, and never unbounded: a feed left running all afternoon must
 *  not turn into a memory leak with a scrollbar. */
const FEED_LIMIT = 100;

export function Monitor() {
  const toast = useToast();
  const [status, setStatus] = useState<MonitorStatus | null>(null);
  const [events, setEvents] = useState<FeedEvent[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const close = useRef<(() => void) | null>(null);

  const refresh = useCallback(() => {
    monitorApi.status().then(setStatus, (e: Error) => setError(e.message));
  }, []);

  useEffect(() => {
    monitorApi.feed().then(
      (data) => {
        setEvents([...data.events].reverse().slice(0, FEED_LIMIT));
        setStatus(data.status);
      },
      (e: Error) => setError(e.message),
    );
    close.current = monitorApi.watch((event) => {
      setEvents((list) => [event, ...list].slice(0, FEED_LIMIT));
      if (event.type === "processed" || event.type === "stopped" || event.type === "started") {
        refresh();
      }
    });
    return () => close.current?.();
  }, [refresh]);

  const act = async (what: "start" | "stop" | "simulate") => {
    setBusy(true);
    try {
      if (what === "simulate") {
        const { file } = await monitorApi.simulate();
        toast(`Dropped ${file.split("/").pop()} into the inbox`);
      } else {
        setStatus(await monitorApi[what]());
        toast(what === "start" ? "Watching for arrivals" : "Stopped watching");
      }
    } catch (e) {
      toast(`Could not ${what}: ${(e as Error).message}`);
    } finally {
      setBusy(false);
    }
  };

  const running = status?.running ?? false;

  return (
    <Shell anchors={ANCHORS}>
      <section className="section" id="watch">
        <div className="section-head">
          <div>
            <Label>live monitoring</Label>
            <h1 style={{ marginTop: "var(--sp-2)" }}>
              {running ? "Watching" : "Not watching"}
            </h1>
          </div>
          <div className="stack" style={{ flexDirection: "row", gap: "var(--sp-2)" }}>
            <button
              type="button"
              className={running ? "btn btn-quiet" : "btn btn-primary"}
              onClick={() => act(running ? "stop" : "start")}
              disabled={busy}
            >
              {running ? "Stop" : "Start watching"}
            </button>
            <button type="button" className="btn btn-ghost" onClick={() => act("simulate")}
                    disabled={busy}>
              Simulate an arrival
            </button>
          </div>
        </div>

        {error && <ErrorNote error={error} />}

        <p className="soft measure">
          Anything copied into{" "}
          <code className="mono">{status?.inbox ?? "the inbox"}</code> is parsed, folded into
          the graph the console already holds, and scored — without re-running the pipeline and
          without retraining anything. A file that arrives twice contributes only what has not
          been seen before.
        </p>

        <div className="stat-grid">
          <Stat title="Files" sublabel="handled this session" value={status?.files ?? 0} />
          <Stat title="Transactions" sublabel="new" value={status?.transactions ?? 0} />
          <Stat title="Alerts" sublabel="raised by arrivals" value={status?.alerts ?? 0} />
          <Stat title="Duplicates" sublabel="already seen" value={status?.duplicates ?? 0} />
        </div>

        {status?.pending?.length ? (
          <Notice title="Waiting in the inbox">
            {status.pending.join(", ")} — picked up within {status.poll_seconds ?? 2}s of
            settling.
          </Notice>
        ) : null}
        {status?.errors ? (
          <Notice title={`${status.errors} file(s) could not be handled`}>
            They are in the archive under <code className="mono">failed/</code>; the watch kept
            running.
          </Notice>
        ) : null}
      </section>

      <section className="section" id="feed">
        <div className="section-head">
          <h2>Arrivals</h2>
          <span className="label">{events.length ? `${events.length} events` : "nothing yet"}</span>
        </div>

        {!events.length ? (
          running ? (
            <SkeletonRows rows={3} />
          ) : (
            <p className="soft measure">
              Start the watch, then drop a file in — or press <em>Simulate an arrival</em> to
              have the system generate one batch of fresh traffic for itself.
            </p>
          )
        ) : (
          <ol className="stack" style={{ gap: "var(--sp-3)", listStyle: "none", padding: 0 }}>
            {events.map((event, i) => (
              <li key={`${event.at}-${i}`}>
                <Arrival event={event} />
              </li>
            ))}
          </ol>
        )}
      </section>
    </Shell>
  );
}

/** One line of the feed. A file that raised nothing says so — a monitoring
 *  feed that only speaks when it finds something cannot be told apart from one
 *  that has silently stopped. */
function Arrival({ event }: { event: FeedEvent }) {
  const time = event.at?.slice(11, 19) ?? "";
  if (event.type === "error") {
    return (
      <div className="well">
        <p className="label">{time} · could not handle {event.name}</p>
        <p className="soft">{event.error}</p>
      </div>
    );
  }
  if (event.type === "started" || event.type === "stopped") {
    return (
      <p className="muted" style={{ fontSize: "var(--fs-small)" }}>
        {time} · {event.type === "started" ? `watching ${event.inbox}` : "watch stopped"}
      </p>
    );
  }
  if (event.type === "file") {
    return (
      <p className="muted" style={{ fontSize: "var(--fs-small)" }}>
        {time} · reading <span className="mono">{event.name}</span>
      </p>
    );
  }

  const alerts = event.alerts ?? [];
  return (
    <div className="well">
      <div className="section-head" style={{ marginBottom: "var(--sp-2)" }}>
        <p className="label">
          {time} · <span className="mono">{event.file}</span>
        </p>
        <span className="label">
          {event.new_rows ?? 0} rows · {event.transactions ?? 0} tx · {event.seconds ?? 0}s
        </span>
      </div>

      {event.quarantined ? (
        <p className="soft">
          {event.quarantined} row(s) quarantined{event.reason ? ` — ${event.reason}` : ""}.
        </p>
      ) : null}
      {event.duplicates ? (
        <p className="muted" style={{ fontSize: "var(--fs-small)" }}>
          {event.duplicates} transaction(s) already seen, not counted twice.
        </p>
      ) : null}

      {alerts.length ? (
        <table className="data">
          <tbody>
            {alerts.slice(0, 6).map((alert) => (
              <tr key={alert.entity_id}>
                <td className="mono" title={alert.entity_id}>
                  <Link to={`/entities/${encodeURIComponent(alert.entity_id)}`} viewTransition>
                    {formatId(alert.entity_id)}
                  </Link>
                </td>
                <td>
                  <RiskMeter score={alert.risk_score} />
                </td>
                <td className="soft">
                  {(alert.pattern_types ?? []).map(patternLabel).join(", ")}
                </td>
                <td className="reason-cell">{alert.reason}</td>
              </tr>
            ))}
          </tbody>
        </table>
      ) : (
        <p className="muted" style={{ fontSize: "var(--fs-small)" }}>
          nothing in this file cleared the alert threshold
        </p>
      )}
    </div>
  );
}
