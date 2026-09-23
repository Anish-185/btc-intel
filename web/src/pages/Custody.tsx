/** Chain of custody: what this system did, and whether the record still holds.
 *
 *  A risk score is a lead. A lead an analyst acts on becomes part of a case,
 *  and a case has to answer where its data came from, whether it changed, and
 *  who touched it. This page is that answer — the ledger, in order, with the
 *  verification run against it.
 *
 *  It is deliberately unglamorous. The interesting states are the bad ones: a
 *  broken chain and a changed file are drawn as prominently as a clean run,
 *  because a page that can only show "verified" is not evidence of anything.
 */
import { useCallback, useEffect, useState } from "react";
import {
  custodyApi,
  type CustodyEntry,
  type CustodyVerification,
} from "../api/monitor";
import { ErrorNote, Label, Notice, SkeletonRows } from "../components/ui";
import { Shell } from "../components/Shell";
import { useApi } from "../lib/useApi";

const ANCHORS = [
  { id: "seal", label: "Verification" },
  { id: "ledger", label: "The record" },
];

const ACTION_LABEL: Record<string, string> = {
  ingest: "data acquired",
  analysis: "pipeline run",
  verdict: "analyst verdict",
  "export.case_report": "case report exported",
  "redteam.inject": "red-team injection",
  "redteam.reset": "dataset restored",
  "monitor.arrival": "traffic arrived",
};

export function Custody() {
  const log = useApi((signal) => custodyApi.log(signal), []);
  const [check, setCheck] = useState<CustodyVerification | null>(null);
  const [checking, setChecking] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const verify = useCallback(() => {
    setChecking(true);
    custodyApi.verify().then(
      (result) => {
        setCheck(result);
        setChecking(false);
      },
      (e: Error) => {
        setError(e.message);
        setChecking(false);
      },
    );
  }, []);

  useEffect(verify, [verify]);

  const entries = [...(log.data?.entries ?? [])].reverse();

  return (
    <Shell anchors={ANCHORS}>
      <section className="section" id="seal">
        <div className="section-head">
          <div>
            <Label>chain of custody</Label>
            <h1 style={{ marginTop: "var(--sp-2)" }}>
              {checking
                ? "Checking…"
                : check?.chain_intact
                  ? "The record is intact"
                  : check
                    ? "The record has been altered"
                    : "Not checked"}
            </h1>
          </div>
          <button type="button" className="btn btn-quiet" onClick={verify} disabled={checking}>
            Verify again
          </button>
        </div>

        {error && <ErrorNote error={error} />}

        <p className="soft measure">
          Every entry carries the hash of the one before it, so an edited or deleted entry
          cannot be made to verify — the next entry's hash was computed over the original.
          Source files are hashed when they are read, and re-hashed here.
        </p>

        {check && !check.chain_intact && (
          <Notice title={`The chain breaks at entry ${check.broken_at}`}>
            Everything before it still verifies. From that entry on, the record cannot be
            relied on.
          </Notice>
        )}
        {check?.files_changed?.length ? (
          <Notice title={`${check.files_changed.length} file(s) no longer match their hash`}>
            {check.files_changed.join(", ")}. {check.note}
          </Notice>
        ) : null}
        {check?.files_missing?.length ? (
          <Notice title={`${check.files_missing.length} recorded file(s) are gone`}>
            {check.files_missing.join(", ")}
          </Notice>
        ) : null}

        {check && (
          <dl className="stack" style={{ gap: "var(--sp-2)" }}>
            <div>
              <Label>entries</Label>
              <p>{check.entries}</p>
            </div>
            <div>
              <Label>ledger head</Label>
              <p className="mono" style={{ fontSize: "var(--fs-small)", wordBreak: "break-all" }}>
                {check.head}
              </p>
            </div>
            <div>
              <Label>recorded as</Label>
              <p className="soft">{log.data?.actor}</p>
            </div>
          </dl>
        )}

        <p className="muted measure" style={{ fontSize: "var(--fs-small)" }}>
          This build has no authentication, so the ledger records what was done but cannot
          prove who did it. A deployment would sign each entry with the analyst's key and keep
          the ledger on write-once storage.
        </p>
      </section>

      <section className="section" id="ledger">
        <div className="section-head">
          <h2>The record</h2>
          <span className="label">{log.data ? `${log.data.total} entries` : "loading"}</span>
        </div>

        {log.error ? (
          <ErrorNote error={log.error} />
        ) : log.loading ? (
          <SkeletonRows rows={5} />
        ) : !entries.length ? (
          <p className="soft measure">
            Nothing recorded yet. Ingest a dataset or run the pipeline and it appears here.
          </p>
        ) : (
          <div className="table-wrap">
            <table className="data">
              <thead>
                <tr>
                  <th className="num">#</th>
                  <th>When</th>
                  <th>What happened</th>
                  <th>Detail</th>
                  <th>Entry hash</th>
                </tr>
              </thead>
              <tbody>
                {entries.map((entry) => (
                  <tr
                    key={entry.seq}
                    data-settled={
                      check && !check.chain_intact && check.broken_at != null
                        ? entry.seq < check.broken_at
                        : undefined
                    }
                  >
                    <td className="num">{entry.seq}</td>
                    <td className="soft">{entry.at.replace("T", " ").replace("+00:00", "")}</td>
                    <td>{ACTION_LABEL[entry.action] ?? entry.action}</td>
                    <td className="soft">
                      <Detail entry={entry} />
                    </td>
                    <td className="mono" title={entry.hash} style={{ fontSize: "var(--fs-small)" }}>
                      {entry.hash.slice(0, 12)}…
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>
    </Shell>
  );
}

/** The fields worth showing per action — not the whole payload, which is
 *  mostly hashes a reader cannot use at a glance. */
function Detail({ entry }: { entry: CustodyEntry }) {
  const d = entry.detail ?? {};
  const files = d.files ?? [];
  const bits: string[] = [];
  const say = (key: string, label = key) => {
    if (d[key] != null) bits.push(`${d[key]} ${label}`);
  };
  say("rows");
  say("transactions", "tx");
  say("alerts");
  say("quarantined");
  say("duplicates", "duplicate tx");
  if (d.entity_id) bits.push(String(d.entity_id).slice(0, 14) + "…");
  if (d.status) bits.push(String(d.status));
  if (d.typology) bits.push(String(d.typology));
  if (d.report_sha256) bits.push(`report ${String(d.report_sha256).slice(0, 10)}…`);
  if (files.length) bits.push(`${files.length} file(s) sealed`);
  return <>{bits.join(" · ") || "—"}</>;
}
