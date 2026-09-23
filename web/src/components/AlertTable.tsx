/** The queue. Everything here serves one question: which case next.
 *
 *  Dense rows, tabular figures, a sticky head, and a verdict two keystrokes
 *  away. Sorting and filtering happen on the rows already in hand — the
 *  server sends the page ranked, and re-ranking a visible page must not cost
 *  a round trip. */
import { useLayoutEffect, useRef, useState } from "react";
import { Link } from "react-router-dom";
import type { Alert } from "../api/types";
import { formatId } from "../lib/formatId";
import { patternLabel } from "../lib/format";
import { reducedMotion } from "../lib/motion";
import { RiskMeter } from "./ui";

export type Verdict = "confirmed" | "false_positive";
export type SortKey = "risk_score" | "entity_id" | "wallets";

export interface AlertTableProps {
  alerts: Alert[];
  verdicts: Record<string, Verdict>;
  pending: Record<string, boolean>;
  onVerdict: (alert: Alert, verdict: Verdict) => void;
  sort: { key: SortKey; dir: "asc" | "desc" };
  onSort: (key: SortKey) => void;
}

/** No taint path at all. Mirrors `fusion.ordering.NO_TAINT`: an entity with no
 *  route from a watchlist seed is not zero hops away, it is not connected. */
export const NO_TAINT = 1_000_000;

/** The queue's published order, `fusion/ordering.py` SORT_KEY, evaluated here.
 *
 *  The composite score decides; when it cannot — and it usually cannot, since
 *  the top of the queue all reads 1.000 — these break the tie in a fixed order:
 *  distinct rule typologies, then hops from a watchlist seed, then the
 *  strongest attribution lead, then transaction volume, then the entity id as
 *  a deterministic backstop. The server sends the page in exactly this order;
 *  this reproduces it so a client-side re-sort lands in the same place.
 */
export function compareByQueueOrder(a: Alert, b: Alert): number {
  return (
    b.risk_score - a.risk_score ||
    (b.rule_typologies ?? 0) - (a.rule_typologies ?? 0) ||
    (a.taint_hops ?? NO_TAINT) - (b.taint_hops ?? NO_TAINT) ||
    (b.lead_confidence ?? 0) - (a.lead_confidence ?? 0) ||
    (b.tx_count ?? 0) - (a.tx_count ?? 0) ||
    a.entity_id.localeCompare(b.entity_id)
  );
}

/** Sorting is stable and total: ties fall back to the published queue order, so
 *  a re-sort never shuffles rows that compare equal and the risk column orders
 *  exactly as the API and the PDF do. */
export function sortAlerts(alerts: Alert[], key: SortKey, dir: "asc" | "desc"): Alert[] {
  if (key === "risk_score") {
    const ranked = [...alerts].sort(compareByQueueOrder);
    return dir === "desc" ? ranked : ranked.reverse();
  }
  const sign = dir === "asc" ? 1 : -1;
  return [...alerts].sort((a, b) => {
    const left = a[key];
    const right = b[key];
    const cmp =
      typeof left === "number" && typeof right === "number"
        ? left - right
        : String(left).localeCompare(String(right));
    return cmp !== 0 ? cmp * sign : compareByQueueOrder(a, b);
  });
}

export function filterAlerts(
  alerts: Alert[],
  { minScore = 0, patternType = "" }: { minScore?: number; patternType?: string },
): Alert[] {
  return alerts.filter(
    (alert) =>
      alert.risk_score >= minScore &&
      (!patternType || alert.pattern_types.includes(patternType)),
  );
}

const ARROW = { asc: "↑", desc: "↓" } as const;

/** The tiebreakers, compactly, in the order they are applied.
 *
 *  Without this the queue asks the reader to trust that row 3 outranks row 7
 *  for a reason, when both print 1.000. `R` is how many distinct rule detectors
 *  fired, `H` the hops from a watchlist seed (`—` when there is no path), `L`
 *  the strongest attribution lead. */
function Tiebreak({ alert }: { alert: Alert }) {
  const hops = alert.taint_hops ?? NO_TAINT;
  const parts = [
    `R${alert.rule_typologies ?? 0}`,
    hops >= NO_TAINT ? "H—" : `H${hops}`,
    `L${(alert.lead_confidence ?? 0).toFixed(2)}`,
  ];
  return (
    <span
      className="mono soft"
      style={{ fontSize: "var(--fs-small)", whiteSpace: "nowrap" }}
      title={`${alert.rule_typologies ?? 0} distinct rule detector(s); `
        + (hops >= NO_TAINT ? "no taint path to a watchlist seed; "
                            : `${hops} hop(s) from a watchlist seed; `)
        + `strongest attribution lead ${(alert.lead_confidence ?? 0).toFixed(3)}; `
        + `${alert.tx_count ?? 0} transactions`}
    >
      {parts.join(" ")}
    </span>
  );
}

const ariaSort = (sort: { key: SortKey; dir: "asc" | "desc" }, me: SortKey) =>
  sort.key === me ? (sort.dir === "asc" ? "ascending" : "descending") : "none";

export function AlertTable({
  alerts,
  verdicts,
  pending,
  onVerdict,
  sort,
  onSort,
}: AlertTableProps) {
  const body = useRef<HTMLTableSectionElement>(null);
  const [focused, setFocused] = useState(0);

  // FLIP. Row positions are recorded after every layout; when a sort or a
  // filter moves a row, it is animated from where it used to be. The rows are
  // already in their final place — the transform is cosmetic, so the table
  // stays clickable throughout.
  const positions = useRef(new Map<string, number>());
  useLayoutEffect(() => {
    const rows = body.current?.querySelectorAll<HTMLElement>("[data-flip]") ?? [];
    const next = new Map<string, number>();
    const quiet = reducedMotion();
    for (const row of rows) {
      const id = row.dataset.flip!;
      const top = row.getBoundingClientRect().top;
      const previous = positions.current.get(id);
      if (!quiet && previous != null && Math.abs(previous - top) > 0.5) {
        row.animate(
          [{ transform: `translateY(${previous - top}px)` }, { transform: "none" }],
          { duration: 280, easing: "cubic-bezier(.22, 1, .36, 1)" },
        );
      }
      next.set(id, top);
    }
    positions.current = next;
  });

  const move = (delta: number) => {
    const next = Math.min(Math.max(focused + delta, 0), alerts.length - 1);
    setFocused(next);
    body.current
      ?.querySelectorAll<HTMLAnchorElement>("[data-row-link]")
      [next]?.focus();
  };

  return (
    <div className="table-wrap">
      <table
        className="data"
        onKeyDown={(event) => {
          if (event.key === "ArrowDown") {
            event.preventDefault();
            move(1);
          } else if (event.key === "ArrowUp") {
            event.preventDefault();
            move(-1);
          }
        }}
      >
        <caption className="sr-only">
          Alerts, ranked by risk score and then by the published tiebreakers —
          distinct rule detectors, hops from a watchlist seed, strongest attribution
          lead, transaction volume, entity id. Use the arrow keys to move between rows.
        </caption>
        <thead>
          <tr>
            <th scope="col" style={{ width: "2.5rem" }} aria-label="Row code" />
            <th scope="col" aria-sort={ariaSort(sort, "entity_id")}>
              <SortButton label="Entity" active={sort} me="entity_id" onSort={onSort} />
            </th>
            <th scope="col">Pattern</th>
            <th scope="col" style={{ textAlign: "right" }} aria-sort={ariaSort(sort, "risk_score")}>
              <SortButton label="Risk" active={sort} me="risk_score" onSort={onSort} />
            </th>
            <th
              scope="col"
              style={{ textAlign: "right" }}
              title={"Why this row sits where it does when several share a risk score: "
                + "distinct rule detectors fired, then hops from a watchlist seed, then "
                + "the strongest attribution lead. Applied in that order."}
            >
              Tiebreak
            </th>
            <th scope="col">Reason</th>
            <th scope="col" style={{ textAlign: "right" }} aria-sort={ariaSort(sort, "wallets")}>
              <SortButton label="Wallets" active={sort} me="wallets" onSort={onSort} />
            </th>
            <th scope="col" style={{ textAlign: "right" }}>
              Verdict
            </th>
          </tr>
        </thead>
        <tbody ref={body}>
          {alerts.map((alert, index) => {
            const verdict = verdicts[alert.alert_id];
            return (
              <tr
                key={alert.alert_id}
                data-flip={alert.alert_id}
                data-settled={verdict ? "true" : undefined}
              >
                <td className="gutter-code">{String(index + 1).padStart(2, "0")}</td>
                <td>
                  <Link
                    to={`/entities/${encodeURIComponent(alert.entity_id)}`}
                    className="row-link"
                    data-row-link
                    title={alert.entity_id}
                    viewTransition
                    style={{ viewTransitionName: `entity-${cssName(alert.entity_id)}` }}
                    onFocus={() => setFocused(index)}
                  >
                    {formatId(alert.entity_id)}
                  </Link>
                </td>
                <td style={{ fontSize: "var(--fs-small)" }} className="soft">
                  {alert.pattern_types.length
                    ? alert.pattern_types.map(patternLabel).join(", ")
                    : "—"}
                </td>
                <td
                  className="num-cell"
                  style={{ viewTransitionName: `score-${cssName(alert.entity_id)}` }}
                >
                  <RiskMeter score={alert.risk_score} cells={6} />
                </td>
                <td className="num-cell">
                  <Tiebreak alert={alert} />
                </td>
                <td className="reason-cell" title={alert.reason}>
                  {alert.reason}
                </td>
                <td className="num-cell">{alert.wallets}</td>
                <td className="num-cell">
                  <VerdictCell
                    alert={alert}
                    verdict={verdict}
                    pending={pending[alert.alert_id]}
                    onVerdict={onVerdict}
                  />
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}

function SortButton({
  label,
  me,
  active,
  onSort,
}: {
  label: string;
  me: SortKey;
  active: { key: SortKey; dir: "asc" | "desc" };
  onSort: (key: SortKey) => void;
}) {
  const on = active.key === me;
  return (
    <button
      type="button"
      onClick={() => onSort(me)}
    >
      {label}
      <span aria-hidden="true" className={on ? undefined : "muted"}>
        {on ? ARROW[active.dir] : "↕"}
      </span>
    </button>
  );
}

function VerdictCell({
  alert,
  verdict,
  pending,
  onVerdict,
}: {
  alert: Alert;
  verdict?: Verdict;
  pending?: boolean;
  onVerdict: (alert: Alert, verdict: Verdict) => void;
}) {
  if (verdict) {
    return (
      <span className={`chip ${verdict === "confirmed" ? "chip-confirmed" : ""}`}>
        <span aria-hidden="true">{verdict === "confirmed" ? "✓" : "✕"}</span>
        {verdict === "confirmed" ? "confirmed" : "false positive"}
      </span>
    );
  }
  return (
    <span style={{ display: "inline-flex", gap: "var(--sp-1)" }}>
      <button
        type="button"
        className="btn btn-quiet"
        disabled={pending}
        onClick={() => onVerdict(alert, "confirmed")}
        title={`Confirm ${alert.entity_id}`}
      >
        confirm
      </button>
      <button
        type="button"
        className="btn btn-quiet"
        disabled={pending}
        onClick={() => onVerdict(alert, "false_positive")}
        title={`Mark ${alert.entity_id} a false positive`}
      >
        reject
      </button>
    </span>
  );
}

/** view-transition-name has to be a valid ident, and an entity id is not. */
export const cssName = (value: string) => value.replace(/[^a-zA-Z0-9_-]/g, "");
