/** Wallet-construction fingerprints: which software family or construction
 *  pattern likely built a transaction. Wording is fixed: a fingerprint names
 *  how a transaction was built, never who built it, and "unknown" is an
 *  answer, shown with its reason. */
import type { FingerprintAnswer, FingerprintDistribution } from "../api/types";
import { Chip, Label } from "./ui";

const pct = (x: number) => `${Math.round(x * 100)}%`;

export function FingerprintPanel({ answer }: { answer: FingerprintAnswer }) {
  const unknown = answer.label === "unknown";
  return (
    <div className="stat" aria-label="Wallet fingerprint">
      <h3>Wallet fingerprint</h3>
      <Label>
        {answer.condition === "structural"
          ? "from structure only: this dataset carries no version, locktime or sequence"
          : "from structure and construction fields"}
      </Label>
      <p style={{ marginTop: "var(--sp-3)", fontSize: "var(--fs-h3, 1.1rem)" }}>
        {answer.display}
        {answer.confidence != null && !unknown && (
          <span className="num"> · {answer.confidence.toFixed(2)}</span>
        )}
      </p>
      {unknown && answer.unknown_reason && (
        <p className="soft" style={{ fontSize: "var(--fs-small)" }}>{answer.unknown_reason}</p>
      )}
      {answer.ranked.length > 0 && (
        <ol className="soft" style={{ fontSize: "var(--fs-small)", marginTop: "var(--sp-2)" }}>
          {answer.ranked.slice(0, 3).map((r) => (
            <li key={r.label}>
              {r.display} <span className="num">{r.confidence.toFixed(2)}</span>
            </li>
          ))}
        </ol>
      )}
      <p className="soft" style={{ fontSize: "var(--fs-small)", marginTop: "var(--sp-2)" }}>
        tells: {answer.observed_tells.map((t) => `${t} ${answer.tells[t]}`).join(" · ") || "none"}
      </p>
    </div>
  );
}

export function FingerprintSplit({
  dist,
  empty,
}: {
  dist: FingerprintDistribution & { without_structure?: number };
  empty: string;
}) {
  if (dist.transactions === 0) {
    return (
      <p className="soft">
        {empty}
        {dist.without_structure ? ` (${dist.without_structure} without transaction structure)` : ""}
      </p>
    );
  }
  return (
    <p>
      {dist.labels.map((l) => (
        <Chip key={l.label} title={`${l.count} of ${dist.transactions}`}>
          {l.display} {pct(l.share)}
        </Chip>
      ))}{" "}
      <span className="soft" style={{ fontSize: "var(--fs-small)" }}>
        over {dist.transactions} transaction{dist.transactions === 1 ? "" : "s"}
        {dist.without_structure ? `; ${dist.without_structure} without structure` : ""}
      </span>
    </p>
  );
}
