/** Small shared pieces. Each one exists because the same thing is drawn in at
 *  least two places, not to have a component library. */
import { useState, type ReactNode } from "react";
import { RISK, brailleMeter, riskLevel } from "../lib/risk";
import { useCountUp } from "../lib/motion";
import type { Validity } from "../api/types";

export function Label({ children }: { children: ReactNode }) {
  return <p className="label">{children}</p>;
}

/** A risk score, always as glyph + cells + number + word. Never colour alone:
 *  in greyscale, in a screenshot or in the printed report, the braille fill and
 *  the word still say how bad this is. */
export function RiskMeter({
  score,
  cells = 8,
  showLabel = true,
}: {
  score: number;
  cells?: number;
  showLabel?: boolean;
}) {
  const level = riskLevel(score);
  const meter = brailleMeter(score, cells);
  return (
    <span
      className="risk"
      style={{ ["--risk-ink" as string]: `var(--risk-${level})` }}
      title={`risk ${score.toFixed(3)} — ${RISK[level].label}`}
    >
      <span className="risk-cells" aria-hidden="true">
        {meter}
      </span>
      <span className="risk-score">{score.toFixed(3)}</span>
      {showLabel && <span className="risk-label">{RISK[level].label}</span>}
      <span className="sr-only">
        risk {score.toFixed(3)}, {RISK[level].label}
      </span>
    </span>
  );
}

export function RiskChip({ score }: { score: number }) {
  const level = riskLevel(score);
  return (
    <span
      className="risk-chip"
      style={{
        ["--risk-ink" as string]: `var(--risk-${level})`,
        ["--risk-bg" as string]: `var(--risk-${level}-bg)`,
      }}
    >
      <span aria-hidden="true">{RISK[level].glyph}</span>
      {RISK[level].label}
    </span>
  );
}

/** An origin's validity verdict. PASS is quiet; a withheld origin names why. */
export function ValidityChip({ validity }: { validity: Validity }) {
  if (validity.status === "PASS") {
    return <Chip title={validity.evidence.join(" ")}>validity pass</Chip>;
  }
  return (
    <Chip tone="caution" title={validity.evidence.join(" ")}>
      <span aria-hidden="true">⚠</span> inconclusive: {(validity.reason ?? "").replace(/_/g, " ").toLowerCase()}
    </Chip>
  );
}

export function Chip({
  children,
  tone,
  title,
}: {
  children: ReactNode;
  tone?: "caution" | "confirmed";
  title?: string;
}) {
  return (
    <span className={`chip${tone ? ` chip-${tone}` : ""}`} title={title}>
      {children}
    </span>
  );
}

/** A big number with a small unit, the way the reference sets them: the unit
 *  never shares the numeral's size. Counts up once on mount. */
export function Stat({
  title,
  sublabel,
  value,
  unit,
  decimals = 0,
  children,
}: {
  title: string;
  sublabel?: string;
  value: number;
  unit?: string;
  decimals?: number;
  children?: ReactNode;
}) {
  const shown = useCountUp(value);
  return (
    <div className="stat">
      <h3>{title}</h3>
      {sublabel && <Label>{sublabel}</Label>}
      <p className="stat-value">
        {shown.toLocaleString(undefined, {
          minimumFractionDigits: decimals,
          maximumFractionDigits: decimals,
        })}
        {unit && <span className="stat-unit">{unit}</span>}
      </p>
      {children}
    </div>
  );
}

/** State the system cannot do something, and what that means for the reader.
 *  Calm on purpose: degraded origin estimation is a limitation, not an alarm. */
export function Notice({ title, children }: { title: string; children: ReactNode }) {
  return (
    <div className="notice" role="status">
      <span aria-hidden="true">⚠</span>
      <div>
        <p className="label">{title}</p>
        <p className="soft" style={{ marginTop: "var(--sp-1)" }}>
          {children}
        </p>
      </div>
    </div>
  );
}

export function Skeleton({ width = "100%", height = "1rem" }: { width?: string; height?: string }) {
  return <div className="skeleton" style={{ width, height }} aria-hidden="true" />;
}

export function SkeletonRows({ rows = 6 }: { rows?: number }) {
  return (
    <div className="stack" style={{ gap: "var(--sp-2)" }} aria-busy="true" aria-live="polite">
      {Array.from({ length: rows }, (_, i) => (
        <Skeleton key={i} height="1.25rem" width={`${90 - i * 4}%`} />
      ))}
      <span className="sr-only">Loading</span>
    </div>
  );
}

/** Long ids are shortened on screen and copied in full. */
export function CopyValue({ value, display }: { value: string; display?: string }) {
  const [copied, setCopied] = useState(false);
  return (
    <button
      type="button"
      className="btn btn-quiet"
      title={`Copy ${value}`}
      onClick={() => {
        navigator.clipboard?.writeText(value).then(
          () => {
            setCopied(true);
            setTimeout(() => setCopied(false), 1200);
          },
          () => setCopied(false),
        );
      }}
    >
      {copied ? "copied" : (display ?? "copy")}
    </button>
  );
}

export function ErrorNote({ error }: { error: string }) {
  return (
    <div className="notice" role="alert">
      <span aria-hidden="true">⚠</span>
      <div>
        <p className="label">Could not load</p>
        <p className="soft" style={{ marginTop: "var(--sp-1)" }}>
          {error}. The pipeline writes what this console reads — run{" "}
          <code className="mono">python -m fusion.pipeline</code> and reload.
        </p>
      </div>
    </div>
  );
}
