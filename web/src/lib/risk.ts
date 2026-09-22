/** The risk language. Colour is never the only signal: a level always travels
 *  with its glyph and its word, and the meter is drawn in braille cells so it
 *  survives greyscale, colour-blindness and a printed case report.
 *
 *  Thresholds match config.yaml's `thresholds` block. */

export type RiskLevel = "low" | "medium" | "high" | "critical";

export const RISK: Record<RiskLevel, { label: string; glyph: string }> = {
  low: { label: "low", glyph: "⠂" },
  medium: { label: "medium", glyph: "⠶" },
  high: { label: "high", glyph: "⣤" },
  critical: { label: "critical", glyph: "⣿" },
};

export function riskLevel(score: number): RiskLevel {
  if (score >= 0.8) return "critical";
  if (score >= 0.6) return "high";
  if (score >= 0.3) return "medium";
  return "low";
}

/** Eight braille cells, filled proportionally. Each cell holds four dot rows,
 *  so the bar has 32 steps of resolution while staying eight characters wide
 *  in any monospaced context — including a copy-paste into a case note. */
const FILL = ["⠀", "⡀", "⣀", "⣠", "⣰"] as const; // ⠀ ⡀ ⣀ ⣠ ⣰
const FULL = "⣿"; // ⣿

export function brailleMeter(score: number, cells = 8): string {
  const clamped = Math.min(Math.max(score, 0), 1);
  const steps = Math.round(clamped * cells * 4);
  let out = "";
  for (let i = 0; i < cells; i += 1) {
    const remaining = steps - i * 4;
    out += remaining >= 4 ? FULL : FILL[Math.max(remaining, 0)];
  }
  return out;
}

export const riskVar = (level: RiskLevel) => `var(--risk-${level})`;
export const riskBgVar = (level: RiskLevel) => `var(--risk-${level}-bg)`;
