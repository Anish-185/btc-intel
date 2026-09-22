/** The risk score as an arc, drawn once when the case opens.
 *
 *  The arc is the least important part: the number, the word and the braille
 *  meter underneath carry the same information without colour. */
import { useEffect, useRef } from "react";
import { RISK, brailleMeter, riskLevel } from "../lib/risk";
import { reducedMotion } from "../lib/motion";

const R = 34;
const CIRC = 2 * Math.PI * R;
const SWEEP = 0.75; // three quarters of a turn

export function Gauge({ score }: { score: number }) {
  const arc = useRef<SVGCircleElement>(null);
  const level = riskLevel(score);
  const filled = CIRC * SWEEP * Math.min(Math.max(score, 0), 1);

  useEffect(() => {
    const node = arc.current;
    if (!node || reducedMotion()) return;
    node.animate(
      [{ strokeDasharray: `0 ${CIRC}` }, { strokeDasharray: `${filled} ${CIRC}` }],
      { duration: 400, easing: "cubic-bezier(.22, 1, .36, 1)", fill: "backwards" },
    );
  }, [filled]);

  return (
    <div className="gauge">
      <svg width="88" height="88" viewBox="0 0 88 88" role="img"
           aria-label={`Risk score ${score.toFixed(3)}, ${RISK[level].label}`}>
        <g transform="rotate(135 44 44)">
          <circle
            cx="44" cy="44" r={R} fill="none" stroke="var(--rule)" strokeWidth="6"
            strokeDasharray={`${CIRC * SWEEP} ${CIRC}`} strokeLinecap="butt"
          />
          <circle
            ref={arc} className="gauge-arc"
            cx="44" cy="44" r={R} fill="none" stroke={`var(--risk-${level})`} strokeWidth="6"
            strokeDasharray={`${filled} ${CIRC}`} strokeLinecap="butt"
          />
        </g>
        <text
          x="44" y="41" textAnchor="middle" fill="var(--ink)"
          fontFamily="var(--font-mono)" fontSize="17" style={{ fontVariantNumeric: "tabular-nums" }}
        >
          {score.toFixed(2)}
        </text>
        <text
          x="44" y="55" textAnchor="middle" fill={`var(--risk-${level})`}
          fontFamily="var(--font-mono)" fontSize="8" letterSpacing="1.2"
        >
          {RISK[level].label.toUpperCase()}
        </text>
      </svg>
      <span
        className="risk-cells"
        style={{ ["--risk-ink" as string]: `var(--risk-${level})`, fontSize: "1.1rem" }}
        aria-hidden="true"
      >
        {brailleMeter(score, 8)}
      </span>
    </div>
  );
}
