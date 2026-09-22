/** Always on screen, bottom-left: what a shape means and what a colour means.
 *
 *  Shape and colour are independent channels — a red diamond is a transaction
 *  in a risky neighbourhood, not a risky transaction — so the legend states
 *  them separately rather than showing eight combined swatches. */
export function Legend() {
  return (
    <div className="graph-legend" aria-label="Legend">
      <div>
        <p className="label">shape</p>
        <ul>
          <li><span className="lg-shape lg-wallet" /> wallet</li>
          <li><span className="lg-shape lg-tx" /> transaction</li>
          <li><span className="lg-shape lg-ip" /> IP address</li>
          <li><span className="lg-shape lg-agg" /> more, batched</li>
        </ul>
      </div>
      <div>
        <p className="label">wallet risk</p>
        <div className="lg-ramp" role="img" aria-label="risk ramp from no signal to critical">
          <span style={{ background: "var(--risk-node-none)" }} />
          <span style={{ background: "var(--risk-node-medium)" }} />
          <span style={{ background: "var(--risk-node-high)" }} />
          <span style={{ background: "var(--risk-node-critical)" }} />
        </div>
        <p className="lg-ramp-ends">
          <span>0.0 no signal</span>
          <span>1.0 critical</span>
        </p>
        <p className="lg-note">red ring = flagged by an engine · dashed edge = IP link</p>
      </div>
    </div>
  );
}
