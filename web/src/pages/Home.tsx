/** What the case looks like from above: how much was ingested, how much is
 *  waiting, and whether anything upstream is not working properly. */
import { Link } from "react-router-dom";
import { api } from "../api/client";
import { useApi } from "../lib/useApi";
import { useEnter } from "../lib/motion";
import { patternLabel } from "../lib/format";
import { AmbientField } from "../components/AmbientField";
import { ErrorNote, Label, Notice, SkeletonRows, Stat } from "../components/ui";
import { Shell } from "../components/Shell";

const ANCHORS = [
  { id: "case", label: "This case" },
  { id: "patterns", label: "Alerts by pattern" },
  { id: "pipeline", label: "Pipeline" },
];

export function Home() {
  const { data, error, loading } = useApi((signal) => api.stats(signal), []);
  const header = useEnter<HTMLDivElement>(0);
  const caseSection = useEnter<HTMLElement>(1);
  const patterns = useEnter<HTMLElement>(2);
  const pipeline = useEnter<HTMLElement>(3);

  const origin = data?.features.origin_estimation;
  const byPattern = Object.entries(data?.alerts_by_pattern_type ?? {}).sort((a, b) => b[1] - a[1]);
  const busiest = byPattern[0]?.[1] ?? 1;

  return (
    <Shell anchors={ANCHORS}>
      <div className="field-panel header-field" ref={header}>
        <AmbientField />
        <div className="header-copy">
          <Label>Investigator console</Label>
          <h1 style={{ marginTop: "var(--sp-2)" }}>
            Most of what crosses the network is nothing. This is the part that is not.
          </h1>
          <p style={{ marginTop: "var(--sp-3)", color: "var(--field-muted)" }}>
            Offline Bitcoin forensics. Every score below is a lead for a human, never a
            conclusion about a person.
          </p>
        </div>
      </div>

      {error && (
        <div className="section">
          <ErrorNote error={error} />
        </div>
      )}

      <section className="section" id="case" ref={caseSection}>
        <div className="section-head">
          <h2>This case</h2>
          <Link to="/alerts" viewTransition>
            Open the queue →
          </Link>
        </div>

        {loading || !data ? (
          <SkeletonRows rows={3} />
        ) : (
          <div className="stat-grid">
            <Stat title="Entities" sublabel="clustered from the transaction graph" value={data.total_entities} />
            <Stat title="Alerts" sublabel="above the fusion threshold" value={data.total_alerts} />
            <Stat
              title="Mean risk"
              sublabel="across alerted entities"
              value={data.avg_confidence}
              decimals={3}
            />
            <Stat
              title="Transactions"
              sublabel={`${data.rows.toLocaleString()} relay observations`}
              value={data.transactions}
            />
          </div>
        )}
      </section>

      <section className="section" id="patterns" ref={patterns}>
        <div className="section-head">
          <h2>Alerts by pattern</h2>
          <span className="label">count per typology</span>
        </div>
        {loading ? (
          <SkeletonRows rows={4} />
        ) : byPattern.length === 0 ? (
          <p className="soft">No alerts yet. Run the pipeline and this fills in.</p>
        ) : (
          <div>
            {byPattern.map(([pattern, count], i) => (
              <div className="bar-row" key={pattern}>
                <span className="soft">{patternLabel(pattern)}</span>
                <span className="bar-track">
                  <span
                    className="bar-fill"
                    style={{
                      display: "block",
                      width: `${(count / busiest) * 100}%`,
                      animation: `grow var(--dur-4) var(--ease-out) ${i * 40}ms backwards`,
                    }}
                  />
                </span>
                <span className="num" style={{ textAlign: "right" }}>
                  {count}
                </span>
              </div>
            ))}
            <style>{`@keyframes grow { from { transform: scaleX(0) } to { transform: none } }`}</style>
          </div>
        )}
      </section>

      <section className="section" id="pipeline" ref={pipeline}>
        <div className="section-head">
          <h2>Pipeline</h2>
          <span className="label">what produced these numbers</span>
        </div>

        {origin?.status === "degraded" && (
          <div style={{ marginBottom: "var(--sp-4)" }}>
            <Notice title="Origin estimation is degraded">
              {origin.reason} Alerts and evidence are unaffected; IP attribution leads are
              weaker than usual and should be read as "seen at", not "sent from".
            </Notice>
          </div>
        )}

        {origin && (
          <dl className="stat-grid" style={{ margin: 0 }}>
            <div className="stat">
              <h3>Estimator</h3>
              <Label>origin selection rule</Label>
              <p className="num" style={{ marginTop: "var(--sp-3)" }}>
                {origin.estimator}
              </p>
            </div>
            <div className="stat">
              <h3>Multi-hop transactions</h3>
              <Label>enough observations to estimate from</Label>
              <p className="num" style={{ marginTop: "var(--sp-3)" }}>
                {origin.multi_hop_transactions.toLocaleString()}
              </p>
            </div>
            <div className="stat">
              <h3>Observations per transaction</h3>
              <Label>mean</Label>
              <p className="num" style={{ marginTop: "var(--sp-3)" }}>
                {origin.mean_observations_per_transaction.toFixed(2)}
              </p>
            </div>
          </dl>
        )}
      </section>
    </Shell>
  );
}
