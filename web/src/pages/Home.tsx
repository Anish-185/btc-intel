/** The front door: what btc-intel does, one pipeline stage at a time, and
 *  what it refuses to claim. The working console starts at /case. */
import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { api } from "../api/client";
import { useApi } from "../lib/useApi";
import { DotArt } from "../components/DotArt";
import { Shell } from "../components/Shell";
import { CAPABILITIES, type Capability } from "../content/capabilities";

const FINDINGS = [
  {
    title: "The fingerprint turned itself off",
    body:
      "On wallet profiles it was trained on, our fingerprint looked excellent. On a profile it had never seen, it gave a contradicting label 80% of the time. A novelty check cut that to 34% — still above the 10% bar we registered in advance, so the console does not show fingerprints.",
  },
  {
    title: "Some senders cannot be named",
    body:
      "With one observer, a broadcaster two hops away never appears among the candidates. The ceiling is zero, not low. When every peer that announced a transaction is a public relay, the system abstains with NOT_REACHABLE instead of naming an innocent relay.",
  },
  {
    title: "A test caught our best number",
    body:
      "Every propagation tree ties at its earliest timestamp. Our first estimator broke the tie by row order, which happened to favour the true origin and inflated top-1 by about fourteen points. A test that reshuffles the input rows caught it. The tie is now broken on evidence.",
  },
];

export function Home() {
  const stats = useApi((signal) => api.stats(signal), []);
  const [active, setActive] = useState(CAPABILITIES[0].id);

  // Light the stage the reader is on in the index.
  useEffect(() => {
    if (typeof IntersectionObserver === "undefined") return;
    const observer = new IntersectionObserver(
      (entries) => {
        const seen = entries.find((e) => e.isIntersecting);
        if (seen) setActive(seen.target.id);
      },
      { rootMargin: "-40% 0px -55% 0px" },
    );
    for (const c of CAPABILITIES) {
      const node = document.getElementById(c.id);
      if (node) observer.observe(node);
    }
    // A stage banner links here as /#stage; the router does not scroll to it.
    if (location.hash) document.getElementById(location.hash.slice(1))?.scrollIntoView();
    return () => observer.disconnect();
  }, []);

  const s = stats.data;

  return (
    <Shell variant="top">
      <header className="hero">
        <div className="hero-copy">
          <p className="hero-kicker">Smart India Hackathon 2026, problem SIH26146</p>
          <h1 className="hero-title">Follow the coin back to the hand that sent it.</h1>
          <p className="hero-lede">
            btc-intel is an offline forensics console for Bitcoin. It groups wallets into owners,
            flags laundering, traces money to its cash-out and estimates which IP address first
            broadcast a transaction. When the evidence cannot support an answer, it says so.
          </p>
          <div className="hero-actions">
            <Link to="/alerts" className="cta cta-solid" viewTransition>
              <span className="cta-mark" aria-hidden="true">
                <span className="wordmark-mark" />
              </span>
              Open the alert queue
            </Link>
            <a href="#pipeline" className="cta cta-line bracket">
              How it works <span aria-hidden="true">↓</span>
            </a>
            <Link to="/redteam" className="cta cta-line bracket" viewTransition>
              Attack it live <span aria-hidden="true">↗</span>
            </Link>
          </div>
        </div>

        <div className="hero-art">
          <DotArt name="hero" mode="glyph" cell={5} reveal className="hero-canvas" />
          <span className="hero-spark" aria-hidden="true" />
        </div>

        <dl className="hero-ticker" aria-label="This case, live from the API">
          <div>
            <dt>transactions</dt>
            <dd>{s ? s.transactions.toLocaleString() : "…"}</dd>
          </div>
          <div>
            <dt>relay observations</dt>
            <dd>{s ? s.rows.toLocaleString() : "…"}</dd>
          </div>
          <div>
            <dt>entities</dt>
            <dd>{s ? s.total_entities.toLocaleString() : "…"}</dd>
          </div>
          <div>
            <dt>alerts to review</dt>
            <dd>{s ? s.total_alerts.toLocaleString() : "…"}</dd>
          </div>
          <div>
            <dt>network calls</dt>
            <dd>0</dd>
          </div>
        </dl>
      </header>

      <section className="proof-strip" aria-labelledby="why">
        <h2 id="why" className="proof-strip-title">
          Why it holds up
        </h2>
        <div className="proof-strip-grid">
          <BigProof value="0" what="false alerts on 949 clean entities, at the same threshold" />
          <BigProof value="5 of 5" what="planted laundering operations caught, 0.934 precision" />
          <BigProof value="91%" what="right when it names an origin IP — and silent when it can't" />
          <BigProof value="20 of 30" what="live red-team injections caught, nothing retrained" />
        </div>
        <p className="proof-strip-note">
          Every figure on this page is on the project's claims sheet with its condition. Model
          numbers are measured on our simulated network, not on Bitcoin itself.
        </p>
      </section>

      <section className="pipeline" id="pipeline" aria-labelledby="pipeline-title">
        <div className="pipeline-head">
          <h2 id="pipeline-title">Nine stages, raw dump to courtroom</h2>
          <p className="soft">
            Each stage below is running in this console on the case you just saw counted. Open any
            of them from its link.
          </p>
        </div>

        <div className="pipeline-body">
          <nav className="stage-index" aria-label="Pipeline stages">
            <ol>
              {CAPABILITIES.map((c, i) => (
                <li key={c.id}>
                  <a href={`#${c.id}`} aria-current={active === c.id ? "step" : undefined}>
                    <span className="stage-num">{String(i + 1).padStart(2, "0")}</span>
                    {c.name}
                  </a>
                </li>
              ))}
            </ol>
          </nav>

          <div className="chapters">
            {CAPABILITIES.map((c, i) => (
              <Chapter key={c.id} capability={c} index={i} />
            ))}
          </div>
        </div>
      </section>

      <section className="honesty" aria-labelledby="honesty-title">
        <div className="honesty-art">
          <DotArt name="capital" mode="dot" cell={5} />
          <span className="art-note art-note-tl">measure</span>
          <span className="art-note art-note-br">then verify</span>
        </div>
        <div className="honesty-copy">
          <h2 id="honesty-title">What it refuses to claim</h2>
          <p className="honesty-lede">
            A forensic tool that overstates is worse than none: its errors land on people. So the
            numbers were registered before they were run, and the results we did not like stayed
            in.
          </p>
          <div className="findings">
            {FINDINGS.map((f) => (
              <article key={f.title} className="finding">
                <h3>{f.title}</h3>
                <p>{f.body}</p>
              </article>
            ))}
          </div>
        </div>
      </section>

      <footer className="outro">
        <DotArt name="ingest" mode="glyph" cell={9} className="outro-canvas" />
        <div className="outro-copy">
          <h2>The case is loaded.</h2>
          <p>
            {s
              ? `${s.total_alerts} alerts across ${s.total_entities.toLocaleString()} entities are waiting.`
              : "Start the API and the case loads here."}{" "}
            Every score is a lead for a person to check, never a conclusion about one.
          </p>
          <div className="hero-actions">
            <Link to="/case" className="cta cta-solid" viewTransition>
              <span className="cta-mark" aria-hidden="true">
                <span className="wordmark-mark" />
              </span>
              Open the case
            </Link>
            <Link to="/custody" className="cta cta-line bracket" viewTransition>
              Verify custody <span aria-hidden="true">↗</span>
            </Link>
          </div>
        </div>
      </footer>
    </Shell>
  );
}

function BigProof({ value, what }: { value: string; what: string }) {
  return (
    <div className="big-proof">
      <p className="big-proof-value">{value}</p>
      <p className="big-proof-what">{what}</p>
    </div>
  );
}

function Chapter({ capability: c, index }: { capability: Capability; index: number }) {
  const num = String(index + 1).padStart(2, "0");
  return (
    <article className="chapter" id={c.id} data-flip={index % 2 === 1 || undefined}>
      <div className="chapter-art">
        <DotArt name={c.art} mode={c.mode} cell={c.mode === "glyph" ? 8 : 5} />
        <span className="art-note art-note-tl">fig. {num}</span>
        <span className="art-note art-note-br">{c.name.toLowerCase()}</span>
        <span className="art-flag" aria-hidden="true" data-at={index % 3} />
      </div>

      <div className="chapter-copy">
        <p className="chapter-stage">
          <span className="stage-num">{num}</span> {c.name}
        </p>
        <h3 className="chapter-title">{c.title}</h3>
        <p className="chapter-body">{c.body}</p>
        {c.sample && (
          <p className="chapter-sample">
            <span aria-hidden="true">›</span> {c.sample}
          </p>
        )}
        <dl className="proofs">
          {c.proofs.map((p) => (
            <div className="proof bracket" key={p.what}>
              <dt className="proof-value">{p.value}</dt>
              <dd className="proof-what">{p.what}</dd>
            </div>
          ))}
        </dl>
        <p className="chapter-foot">
          <span className="condition">{c.condition}</span>
          <Link to={c.to} className="chapter-link" viewTransition>
            {c.cta} <span aria-hidden="true">↗</span>
          </Link>
        </p>
      </div>
    </article>
  );
}
