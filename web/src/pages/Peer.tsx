/** The reverse direction: start from a peer (an IP or an onion identity) or an
 *  ASN, and see what it did on the network. Every lookup is recorded in the
 *  custody ledger by the server.
 *
 *  Wording is fixed, as in LeadsPanel: "peer X", "cluster C", "linked to".
 *  A profile describes network behaviour and never who operates a peer. */
import { useState, type FormEvent } from "react";
import { Link, useNavigate, useParams } from "react-router-dom";
import { api } from "../api/client";
import type { AsnProfile, LinkedCluster, OriginClaim, PeerProfile } from "../api/types";
import { Shell } from "../components/Shell";
import { Chip, ErrorNote, Label, Notice, SkeletonRows, ValidityChip } from "../components/ui";
import { FingerprintSplit } from "../components/Fingerprint";
import { ipClass } from "../lib/format";
import { formatId } from "../lib/formatId";
import { useApi } from "../lib/useApi";

export const peerPath = (peer: string) => `/peers/${encodeURIComponent(peer)}`;

/** "AS64500" or "64500" is an ASN; anything else is a peer. */
function target(query: string): string | null {
  const q = query.trim();
  if (!q) return null;
  const asn = /^(?:AS)?(\d+)$/i.exec(q);
  return asn ? `/asns/${asn[1]}` : peerPath(q);
}

export function PeerLookup() {
  const [query, setQuery] = useState("");
  const navigate = useNavigate();
  const submit = (event: FormEvent) => {
    event.preventDefault();
    const to = target(query);
    if (to) navigate(to);
  };
  return (
    <form onSubmit={submit} className="field" role="search" aria-label="Peer lookup">
      <span className="label">Start from</span>
      <input
        type="search"
        value={query}
        onChange={(e) => setQuery(e.target.value)}
        placeholder="IP, .onion or AS number"
        aria-label="IP address, onion identity or AS number"
        style={{ minWidth: "22rem" }}
      />
      <button className="btn" type="submit">Look up</button>
    </form>
  );
}

export function Peers() {
  return (
    <Shell>
      <section className="section">
        <div className="section-head">
          <div>
            <Label>peer profile</Label>
            <h1 style={{ marginTop: "var(--sp-2)" }}>Start from an address</h1>
          </div>
        </div>
        <p className="soft measure" style={{ marginBottom: "var(--sp-4)" }}>
          What a peer announced, what the origination model names it as origin of, how it
          times its announcements and which clusters the evidence links it to. A profile
          describes network behaviour, not who operates the peer. Every lookup is recorded in
          the chain of custody.
        </p>
        <PeerLookup />
      </section>
    </Shell>
  );
}

export function Peer() {
  const { peer = "" } = useParams();
  const { data, error, loading } = useApi((signal) => api.peerProfile(peer, signal), [peer]);
  return (
    <Shell
      anchors={[
        { id: "originated", label: "Originated" },
        { id: "clusters", label: "Linked clusters" },
        { id: "timing", label: "Timing" },
        { id: "vantage", label: "Vantage" },
      ]}
    >
      <section className="section">
        <div className="section-head">
          <div>
            <Label>{data?.kind === "onion_identity" ? "onion identity" : "peer"}</Label>
            <h1 className="mono" title={peer} style={{ marginTop: "var(--sp-2)", wordBreak: "break-all" }}>
              {peer}
            </h1>
          </div>
          <PeerLookup />
        </div>
        {error ? (
          <ErrorNote error={error} />
        ) : loading || !data ? (
          <SkeletonRows rows={6} />
        ) : (
          <ProfileBody profile={data} />
        )}
      </section>
    </Shell>
  );
}

function ProfileBody({ profile }: { profile: PeerProfile }) {
  const { originated, network } = profile;
  return (
    <>
      {profile.header.simulated_only && (
        <Notice title="Simulated or fixture data only">{profile.header.statement}</Notice>
      )}
      <p className="soft measure" style={{ margin: "var(--sp-3) 0" }}>{profile.caveat}</p>

      <div className="stat-grid" style={{ marginBottom: "var(--sp-4)" }}>
        <div className="stat">
          <h3>Originated</h3>
          <Label>
            {originated.by_tier.PASS} pass · {originated.by_tier.QUALIFIED} qualified ·{" "}
            {originated.by_tier.ANNOTATE} annotated
          </Label>
          <p className="stat-value" style={{ fontSize: "1.75rem" }}>{originated.claimed}</p>
        </div>
        <div className="stat">
          <h3>Withheld</h3>
          <Label>
            {Object.entries(profile.withheld.by_reason)
              .map(([r, n]) => `${n} ${r.replace(/_/g, " ").toLowerCase()}`)
              .join(" · ") || "none"}
          </Label>
          <p className="stat-value" style={{ fontSize: "1.75rem" }}>{profile.withheld.count}</p>
        </div>
        <div className="stat">
          <h3>Relayed</h3>
          <Label>announced without being named origin</Label>
          <p className="stat-value" style={{ fontSize: "1.75rem" }}>{profile.relayed.count}</p>
        </div>
        {network && (
          <div className="stat">
            <h3>Network</h3>
            <Label>{network.basis}</Label>
            <p className="num" style={{ marginTop: "var(--sp-3)" }}>
              {network.asn != null ? (
                <Link to={`/asns/${network.asn}`}>AS{network.asn}</Link>
              ) : (
                "ASN unknown"
              )}
              {network.asn_org ? ` ${network.asn_org}` : ""}
              {network.country ? ` · ${network.country}` : ""}
            </p>
            {network.ip_class && <Chip>{ipClass(network.ip_class).label}</Chip>}
          </div>
        )}
      </div>

      <h2 id="originated">Originated</h2>
      <p className="soft" style={{ marginBottom: "var(--sp-2)" }}>{originated.basis}</p>
      {originated.claims.length === 0 ? (
        <p className="soft">No transaction in any capture names this peer as origin.</p>
      ) : (
        <div className="table-wrap">
          <table className="data">
            <thead>
              <tr>
                <th>Transaction</th>
                <th>Capture · observer</th>
                <th>Claim</th>
                <th>Validity</th>
                <th className="num">Probability</th>
              </tr>
            </thead>
            <tbody>
              {originated.claims.map((c) => (
                <ClaimRow key={`${c.capture_id}-${c.txid}`} claim={c} />
              ))}
            </tbody>
          </table>
        </div>
      )}
      {profile.propagation_origin.count > 0 && (
        <p className="soft" style={{ marginTop: "var(--sp-2)" }}>{profile.propagation_origin.statement}</p>
      )}
      {profile.withheld.items.length > 0 && (
        <details style={{ marginTop: "var(--sp-3)" }}>
          <summary className="label">Withheld answers ({profile.withheld.count})</summary>
          <ul className="soft">
            {profile.withheld.items.map((w) => (
              <li key={`${w.capture_id}-${w.txid}`}>
                <Link className="mono" to={`/tx/${w.txid}`}>{formatId(w.txid)}</Link> · {w.capture_id} ·{" "}
                {w.reason}
              </li>
            ))}
          </ul>
        </details>
      )}
      {profile.relayed.sample.length > 0 && (
        <details style={{ marginTop: "var(--sp-3)" }}>
          <summary className="label">
            Relayed sample ({profile.relayed.sample.length} of {profile.relayed.count})
          </summary>
          <ul className="soft">
            {profile.relayed.sample.map((r) => (
              <li key={`${r.source}-${r.capture_id}-${r.txid}`}>
                <Link className="mono" to={`/tx/${r.txid}`}>{formatId(r.txid)}</Link> · {r.capture_id ?? r.source}
                {r.rank != null && ` · announced ${r.rank} of ${r.candidates}`}
              </li>
            ))}
          </ul>
        </details>
      )}

      {profile.fingerprints && (
        <>
          <h2 style={{ marginTop: "var(--sp-5)" }}>Wallet fingerprints</h2>
          <p className="soft" style={{ marginBottom: "var(--sp-2)" }}>{profile.fingerprints.statement}</p>
          <Label>originated (origination model)</Label>
          <FingerprintSplit dist={profile.fingerprints.originated} empty="No originated transaction to fingerprint." />
          <Label>origin estimated by engines.propagation</Label>
          <FingerprintSplit
            dist={profile.fingerprints.propagation_origin}
            empty="No relay-hop transaction names this peer as origin."
          />
        </>
      )}

      <h2 id="clusters" style={{ marginTop: "var(--sp-5)" }}>Linked clusters</h2>
      {profile.linked_clusters.length === 0 ? (
        <p className="soft">No cluster is linked to this peer.</p>
      ) : (
        profile.linked_clusters.map((c) => <ClusterLink key={c.cluster_id} link={c} />)
      )}
      {profile.excluded_links.length > 0 && (
        <ul className="soft" style={{ marginTop: "var(--sp-2)" }}>
          {profile.excluded_links.map((e) => (
            <li key={e.txid}>
              <Link className="mono" to={`/tx/${e.txid}`}>{formatId(e.txid)}</Link>: {e.statement}
            </li>
          ))}
        </ul>
      )}

      <h2 id="timing" style={{ marginTop: "var(--sp-5)" }}>Timing signature</h2>
      <TimingBlock profile={profile} />

      <h2 style={{ marginTop: "var(--sp-5)" }}>Client history</h2>
      {profile.clients.statement ? (
        <p className="soft">{profile.clients.statement}</p>
      ) : (
        <ul className="soft">
          {profile.clients.user_agents.map((a) => (
            <li key={`ua-${a.value}`}>
              user agent <span className="mono">{a.value}</span> · {a.first_seen} → {a.last_seen}
            </li>
          ))}
          {profile.clients.services.map((s) => (
            <li key={`svc-${s.value}`}>
              services <span className="mono">{s.hex}</span> · {s.first_seen} → {s.last_seen}
            </li>
          ))}
        </ul>
      )}

      <h2 id="vantage" style={{ marginTop: "var(--sp-5)" }}>Seen from</h2>
      <div className="table-wrap">
        <table className="data">
          <thead>
            <tr>
              <th>Source</th>
              <th>Observer</th>
              <th>Provenance</th>
              <th className="num">Announcements</th>
              <th>First → last seen</th>
            </tr>
          </thead>
          <tbody>
            {profile.vantage.map((v) => (
              <tr key={`${v.source}-${v.capture_id}`}>
                <td title={v.vantage}>{v.capture_id ?? v.source}</td>
                <td className="mono">
                  {v.observer.length > 3 ? `${v.observer.length} receiving nodes` : v.observer.join(", ")}
                </td>
                <td>{v.provenance}</td>
                <td className="num">{v.announcements}</td>
                <td className="soft">{v.first_seen} → {v.last_seen}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </>
  );
}

/** The claim in the shape its answer allows: a QUALIFIED answer never reads
 *  as a plain attribution. */
function ClaimRow({ claim }: { claim: OriginClaim }) {
  const kind =
    claim.answer.kind === "broadcasting_peer"
      ? "broadcasting peer · input ownership not attributable"
      : claim.answer.kind === "onion_identity"
        ? "onion identity · not for IP-level follow-up"
        : "estimated origin";
  return (
    <tr>
      <td>
        <Link className="mono" to={`/tx/${claim.txid}`} title={claim.txid}>
          {formatId(claim.txid)}
        </Link>
      </td>
      <td className="soft">
        {claim.capture_id} · {claim.observer}
      </td>
      <td>{kind}</td>
      <td>
        <ValidityChip validity={claim.validity} />
      </td>
      <td className="num" title={claim.calibration_basis}>{claim.probability.toFixed(2)}</td>
    </tr>
  );
}

function ClusterLink({ link }: { link: LinkedCluster }) {
  return (
    <article className="lead">
      <div>
        <p className="lead-ip">
          <Link to={`/entities/${encodeURIComponent(link.cluster_id)}`} className="mono">
            {link.cluster}
          </Link>{" "}
          <Chip>{link.basis}</Chip>
        </p>
        <p className="soft" style={{ fontSize: "var(--fs-small)", marginTop: "var(--sp-1)" }}>
          {link.statement}
        </p>
        <details style={{ marginTop: "var(--sp-2)" }}>
          <summary className="label">
            Evidence: {link.evidence_chain} ({link.evidence.length} of {link.evidence_total})
          </summary>
          <ul className="soft" style={{ fontSize: "var(--fs-small)" }}>
            {link.evidence.map((e) => (
              <li key={`${e.basis}-${e.txid}`}>
                {e.basis}: <Link className="mono" to={`/tx/${e.txid}`}>{formatId(e.txid)}</Link> ·{" "}
                {e.rows.length} raw row{e.rows.length === 1 ? "" : "s"} (
                {e.rows
                  .slice(0, 3)
                  .map((r) => (r.row != null ? `row ${r.row}` : `${r.capture_id} @ ${r.announce_ts}`))
                  .join(", ")}
                {e.rows.length > 3 ? ", …" : ""}) · inputs {e.inputs.map((a) => formatId(a)).join(", ")}
              </li>
            ))}
          </ul>
        </details>
      </div>
      <div style={{ textAlign: "right" }}>
        <p className="label">confidence</p>
        <p className="num" title={link.confidence_rule}>{link.confidence.toFixed(3)}</p>
      </div>
    </article>
  );
}

function TimingBlock({ profile }: { profile: PeerProfile }) {
  const t = profile.timing;
  if (!t.sufficient) return <p className="soft">{t.statement}</p>;
  const hours = t.active_hours_utc ?? [];
  const peak = Math.max(1, ...hours);
  const gaps = t.inter_announcement_s;
  return (
    <>
      <p className="soft">{t.statement}</p>
      <p style={{ marginTop: "var(--sp-2)" }}>
        {t.announce_rate_per_min ?? "—"} announcements/min · interval median{" "}
        {gaps?.median ?? "—"} s, mean {gaps?.mean ?? "—"} s, sd {gaps?.stdev ?? "—"} s
      </p>
      <div
        role="img"
        aria-label={`Announcements by hour, UTC: ${hours.map((n, h) => `${h}h ${n}`).join(", ")}`}
        style={{ display: "flex", alignItems: "flex-end", gap: 2, height: 48, marginTop: "var(--sp-2)" }}
      >
        {hours.map((n, h) => (
          <div
            key={h}
            title={`${h}:00 UTC — ${n}`}
            style={{ flex: 1, height: `${(n / peak) * 100}%`, minHeight: 1, background: "var(--evidence)" }}
          />
        ))}
      </div>
      <Label>active hours, UTC 0–23</Label>
    </>
  );
}

export function Asn() {
  const { asn = "" } = useParams();
  const { data, error, loading } = useApi((signal) => api.asnProfile(asn, signal), [asn]);
  return (
    <Shell>
      <section className="section">
        <div className="section-head">
          <div>
            <Label>autonomous system</Label>
            <h1 className="mono" style={{ marginTop: "var(--sp-2)" }}>AS{asn}</h1>
          </div>
          <PeerLookup />
        </div>
        {error ? (
          <ErrorNote error={error} />
        ) : loading || !data ? (
          <SkeletonRows rows={6} />
        ) : (
          <AsnBody profile={data} />
        )}
      </section>
    </Shell>
  );
}

function AsnBody({ profile }: { profile: AsnProfile }) {
  const t = profile.totals;
  return (
    <>
      {profile.header.simulated_only && (
        <Notice title="Simulated or fixture data only">{profile.header.statement}</Notice>
      )}
      <p className="soft measure" style={{ margin: "var(--sp-3) 0" }}>{profile.caveat}</p>
      <p style={{ marginBottom: "var(--sp-3)" }}>
        {profile.peers} peers · {t.originated} originated ({t.by_tier.PASS} pass,{" "}
        {t.by_tier.QUALIFIED} qualified, {t.by_tier.ANNOTATE} annotated) · {t.withheld} withheld ·{" "}
        {t.relayed} relayed · {t.linked_clusters} linked clusters
      </p>
      <div className="table-wrap">
        <table className="data">
          <thead>
            <tr>
              <th>Peer</th>
              <th className="num">Originated</th>
              <th>By tier</th>
              <th className="num">Withheld</th>
              <th className="num">Relayed</th>
              <th className="num">Clusters</th>
              <th>Seen in</th>
            </tr>
          </thead>
          <tbody>
            {profile.members.map((m) => (
              <tr key={m.peer}>
                <td>
                  <Link className="mono" to={peerPath(m.peer)}>{m.peer}</Link>
                </td>
                <td className="num">{m.originated}</td>
                <td className="soft">
                  {m.by_tier.PASS}/{m.by_tier.QUALIFIED}/{m.by_tier.ANNOTATE}
                </td>
                <td className="num">{m.withheld}</td>
                <td className="num">{m.relayed}</td>
                <td className="num">{m.linked_clusters.length}</td>
                <td className="soft">{m.captures.join(", ")}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </>
  );
}
