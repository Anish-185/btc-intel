/** Investigative leads — deliberately not part of the risk reasons.
 *
 *  A correlation between an entity and an IP address says something about
 *  *where a broadcast was seen*, never about who sent it and never about
 *  whether the entity is criminal. The wording here is fixed: "associated
 *  with", never "belongs to". Every lead states its class, its confidence, and
 *  whether the origin estimate behind it was weak. */
import { Link } from "react-router-dom";
import type { Lead } from "../api/types";
import { ipClass } from "../lib/format";
import { Chip, ValidityChip } from "./ui";

export function LeadsPanel({
  leads,
  lowConfidence,
}: {
  leads: Lead[];
  lowConfidence?: boolean;
}) {
  return (
    <section className="leads" aria-labelledby="leads-head">
      <div className="section-head" style={{ marginBottom: "var(--sp-2)" }}>
        <h2 id="leads-head">Investigative leads</h2>
        <span className="label">attribution · not evidence of crime</span>
      </div>
      <p className="soft measure" style={{ marginBottom: "var(--sp-3)" }}>
        Addresses this entity is <strong>associated with</strong> through observed broadcasts.
        An association is a place to look next, not a person, and not a reason the entity is
        on this list.
      </p>

      {leads.length === 0 ? (
        <p className="soft">No IP association reached the reporting threshold.</p>
      ) : (
        leads.map((lead) => {
          const cls = ipClass(lead.ip_class);
          const anonymized =
            lead.anonymized_entry_point ?? ["tor_exit", "hosting_vpn"].includes(lead.ip_class);
          return (
            <article className="lead" key={`${lead.ip}-${lead.observations}`}>
              <div>
                <p className="lead-ip">
                  <Link to={`/peers/${encodeURIComponent(lead.ip)}`} title="Peer profile">
                    {lead.ip}
                  </Link>{" "}
                  <Chip title={cls.label}>
                    <span aria-hidden="true">{cls.code}</span> {cls.label}
                  </Chip>{" "}
                  {anonymized && (
                    <Chip tone="caution" title="Where the broadcast entered the network, not who sent it">
                      <span aria-hidden="true">⚠</span> anonymized entry point
                    </Chip>
                  )}
                  {lead.validity && <ValidityChip validity={lead.validity} />}{" "}
                  {lowConfidence && (
                    <Chip tone="caution" title="The origin estimate behind this lead is weak">
                      <span aria-hidden="true">⚠</span> low confidence origin
                    </Chip>
                  )}
                </p>
                <p className="soft" style={{ fontSize: "var(--fs-small)", marginTop: "var(--sp-1)" }}>
                  {lead.evidence}
                </p>
              </div>
              <div style={{ textAlign: "right" }}>
                <p className="label">confidence</p>
                <p className="num">{lead.confidence.toFixed(3)}</p>
                <p className="label" style={{ marginTop: "var(--sp-1)" }}>
                  {lead.observations} broadcast{lead.observations === 1 ? "" : "s"}
                </p>
              </div>
            </article>
          );
        })
      )}
    </section>
  );
}
