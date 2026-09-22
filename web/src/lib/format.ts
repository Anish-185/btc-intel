/** Formatting the console agrees on once. */

export const score3 = (value: number | null | undefined) =>
  value == null ? "—" : value.toFixed(3);

export const pct = (value: number | null | undefined) =>
  value == null ? "—" : `${Math.round(value * 100)}%`;

/** Identifier shortening lives in one place — see lib/formatId.ts. Re-exported
 *  here because this is where the rest of the console already looks for
 *  formatting. */
export { ELLIPSIS, ID_HEAD, ID_TAIL, formatId, maxIdLength } from "./formatId";

export const PATTERN_LABEL: Record<string, string> = {
  ransomware_collector: "ransomware collector",
  layering: "layering",
  peel_chain: "peel chain",
  coinjoin: "coinjoin",
  same_actor_cluster: "same-actor cluster",
};

export const patternLabel = (name: string) =>
  PATTERN_LABEL[name] ?? name.replace(/_/g, " ");

/** IP classes are categories, not severities — they get a two-letter code and
 *  a plain-English name, never a place on the risk ramp. */
export const IP_CLASS: Record<string, { code: string; label: string }> = {
  residential_or_unknown: { code: "RS", label: "residential or unknown" },
  tor_exit: { code: "TX", label: "tor exit" },
  hosting_vpn: { code: "HV", label: "hosting / vpn" },
  known_bitcoin_relay: { code: "RL", label: "known bitcoin relay" },
};

export const ipClass = (name: string) =>
  IP_CLASS[name] ?? { code: name.slice(0, 2).toUpperCase(), label: name.replace(/_/g, " ") };

/** What kind of thing an evidence string is, so the list can link it. */
export type EvidenceKind = "transaction" | "wallet" | "ip" | "note";

export function evidenceKind(value: string): EvidenceKind {
  if (/^[0-9a-f]{64}$/i.test(value)) return "transaction";
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(value)) return "ip";
  if (/^(bc1|[13])[a-z0-9]{8,}$/i.test(value)) return "wallet";
  return "note";
}
