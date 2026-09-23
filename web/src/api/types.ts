/** The shapes api/app.py actually returns. Kept narrow on purpose: fields the
 *  console does not draw are not typed here. */

export type IpClass =
  | "residential_or_unknown"
  | "tor_exit"
  | "hosting_vpn"
  | "known_bitcoin_relay";

export interface Lead {
  ip: string;
  ip_class: IpClass;
  confidence: number;
  observations: number;
  anonymized_entry_point?: boolean;
  label?: string;
  evidence: string;
}

export interface Alert {
  alert_id: string;
  entity_id: string;
  entity_type: "cluster" | "wallet";
  pattern_types: string[];
  risk_score: number;
  reason: string;
  evidence: string[];
  top_signal: string;
  rule_score: number;
  anomaly_score: number;
  gnn_score: number;
  taint_score: number;
  taint_path: string[];
  /** JSON strings on this endpoint — the pipeline writes them packed. */
  leads: string;
  contributions: string;
  wallets: number;
  suspicious_merge: boolean;
  /** Queue tiebreakers, in the order fusion/ordering.py applies them after the
   *  composite score. Shown in the queue so the order is legible when several
   *  alerts read the same risk. */
  rule_typologies: number;
  /** Hops from a watchlist seed; 1000000 means no taint path at all. */
  taint_hops: number;
  lead_confidence: number;
  tx_count: number;
  /** The full key as a JSON array, so any consumer orders identically. */
  sort_key: string;
}

export interface AlertsPage {
  alert_threshold: number | null;
  stacker: Record<string, unknown>;
  total: number;
  limit: number;
  offset: number;
  alerts: Alert[];
}

export interface Stats {
  rows: number;
  transactions: number;
  total_entities: number;
  total_alerts: number;
  alerts_by_pattern_type: Record<string, number>;
  avg_confidence: number;
  features: {
    origin_estimation: {
      status: "ok" | "degraded";
      reason: string;
      multi_hop_transactions: number;
      mean_observations_per_transaction: number;
      estimator: string;
    };
  };
  stacker: Record<string, unknown>;
}

export interface EntityDetail {
  entity_id: string;
  entity_type: "cluster" | "wallet";
  wallets: string[];
  flag: string | null;
  features: Record<string, number | string | null>;
  scores: {
    risk_score: number | null;
    rule_score: number | null;
    anomaly_score: number | null;
    gnn_score: number | null;
    taint_score: number | null;
    top_signal: string | null;
    contributions: Record<string, number>;
  };
  alerted: boolean;
  pattern_types: string[];
  reason: string | null;
  evidence: string[];
  taint_path: string[];
  leads: Lead[];
  caveat: string;
}

export type GraphNodeType = "wallet" | "transaction" | "ip";

export interface GraphElements {
  nodes: { data: Record<string, unknown> & { id: string; type?: GraphNodeType } }[];
  edges: { data: Record<string, unknown> & { id: string; source: string; target: string } }[];
}

export interface EntityGraph {
  entity_id: string;
  hops: number;
  truncated: boolean;
  counts: { wallets: number; transactions: number; ips: number };
  layout: { name: string };
  elements: GraphElements;
}

export interface Propagation {
  txid: string;
  estimated_origin: string | null;
  ip_class: IpClass;
  confidence: number;
  attribution_confidence: number;
  estimator: string;
  degraded: boolean;
  low_confidence_origin: boolean;
  anonymized_entry_point: boolean;
  n_observations: number;
  runner_ups: { ip: string; score: number }[];
  caveat: string;
  layout: { name: string; roots: string[] };
  elements: GraphElements;
}
