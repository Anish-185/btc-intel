/** The red-team endpoints: inject, watch, score, reset. */
import { API_BASE } from "./client";

export interface Injection {
  typology: string;
  hops: number;
  total_btc: number;
  window_hours: number;
  wallets: number;
  broadcast: string;
  seed?: number | null;
}

export interface RunEvent {
  type: "stage" | "done" | "failed";
  name?: string;
  detail?: string;
  seconds?: number;
  elapsed: number;
  error?: string;
  detected?: boolean;
  time_to_detect?: number;
}

export interface EngineScore {
  entity_id: string;
  rule_score: number;
  anomaly_score: number;
  gnn_score: number;
  taint_score: number;
  risk_score: number;
}

export interface OriginDetail {
  txid: string;
  true_origin_ip: string;
  estimated_origin_ip: string | null;
  ip_class: string;
  confidence: number;
  low_confidence_origin: boolean;
  rank: number | null;
  observed: boolean;
}

export interface RunResult {
  /** What the generator was asked to build. */
  typology: string;
  /** What the judge chose — the two differ for peel chain. */
  requested_typology: string;
  seed: number;
  transactions: number;
  rows: number;
  entities: string[];
  wallets: string[];
  wallet_count: number;
  minted_wallets: number;
  txids: string[];
  threshold: number;
  detected: boolean;
  alerts: { entity_id: string; risk_score: number; reason: string }[];
  entity_scores: EngineScore[];
  origin: {
    transactions: number;
    named_exactly: number;
    in_candidates: number;
    best_rank: number | null;
    detail: OriginDetail[];
    caveat: string;
  };
  timing: { stages: { name: string; seconds: number }[]; total_seconds: number };
  time_to_detect: number;
  graph: { nodes: number; entities: number };
}

export interface RunSummary {
  run_id: string;
  status: string;
  started_at: string;
  typology: string;
  params: Injection;
  detected: boolean | null;
  time_to_detect: number | null;
  origin_rank: number | null;
  error: string | null;
}

export interface Scoreboard {
  runs: RunSummary[];
  by_typology: Record<string, { runs: number; detected: number; detection_rate: number | null }>;
  total: number;
  detected: number;
  detection_rate: number | null;
}

async function json<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(`${API_BASE}${path}`, init);
  if (!response.ok) {
    let detail = response.statusText;
    try {
      const body = await response.json();
      if (typeof body?.detail === "string") detail = body.detail;
    } catch {
      /* the status line is all we have */
    }
    throw new Error(detail);
  }
  return (await response.json()) as T;
}

export const redteamApi = {
  typologies: (signal?: AbortSignal) =>
    json<{
      typologies: { id: string; label: string; about: string; uses: string[] }[];
      broadcast: { id: string; label: string; about: string }[];
    }>("/redteam/typologies", { signal }),

  start: (body: Injection) =>
    json<{ run_id: string; events: string }>("/redteam/runs", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(body),
    }),

  get: (id: string, signal?: AbortSignal) =>
    json<RunSummary & { stages: RunEvent[]; result: RunResult | null }>(
      `/redteam/runs/${encodeURIComponent(id)}`,
      { signal },
    ),

  scoreboard: (signal?: AbortSignal) => json<Scoreboard>("/redteam/runs", { signal }),

  reset: () => json<{ restored: string[]; hashes_match: boolean }>("/redteam/reset", {
    method: "POST",
  }),

  /** Server-sent events for one run. Returns a closer. */
  watch(id: string, onEvent: (event: RunEvent) => void): () => void {
    const source = new EventSource(`${API_BASE}/redteam/runs/${encodeURIComponent(id)}/events`);
    source.onmessage = (message) => {
      try {
        onEvent(JSON.parse(message.data) as RunEvent);
      } catch {
        /* a keep-alive comment, not an event */
      }
    };
    // The stream closes itself when the run ends; an error here means the
    // connection dropped, and the caller polls once to find out how it went.
    source.onerror = () => source.close();
    return () => source.close();
  },
};
