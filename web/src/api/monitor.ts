/** Live monitoring and the custody ledger — the two endpoints that say what
 *  the system is doing right now, and what it has done. */
import { API_BASE } from "./client";

export interface MonitorStatus {
  running: boolean;
  started_at: string | null;
  inbox: string;
  files: number;
  rows: number;
  transactions: number;
  duplicates: number;
  alerts: number;
  errors: number;
  last_event: string | null;
  pending?: string[];
  poll_seconds?: number;
}

export interface FeedAlert {
  entity_id: string;
  risk_score: number;
  reason: string;
  pattern_types?: string[];
}

export interface FeedEvent {
  type: "started" | "stopped" | "file" | "processed" | "error";
  at: string;
  name?: string;
  bytes?: number;
  file?: string;
  rows?: number;
  new_rows?: number;
  transactions?: number;
  duplicates?: number;
  quarantined?: number;
  reason?: string;
  entities?: string[];
  alerts?: FeedAlert[];
  seconds?: number;
  error?: string;
  inbox?: string;
}

export interface CustodyEntry {
  seq: number;
  at: string;
  action: string;
  actor: string;
  hash: string;
  prev: string;
  detail: {
    files?: { path: string; sha256: string; bytes: number }[];
    [key: string]: unknown;
  };
}

export interface CustodyVerification {
  entries: number;
  chain_intact: boolean;
  broken_at: number | null;
  head: string;
  files_changed: string[];
  files_missing: string[];
  note: string;
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

export const monitorApi = {
  status: (signal?: AbortSignal) => json<MonitorStatus>("/monitor/status", { signal }),
  feed: (signal?: AbortSignal) =>
    json<{ events: FeedEvent[]; status: MonitorStatus }>("/monitor/feed?limit=50", { signal }),
  start: () => json<MonitorStatus>("/monitor/start", { method: "POST" }),
  stop: () => json<MonitorStatus>("/monitor/stop", { method: "POST" }),
  simulate: (transactions = 40) =>
    json<{ file: string }>(`/monitor/simulate?transactions=${transactions}`, { method: "POST" }),

  /** Server-sent events for every arrival. Returns a closer. */
  watch(onEvent: (event: FeedEvent) => void): () => void {
    const source = new EventSource(`${API_BASE}/monitor/events`);
    source.onmessage = (message) => {
      try {
        onEvent(JSON.parse(message.data) as FeedEvent);
      } catch {
        /* a keep-alive comment, not an event */
      }
    };
    source.onerror = () => source.close();
    return () => source.close();
  },
};

export const custodyApi = {
  log: (signal?: AbortSignal) =>
    json<{ total: number; actor: string; head: string; entries: CustodyEntry[] }>(
      "/custody?limit=200",
      { signal },
    ),
  verify: (signal?: AbortSignal) => json<CustodyVerification>("/custody/verify", { signal }),
};
