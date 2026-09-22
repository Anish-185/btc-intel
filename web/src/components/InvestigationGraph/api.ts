/** The graph endpoints. Same base-URL rule as the rest of the console. */
import { API_BASE } from "../../api/client";
import type { GraphPayload } from "./model";

async function get<T>(path: string, signal?: AbortSignal): Promise<T> {
  const response = await fetch(`${API_BASE}${path}`, { signal });
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

export interface NeighborsPage extends GraphPayload {
  node_id: string;
  total: number;
  returned: number;
  offset: number;
  has_more: boolean;
  remaining: number;
}

export interface TracePayload extends GraphPayload {
  root: string;
  direction: "forward" | "backward";
  pruned_edges: number;
  wallets: number;
}

export interface PathPayload extends GraphPayload {
  from: string;
  to: string;
  hops: number;
  path: string[];
}

export interface ClusterPayload extends GraphPayload {
  cluster_id: string;
  size: number;
  risk: number;
  flag: string | null;
}

const q = (value: string) => encodeURIComponent(value);

export const graphApi = {
  neighbors: (
    id: string,
    { direction = "both", limit = 20, offset = 0 }: {
      direction?: "in" | "out" | "both";
      limit?: number;
      offset?: number;
    } = {},
    signal?: AbortSignal,
  ) =>
    get<NeighborsPage>(
      `/graph/nodes/${q(id)}/neighbors?direction=${direction}&limit=${limit}&offset=${offset}`,
      signal,
    ),

  trace: (
    from: string,
    {
      direction = "forward",
      maxHops = 4,
      minAmount = 0,
    }: { direction?: "forward" | "backward"; maxHops?: number; minAmount?: number } = {},
    signal?: AbortSignal,
  ) =>
    get<TracePayload>(
      `/graph/trace?from=${q(from)}&direction=${direction}&max_hops=${maxHops}&min_amount=${minAmount}`,
      signal,
    ),

  taint: (seed: string, maxHops = 4, signal?: AbortSignal) =>
    get<{
      seed: string;
      seed_entity: string;
      tainted: { entity_id: string; score: number; hops: number; path: string[] }[];
      total: number;
      caveat: string;
    }>(`/graph/taint?seed=${q(seed)}&max_hops=${maxHops}`, signal),

  path: (from: string, to: string, signal?: AbortSignal) =>
    get<PathPayload>(`/graph/path?from=${q(from)}&to=${q(to)}`, signal),

  cluster: (id: string, signal?: AbortSignal) =>
    get<ClusterPayload>(`/graph/clusters/${q(id)}`, signal),

  async save(name: string, state: unknown) {
    const response = await fetch(`${API_BASE}/investigations`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ name, state }),
    });
    if (!response.ok) throw new Error(`could not save: ${response.statusText}`);
    return (await response.json()) as { id: string; name: string; saved_at: string };
  },

  load: (id: string, signal?: AbortSignal) =>
    get<{ id: string; name: string; saved_at: string; state: Record<string, unknown> }>(
      `/investigations/${q(id)}`,
      signal,
    ),
};
