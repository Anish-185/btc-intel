/** Tags show their source and date, say "simulated" on every simulated row,
 *  flag conflicts without resolving them, and keep each actor member's tags
 *  under that member. */
import { render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

import { api } from "../api/client";
import type { ShownTag, TagsResponse } from "../api/types";
import { TagsSection } from "../components/Tags";

afterEach(() => vi.restoreAllMocks());

const tag = (over: Partial<ShownTag>): ShownTag => ({
  subject: "a1", label: "simulated ransomware operation C1", category: "ransomware",
  source: "simulated", reference: "generator ground_truth.json, seed 7, cluster C1",
  collected: "2026-09-01", confidence: 1, applies_to: "cluster", simulated: true,
  bundle: "demo", basis: "cluster tag, through member a1", via: "a1",
  effective_confidence: 0.5, ...over,
});

const response = (over: Partial<TagsResponse>): TagsResponse => ({
  kind: "actor", subject: "A-17", tags: 2, simulated: true,
  bundles: [{ name: "demo", ok: true, simulated: true }],
  statement: "Tags describe services and categories, never private individuals.",
  entities: [], addresses: [], ...over,
});

describe("tags", () => {
  it("shows source, date and the simulated flag, and flags a conflict", async () => {
    vi.spyOn(api, "tags").mockResolvedValue(response({
      kind: "entity", subject: "c1",
      entities: [{ entity_id: "c1", merge_confidence: 0.5, conflict: true,
                   categories: ["exchange/VASP", "ransomware"], member_tags: [],
                   tags: [tag({}), tag({ label: "simulated exchange C9 hot wallet",
                                         category: "exchange/VASP" })] }],
    }));
    render(<TagsSection kind="entity" subject="c1" />);
    expect(await screen.findByText("simulated ransomware operation C1")).toBeInTheDocument();
    expect(screen.getByText("simulated exchange C9 hot wallet")).toBeInTheDocument();
    expect(screen.getAllByText("simulated, not intelligence")).toHaveLength(2);
    expect(screen.getByText("conflicting tags")).toBeInTheDocument();
    expect(document.body.textContent).toMatch(/simulated, collected 2026-09-01/);
  });

  it("lists an actor's tags under each member, never across the join", async () => {
    vi.spyOn(api, "tags").mockResolvedValue(response({
      entities: [
        { entity_id: "c1", merge_confidence: 1, conflict: false, categories: ["ransomware"],
          member_tags: [], tags: [tag({})] },
        { entity_id: "c2", merge_confidence: 1, conflict: false, categories: [],
          member_tags: [], tags: [] },
      ],
    }));
    render(<TagsSection kind="actor" subject="A-17" />);
    expect(await screen.findByText("cluster c1")).toBeInTheDocument();
    expect(screen.queryByText("cluster c2")).toBeNull();
    expect(screen.getByText(/Each cluster's tags stay with that cluster/)).toBeInTheDocument();
  });
});
