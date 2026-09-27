/** The cash-out panel: runs on request, marks simulated tags, says where funds
 *  entered a CoinJoin, and never names an untagged sink. */
import { fireEvent, render, screen } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { afterEach, describe, expect, it, vi } from "vitest";

import { api } from "../api/client";
import type { ExitPoints } from "../api/types";
import { ExitPointsSection } from "../components/ExitPoints";

afterEach(() => vi.restoreAllMocks());

const data: ExitPoints = {
  kind: "entity", subject: "S", note: null, simulated_tags: true,
  statement: "An investigative lead, not proof of identity or ownership.",
  traces: [{
    seed: "S", seed_amount: 10, at_depth_limit: { haircut: 0, poison: 0 },
    mixes: { haircut: [{ from: "B", value: 4, txids: ["coinjoin-1"] }], poison: [] },
    sinks: [{ entity_id: "U", label: "untagged sink", share_kept: 0.3 }],
    candidates: [{
      rank: 1, entity_id: "V", conflict: false, receiving_addresses: ["v1"],
      time_window: ["2026-01-01", "2026-01-02"], evidence_sha256: "0".repeat(64),
      tags: [{ subject: "v1", label: "simulated exchange", category: "exchange/VASP",
               source: "simulated", reference: "r", collected: "2026-01-01", confidence: 1,
               applies_to: "cluster", simulated: true, bundle: "demo", basis: "cluster tag",
               via: "v1", effective_confidence: 1 }],
      models: {
        haircut: { amount: 3, share: 0.3, path_confidence: 0.15, score: 0.045, paths: [] },
        poison: { amount: 3, share: 0.3, path_confidence: 0.5, score: 0.15, paths: [] },
      },
    }],
  }],
};

describe("trace to cash-out", () => {
  it("traces on request and states its limits", async () => {
    const spy = vi.spyOn(api, "exitPoints").mockResolvedValue(data);
    render(<MemoryRouter><ExitPointsSection kind="entity" subject="S" /></MemoryRouter>);
    expect(spy).not.toHaveBeenCalled();
    fireEvent.click(screen.getByRole("button", { name: "trace to cash-out" }));
    expect(await screen.findByText("simulated exchange")).toBeInTheDocument();
    expect(screen.getByText(/not proof of identity or ownership/)).toBeInTheDocument();
    expect(screen.getByText("simulated tags")).toBeInTheDocument();
    expect(screen.getByText(/funds entered a CoinJoin from B/)).toBeInTheDocument();
    expect(screen.getByText(/Untagged sinks/).textContent).toMatch(/U 30.0%/);
    expect(screen.getByRole("link", { name: /investigator packet/ })).toHaveAttribute(
      "href", expect.stringContaining("/exit-points/entity/S/packet"));
    expect(document.body.textContent).toMatch(/\(simulated, 2026-01-01\)/);
  });
});
