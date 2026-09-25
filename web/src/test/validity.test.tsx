/** A QUALIFIED origin never renders as if it were an IP attribution: an onion
 *  identity is shown as an onion identity, a CoinJoin's broadcaster says the
 *  inputs' owners are not attributable, and a withheld origin shows no address. */
import { render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { afterEach, describe, expect, it, vi } from "vitest";

import { api } from "../api/client";
import type { Propagation, Validity } from "../api/types";
import { Transaction } from "../pages/Transaction";

vi.mock("../components/FieldGraph", () => ({ FieldGraph: () => <div data-testid="field" /> }));

afterEach(() => vi.restoreAllMocks());

const ONION = "pg6mmjiyjmcrsslvykfwnntlaru7p5svn6y2ymmju6nubxndf4pscryd.onion";

function tree(validity: Validity, answer: Propagation["answer"], origin: string): Propagation {
  return {
    txid: "a".repeat(64), estimated_origin: origin, ip_class: "tor_exit", confidence: 0.8,
    attribution_confidence: 0.4, estimator: "first_timestamp", degraded: false,
    low_confidence_origin: validity.tier === "ABSTAIN", anonymized_entry_point: true,
    probability: 0.8, calibration_basis: "uncalibrated", validity, answer,
    n_observations: 5, runner_ups: [], caveat: "a lead",
    layout: { name: "dagre", roots: [] }, elements: { nodes: [], edges: [] },
  };
}

async function open(data: Propagation) {
  vi.spyOn(api, "propagation").mockResolvedValue(data);
  render(
    <MemoryRouter initialEntries={[`/tx/${data.txid}`]}>
      <Routes>
        <Route path="/tx/:txid" element={<Transaction />} />
      </Routes>
    </MemoryRouter>,
  );
  await waitFor(() => expect(screen.getAllByText(/validity|qualified|abstain/i).length).toBeGreaterThan(0));
}

describe("a qualified origin is never shown as an IP attribution", () => {
  it("shows an onion identity as an onion identity", async () => {
    await open(tree(
      { tier: "QUALIFIED", reason: "TOR_ONION", reasons: ["TOR_ONION"], confidence: 1,
        evidence: ["a Tor hidden service"] },
      { kind: "onion_identity", onion: ONION, actionable: "not for IP-level follow-up" },
      ONION));
    expect(screen.getByRole("heading", { name: /onion identity/i })).toBeInTheDocument();
    expect(screen.queryByRole("heading", { name: /estimated origin/i })).not.toBeInTheDocument();
    expect(screen.getByText(/not for IP-level follow-up/i)).toBeInTheDocument();
    expect(screen.getAllByText(/qualified: tor onion/i).length).toBeGreaterThan(0);
  });

  it("names a CoinJoin's broadcaster and says input ownership is not attributable", async () => {
    await open(tree(
      { tier: "QUALIFIED", reason: "COINJOIN", reasons: ["COINJOIN"], confidence: 1,
        evidence: ["6 of 6 outputs pay 0.1 BTC"] },
      { kind: "broadcasting_peer", ip: "203.0.113.9", input_ownership: "not attributable" },
      "203.0.113.9"));
    expect(screen.getByRole("heading", { name: /broadcasting peer/i })).toBeInTheDocument();
    expect(screen.getByText(/input ownership not attributable/i)).toBeInTheDocument();
    expect(screen.queryByRole("heading", { name: /estimated origin/i })).not.toBeInTheDocument();
  });

  it("shows no address for a withheld origin", async () => {
    await open(tree(
      { tier: "ABSTAIN", reason: "DEGENERATE", reasons: ["DEGENERATE"], confidence: 1,
        evidence: ["1 peer announced this transaction"] },
      null, "203.0.113.9"));
    expect(screen.getByRole("heading", { name: /origin withheld/i })).toBeInTheDocument();
    expect(screen.queryByText("203.0.113.9")).not.toBeInTheDocument();
  });
});
