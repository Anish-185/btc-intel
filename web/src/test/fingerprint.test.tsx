/** The fingerprint panel names a construction, says "unknown" with its reason,
 *  and says when it read structure only. */
import { render, screen } from "@testing-library/react";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { afterEach, describe, expect, it, vi } from "vitest";

import { api } from "../api/client";
import type { TxFingerprint } from "../api/types";
import { Transaction } from "../pages/Transaction";

vi.mock("../components/FieldGraph", () => ({ FieldGraph: () => <div data-testid="field" /> }));
afterEach(() => vi.restoreAllMocks());

const TX = "d".repeat(64);
const ranked = [
  { label: "core_like", display: "Bitcoin Core-like construction", confidence: 0.81, posterior: 0.9 },
  { label: "electrum_like", display: "Electrum-like construction", confidence: 0.12, posterior: 0.08 },
];

function open(fp: TxFingerprint) {
  vi.spyOn(api, "propagation").mockRejectedValue(new Error("no tree"));
  vi.spyOn(api, "origination").mockResolvedValue({ txid: TX, captures: [], note: null });
  vi.spyOn(api, "fingerprint").mockResolvedValue(fp);
  render(
    <MemoryRouter initialEntries={[`/tx/${TX}`]}>
      <Routes>
        <Route path="/tx/:txid" element={<Transaction />} />
      </Routes>
    </MemoryRouter>,
  );
}

describe("wallet fingerprint on the transaction page", () => {
  it("names the construction with its confidence and the ranked alternatives", async () => {
    open({ txid: TX, label: "core_like", display: "Bitcoin Core-like construction", confidence: 0.81,
           unknown_reason: null, ranked, tells: { version: "v2", locktime: "height" },
           observed_tells: ["version", "locktime"], condition: "full" });
    expect(await screen.findByRole("heading", { name: "Wallet fingerprint" })).toBeInTheDocument();
    expect(screen.getAllByText(/Bitcoin Core-like construction/).length).toBeGreaterThan(0);
    expect(screen.getByText(/version v2 · locktime height/)).toBeInTheDocument();
    expect(document.body.textContent).not.toMatch(/owner|operated by|belongs to/i);
  });

  it("says unknown, why, and that it read structure only", async () => {
    open({ txid: TX, label: "unknown", display: "unknown construction", confidence: 0.41,
           unknown_reason: "top confidence 0.41 is under 0.6", ranked, tells: {},
           observed_tells: [], condition: "structural" });
    expect(await screen.findByText("unknown construction")).toBeInTheDocument();
    expect(screen.getByText(/under 0.6/)).toBeInTheDocument();
    expect(screen.getByText(/from structure only/)).toBeInTheDocument();
  });
});
