/** The red-team page, where it would be worst to be wrong.
 *
 *  A miss has to be shown as plainly as a catch — a demo whose detector cannot
 *  visibly lose is not a demo — and the controls a typology ignores must not
 *  look like they do something.
 */
import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { afterEach, describe, expect, it, vi } from "vitest";

import { RedTeam } from "../pages/RedTeam";
import { ToastHost } from "../components/Toasts";
import { redteamApi, type RunResult } from "../api/redteam";

const TYPOLOGIES = {
  typologies: [
    { id: "ransomware_collector", label: "ransomware collector", about: "many victims",
      uses: ["hops", "total_btc", "wallets"] },
    { id: "coinjoin", label: "coinjoin", about: "equal-value mixing",
      uses: ["total_btc", "wallets"] },
  ],
  broadcast: [{ id: "residential", label: "residential IP", about: "a home connection" }],
};

const result = (over: Partial<RunResult> = {}): RunResult => ({
  typology: "coinjoin",
  requested_typology: "coinjoin",
  seed: 42,
  transactions: 3,
  rows: 40,
  entities: ["bc1qinjected0001"],
  wallets: ["bc1qinjected0001", "bc1qinjected0002"],
  wallet_count: 2,
  minted_wallets: 6,
  txids: ["a".repeat(64)],
  threshold: 0.7,
  detected: false,
  alerts: [],
  entity_scores: [{ entity_id: "bc1qinjected0001", rule_score: 0.2, anomaly_score: 0.31,
    gnn_score: 0, taint_score: 0, risk_score: 0.42 }],
  origin: { transactions: 1, named_exactly: 0, in_candidates: 1, best_rank: 3,
    detail: [{ txid: "a".repeat(64), true_origin_ip: "10.1.2.3", estimated_origin_ip: "10.9.9.9",
      ip_class: "residential_or_unknown", confidence: 0.4, low_confidence_origin: true,
      rank: 3, observed: true }],
    caveat: "rank is over the estimator's ranked candidates" },
  timing: { stages: [{ name: "anomaly", seconds: 1.4 }], total_seconds: 2.1 },
  time_to_detect: 2.4,
  graph: { nodes: 100, entities: 40 },
  ...over,
});

/** Start a run, and hand back the callback the page gave the event stream. */
function stubRun(final: RunResult) {
  vi.spyOn(redteamApi, "typologies").mockResolvedValue(TYPOLOGIES);
  vi.spyOn(redteamApi, "scoreboard").mockResolvedValue({
    runs: [], by_typology: {}, total: 0, detected: 0, detection_rate: null });
  vi.spyOn(redteamApi, "start").mockResolvedValue({ run_id: "r1", events: "/x" });
  vi.spyOn(redteamApi, "get").mockResolvedValue({
    run_id: "r1", status: "done", started_at: "", typology: final.requested_typology,
    params: {} as never, detected: final.detected, time_to_detect: final.time_to_detect,
    origin_rank: final.origin.best_rank, error: null, stages: [], result: final });
  const events: ((e: never) => void)[] = [];
  vi.spyOn(redteamApi, "watch").mockImplementation((_id, onEvent) => {
    events.push(onEvent as never);
    return () => undefined;
  });
  return events;
}

const draw = () =>
  render(
    <ToastHost>
      <MemoryRouter>
        <RedTeam />
      </MemoryRouter>
    </ToastHost>,
  );

afterEach(() => vi.restoreAllMocks());

describe("the red-team page", () => {
  it("says plainly when nothing was detected, with every engine's score", async () => {
    const events = stubRun(result());
    draw();
    await screen.findByText("ransomware collector");

    await userEvent.click(screen.getByRole("button", { name: /inject and re-run/i }));
    await waitFor(() => expect(events).toHaveLength(1));
    events[0]({ type: "done", elapsed: 2.4 } as never);

    const notice = await screen.findByText(/did not raise an alert/i);
    expect(notice).toBeTruthy();
    // The numbers that fell short, not a shrug.
    const row = screen.getByText("bc1qin…0001").closest("tr")!;
    expect(within(row).getByText("0.420")).toBeTruthy();   // fused
    expect(within(row).getByText("0.280")).toBeTruthy();   // how far short of 0.7
  });

  it("links a detection into the graph with the injected wallets marked", async () => {
    const events = stubRun(
      result({
        detected: true,
        requested_typology: "ransomware_collector",
        alerts: [{ entity_id: "bc1qinjected0001", risk_score: 0.93,
          reason: "Peeling chain over 5 hops from a collector address." }],
      }),
    );
    draw();
    await screen.findByText("ransomware collector");
    await userEvent.click(screen.getByRole("button", { name: /inject and re-run/i }));
    await waitFor(() => expect(events).toHaveLength(1));
    events[0]({ type: "done", elapsed: 2.4 } as never);

    await screen.findByText(/Peeling chain over 5 hops/);
    const link = screen.getByRole("link", { name: /injected wallets in the graph/i });
    expect(link.getAttribute("href")).toContain("focus=bc1qinjected0001");
    expect(link.getAttribute("href")).toContain("highlight=bc1qinjected0001%2Cbc1qinjected0002");
  });

  it("disables the controls the chosen typology does not read", async () => {
    stubRun(result());
    draw();
    await screen.findByText("ransomware collector");

    // A coinjoin has no hop depth, so the hop slider must not pretend it does.
    await userEvent.selectOptions(screen.getByLabelText(/typology/i), "coinjoin");
    await waitFor(() =>
      expect((screen.getByLabelText(/^hops/i) as HTMLInputElement).disabled).toBe(true));
    expect((screen.getByLabelText(/wallets/i) as HTMLInputElement).disabled).toBe(false);
  });

  it("surprise me stays inside the ranges the endpoint accepts", async () => {
    stubRun(result());
    draw();
    await screen.findByText("ransomware collector");
    const hops = () => Number((screen.getByLabelText(/^hops/i) as HTMLInputElement).value);
    const wallets = () => Number((screen.getByLabelText(/wallets/i) as HTMLInputElement).value);

    for (let i = 0; i < 20; i++) {
      await userEvent.click(screen.getByRole("button", { name: /surprise me/i }));
      expect(hops()).toBeGreaterThanOrEqual(2);
      expect(hops()).toBeLessThanOrEqual(8);
      expect(wallets()).toBeGreaterThanOrEqual(2);
      expect(wallets()).toBeLessThanOrEqual(60);
    }
  });
});
