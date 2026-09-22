/** What must not break.
 *
 *  Four behaviours, each one a thing an investigator would notice immediately:
 *  the queue orders and filters what it says it does, a verdict actually
 *  reaches the API, attribution never gets mixed into the reasons, and the
 *  ambient field stops when the reader asked for less motion. */
import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { AlertTable, filterAlerts, sortAlerts } from "../components/AlertTable";
import { AmbientField } from "../components/AmbientField";
import { Entity } from "../pages/Entity";
import { ToastHost } from "../components/Toasts";
import { api } from "../api/client";
import { ALERTS, DETAIL } from "./fixtures";
import { setReducedMotion } from "./setup";

// Cytoscape needs a layout engine; the entity page's graph is not what these
// tests are about, so the panel is replaced with a marker.
vi.mock("../components/GraphPanel", () => ({
  GraphPanel: () => <div data-testid="graph-panel" />,
}));

afterEach(() => {
  vi.restoreAllMocks();
  setReducedMotion(false);
});

describe("the queue orders and filters", () => {
  it("sorts by risk, highest first, and can reverse", () => {
    const desc = sortAlerts(ALERTS, "risk_score", "desc").map((a) => a.alert_id);
    const asc = sortAlerts(ALERTS, "risk_score", "asc").map((a) => a.alert_id);
    expect(desc).toEqual(["C000001", "C000002", "C000003"]);
    expect(asc).toEqual(["C000003", "C000002", "C000001"]);
  });

  it("breaks ties on the entity id so rows never shuffle", () => {
    const tied = [
      { ...ALERTS[0], alert_id: "B", entity_id: "B", risk_score: 0.5 },
      { ...ALERTS[0], alert_id: "A", entity_id: "A", risk_score: 0.5 },
    ];
    expect(sortAlerts(tied, "risk_score", "desc").map((a) => a.entity_id)).toEqual(["A", "B"]);
  });

  it("filters by minimum score and by pattern", () => {
    expect(filterAlerts(ALERTS, { minScore: 0.6 }).map((a) => a.alert_id)).toEqual([
      "C000001",
      "C000002",
    ]);
    expect(filterAlerts(ALERTS, { patternType: "layering" }).map((a) => a.alert_id)).toEqual([
      "C000002",
    ]);
    expect(filterAlerts(ALERTS, { minScore: 0.99 })).toHaveLength(0);
  });

  it("renders rows in the order it was given, with the score on each", () => {
    render(
      <MemoryRouter>
        <AlertTable
          alerts={sortAlerts(ALERTS, "risk_score", "desc")}
          verdicts={{}}
          pending={{}}
          onVerdict={() => {}}
          sort={{ key: "risk_score", dir: "desc" }}
          onSort={() => {}}
        />
      </MemoryRouter>,
    );
    const rows = screen.getAllByRole("row").slice(1); // skip the head
    expect(within(rows[0]).getByText("0.910")).toBeInTheDocument();
    expect(within(rows[2]).getByText("0.220")).toBeInTheDocument();
  });

  it("asks for the other direction when a sorted column is clicked again", async () => {
    const onSort = vi.fn();
    render(
      <MemoryRouter>
        <AlertTable
          alerts={ALERTS}
          verdicts={{}}
          pending={{}}
          onVerdict={() => {}}
          sort={{ key: "risk_score", dir: "desc" }}
          onSort={onSort}
        />
      </MemoryRouter>,
    );
    await userEvent.click(screen.getByRole("button", { name: /risk/i }));
    expect(onSort).toHaveBeenCalledWith("risk_score");
  });
});

describe("a verdict reaches the API", () => {
  beforeEach(() => {
    vi.spyOn(globalThis, "fetch").mockResolvedValue(
      new Response(JSON.stringify({ alert_id: "C000001", status: "confirmed", recorded: 1 }), {
        status: 200,
        headers: { "content-type": "application/json" },
      }),
    );
  });

  it("posts the status to /alerts/{id}/feedback", async () => {
    await api.feedback("C000001", "confirmed");
    const [url, init] = vi.mocked(globalThis.fetch).mock.calls[0];
    expect(String(url)).toBe("/alerts/C000001/feedback");
    expect(init?.method).toBe("POST");
    expect(JSON.parse(String(init?.body))).toEqual({ status: "confirmed" });
  });

  it("encodes an id that needs it, rather than building a broken path", async () => {
    await api.feedback("bc1q/odd id", "false_positive");
    const [url] = vi.mocked(globalThis.fetch).mock.calls[0];
    expect(String(url)).toBe("/alerts/bc1q%2Fodd%20id/feedback");
  });

  it("reports the verdict in the row once it is recorded", async () => {
    const onVerdict = vi.fn();
    const { rerender } = render(
      <MemoryRouter>
        <AlertTable
          alerts={[ALERTS[0]]}
          verdicts={{}}
          pending={{}}
          onVerdict={onVerdict}
          sort={{ key: "risk_score", dir: "desc" }}
          onSort={() => {}}
        />
      </MemoryRouter>,
    );
    await userEvent.click(screen.getByRole("button", { name: /confirm/i }));
    expect(onVerdict).toHaveBeenCalledWith(ALERTS[0], "confirmed");

    rerender(
      <MemoryRouter>
        <AlertTable
          alerts={[ALERTS[0]]}
          verdicts={{ C000001: "confirmed" }}
          pending={{}}
          onVerdict={onVerdict}
          sort={{ key: "risk_score", dir: "desc" }}
          onSort={() => {}}
        />
      </MemoryRouter>,
    );
    expect(screen.getByText("confirmed")).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /^confirm$/i })).not.toBeInTheDocument();
  });
});

describe("the case page keeps attribution out of the reasons", () => {
  beforeEach(() => {
    vi.spyOn(api, "entity").mockResolvedValue(DETAIL);
    vi.spyOn(api, "entityGraph").mockResolvedValue({
      entity_id: "C000001",
      hops: 2,
      truncated: false,
      counts: { wallets: 2, transactions: 3, ips: 1 },
      layout: { name: "cose" },
      elements: { nodes: [], edges: [] },
    });
  });

  const openCase = async () => {
    render(
      <MemoryRouter initialEntries={["/entities/C000001"]}>
        <ToastHost>
          <Routes>
            <Route path="/entities/:id" element={<Entity />} />
          </Routes>
        </ToastHost>
      </MemoryRouter>,
    );
    await waitFor(() => expect(screen.getByText(/ransomware collector structure/i)).toBeVisible());
  };

  it("puts the leads in their own section, not inside the reason", async () => {
    await openCase();

    const leads = screen.getByRole("region", { name: /investigative leads/i });
    const reason = screen.getByRole("heading", { name: /^reason$/i }).closest("section")!;

    expect(within(leads).getByText("185.220.9.9")).toBeInTheDocument();
    expect(within(reason).queryByText("185.220.9.9")).not.toBeInTheDocument();
    expect(leads.contains(reason)).toBe(false);
    expect(reason.contains(leads)).toBe(false);
  });

  it("says associated with, never belongs to, and marks the anonymized entry point", async () => {
    await openCase();
    const leads = screen.getByRole("region", { name: /investigative leads/i });
    expect(within(leads).getByText(/associated with/i)).toBeInTheDocument();
    expect(within(leads).queryByText(/belongs to/i)).not.toBeInTheDocument();
    expect(within(leads).getByText(/anonymized entry point/i)).toBeInTheDocument();
    expect(within(leads).getByText(/tor exit/i)).toBeInTheDocument();
  });

  it("shows the evidence and the taint path with the reason", async () => {
    await openCase();
    expect(screen.getByRole("heading", { name: /^evidence$/i })).toBeInTheDocument();
    expect(screen.getByText(/taint path/i)).toBeInTheDocument();
  });
});

describe("reduced motion", () => {
  it("leaves the ambient field static", () => {
    setReducedMotion(true);
    const raf = vi.spyOn(globalThis, "requestAnimationFrame");
    render(<AmbientField />);
    expect(screen.getByTestId("ambient-field")).toHaveAttribute("data-animated", "false");
    expect(raf).not.toHaveBeenCalled();
  });

  it("animates it otherwise", () => {
    setReducedMotion(false);
    const raf = vi.spyOn(globalThis, "requestAnimationFrame").mockReturnValue(1);
    render(<AmbientField />);
    expect(screen.getByTestId("ambient-field")).toHaveAttribute("data-animated", "true");
    expect(raf).toHaveBeenCalled();
  });
});
