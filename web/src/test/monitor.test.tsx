/** The two states these pages exist to show honestly: a file that arrived and
 *  raised nothing, and a custody record that no longer verifies. Both are easy
 *  to draw as if they were fine, and both matter more than the happy path. */
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { afterEach, describe, expect, it, vi } from "vitest";

import { Monitor } from "../pages/Monitor";
import { Custody } from "../pages/Custody";
import { ToastHost } from "../components/Toasts";
import { monitorApi, custodyApi, type FeedEvent, type MonitorStatus } from "../api/monitor";

const status = (over: Partial<MonitorStatus> = {}): MonitorStatus => ({
  running: true, started_at: "2026-09-23T10:00:00", inbox: "data/inbox",
  files: 2, rows: 300, transactions: 60, duplicates: 4, alerts: 1, errors: 0,
  last_event: "2026-09-23T10:01:00", pending: [], poll_seconds: 2, ...over,
});

const draw = (node: React.ReactElement) =>
  render(<ToastHost><MemoryRouter>{node}</MemoryRouter></ToastHost>);

afterEach(() => vi.restoreAllMocks());

describe("the live monitor", () => {
  it("says when an arrival raised nothing, rather than showing an empty card", async () => {
    const quiet: FeedEvent = {
      type: "processed", at: "2026-09-23T10:01:00", file: "capture-01.csv",
      rows: 120, new_rows: 120, transactions: 30, duplicates: 0, entities: [], alerts: [],
      seconds: 1.2,
    };
    vi.spyOn(monitorApi, "feed").mockResolvedValue({ events: [quiet], status: status() });
    vi.spyOn(monitorApi, "status").mockResolvedValue(status());
    vi.spyOn(monitorApi, "watch").mockImplementation(() => () => undefined);

    draw(<Monitor />);
    expect(await screen.findByText(/nothing in this file cleared the alert threshold/i))
      .toBeTruthy();
    expect(screen.getByText("capture-01.csv")).toBeTruthy();
  });

  it("shows a rejected file as rejected, not as a quiet one", async () => {
    const rejected: FeedEvent = {
      type: "processed", at: "2026-09-23T10:02:00", file: "capture-bad.csv",
      rows: 0, new_rows: 0, transactions: 0, duplicates: 0, quarantined: 40,
      reason: "every row was rejected — wrong schema?", entities: [], alerts: [], seconds: 0.2,
    };
    vi.spyOn(monitorApi, "feed").mockResolvedValue({ events: [rejected], status: status() });
    vi.spyOn(monitorApi, "status").mockResolvedValue(status());
    vi.spyOn(monitorApi, "watch").mockImplementation(() => () => undefined);

    draw(<Monitor />);
    expect(await screen.findByText(/40 row\(s\) quarantined/i)).toBeTruthy();
    expect(screen.getByText(/wrong schema/i)).toBeTruthy();
  });

  it("offers to start when it is not watching, and to stop when it is", async () => {
    vi.spyOn(monitorApi, "feed").mockResolvedValue({
      events: [], status: status({ running: false }) });
    vi.spyOn(monitorApi, "status").mockResolvedValue(status({ running: false }));
    vi.spyOn(monitorApi, "watch").mockImplementation(() => () => undefined);
    const start = vi.spyOn(monitorApi, "start").mockResolvedValue(status({ running: true }));

    draw(<Monitor />);
    const button = await screen.findByRole("button", { name: /start watching/i });
    await userEvent.click(button);
    expect(start).toHaveBeenCalled();
    await waitFor(() => expect(screen.getByRole("button", { name: /^stop$/i })).toBeTruthy());
  });
});

describe("the custody page", () => {
  const entries = [
    { seq: 1, at: "2026-09-23T09:00:00+00:00", action: "ingest", actor: "x",
      hash: "a".repeat(64), prev: "0".repeat(64), detail: { rows: 4382, transactions: 1200 } },
    { seq: 2, at: "2026-09-23T09:05:00+00:00", action: "verdict", actor: "x",
      hash: "b".repeat(64), prev: "a".repeat(64), detail: { status: "confirmed" } },
  ];

  it("reports a broken chain and where it broke", async () => {
    vi.spyOn(custodyApi, "log").mockResolvedValue({
      total: 2, actor: "btc-intel (unauthenticated demo build)", head: "b".repeat(64), entries });
    vi.spyOn(custodyApi, "verify").mockResolvedValue({
      entries: 2, chain_intact: false, broken_at: 2, head: "b".repeat(64),
      files_changed: ["data/raw/transactions.csv"], files_missing: [], note: "…" });

    draw(<Custody />);
    expect(await screen.findByText(/the record has been altered/i)).toBeTruthy();
    expect(screen.getByText(/the chain breaks at entry 2/i)).toBeTruthy();
    expect(screen.getByText(/1 file\(s\) no longer match their hash/i)).toBeTruthy();
  });

  it("says plainly that it cannot prove who did the work", async () => {
    vi.spyOn(custodyApi, "log").mockResolvedValue({
      total: 2, actor: "btc-intel (unauthenticated demo build)", head: "b".repeat(64), entries });
    vi.spyOn(custodyApi, "verify").mockResolvedValue({
      entries: 2, chain_intact: true, broken_at: null, head: "b".repeat(64),
      files_changed: [], files_missing: [], note: "…" });

    draw(<Custody />);
    expect(await screen.findByText(/the record is intact/i)).toBeTruthy();
    expect(screen.getByText(/no authentication/i)).toBeTruthy();
    expect(screen.getByText("data acquired")).toBeTruthy();
  });
});
