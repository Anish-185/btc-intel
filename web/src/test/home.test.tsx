/** The front door tells the pipeline in order, every stage links into the
 *  console, and every console page knows which stage it belongs to. */
import { render, screen, within } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { afterEach, describe, expect, it, vi } from "vitest";

import { api } from "../api/client";
import { CAPABILITIES, stageFor } from "../content/capabilities";
import { Home } from "../pages/Home";

afterEach(() => vi.restoreAllMocks());

describe("the home page", () => {
  it("shows every stage, in order, each linking to its console page", async () => {
    vi.spyOn(api, "stats").mockRejectedValue(new Error("offline"));
    render(
      <MemoryRouter>
        <Home />
      </MemoryRouter>,
    );
    const titles = screen.getAllByRole("heading", { level: 3 }).map((h) => h.textContent);
    expect(titles.slice(0, CAPABILITIES.length)).toEqual(CAPABILITIES.map((c) => c.title));
    for (const c of CAPABILITIES) {
      const chapter = document.getElementById(c.id)!;
      expect(within(chapter).getByRole("link", { name: c.cta })).toHaveAttribute("href", c.to);
    }
  });

  it("maps console routes to their stage, and leaves the showcase unbannered", () => {
    expect(stageFor("/alerts")?.id).toBe("detect");
    expect(stageFor("/entities/abc")?.id).toBe("exits");
    expect(stageFor("/peers/1.2.3.4")?.id).toBe("origin");
    expect(stageFor("/redteam")?.id).toBe("redteam");
    expect(stageFor("/")).toBeNull();
    expect(stageFor("/case")).toBeNull();
  });
});
