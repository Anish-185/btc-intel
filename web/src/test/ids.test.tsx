/** Identifiers are shortened by one rule, and nothing renders longer than it.
 *
 *  This exists because the graph once drew full 64-character txids on top of
 *  each other and the queue wrapped every row to two lines. Both were fixed by
 *  hand in two places; this is the test that stops the third place from
 *  getting it wrong.
 */
import { render, screen } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { describe, expect, it } from "vitest";

import { ELLIPSIS, ID_HEAD, ID_TAIL, formatId, maxIdLength } from "../lib/formatId";
import { AlertTable } from "../components/AlertTable";
import { toElements } from "../components/InvestigationGraph/InvestigationGraph";
import type { GraphPayload } from "../components/InvestigationGraph/model";
import { alert } from "./fixtures";

const TXID = "a".repeat(64);
const ADDRESS = "bc1q1975bbb1616d4c004ac7159d1b64104d3705125f06cb48ef582c824304";

describe("the formatter", () => {
  it("cuts a long identifier in the middle", () => {
    expect(formatId(TXID)).toBe(`${"a".repeat(ID_HEAD)}${ELLIPSIS}${"a".repeat(ID_TAIL)}`);
    expect(formatId(TXID)).toHaveLength(maxIdLength());
  });

  it("never returns more than the maximum", () => {
    for (const value of [TXID, ADDRESS, "x".repeat(1000), ""]) {
      expect(formatId(value).length).toBeLessThanOrEqual(maxIdLength());
    }
  });

  it("leaves short values alone — half an IP address is not an identifier", () => {
    for (const value of ["", "abc", "1.2.3.4", "C000001"]) {
      expect(formatId(value)).toBe(value);
    }
  });

  it("takes a different head and tail when a heading has the room", () => {
    const out = formatId(TXID, { head: 12, tail: 6 });
    expect(out).toHaveLength(maxIdLength({ head: 12, tail: 6 }));
    expect(out.startsWith("a".repeat(12))).toBe(true);
  });
});

describe("nothing in the queue renders a long identifier", () => {
  const LONG = [
    alert({ alert_id: ADDRESS, entity_id: ADDRESS }),
    alert({ alert_id: TXID, entity_id: TXID, risk_score: 0.5 }),
  ];

  const table = () =>
    render(
      <MemoryRouter>
        <AlertTable
          alerts={LONG}
          verdicts={{}}
          pending={{}}
          onVerdict={() => {}}
          sort={{ key: "risk_score", dir: "desc" }}
          onSort={() => {}}
        />
      </MemoryRouter>,
    );

  it("keeps every entity label within the maximum", () => {
    table();
    const links = screen.getAllByRole("link");
    expect(links.length).toBeGreaterThan(0);
    for (const link of links) {
      expect(link.textContent!.length).toBeLessThanOrEqual(maxIdLength());
    }
  });

  it("keeps the full value on the element, so it can be read and copied", () => {
    table();
    expect(screen.getByTitle(ADDRESS)).toBeInTheDocument();
    expect(screen.getByTitle(TXID)).toBeInTheDocument();
  });
});

describe("nothing on the graph canvas renders a long identifier", () => {
  const payload: GraphPayload = {
    nodes: [
      { data: { id: ADDRESS, type: "wallet", label: ADDRESS, risk: 0.9 } },
      { data: { id: TXID, type: "transaction", label: TXID } },
      { data: { id: "185.220.9.9", type: "ip", label: "185.220.9.9 DE" } },
      { data: { id: "more:x:20", type: "aggregate", label: "+40 more" } },
    ],
    edges: [],
  };

  it("shortens wallet and transaction labels", () => {
    const elements = toElements(payload);
    const label = (id: string) =>
      String((elements.find((e) => e.data?.id === id)?.data as { label: string }).label);

    expect(label(ADDRESS).length).toBeLessThanOrEqual(maxIdLength());
    expect(label(TXID).length).toBeLessThanOrEqual(maxIdLength());
  });

  it("leaves IP addresses and batch labels whole — they are already short", () => {
    const elements = toElements(payload);
    const label = (id: string) =>
      String((elements.find((e) => e.data?.id === id)?.data as { label: string }).label);

    expect(label("185.220.9.9")).toBe("185.220.9.9 DE");
    expect(label("more:x:20")).toBe("+40 more");
  });

  it("keeps the full value as the node id, which is what copy and the API use", () => {
    const elements = toElements(payload);
    expect(elements.some((e) => e.data?.id === ADDRESS)).toBe(true);
    expect(elements.some((e) => e.data?.id === TXID)).toBe(true);
  });
});
