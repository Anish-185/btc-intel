/** The peer profile page: an investigation that starts from an IP, keeps
 *  QUALIFIED and ANNOTATE claims visibly qualified, never shows an onion
 *  identity with network fields, and links both ways to the TXID and entity
 *  pages. */
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter, Route, Routes, useLocation } from "react-router-dom";
import { afterEach, describe, expect, it, vi } from "vitest";

import { api } from "../api/client";
import type { OriginClaim, PeerProfile, TxOrigination, Validity } from "../api/types";
import { Asn, Peer, Peers } from "../pages/Peer";
import { Transaction } from "../pages/Transaction";

vi.mock("../components/FieldGraph", () => ({ FieldGraph: () => <div data-testid="field" /> }));

afterEach(() => vi.restoreAllMocks());

const TX = "a".repeat(64);
const MIX = "c".repeat(64);
const ONION = "pg6mmjiyjmcrsslvykfwnntlaru7p5svn6y2ymmju6nubxndf4pscryd.onion";
const PASS: Validity = { tier: "PASS", reason: null, reasons: [], confidence: null, evidence: ["ok"] };

const claim = (txid: string, validity: Validity, answer: OriginClaim["answer"]): OriginClaim => ({
  txid, capture_id: "cap-a", observer: "198.51.100.2", probability: 0.9,
  calibration_basis: "isotonic", tier: validity.tier, validity, answer, statement: "",
});

function profile(over: Partial<PeerProfile> = {}): PeerProfile {
  return {
    subject: "peer 203.0.113.9", peer: "203.0.113.9", kind: "ip",
    header: { simulated_only: true, provenance: ["fixture"], statement: "Built only from fixture data" },
    originated: {
      claimed: 3, by_tier: { PASS: 1, QUALIFIED: 1, ANNOTATE: 1 }, basis: "origination model",
      claims: [
        claim(TX, PASS, { kind: "ip_attribution", ip: "203.0.113.9" }),
        claim(MIX, { tier: "QUALIFIED", reason: "COINJOIN", reasons: ["COINJOIN"], confidence: 1, evidence: [] },
              { kind: "broadcasting_peer", ip: "203.0.113.9", input_ownership: "not attributable" }),
        claim("b".repeat(64), { tier: "ANNOTATE", reason: "DANDELION_STEM", reasons: ["DANDELION_STEM"],
                                confidence: 0.5, evidence: [] },
              { kind: "ip_attribution", ip: "203.0.113.9" }),
      ],
    },
    propagation_origin: { count: 0, statement: "" },
    withheld: { count: 0, by_reason: {}, items: [] },
    relayed: { count: 4, by_source: { "relay matrix": 4 }, sample: [] },
    timing: { sufficient: false, announcements: 3, threshold: 20,
              statement: "peer 203.0.113.9 was seen announcing 3 transactions; a timing signature needs at least 20" },
    clients: { user_agents: [], services: [], statement: "no version handshake" },
    linked_clusters: [{
      cluster: "cluster C1", cluster_id: "C1", basis: "both", confidence: 0.7, confidence_rule: "stronger",
      statement: "peer 203.0.113.9 is linked to cluster C1 by both", evidence_chain: "raw rows -> transaction -> input addresses -> cluster",
      evidence: [{ basis: "origination", txid: TX, probability: 0.9, rows: [{ source: "relay matrix", txid: TX, capture_id: "cap-a", announce_ts: "t" }], inputs: ["bc1qx"] }],
      evidence_total: 1,
    }],
    excluded_links: [{ txid: MIX, reason: "COINJOIN", statement: "CoinJoin: no cluster link is drawn" }],
    vantage: [{ source: "relay matrix", capture_id: "cap-a", capture_source: "synthetic-fixture:cap-a",
                provenance: "fixture", observer: ["198.51.100.2"], direction: ["inbound"], vantage: "single observer",
                announcements: 7, first_seen: "a", last_seen: "b" }],
    network: { ip: "203.0.113.9", asn: 64500, asn_org: "EXAMPLE", country: "ZZ", ip_class: "residential_or_unknown", basis: "ingest" },
    caveat: "A profile of network behaviour.",
    ...over,
  };
}

function Where() {
  return <p data-testid="where">{useLocation().pathname}</p>;
}

function at(path: string) {
  render(
    <MemoryRouter initialEntries={[path]}>
      <Routes>
        <Route path="/peers" element={<Peers />} />
        <Route path="/peers/:peer" element={<Peer />} />
        <Route path="/asns/:asn" element={<><Asn /><Where /></>} />
        <Route path="/tx/:txid" element={<Transaction />} />
        <Route path="*" element={<Where />} />
      </Routes>
    </MemoryRouter>,
  );
}

describe("peer profile", () => {
  it("keeps qualified and annotated claims qualified, and says it is fixture data", async () => {
    vi.spyOn(api, "peerProfile").mockResolvedValue(profile());
    at("/peers/203.0.113.9");
    await screen.findByText(/simulated or fixture data only/i);
    expect(screen.getByText(/broadcasting peer · input ownership not attributable/i)).toBeInTheDocument();
    expect(screen.getAllByText(/qualified: coinjoin/i).length).toBeGreaterThan(0);
    expect(screen.getAllByText(/annotate: dandelion stem/i).length).toBeGreaterThan(0);
    expect(screen.getAllByText("estimated origin")).toHaveLength(2);
    expect(screen.getByText(/timing signature needs at least 20/i)).toBeInTheDocument();
    expect(document.body.textContent).not.toMatch(/owner of|belongs to|owned by/i);
  });

  it("links to each transaction page and each cluster's entity page", async () => {
    vi.spyOn(api, "peerProfile").mockResolvedValue(profile());
    at("/peers/203.0.113.9");
    const cluster = await screen.findByRole("link", { name: "cluster C1" });
    expect(cluster).toHaveAttribute("href", "/entities/C1");
    const txLinks = screen.getAllByRole("link").map((a) => a.getAttribute("href"));
    expect(txLinks).toContain(`/tx/${TX}`);
    expect(txLinks).toContain(`/tx/${MIX}`);
    expect(txLinks).toContain("/asns/64500");
  });

  it("shows an onion identity without any network field", async () => {
    const { network: _drop, ...rest } = profile();
    vi.spyOn(api, "peerProfile").mockResolvedValue({
      ...rest, kind: "onion_identity", peer: ONION, subject: `onion identity ${ONION}`,
      originated: { ...rest.originated, claims: [claim(TX,
        { tier: "QUALIFIED", reason: "TOR_ONION", reasons: ["TOR_ONION"], confidence: 1, evidence: [] },
        { kind: "onion_identity", onion: ONION, actionable: "not for IP-level follow-up" })] },
    });
    at(`/peers/${ONION}`);
    await screen.findByText(/onion identity · not for IP-level follow-up/i);
    expect(screen.queryByRole("heading", { name: "Network" })).not.toBeInTheDocument();
    expect(screen.queryByText(/AS64500/)).not.toBeInTheDocument();
  });

  it("starts an investigation from an IP or an AS number", async () => {
    vi.spyOn(api, "asnProfile").mockRejectedValue(new Error("stop"));
    at("/peers");
    await userEvent.type(screen.getByRole("searchbox"), "as64500{enter}");
    await waitFor(() => expect(screen.getByTestId("where")).toHaveTextContent("/asns/64500"));
  });
});

describe("the transaction page links back", () => {
  it("names the per-capture origin as a peer with a link to its profile", async () => {
    vi.spyOn(api, "propagation").mockRejectedValue(new Error("unknown transaction"));
    const origination: TxOrigination = {
      txid: TX, note: null,
      captures: [{ capture_id: "cap-a", observer: "198.51.100.2", capture_source: "x", provenance: "fixture",
                   named_peer: "203.0.113.9", probability: 0.9, calibration_basis: "isotonic",
                   validity: PASS, answered: true, abstention_reason: null,
                   answer: { kind: "ip_attribution", ip: "203.0.113.9" }, n_candidates: 3 }],
    };
    vi.spyOn(api, "origination").mockResolvedValue(origination);
    at(`/tx/${TX}`);
    const link = await screen.findByRole("link", { name: "203.0.113.9" });
    expect(link).toHaveAttribute("href", "/peers/203.0.113.9");
  });
});
