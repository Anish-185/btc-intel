/** The pipeline, stage by stage: what the home page tells as a story and
 *  what each console page's banner says it is part of.
 *
 *  Every figure here is on docs/CLAIMS.md, with its condition. Change a
 *  number there first, then here. */

export interface Proof {
  value: string;
  what: string;
}

export interface Capability {
  id: string;
  /** Short name, used in the stage index and the page banner. */
  name: string;
  title: string;
  body: string;
  /** Plain-English evidence the system itself prints, where there is one. */
  sample?: string;
  proofs: Proof[];
  /** "simulated", "measured", "fixture" — see CLAIMS.md. */
  condition: string;
  art: string;
  mode: "dot" | "square" | "glyph";
  to: string;
  cta: string;
}

export const CAPABILITIES: Capability[] = [
  {
    id: "ingest",
    name: "Ingest",
    title: "Reads the dumps investigators actually receive",
    body:
      "CSV, JSON or XML, normalised into one schema. Bad records go to quarantine with the reason and the original row, instead of vanishing or killing the run. IPs are enriched from local GeoIP databases. Nothing at any stage opens a network connection.",
    sample: "quarantined — mismatched output array lengths",
    proofs: [
      { value: "0", what: "network calls, at any stage — offline: true" },
      { value: "3", what: "input formats, one canonical schema" },
    ],
    condition: "measured",
    art: "ingest",
    mode: "glyph",
    to: "/monitor",
    cta: "Watch new transactions arrive",
  },
  {
    id: "cluster",
    name: "Cluster",
    title: "Turns thousands of wallets into a few hundred owners",
    body:
      "Common-input ownership and change detection by majority vote, reimplemented from BlockSci's published heuristics. CoinJoins are detected first and skipped, so strangers who mixed together are never merged. A cluster that grows past 500 wallets is flagged for review, not trusted.",
    proofs: [
      { value: "500", what: "wallets before a cluster is flagged as a suspicious merge" },
      { value: "0.213", what: "ARI against the true partition — it over-splits rather than over-merges" },
    ],
    condition: "simulated",
    art: "cluster",
    mode: "dot",
    to: "/investigate",
    cta: "Open the investigation graph",
  },
  {
    id: "detect",
    name: "Detect",
    title: "Four detectors and a graph network, fused into one score",
    body:
      "Rules for ransomware collection, layering, peel chains and CoinJoin mixing; a graph neural network where entities are nodes and transactions are edges; a stacker that weighs them. Every alert says why, in plain English, with the numbers that made it fire.",
    sample:
      "received from 32 distinct wallets, 32 of them first-time senders (100%), then peeled funds through 8 hops",
    proofs: [
      { value: "5 of 5", what: "planted laundering operations detected" },
      { value: "0.934", what: "alert precision" },
      { value: "0", what: "alerts on 949 entities with nothing planted" },
    ],
    condition: "simulated",
    art: "detect",
    mode: "dot",
    to: "/alerts",
    cta: "Open the alert queue",
  },
  {
    id: "taint",
    name: "Taint",
    title: "Finds the accomplices nobody put on a list",
    body:
      "Risk flows outward from known-bad wallets along the money, decaying with every hop. The entities it surfaces are the ones neither the rules nor the watchlist knew about.",
    proofs: [
      { value: "0.906", what: "precision on accomplices found by taint alone" },
      { value: "0.296", what: "recall of the remainder — it finds some, not all" },
    ],
    condition: "simulated",
    art: "taint",
    mode: "dot",
    to: "/investigate",
    cta: "Follow a taint path",
  },
  {
    id: "origin",
    name: "Origin",
    title: "Estimates which IP address spoke first",
    body:
      "Each transaction gossips across a 500-node peer network. From the relay timings, a supervised model names the most likely broadcaster — or abstains when every peer that announced it is a public relay. It answers rarely and is right when it does.",
    proofs: [
      { value: "91%", what: "right when it answers, on network topologies it never saw" },
      { value: "19%", what: "of transactions it is willing to answer" },
      { value: "0.013", what: "calibration error of the probability it reports" },
    ],
    condition: "simulated",
    art: "origin",
    mode: "square",
    to: "/peers",
    cta: "Look up a peer",
  },
  {
    id: "validity",
    name: "Validity",
    title: "Knows when the trail goes into fog",
    body:
      "Tor exits, Dandelion stems and CoinJoins are detected and change what an answer may claim. Every answer carries a verdict: ANNOTATE, QUALIFIED or ABSTAIN. A CoinJoin answer names the broadcasting peer and states that input ownership is not attributable.",
    sample: "COINJOIN → QUALIFIED: broadcasting peer only, input ownership non-attributable",
    proofs: [
      { value: "1.000", what: "CoinJoin detector recall" },
      { value: "1.000", what: "onion-routing clause precision" },
      { value: "4%", what: "runtime cost of the whole layer" },
    ],
    condition: "simulated",
    art: "validity",
    mode: "square",
    to: "/peers",
    cta: "See a qualified verdict",
  },
  {
    id: "exits",
    name: "Exit points",
    title: "Traces the money to where it cashes out",
    body:
      "Haircut and poison taint follow value forward to exchanges and other sinks, then assemble an investigator packet. The trace stops at a CoinJoin instead of guessing through it.",
    proofs: [
      { value: "100%", what: "of 4,124 CoinJoin traces stop at the mix" },
      { value: "37–49%", what: "reach the true cash-out on deep layering, 7–11 hops away" },
    ],
    condition: "simulated",
    art: "exits",
    mode: "square",
    to: "/alerts",
    cta: "Open a case and trace it",
  },
  {
    id: "redteam",
    name: "Red team",
    title: "Attack it while it runs",
    body:
      "Plant a fresh laundering pattern into the live dataset and watch the stack re-score it. Nothing is retrained, so what catches it is the detector that exists.",
    proofs: [
      { value: "20 of 30", what: "seeded criminal injections detected" },
      { value: "11.5", what: "median transactions of the pattern before its first alert" },
    ],
    condition: "simulated",
    art: "redteam",
    mode: "dot",
    to: "/redteam",
    cta: "Inject an attack",
  },
  {
    id: "custody",
    name: "Custody",
    title: "Evidence that survives a courtroom",
    body:
      "Every action is written to a hash-chained ledger following ISO/IEC 27037. Exports ship with a SHA-256 manifest, so any change after sealing shows.",
    sample: "{ seq, at, action, actor, detail, prev } → sha256 → next entry's prev",
    proofs: [
      { value: "SHA-256", what: "chain over every recorded action" },
      { value: "27037", what: "ISO/IEC guideline the ledger follows" },
    ],
    condition: "measured",
    art: "custody",
    mode: "dot",
    to: "/custody",
    cta: "Verify the chain",
  },
];

/** Which stage a console route belongs to, for its banner. */
export function stageFor(pathname: string): Capability | null {
  const find = (id: string) => CAPABILITIES.find((c) => c.id === id) ?? null;
  if (pathname.startsWith("/monitor")) return find("ingest");
  if (pathname.startsWith("/alerts")) return find("detect");
  if (pathname.startsWith("/investigate") || pathname.startsWith("/actors")) return find("cluster");
  if (pathname.startsWith("/entities")) return find("exits");
  if (pathname.startsWith("/tx") || pathname.startsWith("/peers") || pathname.startsWith("/asns"))
    return find("origin");
  if (pathname.startsWith("/redteam")) return find("redteam");
  if (pathname.startsWith("/custody")) return find("custody");
  return null;
}
