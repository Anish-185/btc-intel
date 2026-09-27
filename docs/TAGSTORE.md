# The tag store

`intel/` is an offline attribution store, modelled on GraphSense TagPacks. A
**tag** says what an address, or the cluster an address defines, is: an
exchange, a sanctioned service, a ransomware operation. It says who said so,
where, and when. Tags reach the analysis machine in **sealed bundles** built
on a connected machine. The analysis machine never fetches anything.

## A tag

| field | meaning |
| --- | --- |
| `subject` | an address |
| `label` | the service or list entry. **Never a private individual's name** |
| `category` | `exchange/VASP`, `sanctioned`, `ransomware`, `darknet market`, `mixer`, `scam`, `other` |
| `source` | who says so: `OFAC SDN`, an operator's list, or `simulated` |
| `reference` | URL or document reference for the claim |
| `collected` | ISO date the source was collected |
| `confidence` | the source's own confidence, 0–1 |
| `applies_to` | `address` (this address only) or `cluster` (this address's cluster is the service) |

The subject is always an address, even for a cluster tag. Our cluster ids
belong to one run of `graph/clustering` and mean nothing on the machine that
built the bundle. So a cluster is tagged the way GraphSense tags one: through
an address in it, with `applies_to: cluster` asserting that the address's
cluster is the service.

Tags describe services and categories. The OFAC importer keeps an
individual's SDN entry as `OFAC SDN individual entry <uid> (<programme>)`, so
the analyst can look the entry up and the tag never carries the name. An
operator's CSV is the operator's responsibility; the same rule applies.

## Bundles and the air gap

A bundle is a directory holding three files:
* `bundle.json`: name, description, sources, whether it is simulated, tag count;
* `tags.jsonl`: one tag per line;
* `manifest.json`: the seal written by `p2p.manifest`, the same code that
  seals a packet capture. There is no second crypto path.

**On the connected machine:**

```sh
# OFAC: download SDN.XML from https://sanctionslist.ofac.treas.gov (the
# "SDN.XML" export), then
python -m intel.bundle ofac SDN.XML --out bundles/ofac-2026-09-27

# an operator-curated list (columns: address,label,category,reference,
# collected,confidence[,applies_to][,source])
python -m intel.bundle csv team-list.csv --out bundles/team-2026-09 --source "Unit 4 list"
```

Each command writes the bundle and seals it. Copy the bundle directory to
removable media.

**On the analysis machine:**

```sh
python -m intel.bundle import /media/usb/ofac-2026-09-27
python -m intel.bundle list
```

Import re-hashes every file against the manifest. It **refuses** a bundle
that:
* has no manifest ("unsealed");
* has a file changed, missing or added since sealing, or a manifest edited
  after sealing ("altered");
* is not a valid tag bundle: a bad tag, a wrong count, or simulated and real
  tags mixed;
* is simulated while the case is real (`ingest.provenance: real`);
* reuses the name of a different, already imported bundle.

Every import and every refusal is written to the custody ledger
(`tags.bundle_imported`, `tags.bundle_refused`), with the reason. An accepted
bundle is copied into `data/tags/<name>/`. Its files are sealed into the
ledger entry, so `custody.verify()` watches them from then on. The store
re-verifies every bundle each time it is loaded. A bundle altered inside the
store is left out and reported.

**What the seal proves, and what it does not.** `p2p.manifest` has no keys.
The seal shows a bundle is unchanged since it was sealed. It does not show
who sealed it. Someone who can write to the media can rebuild and reseal a
bundle, and the import will accept it. Carry bundles by a channel you trust,
and compare the `manifest_hash` that `import` prints with the one printed
when the bundle was built. Signing `manifest_hash` with the builder's key is
the single integration point for real authenticity (see p2p/manifest.py).

## Importers

* **OFAC SDN** (`intel.importers.ofac`). Reads SDN.XML's `sdnEntry` records
  and turns every `idList/id` whose `idType` is `Digital Currency Address - XBT`
  into a `sanctioned` tag with `applies_to: address`, the entry's uid in the
  reference, and the list's `Publish_Date` as the collection date. Element
  names are matched without their namespace.
  **This parser was written against the documented format and a hand-built
  fixture (`tests/fixtures/sdn_fixture.xml`). This environment has no network
  and has never seen a real copy. Check the element names (`sdnEntry`, `uid`,
  `sdnType`, `lastName`, `programList/program`, `idList/id/idType`,
  `idNumber`, `publshInformation/Publish_Date`) against a real downloaded
  SDN.XML before operational use.**
* **CSV** (`intel.importers.from_csv`). For operator-curated lists. Any
  invalid row fails the whole file and names its line.
* **Demo** (`intel.importers.demo`). Built from a generated dataset's
  `ground_truth.json`: every illicit operation's origin cluster and every
  exchange's hot wallet, each `applies_to: cluster`. Every tag is
  `source: "simulated"`, and `simulated` is derived from the source rather
  than stored. It cannot be presented as real intelligence:
  * a tag whose reference points at ground truth must be simulated
    (`Tag.__post_init__`);
  * editing the source after sealing breaks the seal;
  * a bundle cannot mix simulated and real tags;
  * a simulated bundle is refused when the case is real;
  * the console marks every simulated tag "simulated, not intelligence".

  The same pattern as the P3 ground-truth label files: the source is
  checked, not trusted.

## Propagation

* A **cluster tag** (`applies_to: cluster`) reaches every member address of
  the cluster its subject is in. Its effective confidence is the tag's
  confidence times the cluster's merge confidence (`Clustering.confidence`,
  lowered where merges are uncertain).
* An **address tag** stays on its address. On a multi-address entity it is
  listed as "on member address X, not extended to the cluster", and it does
  not score the entity. A lone wallet is its own address, so there it does
  score.
* **Nothing else carries a tag.** Fingerprints do not, transaction flows do
  not (that is taint's job, from the watchlist), and actor joins do not. An
  actor is a view, not a merge: its page lists each member cluster's tags
  under that member. (The actor's own risk score is still the P9 weighted
  maximum over its members' signals, `tag_score` included, as for every other
  signal.)
* **Conflicts are shown, not resolved.** When an entity's tags disagree on
  category, or its cluster tags disagree on label, every tag is shown and the
  entity is flagged `conflict`. An exchange tag and a ransomware tag on one
  cluster usually means the cluster over-merged. That is for the analyst to
  see.

## Scoring

Tags feed the existing fusion stacker as one more signal, `tag_score`: the
strongest applied tag's `tags.risk[category] × effective confidence`.
Exchange/VASP tags weigh 0. They say where money went, not that an entity is
suspect; P12 uses them for exit points. A fitted stacker learns the signal's
weight. The unfitted fallback uses `tags.fallback_weight`. With an empty store,
`tag_score` is 0 for every entity: a fitted stacker gives it no weight, but
the unfitted fallback's normaliser now includes `tags.fallback_weight`, so
unfitted scores are 1.10/1.35, about a fifth, lower than before tags existed, at an unchanged threshold. The served demo and the evaluation use fitted stackers.

The evaluation never reads the operator's store (`data/tags`).
`eval.report` switches it off, because a demo bundle there is derived from
ground truth and would leak into any dataset that shares its addresses. The
test suite does the same (`tests/conftest.py`). Section 15 of
`eval/results.md` builds its own store to measure red-team detection with
tags, and labels the result an **upper bound**.

## Surfaces

* `GET /tags/{entity|transaction|actor|peer}/{subject}`: the tags on one
  page's subject, with the store's bundles and whether any is simulated.
* The console's entity, transaction, actor and peer pages show a Tags
  section: label, category, source, collection date, basis and effective
  confidence, with conflicts flagged.
