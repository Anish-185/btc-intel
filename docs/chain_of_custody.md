# Chain of custody

A risk score is a lead. A lead an analyst acts on becomes part of a case, and a
case that reaches a court — or an inter-agency handover, or an internal review
a year later — has to answer three questions about every artefact in it. These
are ISO/IEC 27037's principles (auditability, repeatability, reproducibility),
in plain words:

| The question | What answers it here |
| --- | --- |
| Where did this come from? | The source file is hashed the moment it is read, before anything transforms it. |
| Has it changed since? | The hash is recorded; `python -m custody verify` re-computes it. |
| Who did what to it, and when? | Every consequential action is appended to the ledger with a timestamp. |

## What gets recorded

| Action | When | What is sealed |
| --- | --- | --- |
| `ingest` | a dump is parsed | the source file and the parquet written from it |
| `analysis` | the pipeline runs | the input, the alert parquet, the alert JSON, the threshold, whether the stacker was fitted |
| `monitor.arrival` | a file arrives in the live monitor | the arriving file (at its archived path), the dataset, the alert list |
| `verdict` | an analyst confirms or dismisses an alert | the feedback file, the alert, the verdict |
| `export.case_report` | a PDF is exported | the data it was made from, and the PDF's own SHA-256 |
| `redteam.inject` | an attack is injected | the dataset after the injection |
| `redteam.reset` | the dataset is restored | every restored file |

## Why the entries are chained

Each entry carries the hash of the entry before it, and its own hash is
computed over its content *and* that predecessor hash:

```
entry 1   prev = 000…000   hash = H(content₁, 000…000)
entry 2   prev = hash₁     hash = H(content₂, hash₁)
entry 3   prev = hash₂     hash = H(content₃, hash₂)
```

This makes the record **tamper-evident**, not tamper-proof. Anyone with write
access can still edit the file — what they cannot do is edit one entry and
leave the rest verifying, because every later hash was computed over the
original. `verify()` reports the first entry where the chain breaks.

`tests/test_custody.py` breaks it four ways on purpose — an edited entry, an
edited entry that has been carefully re-hashed by someone who knows the scheme,
a deleted entry, and an edited source file — and asserts that each is caught.
A ledger nobody can break is worthless as evidence, because "intact" would then
mean nothing.

## Files change; that is not tampering

A dataset legitimately changes over a case: it is re-ingested, a red-team run
appends to it, a reset puts it back. Each of those wrote its own seal, so a
file is checked against **the most recent seal recorded for it**, and an older
seal is treated as history rather than as a claim about the present. A file
reported as changed is therefore a file that moved *after the last action this
ledger knows about* — a fact to explain, not a verdict.

## The exported report

A PDF cannot contain its own hash. So the two halves point at each other:

* the **report** prints the ledger head at the time it was made and the SHA-256
  of the data it was made from (the "evidence seal" block at the foot of the
  page);
* the **ledger** holds the SHA-256 of the report.

Either half identifies the other. A PDF with no matching `export.case_report`
entry was not produced by this system, and a PDF whose bytes have been edited
no longer matches the hash the ledger recorded. The response also carries
`x-custody-entry` and `x-custody-report-sha256` headers, so a tool that fetches
a report can check it without reading the PDF.

## What this does not prove

**It does not prove who did anything.** This build has no authentication —
`custody.actor` says `btc-intel (unauthenticated demo build)` rather than
inventing a name that a court would later have to test. A deployment would:

* sign each entry with the analyst's key, so the actor field is attested rather
  than asserted;
* keep the ledger on write-once storage or mirror it to a second host, so
  "tamper-evident" becomes "tamper-resistant";
* record reads as well as writes, if who *looked* at a case is in scope.

The gap is named here rather than papered over, because a chain of custody that
overstates what it proves is worse than none: it invites a reliance it cannot
support.

## Using it

```sh
python -m custody log       # what happened, oldest first
python -m custody verify    # is the chain intact, are the files unchanged
```

```
GET /custody          # the ledger as JSON
GET /custody/verify   # the verification, run now
```

The console draws both at `/custody`.
