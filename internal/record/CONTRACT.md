# The Anvil Record Field Contract

**Status: frozen interface.** Everything Anvil produces or consumes crosses this boundary. Once the contract freeze's
exit gate passes, no area may add, rename, or re-type a field here without amending
`plan/design/record-and-store.md` and the shared-vocabulary review.

| | |
|---|---|
| Wire format | SARIF 2.1.0 Plus Errata 01, pinned exactly. Not the 2.2 draft. |
| Extension | `anvil/*` property bags, versioned once at `sarifLog.properties["anvil/schemaVersion"]` = `1.0.0` |
| Go source of truth | `internal/record/contract.go` |
| JSON Schema | `schemas/anvil-record-v1.schema.json` |
| Ground truth this file matches | `plan/design/record-and-store.md` § "Record Field Contract"; the spine's corrected-requirements, record and safety sections; the shared-vocabulary review |

---

## 0. Read this first if you own another area

The shared-vocabulary review ran two owed review gates on 2026-08-07 and confirmed ten defects.
**Nine of the ten were the same structural error:** eight agents who could not see each other each
declared the shared vocabulary from their own side, and no step had been assigned to reconcile them.
Every one was a produce/consume break — one area wrote literals another area's `NOT NULL` column could
not accept. `dast_status` and `target_provenance` were each found independently by two different critics.

The ruling: **the record area owns every shared enum, and no other area may declare one.** This file is where
they live.

If you produce one of these values, **emit these literals directly**. If your area has its own
in-process vocabulary, you may map onto these literals only at a named, tested boundary step; the
permitted mappings are listed in §3 and are also machine-readable as `record.AreaMappingOwners`.
Lowercase `snake_case` is the record's convention throughout — any area emitting `SCREAMING_CASE` maps at
its own boundary.

Two habits that will save you a rerouted packet:

* Enumerate with the constants, never with string literals: `record.DastStatusCompletedClean`, not
  `"completed_clean"`.
* Validate before you write: every enum has a `Valid()` method and a `ValidateX(string) error` that names
  every legal value in its error message, and `(*SARIFLog).Validate()` checks a whole record.

---

## 1. The six frozen enums

Frozen verbatim by the shared-vocabulary review. Declared once in `internal/record/contract.go`.

### 1.1 `anvil/state` — audit lifecycle (the audit-state ruling)

`collecting | sast_sealed | dast_sealed | both_sealed | consumed | expired`

**Producer:** the scan controller (the controller's state wiring). **Consumer:** the handoff consumer, the store
(`audit_record.state`), the report.

**Why `dast_sealed` and `both_sealed` both exist — do not collapse them into one `sealed`.**
The spine's corrected-requirements table requires "one audit identity, two **independently**-sealed halves, a re-entrant
consumer." A state machine whose only sealing path is SAST-then-DAST cannot express a DAST-first seal at
all, and a DAST-first seal is reachable in practice: the SAST half can be slow or can fail while the DAST
half completes. Collapsing also makes `sealed` terminal, which makes `consumed` unreachable, which
silently disables the re-entrant consumer. The control plane's earlier four-state machine
(`open → sast_sealed → sealed → expired`) had exactly these two failures and is struck.

The sealer additionally requires a DAST-disabled audit to reach `both_sealed` — a value the control plane was previously
*forbidden* from producing.

### 1.2 `anvil/status` — per-half run status (the half-status ruling)

`running | sealed | failed | timed_out | skipped`

**Producer:** the SAST/DAST worker, at seal time. **Consumer:** the re-entrant consumer's read gate
(the sealer), the report.

`sealed` is load-bearing, not cosmetic. The sealer makes this exact token the hard read gate: *a consumer may
not read a half's results before that half's status equals `sealed`*. The control plane keyed its transitions on
`complete`, which means the gate never opens and the consumer never runs. `timed_out` is adopted from
the control plane — it distinguishes "it broke" from "it ran out of clock".

`anvil/sealedAt` is required exactly when status is `sealed`, and is explicitly `null` otherwise. A
missing key and an unsealed half must not be the same observation.

### 1.3 `anvil/dastStatus` — audit-level DAST outcome (the dastStatus ruling, found twice)

`not_run | skipped_no_manifest | running | completed_clean | completed_findings | completed_partial |
completed_failed |
target_boot_failed | target_unreachable | timed_out`

**Producer:** the scan controller, **derived from** the DAST half's `anvil/status` and from
`anvil/target.provenance`. Emitted by coverage reporting. **Consumer:** the coding agent (which must not treat an
absent DAST half as "scanned clean"), the report, `audit_record.dast_status` (`NOT NULL`, default
`not_run`).

The record area had seven values and the dynamic tier had five, with **zero literal overlap** — the dynamic tier could not have written a
single row into the record area's `NOT NULL` column. The frozen set is the union plus the dynamic tier's `partial`, renamed
`completed_partial`.

**Why `skipped_no_manifest` is distinct from `not_run` — do not merge them.**

* `not_run` — the DAST tier is not installed at all. Under the two-artifact split, DAST ships as
  a separate distribution artifact, so this is the common case and it says nothing about the target.
* `skipped_no_manifest` — the DAST tier *is* installed and ran, and no target manifest was declared, so
  there was nothing to scan. That is a configuration gap in the target, and it is actionable.

The spine's record section requires that a target which failed to boot be distinguishable from one scanned
clean; the same argument applies one level up. `research/23-dast-signal-sources.md` Risk #1: "Anvil must
never report '0 DAST findings' as 'no dynamic vulnerabilities'." Merging these makes that mistake
unfixable at the schema level.

**Only `completed_clean` may be read as "dynamically scanned, nothing found."** Use
`DastStatus.MeansDynamicallyScannedClean()` rather than `!= "completed_findings"`.

### 1.4 `anvil/target.provenance` — boot / reachability outcome (the target-provenance split, found twice)

`booted_clean | boot_failed | build_failed | no_target_declared | unreachable_at_scan_time`

**Producer:** the target lifecycle harness (the dynamic tier). This area reserves the field and owns the
vocabulary. **Consumer:** the coding agent, the `dast_status` derivation, the report,
`audit_record.target_provenance` (`NOT NULL`).

### 1.5 `anvil/target.provisioning` — which provisioning path (NEW required field)

`ephemeral_manifest | live_url_authorized`

**Producer:** the target lifecycle harness (coverage reporting). **Consumer:** the authorization audit trail, the
report.

**Why 1.4 and 1.5 are two fields — do not merge them back into one.** They were previously one field
name carrying two meanings, which is how the defect happened: the dynamic tier wrote its provisioning-path literals
into a field the record area defined as a boot outcome. They are genuinely different measurements and both are
required:

* `provenance` answers *what happened when we tried to run the target*. **`dastStatus` is derived from
  this one** (`booted_clean` → the DAST half's own outcome; `boot_failed`/`build_failed` →
  `target_boot_failed`; `unreachable_at_scan_time` → `target_unreachable`; `no_target_declared` →
  `skipped_no_manifest`). A merged field cannot support that derivation, and the spine's
  requirement that a failed-to-boot target be distinguishable from a clean scan is information a merged
  field loses.
* `provisioning` answers *which path did we take to get a target*. A live third-party URL and a
  throwaway container Anvil built itself are not the same authorization question, and the spine's safety section makes the authorization kernel a pure function of `(target, scope, attestation, clock)`. The record
  must state which one was scanned. Never infer `live_url_authorized` from reachability, and never from
  `security.txt` — the spine's safety section: "`security.txt` resolves a reporting channel and never grants permission."

### 1.6 `anvil/verdict` — triage judgment about the finding (the verdict-mapping ruling)

`true_positive | false_positive | insufficient_context`

**Producer:** the detector model / triage gate, via **the Lane B pipeline's** named mapping. **Consumer:** the
coding-agent consumption pipeline — it drops `false_positive` and demotes `insufficient_context` to
report-only — plus the report and `finding.verdict`.

**Why `insufficient_context` is a verdict and not a low confidence score — do not replace it with a
threshold on `anvil/confidence`.** The spine's record section is explicit: "`INSUFFICIENT_CONTEXT` as a valid
detector verdict, not just a confidence float." A low confidence score means *this is probably not a real
defect*. `insufficient_context` means *this may well be a real defect and the detector could not see
enough to tell* — typically because the sink sits behind a dynamic dispatch, a framework boundary, or a
file the scan did not have. Those two demand opposite handling: the first is dropped, the second is
escalated to a human or to the DAST half. A confidence threshold silently discards exactly the second
population, and a float cannot express the difference.

Lane B keeps its own in-process `Verdict.Result` (`EXHIBITS|…`), which is a judgment about the **code**;
`anvil/verdict` is a judgment about the **finding**. Collapsing them would lose that distinction, so both
stand and **the Lane B pipeline owns the mapping, including case normalisation**. A mapping with an owner and a test is
not the same thing as two vocabularies drifting.

---

## 2. `anvil/trust` — required on every string originating outside Anvil

`untrusted | anvil_generated | verified`

**Producer:** whichever component ingests the external string (advisory text, DAST response bodies,
repo source snippets, third-party SARIF imports). **Consumer:** the prompt builder, which must never
treat `untrusted` text as instructions (the spine's safety section prompt-injection containment), and the
report.

> **A repo source snippet is `untrusted` even though Anvil is what put it in the struct.**
>
> Lane B was found stamping `anvil_generated` on a struct whose `Snippet` field is verbatim target-repo
> source. That would have disabled remediation's containment check on the exact string that most needs it: an
> attacker who can commit to the scanned repository can write agent instructions into a comment, and that
> comment lands in `region.snippet.text`. The question `anvil/trust` answers is **who wrote these bytes**,
> never **who assigned this field**.

`anvil_generated` means Anvil *produced* the bytes — detector reasoning, derived summaries, computed
digests. It never means "Anvil assembled the containing object." `verified` means the bytes came from
outside **and** passed an explicit validation step named in the record; it is never a default.

`Trust.LegalForExternalString()` encodes the rule: an external string may be `untrusted` or `verified`,
never `anvil_generated`.

### How trust is carried

The spine's record section says *every* external string, and one result carries several strings of different
provenance at once — a repo snippet, a model-generated explanation, an attacker-controlled response body.
So:

* **SARIF-native strings** cannot change shape without breaking SARIF, so they are classified out of
  band. `result.properties["anvil/trust"]` is `{ "default": <trust>, "fields": { <JSON Pointer>: <trust> } }`,
  where each pointer is RFC 6901 **relative to the result object**.
* **`anvil/*` extension strings** that carry external text use the inline `{ "text", "trust" }` shape
  (`record.TrustedString`) — currently `anvil/advisory.excerpt` and `anvil/repro.observedSignal.match`.

`record.ValidateResultTrust` walks `Result.ExternalStringPointers()` — region and context-region snippets
in `locations`, `relatedLocations` and `codeFlows`, plus `webResponse.body.text` and
`webResponse.headers` — and rejects any that is classified `anvil_generated`. A result carrying a
`webResponse` must additionally set `default` to `untrusted`: the spine's safety section names the DAST
response body the highest-risk field in the system, "up to 32 KB of attacker-controlled bytes fed to a
repo-credentialed agent."

---

## 3. Vocabularies that are **not** among the six, and who owns them

| Vocabulary | Values | Owner / status |
|---|---|---|
| `handoff.state` | `ready, leased, validated, failed_validation, failed_format, skipped_budget, false_positive, regression_introduced, fixed_incidentally, split_required, withdrawn, superseded, expired` | Literals frozen here (the shared-vocabulary review's enum block, the handoff-table and one-ledger rulings); the **table and DDL are the store schema's**. The consumption controller and the queue cut read and write it. Remediation's `anvil_ledger` is deleted — a second durable copy directly violates the spine's corrected-requirements table, and the concrete failure traced was the queue cut writing `SKIPPED_BUDGET` to the ledger while the record area's ready-set index still saw the row as `ready`, so it was re-leased forever. |
| `handoff.consumption_class` | `static_only, requires_dynamic_confirmation` | Column merged into `handoff` by the handoff-table ruling (came from the handoff adapter). Nothing else in the schema expresses the static-only vs. requires-dynamic-confirmation gate. |
| `anvil/half` | `sast, dast` | The record area. Which **half of the audit** produced the run/result. |
| `anvil/evidenceClass` | `dast_confirmed, sast_reachable, sast_static_only, sca, host` | The record area. `research/24`: "this is the field that makes tier-0 ordering possible." Consumed by the queue re-cut and the read path's read order. |
| `finding.detector` | `sast, dast, sca, host` | The record area. Deliberately **not** the same enum as `evidenceClass`: `sast_reachable` and `sast_static_only` are both produced by the `sast` detector and must hash under the same fingerprint tier. |
| `anvil/repro.injectionPoint.kind` | `query, body, header, cookie, path` | The record area (the Fingerprint Specification hashes it). |
| `anvil/repro.observedSignal.kind` | `responseStackTrace, statusCodeFlip, dbErrorString, timingSideChannel, reflectedPayload, other` | The record area (hashed as a separate field from `injectionPoint`: *where the payload went in* and *how the defect showed up* are independent facts). |
| `anvil/correlation.signals[].name` | `responseStackTrace, routeTable, callGraphReach, parameterName, cweMatch, rerunFlip` | The record area; consumed by correlation. |
| `finding.state` | `open, resolved, suppressed, regressed` | The record area (store). |
| `scan_run.status` | `running, ok, failed, partial` | The record area (store); **written by the control plane**. |
| `anvil/dastCoverage.inventoryProvenanceMix` keys | `runtime_spec, repo_spec, static_extraction, crawl` | **Produced by the dynamic tier (the inventory, crawl and authentication)**, mirrored here so a naming drift is caught at this file rather than at integration. Flagged to the orchestrator as a candidate seventh frozen enum. |
| `anvil/specHarvest.outcome` | `harvest_ran, harvest_skipped` | The record area owns the vocabulary; the **SAST spec-harvest pass produces it** and **the repo spec reader consumes it**. `AreaMappingOwners` records that **no mapping step is permitted**: `inventory.HarvestOutcome` already uses these two literals, so the handoff is identity today and a translating step would re-open the produce/consume break the shared-vocabulary review closed, at the one seam where the two vocabularies cannot disagree. There is no third literal — see §5. |
| `anvil/locus.proximityClass` | *unenumerated* | Owned by the coding-agent consumption area (`research/24`'s Hunk4J citation). **Register it here before a second area consumes it**, or it becomes the eleventh defect of this exact shape. |

`record.AreaMappingOwners` carries the same ownership statements in code, so they survive independently
of this document.

---

## 4. Audit envelope — `sarifLog` and `sarifLog.properties`

Every row names its producer and its consumer. **NEW** marks a field the spine's record section flagged as
absent from branch 18's original design.

| Field | Native / ext | Required? | Producer | Consumer |
|---|---|---|---|---|
| `$schema` / `version` | SARIF-native | required, pinned to `2.1.0` exactly | record assembler | any SARIF consumer, GitHub, DefectDojo |
| `anvil/schemaVersion` | ext | required | record assembler | store, migrations, coding agent |
| `anvil/auditId` | ext | required | scan controller, at scan start | store (PK), handoff, coding agent, report |
| `anvil/state` **NEW** | ext | required, §1.1 enum | scan controller (the controller's state wiring) | handoff consumer, store, report |
| `anvil/version` **NEW** | ext | required, monotonic int ≥ 1, bumped on every re-scan of the same audit | scan controller | the queue re-cut |
| `anvil/createdAt` | ext | required | scan controller | store, reaper |
| `anvil/target.{repoUrl,ref,commit,subpath}` | ext | required | scan controller | coding agent, correlation, report |
| `anvil/target.runtimeBaseUrl` | ext | required only when DAST is enabled | scan controller | DAST worker, repro replay |
| `anvil/target.provenance` **NEW** | ext | required, §1.4 enum | target lifecycle harness (the dynamic tier) | coding agent, `dastStatus` derivation, report |
| `anvil/target.provisioning` **NEW** | ext | required, §1.5 enum | target lifecycle harness (coverage reporting) | authorization audit trail, report |
| `anvil/trigger.{kind,policyId,policyRef,configSource,actor,resolvedAt}` | ext | required | scan controller | report, audit trail |
| `anvil/deadline.deadlineAt` | ext | required, `= scan_run.started_at + claimTimeoutSeconds`, computed **once at scan START** and never recomputed | scan controller | reaper, handoff, coding agent |
| `anvil/deadline.claimTimeoutSeconds` | ext | required, default `28800` (8 h), config-driven | config loader | reaper |
| `anvil/deadline.dastDeadlineSeconds` **NEW** | ext | required key; `null` when DAST is disabled. An **independent clock** from `claimTimeoutSeconds` | config loader | DAST worker, target lifecycle harness |
| `anvil/db.recordId` / `.writtenAt` | ext | required after the DB commit; absent before | store writer | audit trail |
| `anvil/index.*` (Tier-0 manifest: `counts`, `readOrder`, `byCluster`, `byCwe`, `byPath`, `taskCards`, `blobs`) | ext | required, ≤ 8 KB | record assembler | coding agent (Tier-0 read) |
| `anvil/dastStatus` **NEW** | ext | required, **never null**, §1.3 enum | scan controller (derived), emitted by coverage reporting | coding agent, report |

`anvil/deadline` replaces branch 18's `anvil/buffer` per the spine's corrected-requirements table correction: the eight
hours is a **claim timeout**, not a deletion policy and not a confidentiality control. See
`internal/record/SECRETS.md` (the retention document).

`anvil/deadline.deadlineAt` and `anvil/sealedAt` are **independent clocks with independent semantics**
and must never be conflated: `sealedAt` records per-half completion, `deadlineAt` records when an
unclaimed finding stops being eligible. `(*SARIFLog).Validate()` rejects a `deadlineAt` that is not
exactly `createdAt + claimTimeoutSeconds`, which is what makes "anchored to scan start, never to the last
write" checkable rather than aspirational.

`anvil/trigger` **references** the policy that fired; no trigger condition is ever encoded in the record.

---

## 5. Per-half run — `run.automationDetails`, `run.properties`

| Field | Native / ext | Required? | Producer | Consumer |
|---|---|---|---|---|
| `run.automationDetails.correlationGuid` | SARIF-native §3.17.5 | required; **identical in both runs and equal to `anvil/auditId`** | record assembler | correlation / cluster logic |
| `run.properties["anvil/half"]` | ext | required, `sast` or `dast` | SAST/DAST worker | routing |
| `run.properties["anvil/status"]` **NEW** | ext | required, §1.2 enum | SAST/DAST worker at seal time | re-entrant consumer read gate, report |
| `run.properties["anvil/sealedAt"]` **NEW** | ext | required key; a timestamp iff status is `sealed`, otherwise `null` | SAST/DAST worker | re-entrant consumer read gate, deadline math |
| `run.properties["anvil/dastCoverage"]` **NEW** | ext | required on the DAST run | attack-surface discovery (coverage reporting) | coding agent (confidence weighting), report |
| `run.properties["anvil/routeTableDigest"]` | ext | required on the DAST run | DAST worker | audit trail, correlation replay |
| `run.properties["anvil/advisorySnapshot"]` | ext | required on the SAST run | ingestion subsystem (Lane A) | coding agent (staleness), report |
| `run.properties["anvil/runtimeTarget"]` | ext | required on the DAST run | DAST worker | correlation, repro replay |
| `run.properties["anvil/specHarvest"]` **NEW** | ext | optional; **legal only on the SAST run** — `(*Run).validate` rejects it on the DAST run | the SAST spec-harvest pass | attack-surface discovery Tier 1 (the repo spec reader), coverage reporting |

`anvil/runtimeTarget.authProfileRef` is a **config file path and revision**. The record never carries
credentials.

### `anvil/specHarvest` — an outcome, a file list and an omission count, never a bare file list

`plan/design/dynamic-tier.md:628-630` forbids the DAST tier from harvesting spec files itself — "that is explicitly
the SAST tier's job" — so Tier 1 can only ever see a slice somebody handed it. An **empty** slice has
three meanings:

| What happened | Whose fact is it? |
|---|---|
| the repository ships no spec files | the **repository's** — reportable, and the only one that may size a coverage denominator |
| the harvest pass never ran | **Anvil's** |
| files arrived and none of them could be read | **Anvil's** |

All three produce a byte-identical empty route list, and that list flows into the **denominator** of
`anvil/dastCoverage.endpointCoverage`, where a vanished denominator is the shape every "100 % covered"
report is made of. `research/23-dast-signal-sources.md` Risk #1 — "Anvil must never report '0 DAST
findings' as 'no dynamic vulnerabilities'" — is the same mistake one level down.

**The third meaning is deliberately not a third literal.** It is not a fact about the harvest at all: the
harvest ran and delivered files, and what happened next is the DAST tier's own per-file accounting. A
literal for it here would let two areas disagree about which of them observed the failure.

| Sub-field | Meaning |
|---|---|
| `outcome` | §3's `anvil/specHarvest.outcome`. Required; **the zero value is refused**, because the permissive reading of an unset outcome is "the repository ships no specs". |
| `files[]` | Every harvested file carried. Required as an **array** under `harvest_ran` — an empty array, never `null`, the same rule `anvil/repro.env.sanitizers` already states. Must be empty under `harvest_skipped`: a pass that did not run cannot have delivered files. |
| `omittedFileCount` | How many files the harvest **saw and did not carry**. Required under `harvest_ran` and **a pointer / explicit `null`, never a plain int**: `0` asserts that `files` is complete, and that is the answer a forgetful producer would get for free. `null` under `harvest_skipped`. `files` + `omittedFileCount` is the total the pass saw. |

`SpecHarvest` **absent entirely** (`nil`) means *the record makes no statement* — a record assembled
before this slot was wired. It is **not** the same as `harvest_skipped`, and a consumer must read it as
"unknown", never as "the repository ships no specs".

| `files[]` sub-field | Meaning |
|---|---|
| `location` | SARIF §3.4 `artifactLocation`. `uri` required — a harvested file nobody can name is one no operator can go look at when its routes turn out to be wrong. |
| `sizeBytes` | The file's exact harvested length. **Zero is legal**: a repository may commit a zero-byte `openapi.yaml`, and refusing to record that would delete the file from the list, which is the silent loss this struct exists to prevent. |
| `contentSha256` | Lowercase-hex SHA-256 of the exact harvested bytes, before any normalisation or YAML→JSON conversion. Validated by `ValidateDigest`, the package's one digest-shape check. It states **which bytes the DAST tier parsed**. |
| `content` | Optional inline bytes (SARIF §3.3). When present it is the **whole** file: `len(text)` must equal `sizeBytes`. There is no truncation flag on purpose — a truncated spec yields a short route list, a short route list is a smaller denominator, and a smaller denominator makes coverage look better than it is. Truncate out of band and elide `content`. |
| `declaredFormat` | What the **harvester claimed**. Recorded, never believed: the repo spec reader classifies from the bytes, because the harvester classifies on a path and the path is in the repository. **Deliberately not an enum frozen here** — the parser vocabulary is the dynamic tier's growing allowlist, and freezing a snapshot of it would make every new parser a produce/consume break in the opposite direction. |
| `trust` | §2's label, over the URI, the declared format and the content. `anvil_generated` is **refused**: a committed spec file is external text whatever Anvil did to assemble the struct around it. This is the area-B mislabelling of §2, in the field where the bytes are most obviously attacker-authored. |

**Why the SAST run only.** Harvesting is the SAST tier's job by plan, so a copy on the DAST run would be
a second durable statement of one fact that can disagree with the first — the shape the spine's corrected-requirements table and the one-ledger ruling both refuse, and the shape that produced the `anvil_ledger` defect.

### `anvil/dastCoverage` — a numerator, a denominator and a provenance mix, never a bare ratio

| Sub-field | Meaning |
|---|---|
| `probedCount` | Confirmed-probed endpoints. **Never a request count.** |
| `inventoryUnionCount` | The union of the Tier 0–2 inventory — the required denominator. |
| `endpointCoverage` | The spine's `endpoint_coverage`: `probedCount / inventoryUnionCount`, in `[0,1]`. Validated against the two counts, so it cannot drift into a hand-written percentage. |
| `serverLineCoverage` | `null` — **not `0`** — on incremental scans. Zero would read as "we ran and covered nothing." Populated on scheduled full scans only. |
| `inventoryProvenanceMix` | The spine's `inventory_provenance`, aggregated: endpoint count per provenance literal. This is what makes the SAST→DAST handoff auditable. |
| `confirmedCount` / `candidateCount` | Inventory split by whether the endpoint was confirmed to exist or only inferred. |

A bare "62 % covered" is unfalsifiable. `probedCount=31` of `inventoryUnionCount=50`, of which 40 came
from a runtime spec and 10 from a crawl, is not (`research/14` critique m6).

This field consolidates the spine's `dast_coverage`, `endpoint_coverage` and `inventory_provenance` into one
place. `plan/design/record-and-store.md` Open Question 5 asks the attack-surface area to confirm nothing is
lost by that consolidation; nothing here forbids splitting it later.

---

## 6. Per-finding result — `result.*`

SARIF-native slots are used wherever they exist. An `anvil/*` key that duplicates a native mechanism is a
defect, not a convenience.

| Field | Native / ext | Required? | Producer | Consumer |
|---|---|---|---|---|
| `result.correlationGuid` | SARIF-native §3.27.4 | required for clustered findings only; assigned **per cluster**, not per finding | correlation engine | consumer clustering |
| `physicalLocation.region` + `.contextRegion` + `region.snippet` | SARIF-native | required for SAST, absent for pure-DAST | detector | coding agent (Tier-1 card) |
| `logicalLocations[]` | SARIF-native §3.33 | required when a symbol resolves | detector | coding agent |
| `codeFlows[].threadFlows[]` | SARIF-native §3.36/§3.37 | required when a taint path is known | detector | coding agent (where the value enters) |
| `result.taxa[]` / `run.taxonomies[]` (CWE) | SARIF-native §3.8.2 — preferred over tags | required | detector | coding agent, report |
| `result.webRequest` / `.webResponse` | SARIF-native §3.27.14/15 | required for DAST findings; **masked by secrets masking before storage** | DAST worker → masking pipeline | coding agent, verification replay |
| `result.partialFingerprints["anvilFindingId/v1"]` | native mechanism, Anvil-defined value | required, 64 lowercase hex, **never truncated** | fingerprint engine (the fingerprint) | store identity join, regression engine |
| `result.partialFingerprints["primaryLocationLineHash"]` | native mechanism | required when a physical location exists | fingerprint engine | **GitHub upload path only** (the GitHub projection) — the only partial fingerprint GitHub reads |
| `result.partialFingerprints["regionSha256"]` | native mechanism | optional, reserved — see deviation 2 | fingerprint engine (the fingerprint) | coding-agent handoff |
| `result.provenance.*` | SARIF-native §3.48 | required | store, on read-back | regression history, report |
| `result.fixes[]` | SARIF-native §3.27.30 | written only after a coding-agent proposal | coding agent (remediation) | PR generator, verification. **Never auto-merged** (the spine's safety section) |
| `result.rank` | SARIF-native §3.27.11 | optional | ranking | queue order. **Priority, not confidence**; ingested third-party `rank` is untrusted and re-derived (`research/18` Risk #8) |
| `result.properties["anvil/findingId"]` | ext | required | record assembler | cross-reference (task cards, DB) |
| `result.properties["anvil/half"]` | ext | required, must equal the run's half | detector | routing |
| `result.properties["anvil/confidence"]` | ext | required, `[0,1]` | detector model | ranking, report |
| `result.properties["anvil/verdict"]` **NEW** | ext | required, §1.6 enum | detector / triage gate via the Lane B pipeline | consumption pipeline, report |
| `result.properties["anvil/remediableByAgent"]` **NEW** | ext | required, boolean; **host findings are always `false`** | record assembler, derived from `detector` | coding agent (never attempts host fixes — the spine's safety section read-only host agent) |
| `result.properties["anvil/reasoning"]` | ext | required | detector model | report, coding-agent context |
| `result.properties["anvil/detector"]` (`.kind`, `.model`, `.revision`, `.promptDigest`) | ext | required | detector model | audit trail, prompt-digest replay, fingerprint tier selection |
| `result.properties["anvil/evidenceClass"]` | ext | required | record assembler, derived from detector + correlation state | ranking (the queue re-cut), coding agent (the read path read order) |
| `result.properties["anvil/trust"]` **NEW** | ext | required — see §2 | whichever component ingests the external string | prompt builder (the spine's safety-section containment), report |
| `result.properties["anvil/advisory"]` (`.ids`, `.cveIds`, `.sourceFeed`, `.snapshotDigest`, `.licenseSpdx`, `.asOf` **NEW**, `.stalenessSeconds` **NEW**, `.parseDegraded` **NEW**, `.excerpt`, `.licenseManualNote` **NEW**) | ext | required when an advisory is linked | ingestion subsystem at record-assembly time | coding agent (down-weight stale/degraded context), report; `.licenseSpdx` and `.licenseManualNote` → `plan/design/licences.md` |
| `result.properties["anvil/risk"]` | ext | optional — see deviation 1 | Lane A ingestion | ranking (the queue re-cut, the read path), report |
| `result.properties["anvil/patchContext"]` | ext | required for remediable findings | record assembler | coding agent |
| `result.properties["anvil/correlation"]` | ext | required for clustered findings only | correlation engine | coding agent (peer lookup), report |
| `result.properties["anvil/repro"]` (+ `.env.sanitizers[]` **NEW**, `.env.aslrEnabled` **NEW**) | ext | required on any reproducer | DAST worker / dynamic-analysis harness | verification pipeline (the spine's safety section) |
| `result.properties["anvil/locus"].proximityClass` | ext | required for SAST findings | record assembler | fix-grouping (coding-agent area) |
| `result.properties["anvil/chunkRef"]` | ext | required | task-card generator (the read path) | coding agent (Tier-1 pointer) |
| `result.properties["anvil/groupId"]` | ext | key **reserved here**; assigned by the coding-agent consumption pipeline, not by this area | coding agent | coding agent (self-consumed) |
| `location.properties["anvil/locationKind"]`, `["anvil/routeTemplate"]` | ext | required on DAST endpoint locations | DAST worker | correlation, report |

### Notes that have bitten someone already

* **`anvil/half` vs `anvil/detector.kind`.** SCA and host findings are static, so they live in the
  **SAST run** with `half = "sast"` and `detector.kind = "sca"` or `"host"`. `half` is which half of the
  audit; `detector.kind` is which detector. They are not the same question and they do not have the same
  cardinality.
* **`anvil/confidence` is not `rank` and not `level`.** SARIF has no confidence field, so tools stuff
  either priority or confidence into `rank`. `level` is severity (a four-value enum), `rank` is priority
  (0–100), `anvil/confidence` is detector certainty (`[0,1]`). A consumer that reads `rank` as certainty
  cannot tell "high severity" from "high confidence".
* **`anvil/locus` carries only `proximityClass`.** Path, start line, end line and enclosing symbol are
  SARIF-native (`physicalLocation.region`, `logicalLocations`); duplicating them into the property bag
  would create two sources of truth for the same fact. `research/24` lists them as `locus.*` because it
  was writing against a bespoke schema, not SARIF.
* **`anvil/repro.env` is not bookkeeping.** A crash that reproduces only under ASan is a different claim
  from one that reproduces on a stock build, and a use-after-free that reproduces only with ASLR disabled
  may not be exploitable as shipped. The spine's safety section lets only a reproduction that now *fails* earn
  "verified fixed" — a verification re-run under a different sanitizer or ASLR setting is not the same
  experiment, and without these fields nothing can detect that. `sanitizers` is an empty array for a
  stock build, **never null**: null cannot be distinguished from "nobody recorded it."
* **`anvil/advisory.licenseManualNote` sits beside the excerpt because it licenses the excerpt.** It is
  the manual licence override — the **quoted operative sentence** from the publisher's own licence text, which
  Lane A's licence gate requires whenever `licenseSpdx` is `NONE`, `NOASSERTION` or a `LicenseRef-` id:
  exactly the population where the SPDX identifier establishes nothing, and exactly how the KEV metadata
  override was admitted. The feed licence attaches to the **text**, not to Anvil, which is why
  `licenseSpdx` is already per finding rather than per run; a note that stayed behind in the ingestion
  database while the text it licenses travelled into the record would put the redistribution terms and
  the redistributed bytes in two different places. It is a `TrustedString`, not a bare string and not a
  second use of `licenseSpdx`: the note is a **quotation from a publisher's LICENSE file**, so the bytes
  originated outside Anvil, `anvil_generated` is refused exactly as it is for `.excerpt`, and
  `licenseSpdx` is an identifier field that prose corrupts. A present note whose text is **blank is
  refused** — it would satisfy "a note exists" while establishing nothing, which is the absent value
  wearing the legitimate one's clothes; the ingestion cache enforces the same shape in SQL
  (`length(trim(license_manual_note)) > 0`). **Scope:** this slot does *not* make the record the
  enforcement point for the spine's licence section. The standing ruling that the grammatical subject of the spine's licence section is the **CI gate**, not the
  record, is unchanged, and `(*Result).validate` deliberately does **not** require a note when
  `licenseSpdx` is absent — that gate is the cache's `advisory_license_declared` CHECK. This field only
  makes the note **survive** into the record.
* **`anvil/correlation` links, never merges.** Both findings always survive independently: the SAST
  finding owns the file and line, the DAST finding owns the proof, and merging destroys exactly what the
  other contributes. `merged` is unconditionally `false`. At least two independent signals are required,
  a CWE-only match is banned as a sole signal, and `verified: true` requires a `responseStackTrace` or
  `rerunFlip` signal specifically — confidence alone never qualifies (the spine's safety section). The correlation mechanism
  carries an **unresolved patent question** (US10043004B2); see `plan/design/record-and-store.md` Open
  Question 1. Correlation flags it in code and the queue and read-path review verifies the flag exists; **neither resolves it, and it must
  be escalated to the owner before correlation's output ships in a release.**

---

## 7. Size and read path

| Tier | Budget | Contents |
|---|---|---|
| Tier 0 — manifest | ≤ 8 KB | `sarifLog` with tools, rules, taxonomies, `automationDetails`, the `anvil/*` envelope and `anvil/index`; results externalised via SARIF's native `externalPropertyFileReferences` (§3.15) |
| Tier 1 — task cards | ~1,500–2,500 tokens each | One self-contained derived JSON per finding. The SARIF stays authoritative. |
| Tier 2 — blobs | content-addressed | Full response bodies, long thread flows, whole files. Referenced by `sha256:` digest. |

Inline caps: **8 KB request / 32 KB response**, the same thresholds ZAP's SARIF reporter uses. The
remainder **spills to a Tier-2 blob, never dropped**. Advisory excerpts are ≤ 800 tokens, pre-trimmed by
ingestion, never a whole advisory.

Default agent read order is deterministic and not model-chosen: **correlated clusters → SAST-only by rank
→ DAST-only** (`record.DefaultReadOrder()`).

The GitHub upload is a **projection, not the record** (the GitHub projection): only results with a physical code location
and a populated `primaryLocationLineHash`, sharded under 25,000 results/run, 20 runs/file and 10 MB
gzip. `webRequest`, `webResponse`, `taxonomies`-as-relationships, `provenance` and every `anvil/*` bag
are stripped explicitly rather than left for GitHub to ignore silently.

---

## 8. How to validate

Two gates. Both are required, and they are deliberately separate.

1. **Stock SARIF conformance** — validate against `sarif-schema-2.1.0.json`. This is what GitHub and
   DefectDojo need in order to accept the file.
2. **The Anvil extension** — validate against `schemas/anvil-record-v1.schema.json`. This checks the
   `anvil/*` bags, the frozen enums and the S6-required fields.

The Anvil schema does **not** `$ref` the SARIF base schema, because that reference is not resolvable in
Anvil's offline CI, and because keeping the gates separate makes a SARIF-conformance failure
distinguishable from an `anvil/*` failure. The base schema is declared in the non-validating
`x-anvil-baseSchema` annotation.

In Go, `(*record.SARIFLog).Validate()` is the in-process gate — a producer fails at assembly time rather
than at the store boundary. It is not a JSON Schema replacement; it additionally checks the cross-field
invariants a schema cannot express (deadline anchoring, state-vs-halves agreement, coverage arithmetic,
trust classification of external strings).

---

## 9. Logged deviations from `plan/design/record-and-store.md`'s Record Field Contract table

The record contract is required to match that table row for row, or log the deviation. Five deviations, all
additive, none renaming or re-typing an existing row.

1. **`result.properties["anvil/risk"]` added.** No row exists in the plan's table, but
   `research/24-coding-agent-consumption.md` lists `risk.{cvss_v4_base, epss_score, epss_percentile,
   epss_model_date, kev_member, kev_ransomware_use}` among its **non-negotiable** handoff fields,
   "because there is no orchestrator to compute them later," and the queue re-cut and the read path rank on it. It has no
   SARIF-native slot. Optional on the wire.
2. **`partialFingerprints["regionSha256"]` reserved.** `research/24` names
   `fingerprint.region_sha256` as non-negotiable; the plan's table lists only `anvilFindingId/v1` and
   `primaryLocationLineHash`. Reserved and optional; **the fingerprint decides whether to populate it**, and the fingerprint may
   strike it if the algorithm has no use for it.
3. **`anvil/trust` is an object, not a bare enum.** The plan's table types it as a bare enum. One result
   carries several strings of different provenance simultaneously, and a single enum per result collapses
   to the most permissive value — which is precisely the failure mode §2 describes. **The three literals
   are unchanged**; only the container is richer. See §2 for the shape.
4. **`run.properties["anvil/specHarvest"]` added.** No row exists in the plan's table, and none existed
   anywhere: the repo spec reader's Ruling-7 reconciliation grepped `contract.go` and this file for a `SpecFile`, an
   `Artifacts` list, or any run-level slot for SAST-harvested spec files and **found nothing to consume**,
   which is why that packet shipped `PARTIAL`. Without the slot a repository that ships no API specs and
   a harvest handoff that was never wired produce byte-identical records, and both size the denominator
   of `endpointCoverage`. Optional on the wire, SAST-run only. See §5.
5. **`result.properties["anvil/advisory"].licenseManualNote` added.** No row exists in the plan's table.
   The spine's licence section requires "a manual-override field carrying the quoted operative sentence", and
   the Lane A chain ledger records the licence gate admitting the KEV metadata override **on the strength
   of exactly that note** — but the note stopped at `internal/ingest` and did not survive into the record,
   so `internal/record/lanea/emit.go` was carrying it out of band on `Emission.LicenseManualNote` and
   reporting the gap (its deviation 1). Optional on the wire. **This does not move the spine's enforcement point:**
   the standing ruling that the grammatical subject of the spine's licence section is the CI gate stands, and this contract does not
   require a note when `licenseSpdx` resolves. See §6.

Two further reconciliations, recorded because a reader of `research/18`'s annotated example will notice
them:

* Branch 18's example writes `injectionPoint.kind: "jsonBodyField"` and
  `observedSignal.kind: "dbErrorInResponseBody"`. Both are ad-hoc labels that predate
  `plan/design/record-and-store.md`'s Fingerprint Specification, which froze `body` and `dbErrorString`
  respectively. **The Fingerprint Specification wins**, because those tokens are hashed and a producer
  using the older spelling would mint a different digest for the same defect.
* Branch 18's `anvil/buffer.{createdAt,expiresAt,retentionSeconds,deletePolicyRef}` is replaced by
  `anvil/deadline` per the spine's corrected-requirements table correction. `research/18`'s annotated example therefore
  does **not** validate against this schema, and that is by design: it predates the spine's record section and lacks every field
  the spine's record section added. See §10.

---

## 10. Evidence

`(*SARIFLog).Validate()` and `schemas/anvil-record-v1.schema.json` were both exercised against a
synthetic record carrying one SAST, one SCA, one host and one DAST finding with a correlated
SAST↔DAST cluster, produced by marshalling `internal/record`'s own Go structs. Result: **Go validation
passes; JSON Schema validation reports zero errors.**

Seventeen Go-level and twenty schema-level negative fixtures were each confirmed rejected, including
every literal the shared-vocabulary rulings struck: `dast_status: "clean"` (the dynamic tier's old set), `status: "complete"` and
`state: "sealed"` (the control plane's old machine), a provisioning literal written into `target.provenance`, a repo
snippet stamped `anvil_generated`, a host finding marked remediable, a truncated 32-hex fingerprint, a
CWE-only correlation, `verified: true` without a stack-trace or re-run-flip signal, `merged: true`, a
recomputed deadline, a DAST run with no coverage block, and `version: "2.2"`.

`research/18`'s annotated example (comments stripped) produces **30 validation errors**, all of them the
record-section additions it predates — `anvil/state`, `anvil/version`, `anvil/deadline`, `anvil/dastStatus`,
`target.provenance`, `target.provisioning`, per-half `status`/`sealedAt`, `anvil/dastCoverage`,
`anvil/verdict`, `anvil/remediableByAgent`, `anvil/evidenceClass`, `anvil/trust`, advisory
`asOf`/`stalenessSeconds`/`parseDegraded`, `repro.env`, `detector.kind`, correlation
`signals`/`verified` — plus the two renamed reproduction literals in §9. **That the older example fails
is the schema working**, not a defect; the packet's original "validates the annotated example with zero
errors" criterion was written before the shared-vocabulary rulings and cannot be satisfied simultaneously with the spine's
"all of these are required."


---

## Amendment 2026-08-07 — `anvil/dastStatus` gains `completed_failed`

The frozen enum had **no image for "the DAST half itself broke"**. A half with `anvil/status = failed`
against a target whose provenance is `booted_clean` had nowhere legal to land, and `the sealer` was folding it
onto `completed_partial` — flagging the compromise rather than absorbing it silently.

That fold is wrong for the same reason the spine's record section requires a failed target to be distinguishable from one
scanned clean: a half that **crashed** differs from one that **covered part of the surface**. Collapsing
them makes `dast_coverage` uninterpretable, because a 40% figure could mean "we probed 40% and stopped"
or "we probed 40% and the engine died". `DeriveDastStatus` is now total — every
(provenance, half-status) pair has exactly one image.

**This vocabulary lives in five places and all five must move together:**

| # | Location | What it is |
|---|---|---|
| 1 | The shared-vocabulary review | the ruling |
| 2 | `internal/record/contract.go` | the Go constants and `DastStatusValues()` |
| 3 | `internal/store/schema.sql` | `ck_audit_record_dast_status` |
| 4 | `schemas/anvil-record-v1.schema.json` | the published wire schema |
| 5 | this file | the contract other areas are pointed at |

**The amendment initially landed in only 1 and 2, and the tree went red.** `the store schema`'s
`TestEnumCheckConstraintsMatchContractLiteralForLiteral` caught it immediately by comparing the SQL
CHECK against the Go enum literal-for-literal — the guard working exactly as intended. The operational
consequence had it shipped was worse than the fold it replaced: an audit whose DAST half crashed could
not be persisted **at all**, because the derivation produced a literal the store rejected.

Recorded because the lesson generalises: **one vocabulary with five definitions is the same defect §6
was written to close**, and an amendment is exactly when it recurs.

---

## Amendment 2026-08-23 — two additive slots: `anvil/specHarvest` and `anvil/advisory.licenseManualNote`

Both were **gaps other packets found and reported rather than patched locally**, which is the behaviour
§0 asks for. Both are additive: no existing field changed, no field reordered, and none of the six frozen
enums touched. `contract_test.go` pins the six literal-for-literal and is what would have caught it.

### The two gaps

| Gap | Found by | What was missing |
|---|---|---|
| No spec-harvest slot | **the repo spec reader** (Tier 1, the repo-spec route), performing the inventory ruling's reconciliation against `internal/record` instead of the placeholder at `plan/design/dynamic-tier.md:1246-1248` | No `SpecFile`, no `Artifacts` list, no run-level slot. The repo spec reader built `HarvestOutcome` locally because "it is the only thing that can separate a genuinely specless repository from an unwired handoff", and shipped `PARTIAL`. |
| No `license_manual_note` slot | **record emission** (`internal/record/lanea/emit.go`, deviation 1) | `AdvisoryContext` carried `LicenseSpdx` and nothing else; `AdvisorySnapshot` carried no licence field either. The note travelled out of band on `Emission.LicenseManualNote`. |

### Where each vocabulary lives now

The 2026-08-07 amendment recorded that `anvil/dastStatus` lives in five places and all five must move
together. `anvil/specHarvest.outcome` lives in **four**, and the fifth is deliberately absent:

| # | Location | What it is |
|---|---|---|
| 1 | `internal/record/contract.go` | `SpecHarvestOutcome` and `SpecHarvestOutcomeValues()` |
| 2 | `internal/record/contract_test.go` | the literal pin, and the pin against the repo spec reader's own vocabulary |
| 3 | `schemas/anvil-record-v1.schema.json` | `$defs.specHarvestOutcome`, `$defs.specHarvest`, `$defs.specHarvestFile` |
| 4 | this file (§3, §5) | the contract other areas are pointed at |
| — | `internal/store/schema.sql` | **no column, by design.** Nothing keys off this value in SQL; it travels inside `audit_record.payload`. `internal/store`'s `enumChecks` table is an explicit list, not a sweep of every enum, so adding a vocabulary with no column does not break `TestEnumCheckConstraintsMatchContractLiteralForLiteral`. **If a column is ever added, this row becomes a fifth place that must move with the rest.** |

`inventory.HarvestOutcome` (the dynamic tier) is a **fifth site by necessity** — `internal/record` cannot import
`internal/dast/inventory` to assert agreement, because `inventory` imports `internal/record`. The literals
are therefore pinned by hand on both sides, `TestSpecHarvestOutcomeLiteralsMatchTheTierOneVocabulary`
asserts this side, and `AreaMappingOwners["anvil/specHarvest.outcome"]` records that **no translating step
is permitted** — the handoff is identity today and must stay identity.

### The guards, and the mutations that proved they fire

Every guard below was broken, watched go red, and restored byte-for-byte (SHA-256 verified). A guard that
has never failed has not been tested.

| Guard | Mutation | Result |
|---|---|---|
| `outcome` has no legal zero value | skip `ValidateSpecHarvestOutcome` | RED |
| `files` is an array, never `null`, under `harvest_ran` | drop the nil check | RED |
| `omittedFileCount` is required under `harvest_ran` | default the nil case to `0` — the realistic defect | RED, at **both** `ValidateSpecHarvest` and `(*SARIFLog).Validate` |
| `harvest_skipped` cannot carry files | drop the check | RED |
| `anvil/specHarvest` is refused on the DAST run | drop the check | RED |
| `contentSha256` is a real digest | skip `ValidateDigest` | RED on all three of empty / truncated / uppercase |
| inline `content` is the whole file | drop the length equality | RED on both short and long |
| a repo spec file is never `anvil_generated` | drop `LegalForExternalString` | RED |
| the licence note is never blank | drop the `TrimSpace` check | RED on both empty and whitespace |
| the licence note is never `anvil_generated` | drop `LegalForExternalString` | RED on both `anvil_generated` and unset |
| the licence note reaches the wire | retag the field `json:"-"` | RED |
| the spec harvest reaches the wire | retag the field `json:"-"` | RED — the two records became byte-identical, which is the defect in its original form |

Every refusal has a **positive control** beside it, because a refusal that fires for every input is not a
gate, it is an outage: a legal harvest under each outcome, a file with its bytes elided, a **zero-byte**
committed spec file, both legal external trust labels on the note, and a finding with no note at all.

### Wire-schema evidence

The Go structs and `schemas/anvil-record-v1.schema.json` were checked against each other rather than
asserted to agree: `internal/record`'s own fixtures were marshalled to JSON and validated with
`jsonschema` 4.26.0 as draft 2020-12. **Four `runProperties` fixtures and one `advisoryContext` fixture
validate; twelve negative controls are all refused** — zero outcome, null `files` under `harvest_ran`,
null `omittedFileCount` under `harvest_ran`, files under `harvest_skipped`, `omittedFileCount` under
`harvest_skipped`, `anvil_generated` file trust, uppercase digest, empty URI, negative `sizeBytes`, a DAST
run carrying a spec harvest, a blank licence note, and an `anvil_generated` licence note.

One disagreement was found and fixed while doing this, and it is the reason the check was run rather than
skipped: `SpecHarvest{Outcome: SpecHarvestSkipped}` marshals `files` as `null`, which the first draft of
the schema refused while the Go validator accepted. The `harvest_skipped` branch now admits `null` and
`[]` alike (they mean the same thing when there is no list to have been written down), and the
`harvest_ran` branch narrows back to an array, which is where the distinction is load-bearing.
