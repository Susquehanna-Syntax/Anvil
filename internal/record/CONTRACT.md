# The Anvil Record Field Contract

**Status: frozen interface.** Everything Anvil produces or consumes crosses this boundary. Once R.17's
exit gate passes, no area may add, rename, or re-type a field here without amending
`plan/40-record-and-storage.md` and `plan/IMPLEMENTATION-PLAN.md` §6.

| | |
|---|---|
| Wire format | SARIF 2.1.0 Plus Errata 01, pinned exactly. Not the 2.2 draft. |
| Extension | `anvil/*` property bags, versioned once at `sarifLog.properties["anvil/schemaVersion"]` = `1.0.0` |
| Go source of truth | `internal/record/contract.go` |
| JSON Schema | `schemas/anvil-record-v1.schema.json` |
| Ground truth this file matches | `plan/40-record-and-storage.md` § "Record Field Contract"; `plan/00-SPINE.md` S1/S6/S7; `plan/IMPLEMENTATION-PLAN.md` §6 |

---

## 0. Read this first if you own another area

`plan/IMPLEMENTATION-PLAN.md` §6 ran two owed review gates on 2026-08-07 and confirmed ten defects.
**Nine of the ten were the same structural error:** eight agents who could not see each other each
declared the shared vocabulary from their own side, and no step had been assigned to reconcile them.
Every one was a produce/consume break — one area wrote literals another area's `NOT NULL` column could
not accept. `dast_status` and `target_provenance` were each found independently by two different critics.

The ruling: **area 40 owns every shared enum, and no other area may declare one.** This file is where
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

Frozen verbatim by `plan/IMPLEMENTATION-PLAN.md` §6. Declared once in `internal/record/contract.go`.

### 1.1 `anvil/state` — audit lifecycle (ruling G2)

`collecting | sast_sealed | dast_sealed | both_sealed | consumed | expired`

**Producer:** the scan controller (O.2). **Consumer:** the handoff consumer, the store
(`audit_record.state`), the report.

**Why `dast_sealed` and `both_sealed` both exist — do not collapse them into one `sealed`.**
`plan/00-SPINE.md` S1 requires "one audit identity, two **independently**-sealed halves, a re-entrant
consumer." A state machine whose only sealing path is SAST-then-DAST cannot express a DAST-first seal at
all, and a DAST-first seal is reachable in practice: the SAST half can be slow or can fail while the DAST
half completes. Collapsing also makes `sealed` terminal, which makes `consumed` unreachable, which
silently disables the re-entrant consumer. Area O's earlier four-state machine
(`open → sast_sealed → sealed → expired`) had exactly these two failures and is struck.

R.6 additionally requires a DAST-disabled audit to reach `both_sealed` — a value area O was previously
*forbidden* from producing.

### 1.2 `anvil/status` — per-half run status (ruling G5)

`running | sealed | failed | timed_out | skipped`

**Producer:** the SAST/DAST worker, at seal time. **Consumer:** the re-entrant consumer's read gate
(R.6), the report.

`sealed` is load-bearing, not cosmetic. R.6 makes this exact token the hard read gate: *a consumer may
not read a half's results before that half's status equals `sealed`*. Area O keyed its transitions on
`complete`, which means the gate never opens and the consumer never runs. `timed_out` is adopted from
area O — it distinguishes "it broke" from "it ran out of clock".

`anvil/sealedAt` is required exactly when status is `sealed`, and is explicitly `null` otherwise. A
missing key and an unsealed half must not be the same observation.

### 1.3 `anvil/dastStatus` — audit-level DAST outcome (rulings G3 + G6, found twice)

`not_run | skipped_no_manifest | running | completed_clean | completed_findings | completed_partial |
completed_failed |
target_boot_failed | target_unreachable | timed_out`

**Producer:** the scan controller, **derived from** the DAST half's `anvil/status` and from
`anvil/target.provenance`. Emitted by D.26. **Consumer:** the coding agent (which must not treat an
absent DAST half as "scanned clean"), the report, `audit_record.dast_status` (`NOT NULL`, default
`not_run`).

Area 40 had seven values and area D had five, with **zero literal overlap** — D could not have written a
single row into 40's `NOT NULL` column. The frozen set is the union plus D's `partial`, renamed
`completed_partial`.

**Why `skipped_no_manifest` is distinct from `not_run` — do not merge them.**

* `not_run` — the DAST tier is not installed at all. Under `plan/00-SPINE.md` S9-AMENDED, DAST ships as
  a separate distribution artifact, so this is the common case and it says nothing about the target.
* `skipped_no_manifest` — the DAST tier *is* installed and ran, and no target manifest was declared, so
  there was nothing to scan. That is a configuration gap in the target, and it is actionable.

`plan/00-SPINE.md` S6 requires that a target which failed to boot be distinguishable from one scanned
clean; the same argument applies one level up. `research/23-dast-signal-sources.md` Risk #1: "Anvil must
never report '0 DAST findings' as 'no dynamic vulnerabilities'." Merging these makes that mistake
unfixable at the schema level.

**Only `completed_clean` may be read as "dynamically scanned, nothing found."** Use
`DastStatus.MeansDynamicallyScannedClean()` rather than `!= "completed_findings"`.

### 1.4 `anvil/target.provenance` — boot / reachability outcome (rulings G4 + G7, found twice)

`booted_clean | boot_failed | build_failed | no_target_declared | unreachable_at_scan_time`

**Producer:** the target lifecycle harness (area D). This area reserves the field and owns the
vocabulary. **Consumer:** the coding agent, the `dast_status` derivation, the report,
`audit_record.target_provenance` (`NOT NULL`).

### 1.5 `anvil/target.provisioning` — which provisioning path (NEW required field)

`ephemeral_manifest | live_url_authorized`

**Producer:** the target lifecycle harness (D.26). **Consumer:** the authorization audit trail, the
report.

**Why 1.4 and 1.5 are two fields — do not merge them back into one.** They were previously one field
name carrying two meanings, which is how the defect happened: area D wrote its provisioning-path literals
into a field area 40 defined as a boot outcome. They are genuinely different measurements and both are
required:

* `provenance` answers *what happened when we tried to run the target*. **`dastStatus` is derived from
  this one** (`booted_clean` → the DAST half's own outcome; `boot_failed`/`build_failed` →
  `target_boot_failed`; `unreachable_at_scan_time` → `target_unreachable`; `no_target_declared` →
  `skipped_no_manifest`). A merged field cannot support that derivation, and `plan/00-SPINE.md` S6's
  requirement that a failed-to-boot target be distinguishable from a clean scan is information a merged
  field loses.
* `provisioning` answers *which path did we take to get a target*. A live third-party URL and a
  throwaway container Anvil built itself are not the same authorization question, and `plan/00-SPINE.md`
  S7 makes the authorization kernel a pure function of `(target, scope, attestation, clock)`. The record
  must state which one was scanned. Never infer `live_url_authorized` from reachability, and never from
  `security.txt` — S7: "`security.txt` resolves a reporting channel and never grants permission."

### 1.6 `anvil/verdict` — triage judgment about the finding (ruling G8)

`true_positive | false_positive | insufficient_context`

**Producer:** the detector model / triage gate, via **B.12's** named mapping. **Consumer:** the
coding-agent consumption pipeline — it drops `false_positive` and demotes `insufficient_context` to
report-only — plus the report and `finding.verdict`.

**Why `insufficient_context` is a verdict and not a low confidence score — do not replace it with a
threshold on `anvil/confidence`.** `plan/00-SPINE.md` S6 is explicit: "`INSUFFICIENT_CONTEXT` as a valid
detector verdict, not just a confidence float." A low confidence score means *this is probably not a real
defect*. `insufficient_context` means *this may well be a real defect and the detector could not see
enough to tell* — typically because the sink sits behind a dynamic dispatch, a framework boundary, or a
file the scan did not have. Those two demand opposite handling: the first is dropped, the second is
escalated to a human or to the DAST half. A confidence threshold silently discards exactly the second
population, and a float cannot express the difference.

Lane B keeps its own in-process `Verdict.Result` (`EXHIBITS|…`), which is a judgment about the **code**;
`anvil/verdict` is a judgment about the **finding**. Collapsing them would lose that distinction, so both
stand and **B.12 owns the mapping, including case normalisation**. A mapping with an owner and a test is
not the same thing as two vocabularies drifting.

---

## 2. `anvil/trust` — required on every string originating outside Anvil

`untrusted | anvil_generated | verified`

**Producer:** whichever component ingests the external string (advisory text, DAST response bodies,
repo source snippets, third-party SARIF imports). **Consumer:** the prompt builder, which must never
treat `untrusted` text as instructions (`plan/00-SPINE.md` S7 prompt-injection containment), and the
report.

> **A repo source snippet is `untrusted` even though Anvil is what put it in the struct.**
>
> Area B was found stamping `anvil_generated` on a struct whose `Snippet` field is verbatim target-repo
> source. That would have disabled area X's containment check on the exact string that most needs it: an
> attacker who can commit to the scanned repository can write agent instructions into a comment, and that
> comment lands in `region.snippet.text`. The question `anvil/trust` answers is **who wrote these bytes**,
> never **who assigned this field**.

`anvil_generated` means Anvil *produced* the bytes — detector reasoning, derived summaries, computed
digests. It never means "Anvil assembled the containing object." `verified` means the bytes came from
outside **and** passed an explicit validation step named in the record; it is never a default.

`Trust.LegalForExternalString()` encodes the rule: an external string may be `untrusted` or `verified`,
never `anvil_generated`.

### How trust is carried

`plan/00-SPINE.md` S6 says *every* external string, and one result carries several strings of different
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
`webResponse` must additionally set `default` to `untrusted`: `plan/00-SPINE.md` S7 names the DAST
response body the highest-risk field in the system, "up to 32 KB of attacker-controlled bytes fed to a
repo-credentialed agent."

---

## 3. Vocabularies that are **not** among the six, and who owns them

| Vocabulary | Values | Owner / status |
|---|---|---|
| `handoff.state` | `ready, leased, validated, failed_validation, failed_format, skipped_budget, false_positive, regression_introduced, fixed_incidentally, split_required, withdrawn, superseded, expired` | Literals frozen here (§6's enum block, rulings G9+G10); the **table and DDL are R.4's**. X.8/X.9 read and write it. Area X's `anvil_ledger` is deleted — a second durable copy is a direct S1 violation, and the concrete failure traced was X.9 writing `SKIPPED_BUDGET` to the ledger while 40's ready-set index still saw the row as `ready`, so it was re-leased forever. |
| `handoff.consumption_class` | `static_only, requires_dynamic_confirmation` | Column merged into `handoff` by ruling G9 (came from O.3). Nothing else in the schema expresses the static-only vs. requires-dynamic-confirmation gate. |
| `anvil/half` | `sast, dast` | Area 40. Which **half of the audit** produced the run/result. |
| `anvil/evidenceClass` | `dast_confirmed, sast_reachable, sast_static_only, sca, host` | Area 40. `research/24`: "this is the field that makes tier-0 ordering possible." Consumed by R.11's queue re-cut and R.13's read order. |
| `finding.detector` | `sast, dast, sca, host` | Area 40. Deliberately **not** the same enum as `evidenceClass`: `sast_reachable` and `sast_static_only` are both produced by the `sast` detector and must hash under the same fingerprint tier. |
| `anvil/repro.injectionPoint.kind` | `query, body, header, cookie, path` | Area 40 (the Fingerprint Specification hashes it). |
| `anvil/repro.observedSignal.kind` | `responseStackTrace, statusCodeFlip, dbErrorString, timingSideChannel, reflectedPayload, other` | Area 40 (hashed as a separate field from `injectionPoint`: *where the payload went in* and *how the defect showed up* are independent facts). |
| `anvil/correlation.signals[].name` | `responseStackTrace, routeTable, callGraphReach, parameterName, cweMatch, rerunFlip` | Area 40; consumed by R.12. |
| `finding.state` | `open, resolved, suppressed, regressed` | Area 40 (store). |
| `scan_run.status` | `running, ok, failed, partial` | Area 40 (store); **written by area O**. |
| `anvil/dastCoverage.inventoryProvenanceMix` keys | `runtime_spec, repo_spec, static_extraction, crawl` | **Produced by area D (D.18–D.25)**, mirrored here so a naming drift is caught at this file rather than at integration. Flagged to the orchestrator as a candidate seventh frozen enum. |
| `anvil/locus.proximityClass` | *unenumerated* | Owned by the coding-agent consumption area (`research/24`'s Hunk4J citation). **Register it here before a second area consumes it**, or it becomes the eleventh defect of this exact shape. |

`record.AreaMappingOwners` carries the same ownership statements in code, so they survive independently
of this document.

---

## 4. Audit envelope — `sarifLog` and `sarifLog.properties`

Every row names its producer and its consumer. **NEW** marks a field `plan/00-SPINE.md` S6 flagged as
absent from branch 18's original design.

| Field | Native / ext | Required? | Producer | Consumer |
|---|---|---|---|---|
| `$schema` / `version` | SARIF-native | required, pinned to `2.1.0` exactly | record assembler | any SARIF consumer, GitHub, DefectDojo |
| `anvil/schemaVersion` | ext | required | record assembler | store, migrations, coding agent |
| `anvil/auditId` | ext | required | scan controller, at scan start | store (PK), handoff, coding agent, report |
| `anvil/state` **NEW** | ext | required, §1.1 enum | scan controller (O.2) | handoff consumer, store, report |
| `anvil/version` **NEW** | ext | required, monotonic int ≥ 1, bumped on every re-scan of the same audit | scan controller | queue re-cut (R.11) |
| `anvil/createdAt` | ext | required | scan controller | store, reaper |
| `anvil/target.{repoUrl,ref,commit,subpath}` | ext | required | scan controller | coding agent, correlation, report |
| `anvil/target.runtimeBaseUrl` | ext | required only when DAST is enabled | scan controller | DAST worker, repro replay |
| `anvil/target.provenance` **NEW** | ext | required, §1.4 enum | target lifecycle harness (area D) | coding agent, `dastStatus` derivation, report |
| `anvil/target.provisioning` **NEW** | ext | required, §1.5 enum | target lifecycle harness (D.26) | authorization audit trail, report |
| `anvil/trigger.{kind,policyId,policyRef,configSource,actor,resolvedAt}` | ext | required | scan controller | report, audit trail |
| `anvil/deadline.deadlineAt` | ext | required, `= scan_run.started_at + claimTimeoutSeconds`, computed **once at scan START** and never recomputed | scan controller | reaper, handoff, coding agent |
| `anvil/deadline.claimTimeoutSeconds` | ext | required, default `28800` (8 h), config-driven | config loader | reaper |
| `anvil/deadline.dastDeadlineSeconds` **NEW** | ext | required key; `null` when DAST is disabled. An **independent clock** from `claimTimeoutSeconds` | config loader | DAST worker, target lifecycle harness |
| `anvil/db.recordId` / `.writtenAt` | ext | required after the DB commit; absent before | store writer | audit trail |
| `anvil/index.*` (Tier-0 manifest: `counts`, `readOrder`, `byCluster`, `byCwe`, `byPath`, `taskCards`, `blobs`) | ext | required, ≤ 8 KB | record assembler | coding agent (Tier-0 read) |
| `anvil/dastStatus` **NEW** | ext | required, **never null**, §1.3 enum | scan controller (derived), emitted by D.26 | coding agent, report |

`anvil/deadline` replaces branch 18's `anvil/buffer` per the `plan/00-SPINE.md` S1 correction: the eight
hours is a **claim timeout**, not a deletion policy and not a confidentiality control. See
`internal/record/SECRETS.md` (R.9).

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
| `run.properties["anvil/dastCoverage"]` **NEW** | ext | required on the DAST run | attack-surface discovery (D.26) | coding agent (confidence weighting), report |
| `run.properties["anvil/routeTableDigest"]` | ext | required on the DAST run | DAST worker | audit trail, correlation replay |
| `run.properties["anvil/advisorySnapshot"]` | ext | required on the SAST run | ingestion subsystem (area A) | coding agent (staleness), report |
| `run.properties["anvil/runtimeTarget"]` | ext | required on the DAST run | DAST worker | correlation, repro replay |

`anvil/runtimeTarget.authProfileRef` is a **config file path and revision**. The record never carries
credentials.

### `anvil/dastCoverage` — a numerator, a denominator and a provenance mix, never a bare ratio

| Sub-field | Meaning |
|---|---|
| `probedCount` | Confirmed-probed endpoints. **Never a request count.** |
| `inventoryUnionCount` | The union of the Tier 0–2 inventory — the required denominator. |
| `endpointCoverage` | S6's `endpoint_coverage`: `probedCount / inventoryUnionCount`, in `[0,1]`. Validated against the two counts, so it cannot drift into a hand-written percentage. |
| `serverLineCoverage` | `null` — **not `0`** — on incremental scans. Zero would read as "we ran and covered nothing." Populated on scheduled full scans only. |
| `inventoryProvenanceMix` | S6's `inventory_provenance`, aggregated: endpoint count per provenance literal. This is what makes the SAST→DAST handoff auditable. |
| `confirmedCount` / `candidateCount` | Inventory split by whether the endpoint was confirmed to exist or only inferred. |

A bare "62 % covered" is unfalsifiable. `probedCount=31` of `inventoryUnionCount=50`, of which 40 came
from a runtime spec and 10 from a crawl, is not (`research/14` critique m6).

This field consolidates S6's `dast_coverage`, `endpoint_coverage` and `inventory_provenance` into one
place. `plan/40-record-and-storage.md` Open Question 5 asks the attack-surface area to confirm nothing is
lost by that consolidation; nothing here forbids splitting it later.

---

## 6. Per-finding result — `result.*`

SARIF-native slots are used wherever they exist. An `anvil/*` key that duplicates a native mechanism is a
defect, not a convenience.

| Field | Native / ext | Required? | Producer | Consumer |
|---|---|---|---|---|
| `result.correlationGuid` | SARIF-native §3.27.4 | required for clustered findings only; assigned **per cluster**, not per finding | correlation engine (R.12) | consumer clustering |
| `physicalLocation.region` + `.contextRegion` + `region.snippet` | SARIF-native | required for SAST, absent for pure-DAST | detector | coding agent (Tier-1 card) |
| `logicalLocations[]` | SARIF-native §3.33 | required when a symbol resolves | detector | coding agent |
| `codeFlows[].threadFlows[]` | SARIF-native §3.36/§3.37 | required when a taint path is known | detector | coding agent (where the value enters) |
| `result.taxa[]` / `run.taxonomies[]` (CWE) | SARIF-native §3.8.2 — preferred over tags | required | detector | coding agent, report |
| `result.webRequest` / `.webResponse` | SARIF-native §3.27.14/15 | required for DAST findings; **masked by R.8 before storage** | DAST worker → masking pipeline | coding agent, verification replay |
| `result.partialFingerprints["anvilFindingId/v1"]` | native mechanism, Anvil-defined value | required, 64 lowercase hex, **never truncated** | fingerprint engine (R.2) | store identity join, regression engine |
| `result.partialFingerprints["primaryLocationLineHash"]` | native mechanism | required when a physical location exists | fingerprint engine | **GitHub upload path only** (R.14) — the only partial fingerprint GitHub reads |
| `result.partialFingerprints["regionSha256"]` | native mechanism | optional, reserved — see deviation 2 | fingerprint engine (R.2) | coding-agent handoff |
| `result.provenance.*` | SARIF-native §3.48 | required | store, on read-back | regression history, report |
| `result.fixes[]` | SARIF-native §3.27.30 | written only after a coding-agent proposal | coding agent (area X) | PR generator, verification. **Never auto-merged** (S7) |
| `result.rank` | SARIF-native §3.27.11 | optional | ranking | queue order. **Priority, not confidence**; ingested third-party `rank` is untrusted and re-derived (`research/18` Risk #8) |
| `result.properties["anvil/findingId"]` | ext | required | record assembler | cross-reference (task cards, DB) |
| `result.properties["anvil/half"]` | ext | required, must equal the run's half | detector | routing |
| `result.properties["anvil/confidence"]` | ext | required, `[0,1]` | detector model | ranking, report |
| `result.properties["anvil/verdict"]` **NEW** | ext | required, §1.6 enum | detector / triage gate via B.12 | consumption pipeline, report |
| `result.properties["anvil/remediableByAgent"]` **NEW** | ext | required, boolean; **host findings are always `false`** | record assembler, derived from `detector` | coding agent (never attempts host fixes — S7 read-only host agent) |
| `result.properties["anvil/reasoning"]` | ext | required | detector model | report, coding-agent context |
| `result.properties["anvil/detector"]` (`.kind`, `.model`, `.revision`, `.promptDigest`) | ext | required | detector model | audit trail, prompt-digest replay, fingerprint tier selection |
| `result.properties["anvil/evidenceClass"]` | ext | required | record assembler, derived from detector + correlation state | ranking (R.11 re-cut), coding agent (R.13 read order) |
| `result.properties["anvil/trust"]` **NEW** | ext | required — see §2 | whichever component ingests the external string | prompt builder (S7 containment), report |
| `result.properties["anvil/advisory"]` (`.ids`, `.cveIds`, `.sourceFeed`, `.snapshotDigest`, `.licenseSpdx`, `.asOf` **NEW**, `.stalenessSeconds` **NEW**, `.parseDegraded` **NEW**, `.excerpt`) | ext | required when an advisory is linked | ingestion subsystem at record-assembly time | coding agent (down-weight stale/degraded context), report; `.licenseSpdx` → `plan/80-compliance.md` |
| `result.properties["anvil/risk"]` | ext | optional — see deviation 1 | Lane A ingestion | ranking (R.11, R.13), report |
| `result.properties["anvil/patchContext"]` | ext | required for remediable findings | record assembler | coding agent |
| `result.properties["anvil/correlation"]` | ext | required for clustered findings only | correlation engine (R.12) | coding agent (peer lookup), report |
| `result.properties["anvil/repro"]` (+ `.env.sanitizers[]` **NEW**, `.env.aslrEnabled` **NEW**) | ext | required on any reproducer | DAST worker / dynamic-analysis harness | verification pipeline (S7) |
| `result.properties["anvil/locus"].proximityClass` | ext | required for SAST findings | record assembler | fix-grouping (coding-agent area) |
| `result.properties["anvil/chunkRef"]` | ext | required | task-card generator (R.13) | coding agent (Tier-1 pointer) |
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
  may not be exploitable as shipped. `plan/00-SPINE.md` S7 lets only a reproduction that now *fails* earn
  "verified fixed" — a verification re-run under a different sanitizer or ASLR setting is not the same
  experiment, and without these fields nothing can detect that. `sanitizers` is an empty array for a
  stock build, **never null**: null cannot be distinguished from "nobody recorded it."
* **`anvil/correlation` links, never merges.** Both findings always survive independently: the SAST
  finding owns the file and line, the DAST finding owns the proof, and merging destroys exactly what the
  other contributes. `merged` is unconditionally `false`. At least two independent signals are required,
  a CWE-only match is banned as a sole signal, and `verified: true` requires a `responseStackTrace` or
  `rerunFlip` signal specifically — confidence alone never qualifies (S7). The correlation mechanism
  carries an **unresolved patent question** (US10043004B2); see `plan/40-record-and-storage.md` Open
  Question 1. R.12 flags it in code and R.15 verifies the flag exists; **neither resolves it, and it must
  be escalated to the owner before R.12's output ships in a release.**

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

The GitHub upload is a **projection, not the record** (R.14): only results with a physical code location
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

## 9. Logged deviations from `plan/40-record-and-storage.md`'s Record Field Contract table

R.1's contract is required to match that table row for row, or log the deviation. Three deviations, all
additive, none renaming or re-typing an existing row.

1. **`result.properties["anvil/risk"]` added.** No row exists in the plan's table, but
   `research/24-coding-agent-consumption.md` lists `risk.{cvss_v4_base, epss_score, epss_percentile,
   epss_model_date, kev_member, kev_ransomware_use}` among its **non-negotiable** handoff fields,
   "because there is no orchestrator to compute them later," and R.11/R.13 rank on it. It has no
   SARIF-native slot. Optional on the wire.
2. **`partialFingerprints["regionSha256"]` reserved.** `research/24` names
   `fingerprint.region_sha256` as non-negotiable; the plan's table lists only `anvilFindingId/v1` and
   `primaryLocationLineHash`. Reserved and optional; **R.2 decides whether to populate it**, and R.2 may
   strike it if the algorithm has no use for it.
3. **`anvil/trust` is an object, not a bare enum.** The plan's table types it as a bare enum. One result
   carries several strings of different provenance simultaneously, and a single enum per result collapses
   to the most permissive value — which is precisely the failure mode §2 describes. **The three literals
   are unchanged**; only the container is richer. See §2 for the shape.

Two further reconciliations, recorded because a reader of `research/18`'s annotated example will notice
them:

* Branch 18's example writes `injectionPoint.kind: "jsonBodyField"` and
  `observedSignal.kind: "dbErrorInResponseBody"`. Both are ad-hoc labels that predate
  `plan/40-record-and-storage.md`'s Fingerprint Specification, which froze `body` and `dbErrorString`
  respectively. **The Fingerprint Specification wins**, because those tokens are hashed and a producer
  using the older spelling would mint a different digest for the same defect.
* Branch 18's `anvil/buffer.{createdAt,expiresAt,retentionSeconds,deletePolicyRef}` is replaced by
  `anvil/deadline` per the `plan/00-SPINE.md` S1 correction. `research/18`'s annotated example therefore
  does **not** validate against this schema, and that is by design: it predates S6 and lacks every field
  S6 added. See §10.

---

## 10. Evidence

`(*SARIFLog).Validate()` and `schemas/anvil-record-v1.schema.json` were both exercised against a
synthetic record carrying one SAST, one SCA, one host and one DAST finding with a correlated
SAST↔DAST cluster, produced by marshalling `internal/record`'s own Go structs. Result: **Go validation
passes; JSON Schema validation reports zero errors.**

Seventeen Go-level and twenty schema-level negative fixtures were each confirmed rejected, including
every literal the §6 rulings struck: `dast_status: "clean"` (area D's old set), `status: "complete"` and
`state: "sealed"` (area O's old machine), a provisioning literal written into `target.provenance`, a repo
snippet stamped `anvil_generated`, a host finding marked remediable, a truncated 32-hex fingerprint, a
CWE-only correlation, `verified: true` without a stack-trace or re-run-flip signal, `merged: true`, a
recomputed deadline, a DAST run with no coverage block, and `version: "2.2"`.

`research/18`'s annotated example (comments stripped) produces **30 validation errors**, all of them the
S6 additions it predates — `anvil/state`, `anvil/version`, `anvil/deadline`, `anvil/dastStatus`,
`target.provenance`, `target.provisioning`, per-half `status`/`sealedAt`, `anvil/dastCoverage`,
`anvil/verdict`, `anvil/remediableByAgent`, `anvil/evidenceClass`, `anvil/trust`, advisory
`asOf`/`stalenessSeconds`/`parseDegraded`, `repro.env`, `detector.kind`, correlation
`signals`/`verified` — plus the two renamed reproduction literals in §9. **That the pre-S6 example fails
is the schema working**, not a defect; the packet's original "validates the annotated example with zero
errors" criterion was written before §6's rulings and cannot be satisfied simultaneously with S6's
"all of these are required."


---

## Amendment 2026-08-07 — `anvil/dastStatus` gains `completed_failed`

The frozen enum had **no image for "the DAST half itself broke"**. A half with `anvil/status = failed`
against a target whose provenance is `booted_clean` had nowhere legal to land, and `R.6` was folding it
onto `completed_partial` — flagging the compromise rather than absorbing it silently.

That fold is wrong for the same reason S6 requires a failed target to be distinguishable from one
scanned clean: a half that **crashed** differs from one that **covered part of the surface**. Collapsing
them makes `dast_coverage` uninterpretable, because a 40% figure could mean "we probed 40% and stopped"
or "we probed 40% and the engine died". `DeriveDastStatus` is now total — every
(provenance, half-status) pair has exactly one image.

**This vocabulary lives in five places and all five must move together:**

| # | Location | What it is |
|---|---|---|
| 1 | `plan/IMPLEMENTATION-PLAN.md` §6 | the ruling |
| 2 | `internal/record/contract.go` | the Go constants and `DastStatusValues()` |
| 3 | `internal/store/schema.sql` | `ck_audit_record_dast_status` |
| 4 | `schemas/anvil-record-v1.schema.json` | the published wire schema |
| 5 | this file | the contract other areas are pointed at |

**The amendment initially landed in only 1 and 2, and the tree went red.** `R.4`'s
`TestEnumCheckConstraintsMatchContractLiteralForLiteral` caught it immediately by comparing the SQL
CHECK against the Go enum literal-for-literal — the guard working exactly as intended. The operational
consequence had it shipped was worse than the fold it replaced: an audit whose DAST half crashed could
not be persisted **at all**, because the derivation produced a literal the store rejected.

Recorded because the lesson generalises: **one vocabulary with five definitions is the same defect §6
was written to close**, and an amendment is exactly when it recurs.
