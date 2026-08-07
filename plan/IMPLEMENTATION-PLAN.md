# Anvil — Executable Implementation Plan

**For an agent running the `multi-model-agent-orchestrator` skill.** This is not a document to read and
then improvise from. It is a sequence of **158 worker packets** across eight areas, each with a routed
model, a scope, forbidden actions, required evidence, and a stop condition.

**Assembled:** 2026-08-06 by the Opus orchestrator. Synthesis, conflict resolution and global sequencing
were not delegated.

| Read this | For |
|---|---|
| `00-SPINE.md` | The locked architecture. Binding. Not open for re-litigation. |
| `00-ROUTING.md` | Packet format + model routing policy. Binding. |
| `spine-a/b/c-*.md` | The three spine decisions and their evidence |
| `10-` … `80-*.md` | The 158 packets themselves, by area |
| **this file** | Global order, cross-area dependencies, resolved conflicts, route corrections |

---

## 0. Before you dispatch anything — read this section

### 0.1 The route IDs in the skill do not all work here. Verified 2026-08-06.

This was discovered by smoke-testing rather than by assumption, after a first attempt failed in 2 seconds.

| Skill's route | Status in this install | Use instead |
|---|---|---|
| `qwen/qwen3-coder:free` | **ABSENT** — only paid `openrouter/qwen/qwen3-coder` exists | `openrouter/openai/gpt-oss-20b:free`, scope narrowed |
| `openai/gpt-oss-120b:free` | **ABSENT** — only paid `openrouter/openai/gpt-oss-120b` | `openrouter/openai/gpt-oss-20b:free` |
| any bare `provider/model:free` | **will not resolve** | prefix it: `openrouter/<provider>/<model>:free` |
| `nvidia/nemotron-3-super-120b-a12b:free` | present, but **HUNG** with zero output on a 70 KB read | keep off the critical path |
| `nvidia/nemotron-3-ultra-550b-a55b:free` | present | skill already warns of 10–20 min hangs — do not use |
| `openai/gpt-5.5` (paid) | present, **unprefixed** | escalation only, with logged justification |

**Verified working:** `openrouter/openai/gpt-oss-20b:free` — 15 s, clean exit, correct token.
**Always smoke-test a route before depending on it.** Fourteen `:free` routes exist here; enumerate with
`opencode models` rather than trusting any table, including this one.

### 0.2 Correct the area files' critic routing before dispatch

The Lane A planner routed **six** critic steps to paid `openai/gpt-5.5` / `-fast` by default. That
inverts the policy: free first, paid on justification. **Normalisation, applied globally:**

- Keep paid `openai/gpt-5.5` for exactly two classes: the **authorization-kernel** review (`D.2`–`D.9`
  critics) and the **host read-only boundary** review (`A.12`). Both are security gates where a miss is
  unrecoverable.
- Every other cross-family critic → `openrouter/openai/gpt-oss-20b:free` with a **narrowed, mechanical
  scope** matching its guard ("fast source triage, table extraction, draft summaries; avoid hard final
  judgment"). Do not hand it open-ended judgment.
- Escalate to paid only after **observed** weak output, and log the reroute.

### 0.3 The Anthropic session cap is real and it will bite

Six of eight area planners died mid-run on `You've hit your session limit`. **Every one had already
written its file.** The failure was on the return path, not the deliverable.

**Operational rule: check the filesystem before concluding a step failed.** If the artifact exists and is
structurally complete, the step succeeded. Re-running it wastes budget and risks overwriting good work.
This exact pattern also destroyed 19 agents during the research phase that produced `research/`.

---

## 1. Global sequence

Cross-area edges below were derived by the orchestrator from the eight `Dependency Summary` sections. No
area could see the others, so **these edges exist in no area file** — they are the assembly.

```
PHASE 0  serial ─ repo bootstrap
   └─ C.1  LICENSE / NOTICE / THIRD-PARTY-LICENSES        [orchestrator-inline]
   └─ Go module init, cmd/ layout, modernc.org/sqlite dep  [orchestrator-inline]

PHASE 1  parallel group 1 ─ the two true roots
   ├─ M0.1 … M0.17   Evaluation harness + experiment register
   └─ R.1  … R.13    Record contract, fingerprint, store schema, handoff  (NOT the freeze)

PHASE 2  serial ─ THE GATE
   ├─ M0.18  Kill-criteria decision. Reads the register. Decides whether Lane B Tier 3 exists at all.
   └─ R.17   Interface freeze — ONLY after M0.18, because M0 can delete record fields.

PHASE 3  parallel group 2
   ├─ A.1  … A.21   Lane A: ingestion, cache, host + repo SCA        (needs R.1, R.2)
   ├─ B.1  … B.15   Lane B: recall, adjudicator, serving             (needs R.1, R.2, M0.18)
   └─ O.1  … O.7    Scan controller state machine + trigger policy   (needs R.1, R.7)

PHASE 4  serial ─ DAST  (ships as its own artifact — see §2.2)
   └─ D.1  … D.31   needs: R.1, O.2, and TWO edges into Lane B —
                    D.19 ← Lane B's harvested-spec handoff field shape
                    D.29 ← Lane B's adjudicator base-model pick

PHASE 5  serial ─ Remediation
   └─ X.1  … X.24   needs: R.1, R.2, R.7, R.13, O handoff table, D repro artifact
                    (area 60's steps were renumbered 60.n → X.n on 2026-08-06 — see §2.6 D1)

PHASE 6  parallel group 3
   ├─ O.8 … O.20    CI integration, distribution, resource units
   └─ C.2 … C.12    Compliance: quarantine, SPDX gate, plugin boundary, pins

PHASE 7  serial ─ release
   └─ A.21 / B.15 / D.31 / 60.24 conformance harnesses, then the two-artifact split
```

### Cross-area dependency edges (the assembly, not in any area file)

| Consumer | Depends on | The thing |
|---|---|---|
| `A.19` | `R.1`, `R.2` | Lane A must populate the canonical record and **must not invent a second fingerprint** |
| `B.4`, `B.12` | `M0.18` | adjudicator model pick is void until the kill-criteria decision lands |
| `B.*` | `R.1` | `INSUFFICIENT_CONTEXT` and detector-reasoning fields |
| `D.19` | Lane B | field name/shape for harvested `openapi.yaml` / `schema.graphql` / Postman handoff |
| `D.29` | Lane B | DAST model inherits the SAST adjudicator's base model (spine: same base, bigger budget) |
| `X.*` | `R.1`,`R.2`,`R.7`,`R.13` | record, fingerprint, claim protocol, three-tier read path |
| area 60 gate **G7** | `D` | `dast_confirmed` repro artifact — without it, tier-0 ordering **and** the exploit oracle both degrade (G7 is a *validation-ladder gate*, not a step ID) |
| `O.13`,`O.14` | `O.12` | resource figures re-derived from the S9 tier matrix |
| `C.9`,`C.10` | all areas | SPDX gate needs every area's pinned versions |

---

## 2. Conflicts resolved by the orchestrator

Areas were instructed to escalate rather than silently diverge. They did. These are my rulings.

### 2.1 Two areas both claimed to be first — RESOLVED: they are parallel, with one gate

`40-record-and-storage.md`: *"no upstream dependency … it is the first area a coding agent should build."*
`10-milestone0-evaluation.md`: *"M0 is the first milestone by construction."*

Both are right about themselves and neither could see the other. They are **not** in conflict once you
separate **component selection** from **interface definition**:

- M0 decides *whether the model tier exists and which model*. It needs no record — it is a standalone
  harness over PrimeVul / ARVO / `llama-bench`.
- R defines *the interface*. Most of it is independent of whether Tier 3 survives.

**Ruling: run both in Phase 1, in parallel. But R must not freeze its interface until M0.18 lands**,
because a kill decision deletes `INSUFFICIENT_CONTEXT`, detector-reasoning and detector-confidence fields
from the contract. Freezing first would bake in fields for a tier that may not exist.

### 2.2 DAST packaging — RESOLVED: split the artifact (spine S9-AMENDED)

The DAST planner escalated a genuine defect in my own spine. S9 modelled DAST as a config flag
(`dast.enabled=false`); research/20's runner-up wanted a separately distributed package to reduce UK CMA
**s.3A(2)** supply exposure. The planner's objection is correct: **a boolean inside a shipped binary still
supplies the capability to everyone.**

**Ruling: split.** `anvil` (core, no network probing compiled in) and `anvil-dast` (separate artifact,
separate install, explicit attestation). The separate-artifact machinery is already mandatory for the
GPL-3.0 sqlmap driver, so marginal cost is low — and retrofitting after users depend on one binary is far
more expensive. Not a legal conclusion; a risk posture. Full reasoning in `00-SPINE.md` §S9-AMENDED.

### 2.3 Greenbone "unsourced" flag — RESOLVED: false alarm, item stands

Lane A reported "Greenbone VT content" had zero support in the corpus and omitted it. **Verified: it is
extensively sourced** — 17 mentions in `research/15`, which quotes Greenbone's own licence page (*"The
OPENVAS COMMUNITY FEED is a database licensed under the Open Data Commons Open Database License version
1.0"*), plus 13, 13a, 14 and the master report. The planner grepped only its own three input files.
**Right action, wrong reason:** Greenbone belongs to the dynamic/host tier, not Lane A's feed table. The
ODbL share-alike quarantine stands.

### 2.4 Two fingerprint algorithms — RESOLVED inside area 40, correctly

`research/07` and `research/18` specified different `/v1` algorithms under the same name — the exact
defect the audits caught. Area 40 resolved it under its S6 delegation and ships a **conformance test
asserting identical digests on a fixed corpus**. No orchestrator action needed; recorded so it is not
re-opened.

### 2.5 Resource numbers — RESOLVED: re-derive, do not inherit

`research/21`'s systemd figures (18G/22G/24G/28G) carry no source and contradict the minimal-compute
constraint. Area 70 re-derives every figure from the S9 tier matrix. Correct. Any packet quoting the
original numbers is defective.

---

### 2.6 Defects found by deterministic cross-reference — FIX THESE BEFORE DISPATCH

Both cross-family critics failed (see §5), so the cross-area check was done **mechanically, in code**,
over all 159 packets: extract every declared step ID, every cited step ID, and every claimed path, then
diff. For a mechanical consistency question this is better evidence than a model would have produced —
it is exhaustive and reproducible. Re-run it after any edit to an area file.

| # | Defect | Impact | Fix |
|---|---|---|---|
| **D1** | Area 60 numbers its steps **`60.1`–`60.24`**, not `X.1`–`X.24` as the area-prefix convention assigned. | An executing agent following an `X.*` reference finds nothing. This file previously carried that error and is now corrected. | Either renumber area 60 to `X.n`, or accept `60.n` — but do it **once**, globally. Do not leave both conventions live. |
| **D2** | `40-record-and-storage.md` cites **`R.19`** in its Dependency Summary. Only `R.1`–`R.17` are defined. | Compliance (`C.9`/`C.10`) is told to depend on a step that does not exist. | Repoint to the real step that owns the version pins, or add `R.18`/`R.19`. |
| **D3** | `cmd/license-gate/` is named by both area 50 and area 80; `data/LICENSES/` by both area 30 and area 80. | Probably benign cross-references rather than write claims, but **write-scope overlap is the one thing parallel groups must never have**. | Confirm area 80 is the sole writer of both, and that 30/50 only read. |

**Verified clean:** step numbering is gapless in all eight areas (M0 1–18, A 1–21, B 1–15, R 1–17,
D 1–31, X 1–24, O 1–20, C 1–12), and `R.19` is the *only* dangling reference in 159 packets.

### 2.7 Rulings on D1–D3 — applied 2026-08-06 by the executing orchestrator

All three are **closed**. `tools/plan_xref.py` is the executable form of the §2.6 check; re-run it after
any edit to an area file (`python tools/plan_xref.py`, exit 0 = clean).

**D1 — RESOLVED: `X.n` globally.** Area 60's 90 `60.n` occurrences were mechanically renamed to `X.n`
(all 24 IDs verified gapless afterwards, and every `60.n` occurrence in that file was confirmed to be a
step reference — no decimals or percentages were caught in the rename). `X.n` won over `60.n` because
seven of eight areas already use a single-letter prefix, `X` was the letter this area was assigned, and
`60.13` reads as a section number. Downstream references in this file were repointed in the same pass.

**D2 — RESOLVED: repointed, no new step invented.** `R.19` never existed. The pins in area 40's
*Pinned Versions And Licences* table are already owned by live steps: the SARIF 2.1.0 and
`owenrumney/go-sarif` pins are `R.1`'s (that table names the go-sarif fetch as "R.1's first sub-action"),
and the `modernc.org/sqlite` pin is exercised by `R.4`/`R.5` (`R.5` owns the startup FTS5 guard). The
Dependency Summary line now reads `R.1, R.4, R.5`. **One real gap is left open by this ruling and is not
silently closed:** the zstd library for `audit_record.payload` is unpinned and unowned (area 40 Open
Question 4). `C.9`/`C.10` must treat a missing zstd pin as a gate failure, not as an absent dependency.

**Two further defects, D4 and D5, were found by the same script once it parsed all 158 packets** — see
§2.8. Neither appears anywhere in §2.6, because the original check never parsed area 10 (its packets use
a `**Step ID:** M0.1` bold dialect instead of the fenced `Step ID:  M0.1` the other seven use) and never
checked dependency ordering or write-scope overlap at all.

**D3 — RESOLVED: area 80 is the sole writer of `cmd/license-gate/`; `data/LICENSES/` is
partitioned by filename with area 80 owning the index.** Evidence:
- `cmd/license-gate/` — area 50 names it exactly once, in prose, as a "sibling precedent"
  (`50-dast.md:29`). It is a **read/reference**, not a write claim. Area 80 (`C.9`, `C.10`) is the only
  declared writer. No overlap.
- `data/LICENSES/` — three areas genuinely write here, at **disjoint paths, in different phases**:
  area 30 writes `opengrep-binary-distribution.md` and `adjudicator-candidates.md` (Phase 3), area 50
  writes `nuclei-templates/LICENSE` (Phase 4), area 80 writes the model/component LICENSE archives
  (Phase 6). No two are ever in the same parallel group, so the write-scope rule is not violated.
- **Binding rule going forward:** area 80 is the sole writer of the *index* artifacts —
  `data/LICENSES/MODEL-REVISION-PINS.csv`, `data/LICENSE-OVERRIDES.csv`, `data/EXCLUSION-LIST.json` — and
  of the root `NOTICE`. Any other area needing a licence body archived declares the pin in its own
  Pinned Versions table and lets `C.3`–`C.5` do the archiving. **No area outside 80 appends to a shared
  file under `data/`.**

### 2.8 D4 and D5 — found by `tools/plan_xref.py`, both fixed 2026-08-06

**The packet count is 158, not 159.** This file says both in different places. 158 is correct and is now
machine-verified: M0 18 · A 21 · B 15 · R 17 · D 31 · X 24 · O 20 · C 12 = 158, gapless in every area.

**D4 — `D.15` depended on `D.16`, a step numbered after it. FIXED by swapping the two IDs.**
`D.15` was the serial cross-family critic of *both* probe-engine drivers; `D.16` was the ZAP driver it
reviews. The file's physical order was already right (D.14, D.16 in parallel group 4, then D.15 serial),
and `Depends on: D.14, D.16` was explicit and correct — but any dispatcher walking step IDs in ascending
order runs the critic before the thing it criticises. This was the **only** such inversion in 158 packets,
so it is an anomaly, not a convention. The swap was safe to do blind because every one of the 14 live
references was semantically consistent beforehand: each mention of `D.16` meant the ZAP driver and each
mention of `D.15` meant the critic, so exchanging the labels preserves every sentence. Verified after:
`D.14` nuclei driver, `D.15` ZAP driver (parallel group 4), `D.16` critic (serial, depends on D.14+D.15).
**Invariant now enforced by the script: within an area, step number order == execution order.**

**D5 — `O.15` (a review-only critic) held a write claim on `O.3`'s implementation file. FIXED.**
Its scope read *"WRITE: a review note appended to `internal/scanctl/handoff.go`'s package doc comment or a
sibling `REVIEW-O.15.md` in the same directory as the reviewed files — worker states which."* Three things
wrong with that: it let a critic write into the implementer's file, it contradicted its own
`Forbidden actions` line (*"Do not modify … handoff.go logic — review only"*), and it left the path to
**worker choice**, which makes write-scope collision unpredictable rather than merely possible. Now fixed
to `WRITE: internal/scanctl/REVIEW-O.15.md`, matching the `REVIEW-O.4.md` / `REVIEW-O.11.md` /
`REVIEW-O.20.md` convention this same area already uses three times.

**What the script now checks, and what it still cannot:** it enforces unique IDs, gapless numbering,
resolvable citations, resolvable dependencies, intra-area ordering, intra-group write-scope disjointness,
and mandatory-field presence. It does **not** check cross-*area* ordering (the §1 assembly) and it cannot
see a semantic contradiction. Those two remain the job of the review gates in §4.

A second script, `tools/plan_fields.py`, does the mechanical half of the semantic gate: it extracts every
name used by more than one area, with context, so a critic gets a 24 KB input instead of 480 KB of plan.
Its most useful output is a negative: **155 distinct `internal/**.go` paths are named across the eight
areas and not one is named by two of them.** Cross-area write-scope collision on Go source is ruled out
mechanically, which is the strongest form of the guarantee §2.6-D3 was reaching for.

### 2.9 D6 and D7 — the spine's own DAST split never reached area 70. Fixed 2026-08-06.

`00-SPINE.md` §S9-AMENDED and this file's §2.2 both rule that Anvil ships as **two artifacts**: `anvil`
(core, *no network probing capability compiled in*) and `anvil-dast`. That ruling was made when the DAST
area escalated it — **after** area 70 was written. Area 70 never learned about it, and nothing propagated
the ruling into the packets that build and package the binaries. The result is a spine requirement with
no owner, which is worse than an open question because it reads as settled.

**D6 — `cmd/anvil-dast` is mandated by the spine and built by no packet. FIXED in `O.16`.**
`O.16` said *"Build the single static Go binary target — `cmd/anvil`"*, and `O.17` (container) and `O.18`
(systemd tarball) each package that one binary. §1's Phase 7 line says "then the two-artifact split" but
assigns it no step ID. `O.16`/`O.17`/`O.18` are now amended to build and package both artifacts.
**Critically, `O.16` now also owns a build-time import-graph guard** — a test that fails if any
`internal/dast/**` package is reachable from `cmd/anvil`'s import graph. This deliberately mirrors the
mechanism §S7 already mandates for the authorization kernel (*"compiled separately from the model
runtime, with a build-time test that fails if the dependency graph inverts"*). Without it, "no probing
capability compiled in" is a comment, and §2.2's whole argument was that **a boolean does not address the
supply concern** — neither does an unenforced convention.

**D7 — `D.17` writes DAST code into the core binary's directory. FIXED: moved to `cmd/anvil-dast/`.**
The nuclei-templates pinning job declared `WRITE: cmd/anvil/dast-pin-templates.go` while also declaring
`READ: internal/dast/engines/nuclei.go` for the `LoadTemplates` interface it feeds. In Go that is not a
naming quibble: a file in `package main` under `cmd/anvil` that references `internal/dast` **compiles
`internal/dast` into the core binary**, defeating the split at the exact point the split exists to hold.
Now `cmd/anvil-dast/pin-templates.go`. The guard in `O.16` would have caught this at build time; it is
better caught here.

**D8 — the root `NOTICE` had three writers. FIXED: area 80 owns it, `O.17` verifies it.**
`C.1` creates `NOTICE`, `C.4`'s stop condition appends component entries to it, and `O.17` declared
`WRITE: … NOTICE (aggregated)`. Three writers on the file whose entire purpose is to be the single
authoritative attribution point is a defect on its face. Per §2.7-D3 area 80 is the sole writer.
`O.17` is now **read-only on `NOTICE`** and instead *verifies* it: `scripts/collect-licenses.sh` fails the
image build if a component baked into the image has no `NOTICE` entry. That is strictly better than a
third writer, because a verifier catches the omission that an appender would paper over.

**Scope note, stated rather than hidden:** D6/D7 are the only two places the split failed to propagate.
This was checked by grepping every `cmd/` path in all eight area files (`cmd/anvil` ×8 — all in areas 50
and 70; `cmd/license-gate` ×13 — all area 80) and confirming `internal/dast/**` is named only by area 50.

## 3. Review gates (from `00-ROUTING.md`, applied to this plan)

| Gate | Where it binds here |
|---|---|
| Independent critic, **different model family** | authorization kernel (`D.2`–`D.9`), host read-only boundary (`A.9`/`A.12`), record emission (`A.19`), patch generation (`X.*`), every licence conclusion (`C.*`) |
| Tests / build / lint evidence | every code-producing packet |
| Conformance harness | `A.21`, `B.15`, `D.31`, `X.24`, plus `R.2`'s digest test |
| Synthesis cites worker evidence | this file |

**Never delegate:** coordination, synthesis, user communication, or anything destructive, credentialed,
external, or approval-requiring. Those are the orchestrator's or the human's.

---

## 4. What the plan does NOT cover — stated plainly

- **The `opus` dependency-order critic was never run.** The Anthropic session cap made Anthropic
  subagents unavailable, so I performed the ordering analysis myself (§1, §2.1). That is a
  single-perspective result on the most error-prone part of the assembly. **Re-run it when the cap
  resets** — the packet is: *"read every area's Dependency Summary and prove no step depends on a later
  one; report ordering defects only."*
- **No external model reviewed this assembly.** Both free cross-family routes failed and the paid
  escalation was unavailable (out of usage). The substitute was a deterministic code cross-reference
  (§2.6) — exhaustive for *mechanical* consistency, and it found three real defects, but it cannot catch
  a semantic contradiction such as two areas meaning different things by the same field name. **That
  class of defect is unchecked.** Run one cross-family critic when a route becomes available.
- **158 packets were written by 8 agents that could not see each other.** The cross-area edges in §1 are
  my reconstruction. Treat them as the most likely place for an error.
- **Everything downstream of M0 is provisional by design.** If EXP-01 (advisory permutation) or EXP-02
  (code-metrics baseline) fails, Lane B Tier 3 is deleted and Anvil becomes a deterministic scanner with
  an LLM patcher. Phases 3–7 assume it survives. That is the intended shape, not an oversight.
- **`research/` is gitignored.** The plan cites it heavily. Do not assume a fresh clone can read it.

---

## 5. Routing ledger

**Used:** `opus` (orchestrator, spine, sequencing, conflict resolution) · `sonnet` ×6 (build-vs-fork,
language, and 5 component areas) · `haiku` ×2 (licence closure, compliance) ·
`openrouter/openai/gpt-oss-20b:free` (cross-family critic, after reroute).

**Escalation attempted and unavailable:**
- `openai/gpt-5.5` — cross-area consistency review. The trigger was properly met: two consecutive
  free-route failures, observed not predicted. `nemotron-3-super-120b-a12b:free` hung with zero output on
  a 70 KB read; `gpt-oss-20b:free` then consumed **34,589 tokens and emitted 44 output tokens**, its
  reasoning trace looping (*"Wait this is repeating"*) without ever reaching an answer.
  **The escalation could not run — the gpt-5.5 account is out of usage.** So the cross-family critic slot
  is **unfilled**, and the cross-area check was done mechanically in code instead (§2.6), which found
  three defects a model likely would have missed.
  **For the executing agent: no external model reviewed this assembly.** The `opus` dependency-order
  critic is still owed once the Anthropic cap resets — that packet is in §4.

**Considered and deliberately unused:**
- `nvidia/nemotron-3-ultra-550b-a55b:free` — strongest free route present; skill documents 10–20 min
  hangs and both critic slots sat on the critical path.
- `qwen/qwen3-coder:free`, `openai/gpt-oss-120b:free` — do not exist in this install.

**Reroutes logged:** 2 — (1) `nemotron-3-super:free` → `gpt-oss-20b:free` on timeout with empty output;
(2) `gpt-oss-20b:free` → paid `openai/gpt-5.5` on non-answer. **Lesson for the executing agent: the free
tier here is not reliable for whole-plan judgment.** Use it for bounded extraction and mechanical checks,
which is what its guard says, and budget for paid escalation on any cross-cutting review.
**Verification performed by the orchestrator rather than trusted:** Gemma 4's licence, `antst/go-apispec`
identity, artiphishell's CodeQL coupling, `ossf/oss-crs` existence, `modernc.org/sqlite` FTS5 support,
Greenbone's corpus support. Four of six changed or defended a decision.
