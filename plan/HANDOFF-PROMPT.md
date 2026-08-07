# Handoff Prompt — Implementing Anvil

**Paste everything below the line into a fresh agent.** It is self-contained; the agent starts cold and
should need nothing from the conversation that produced the plan.

---

You are the **orchestrator** for building a project called **Anvil**. Load the
`multi-model-agent-orchestrator` skill and run as its Opus main agent: you own task framing, final
synthesis, side effects, user communication, and conflict resolution, and you delegate everything else.
Workers never spawn workers.

## What Anvil is

An open-source, **profit-free**, self-hostable system that finds vulnerabilities in Linux servers and
code repositories and proposes fixes, using locally-served open-weight models and never browsing the live
web at inference time. It is greenfield — the repo currently contains only `README.md`, `.gitignore`,
`plan/`, and `research/`.

## Your job

Execute `plan/IMPLEMENTATION-PLAN.md`: **159 worker packets** across eight areas and seven phases. Each
packet already specifies its objective, scope, forbidden actions, required evidence, stop condition, and a
routed model. You dispatch them, enforce the review gates, resolve conflicts workers escalate, and
assemble results. You do **not** re-plan what is already planned.

## Read in this order, before dispatching anything

1. `plan/IMPLEMENTATION-PLAN.md` — global sequence, cross-area dependencies, resolved conflicts, and the
   environment corrections in §0. **§0 will save you two failed attempts. Read it first.**
2. `plan/00-SPINE.md` — the locked architecture. **Binding. Not open for re-litigation.**
3. `plan/00-ROUTING.md` — packet format and model-routing policy. **Binding.**
4. The area file for whatever phase you are on: `plan/10-` … `plan/80-*.md`.
5. Only if you need the underlying evidence: `plan/spine-a/b/c-*.md`, then `research/`.

## Four operational facts, each verified the hard way

1. **Free OpenRouter routes here need an `openrouter/` prefix, and two of the skill's defaults do not
   exist at all** (`qwen/qwen3-coder:free`, `openai/gpt-oss-120b:free`). Enumerate with
   `opencode models` and **smoke-test any route before depending on it.** Verified working:
   `openrouter/openai/gpt-oss-20b:free`.
2. **The free tier is unreliable for whole-plan judgment.** One route hung with zero output; another
   burned 34,589 tokens to emit 44 while looping. Use free routes for bounded extraction and mechanical
   checks — their documented lane — and expect to escalate for anything cross-cutting.
   **`openai/gpt-5.5` is currently out of usage.** Do not plan around it without checking.
3. **The Anthropic session cap will kill subagents mid-run.** When it does, **check the filesystem before
   concluding a step failed** — during planning, six of eight agents died on the return path *after*
   writing complete files. Re-running them would have destroyed good work. This has now happened twice on
   this project; treat it as expected behaviour, not an anomaly.
4. **For mechanical consistency questions, write code, not a prompt.** The cross-area check that found
   three real defects was a script over all 159 packets, not a model. It is in
   `IMPLEMENTATION-PLAN.md` §2.6 — re-run it after any edit to an area file.

## Pre-dispatch defects — ALL RESOLVED 2026-08-06. Do not redo these.

`IMPLEMENTATION-PLAN.md` §2.6 listed three defects (D1-D3) found by deterministic cross-reference. They
are fixed, and running the check as code found **five more** (D4-D8). All eight rulings are recorded in
`IMPLEMENTATION-PLAN.md` §2.7-§2.9. Summary:

- **D1** — area 60 renumbered `60.n` -> `X.n` globally. `X.n` is now the only live convention.
- **D2** — the dangling `R.19` repointed to `R.1, R.4, R.5`, the steps that actually own those pins.
  The zstd pin remains genuinely unowned; `C.9`/`C.10` must treat that as a gate failure.
- **D3** — area 80 confirmed sole writer of `cmd/license-gate/` and of every index artifact under
  `data/`. `data/LICENSES/` is written by three areas at disjoint paths in different phases.
- **D4** — `D.15` depended on `D.16`. IDs swapped; `D.15` is now the ZAP driver and `D.16` the critic.
- **D5** — `O.15`, a review-only critic, held a write claim on `O.3`'s `handoff.go`. Now writes only
  `internal/scanctl/REVIEW-O.15.md`.
- **D6** — `cmd/anvil-dast` is spine-mandated by S9-AMENDED and was built by no packet. `O.16`/`O.17`/
  `O.18` now build and package both artifacts, and `O.16` owns an import-graph guard.
- **D7** — `D.17` wrote DAST code into `cmd/anvil/`, compiling `internal/dast` into the core binary.
  Moved to `cmd/anvil-dast/`.
- **D8** — the root `NOTICE` had three writers. Area 80 owns it; `O.17` verifies rather than edits.

**Two scripts now exist and are the reproducible form of this check. Re-run both after any area edit:**

```
python tools/plan_xref.py     # exit 0 = clean. 158 packets, 7 invariants.
python tools/plan_fields.py   # shared-vocabulary extraction for the semantic gate
```

`plan_xref.py` enforces: unique IDs, gapless numbering per area, resolvable citations, resolvable
dependencies, **intra-area ordering (step number order == execution order)**, intra-group write-scope
disjointness, and mandatory-field presence. `plan_fields.py`'s most useful output is a negative: 155
distinct `internal/**.go` paths across the eight areas, **zero named by two areas**.

**The packet count is 158, not 159.** Machine-verified: M0 18 + A 21 + B 15 + R 17 + D 31 + X 24 + O 20
+ C 12.

## Two review gates are owed. Do not skip them silently.

- **A cross-family critic never ran** on the assembled plan — both free routes failed and the paid
  escalation was unavailable. The mechanical check cannot catch a *semantic* contradiction (two areas
  meaning different things by the same field name). Run one when a route is available.
- **The `opus` dependency-order critic never ran.** Its packet: *"Read every area's Dependency Summary.
  Prove no step depends on a step that runs later. Report ordering defects only."* Run it once the
  Anthropic cap resets.

## Where to start

**Phase 0**, serial: repo bootstrap — Go module init, `cmd/` layout, `modernc.org/sqlite` dependency, and
`C.1` (LICENSE / NOTICE / THIRD-PARTY-LICENSES). Then **Phase 1**, parallel: Milestone 0 (`M0.1`–`M0.17`)
alongside the record contract (`R.1`–`R.13`).

**The Phase 2 gate is the most important decision in the project.** `M0.18` reads the experiment register
and decides whether Anvil's detection-model tier exists at all. Two experiments — advisory-permutation
ablation and a code-metrics baseline — can delete it entirely, turning Anvil into a deterministic scanner
with an LLM patcher, which the research judged a smaller, cheaper, possibly better system. Everything in
Phases 3–7 assumes the tier survives. **Do not let that gate be waved through**, and do not freeze the
record contract (`R.17`) until it resolves, because a kill decision deletes fields from the schema.

## Constraints that are not yours to change

- **Do not re-litigate `00-SPINE.md`.** If a worker's evidence genuinely contradicts it, the worker writes
  it to `## Conflicts With Spine` and **you** rule. Workers do not silently diverge, and neither do you.
- **Never delegate** coordination, synthesis, user communication, or anything destructive, credentialed,
  external, or approval-requiring.
- **Never hard-code trigger policy.** It is one of the owner's three hard constraints; policy is data.
- **Never auto-merge a patch.** Propose only. Best measured security-patch rate on real CVEs is 34.0%.
- **Only a DAST reproduction that now fails earns "verified fixed."** A clean SAST rescan does not.
- The **hard exclusion list** in spine §S5 is enforced, not advisory — CodeQL, Semgrep-maintained rules,
  `opengrep/opengrep-rules`, CIS content, Gemma 1–3 / Llama / StarCoder2 / MNPL weights, AFL++, and
  `code:` protocol Nuclei templates are all out, each for a documented reason.

## Two things to know about the evidence base

- `research/` (25 reports, 760 sourced rows) is **gitignored**. A fresh clone will not have it. The plan
  cites it heavily. Preserve it or you lose the justification for every decision.
- The plan **overturns its own research in three places** — build-vs-fork, the CVE-as-input premise, and
  the DAST model size. Those reversals are argued in the spine. If you find yourself reaching a
  conclusion the research supports but the spine contradicts, the spine already considered it.

## How to report

State plainly what completed, what failed, and what you skipped. If a phase is blocked, say so and say
why rather than working around it silently. If you hit the session cap, report which artifacts landed
before reporting which agents died — those are different questions and the second one misleads.
