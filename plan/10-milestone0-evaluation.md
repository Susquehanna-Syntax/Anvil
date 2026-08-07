# Anvil Implementation — Milestone 0: Evaluation Harness

## Overview

Milestone 0 runs before any component in `00-SPINE.md` S4 is treated as final — every pick there is
explicitly "provisional on S3." The corpus names twelve decisive experiments and assigns owners to none
(`research/14-critique-and-gaps.md` B7); two of them can delete the entire small-model detection tier
outright (S3.1, S3.2). This milestone builds one checked-in, machine-readable experiment register; runs
the two kill-criteria experiments plus the prefill-cost and patch-quality experiments plus the permanent
candidates-per-scan instrument and the encoder-RTT measurement; and schedules or explicitly defers the
remaining eight named experiments with a threshold each. The repo is greenfield (only `README.md` and
`.gitignore` exist), so M0 also creates the first real directory (`eval/`), which is a Python tree per the
S12 exception for "the evaluation harness," not part of the Go control plane.

## Dependency Summary

**Before M0.1 can run:** nothing beyond what already exists — `plan/00-SPINE.md`, `plan/00-ROUTING.md`,
and `plan/spine-b-open-licences.md` (for the CWE-Bench-Java licence citation) must be present, which they
are. No prior milestone, no prior code. M0 is the first milestone by construction (S3: "No component is
selected before it runs").

**What depends on M0:** every component pick in S4 is provisional until M0.18 (the kill-criteria decision)
resolves; specifically the SAST adjudicator pick (Qwen3.5-2B vs. deletion of Tier 3 entirely), the
candidates-per-scan budget that S2 says "determines feasibility," the Go-vs-Python control-plane boundary
at the encoder (S12's recorded counter-argument), and the coding-agent's claimed differentiator (S4's
"possibly better system" framing, tested by EXP-04). No Milestone 1 component-build packet may begin
before `eval/register.yaml`'s EXP-01 and EXP-02 rows carry a recorded decision.

## Steps

---

**Step ID:** M0.1
**Phase/group:** parallel group 1
**Depends on:** none
**Backend/model:** Claude Code subagent (haiku)
**Objective:** Author the experiment register schema and the initial `eval/register.yaml` file with all
fourteen rows (EXP-01…EXP-12, INSTR-01, S12-RTT) pre-filled from this document's `## Experiment Register
Schema` and `## Go/No-Go Decision Table` sections.
**Scope and files:**
- Read: this file (`plan/10-milestone0-evaluation.md`), `plan/00-SPINE.md`.
- Write: `eval/register.yaml`, `eval/schema/register.schema.json`.
**Forbidden actions:** Do not invent thresholds not present in this document. Do not mark any of the
twelve named experiments "not applicable" — every row must be `not_started` or `deferred`, never absent.
**Inputs/artifact refs:** `plan/10-milestone0-evaluation.md#Experiment-Register-Schema`,
`plan/10-milestone0-evaluation.md#GoNo-Go-Decision-Table`.
**Expected output schema:** valid YAML matching `eval/schema/register.schema.json`; 14 top-level entries
under `experiments:`.
**Validation/evidence required:** a schema-validation run (e.g. `python -c "import yaml,jsonschema..."`)
logged in the PR/commit description showing zero validation errors.
**Stop condition:** register file exists, validates against its own schema, and every one of the 14 IDs
from this document is present exactly once.
**Why this model:** mechanical transcription of already-fully-specified rows into a schema-conformant
file — "fastest worker: ... docs, mechanical edits, compact verification" (00-ROUTING.md Anthropic worker
routes table).

---

**Step ID:** M0.2
**Phase/group:** parallel group 1
**Depends on:** none
**Backend/model:** Claude Code subagent (sonnet)
**Objective:** Scaffold the Python evaluation-harness project (dependency manifest, package layout, test
runner) that every later M0 experiment step builds on.
**Scope and files:**
- Read: `plan/00-SPINE.md` S12 (Python-survives exception #3).
- Write: `eval/pyproject.toml`, `eval/src/anvil_eval/__init__.py`, `eval/tests/`, `eval/requirements.txt`
  (or lockfile), `eval/.gitignore` additions for model/data caches.
**Forbidden actions:** Do not add `mattn/go-sqlite3` or any cgo dependency (S12 explicitly says use
`modernc.org/sqlite` in the Go tree; this is irrelevant here but no Go code belongs in `eval/` at all — it
is a pure-Python tree by S12's own carve-out). Do not vendor any dataset or model weight in this step.
**Inputs/artifact refs:** none beyond the spine.
**Expected output schema:** an installable Python package (`pip install -e eval/`) with a passing
`pytest --collect-only`.
**Validation/evidence required:** `pip install -e eval/` succeeds; `pytest --collect-only` exits 0.
**Stop condition:** scaffold installs cleanly in a fresh virtualenv with no network access beyond the
package index.
**Why this model:** ordinary implementation scaffolding — "default strong worker: implementation, refactor
... most parallel work" (00-ROUTING.md).

---

**Step ID:** M0.3
**Phase/group:** parallel group 2
**Depends on:** M0.2
**Backend/model:** Claude Code subagent (sonnet)
**Objective:** Acquire PrimeVul and PrimeVul-Paired (MIT) and build the permuted-advisory dataset that
EXP-01 and EXP-02 both consume.
**Scope and files:**
- Read: `eval/src/anvil_eval/` (M0.2's scaffold).
- Write: `eval/data/primevul/**` (raw + processed), `eval/src/anvil_eval/data/primevul.py`.
**Forbidden actions:** Do not redistribute PrimeVul's raw files outside `eval/data/` (Google-Drive-gated
distribution per `research/03-detection-training-data-and-method.md` Gaps #1 — download once, do not
re-host). Do not use BigVul, Devign/CodeXGLUE, or DiverseVul as substitutes (licence-unverified or
no-licence per `research/03` Table 1).
**Inputs/artifact refs:** `research/03-detection-training-data-and-method.md` Table 1 (PrimeVul row: MIT,
Train 5,574/178,853, Test 695/25,216, paired 4,354/562/564).
**Expected output schema:** a loader producing `(advisory_text, code_chunk, label)` triples for the
unpaired test split and `(advisory_text, pre_patch_fn, post_patch_fn)` triples for the paired split, plus
a permutation utility that reassigns advisories across pairs.
**Validation/evidence required:** row counts logged and cross-checked against the published splits above
(695/25,216 unpaired test; 564 paired test pairs).
**Stop condition:** loader returns the exact published counts; permutation utility is deterministic given
a fixed seed.
**Why this model:** data-pipeline implementation with a licence-scoping constraint to enforce — sonnet
default strong worker (00-ROUTING.md).

---

**Step ID:** M0.4
**Phase/group:** parallel group 2
**Depends on:** M0.2
**Backend/model:** Claude Code subagent (sonnet)
**Objective:** Acquire an ARVO (BSD-2-Clause) subset and build the reproducer-wrapper pattern EXP-04 and
the future patch-validation harness will reuse.
**Scope and files:**
- Read: `eval/src/anvil_eval/`.
- Write: `eval/data/arvo/**`, `eval/src/anvil_eval/data/arvo.py`.
**Forbidden actions:** Do not cite `arxiv.org/abs/2606.17283` as a 2026 ARVO update — it is withdrawn
(`research/16-fuzzing-and-dynamic-analysis.md` S25); use the canonical 2024-08 paper (arXiv:2408.02153)
and the live `n132/ARVO` repo only. Do not pull the full 6,100+ case corpus — sample a bounded subset
(propose: 100–200 cases) to keep M0 within its own compute budget.
**Inputs/artifact refs:** `research/16-fuzzing-and-dynamic-analysis.md` (ARVO: BSD-2-Clause, 6,100+
vulns/311 projects, 81% reproducible, Docker `n132/arvo:<id>-vul`); `research/11-fix-validation-and-false-positives.md`
(OSS-Fuzz `reproduce` contract: `build_image` → `build_fuzzers --sanitizer <address|memory|undefined>` →
`reproduce <target> <testcase>`, `-timeout=65`, `-rss_limit_mb=2560`).
**Expected output schema:** for each sampled case: triggering input, canonical patch diff, and a
`reproduce()` function wrapping the documented Docker/OSS-Fuzz contract, returning crash/no-crash.
**Validation/evidence required:** reproduction rate on the sampled subset logged; expect close to the
published 81% (research/16) — if materially lower, flag in the step's notes, do not silently drop cases.
**Stop condition:** sampled subset reproduces at a rate the step records (whatever it is), with every case
carrying sanitizer + ASLR state recorded (research/11 finding: MSan/ASLR interaction causes false
"fixed" verdicts if unrecorded).
**Why this model:** licence-scoped data acquisition plus a non-trivial reproducibility contract — sonnet
default strong worker.

---

**Step ID:** M0.5
**Phase/group:** parallel group 2
**Depends on:** M0.2
**Backend/model:** Claude Code subagent (sonnet)
**Objective:** Acquire a CWE-Bench-Java (MIT, `iris-sast/cwe-bench-java`) subset for the Java arm of EXP-04.
**Scope and files:**
- Read: `eval/src/anvil_eval/`, `plan/spine-b-open-licences.md` (licence confirmation, section 7).
- Write: `eval/data/cwe-bench-java/**`, `eval/src/anvil_eval/data/cwe_bench_java.py`.
**Forbidden actions:** Do not use this corpus for anything beyond eval-use (per
`plan/spine-b-open-licences.md`'s scope note: "Eval-use does not trigger distribution obligations").
**Inputs/artifact refs:** `plan/spine-b-open-licences.md` section 7 (MIT, confirmed via raw LICENSE and
GitHub API).
**Expected output schema:** a loader mirroring M0.4's shape for Java cases.
**Validation/evidence required:** licence file re-fetched and hash-compared against the text already
quoted in `plan/spine-b-open-licences.md` section 7, to catch upstream relicensing.
**Stop condition:** loader produces at least one working end-to-end case (build, vulnerable-labelled
location, patch reference).
**Why this model:** data-pipeline implementation, disjoint write scope from M0.4 — sonnet default strong
worker.

---

**Step ID:** M0.6
**Phase/group:** parallel group 2
**Depends on:** M0.2
**Backend/model:** Claude Code subagent (sonnet)
**Objective:** Acquire and licence-verify the candidate detection models needed by EXP-01/02/03/S12-RTT:
`Qwen/Qwen3.5-2B`, a Gemma-4 variant, `HuggingFaceTB/SmolLM3-3B` (Tier-3 generative candidates), and
`microsoft/unixcoder-base` (Tier-2 encoder candidate), each as a quantised GGUF/ONNX artifact with a pinned
revision SHA.
**Scope and files:**
- Read: `plan/00-SPINE.md` S4 (Qwen3.5-2B pick, Gemma-4 caveat), S8 (compliance mechanics — pin exact
  revision SHAs, archive LICENSE at that revision).
- Write: `eval/models/**` (weights or pointers/checksums, not necessarily the raw weights themselves if
  large — a pinned-download manifest is acceptable), `eval/notes/model-licence-findings.md`.
**Forbidden actions:** Do not accept the Qwen3.5 family's licence tag at face value without confirming a
**text-only** variant exists — S4 flags Qwen3.5 as vision-language by default; carrying the vision tower
into an always-on detector inflates the resident footprint (14-critique M2). Do not accept the Gemma-4
family-level Apache-2.0 reversal (S4) as covering the *specific* variant downloaded — S4 is explicit that
Qwen (and by caution, other families) split licences by parameter count within one line; re-read the
LICENSE file for the exact revision pulled. Do not download any Gemma 1–3, Llama, StarCoder2, or
Mistral-MNPL weight (S5 hard exclusion).
**Inputs/artifact refs:** `research/02-small-detection-models.md` Table 1 & Table 2 (candidate roster,
licences, sizes); `research/14-critique-and-gaps.md` M2 (VLM footprint warning).
**Expected output schema:** `eval/notes/model-licence-findings.md` with one section per model: exact HF
revision SHA, licence text quote, whether it is confirmed text-only, and quantisation used.
**Validation/evidence required:** every licence claim traced to the model's own LICENSE file or HF API
`cardData.license` field fetched in-session, not recalled — per the corpus's own verification discipline
(research/02, research/14).
**Stop condition:** every one of the four models has a recorded revision SHA and a licence finding; any
model that turns out non-Apache-2.0/non-MIT for the pulled variant is flagged, not silently substituted.
**Why this model:** produces a licence conclusion — cross-family critique is mandatory for this class of
step per 00-ROUTING.md ("Any step that produces ... a licence conclusion must carry a critic step from a
different model family"); sonnet does the implementation, M0.8 supplies the critic.

---

**Step ID:** M0.7
**Phase/group:** parallel group 2
**Depends on:** M0.2
**Backend/model:** Claude Code subagent (sonnet)
**Objective:** Acquire the `opengrep` engine (LGPL-2.1) and `AikidoSec/opengrep-rules` (MIT) as the
deterministic recall-tier stand-in that INSTR-01 (candidates-per-scan) measures against.
**Scope and files:**
- Read: `plan/00-SPINE.md` S4 (source recall pick), S5 (hard exclusions — never `opengrep/opengrep-rules`,
  archived/NOASSERTION/Commons-Clause).
- Write: `eval/tools/opengrep/**` (pinned binary/build + pinned rules checkout).
**Forbidden actions:** Do not use `opengrep/opengrep-rules` (S5 hard exclusion: archived, NOASSERTION,
LGPL-2.1 + Commons Clause). Do not use any Semgrep-maintained ruleset (S5 hard exclusion: internal-business-use-only
licence).
**Inputs/artifact refs:** `research/14-critique-and-gaps.md` M6 (confirms `AikidoSec/opengrep-rules` MIT,
actively pushed; confirms the archived substitute is unusable).
**Expected output schema:** a runnable `opengrep --config <AikidoSec-rules-path> <target-dir>` invocation
wrapped in a Python subprocess call, pinned to a commit SHA for the ruleset (S7's supply-chain pinning
principle, applied here even though S7 states it for nuclei-templates specifically).
**Validation/evidence required:** a smoke run against any small sample repo returning a non-error exit
code and parseable output.
**Stop condition:** wrapper runs end-to-end and the ruleset commit SHA is recorded.
**Why this model:** tool integration with a licence-exclusion list to enforce — sonnet default strong
worker.

---

**Step ID:** M0.8
**Phase/group:** serial
**Depends on:** M0.6
**Backend/model:** OpenCode/OpenRouter route — `openai/gpt-oss-120b:free`
**Objective:** Independently review M0.6's licence findings for every acquired model, flagging any
unverified or misclassified licence before EXP-01/02/03/S12-RTT are allowed to depend on them.
**Scope and files:**
- Read: `eval/notes/model-licence-findings.md`, `plan/00-SPINE.md` S4/S5/S8.
- Write: `eval/notes/model-licence-critique.md`.
**Forbidden actions:** Do not re-run M0.6's downloads. Do not approve a licence finding that rests on a
GitHub/HF API `license` field alone without a quoted LICENSE-file excerpt (S8's compliance-mechanics
requirement: "reads LICENSE file bodies, never API metadata").
**Inputs/artifact refs:** `eval/notes/model-licence-findings.md` (M0.6 output).
**Expected output schema:** a pass/fail note per model with either concurrence or a named objection.
**Validation/evidence required:** every objection cites the specific missing or contradictory evidence.
**Stop condition:** every model in M0.6's output has a recorded critic verdict.
**Why this model:** cross-family critique rule — Anthropic-written (sonnet) licence conclusions must carry
an OpenCode/OpenRouter critic before acceptance (00-ROUTING.md, mandatory category: "a licence
conclusion").

---

**Step ID:** M0.9
**Phase/group:** parallel group 3
**Depends on:** M0.3, M0.6, M0.8
**Backend/model:** Claude Code subagent (sonnet)
**Objective:** Build and run EXP-01 (advisory-permutation ablation / Test 4) — the single most important
experiment in the project — against Qwen3.5-2B (primary) and Gemma-4 (secondary), measuring the
`EXHIBITS`→`DOES_NOT_EXHIBIT` flip rate when the wrong advisory is substituted.
**Scope and files:**
- Read: `eval/data/primevul/**` (M0.3), `eval/models/**` (M0.6, licence-cleared per M0.8).
- Write: `eval/harness/exp01_ablation.py`, `eval/results/EXP-01.json`.
**Forbidden actions:** Do not run this on any model whose licence M0.8 flagged as unresolved. Do not use
the unpaired split for this test — Test 4 is defined over PrimeVul-Paired (research/03). Do not report a
single aggregate flip rate without also reporting per-model breakdown (Qwen3.5-2B vs Gemma-4) — the two
candidates may diverge and that divergence is itself evidence for model selection.
**Inputs/artifact refs:** `research/03-detection-training-data-and-method.md` Evaluation-harness Table,
Test 4 row (metric: flip rate; bar: >80%); `plan/00-SPINE.md` S3.1 (>80% validates, <50% means CVE
ingestion is decoration).
**Expected output schema:** `EXP-01.json` = `{model: str, flip_rate: float, n_pairs: int, ci_95: [lo, hi],
per_cwe_breakdown: {...}}` for each candidate model.
**Validation/evidence required:** flip rate reported with a bootstrap 95% confidence interval (n_pairs is
only 564 for the paired test split — CI width matters at this sample size).
**Stop condition:** result recorded for both candidate models with confidence intervals; raw permutation
log retained for the critic step.
**Why this model:** implementation of the project's most consequential eval script — sonnet default
strong worker, escalated to a critic in M0.10 given the stakes (00-ROUTING.md: "escalate only genuinely
ambiguous architecture to opus" — this is implementation, not architecture, so sonnet + critic, not opus).

---

**Step ID:** M0.10
**Phase/group:** parallel group 3
**Depends on:** M0.3, M0.6, M0.8
**Backend/model:** Claude Code subagent (sonnet)
**Objective:** Build and run EXP-02 (code-metrics logistic-regression baseline) on the same PrimeVul splits
EXP-01 uses, and compare its Test-1 (P-C) and Test-2 (precision at recall 0.70) scores head-to-head against
the small model's.
**Scope and files:**
- Read: `eval/data/primevul/**`, `eval/models/**`.
- Write: `eval/harness/exp02_metrics_baseline.py`, `eval/results/EXP-02.json`.
**Forbidden actions:** Do not train the logistic regression on the paired test split used for evaluation
(no leakage). Do not balance the training set — research/03 and research/14 (S14 citation) both identify
balanced-training as the specific failure mode that produces false confidence.
**Inputs/artifact refs:** `research/02-small-detection-models.md` finding B / S3 (arXiv:2509.19117: "a
classifier trained solely on these metrics performs on par with state-of-the-art LLMs for vulnerability
discovery," causal not just correlational); `plan/00-SPINE.md` S3.2; `research/03` Table under
"Evaluation harness" (Test 1: P-C > 25% bar, reference GPT-4 CoT 12.94%; Test 2: F1 > 5.22% flag-everything
bar, reference best fine-tune 5.82%).
**Expected output schema:** `EXP-02.json` = `{metrics_used: [...], lr_test1_pc: float, lr_test2_f1: float,
lr_test2_precision_at_recall70: float, model_test1_pc: float (from EXP-01's model), model_test2_*: float}`
plus bootstrap CIs for both arms.
**Validation/evidence required:** the same metric definitions and same held-out split as EXP-01/the
model's own eval, so the comparison is apples-to-apples.
**Stop condition:** both arms scored on identical data with CIs; raw feature list (cyclomatic complexity,
LoC, nesting depth, etc.) recorded for reproducibility.
**Why this model:** implementation of the second kill-criterion experiment — sonnet default strong worker,
escalated to a critic in M0.13.

---

**Step ID:** M0.11
**Phase/group:** parallel group 3
**Depends on:** M0.6
**Backend/model:** Claude Code subagent (sonnet)
**Objective:** Run EXP-03 — `llama-bench` prefill sweep for each candidate model at realistic pair-prompt
length (~2,000 tokens: ~800 advisory/CWE text + ~1,000 code chunk + ~200 instruction) on whatever hardware
tier is actually available for this run, and record it against the S9 tier it represents.
**Scope and files:**
- Read: `eval/models/**`.
- Write: `eval/harness/exp03_llama_bench.py`, `eval/results/EXP-03.json`.
**Forbidden actions:** Do not report generation throughput as the headline number — Anvil is prefill-bound
(research/02 S8, research/14 B1). Do not extrapolate from a different model family's measured numbers in
place of an actual run — the entire point of this experiment is that no Qwen3.5/Gemma-4 CPU throughput
number has been measured anywhere in the corpus (research/02 Gaps).
**Inputs/artifact refs:** `research/02-small-detection-models.md` S8 (Malakhov CEUR-WS Table 1: 256-token
prompt costs 1.5s on Xeon Platinum 8480+ for a 7B model, ≈170 tok/s prefill measured); `research/14-critique-and-gaps.md`
B1 (scaled estimate: ~600 tok/s for a ~2B model by parameter ratio; the "2,000 tok/s" figure used elsewhere
is explicitly "a 3.3× gift to the design").
**Expected output schema:** `EXP-03.json` = `{model: str, hardware_tier: "S"|"M"|"L", cores: int,
prompt_tokens: 2000, prefill_tok_per_s: float, gen_tok_per_s: float}` per model × available tier.
**Validation/evidence required:** raw `llama-bench` output log attached; quantisation level (Q4_K_M or
whatever was used) recorded, since the corpus's own <1% quality-loss claim for Q4 is itself flagged
unverified for Anvil's exact task (research/02 Risks).
**Stop condition:** at least one real measured prefill number exists per candidate model on at least one
available hardware tier.
**Why this model:** benchmark execution and interpretation against a stated threshold — sonnet default
strong worker (build/quantisation judgment calls take this past a pure mechanical-verification haiku task).

---

**Step ID:** M0.12
**Phase/group:** serial
**Depends on:** M0.9
**Backend/model:** OpenCode/OpenRouter route — `qwen/qwen3-coder:free`
**Objective:** Independently review EXP-01's harness code and result for methodology soundness (no data
leakage, correct permutation logic, correct flip-rate definition) before its result is entered into the
register as a kill-criterion input.
**Scope and files:**
- Read: `eval/harness/exp01_ablation.py`, `eval/results/EXP-01.json`, `research/03-detection-training-data-and-method.md`.
- Write: `eval/notes/EXP-01-critique.md`.
**Forbidden actions:** Do not re-run the harness with different parameters — this is a code/methodology
review, not a re-experiment. Do not approve if the permutation swaps advisories *within* the same CWE
class only (that would understate the true flip rate and bias toward false PASS).
**Inputs/artifact refs:** `eval/harness/exp01_ablation.py`, `eval/results/EXP-01.json`.
**Expected output schema:** pass/fail verdict with specific line-level objections if any.
**Validation/evidence required:** explicit confirmation the permutation is drawn from the full advisory
pool, not a CWE-matched subset.
**Stop condition:** verdict recorded; if fail, M0.9 is rerouted once per 00-ROUTING.md's rerouting policy
before the register is updated.
**Why this model:** cross-family critique rule, mandatory given this experiment's stakes and given
00-ROUTING.md's general rule that "Anthropic-written code and plans get an OpenCode/OpenRouter critic";
`qwen/qwen3-coder:free` is the routing table's "default coding / technical scout" for exactly this kind of
code-methodology review.

---

**Step ID:** M0.13
**Phase/group:** serial
**Depends on:** M0.10
**Backend/model:** OpenCode/OpenRouter route — `qwen/qwen3-coder:free`
**Objective:** Independently review EXP-02's harness code and result for methodology soundness (no
leakage between LR training and eval split, no balanced-training artifact, identical metric definitions to
EXP-01's model arm).
**Scope and files:**
- Read: `eval/harness/exp02_metrics_baseline.py`, `eval/results/EXP-02.json`.
- Write: `eval/notes/EXP-02-critique.md`.
**Forbidden actions:** Do not approve a result where the LR was trained on a class-balanced resample of
PrimeVul — research/03's Gaps section names this exact failure mode ([S14]'s 0.09-precision catastrophe).
**Inputs/artifact refs:** `eval/harness/exp02_metrics_baseline.py`, `eval/results/EXP-02.json`.
**Expected output schema:** pass/fail verdict with specific objections if any.
**Validation/evidence required:** explicit confirmation the LR's training prevalence matches the deployed
prevalence assumption, not an artificially balanced one.
**Stop condition:** verdict recorded.
**Why this model:** cross-family critique rule, same justification as M0.12 — this is the second
kill-criterion experiment and deserves the same scrutiny.

---

**Step ID:** M0.14
**Phase/group:** parallel group 4
**Depends on:** M0.2, M0.7
**Backend/model:** Claude Code subagent (sonnet)
**Objective:** Build and run INSTR-01 — the candidates-per-scan instrument (S2) — using M0.7's opengrep +
AikidoSec/opengrep-rules stand-in against a fixed sample corpus, producing the first real
candidates-emitted-per-scan and per-push measurements.
**Scope and files:**
- Read: `eval/tools/opengrep/**`.
- Write: `eval/harness/instr01_candidates.py`, `eval/results/INSTR-01.json`.
**Forbidden actions:** This is *instrumentation*, not a one-off experiment — do not write it as a
throwaway script; it must be re-runnable against arbitrary target repos, because S2 says "instrument it on
day one" as a permanent measurement, not a single M0 data point.
**Inputs/artifact refs:** `plan/00-SPINE.md` S2 (thresholds: <500/full scan and <50/push → ~17 min and
~2 min model-tier cost; "in the thousands" → re-scope).
**Expected output schema:** `INSTR-01.json` = `{target_repo: str, candidates_full_scan: int,
candidates_per_push: int, ruleset_commit: str}` for each sample repo used.
**Validation/evidence required:** run against at least 3 structurally different sample repos (e.g. small
CLI tool, a web-app-shaped repo, a library) so the count is not an artifact of one repo's shape.
**Stop condition:** counts recorded for all sample repos; instrument is callable as a standalone function,
not just a notebook cell.
**Why this model:** builds a permanent, reusable instrument with real engineering surface — sonnet default
strong worker.

---

**Step ID:** M0.15
**Phase/group:** parallel group 4
**Depends on:** M0.2, M0.6
**Backend/model:** Claude Code subagent (sonnet)
**Objective:** Build and measure S12-RTT — the encoder HTTP round-trip time under realistic pair volume —
per spine S12's recorded counter-argument, to be checked before the Go-vs-Python control-plane boundary is
irreversible.
**Scope and files:**
- Read: `eval/models/**` (the Tier-2 encoder candidate, `microsoft/unixcoder-base`, served via ONNX
  Runtime per S12 exception #1).
- Write: `eval/harness/s12_rtt.py`, `eval/results/S12-RTT.json`.
**Forbidden actions:** Do not measure the encoder in-process — the whole point is to measure the HTTP
round-trip of the S12-mandated separate-process architecture ("a separate always-on process addressed over
HTTP, never an in-process library call"). Do not use a toy pair count — measure at "thousands of
advisory×code-chunk pairs per scan," per S12's own framing.
**Inputs/artifact refs:** `plan/00-SPINE.md` S12 (the exact sentence: "if the encoder HTTP round-trip
dominates latency at real scan volume ... then collapsing encoder and orchestrator into one process
becomes attractive ... Measure encoder RTT under realistic pair volume during Milestone 0 before this is
irreversible").
**Expected output schema:** `S12-RTT.json` = `{pair_count: int, total_rtt_seconds: float,
rtt_per_pair_ms: float, in_process_baseline_ms: float|null}`.
**Validation/evidence required:** pair count used and its relationship to INSTR-01's measured
candidates-per-scan explicitly stated, so the overhead-fraction calculation in the Go/No-Go table is
traceable.
**Stop condition:** RTT measured at a pair count that is at least as large as INSTR-01's measured
candidates-per-scan for the sample repos used.
**Why this model:** stands up a real HTTP service and measures it under load — sonnet default strong
worker.

---

**Step ID:** M0.16
**Phase/group:** parallel group 4
**Depends on:** M0.4, M0.5, M0.6, M0.8
**Backend/model:** Claude Code subagent (sonnet)
**Objective:** Build and run EXP-04 — open-weight (Qwen3-Coder-Next) patch quality on the sampled ARVO and
CWE-Bench-Java subsets, using the AutoPatchBench-style three-stage validation gate and ARVO's
`reproduce()` contract, and record the verified-fix rate against published frontier reference points
(taken from the literature, not re-run — Anvil does not call paid frontier APIs).
**Scope and files:**
- Read: `eval/data/arvo/**`, `eval/data/cwe-bench-java/**`, `eval/models/**` (Qwen3-Coder-Next).
- Write: `eval/harness/exp04_patch_quality.py`, `eval/results/EXP-04.json`.
**Forbidden actions:** Do not call a proprietary frontier API (OpenAI/Anthropic/Google) as the comparison
arm — S0 requires self-hosted open-weight models only; frontier numbers come from the published references
below, not a live re-run. Do not skip the exploit-oracle gate (research/11 gate 9) and count a patch as
"fixed" on test-suite-pass alone — research/11's Vul4J finding is that 10.3% of patches pass tests while
remaining exploitable.
**Inputs/artifact refs:** `research/11-fix-validation-and-false-positives.md` (AutoPatchBench: Gemini 1.5
Pro 61.1% generation / 5.3% fully-verified; three-stage gate: crash-input no longer crashes → 10-minute
fuzz survival → differential behaviour check; OSS-Fuzz `reproduce` contract); `research/16-fuzzing-and-dynamic-analysis.md`
S18 (DARPA AIxCC: 68% of synthetic vulnerabilities patched, ~$152/task average); `plan/00-SPINE.md` S7
("Best measured security-patch rate on real CVEs is 34.0%").
**Expected output schema:** `EXP-04.json` = `{corpus: "arvo"|"cwe-bench-java", n_cases: int,
generation_success_rate: float, verified_fix_rate: float, gate_failure_breakdown: {compile_fail: int,
test_fail: int, exploit_still_triggers: int, deceptive_pass: int}}`.
**Validation/evidence required:** every "verified" case has a recorded exploit-oracle re-execution, per
research/11's gate 9 — an upstream "fixed" label is never trusted as ground truth (research/11 finding:
ARVO found 300+ falsely-patched still-active vulnerabilities in OSS-Fuzz's own "fixed" set).
**Stop condition:** verified-fix rate recorded per corpus with the full gate-failure breakdown, not just
an aggregate percentage.
**Why this model:** implementation of a multi-stage validation harness against an external published
comparison — sonnet default strong worker.

---

**Step ID:** M0.17
**Phase/group:** serial
**Depends on:** M0.9, M0.10, M0.11, M0.12, M0.13, M0.14, M0.15, M0.16
**Backend/model:** Claude Code subagent (haiku)
**Objective:** Aggregate all completed experiment/instrument results into `eval/register.yaml` and author
the deferred specs for EXP-05 through EXP-12 (threshold + deferral reason + owning future phase, all
already defined in this document's Go/No-Go table) as `status: deferred` rows.
**Scope and files:**
- Read: `eval/results/*.json`, `eval/notes/*-critique.md`, this document's `## Go/No-Go Decision Table`.
- Write: `eval/register.yaml` (update, not recreate).
**Forbidden actions:** Do not mark any deferred row `not_started` — they must be `deferred` with a
`deferred_reason` and `owning_future_phase` populated. Do not compute a PASS/FAIL/AMBIGUOUS `decision`
field for EXP-01 or EXP-02 yourself — that determination belongs to M0.18 (orchestrator-inline); this step
only transcribes measured `result` values and each critic's verdict.
**Inputs/artifact refs:** all `eval/results/*.json` files, all `eval/notes/*-critique.md` files, this
document's `## Go/No-Go Decision Table` (source of the eight deferred rows' thresholds).
**Expected output schema:** `eval/register.yaml` with all 14 rows carrying either a `result` +
critic-reviewed status (for the 6 executed items: EXP-01, EXP-02, EXP-03, EXP-04, INSTR-01, S12-RTT) or a
`deferred` status with reason and owning phase (for EXP-05…EXP-12).
**Validation/evidence required:** schema re-validation against `eval/schema/register.schema.json`.
**Stop condition:** all 14 rows populated; file validates.
**Why this model:** mechanical aggregation/transcription of already-computed values and already-defined
deferred specs — haiku, "docs, mechanical edits, compact verification" (00-ROUTING.md).

---

**Step ID:** M0.18
**Phase/group:** serial
**Depends on:** M0.17
**Backend/model:** orchestrator-inline
**Objective:** Read the completed register's EXP-01 and EXP-02 rows (the two kill-criteria experiments)
plus EXP-03/INSTR-01 as supporting feasibility context, and record the milestone-defining decision: proceed
to Milestone 1 component-build work with the three-tier detection design intact, or delete the small-model
detection tier from the plan and re-scope Anvil as a deterministic scanner (Lane A SCA/host + Lane B
opengrep recall) with an LLM patcher, per `plan/00-SPINE.md` S3.
**Scope and files:**
- Read: `eval/register.yaml`.
- Write: `eval/register.yaml` (`decision` fields for EXP-01, EXP-02), a short decision record appended to
  the register or as `eval/DECISION-M0.md`.
**Forbidden actions:** none beyond the standing rule that this decision is not delegable to a worker
(00-ROUTING.md: "own[s] task framing, final synthesis, side effects, user communication, and conflict
resolution, and never delegates them").
**Inputs/artifact refs:** `eval/register.yaml`, `plan/10-milestone0-evaluation.md#GoNo-Go-Decision-Table`.
**Expected output schema:** a recorded decision with the exact numeric results cited and the resulting
architecture action stated in one paragraph.
**Validation/evidence required:** the decision must cite the actual measured flip rate (EXP-01) and the
actual LR-vs-model comparison (EXP-02), not a qualitative impression.
**Stop condition:** decision recorded; if the tier is deleted, this step also flags every downstream S4
row that named the small model (SAST adjudicator, DAST model) as requiring re-scoping before Milestone 1
starts.
**Why this model:** final synthesis and architecture-affecting conflict resolution — reserved to the
orchestrator, never delegated (00-ROUTING.md).

---

## Experiment Register Schema

`eval/register.yaml`, one entry per experiment or instrument, versioned:

```yaml
version: 1
experiments:
  - id: string                # "EXP-01".."EXP-12", "INSTR-01", "S12-RTT" — stable, never reused
    name: string               # short human title
    kind: enum[experiment, instrumentation]
    spine_ref: string          # e.g. "S3.1", "S2", "S12"
    source_ref: string         # research file + section that named this experiment
    owner_step: string         # the M0.x step ID that builds/runs it, or "deferred"
    status: enum[not_started, in_progress, blocked, complete, deferred]
    decision_gated: string     # free text: what this outcome decides
    corpus:
      - name: string
        licence: string
        licence_ref: string    # file + section confirming the licence
    method: string              # short description of the procedure
    metric: string               # what is measured
    threshold_pass: string
    threshold_fail: string
    reference_baseline: string   # "file#figure" citation, or "PROPOSED — no published baseline"
    result:
      value: number|null
      unit: string|null
      measured_at: date|null
      artifact_path: string|null   # eval/results/<id>.json
    decision: enum[PASS, FAIL, AMBIGUOUS, DEFERRED, null]
    depends_on: [string]
    deferred_reason: string|null
    owning_future_phase: string|null
```

`decision` is only ever set by an orchestrator-inline step (M0.18 for EXP-01/EXP-02; future
orchestrator-inline steps for the rest), never by a worker packet — workers populate `result` and leave
`decision: null` for the orchestrator to fill.

## Go/No-Go Decision Table

| Experiment | Threshold | If PASS | If FAIL |
|---|---|---|---|
| **EXP-01** Advisory-permutation ablation (Test 4) | Flip rate on PrimeVul-Paired: **>80% PASS**, **<50% FAIL** (`plan/00-SPINE.md` S3.1; `research/03-detection-training-data-and-method.md` Test 4 row). 50–80% is ambiguous — PROPOSED handling: run the QLoRA runner-up (research/03) before a final call. | Advisory-conditioning is real; proceed with the three-tier design (research/02) using this candidate model. | **Kill criterion #1.** CVE ingestion is decoration (S3.1). Delete advisory-text conditioning from the SAST adjudicator's design; restrict advisory text to the narrow vendored/backported-code scope only (S1 corrected requirement #8; `research/14-critique-and-gaps.md` B2 fix), and re-evaluate whether Tier 3 should exist at all pending EXP-02. |
| **EXP-02** Code-metrics logistic-regression baseline | PROPOSED — no published Anvil-specific equivalence margin exists. Comparative test: LR's Test-1 P-C and Test-2 precision-at-recall-0.70 fall within/exceed the small model's 95% CI (`research/02-small-detection-models.md` S3, arXiv:2509.19117; `plan/00-SPINE.md` S3.2). | LR is significantly worse than the model on both metrics (non-overlapping CIs, LR lower) → the model tier is justified. | **Kill criterion #2.** The model tier does not exist (S3.2). Delete Tier 3 (small-model adjudicator) entirely; ship Tier 1 (deterministic pre-filter) + optional Tier 2 (encoder ranker or the LR itself) only (`research/02` three-tier design, demoted to two). |
| **EXP-03** `llama-bench` prefill on real hardware | PROPOSED, informed by published scaling: PASS if measured prefill ≥ **600 tok/s** on Tier-S hardware for the ~2B candidate (the non-generous parameter-scaled estimate; `research/14-critique-and-gaps.md` B1, scaling `research/02` S8's measured 170 tok/s@7B). | Every downstream compute claim (S2's ~17 min/~2 min budget, S9's tier assignments) stands as written. | Re-derive the candidates-per-scan ceiling from INSTR-01's measured count against the *actual* throughput; if the recomputed wall-clock exceeds S2's budget, drop to `Qwen3.5-0.8B`, move Tier-3 to the encoder-only ranker (research/02's flip condition #2), or raise the minimum hardware tier for the detection path. |
| **INSTR-01** Candidates-per-scan (permanent instrument, not a kill gate) | <500/full scan and <50/push (`plan/00-SPINE.md` S2, exact figures) → model tier costs ~17 min/~2 min. "In the thousands" → design does not work. | Affordability confirmed at current recall-tier tuning; carry the measured count into Milestone 1's scheduler design. | Re-scope the recall tier: narrower rules, CWE-class routing, or tighter version-range matching (`research/14-critique-and-gaps.md` B1 "Suggested fix") before Milestone 1 proceeds. |
| **S12-RTT** Encoder HTTP round-trip under realistic pair volume | PROPOSED — spine explicitly calls this "a cost never measured" (`plan/00-SPINE.md` S12). Decision rule: flag if aggregate encoder overhead exceeds **20%** (proposed) of the per-scan model-tier wall clock established by EXP-03 × INSTR-01's candidate count. | S12's Go-for-control-plane pick is confirmed; no action needed. | Record as a **Conflict With Spine** item (see below) for the orchestrator: collapsing encoder and orchestrator into one Python process becomes the stronger pick per S12's own stated counter-argument. |
| **EXP-04** Open-weight vs. frontier patch quality (ARVO / CWE-Bench-Java) | PROPOSED: ≥5% verified-fix rate on ARVO (matching/exceeding Gemini 1.5 Pro's AutoPatchBench-verified 5.3%, `research/11-fix-validation-and-false-positives.md` S7) as the pass bar; <2% as the fail bar. | Supports the "possibly better system" / central-differentiator framing (S3); no redesign forced — S7's never-auto-merge posture already assumes a low verified-fix rate. | Coding-agent tier needs a larger/different open-weight model, or the differentiator claim in project messaging should be revised; does not by itself change the safety posture (S7 already mandates human review regardless of rate). |
| **EXP-05** Batch-size vs. validated-fix-rate curve | PROPOSED — no published baseline; qualitative floor from `research/11` S22 (curl bounty confirmation rate fell <5% once noise ratio inverted; ~15% was the pre-slop baseline) and gate 16's default (≤3 open PRs/repo). | Batch size tuned to keep PR acceptance rate near the ~15% pre-slop order of magnitude. | Reduce batch size / rate limit further. |
| **EXP-06** SAST↔DAST correlation precision/recall | PROPOSED — no published baseline; success criterion to be defined against a seeded corpus once S6's schema exists. | Correlation is trustworthy; keep `correlationGuid`-based design (S6). | Correlation cannot be trusted as designed; treat SAST and DAST as independently-sealed halves with no automatic linkage claim (already the S6/B3 fallback). |
| **EXP-07** Static route extraction vs. runtime spec probe | PROPOSED — report numerator + provenance mix, not a coverage percentage (`research/14-critique-and-gaps.md` m6). | S4's declared ordering (runtime probe → repo specs → static extraction → browser crawl last) stands. | Reorder or drop the weakest-evidenced stage. |
| **EXP-08** Grammar-constrained DAST confirmation eval | PROPOSED, informed by `research/14-critique-and-gaps.md` M1's "same-size-or-smaller" verdict (5 branches against the 9B pick, 2 of them survivor-biased/self-reported). | A 2–4B model matches the disputed 9B pick under grammar-constrained tool calling. | Keep the DAST model at the same size as the SAST model and scale turn budget/context instead of parameters (M1's fix). |
| **EXP-09** `runsc` vs. `runc` overhead | PROPOSED — no published Anvil-specific number. | gVisor overhead fits within Tier-M's 32 GB/8-core budget (S9). | Narrow gVisor to only the highest-risk boundary, or raise the DAST-enabled hardware floor. |
| **EXP-10** ZAP JVM RSS under a representative full scan | PROPOSED, informed by `research/14-critique-and-gaps.md` C12 (ZAP footprint "unquantified," the 10-minute `docker stats` measurement is the proposed method). | ZAP's measured RSS fits the opt-in DAST tier budget (S9). | Confirms S9's existing default ("do not run ZAP always-on"); no redesign needed, just confirmation. |
| **EXP-11** Task cards vs. raw SARIF (branch 18's "highest-value early A/B test") | PROPOSED — A/B compare coding-agent fix-success rate on task cards vs. raw SARIF excerpts, reusing EXP-04's ARVO/CWE-Bench-Java subset. | Task-card format is worth its own schema slot in S6. | Feed raw SARIF excerpts directly; drop the task-card abstraction layer. |
| **EXP-12** `llama-server` LoRA hot-swap | PROPOSED — entirely contingent on EXP-01/EXP-02 justifying training adapters at all (S3/S4: "Not vLLM in v1 ... requires fine-tuned adapters that must not exist before S3"). | Only relevant if a later milestone trains adapters; measure hot-swap latency vs. static loading then. | Not applicable while v1 ships zero-training (research/03 primary recommendation). |

## Exit Criteria

- `eval/register.yaml` exists, is checked into git, validates against `eval/schema/register.schema.json`,
  and contains exactly 14 rows: EXP-01…EXP-12, INSTR-01, S12-RTT.
- EXP-01, EXP-02, EXP-03, EXP-04, INSTR-01, and S12-RTT each have `status: complete`, a populated `result`,
  a recorded critic verdict where one was required (EXP-01, EXP-02, and the licence findings feeding all
  of them), and an `artifact_path` pointing at a real `eval/results/*.json` file.
- EXP-05 through EXP-12 each have `status: deferred`, a non-null `deferred_reason`, and a non-null
  `owning_future_phase`.
- Every `threshold_pass`/`threshold_fail` in the register either cites a research file + figure or is the
  literal string `"PROPOSED — no published baseline"`.
- M0.18's decision is recorded with the exact EXP-01 flip rate and EXP-02 comparison result quoted, and, if
  the tier was killed, a list of every S4 row that must be re-scoped before Milestone 1 starts.
- No Milestone-1 component-selection packet has been dispatched before M0.18's decision is recorded.

## Pinned Versions And Licences

| Artifact | Pin | Licence | Why |
|---|---|---|---|
| PrimeVul / PrimeVul-Paired | dataset snapshot as of acquisition date, recorded in `eval/data/primevul/MANIFEST` | MIT (`research/03` S2) | EXP-01, EXP-02 corpus |
| ARVO | `n132/ARVO` repo commit SHA + specific `n132/arvo:<id>-vul` Docker tags used | BSD-2-Clause (`research/16` S2/S25) | EXP-04 corpus + patch-validation pattern. Note: cite only the canonical 2024-08 paper (arXiv:2408.02153); the 2026 posting is withdrawn. |
| CWE-Bench-Java | `iris-sast/cwe-bench-java` commit SHA | MIT (`plan/spine-b-open-licences.md` §7) | EXP-04 Java corpus |
| `AikidoSec/opengrep-rules` | pinned commit SHA, diffed before any future promotion | MIT (`research/14` M6) | INSTR-01 recall-tier stand-in |
| `opengrep` engine | pinned release version | LGPL-2.1 (`plan/00-SPINE.md` S4) | INSTR-01 tool (subprocess invocation only) |
| `Qwen/Qwen3.5-2B` | exact HF revision SHA, archived LICENSE at that revision (S8) | Apache-2.0 — **pending text-only-variant confirmation** (M0.6/M0.8) | EXP-01, EXP-02, EXP-03 primary candidate |
| Gemma-4 (specific variant TBD) | exact HF revision SHA | Apache-2.0 **for the specific variant only** — re-verify per-variant, do not infer from the family-level reversal (`plan/00-SPINE.md` S4 caveat) | EXP-01, EXP-03 secondary candidate |
| `HuggingFaceTB/SmolLM3-3B` | exact HF revision SHA | Apache-2.0 (`research/02` S13) | EXP-03 auditability runner-up |
| `microsoft/unixcoder-base` | exact HF revision SHA | Apache-2.0 weights / MIT repo (`research/02` S18) | Tier-2 encoder candidate, S12-RTT |
| `Qwen/Qwen3-Coder-Next` | exact HF revision SHA | Apache-2.0 (verified `research/14` "Held up exactly" table: 79.7B params, 512 experts, 10 active) | EXP-04 coding-agent arm |
| `llama-bench` (ggml-org/llama.cpp) | pinned release tag | MIT | EXP-03 measurement tool |
| ONNX Runtime | pinned release version | MIT | S12-RTT encoder worker |

## Open Questions

- **EXP-01's 50–80% ambiguous band** has no published guidance beyond a directional lean toward training
  (`research/03`'s "what would flip this decision"). M0.18's orchestrator must set an explicit escalation
  policy for this band before it can occur in practice.
- **EXP-02's equivalence margin is PROPOSED, not sourced.** No paper defines "matches" numerically for
  Anvil's exact task; the bootstrap-CI-overlap rule in this document is an engineering judgment call, not
  a citation. Confirm the statistical protocol (sample size, CI method) before EXP-02 runs.
- **PrimeVul's Google-Drive-gated distribution** (`research/03` Gaps #1) — a one-time offline acquisition
  during M0.3 should be fine for an internal eval corpus, but if Anvil's CI needs to re-fetch it
  automatically later, the gating needs a resolution (mirror, or accept manual refresh).
- **EXP-04's PASS/FAIL thresholds (≥5% / <2%) are PROPOSED**, derived by analogy to AutoPatchBench's
  Gemini 1.5 Pro figure, not a number anyone has published for Qwen3-Coder-Next specifically. Needs
  explicit sign-off before it drives any messaging claim.
- **BenchVul/TitanVul** (`research/03` S12) is the strongest available out-of-distribution eval corpus but
  its licence is unverified — excluded from this milestone's corpus list per the task's licence-clean
  constraint. If its licence clears later, "Test 3" (OOD generalisation, balanced accuracy > 0.50 bar,
  reference: BigVul-trained model at 0.493) could be added as a thirteenth experiment.
- **Hardware availability for EXP-04.** Qwen3-Coder-Next is RAM-bound (~80B MoE, S4) and S9 marks the
  coding agent "remote" for Tier S/M. M0.16 needs either Tier-L local hardware or a self-hosted remote
  deployment of the same open-weight model — never a proprietary API substitute (S0).

## Conflicts With Spine

None identified that require re-litigating `00-SPINE.md`. One item is flagged for the orchestrator's
attention rather than treated as settled: if **S12-RTT** (see Go/No-Go table) measures encoder overhead
above the proposed 20% threshold, that is not a defect in this plan — it is the exact scenario S12 itself
names as the condition under which "Python becomes the stronger pick" for the control plane. This
milestone does not resolve that question; it only produces the number S12 asks for. The resulting decision
belongs to whichever future step owns S12, not to M0.
