# Anvil Implementation — Lane B: Source Detection And Model Serving

## Overview

Lane B turns first-party source code into adjudicated findings without ever pairing every advisory
against every code unit — the N×M cross product spine S1 forbids and research/10's R1 quantifies at up
to 4.6 CPU-days per full repo scan. A deterministic opengrep + AikidoSec-rules pass (Tier 1) owns recall
at near-zero cost and produces a short, pre-localized candidate list; an optional ONNX INT8 encoder
(Tier 2) may re-rank that list, shipped only if it measurably beats a code-metrics baseline; a small
instruction model (Tier 3) adjudicates each surviving candidate against its rule/CWE context into
`{EXHIBITS, DOES_NOT_EXHIBIT, INSUFFICIENT_CONTEXT}` plus evidence sentences. Every accuracy or
ranker-value claim in this plan is gated on Milestone 0 (spine S3) — nothing here is selected before the
harness runs. Serving is llama-server plus a separate Python ONNX HTTP worker, entirely config-driven,
with `--mlock` on the always-resident detection tier and KL-divergence-validated quantisation.

## Dependency Summary

| Step | Depends on | Group |
|---|---|---|
| B.1 | none | parallel group 1 |
| B.2 | none | parallel group 1 |
| B.3 | none | parallel group 1 |
| B.4 | none | parallel group 1 |
| B.5 | none | parallel group 1 |
| B.9 | none | parallel group 1 |
| B.6 | B.1, B.2 | parallel group 2 |
| B.7 | B.3, B.4 | parallel group 2 |
| B.8 | B.5 | parallel group 2 |
| B.10 | B.7 | parallel group 3 |
| B.11 | B.9, B.7 | parallel group 3 |
| B.12 | B.10, B.6, B.11 | parallel group 4 |
| B.13 | B.8, B.10 | parallel group 4 |
| B.14 | B.1, B.2, B.4, B.6, B.12, B.13 | serial |
| B.15 | B.6, B.7, B.8, B.9, B.10, B.11, B.12, B.13, B.14 | serial |

Six independent streams (B.1, B.2, B.3, B.4, B.5, B.9) build Tier 1's engine, Tier 1's ruleset, the
Milestone 0 harness, the Tier 3 candidate/licence matrix, the serving scaffold, and the Tier 2 worker with
disjoint file scopes. Group 2 turns those into a candidate schema, executed gating results, and a validated
quant. Group 3 builds the adjudicator contract and the Tier 2 ship/no-ship decision, both gated on group 2's
Milestone 0 results. Group 4 wires the pipeline and deploys serving. B.14 is a mandatory cross-family
critique of every licence and security-relevant conclusion; B.15 verifies the whole lane against this
document's own contract and exit criteria.

## Steps

```text
Step ID:          B.1
Phase/group:      parallel group 1
Depends on:       none
Backend/model:    Claude Code subagent (sonnet)
Objective:        Implement a Go subprocess wrapper that invokes the opengrep CLI binary as an external
                   process (never linked, never called via bindings) against a target repository and
                   parses its native JSON output into an internal finding struct.
Scope and files:  WRITE internal/detect/opengrep/client.go, internal/detect/opengrep/parse.go,
                   internal/detect/opengrep/client_test.go. READ: this plan file, spine S12.
Forbidden actions: No cgo. No in-process linking of the opengrep OCaml library — opengrep has zero
                   bindings in any language (spine S12), subprocess is the only option. No invocation of
                   opengrep/opengrep-rules (archived) or any Semgrep-maintained rules. No network calls.
                   No writes outside the listed scope.
Inputs/artifact refs: opengrep CLI (opengrep/opengrep, LGPL-2.1, research/10 Table 1) binary path from
                   config; a target repo path.
Expected output schema: Go struct `RawFinding{RuleID, Path, StartLine, EndLine, Message, Severity,
                   Metadata map[string]string}` per opengrep JSON result; `Run(ctx, repoPath,
                   rulesetPath) ([]RawFinding, error)`; correct handling of opengrep's nonzero exit code
                   on findings-present (not an error condition).
Validation/evidence required: Unit test invoking opengrep against a small fixture repo with 1-2 known
                   findings; test/lint asserts no opengrep Go/OCaml package is imported (subprocess-only
                   boundary); `go build`/`go vet` clean.
Stop condition:    Wrapper compiles, fixture test passes, subprocess boundary verified by absence of any
                   opengrep library import.
Why this model:    sonnet — default strong worker for implementation (00-ROUTING.md).
```

```text
Step ID:          B.2
Phase/group:      parallel group 1
Depends on:       none
Backend/model:    Claude Code subagent (sonnet)
Objective:        Vendor AikidoSec/opengrep-rules at a pinned commit SHA, record per-rule provenance
                   metadata, and document the LGPL-2.1 binary-distribution obligation that shipping the
                   compiled opengrep binary inside an Anvil container image would trigger.
Scope and files:  WRITE data/rules/opengrep-aikido/** (vendored rules + VENDOR.md pin file),
                   config/detect/tier1_opengrep.yaml, data/LICENSES/opengrep-binary-distribution.md.
Forbidden actions: Do not vendor opengrep/opengrep-rules (archived, LGPL-2.1 + Commons Clause,
                   NOASSERTION) or any Semgrep-maintained ruleset (spine S5). Do not read licence from
                   package/API metadata — read the LICENSE file body itself (spine S8: "seven artifacts
                   return NOASSERTION over a real licence").
Inputs/artifact refs: AikidoSec/opengrep-rules (MIT, research/10 Table 1); opengrep engine's own
                   LGPL-2.1 terms.
Expected output schema: VENDOR.md `{repo_url, pinned_commit_sha, licence_spdx, fetch_date}`;
                   tier1_opengrep.yaml `{ruleset_path, ruleset_commit_sha, engine_binary_path,
                   engine_version}`; opengrep-binary-distribution.md stating that packaging the compiled
                   opengrep binary into an Anvil-distributed container image constitutes "distribution"
                   under LGPL-2.1 and requires either a NOTICE plus a corresponding-source offer for that
                   exact binary, or excluding the binary from the shipped image in favour of
                   fetch-on-first-boot.
Validation/evidence required: SPDX check confirms MIT on the vendored ruleset's LICENSE file body; commit
                   SHA reproducible via `git log -1` in the vendored tree.
Stop condition:    Ruleset vendored, provenance file present, compliance note written and cross-referenced
                   from tier1_opengrep.yaml.
Why this model:    sonnet — licence-relevant work needs the default strong worker (00-ROUTING.md); this
                   step's conclusions are cross-family-critiqued at B.14 because it is a licence
                   conclusion (00-ROUTING.md mandatory cross-family rule).
```

```text
Step ID:          B.3
Phase/group:      parallel group 1
Depends on:       none
Backend/model:    Claude Code subagent (sonnet)
Objective:        Build the Milestone 0 evaluation harness implementing research/03's Test 1 (pairwise
                   discrimination), Test 2 (precision at fixed recall 0.70 vs. a code-metrics
                   logistic-regression baseline), and Test 4 (advisory-permutation ablation), using
                   PrimeVul-Paired (MIT), CVEfixes (MIT code / CC-BY-4.0 data), and CrossVul (CC-BY-4.0).
Scope and files:  WRITE eval/milestone0/harness.py, eval/milestone0/baseline_logreg.py,
                   eval/milestone0/ablation.py, eval/milestone0/data_ingest.py,
                   eval/milestone0/requirements.txt.
Forbidden actions: No fine-tuning/training of any adjudicator candidate (spine: zero training in v1;
                   research/03 primary pick is "do not train a detection model for v1"). The logistic
                   regression is a classical-ML baseline required by spine S3 item 2, not an exception to
                   the no-training rule. Do not ingest DiverseVul (no licence), Devign/CodeXGLUE (licence
                   unverified, 24.0% label accuracy), or Big-Vul (25.0% label accuracy) — research/03
                   Table 1.
Inputs/artifact refs: research/03-detection-training-data-and-method.md Tables 1-3 and the "Evaluation
                   harness" subsection; PrimeVul-Paired test set (564 pairs), unpaired test
                   (695/25,216).
Expected output schema: CLI entrypoints `harness.py test1|test2|test4 --model-endpoint <url>` emitting
                   JSON `{test, metric_name, value, threshold, pass}`; baseline_logreg.py fits/evaluates
                   a scikit-learn logistic regression over classic code metrics (cyclomatic complexity,
                   LOC, nesting depth, token entropy) and reports F1/precision/recall.
Validation/evidence required: Harness runs end-to-end against a stub endpoint returning random verdicts
                   and produces well-formed JSON (proves plumbing before a real model exists); a licence
                   manifest records every ingested dataset's verified licence.
Stop condition:    All three tests execute against the mock endpoint without error; baseline_logreg.py
                   reports a numeric F1 on the PrimeVul unpaired test set.
Why this model:    sonnet — Milestone 0 harness work, one of the three sanctioned Python roles in the Go
                   control plane (spine S12 point 3); requires faithful translation of research/03's test
                   definitions.
```

```text
Step ID:          B.4
Phase/group:      parallel group 1
Depends on:       none
Backend/model:    Claude Code subagent (sonnet)
Objective:        Verify, against each candidate's own LICENSE file body and model card, the exact
                   shippable variant, licence, and footprint of the four Tier 3 adjudicator candidates —
                   Qwen3.5-2B (confirm a text-only, non-VLM checkpoint exists), SmolLM3-3B, Phi-4-mini,
                   and Gemma 4 (the specific parameter-count variant to be shipped) — and record the
                   result as config, never as a hard-coded model name.
Scope and files:  WRITE config/detect/tier3_adjudicator.yaml (candidates section only),
                   data/LICENSES/adjudicator-candidates.md.
Forbidden actions: Do not infer licence from HF API metadata or a repo badge (spine S8: this is exactly
                   how seven artifacts were mis-read as NOASSERTION). Do not select
                   Qwen2.5-Coder-3B-Instruct (non-commercial-only), gemma-3-* (old kill-switch Terms),
                   Llama-3.2-* (Built-with-Llama duty), or starcoder2-3b (OpenRAIL-M) — research/02
                   "Explicitly rejected". Never hard-code a model name/path/endpoint outside this config
                   file.
Inputs/artifact refs: research/02-small-detection-models.md Table 1 and "Explicitly rejected" section;
                   spine S4's Gemma 4 reversal and its caveat that Qwen splits licences by parameter
                   count within one family.
Expected output schema: tier3_adjudicator.yaml candidates list, each entry `{name, hf_id, revision_sha,
                   licence_spdx, licence_verified_from: "LICENSE file body", context_window, params,
                   is_text_only: bool, status: eligible|flagged|rejected}`; adjudicator-candidates.md
                   quoting the operative licence clause for each.
Validation/evidence required: For Qwen3.5-2B — explicit confirmation or refutation that a text-only
                   checkpoint exists separate from the vision-language default; if none exists, mark
                   `status: flagged` and record research/02's stated fallbacks (Qwen3.5-0.8B /
                   Qwen3-0.6B). For Gemma 4 — the exact shipped variant's own LICENSE resolving to
                   Apache-2.0, re-verified independently (do not reuse a sibling's licence per spine S4's
                   caveat).
Stop condition:    All four candidates have a recorded, sourced licence verdict; at least one candidate
                   is `status: eligible`.
Why this model:    sonnet with WebFetch — licence verification is exactly the high-stakes,
                   easily-misread task spine S8 warns about; default strong worker, cross-family-critiqued
                   at B.14 as a licence conclusion (00-ROUTING.md).
```

```text
Step ID:          B.5
Phase/group:      parallel group 1
Depends on:       none
Backend/model:    Claude Code subagent (sonnet)
Objective:        Scaffold llama-server process configuration for Lane B's Tier 3 tier — one resident
                   instance with `--mlock`, Q4_K_M+imatrix quantisation — as config-declared
                   OpenAI-compatible base URLs, never hard-coded endpoints.
Scope and files:  WRITE internal/serving/llama/config.go, internal/serving/llama/tiers.go,
                   config/detect/serving.yaml.
Forbidden actions: Do not propose vLLM (spine: "Not vLLM in v1" — multi-LoRA needs adapters that must
                   not exist pre-S3). Do not omit `--mlock` on the always-on detection tier. Do not select
                   a quant below Q4_K_M without an imatrix.
Inputs/artifact refs: research/05-inference-serving-and-hardware.md "Concrete deployment recipe" and
                   "Quantization policy" subsections.
Expected output schema: serving.yaml `{tier: "detection_adjudicator", model_path: "${configured}", port,
                   parallel: 2, ctx_size: 16384, mlock: true, quant: "Q4_K_M+imatrix"}`; Go structs
                   mirroring this plus a `Launch(cfg) (*Process, error)` supervisor stub.
Validation/evidence required: Config round-trips through the Go struct in a marshal/unmarshal test; no
                   literal model filename or port appears in .go source, only in config.
Stop condition:    Config schema defined, supervisor stub compiles, parsing unit test passes.
Why this model:    sonnet — control-plane serving code in Go is core implementation work (spine S12);
                   default strong worker.
```

```text
Step ID:          B.6
Phase/group:      parallel group 2
Depends on:       B.1, B.2
Backend/model:    Claude Code subagent (sonnet)
Objective:        Extend the opengrep wrapper into Tier 1's public candidate contract — attach
                   per-finding rule provenance and instrument the candidates-per-scan counter spine S2
                   requires the scan controller to consume as a first-class input.
Scope and files:  WRITE internal/detect/opengrep/candidates.go, internal/detect/metrics/candidates.go.
Forbidden actions: Do not drop provenance on any finding. Do not expose statement-level line numbers as
                   authoritative — function/file identity is authoritative, line numbers are derived and
                   advisory only (research/02: best system on SecVulEval reaches 23.83% F1 at statement
                   level — "statement-level localisation is unsolved").
Inputs/artifact refs: B.1's RawFinding; B.2's tier1_opengrep.yaml provenance fields; spine S2; spine S6
                   (`anvil/trust` tagging — rule-derived text is `anvil_generated`).
Expected output schema: `Candidate{ID, FunctionOrFileID string (authoritative), AdvisoryLineHint int
                   (advisory only), RuleID, RuleProvenance{Repo, CommitSHA, Licence}, CWE, Snippet string,
                   Trust: "anvil_generated"}`; `metrics.CandidatesPerScan` with `Emit(scanID string, n
                   int)`, exposed via an interface for the scan controller to consume (owned elsewhere,
                   only exposed here).
Validation/evidence required: Unit test asserting every emitted Candidate carries non-empty
                   RuleProvenance; a test scan against B.1's fixture repo reports and logs a
                   candidates-per-scan value.
Stop condition:    Candidate schema finalized, provenance populated on 100% of test findings, metric
                   emitted and observable. Flag to the orchestrator if a real-corpus candidate count later
                   lands in the thousands (spine S2: "the design does not work and must be re-scoped").
Why this model:    sonnet — direct continuation of B.1's implementation; default strong worker.
```

```text
Step ID:          B.7
Phase/group:      parallel group 2
Depends on:       B.3, B.4
Backend/model:    Claude Code subagent (sonnet)
Objective:        Execute Milestone 0's Test 1, Test 2, and Test 4 against the eligible candidate(s) from
                   B.4, using both the PrimeVul-Paired CVE-conditioned framing (as published) and a
                   Lane-B-shaped rule-message-plus-CWE-description framing built from the AikidoSec
                   ruleset — Lane B's actual production input has no CVE, only rule/CWE text.
Scope and files:  WRITE eval/milestone0/results/test1_pairwise.json,
                   eval/milestone0/results/test2_precision_recall.json,
                   eval/milestone0/results/test4_ablation.json,
                   eval/milestone0/lane_b_shape_adapter.py.
Forbidden actions: Do not train or fine-tune any candidate here — evaluate off-the-shelf only
                   (research/03 primary pick). Do not report a headline number sourced from
                   undeduplicated BigVul/Devign-style data (research/02: label accuracy 24-60% on those
                   sets).
Inputs/artifact refs: B.3 harness; B.4 candidate list; research/03 thresholds (Test 1 pass bar P-C >25%,
                   GPT-4 CoT reference 12.94%, flag-everything F1 floor 5.22%; Test 4 pass bar flip rate
                   >80%, fail bar <50%).
Expected output schema: Per-candidate JSON `{candidate, test1_pc, test2_precision_at_recall70,
                   test4_flip_rate_primevul_shape, test4_flip_rate_laneb_shape, verdict:
                   pass|fail|marginal}`.
Validation/evidence required: The Lane-B-shape result is compared against the PrimeVul-shape result for
                   the same candidate; any divergence >15 points between the two framings is flagged
                   explicitly rather than averaged (this is the CVE-vs-CWE conditioning evidence gap — see
                   Open Questions).
Stop condition:    Every eligible B.4 candidate has a complete four-metric result row and an explicit
                   pass/fail/marginal verdict against research/03's thresholds.
Why this model:    sonnet — running and interpreting an evaluation harness against published thresholds is
                   implementation-adjacent judgement work; default strong worker. On an ambiguous/marginal
                   result, reroute once per 00-ROUTING.md rather than guessing.
```

```text
Step ID:          B.8
Phase/group:      parallel group 2
Depends on:       B.5
Backend/model:    Claude Code subagent (sonnet)
Objective:        Build and run the KL-divergence quantisation validation harness
                   (`llama-perplexity --kl-divergence-base` against FP16 logits) on a held-out slice of
                   Anvil's own advisory/rule+code corpus, before any Q4_K_M quant of the Tier 3 model may
                   ship.
Scope and files:  WRITE eval/quant/kl_divergence.py, eval/quant/results/tier3_kl.json.
Forbidden actions: Do not substitute a general-benchmark perplexity number for this measurement
                   (research/05: "no published benchmark covers Anvil's task distribution"). Do not ship a
                   quant below Q4_K_M. Never use bitsandbytes/HQQ runtime quantisation (research/05:
                   measured "+10% to +886% latency for no correctness gain").
Inputs/artifact refs: research/05 "Quantization policy" and "Validate with KL divergence, not
                   perplexity" subsections; B.5's serving config for the FP16 and Q4_K_M+imatrix GGUF
                   paths.
Expected output schema: tier3_kl.json `{model, quant, kl_divergence_mean, kl_divergence_p99, corpus_size,
                   pass: bool}`. The numeric pass threshold is UNMEASURED — gated on Milestone 0; do not
                   invent one — flag any result for human review rather than silently thresholding.
Validation/evidence required: Script runs against both FP16 and Q4_K_M+imatrix builds of the same pinned
                   revision and produces a real divergence number, not a placeholder.
Stop condition:    KL-divergence result recorded for the Tier 3 candidate selected in B.7; result is
                   either accepted or explicitly escalated as a risk to the orchestrator.
Why this model:    sonnet — quantisation validation harness is one of Python's three sanctioned
                   control-plane roles (spine S12 point 3); implementation plus measurement work.
```

```text
Step ID:          B.9
Phase/group:      parallel group 1
Depends on:       none
Backend/model:    Claude Code subagent (sonnet)
Objective:        Build the ONNX INT8 encoder worker — a standalone, always-on Python HTTP process (never
                   an in-process library call, per spine S12) — that scores (candidate snippet, rule/CWE
                   metadata) pairs for the optional Tier 2 ranker.
Scope and files:  WRITE workers/onnx-encoder/server.py, workers/onnx-encoder/model.py,
                   workers/onnx-encoder/requirements.txt, config/detect/tier2_encoder.yaml (contract
                   section only: host, port, batch_size).
Forbidden actions: Do not embed this worker into the Go control-plane binary or call ONNX Runtime via
                   cgo/in-process bindings (spine S12: "Go has only a community cgo wrapper" — do not use
                   it). Do not fine-tune the encoder in this step — base model only; calibration is an
                   open question, not decided here.
Inputs/artifact refs: research/02 Table 2 (encoder candidates) and its Tier 2 recommendation ("A
                   fine-tuned microsoft/unixcoder-base... ship this only if it beats the baseline —
                   measure, do not assume"); research/05's ONNX Runtime recipe (INT8, static batch 32-64,
                   `intra_op_num_threads = physical cores`).
Expected output schema: HTTP contract `POST /score {snippet, rule_id, cwe} -> {score: float,
                   model_revision: string}`; `POST /score_batch` for the full-scan path; a schema doc in
                   the same directory.
Validation/evidence required: Worker starts, responds to a health check, and returns a deterministic
                   score for a fixed input across two consecutive calls (proves no hidden statefulness);
                   base model licence recorded (`microsoft/unixcoder-base`: Apache-2.0 weights / MIT repo,
                   research/02 S18).
Stop condition:    Worker serves `/score` and `/score_batch` over HTTP and passes a smoke test against
                   B.1's fixture repo output.
Why this model:    sonnet — this is the one place research/05 and spine S12 mandate a separate Python HTTP
                   service; implementation work, default strong worker.
```

```text
Step ID:          B.10
Phase/group:      parallel group 3
Depends on:       B.7
Backend/model:    Claude Code subagent (sonnet)
Objective:        Implement Tier 3's adjudication contract in Go — one CWE/rule advisory + one
                   pre-localized snippet in, `{EXHIBITS, DOES_NOT_EXHIBIT, INSUFFICIENT_CONTEXT}` plus
                   evidence sentences out — against B.7's winning candidate served by B.5, and define the
                   SAST-owned subset of the evidence-vector confidence schema (never a scalar).
Scope and files:  WRITE internal/detect/adjudicator/client.go, internal/detect/adjudicator/prompt.go,
                   internal/detect/adjudicator/verdict.go, internal/record/evidence.go.
Forbidden actions: Do not collapse the verdict to a two-way choice (research/03: "a two-way forced choice
                   guarantees noise" — INSUFFICIENT_CONTEXT is non-negotiable). Do not emit or accept a
                   bare scalar confidence float anywhere in this schema (research/11: "Do not emit a
                   probability from the detection model and threshold on it" — repo-level ECE 0.70-0.73,
                   false-trust 18.6-40.3% at p>=0.8). Do not feed whole files to the model — hard-cap
                   snippet size (research/02: "accuracy declines, and hallucinations increase as the code
                   size grows").
Inputs/artifact refs: research/03 "Model call" (advisory + code chunk + fixed instruction → three-way
                   verdict); research/11's evidence-vector fields (`advisory_match`, `reachable`,
                   `detector_agreement`, `reproducer_available`, `prior_regression`) — Lane B owns
                   `advisory_match`, `detector_agreement=sast_only`, and `prior_regression`, and leaves
                   `dast_corroborated`/`reproducer_available` for later lanes to populate; B.7's winning
                   candidate.
Expected output schema: `Verdict{Result: EXHIBITS|DOES_NOT_EXHIBIT|INSUFFICIENT_CONTEXT,
                   EvidenceSentences []string, EvidenceVector: {AdvisoryMatch: exact_rule|cwe_class_only,
                   DetectorAgreement: "sast_only", PriorRegression: previously_fixed_here|novel}}`; prompt
                   template over `{cwe_description, rule_message, rule_references, snippet}` — no
                   CVE-specific field, Lane B has none.
Validation/evidence required: Unit test with a mocked llama-server response for each of the three verdict
                   values; a malformed/missing evidence-sentence field must fail closed to
                   `INSUFFICIENT_CONTEXT`, never silently default to `DOES_NOT_EXHIBIT`; schema review
                   confirms no scalar-only confidence field exists anywhere.
Stop condition:    Adjudicator client compiles, all three verdict paths are unit-tested, evidence vector
                   matches research/11's non-scalar design.
Why this model:    sonnet — implementation of a security-relevant decision path; default strong worker,
                   cross-family-critiqued at B.14 as security-relevant code (00-ROUTING.md).
```

```text
Step ID:          B.11
Phase/group:      parallel group 3
Depends on:       B.9, B.7
Backend/model:    Claude Code subagent (sonnet)
Objective:        Benchmark the Tier 2 ONNX encoder (B.9) against the Milestone 0 code-metrics
                   logistic-regression baseline (B.3/B.7) on the same held-out corpus, and record the
                   ship/no-ship decision as config, never as a code branch.
Scope and files:  WRITE config/detect/tier2_encoder.yaml (decision section only — disjoint from B.9's
                   contract section), eval/milestone0/results/tier2_benchmark.json.
Forbidden actions: Do not ship Tier 2 by default — "ship this only if it beats the code-metrics baseline
                   — measure, do not assume" (research/02). Do not fine-tune the encoder to win this
                   comparison — that would both invalidate the measurement and constitute training,
                   forbidden for v1.
Inputs/artifact refs: B.3's baseline_logreg.py output; B.9's `/score_batch` endpoint; research/02's flip
                   condition ("A measured result on Anvil's own held-out corpus showing the code-metrics
                   baseline matching [the model tier]. If that happens, delete [the model tier]") applied
                   symmetrically to Tier 2 vs. the baseline.
Expected output schema: tier2_benchmark.json `{baseline_f1, encoder_f1, baseline_precision_at_recall70,
                   encoder_precision_at_recall70, decision: ship|do_not_ship}`; tier2_encoder.yaml
                   `enabled: <decision>`.
Validation/evidence required: Both models evaluated on the identical held-out split; the `decision` field
                   is a direct function of the measured comparison, never a default value.
Stop condition:    `enabled` is set from a real measurement and the measurement JSON is non-empty.
Why this model:    sonnet — measurement plus config-decision work; default strong worker.
```

```text
Step ID:          B.12
Phase/group:      parallel group 4
Depends on:       B.10, B.6, B.11
Backend/model:    Claude Code subagent (sonnet)
Objective:        Wire the full Lane B pipeline — Tier 1 candidates → (Tier 2 re-rank, only if B.11
                   decided `ship`) → Tier 3 adjudication — into one orchestration path, populating the
                   evidence-vector fields on the unified record at runtime, and guarantee by construction
                   that the pipeline never forms an N×M pass over advisories and files.
Scope and files:  WRITE internal/detect/pipeline.go, internal/detect/encoder/client.go (Go HTTP client
                   for B.9's worker).
Forbidden actions: Never call the Tier 3 adjudicator once per (advisory, file) pair — it is called only
                   once per Tier-1-emitted (optionally Tier-2-filtered) candidate; this is the entire
                   point of the recall-then-adjudicate design (spine S1; research/10 R1). Never call the
                   ONNX worker in-process — HTTP only.
Inputs/artifact refs: B.6 Candidate struct; B.10 adjudicator client + evidence.go; B.11's
                   tier2_encoder.yaml decision; B.9's HTTP contract.
Expected output schema: `RunPipeline(ctx, repoPath) ([]record.Finding, error)`, each Finding carrying
                   `{Candidate, optional EncoderScore, Verdict, EvidenceVector,
                   CandidatesPerScanMetric}`; a config toggle reads B.11's `enabled` field to decide
                   whether Tier 2 runs at all.
Validation/evidence required: Integration test over B.1's fixture repo asserting: (a) Tier 3 call count
                   equals Tier 1 candidate count (post Tier-2-filter if enabled), never files-times-rules;
                   (b) every Finding has a non-empty EvidenceVector; (c) `INSUFFICIENT_CONTEXT` verdicts
                   are recorded as findings, not discarded.
Stop condition:    Pipeline integration test passes end-to-end with the Tier 2 toggle exercised in both
                   positions.
Why this model:    sonnet — integration/orchestration implementation; default strong worker.
```

```text
Step ID:          B.13
Phase/group:      parallel group 4
Depends on:       B.8, B.10
Backend/model:    Claude Code subagent (sonnet)
Objective:        Deploy the Tier 3 llama-server instance for production use — config-driven model
                   selection (the B.7-winning, B.8-validated candidate, never hard-coded), `--mlock`
                   applied, Q4_K_M+imatrix quant confirmed via B.8's KL-divergence pass.
Scope and files:  WRITE internal/serving/llama/deploy.go, config/detect/serving.yaml (extend the Tier 3
                   section only — disjoint from B.5's base schema, which this fills in).
Forbidden actions: Do not deploy a quant that failed or was never run through B.8's KL-divergence check.
                   Do not deploy vLLM (spine exclusion). Do not point at a remote endpoint by default
                   without it being explicitly config-selectable (research/05: remote-endpoint offload is
                   first-class, not a silent default).
Inputs/artifact refs: B.5 scaffold; B.7 winning candidate; B.8 KL-divergence result.
Expected output schema: serving.yaml Tier 3 entry fully populated `{model_hf_id, revision_sha, quant,
                   mlock: true, ctx_size: 16384, parallel: 2, endpoint_base_url}`; `Deploy(cfg) error`
                   that fails closed (refuses to start) if B.8's KL-divergence record for this exact
                   revision+quant is missing or `pass: false`.
Validation/evidence required: Unit test that `Deploy` refuses to start against a config missing a
                   KL-divergence pass record, and succeeds against one with a (mocked) pass record present.
Stop condition:    Deploy path compiles, fail-closed test passes, serving.yaml fully specifies the Tier 3
                   model with no literal value in Go source.
Why this model:    sonnet — serving/deployment implementation tied directly to a prior measurement gate;
                   default strong worker.
```

```text
Step ID:          B.14
Phase/group:      serial
Depends on:       B.1, B.2, B.4, B.6, B.12, B.13
Backend/model:    OpenCode route (openai/gpt-5.5)
Objective:        Independent cross-family critique of every licence conclusion and every
                   security-relevant boundary produced in Lane B: the opengrep subprocess/LGPL boundary
                   and its binary-distribution note (B.1, B.2), the adjudicator candidate licence verdicts
                   (B.4), the untrusted-input handling into the adjudicator prompt (B.6, B.12), and the
                   fail-closed serving gate (B.13).
Scope and files:  READ internal/detect/opengrep/**, data/rules/opengrep-aikido/VENDOR.md,
                   data/LICENSES/**, config/detect/**, internal/detect/pipeline.go,
                   internal/serving/llama/deploy.go. WRITE: none required; may write
                   data/critique/lane-b-critique.md as a durable record if the route supports it.
Forbidden actions: Must not re-derive or override licence/security conclusions unilaterally — flag
                   disagreements for the orchestrator to resolve (spine: "not open for re-litigation by
                   component workers"). Must not modify any B.1-B.13 file directly.
Inputs/artifact refs: 00-ROUTING.md cross-family critique rule ("Anthropic-written code and plans get an
                   OpenCode/OpenRouter critic... Any step that produces security-relevant code... a
                   licence conclusion must carry a critic step from a different model family"); all Lane B
                   artifacts listed above.
Expected output schema: Structured findings `{artifact, concern, severity, agree|disagree-with-recommendation}`,
                   explicitly covering: (1) does the opengrep binary-distribution note correctly state
                   LGPL-2.1 obligations; (2) does any candidate's licence verdict rest on API metadata
                   rather than a LICENSE file body; (3) is untrusted advisory/rule text properly
                   trust-tagged before reaching the adjudicator prompt (spine S6; research/11 risks #5-6);
                   (4) any missed N×M cross-product path.
Validation/evidence required: All four explicit checks receive an explicit answer, not a skip.
Stop condition:    Critique returned with all four checks answered; "disagree" items logged for
                   orchestrator resolution, not silently applied.
Why this model:    OpenCode `openai/gpt-5.5` — 00-ROUTING.md mandates a different-family critic for
                   security-relevant code, migrations, and licence conclusions, all four of which apply
                   here. The paid route is justified over a free one because a wrong call on the LGPL
                   binary-distribution question or the untrusted-input boundary is exactly the high-risk
                   review case the guard reserves this tier for, and research/10 R5 names licence
                   contamination "the most likely way this project quietly dies."
```

```text
Step ID:          B.15
Phase/group:      serial
Depends on:       B.6, B.7, B.8, B.9, B.10, B.11, B.12, B.13, B.14
Backend/model:    Claude Code subagent (sonnet)
Objective:        Verify Lane B end-to-end against this document's Tier Contract and Exit Criteria, and
                   produce the Milestone 0 decision log the orchestrator needs to greenlight Lane B for
                   integration with Lane A and the unified record.
Scope and files:  WRITE internal/detect/pipeline_integration_test.go,
                   eval/milestone0/results/gate_decision.json.
Forbidden actions: Do not mark any exit criterion satisfied without a corresponding artifact from
                   B.1-B.14 to cite. Do not paper over a B.14 "disagree" item.
Inputs/artifact refs: This document's "Tier Contract" and "Exit Criteria" sections; all prior step
                   outputs.
Expected output schema: gate_decision.json `{tier1: pass|fail, tier2_shipped: bool+reason, tier3_model:
                   <name+revision>, tier3_milestone0_verdict: pass|fail|marginal, serving_kl_divergence:
                   pass|fail, candidates_per_scan_measured: <int>, b14_open_items: [...]}`.
Validation/evidence required: Every field populated from a real prior-step artifact (cited by path);
                   `pipeline_integration_test.go` passes.
Stop condition:    gate_decision.json is complete; every exit criterion below is either satisfied or
                   explicitly marked as an open item for the orchestrator.
Why this model:    sonnet — synthesis-adjacent verification spanning 14 prior steps' artifacts; earns
                   delegation under 00-ROUTING.md ("do not write a step that delegates trivia... mark
                   single-file edits orchestrator-inline") because this is not a single-file trivial edit.
```

## Tier Contract

| Tier | What it does | Deterministic? | Input | Output | Where it runs |
|---|---|---|---|---|---|
| **Tier 1 — Recall** | opengrep pattern match, invoked as a subprocess, against `AikidoSec/opengrep-rules` | Yes | Repo source tree + pinned ruleset | Candidate list: function/file-authoritative ID, advisory-only line hint, rule ID, CWE, snippet, rule provenance | Compiled OCaml `opengrep` CLI, invoked as a subprocess from the Go control-plane host (research/10, spine S12) |
| **Tier 2 — Optional ranker** | ONNX INT8 encoder scores/reranks Tier 1 candidates | No (ML classifier, non-generative) — ships only if B.11 measures it beating the code-metrics baseline | (candidate snippet, rule/CWE metadata) pairs | Score per candidate | Separate, always-on Python HTTP worker process, never in-process (research/05, spine S12); CPU, static-batched 32-64 |
| **Tier 3 — Adjudicator** | Small instruction LLM decides applies / does-not-apply per candidate | No | One CWE/rule advisory text + one pre-localized snippet | `{EXHIBITS, DOES_NOT_EXHIBIT, INSUFFICIENT_CONTEXT}` + evidence sentences + SAST-owned evidence-vector fields | `llama-server`, OpenAI-compatible HTTP, resident with `--mlock`, config-declared base URL (local or remote) |

**Tier-numbering note:** research/05's serving recipe uses its own Tier 0-3 spanning the whole system
(SAST encoder / SAST generative verifier / DAST model / coding agent). Lane B's Tier 1-3 above map onto
research/05's Tier 0 (= Lane B Tier 2, encoder) and Tier 1 (= Lane B Tier 3, generative verifier) only;
research/05's Tier 2 (DAST) and Tier 3 (coding agent) belong to other lanes and are out of scope here.

## Model Selection Gate

| Candidate | Licence | Size | Gating experiment | Flip condition |
|---|---|---|---|---|
| **Qwen3.5-2B** (primary pick, research/02) | Apache-2.0 — **must verify a text-only checkpoint exists**; the Qwen3.5 line is vision-language by default (spine S4) | 2B | B.7: Milestone 0 Tests 1/2/4 (both PrimeVul-shape and Lane-B-shape) | No text-only checkpoint exists → fall back to `Qwen3.5-0.8B` or `Qwen3-0.6B` (Apache-2.0, 32K ctx, verified text-only, research/02) |
| **SmolLM3-3B** (runner-up, research/02) | Apache-2.0, fully open training data + configs + checkpoints | 3B | Same as above | Take if auditability (open training data) outranks efficiency, or if the Qwen3.5-2B text-only variant is unavailable |
| **Phi-4-mini-instruct** (second runner-up, research/02) | MIT — most permissive in the candidate set | 3.8B | Same as above | Take if licence permissiveness is the deciding constraint; penalised by Python-centric training bias and self-declared function-name hallucination (research/02) |
| **Gemma 4** (newly eligible, spine S4) | Apache-2.0 for the *specific variant only* — Qwen precedent shows licences split by parameter count within one family; the sibling check at spine level does not clear an unverified variant | Variant TBD — B.4 must select one | Same as above, plus an independent per-variant licence re-check (B.4) beyond the spine-level Gemma 4 reversal | Disqualify immediately if the shipped variant's own LICENSE file (not API metadata) fails to resolve to Apache-2.0, or if any remnant of the old Gemma Terms kill-switch clause appears in that variant's terms |

**Overall flip conditions (research/03 "What would flip this decision", spine S3):**
- Test 1 P-C ≤25% or Test 4 flip rate <50% for every candidate → the off-the-shelf model is not
  conditioning on the advisory; escalate to the orchestrator rather than implementing training in v1
  (training is out of scope per this plan's FORBIDDEN constraints even though research/03 names a
  runner-up training path — do not build it here).
- Test 1 P-C >40% and Test 4 flip rate >80% untrained → confirmed; ship Tier 3 with the cheapest
  candidate clearing both bars.
- Test 2 precision@recall0.70 stays below ~0.20 after the pre-filter → drop Tier 3 entirely; Lane B
  becomes deterministic-only, with confirmation deferred to the coding-agent lane.
- Milestone 0's code-metrics baseline matches Tier 3's measured performance → delete Tier 3, ship
  Tiers 1-2 only (research/02 flip condition 1).

## Exit Criteria

**Tier 1**
- opengrep is invoked only as a subprocess — no opengrep OCaml/Go bindings anywhere in the dependency
  tree (B.1).
- `AikidoSec/opengrep-rules` vendored at a pinned commit SHA with MIT licence text verified from the
  LICENSE file body, not API metadata (B.2).
- 100% of emitted candidates carry non-empty rule provenance: repo, commit SHA, licence (B.6).
- Candidates-per-scan metric is emitted per scan and exposed for the scan controller/scheduler (B.6,
  spine S2). If a real-corpus measurement lands in the thousands, this is flagged to the orchestrator as
  a re-scope trigger (spine S2: "In the thousands, the design does not work").
- The opengrep-binary container-distribution LGPL obligation is documented (B.2).

**Tier 2**
- The ship/no-ship decision in `config/detect/tier2_encoder.yaml` is derived from a real measured
  comparison against the code-metrics baseline, never defaulted (B.11).
- If shipped: `/score` and `/score_batch` respond over HTTP from a separate process; zero in-process
  ONNX Runtime calls anywhere in the Go control plane (B.9, B.12).

**Tier 3**
- Milestone 0 Test 1 (P-C), Test 2 (precision@recall0.70), and Test 4 (advisory-permutation flip rate,
  both framings) are recorded for every eligible candidate (B.7).
- `INSUFFICIENT_CONTEXT` is a distinct, unit-tested verdict path, never folded into `DOES_NOT_EXHIBIT`
  (B.10).
- No scalar confidence field exists anywhere in the verdict/evidence schema (B.10).
- Tier 3 model selection is a config value; zero hard-coded model names/paths/endpoints in Go source
  (B.4, B.5, B.13).
- KL-divergence of the shipped quant vs. FP16 is measured on Anvil's own corpus before deployment; the
  deploy path fails closed without a recorded pass (B.8, B.13).

**Pipeline-level**
- The pipeline never calls Tier 3 more than once per Tier-1-emitted (optionally Tier-2-filtered)
  candidate — verified by an integration test asserting call count equals candidate count, never
  files × rules (B.12).
- B.14's cross-family critique is complete, all four explicit checks answered, and any disagreements are
  logged for the orchestrator, not silently applied.
- `gate_decision.json` (B.15) is complete, with every field citing a concrete prior-step artifact.

## Pinned Versions And Licences

| Component | Repo / artifact | Licence | Verified from | Pin discipline |
|---|---|---|---|---|
| opengrep engine | `opengrep/opengrep` | LGPL-2.1 | research/10 Table 1; spine S4, S11 | Pin exact release/commit; subprocess only, never linked |
| Rule pack | `AikidoSec/opengrep-rules` | MIT | research/10 Table 1 (S13) | Pin commit SHA (B.2) |
| llama.cpp / llama-server | `ggml-org/llama.cpp` | MIT | research/05 Recommendation | Pin release tag |
| ONNX Runtime | `microsoft/onnxruntime` | MIT | research/05 Recommendation | Pin package version |
| Tier 2 default candidate | `microsoft/unixcoder-base` | Apache-2.0 (weights) / MIT (repo) | research/02 (S18), Table 2 | Pin revision SHA |
| Tier 3 primary candidate | `Qwen/Qwen3.5-2B` (text-only variant, pending verification) | Apache-2.0 | research/02 (S20); spine S4 caveat | Pin revision SHA; re-verify per spine S8 |
| Tier 3 runner-up | `HuggingFaceTB/SmolLM3-3B` | Apache-2.0 | research/02 (S13) | Pin revision SHA |
| Tier 3 second runner-up | `microsoft/Phi-4-mini-instruct` | MIT | research/02 (S17) | Pin revision SHA |
| Tier 3 newly-eligible candidate | Gemma 4, specific variant TBD | Apache-2.0 per the shipped variant's own LICENSE — verify individually | spine S4 | Pin revision SHA; independent per-variant re-check mandatory (B.4) |

**Explicitly excluded — do not vendor or ship:** `opengrep/opengrep-rules` (archived, LGPL-2.1 + Commons
Clause, NOASSERTION); `semgrep/semgrep-rules` (Semgrep Rules License v1.0, no redistribution); CodeQL
CLI/queries (proprietary CI/CD restriction attaches to the *target*, not to Anvil);
`Qwen/Qwen2.5-Coder-3B-Instruct` (non-commercial-only); `google/gemma-3-*` (superseded — old Terms
kill-switch clause); `meta-llama/Llama-3.2-*` (Built-with-Llama naming duty); `bigcode/starcoder2-3b`
(OpenRAIL-M propagating restrictions, and not an instruction model).

**Compliance note (binary distribution):** shipping the compiled opengrep binary inside an Anvil
container image is "distribution" under LGPL-2.1 and triggers notice + offer-source duties on that
binary specifically — this is treated as the most likely real compliance event in this lane, not a
theoretical risk (see B.2, `data/LICENSES/opengrep-binary-distribution.md`).

## Open Questions

1. **CVE-conditioning vs. CWE/rule-conditioning evidence gap.** research/03's positive evidence
   (Vul-RAG, PrimeVul-Paired's `CVE description + CWE description → verdict` framing) is for
   CVE-description conditioning. Lane B's actual production input has no CVE — only CWE-class text and
   opengrep rule metadata. B.7 tests both framings and flags material divergence, but no published result
   covers the Lane-B-shaped case directly; treat Test 4's Lane-B-shape number, not the PrimeVul-shape
   number, as the one that gates shipping.
2. **Container packaging of the opengrep binary vs. fetch-on-first-boot.** A real product decision with
   licence weight (B.2's note); not resolved here and likely belongs to a packaging/deployment lane, not
   Lane B.
3. **Does Tier 2 calibration count as forbidden "training"?** Fitting a linear probe/threshold on top of
   frozen `unixcoder-base` embeddings is plausibly distinct from fine-tuning the encoder's weights, but
   this plan treats the encoder as strictly off-the-shelf/frozen (B.9, B.11) pending orchestrator
   clarification of where that line sits.
4. **Exact Gemma 4 variant is unspecified by spine S4** (which parameter count, which context length);
   B.4/B.7 must pick one, and the choice is not made in this plan.
5. **Encoder HTTP round-trip cost at real scan volume.** Spine S12 flags this as the one measurement that
   could flip the Go/Python process boundary decision ("if the encoder HTTP round-trip dominates latency
   at real scan volume... Python becomes the stronger pick"). B.9/B.11 should measure RTT under realistic
   (thousands-of-pairs) volume, not just a smoke test.
6. **AikidoSec/opengrep-rules' first-party coverage per language Anvil targets is unverified anywhere in
   the research corpus.** A coverage audit alongside Milestone 0 would reduce the risk of Tier 1 recall
   being silently poor for some language — not currently a step in this plan.

## Conflicts With Spine

None identified that require re-litigation. Two apparent tensions were checked and are resolutions
already made at the spine level, not open conflicts:

- research/10's primary recommendation was to fork `shellphish/artiphishell`; spine S11 overturns this
  ("do not fork an AIxCC CRS"). This plan builds Tier 1-3 itself and reuses only research/10's rule-source
  and licence conclusions (`AikidoSec/opengrep-rules`, the N×M quantification), which is consistent with
  S11's own reasoning.
- research/02 rejects the entire Gemma family on kill-switch-clause grounds; spine S4 carves out Gemma 4
  specifically as eligible. This plan treats Gemma 4 as eligible-pending-per-variant-verification (B.4),
  consistent with S4, and treats research/02's rejection as applying only to Gemma 1-3, per S4's own
  wording.
