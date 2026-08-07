# Anvil Implementation — Remediation And Validation

## Overview

This document steps the tier that consumes a sealed audit record and produces **proposed** fixes: a
cheap pre-generation triage gate, the 22-step consumption protocol (lease → persist → group → rank →
generate → apply → validate → commit → re-anchor → yield → emit), the patch-side validation gate
ladder, and the PR lifecycle. Nothing in this tier merges anything — every path terminates in a draft
PR, a report-only finding, or a withdrawn/superseded proposal. The coding agent talks to a pluggable
OpenAI-compatible endpoint (config value, never hard-coded); the harness — not the model — parses,
validates, and applies every edit. The state machine described here is a sub-machine registered under
Anvil's single named scan controller (spine S10), not a second competing controller.

## Dependency Summary

**Consumed, owned elsewhere (read-only from this tier's point of view):**

| Dependency | Owned by | What this tier assumes |
|---|---|---|
| Unified audit record (SARIF 2.1.0 + `anvil/*` extension), incl. **the one fingerprint algorithm defined once** (spine S6) | Record/schema tier (research/18) | This tier **consumes** `primaryLocationLineHash`-style fingerprints; it must never define a second algorithm under the same name — spine S6 flags exactly this failure mode |
| SQLite WAL + FTS5 store, single writer | Database tier (research/07) | Ledger table lives here; this tier adds rows, does not own schema migration tooling |
| 8-hour regenerable buffer/handoff packet | Buffer tier (research/08) | The buffer is a cache, never the resumption source of truth (spine S1 #5) |
| The single named scan controller / state machine | Orchestration tier (spine S10) | This tier's consumption protocol is a registered sub-machine, invoked on buffer arrival, not a standalone daemon |
| DAST reproduction artifact (replayable request/response or exploit script) on `dast_confirmed` findings | DAST tier (research/15–17, 23) | Without this field, tier-0 ordering and the exploit-oracle gate (G7) both degrade to unavailable — see Open Questions |
| Lane A/B candidate recall, CWE 4.20 label space | Detection tiers (research/01–03) | This tier receives adjudicated findings; it does not re-run detection |
| Sandboxed target checkout (read for scan, write only to `anvil/fix/<audit_id>`) | Target-environment tier (research/19) | Isolation and network egress control are provided by that tier; this tier enforces the credential/network boundary *inside* its own generation step regardless |

**Owned and stepped in this document:** triage gate, consumption protocol/state machine, fix-group
batching, ranking contract, SEARCH/REPLACE edit protocol, diff synthesis + `git apply` wrapper, the
patch-side validation gate ladder, commit/rollback + lease-theft mitigation, re-anchoring, PR
lifecycle, regression re-check scheduler, PR-acceptance-rate metric, and the pluggable model backend
client for the coding agent.

---

## Steps

All Go packages live under `internal/remediation/**` unless stated otherwise. Config additions are
Go structs owned by the package that uses them; a later integration step composes them into
`.anvil/policy.yml` — no two parallel steps write the same config file.

```text
Step ID:          X.1
Phase/group:      parallel group 1
Depends on:        none
Backend/model:    Claude Code subagent (sonnet)
Objective:        Implement the resumption ledger: DB schema, worker leases, and idempotency keys.
Scope and files:  WRITE internal/remediation/ledger/**, migrations/NNN_remediation_ledger.{up,down}.sql.
                  READ research/24 §G (idempotency), research/24 consumption-protocol steps 1,4,20.
Forbidden actions: Do not define a second fingerprint algorithm — consume the record tier's fingerprint
                  type as an opaque imported value. Do not treat the buffer packet as authoritative.
Inputs/artifact refs: idempotency key = sha256(audit_id ‖ finding_fingerprint ‖ base_commit_sha);
                  ledger states PENDING|LEASED|VALIDATED|FAILED_VALIDATION|FAILED_FORMAT|
                  SKIPPED_BUDGET|FALSE_POSITIVE|REGRESSION_INTRODUCED|FIXED_INCIDENTALLY|
                  SPLIT_REQUIRED|WITHDRAWN|SUPERSEDED.
Expected output schema: Go package `ledger` exporting Lease(), Renew(), Steal(), MarkState(),
                  LoadAlreadyDone(audit_id) (unions DB rows with git-trailer scan results — trailer
                  scan itself is step X.8's concern; this step exposes the DB half).
Validation/evidence required: go test ./internal/remediation/ledger/... covering lease expiry, lease
                  steal, and idempotency-key collision; migration applies and rolls back cleanly.
Stop condition:   Tests green; schema reviewed for WAL single-writer compatibility.
Why this model:   Bounded, well-specified store implementation — default strong-worker lane per
                  00-ROUTING.md; not ambiguous enough to escalate to opus.
```

```text
Step ID:          X.2
Phase/group:      parallel group 1
Depends on:        none
Backend/model:    Claude Code subagent (sonnet)
Objective:        Build the pluggable OpenAI-compatible coding-agent client with a loud, default-off
                  warning for hosted/free endpoints.
Scope and files:  WRITE internal/remediation/backend/**.
                  READ research/04 "Architecture: make the backend pluggable" + its Risks.
Forbidden actions: Do not hard-code any model ID, endpoint URL, or context budget — config only. Do
                  not silently default to a public hosted endpoint. Do not log or persist the endpoint
                  credential.
Inputs/artifact refs: `/v1/chat/completions` shape (vLLM/llama.cpp/Ollama/hosted-compatible). Config
                  fields: endpoint_url, model_id, context_budget_tokens, trust_tier ∈
                  {self_hosted, user_remote, public_hosted}.
Expected output schema: Go package `backend` exporting Client interface {Complete(ctx, prompt) (…)}
                  and a Warn() call that fires at config-load time whenever trust_tier=public_hosted or
                  the endpoint host matches a known free-tier provider heuristic, stating explicitly
                  that unremediated vulnerabilities and proprietary source will be disclosed to a third
                  party. Default trust_tier is self_hosted; public_hosted requires an explicit opt-in
                  flag.
Validation/evidence required: unit test asserting Warn() fires for public_hosted and any known
                  free-provider hostname, and does NOT fire for self_hosted/user_remote; config
                  round-trip test.
Stop condition:   Tests green; warning text reviewed for clarity by the X.7 critic.
Why this model:   Config/HTTP-client implementation, bounded scope — default strong-worker lane.
```

```text
Step ID:          X.3
Phase/group:      parallel group 1
Depends on:        none
Backend/model:    Claude Code subagent (sonnet)
Objective:        Implement the ranking contract with the CVE-less path as the default ordering and
                  the queue-cut/re-cut-with-reserve budget logic.
Scope and files:  WRITE internal/remediation/rank/**.
                  READ plan/00-SPINE.md §S1(#4a note), §S6 "Ordering"; research/24 Table 3 and
                  Recommendation item 4 (for the superseded ordering — do not implement it as written).
Forbidden actions: Do NOT implement research/24's literal `rank_key` (which places KEV/EPSS ahead of
                  reachability) — the spine correction below overrides it. Do not make KEV/EPSS/CVSS
                  required fields; they must be nullable and treated as tie-break bonus terms only.
Inputs/artifact refs: see "## Ranking Contract" below for the exact key.
Expected output schema: Go package `rank` exporting Score(finding) RankKey, CutQueue(groups, budget,
                  reserve_fraction) ([]Group, []Group /*deferred*/), and RecutOnVersionBump(prior,
                  incoming) — reserves `reserve_fraction` (config, default 0.5) of *remaining* budget
                  for late-arriving dast_confirmed findings on every re-cut, per spine S6.
Validation/evidence required: table-driven test proving an all-null-bonus-terms finding (no CVSS/EPSS/
                  KEV — the common case) still sorts correctly on the primary 4-tuple alone; test that
                  a late dast_confirmed arrival after cut consumes only from the reserved fraction.
Stop condition:   Tests green, including the "CVE-less majority" regression test.
Why this model:   Pure logic over a fully specified contract — default strong-worker lane.
```

```text
Step ID:          X.4
Phase/group:      parallel group 1
Depends on:        none
Backend/model:    Claude Code subagent (sonnet)
Objective:        Implement fix-group batching: same file AND same enclosing symbol, capped size.
Scope and files:  WRITE internal/remediation/group/**.
                  READ research/24 §B (Hunk4J locality gradient), consumption-protocol step 8.
Forbidden actions: Never batch across files. Never merge findings from different enclosing symbols
                  into one group even if same file.
Inputs/artifact refs: cap = 5 findings / 1,500 payload tokens per group (config-overridable); a group
                  inherits the max rank_key of its members (from X.3).
Expected output schema: Go package `group` exporting Partition(findings) []Group, where Group carries
                  {path, enclosing_symbol, members, proximity_class ∈ Nucleus|Cluster|Orbit|Sprawl|
                  Fragment}.
Validation/evidence required: unit test asserting same-file-different-symbol findings never co-occur
                  in one group; cap-overflow spills into a second group, never truncates silently.
Stop condition:   Tests green.
Why this model:   Bounded partitioning logic — default strong-worker lane.
```

```text
Step ID:          X.5
Phase/group:      parallel group 2
Depends on:        X.2
Backend/model:    Claude Code subagent (sonnet)
Objective:        Implement the pre-generation triage gate: one cheap model call per sast_static_only
                  finding, verdict in {true_positive, false_positive, insufficient_context}.
Scope and files:  WRITE internal/remediation/triage/**.
                  READ research/24 §C, Recommendation item 7; plan/00-SPINE.md §S1 Requirement #4a.
Forbidden actions: MUST skip this gate entirely for evidence_class=dast_confirmed findings (they carry
                  a proof already). Must not let a false_positive verdict reach the coding agent. Must
                  not treat this gate's verdict as a merge signal — it only gates entry to generation.
Inputs/artifact refs: uses backend.Client from X.2, pointed at the small adjudicator model (Qwen3.5-2B
                  or Gemma-4 per spine S4, config-selected, not hard-coded here).
Expected output schema: Go package `triage` exporting Adjudicate(finding) Verdict; false_positive →
                  ledger.MarkState(FALSE_POSITIVE); insufficient_context → report-only, no generation.
Validation/evidence required: unit test with a stub backend confirming dast_confirmed findings never
                  invoke Adjudicate(); integration test against a fixed labeled sample measuring
                  precision/recall so the project has its own number instead of inheriting the Tencent
                  76%-FP baseline.
Stop condition:   Tests green; the "skip for dast_confirmed" branch has explicit coverage.
Why this model:   Security-relevant gate (it is "the only thing between a false positive and a
                  committed code change" per spine S1) but implementation itself is bounded —
                  sonnet default worker, escalated to a cross-family critic at X.7 per the mandatory
                  security-review gate.
```

```text
Step ID:          X.6
Phase/group:      parallel group 2
Depends on:        X.4
Backend/model:    Claude Code subagent (sonnet)
Objective:        Implement the prompt builder: fixed section order, hard token budget with abort.
Scope and files:  WRITE internal/remediation/prompt/**.
                  READ research/24 Recommendation item 1 and consumption-protocol step 12.
Forbidden actions: Never exceed 16,000 total tokens (abort → SPLIT_REQUIRED). Never batch across
                  files inside one prompt. Never include a whole advisory — excerpt only, ≤800 tok.
Inputs/artifact refs: sections in fixed order: (a) protocol+format spec ~700 tok, (b) repo/build facts
                  ~300 tok, (c) group findings ≤1,500 tok, (d) advisory excerpt ≤800 tok, (e) enclosing
                  symbol ±40 lines (whole-file only if <300 lines) ≤6,000 tok, (f) DAST reproduction
                  for dast_confirmed groups.
Expected output schema: Go package `prompt` exporting Build(group) (string, tokenCount, error); error
                  when tokenCount > 16,000; a Warning field when > 12,000.
Validation/evidence required: unit test asserting section order is fixed and unconditional; boundary
                  tests at 12,000 and 16,000 tokens.
Stop condition:   Tests green.
Why this model:   Bounded formatting/budget logic — default strong-worker lane.
```

```text
Step ID:          X.7
Phase/group:      serial
Depends on:        X.2, X.5
Backend/model:    OpenCode route: openai/gpt-5.5
Objective:        Cross-family security critique of the triage gate and the pluggable backend client.
Scope and files:  READ internal/remediation/triage/**, internal/remediation/backend/**. WRITE: none —
                  findings returned as text to the orchestrator for follow-up.
Forbidden actions: Do not modify source. Do not approve a design that lets a false_positive verdict
                  reach generation, or that defaults trust_tier to public_hosted.
Inputs/artifact refs: research/04 Risks ("Anvil must warn loudly..."); research/24 Recommendation
                  item 7.
Expected output schema: Structured critique: {pass|fail per forbidden-action check, disclosure-risk
                  assessment of the backend warning copy, any bypass path found}.
Validation/evidence required: Explicit statement of whether the dast_confirmed skip is unconditionally
                  enforced (code path, not comment).
Stop condition:   Critique delivered; reroute once to a different OpenCode route if this one times out
                  or returns malformed output, per 00-ROUTING.md rerouting rule.
Why this model:   Cross-family critique is a hard requirement for Anthropic-written security-relevant
                  code (00-ROUTING.md); this is a false-positive gate and a data-disclosure boundary —
                  both qualify.
```

```text
Step ID:          X.8
Phase/group:      serial
Depends on:        X.1
Backend/model:    Claude Code subagent (opus)
Objective:        Build the consumption controller skeleton: detect-and-lease, persist-before-work,
                  base-commit snapshot, and cold-start-vs-resume dedupe (protocol steps 1–5).
Scope and files:  WRITE internal/remediation/consume/controller.go, consume/dedupe.go, consume/snapshot.go.
                  READ research/24 "The consumption protocol" steps 1–5 in full; plan/00-SPINE.md §S10.
Forbidden actions: Do not build a second top-level state machine — this registers under the single
                  named scan controller (spine S10), it does not run standalone. Do not skip the
                  persist-before-model-call ordering (protocol step 2) — the buffer is a cache only.
Inputs/artifact refs: dedupe = union of `git log --grep='^Anvil-Finding:' --format=%B base..HEAD` and
                  `SELECT finding_fingerprint, state FROM anvil_ledger WHERE audit_id=?` (X.1).
Expected output schema: Go package `consume` exporting Controller.Run(auditID) that performs lease,
                  persist, snapshot base_commit_sha, create anvil/fix/<audit_id>, and return the
                  already-done set plus cold-start/resume flag.
Validation/evidence required: integration test simulating an interrupted run (kill mid-loop) followed
                  by a second Run() call against the same base_commit_sha, asserting zero duplicate
                  work and correct cold-start-vs-resume detection.
Stop condition:   Tests green; resume path exercised, not just cold start.
Why this model:   This is the one genuinely hard parallel sub-problem in the tier — reconciling two
                  independent sources of truth (git trailers, DB ledger) into one dedupe set under
                  crash/resume semantics — escalated to opus per 00-ROUTING.md guard ("the one
                  genuinely hard parallel sub-problem").
```

```text
Step ID:          X.9
Phase/group:      serial
Depends on:        X.8, X.3, X.4
Backend/model:    Claude Code subagent (sonnet)
Objective:        Wire ranking and grouping into the controller: cut the queue by budget, order
                  execution, mark groups LEASED (protocol steps 6–11 minus the triage gate itself).
Scope and files:  WRITE internal/remediation/consume/queue.go.
                  READ research/24 protocol steps 6–11; Table 4 (throughput budget — treat as a
                  placeholder to be replaced by a measured tok/s, per that table's own caveat).
Forbidden actions: Do not hard-code the throughput budget numbers from research/24 Table 4 — they are
                  explicitly flagged as unmeasured placeholder arithmetic; read tok/s from a runtime
                  measurement hook (stubbed here, wired to real telemetry by the serving tier).
Inputs/artifact refs: order = stable-sort in-budget groups by (path, rank_key desc); everything past
                  the cut → SKIPPED_BUDGET, never silently dropped.
Expected output schema: Controller.CutAndOrder(groups) ([]Group /*in-budget, ordered*/, []Group
                  /*SKIPPED_BUDGET*/).
Validation/evidence required: test asserting SKIPPED_BUDGET groups are written to the ledger (not
                  dropped) and appear in the eventual report.
Stop condition:   Tests green.
Why this model:   Integration wiring over already-specified components — default strong-worker lane.
```

```text
Step ID:          X.10
Phase/group:      serial
Depends on:        X.2, X.5, X.6, X.9
Backend/model:    Claude Code subagent (sonnet)
Objective:        Implement the bounded 3-turn generation loop (turn 1 generate, turn 2 anchor-repair)
                  with the prompt-injection containment boundary enforced at the process level.
Scope and files:  WRITE internal/remediation/consume/generate.go.
                  READ research/24 Recommendation item 3 and protocol steps 12–15; plan/00-SPINE.md §S7
                  prompt-injection paragraph.
Forbidden actions: The generation process MUST hold no credentials and no network handle — enforce by
                  running it in a context with no repo-write token and no egress, not by convention.
                  Every advisory/repo-derived string entering the prompt must already carry
                  `anvil/trust: untrusted` and be declared non-instructional in the system prompt,
                  pinned to this one task. No free-form shell tool in the default profile — only
                  read_region and run_validation are exposed, and run_validation is X.14/X.15's
                  concern, not this step's. k=2 sampling for tier-0 groups, k=1 otherwise. Restate the
                  full task each turn — do not rely on conversation history for correctness.
Inputs/artifact refs: SEARCH/REPLACE output format only (research/24 §F — best measured apply fidelity
                  at every model size).
Expected output schema: Generate(group) → raw SEARCH/REPLACE block text (unvalidated — X.11 validates
                  it). Turn cap = 3 total across generate + repair.
Validation/evidence required: process-isolation test proving the generation call path has zero
                  environment variables matching credential/token patterns and zero open sockets other
                  than the model backend connection itself.
Stop condition:   Tests green; isolation test is the hard gate, not optional.
Why this model:   Bounded loop implementation against a fully specified contract — default strong-
                  worker lane; carries a mandatory cross-family critic at X.13 because it is the
                  prompt-injection attack surface.
```

```text
Step ID:          X.11
Phase/group:      serial
Depends on:        X.10
Backend/model:    Claude Code subagent (sonnet)
Objective:        Implement the in-process SEARCH/REPLACE anchor validator — no repo writes.
Scope and files:  WRITE internal/remediation/edit/anchor.go.
                  READ research/24 protocol step 14–15.
Forbidden actions: Never touch the working tree in this step — validation is purely against in-memory
                  file content. Never accept a SEARCH block that matches zero or ≥2 times.
Inputs/artifact refs: 0 matches → ANCHOR_MISS (feed back to turn 2 with the failing anchor quoted);
                  ≥2 matches → AMBIGUOUS; whole-file rewrite fallback only if file <300 lines AND turn 2
                  also fails (research/24 §F, Table 1 "Emergency fallback only").
Expected output schema: Validate(fileContent, block) (Result{OK|ANCHOR_MISS|AMBIGUOUS}, matchSpan).
Validation/evidence required: property test with synthetic files proving exact-substring-exactly-once
                  semantics; fallback path tested at the 300-line boundary.
Stop condition:   Tests green.
Why this model:   Deterministic string-matching logic — default strong-worker lane.
```

```text
Step ID:          X.12
Phase/group:      serial
Depends on:        X.11
Backend/model:    Claude Code subagent (sonnet)
Objective:        Synthesize a unified diff carrying blob identity from the accepted S/R edit, and wrap
                  `git apply --check` / `--3way --index`.
Scope and files:  WRITE internal/remediation/edit/apply.go.
                  READ research/24 §D and protocol step 16; plan/00-SPINE.md §S7 (harness applies, never
                  the model) and MUST-COVER note on `--3way` degrading without `index` lines.
Forbidden actions: NEVER pass `--reject` — atomicity is the safety property Anvil relies on. The diff
                  MUST be synthesized by the harness against the known blob (compute the blob SHA of the
                  current file, embed `index <old>..<new>` lines) — never forward a model-authored diff
                  as-is, because it lacks blob identity and silently degrades `--3way` to a plain apply.
                  On conflict markers, do not attempt to rebase the diff — discard and re-enter with
                  current file content, one retry only.
Inputs/artifact refs: `git apply --check` dry run first, then `git apply --3way --index`.
Expected output schema: Apply(edit, baseSHA) (CommitReady{diff, blobSHAs}, error ∈
                  {CHECK_FAILED, CONFLICT_MARKERS, OK}).
Validation/evidence required: integration test against a real git worktree proving (a) a synthesized
                  diff with correct `index` lines 3-way-merges cleanly on a file that moved slightly
                  since scan time, (b) `--reject` is never invoked anywhere in the call graph (grep-
                  based CI check), (c) the one-retry-then-abandon path is exercised.
Stop condition:   Tests green, including the negative grep-for---reject check.
Why this model:   Correctness-critical but fully specified against documented git semantics — default
                  strong-worker lane; reviewed by the cross-family critic at X.13.
```

```text
Step ID:          X.13
Phase/group:      serial
Depends on:        X.10, X.11, X.12
Backend/model:    OpenCode route: openai/gpt-5.5
Objective:        Cross-family critique of the generation loop, anchor validator, and apply wrapper as
                  one unit — this is Anvil's prompt-injection attack surface and its only repo-write path.
Scope and files:  READ internal/remediation/consume/generate.go, internal/remediation/edit/**.
                  WRITE: none — findings returned as text.
Forbidden actions: Do not modify source. Do not sign off if any path lets the model apply an edit
                  directly, or if `--reject` appears anywhere, or if the generation step can reach a
                  credential or a network socket other than the model backend.
Inputs/artifact refs: plan/00-SPINE.md §S7; research/11 §H (documented Claude Code GitHub Action
                  exfiltration chain) as the negative example to check against.
Expected output schema: Structured critique enumerating any path where untrusted advisory/repo text
                  could reach an instruction-following context, and any path where the harness does not
                  strictly own the apply step.
Validation/evidence required: explicit sign-off statement or a blocking list of required fixes.
Stop condition:   Critique delivered; reroute once on timeout/malformed output.
Why this model:   Mandatory cross-family critic for security-relevant, Anthropic-written code
                  (00-ROUTING.md); this is also explicitly flagged by the MUST-COVER prompt-injection
                  requirement as needing a critic before acceptance.
```

```text
Step ID:          X.14
Phase/group:      serial
Depends on:        X.12
Backend/model:    Claude Code subagent (sonnet)
Objective:        Implement validation gates G2–G6: disallowed-path check, patch size limit, build,
                  existing test suite (zero new failures).
Scope and files:  WRITE internal/remediation/validate/gates.go.
                  READ research/11 "The minimum validation gate" Phase 0–2 (gates 4–8); plan/00-SPINE.md
                  §S5 (CodeQL exclusion — do not use CodeQL as the build/rescan tool).
Forbidden actions: No gate here may be skipped by configuration except the size-limit threshold value
                  itself, which is config (default ≤3 files / ≤100 changed lines). Disallowed-path deny-
                  list must include `.github/workflows/**`, CI config, lockfiles, dependency manifests,
                  signing keys, `.git/**`, Anvil's own config. Must run in an isolated environment with
                  no network (build step).
Inputs/artifact refs: gate order fixed: disallowed-path → size → build → test-suite.
Expected output schema: RunGates(commitReady) GateResult{gate, pass, evidence} for each of G2–G6,
                  first hard-fail short-circuits.
Validation/evidence required: unit tests per gate with synthetic failing/passing fixtures; explicit
                  test that a patch touching `.github/workflows/` is rejected.
Stop condition:   Tests green.
Why this model:   Well-specified, bounded gate implementation — default strong-worker lane.
```

```text
Step ID:          X.15
Phase/group:      serial
Depends on:        X.14
Backend/model:    Claude Code subagent (sonnet)
Objective:        Implement the exploit-oracle gate (G7) with mandatory payload mutation, and the
                  opt-in, campaign-decoupled fuzz/soak gate (G8).
Scope and files:  WRITE internal/remediation/oracle/**.
                  READ research/11 §E, Table 1 gates 6–7; plan/00-SPINE.md §S7 ("only a DAST
                  reproduction that now fails earns verified fixed"); research/16 Recommendation
                  ("fuzzing cannot be in Anvil's main scan loop... campaign service, fully decoupled").
Forbidden actions: G7 may only be satisfied by re-executing the stored DAST reproduction (and mutated
                  variants) against the patched code — a clean SAST/Semgrep rescan must NEVER be
                  accepted as evidence for this gate (spine S7 is explicit; detectors reach only
                  10.16–13.82% TPR on vulnerabilities surviving an incomplete patch). G8 must run as a
                  decoupled campaign (default honggfuzz, Apache-2.0) writing crashes to the DB for the
                  *next* scan — never AFL++ linked in-process (AGPL-3.0, spine S5 hard exclusion), and
                  never inside the 8-hour window by default.
Inputs/artifact refs: mutation set = ≥1 payload variant beyond the recorded request/exploit script
                  (research/24 Risks: "mutate the reproduction... before accepting, or the model learns
                  to defeat the one recorded request").
Expected output schema: ExploitOracle(reproduction, patchedTarget) Result{no_reproducer |
                  still_exploitable | fixed_original_only | fixed_incl_mutants}; only fixed_incl_mutants
                  may set the "verified fixed" label. Absence of a reproducer → UNVERIFIED_SECURITY,
                  not a hard fail of the group.
Validation/evidence required: test proving a patch that only special-cases the exact recorded payload
                  (narrow fix) is rejected once mutation is applied; test that G8 never blocks the main
                  loop (it is invoked async/opt-in only).
Stop condition:   Tests green, including the narrow-fix-detection regression test.
Why this model:   Bounded, fully specified against explicit spine language — default strong-worker
                  lane; reviewed by the cross-family critic at X.16 because it is the tier's primary
                  correctness claim.
```

```text
Step ID:          X.16
Phase/group:      serial
Depends on:        X.14, X.15
Backend/model:    OpenCode route: openai/gpt-5.5
Objective:        Cross-family critique of the validation gate ladder implementation, focused on
                  over-claiming: does any gate's code path label a result more strongly than the
                  evidence supports?
Scope and files:  READ internal/remediation/validate/**, internal/remediation/oracle/**. WRITE: none.
Forbidden actions: Do not modify source. Do not sign off if a passing G10 (diff-aware rescan) or G6
                  (test suite) can, anywhere in the code, produce a "verified fixed" label — only G7
                  with the mutation set may.
Inputs/artifact refs: research/11 §F ("random selection beats all six SOTA overfitting-detection tools
                  in 71–96% of cases" — no overfit classifier may exist in this codebase); the
                  Validation Gate Ladder section below as the acceptance spec.
Expected output schema: Structured critique confirming or rejecting the "no gate over-claims" property,
                  gate-by-gate.
Validation/evidence required: explicit line-by-line confirmation that the label-setting code path is
                  gated only on G7's fixed_incl_mutants result.
Stop condition:   Critique delivered; reroute once on timeout/malformed output.
Why this model:   Security/correctness-critical validation logic requires an independent, different-
                  family critic per 00-ROUTING.md; this is also the exact failure the research corpus
                  documents as most dangerous (a plausible-but-wrong patch passing weak validation).
```

```text
Step ID:          X.17
Phase/group:      serial
Depends on:        X.12, X.14, X.15, X.1
Backend/model:    Claude Code subagent (sonnet)
Objective:        Implement commit-or-rollback with git trailers, the diff-aware rescan gate (G10), and
                  lease-theft mitigation (conditional commit in the same DB transaction as the ledger
                  state check).
Scope and files:  WRITE internal/remediation/consume/commit.go.
                  READ research/24 protocol steps 18, and Risks "Lease theft can double-apply."
Forbidden actions: Rollback scope is the group, NEVER the run (`git reset --hard <group_parent>` only).
                  The final commit must be conditional on the ledger row still being LEASED by this
                  worker, checked and updated inside one DB transaction — this is the only fix for the
                  lease-theft double-apply risk research/24 names explicitly. G10's rescan must never be
                  the sole basis for a "verified fixed" label (see X.15/X.16) — it may only block on
                  failure (new finding introduced), not grant success on its own.
Inputs/artifact refs: commit trailers: `Anvil-Finding: <fingerprint>` (one per group member),
                  `Anvil-Audit: <audit_id>`, `Anvil-Idempotency-Key: <sha256>`.
Expected output schema: CommitOrRollback(group, gateResults) → ledger state VALIDATED |
                  FAILED_VALIDATION, with all trailers present on success.
Validation/evidence required: integration test with two concurrent "workers" racing past an expired
                  lease, asserting only one commit lands; trailer-presence schema test.
Stop condition:   Tests green, including the concurrency race test.
Why this model:   Bounded transactional logic against a fully specified failure mode — default strong-
                  worker lane.
```

```text
Step ID:          X.18
Phase/group:      serial
Depends on:        X.17
Backend/model:    Claude Code subagent (sonnet)
Objective:        Implement post-commit re-anchoring: recompute fingerprints for remaining findings in
                  touched files, and classify FIXED_INCIDENTALLY / moved-locus / REGRESSION_INTRODUCED.
Scope and files:  WRITE internal/remediation/reanchor/**.
                  READ research/24 protocol step 19; plan/00-SPINE.md §S6 fingerprint requirement.
Forbidden actions: Do not redefine the fingerprint algorithm — call the record tier's exported
                  function. A newly-appearing finding in a touched file MUST enqueue as
                  REGRESSION_INTRODUCED at tier-0 priority, not silently merge into the current run's
                  backlog at normal priority.
Inputs/artifact refs: re-run the small SAST model on the touched file only, per research/24 step 19.
Expected output schema: Reanchor(touchedFiles) → {fixed_incidentally: [...], moved: [...],
                  regressions: [...]}; regressions call back into X.9's queue with forced tier-0 rank.
Validation/evidence required: test with a synthetic "patch introduces a new sink" fixture proving
                  REGRESSION_INTRODUCED is enqueued at tier-0, not appended at the tail.
Stop condition:   Tests green.
Why this model:   Bounded integration logic reusing an external fingerprint contract — default strong-
                  worker lane.
```

```text
Step ID:          X.19
Phase/group:      serial
Depends on:        X.8, X.9, X.17, X.18
Backend/model:    Claude Code subagent (sonnet)
Objective:        Implement renew-or-yield wall-clock handling and wire the whole consumption
                  controller into the single named scan controller (spine S10) as a registered
                  sub-machine.
Scope and files:  WRITE internal/remediation/consume/schedule.go.
                  READ research/24 protocol steps 20–22; plan/00-SPINE.md §S10.
Forbidden actions: Below 15 minutes remaining in the window, stop starting new groups — flush ledger,
                  write report, leave every unstarted group PENDING (never mark it failed). Do not
                  register a second top-level daemon/entrypoint — this must attach to the existing scan
                  controller's lifecycle hooks.
Inputs/artifact refs: 8-hour buffer-lifetime window (spine S1 #5, a claim timeout not a deletion
                  policy for the DB copy).
Expected output schema: Controller registers Start/Resume/Yield hooks with the scan-controller
                  interface (owned by orchestration tier — this step implements the remediation side of
                  that interface, not the interface itself).
Validation/evidence required: test simulating window exhaustion mid-run, asserting all unstarted groups
                  remain PENDING and are picked up by a second Run() against the same base_commit_sha.
Stop condition:   Tests green; no standalone entrypoint exists outside the scan-controller registration.
Why this model:   Integration wiring against an already-specified contract — default strong-worker
                  lane.
```

```text
Step ID:          X.20
Phase/group:      serial
Depends on:        X.17, X.18, X.3
Backend/model:    Claude Code subagent (sonnet)
Objective:        Implement the PR lifecycle: draft PR with evidence-vector body, disposition report,
                  rate limiting, and the credentialed-push step as a separate process/token scope.
Scope and files:  WRITE internal/remediation/pr/**.
                  READ research/11 "Phase 3 — the PR itself" (gates 13–16); plan/00-SPINE.md §S7
                  (credentialed push separate process, separate token scope).
Forbidden actions: This package MUST NOT hold repo-write credentials in the generation process's
                  environment — the push step is a separate process invoked with only a diff and a
                  narrowly-scoped token (open-PR permission only, never merge permission — enforce by
                  token scope, not by application logic). Never call any merge API. Default open-PR cap
                  per repo per period = 3 (config-overridable).
Inputs/artifact refs: PR body embeds the evidence vector (research/11 §"Confidence expression"), gate
                  results table, advisory source URL + licence, model ID + revision, exact reproducer
                  command, and the buffer ID of the source audit record.
Expected output schema: OpenDraftPR(commitReady, evidenceVector) → PR{url, labelled_unverified_security
                  bool}; rate limiter returning SKIPPED_BUDGET-equivalent when the per-repo cap is hit.
Validation/evidence required: test proving the push credential's token scope literally cannot call a
                  merge endpoint (assert on the OAuth scope string, not just on application logic not
                  calling it); test that a group without a G7 pass opens a PR titled/labeled
                  "unverified-security", never "fixed".
Stop condition:   Tests green, including the token-scope assertion.
Why this model:   Bounded implementation against a fully specified authorization boundary — default
                  strong-worker lane; reviewed by the cross-family critic at X.21 because this is the
                  tier's only externally-visible, credentialed, write-adjacent action.
```

```text
Step ID:          X.21
Phase/group:      serial
Depends on:        X.20
Backend/model:    OpenCode route: openai/gpt-5.5
Objective:        Cross-family critique of the PR lifecycle and the credential/token-scope separation.
Scope and files:  READ internal/remediation/pr/**. WRITE: none.
Forbidden actions: Do not modify source. Do not sign off if the push credential and the generation
                  process share a process, an environment, or a token with merge scope.
Inputs/artifact refs: plan/00-SPINE.md §S7; research/11 §I (GitHub's own guardrails as the floor, not
                  the ceiling) as the comparison baseline.
Expected output schema: Structured critique with an explicit pass/fail on "no auto-merge is reachable
                  from any code path" and "credential separation is structural, not conventional."
Validation/evidence required: sign-off statement or blocking findings list.
Stop condition:   Critique delivered; reroute once on timeout/malformed output.
Why this model:   Authorization-boundary code is one of the explicit triggers for a mandatory different-
                  family critic per 00-ROUTING.md's review-gates table ("auth, payments, deployment").
```

```text
Step ID:          X.22
Phase/group:      serial
Depends on:        X.15, X.20
Backend/model:    Claude Code subagent (sonnet)
Objective:        Implement the regression re-check scheduler and the PR-acceptance-rate metric.
Scope and files:  WRITE internal/remediation/regression/**, internal/remediation/metrics/pr_acceptance.go.
                  READ research/11 "Regression-check path" and Risks item 13 (curl bounty shutdown);
                  research/24 Risks (post-incomplete-patch TPR 10.16–13.82%).
Forbidden actions: Never trust an upstream "fixed" label as ground truth — always re-execute Anvil's
                  own stored reproducer. Never compute PR acceptance rate as findings-per-scan; it is
                  strictly accepted / (accepted + rejected + stale-closed) per repo and globally.
Inputs/artifact refs: schedule cadence is config (`.anvil/policy.yml`), not hard-coded; re-trigger fires
                  gate G7 (X.15) against current HEAD for every prior VALIDATED finding.
Expected output schema: Recheck(findingID) → reopen-at-T0 if reproducer still triggers, else no-op;
                  Metrics.PRAcceptanceRate(scope) float64, exposed for the dashboard/report.
Validation/evidence required: test proving a finding whose upstream/manual "fixed" label is stale (the
                  stored reproducer still triggers) is reopened at T0, not trusted.
Stop condition:   Tests green.
Why this model:   Bounded scheduler + metric implementation — default strong-worker lane.
```

```text
Step ID:          X.23
Phase/group:      serial
Depends on:        X.1–X.22 (all prior implementation steps)
Backend/model:    Claude Code subagent (sonnet)
Objective:        Build the conformance/integration test harness proving the Exit Criteria below,
                  end to end, against a fixed corpus.
Scope and files:  WRITE internal/remediation/consume/consume_test.go (integration),
                  test/remediation_integration_test.go, test/testdata/remediation-fixed-corpus/**.
                  READ "## Exit Criteria" below.
Forbidden actions: Do not mark any Exit Criterion satisfied without a corresponding automated
                  assertion — no "manually verified" entries.
Inputs/artifact refs: a fixed, versioned corpus (small synthetic repo + 3–5 synthetic findings spanning
                  dast_confirmed, sast_reachable, sast_static_only, and one CVE-less finding with all
                  bonus terms null) checked into test/testdata/.
Expected output schema: A test suite where each Exit Criterion below maps to exactly one named test.
Validation/evidence required: full suite green, including the idempotent-double-run test, the
                  --reject-never-invoked grep check, and the credential/network-isolation test for the
                  generation sandbox.
Stop condition:   All Exit Criteria have a passing, named test.
Why this model:   Integration-test authorship spanning many packages against a fully specified
                  acceptance list — default strong-worker lane, not mechanical enough for haiku given
                  the cross-package DB/git fixtures involved.
```

```text
Step ID:          X.24
Phase/group:      serial
Depends on:        X.23 (and transitively all prior steps)
Backend/model:    OpenCode route: openai/gpt-5.5
Objective:        Final whole-tier security and correctness review before this tier is accepted as
                  built: auto-merge unreachability, credential/network isolation, prompt-injection
                  containment, and validation-gate honesty, reviewed as one system.
Scope and files:  READ all of internal/remediation/**. WRITE: none — findings returned as text; the
                  orchestrator files any required fixes as follow-up steps.
Forbidden actions: Do not modify source. Do not approve if any single code path can reach a merge
                  action, or if the generation process can reach a credential or network handle, or if
                  any gate's success path can set "verified fixed" without G7's fixed_incl_mutants
                  result.
Inputs/artifact refs: this entire document as the acceptance spec, plus plan/00-SPINE.md §S7.
Expected output schema: Final structured review: {invariant, verified(bool), evidence-pointer} for each
                  of the four invariants above, plus any open findings.
Validation/evidence required: explicit pass on all four invariants, or a blocking list routed back to
                  the relevant step for a fix-and-reroute cycle.
Stop condition:   All four invariants explicitly pass, or the tier is not considered built.
Why this model:   High-stakes final judgment over security-relevant, migration-adjacent, auth-adjacent
                  code — the paid-route justification 00-ROUTING.md requires ("high-stakes final
                  judgment... not by default"), and cross-family because the majority of the tier was
                  Anthropic-written.
```

---

## Validation Gate Ladder

Ordered. Gates G0–G13 apply to a single fix group's candidate patch. **A pass never claims more than
its own row** — the specific failure mode the research corpus documents as most dangerous is a gate
whose result is reported as stronger evidence than it actually is.

| # | Gate | What it actually proves | What it does NOT prove | Blocking? |
|---|---|---|---|---|
| G0 | Triage gate (pre-generation, skipped for `dast_confirmed`) | This cheap model's judgment that the alarm is plausible given the snippet | That the finding is real (the adjudicator itself is ~83–93% precise on the studied corpus, unmeasured on Anvil's own); that a `true_positive` verdict is exploitable | Yes, except `dast_confirmed` skip |
| G1 | Ledger/trailer dedupe | This fingerprint@base_commit_sha was not already processed | That the finding is still valid — code may have drifted; re-anchoring (post-commit) handles that, not this gate | Yes |
| G2 | SEARCH/REPLACE anchors uniquely + synthesized diff applies (`--check`, `--3way`) | The edit is syntactically well-formed and merges against the exact scanned blob | That the edit is semantically correct or safe | Yes |
| G3 | Disallowed-path / blast-radius check | The diff touches only allow-listed paths | That allow-listed edits are themselves benign — injected content can still target allowed source files | Yes |
| G4 | Patch size limit | The change is reviewable in scale | Correctness; the threshold is engineering judgement, not measured evidence | Yes |
| G5 | Builds/compiles cleanly, isolated, no network | Syntactic + type validity | Semantics — 13.2% of LLM security patches fail even this | Yes |
| G6 | Existing test suite passes, zero new failures | No observed functional regression against the existing suite | That the vulnerability is fixed — 10.3% of patches pass the full suite and remain exploitable (the "deceptive patch" class); mean functionality-preservation (0.832) is 3.3× mean security-achievement (0.251) | Yes |
| G7 | Exploit oracle: stored DAST reproduction **and mutated payload variants** now fail | The specific vulnerability instance, and near variants in the mutation set, no longer reproduce | Absence of the vulnerability class generally; variants outside the mutation set; a narrow model-learned defeat of only the tested requests if the mutation set is thin | Yes, **only** for the "verified fixed" label. No reproducer → PR still opens, labeled `unverified-security`, and G11 (human review) becomes non-waivable |
| G8 | Fuzz/soak budget, opt-in, decoupled campaign (default 10 min, honggfuzz) | The patch is not narrowly special-cased to the one known input, within budget | Anything, if the budget finds no crash (absence of evidence); runs outside the 8-hour window by design | No — config-gated, campaign-decoupled, never in the main loop |
| G9 | Differential/behavioral equivalence vs. reference | *Deferred — not implemented in v1.* Would prove the fix did not quietly delete functionality outside the vulnerable path | Nothing — do not claim this gate exists in the report until it is built (tracked in Open Questions) | N/A in v1 |
| G10 | Diff-aware rescan: originating finding gone AND no new finding introduced | Anvil's own detector, re-run, agrees | **Little** — this is the most Goodhartable gate in the ladder: the same detector that raised the finding adjudicates its own fix, and post-incomplete-patch detection TPR is only 10.16–13.82%. **Never sufficient alone; never substitutes for G7.** | Yes — but a pass here can never upgrade a group's label; only a failure here can downgrade one |
| G11 | Human review (mandatory, structural — Anvil holds no merge token) | Nothing automatically — it is the backstop | That the patch is correct merely by being opened; correctness is measured externally via PR acceptance rate | Yes, structurally (token-scope enforced, not policy-toggle) |
| G12 | Signed commit + machine-readable provenance in PR body | Attribution/auditability chain back to the audit record | Patch correctness or authenticity of the underlying finding | Yes (mechanical, near-zero cost) |
| G13 | Rate limit / back-pressure (default 3 open PRs/repo) | Anvil will not exceed a configured number of simultaneously open proposals per repo | Quality of any individual proposal — this is a maintainer-channel-capacity control, not a correctness gate | Yes (queue-level; excess groups go to `SKIPPED_BUDGET`/`PENDING`, never silently dropped) |

**The single rule that governs the whole ladder:** only G7 with `fixed_incl_mutants` may set the
"verified fixed" label (spine S7). G6 and G10 passing, individually or together, **never** does.

---

## Ranking Contract

**The CVE-less path is the default, not a fallback.** Most first-party findings from Anvil's own SAST/
DAST tiers have no CVE and therefore no EPSS, no KEV membership, and no CVSS vector — research/24's own
Risks section states this explicitly. research/24's Table 3 recommendation (KEV, then EPSS, then
reachability, then CVSS) is **superseded** by the spine's correction and is not implemented as written.

```
rank_key = (
    evidence_class == 'dast_confirmed',   -- primary tier 0: a proof, not a prediction
    reachable,                            -- call_path_found > entry_point_unknown > not_analyzed
    cwe_class_prior,                      -- config table, TP-and-fixable prior per CWE class;
                                           -- unknown CWE defaults to 0.5, never null
    proximity_rank,                       -- Nucleus > Cluster > Orbit > Sprawl > Fragment (Hunk4J)
)
-- descending lexicographic on the four terms above. This tuple alone fully orders every
-- CVE-less finding, which is the majority case.

-- Bonus terms — nullable, optional at install (EPSS especially: no SPDX licence, terms-of-use
-- language only, per research/24 Gaps). They break ties ONLY among rows with an identical primary
-- 4-tuple; they never override it:
    kev_member,            -- bool or null
    kev_ransomware_use,    -- bool or null
    epss_score,            -- float or null
    cvss_base,              -- float or null
```

All weights and the `cwe_class_prior` table come from `.anvil/policy.yml` (requirement 7 — config,
never code). At launch, `cwe_class_prior` has no established source and must be seeded uniformly or
from published per-CWE fix-rate data (e.g. research/11 S12's per-CWE spread: 45% CWE-835, 0% CWE-20)
until Anvil accumulates its own outcome data — see Open Questions.

**Queue cut and re-cut (spine S6):** every version bump re-cuts the queue. On every re-cut, reserve a
configurable fraction (default 50%, `.anvil/policy.yml: recut_reserve_fraction`) of the *remaining*
budget for late-arriving `dast_confirmed` findings — otherwise incremental publication silently
inverts the priority scheme, because nothing is DAST-confirmed when a queue is first cut.

---

## Failure Dispositions

Every terminal or long-lived state a finding can reach, and what the maintainer sees.

| Disposition | Trigger | What the maintainer sees |
|---|---|---|
| `VALIDATED` | Passed G2–G6, G10, G11–G13, **and** G7 with `fixed_incl_mutants` | A normal PR, evidence vector attached, explicitly labeled "verified fixed" |
| `VALIDATED — unverified-security` | Passed G2–G6, G10, G11–G13; no reproducer existed for G7 | A **draft** PR, title/body explicitly say "unverified-security — no exploit oracle available"; never called "fixed" |
| `FAILED_VALIDATION` | Any blocking gate (G3–G6, G10) failed | No PR opened. Patch text retained as a human-readable proposal in Anvil's report only — never applied to any branch |
| `FAILED_FORMAT` | Anchor validation failed twice; whole-file fallback ineligible (file ≥300 lines) or also failed | Group abandoned; report shows the underlying finding (path/line/CWE) with no patch attached |
| `FALSE_POSITIVE` | Triage gate (G0) verdict | Dropped before generation; not shown by default, visible only in an optional triage audit log |
| `INSUFFICIENT_CONTEXT` | Triage gate (G0) verdict | Demoted to report-only: "found, needs manual review, model could not adjudicate" |
| `SKIPPED_BUDGET` | In-scope but past the queue cut (G13 / budget) | "Found, not fixed this run — queued for next scan." Never silently dropped |
| `SPLIT_REQUIRED` | Prompt would exceed the 16,000-token abort ceiling | "Too large for automatic remediation" in the report; candidate for manual split |
| `REGRESSION_INTRODUCED` | Post-commit re-anchor finds a brand-new finding in a touched file | Called out explicitly against the commit that introduced it; auto-enqueued at tier-0 for the next cycle |
| `FIXED_INCIDENTALLY` | Post-commit re-anchor: original fingerprint no longer resolves, re-scan confirms it is gone | Folded into the triggering PR's evidence vector as a bonus, not a separate PR |
| `PENDING` | Not yet reached; no lease taken | Invisible until picked up by the next matching run against the same `base_commit_sha` |
| `LEASED` / lease-expired / stolen | Worker crash bookkeeping | Operator-dashboard only, never on the PR surface |
| `WITHDRAWN` / `SUPERSEDED` | (a) maintainer rejects the draft PR — reason recorded, feeds PR-acceptance-rate and down-weights that CWE's prior; (b) the regression re-checker finds a merged fix's reproducer still triggers — Anvil reopens at T0 and posts a follow-up; (c) a later re-cut produces a better patch for the same finding — the old draft PR is closed with a comment linking the new one | A closed PR with an explanatory comment — never a silent disappearance |
| PR-acceptance-rate (rollup, not per-finding) | `accepted / (accepted + rejected + stale-closed)`, per repo and globally | Exposed as Anvil's own success metric — the number the tier is designed to protect, per the curl bug-bounty-shutdown precedent |

---

## Exit Criteria

Objectively checkable; each maps to a named automated test authored in step X.23.

1. `go test ./internal/remediation/...` passes with no skipped security-relevant test.
2. A fixed corpus produces an identical fingerprint digest across two independent runs (conformance
   test against the record tier's shared fingerprint algorithm — this tier consumes, does not define).
3. CI grep confirms `git apply … --reject` is never invoked anywhere in `internal/remediation/**`.
4. No code path in `internal/remediation/**` calls a repository merge API — verified by static
   grep/AST check plus the X.24 review sign-off.
5. The generation step (X.10) runs with zero credential-shaped environment variables and zero open
   sockets other than the model backend connection — verified by a process-isolation test.
6. The credentialed push step (X.20) runs in a separate process from generation, with a token whose
   OAuth/API scope literally excludes merge permission — verified by asserting on the scope string.
7. Running the consumption controller twice against the same `audit_id` and `base_commit_sha` produces
   zero duplicate commits and zero duplicate ledger rows (idempotency test).
8. A finding with all four bonus rank terms null (the CVE-less majority case) is still fully ordered
   and reaches generation — unit test on the ranking contract.
9. Injecting a late `dast_confirmed` finding after an initial queue cut consumes only from the
   reserved `recut_reserve_fraction` budget, never displacing already-committed in-budget work.
10. A patch that only special-cases the exact recorded exploit payload is rejected once G7's mutation
    set is applied (narrow-fix regression test).
11. The "verified fixed" label is reachable in code **only** through G7's `fixed_incl_mutants` result —
    verified by the X.16 and X.24 critic sign-offs plus a static path-reachability check.
12. `backend.Warn()` fires for `trust_tier=public_hosted` and is silent for `self_hosted`/`user_remote`.
13. Every `VALIDATED` commit carries all three git trailers (`Anvil-Finding`, `Anvil-Audit`,
    `Anvil-Idempotency-Key`).
14. All Failure Dispositions in the table above have at least one reachable code path and one test.

---

## Pinned Versions And Licences

| Component | Role in this tier | Licence | Pinning requirement |
|---|---|---|---|
| `Qwen/Qwen3-Coder-Next` | Primary coding-agent weights (served behind the pluggable backend, config-selected) | Apache-2.0 | Pin exact revision SHA; archive LICENSE at that revision (spine S8 compliance mechanic) |
| `mistralai/Devstral-Small-2-24B-Instruct-2512` | Low-resource default coding-agent option | Apache-2.0 | Same pin-and-archive rule |
| `Qwen3.5-2B` / `google/gemma-4-*` | Triage-gate (G0) adjudicator, config-selected | Apache-2.0 (verify the specific Gemma 4 variant at selection time per spine S4 caveat — licence splits by parameter count within a family) | Pin exact revision SHA |
| llama.cpp / llama-server (or any OpenAI-compatible server) | Serving layer behind `internal/remediation/backend` | MIT | Not vendored; invoked over HTTP only |
| `git` (system) | Diff synthesis + `--3way --index` apply | GPL-2.0 (invoked as a subprocess, not linked) | System dependency, version-agnostic within modern git |
| honggfuzz | Opt-in campaign engine for gate G8 | Apache-2.0 | Preferred over AFL++ (AGPL-3.0-or-later, spine S5 hard exclusion) |
| Semgrep CE engine | Diff-aware rescan (gate G10), if used as the rescan tool | LGPL-2.1 | Engine only — **never** bundle `semgrep-rules` (Semgrep Rules License v1.0, internal-business-use only) |
| ARVO | Design pattern + offline validation corpus for gate G7's harness shape (C/C++ scope only) | BSD-2-Clause | Referenced as a pattern/eval corpus, not a runtime dependency |
| AutoPatchBench validation policy shape | Three-stage gate shape adopted for G7/G8 | MIT (PurpleLlama evals) | Design reuse only; no Llama-licensed weights are pulled in by this |
| CISA KEV feed | Optional bonus rank term | US federal government work; terms-of-use page not verified in-session (research/24 Gaps) | Optional at install; treat as advisory, not load-bearing |
| EPSS API/CSV | Optional bonus rank term | **No SPDX licence — terms-of-use language only** (research/24 Gaps) | **Must be optional at install time**, per MUST-COVER; do not make any gate depend on it being present |
| **Excluded by spine S5 — do not use in this tier** | CodeQL (as build/rescan tool), `opengrep/opengrep-rules`, AFL++ linked in-process, CIS Benchmark content | — | Hard exclusions; carried forward from spine, not re-litigated here |

---

## Open Questions

- **No measured batch-size-vs-patch-correctness curve for security fixes exists** (research/24 Gaps).
  The "1 primary + ≤4 co-located" group cap (X.4) is an inference from Hunk4J's locality gradient, not
  a measurement. The owner should run the 200-finding, batch-sizes-{1,3,5,10,20} experiment research/24
  proposes before treating the cap as final.
- **No published benchmark measures "one coding agent consumes a mixed SAST+DAST audit record."**
  Anvil's real PR-acceptance rate (the tier's chosen success metric) is entirely unmeasured until it
  ships; Exit Criteria in this document are structural, not performance-based, for exactly that reason.
- **`cwe_class_prior` has no established source at launch.** It must be seeded (uniform, or from
  research/11 S12's per-CWE spread) and then learned from Anvil's own outcome data over time — this is
  a cold-start problem the Ranking Contract does not solve on its own.
- **Whether the DAST tier can serve as G7's exploit oracle for non-memory-safety classes** (web CWEs,
  injection, authz) is a cross-branch dependency on the DAST tier's design. If yes, `dast_confirmed` /
  T0 becomes the common case; if the DAST tier covers mainly memory-safety classes, most findings stay
  permanently `unverified-security`, and G11 (human review) becomes non-waivable far more often than
  the tier's design implicitly assumes.
- **Quantization's effect on security-patch correctness is unmeasured** (research/04 Gaps). Anvil will
  likely run the pinned coding-agent weights at Q4; whether that precision loss disproportionately hurts
  security-relevant repair (versus general coding) is unknown and affects the pin in Pinned Versions.
  Re-verify before shipping a default quantization.
- **Disallowed-path list and the ≤3-files/≤100-lines size ceiling are engineering judgement, not
  evidence** (research/11 explicit gap). Instrument actual rejection rates at G3/G4 and revisit.
  Instead of writing this as a durable open item, consider promoting it to a Milestone-0-style
  measurement once real findings flow through the tier.
- **G9 (differential/behavioral equivalence) is deferred, not built, in this stepping.** AutoPatchBench's
  own numbers show it catches meaningful over-removal/API-contract-violation classes; its LLDB-based
  implementation is heavy tooling not justified until G7 coverage (previous bullet) is resolved. Revisit
  once the DAST-oracle coverage question above is answered.
- **The OSS-CRS adapter spike is an open thread carried from spine S11** ("whether an OSS-CRS adapter —
  `crs-patch-ensemble` — could be retargeted from OSS-Fuzz-crash input to Anvil's SARIF record... worth
  one bounded spike before the remediation tier is built — not a blocker"). This document did not spike
  it; if it proves adaptable it could reduce the implementation cost of X.10–X.17 substantially.
- **EPSS and KEV terms-of-use were not fully verified in-session by upstream research** (both flagged
  403/ambiguous). Both are wired as optional, nullable bonus terms in the Ranking Contract specifically
  so a licence resolution later does not require re-architecting the ranker.

---

## Conflicts With Spine

**None identified.** Two apparent tensions were checked and resolved without contradiction, both
recorded above rather than escalated here:

1. **research/24's Table 3 ordering (KEV → EPSS → reachability → CVSS) versus the spine's explicit
   correction (CVE-less path as default, KEV/EPSS/CVSS as nullable bonus terms).** This is not a live
   conflict — the spine text already supersedes the research recommendation by name. The Ranking
   Contract section implements the spine's ordering and explicitly does not implement research/24's
   literal `rank_key`.
2. **Spine S9's "coding agent remote" for hardware Tiers S/M versus research/04's "default the hosted
   path to off, warn loudly."** These reconcile via the `trust_tier` field in X.2: a user's own remote
   inference box (`user_remote`) is exactly what S9 anticipates and carries no warning; a public
   free-tier endpoint (`public_hosted`) is what research/04 warns against and stays opt-in, defaulted
   off. The pluggable backend accommodates both without treating them as the same case.
