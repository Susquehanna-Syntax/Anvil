# Anvil Implementation — Scan Controller, Triggers And Resources

## Overview

This section builds the component spine S10 demands: **one named scan controller** (`anvil-scanctl`,
package `internal/scanctl`) owning a single state machine (`open → sast_sealed → sealed → expired`) with
per-half seals, leases, a re-entrant handoff table, and incremental publication — replacing the four
independent partial orchestrators the research corpus produced. Trigger policy is entirely data
(`.anvil/policy.yml`, Renovate-shaped, JSON-Schema-validated, zero hard-coded conditions), evaluated by a
policy engine the GitHub Action calls locally before ever waking the daemon. CI integration ships as a
thin trigger, fat daemon: the Action never scans, it dispatches. Resource governance is a systemd
cgroup-v2 slice tree whose numbers are derived from the S9 tier matrix, not copied from research/21's
unsourced figures. Distribution is the single static Go binary (S12, no cgo) plus a container image, a
systemd unit tarball, and the published Action, in that dependency order.

## Dependency Summary

- **Consumes from other sections (not built here):** the SARIF 2.1.0 + `anvil/*` extension record schema
  and its required fields (S6); the single-writer SQLite+FTS5 store and `modernc.org/sqlite` no-cgo
  driver (S12); the authorization kernel that scopes any DAST target access (S7) — the scan controller
  calls it, never re-implements scope checks; the fingerprint algorithm (S6) the handoff table keys
  findings by.
- **Produces for other sections:** the `handoff` table and lease/claim API is the interface the
  remediation/coding-agent tier consumes — S6's "reserve 50% of remaining budget for late DAST-confirmed
  arrivals" work-queue rule is enforced by that consumer against this section's handoff records, not
  inside this section. The Lane A/Lane B detector tiers (S1) are producers into the bounded rings this
  section owns; their internals are out of scope here.
- **Internal ordering:** the deadline/collision design (O.1) gates the state machine (O.2→O.3); the policy
  schema (O.5) gates the engine (O.6) and semver-bump computation (O.7); both tracks converge at the
  GitHub Action (O.8); resource-tier derivation (O.12) gates the queue and liveness implementations
  (O.13, O.14); distribution (O.16–O.18) depends on the controller binary, the queue, and the resource
  units all existing.

## Steps

### Parallel group 1

```
Step ID:          O.1
Phase/group:      parallel group 1
Depends on:        none
Backend/model:    Claude Code subagent (opus)
Objective:        Resolve the two independent hard constraints that collide with the 8-hour retention
                   window and were never reconciled by the research corpus — GitHub-hosted job cap (6h),
                   self-hosted runner cap (5 days), and a ZAP full scan's ability to outrun retention —
                   and produce the authoritative deadline/handoff design the state machine must implement.
Scope and files:  WRITE: internal/scanctl/deadlines.go (types + extensive doc comments only, no
                   unrelated implementation). READ: research/09-orchestration-and-github-actions.md
                   (Recommendation §3, Risks #1,#3,#12), research/21-concurrent-scheduling-and-resources.md
                   (Recommendation §5, Risks), plan/00-SPINE.md S6, S9, S10.
Forbidden actions: Do not implement the state machine transitions themselves (that is O.2). Do not
                   propose a second LLM tier. Do not change the 8-hour default without flagging it as
                   config, not a constant.
Inputs/artifact refs: research/09 §3 (thin-Action/fat-daemon), research/21 §5 (incremental publication,
                   dast_deadline).
Expected output schema: Go source file defining `DeadlinePolicy` (created_at-anchored `deadline_at`,
                   configurable `dast_deadline` default 4h = half of `deadline_at`), and a doc comment
                   block titled "Constraint Resolution" stating: (a) the 6-hour GitHub-hosted cap binds
                   the Action's own runtime only — because DAST/full scans are dispatched to the user's
                   daemon (thin Action, fat daemon), the Action itself must never block waiting for scan
                   completion, only fire-and-return; (b) the 5-day self-hosted cap is moot because Anvil
                   refuses/gates self-hosted runners on public repos and never treats a self-hosted runner
                   as the DAST execution host regardless; (c) a ZAP full scan outrunning the 8h window is
                   bounded by `dast_deadline`, after which `dast.status = timed_out` and the record seals
                   regardless; (d) the residual risk — a long-running daemon-side DAST scan dispatched via
                   `repository_dispatch` has no GitHub check-run tied to it after the triggering Action
                   returns, so the daemon must independently create/update a Checks API run (or Commit
                   Status) rather than relying on the original Action's job status, and must do so within
                   GitHub's own check-run update semantics — flag this explicitly as needing a follow-up
                   design spike, do not silently assume it away.
Validation/evidence required: Doc comments cite the specific constraint (job cap / runner cap / ZAP
                   runtime) each resolution addresses; the residual-risk paragraph is present and not
                   elided.
Stop condition:    File compiles (`go build ./internal/scanctl/...`), all three constraints are addressed
                   by name, and the residual check-run risk is documented.
Why this model:    This is the one genuinely hard, ambiguous architecture sub-problem the research corpus
                   explicitly left unreconciled — exactly opus's reserved lane per 00-ROUTING.md, not a
                   bounded implementation chore.
```

```
Step ID:          O.5
Phase/group:      parallel group 1
Depends on:        none
Backend/model:    Claude Code subagent (sonnet)
Objective:        Ship the `.anvil/policy.yml` JSON Schema and the config-file search-order resolver so
                   trigger policy is provably data, never code.
Scope and files:  WRITE: schemas/policy.schema.json, internal/policy/locate.go. READ:
                   research/09-orchestration-and-github-actions.md (Recommendation §2), plan/00-SPINE.md
                   S1 (no hard-coded triggers is a hard constraint).
Forbidden actions: Do not hard-code any event name, ref pattern, semver bump type, or cadence as a Go
                   constant used for matching — every matchable value must come from the parsed YAML.
                   Do not vendor Renovate code or types — convention only (Renovate is AGPL-3.0).
Inputs/artifact refs: research/09 §2 (`matchEvents`/`matchRefs`/`matchSemverBump`/`matchPaths` shape,
                   config search order).
Expected output schema: `schemas/policy.schema.json` — draft-07 or 2020-12 JSON Schema validating
                   `version`, `defaults` (detectors, depth, timeout, failOn, publish), and `scanRules[]`
                   (name, match* keys applied in array order, later-overrides-earlier semantics documented
                   in `description` fields, detectors/depth/timeout/dast overrides). `locate.go` exports
                   `Locate(root string) (path string, err error)` implementing the search order
                   `.anvil/policy.yml → .anvil/policy.yaml → .anvil/policy.toml → anvil.toml →
                   .github/anvil.yml`, stop at first match, `ErrNoPolicyFound` if none.
Validation/evidence required: A fixture policy YAML (SAST on every push; SAST+DAST on tagged releases
                   gated by `matchSemverBump`) validates cleanly against the schema via a table test; a
                   second fixture with an invalid `matchSemverBump` enum value fails validation.
Stop condition:    Schema validates both fixtures correctly; `Locate` unit tests cover all five search
                   paths plus the not-found case.
Why this model:    Direct implementation of an already-well-specified schema and file-search routine —
                   sonnet's default lane, no architectural ambiguity remaining after research/09.
```

```
Step ID:          O.12
Phase/group:      parallel group 1
Depends on:        none
Backend/model:    Claude Code subagent (sonnet)
Objective:        Derive per-tier (S/M/L) systemd slice-tree cgroup-v2 resource numbers from the S9
                   hardware matrix, explicitly not from research/21's unsourced figures, and emit the
                   annotated unit files.
Scope and files:  WRITE: deploy/systemd/anvil.slice, deploy/systemd/anvil-core.slice,
                   deploy/systemd/anvil-detect.slice, deploy/systemd/anvil-recall.slice,
                   deploy/systemd/anvil-scan.slice, deploy/systemd/anvil-fix.slice (one set of files per
                   tier, suffixed `-tier-s`, `-tier-m`, `-tier-l`, or a templated `%i` instance — worker's
                   choice, state which in the output). READ: plan/00-SPINE.md S9,
                   research/21-concurrent-scheduling-and-resources.md (Recommendation §3, Key Findings §E),
                   research/05-inference-serving-and-hardware.md (Recommendation, memory budget table).
Forbidden actions: Do not copy research/21's MemoryHigh=18G/MemoryMax=22G example numbers verbatim — the
                   task brief flags them as unsourced and contradicting the minimal-compute constraint.
                   Every number must either show its derivation from an S9 tier total or be labelled
                   "MEASURE FIRST". Do not set `--mlock`-equivalent expectations together with a
                   `MemoryMax=` that would convert graceful reclaim into an immediate OOM kill.
Inputs/artifact refs: S9 tier table (S: 8GB/4core no GPU, SAST only, DAST off; M: 32GB/8core, SAST+DAST
                   against ephemeral targets, coding agent remote; L: 64GB+/GPU, everything local).
Expected output schema: One slice tree per tier with `MemoryLow=`, `MemoryHigh=`, `MemoryMax=`,
                   `AllowedCPUs=`, `AllowedMemoryNodes=`, `CPUWeight=`/`CPUQuota=`, `IOWeight=`,
                   `OOMPolicy=stop` on the coder unit, each annotated with a comment showing the arithmetic
                   against the tier's total RAM/cores, or literal text `# MEASURE FIRST: <reason>` where no
                   derivation is possible (e.g. opengrep/Trivy/ZAP resident memory under real load).
                   Tier S must mask/omit `anvil-scan.slice` (DAST off) and keep `anvil-fix.slice` trivial
                   (remote coding agent — thin HTTP client only, no local weights). Tier L's
                   `anvil-fix.slice` must carry an explicit "MEASURE FIRST" flag rather than a fixed number,
                   because the spine-selected coding model (Qwen3-Coder-Next, 3B active / 80B total,
                   RAM-bound) is a large MoE that research/05's example budgets (based on 7–27B dense
                   models) do not cover — its resident-weight footprint at Q4_K_M could approach or exceed
                   a naive 64GB floor once detect+scan slices are also resident, and this must be measured,
                   not assumed.
Validation/evidence required: `systemd-analyze verify` (or equivalent static check) passes on every unit
                   file; a written derivation line precedes every numeric directive.
Stop condition:    All three tiers have a complete slice tree, every number is either derived-and-shown or
                   marked MEASURE FIRST, and Tier L's fix-slice caveat is explicit.
Why this model:    Bounded arithmetic derivation against an already-fixed matrix (S9) plus systemd unit
                   syntax — sonnet's implementation lane; no open architectural question once the "derive,
                   don't copy" constraint is followed mechanically.
```

### Parallel group 2

```
Step ID:          O.2
Phase/group:      parallel group 2
Depends on:        O.1
Backend/model:    Claude Code subagent (sonnet)
Objective:        Implement the scan controller state machine — states, valid transitions, per-half seal,
                   and version-bump-on-watermark incremental publication.
Scope and files:  WRITE: internal/scanctl/statemachine.go, internal/scanctl/statemachine_test.go. READ:
                   internal/scanctl/deadlines.go (O.1 output), research/21 Recommendation §5, plan/00-SPINE.md
                   S6 (ordering/version-bump rule), S10.
Forbidden actions: Do not let SAST block on DAST completion. Do not write the DB record more than once
                   (only at final seal — the buffer carries incremental versions). Do not invent a fifth
                   top-level state.
Inputs/artifact refs: The `audit_record` shape from research/21 §5 (`scan_id`, `created_at`, `deadline_at`,
                   `version`, `state`, per-half `status`/`sealed_at`/`findings[]`, `correlation`).
Expected output schema: `AuditRecord` struct and `Transition(record, event) (AuditRecord, error)` covering
                   `open → sast_sealed` (on `sast.status=complete`), `open|sast_sealed → sealed` (on DAST
                   terminal state per O.1's `dast_deadline`), `open|sast_sealed → expired` (on
                   `deadline_at` reached with nothing sealed, or lease/claim exhaustion — see O.3). Version
                   bumps on: SAST complete, every N DAST findings or M minutes (config, not constant),
                   DAST terminal state.
Validation/evidence required: Table-driven tests exercising every legal transition and asserting every
                   illegal transition returns an error, not a panic or a silent no-op.
Stop condition:    `go test ./internal/scanctl/...` passes, including a test that a slow/never-terminating
                   DAST run still produces a `sast_sealed`-then-`expired` (not stuck-`open`) record.
Why this model:    Implementation of an already-specified state machine — sonnet's default lane.
```

```
Step ID:          O.6
Phase/group:      parallel group 2
Depends on:        O.5
Backend/model:    Claude Code subagent (sonnet)
Objective:        Implement the policy engine: Renovate-shaped match/apply evaluation in array order,
                   later-rule-overrides-earlier, against the O.5 schema.
Scope and files:  WRITE: internal/policy/engine.go, internal/policy/engine_test.go. READ:
                   schemas/policy.schema.json (O.5 output), research/09 §2 fixture YAML.
Forbidden actions: Do not hard-code any rule's match values as Go switch cases — the evaluator must be
                   generic over whatever `scanRules` the parsed file contains. Do not short-circuit on
                   first match — Renovate semantics apply every matching rule in order and later rules
                   override earlier ones' fields, they do not replace the whole rule.
Inputs/artifact refs: research/09 §2 design notes (the matchEvents+matchRefs+matchSemverBump triple).
Expected output schema: `Evaluate(policy Policy, ctx TriggerContext) (ResolvedRule, error)` where
                   `TriggerContext` carries event name, ref, changed paths, and (once computed by O.7) the
                   semver bump kind. Output merges `defaults` with matched `scanRules` in array order.
Validation/evidence required: Reproduce, as a test fixture, the two rules the owner's explicit requirement
                   demands — "SAST on every push" and "SAST+DAST only on tagged releases, gated by semver
                   bump" — from research/09's example policy, and assert the engine resolves each event
                   scenario to the correct detector set and depth.
Stop condition:    `go test ./internal/policy/...` passes including the two owner-requirement fixtures.
Why this model:    Direct implementation against a finished schema — sonnet's default lane.
```

```
Step ID:          O.13
Phase/group:      parallel group 2
Depends on:        O.12
Backend/model:    Claude Code subagent (sonnet)
Objective:        Implement the bounded finding rings (count + bytes bound), block-the-producer
                   backpressure for SAST, and admission-time shedding above a configurable watermark.
Scope and files:  WRITE: internal/queue/ring.go, internal/scanctl/admission.go, and their _test.go files.
                   READ: research/21 Recommendation §4 and Key Findings §F, deploy/systemd/anvil-core.slice
                   (O.12, for the memory ceiling the watermark must respect).
Forbidden actions: Never drop a SAST finding to relieve backpressure — block the producer instead. Never
                   let a scan start mid-way and then fail from resource exhaustion — refuse at admission,
                   before any state transitions from `open` occur.
Inputs/artifact refs: research/21 §F (Google reject-not-queue guidance, Ollama's 512-then-503 precedent).
Expected output schema: `Ring[T]` generic bounded by both `maxCount` and `maxBytes` (config, suggested
                   defaults 5,000 findings / 64 MiB per side per scan, not hard-coded); `Push` blocks when
                   full for the SAST role; `AdmissionGate.TryStart(scanID) error` returning a typed
                   `ErrAtCapacity` (mapped to HTTP 503 at the API layer) when aggregate buffer occupancy
                   exceeds the watermark.
Validation/evidence required: A load test that pushes past the ring bound and asserts zero drops with the
                   producer blocking (not erroring, not dropping); a second test that starts scans past the
                   watermark and asserts a clean `ErrAtCapacity` with no partial `AuditRecord` created.
Stop condition:    Both load tests pass deterministically (no flakiness from goroutine timing — use
                   synchronization primitives, not sleeps, in the test).
Why this model:    Concurrency-primitive implementation against an already-decided policy (block, don't
                   drop; shed at admission, not mid-scan) — sonnet's default lane.
```

```
Step ID:          O.14
Phase/group:      parallel group 2
Depends on:        O.12
Backend/model:    Claude Code subagent (sonnet)
Objective:        Implement a liveness signal that distinguishes a detector throttled by `MemoryHigh=`
                   pressure from one that is actually wedged, so operators do not kill healthy scans.
Scope and files:  WRITE: internal/health/liveness.go, internal/health/liveness_test.go. READ:
                   research/21 Risks ("MemoryHigh= failure looks like a hang, not a crash"),
                   deploy/systemd/anvil-detect.slice (O.12).
Forbidden actions: Do not conflate "no forward progress" with "no CPU scheduled" — a throttled-but-alive
                   process legitimately makes near-zero progress for minutes; the signal must come from
                   cgroup memory-pressure/event counters, not from a naive progress timeout alone.
Inputs/artifact refs: cgroup v2 `memory.pressure` and `memory.events` (`high` counter) semantics as
                   described in research/21 Key Findings §E.
Expected output schema: `LivenessState` enum `{Healthy, Throttled, Wedged, Unknown}` and a `/healthz`
                   handler reading the unit's `memory.events`/`memory.pressure` (via cgroup fs path,
                   injectable for tests) plus a last-heartbeat timestamp from the detector process itself;
                   `Throttled` = rising `high` events count with a recent heartbeat; `Wedged` = no
                   heartbeat past a configurable grace period regardless of memory events.
Validation/evidence required: A test that injects synthetic rising `memory.events high` counters with
                   fresh heartbeats and asserts `Throttled`, and a separate test with a stale heartbeat and
                   flat memory events that asserts `Wedged`.
Stop condition:    Both synthetic tests pass and the distinction is documented in a doc comment an operator
                   would read before writing an alerting rule.
Why this model:    Bounded implementation against a clearly specified distinguishing signal — sonnet's
                   default lane.
```

### Parallel group 3

```
Step ID:          O.3
Phase/group:      parallel group 3
Depends on:        O.2
Backend/model:    Claude Code subagent (sonnet)
Objective:        Implement the handoff table (SQLite migration + Go repository), lease acquire/renew/
                   expire, and re-entrant, idempotent consumption for the coding-agent claim path.
Scope and files:  WRITE: internal/store/migrations/0002_handoff.sql, internal/scanctl/handoff.go,
                   internal/scanctl/handoff_test.go. READ: internal/scanctl/statemachine.go (O.2 output),
                   plan/00-SPINE.md S6 (fingerprint algorithm, `remediable_by_agent`), S7 (no auto-merge —
                   leases grant claim, never merge authority).
Forbidden actions: Do not let a crashed/OOM-killed consumer's expired lease corrupt state — reclaiming an
                   expired lease and re-processing must be idempotent, keyed by (finding fingerprint,
                   record version). Do not let a lease grant any authority beyond "may act on this
                   finding" — never merge, never widened scope.
Inputs/artifact refs: The consumption-policy split from research/21 §5: `static_only` findings claimable
                   once `sast.status=complete`; `requires_dynamic_confirmation` findings must wait on
                   `dast.status`.
Expected output schema: `handoff` table columns: finding_fingerprint, scan_id, record_version, status
                   (unclaimed|leased|done), lease_owner, lease_expires_at, consumption_class
                   (static_only|requires_dynamic_confirmation). `AcquireLease`, `RenewLease`,
                   `ReleaseLease`, `ReclaimExpired` functions.
Validation/evidence required: A test that acquires a lease, simulates the holder dying (no renew), advances
                   the clock past expiry, reclaims, and re-processes — asserting the finding is not
                   double-applied and no duplicate side effect is observable; a test asserting a
                   `requires_dynamic_confirmation` finding cannot be leased before `dast.status` reaches a
                   terminal state.
Stop condition:    `go test ./internal/scanctl/...` passes including the crash-and-reclaim scenario.
Why this model:    Direct implementation of an already-decided consumption contract — sonnet's default
                   lane; the correctness-critical review happens next, at O.4.
```

```
Step ID:          O.7
Phase/group:      parallel group 3
Depends on:        O.6
Backend/model:    Claude Code subagent (sonnet)
Objective:        Implement Anvil's own semver-bump computation (`git describe --tags --abbrev=0 <tag>^`)
                   so `matchSemverBump` never depends on GitHub's payload, which carries no "previous tag".
Scope and files:  WRITE: internal/policy/semver.go, internal/policy/semver_test.go. READ:
                   internal/policy/engine.go (O.6 output), research/09 §2 design notes on
                   `matchSemverBump`.
Forbidden actions: Do not read the bump kind from the GitHub event payload — it does not exist there. Do
                   not assume `fetch-depth: 0`/`fetch-tags: true` are already set; this function must fail
                   loudly and specifically (not just "git error") when the checkout is shallow, since that
                   is the documented operational footgun.
Inputs/artifact refs: research/09 §2: "Anvil derives it with `git describe --tags --abbrev=0 <tag>^` and
                   therefore the Action must set `actions/checkout` `fetch-depth: 0` and `fetch-tags:
                   true`."
Expected output schema: `ComputeSemverBump(repoPath, newTag string) (BumpKind, error)` returning
                   `major|minor|patch|prerelease`, with a distinct sentinel error (e.g.
                   `ErrShallowCheckout`) when `git describe` fails in a way consistent with a shallow clone
                   (heuristic: no prior tag reachable / git error mentioning "no tag" on a repo whose
                   `.git/shallow` file exists).
Validation/evidence required: A test fixture repo with a real tag sequence (v1.0.0 → v1.1.0 → v1.1.1 →
                   v2.0.0) asserting each bump is classified correctly; a second test against a
                   shallow-cloned fixture asserting `ErrShallowCheckout` specifically, not a generic error.
Stop condition:    `go test ./internal/policy/...` passes both scenarios.
Why this model:    Bounded, well-specified git-plumbing implementation — sonnet's default lane.
```

```
Step ID:          O.15
Phase/group:      parallel group 3
Depends on:        O.12, O.13, O.14
Backend/model:    OpenCode route openai/gpt-5.5-fast
Objective:        Cross-family critique of the resource-governance triad (slice tree, queue/admission,
                   liveness signal) for OOM/lease interaction bugs and numeric traceability.
Scope and files:  READ ONLY: deploy/systemd/anvil-*.slice (O.12), internal/queue/ring.go,
                   internal/scanctl/admission.go (O.13), internal/health/liveness.go (O.14). WRITE:
                   internal/scanctl/REVIEW-O.15.md
Forbidden actions: Do not modify statemachine.go, handoff.go logic, or policy files — review only. Do not
                   approve any numeric directive that lacks either a derivation comment or a MEASURE FIRST
                   label.
Inputs/artifact refs: research/21 Risks ("MemoryHigh= failure looks like a hang", "a bot... is a
                   supply-chain actor" — not this step's concern, that's O.11), plan/00-SPINE.md S9.
Expected output schema: A structured findings list: for each slice/queue/liveness file, PASS or a specific
                   defect (e.g. "OOMPolicy=stop on anvil-fix.slice will strand a held lease if handoff.go's
                   lease TTL exceeds systemd's Restart backoff — verify RestartSec vs lease_expires_at
                   ordering").
Validation/evidence required: Every MEASURE FIRST label from O.12 is either endorsed or challenged with a
                   specific reason; the OOMPolicy=stop-vs-lease-expiry interaction is explicitly checked.
Stop condition:    Findings list delivered; no PASS issued on a directive lacking derivation or MEASURE
                   FIRST label.
Why this model:    Cross-family critique is mandatory here per 00-ROUTING.md's review-gate table (resource
                   governance touches data-loss risk via OOM kills mid-lease); gpt-5.5-fast is justified as
                   a bounded, reviewable check rather than open-ended architecture, so the -fast tier
                   suffices without paying for full gpt-5.5.
```

### Parallel group 4

```
Step ID:          O.4
Phase/group:      parallel group 4
Depends on:        O.3
Backend/model:    OpenCode route openai/gpt-5.5
Objective:        Cross-family critique of the scan controller core (deadlines, state machine, handoff/
                   lease/re-entrancy) — this becomes the reference every later consumer builds against, so
                   it gets the strongest available critic.
Scope and files:  READ ONLY: internal/scanctl/deadlines.go, statemachine.go, handoff.go and their tests
                   (O.1, O.2, O.3 outputs). WRITE: REVIEW-O.4.md in internal/scanctl/.
Forbidden actions: Do not modify any reviewed file. Do not re-open the "no second LLM tier" or "one
                   audit identity, two sealed halves" decisions — those are spine, not open questions.
Inputs/artifact refs: plan/00-SPINE.md S6, S7, S10; research/21 §5 four-reasons-incremental-is-right list.
Expected output schema: A structured findings list covering: re-entrancy races (two consumers racing an
                   expired lease), deadline anchoring correctness (anchored to scan start, not last write),
                   completeness of the state machine against the four states, and whether the residual
                   check-run-update risk from O.1 is adequately isolated from the state machine's own
                   correctness (i.e., a stalled GitHub check must never be able to corrupt or stall the
                   daemon-side record).
Validation/evidence required: Each finding cites the specific function/test it concerns; any concurrency
                   claim is backed by a proposed test scenario, not just prose.
Stop condition:    Findings list delivered; any defect rated blocking is called out as such explicitly.
Why this model:    Per 00-ROUTING.md's cross-family rule, Anthropic-written code doing this much
                   correctness-critical, re-entrancy-sensitive work requires an OpenCode/OpenRouter critic;
                   gpt-5.5 is justified because this is the "one genuinely hard parallel sub-problem"'s
                   downstream implementation and the interface every later component depends on — a
                   mis-review here propagates everywhere.
```

```
Step ID:          O.8
Phase/group:      parallel group 4
Depends on:        O.7
Backend/model:    Claude Code subagent (sonnet)
Objective:        Publish the GitHub Action as a thin trigger — evaluate policy locally, run inline SAST
                   only for `detectors:[sast], depth:delta`, otherwise dispatch to the daemon — and gate
                   the self-hosted-runner-on-public-repo path loudly.
Scope and files:  WRITE: action/action.yml, action/workflow-template.yml (the skeleton users copy into
                   `.github/workflows/anvil.yml`), action/README.md (self-hosted warning only — no other
                   prose files). READ: internal/policy/engine.go (O.6), internal/policy/semver.go (O.7),
                   research/09 §3 workflow skeleton and Table D.
Forbidden actions: The Action must never download model weights or hold the CVE cache. Do not use
                   `pull_request_target` anywhere in the shipped workflow template. Do not default to or
                   silently enable self-hosted runners.
Inputs/artifact refs: research/09 §3 (separate `push: branches` / `push: tags` trigger blocks — a single
                   block with only `branches` silently drops tag pushes; `release: types:[published]` as
                   the 3-tag-drop safety net; `permissions: contents:read, security-events:write`).
Expected output schema: `action.yml` (composite or JS action) that: locates+parses `.anvil/policy.yml`
                   (via the same search order as O.5, reimplemented or vendored as a small standalone
                   binary/script since the Action runs without the daemon), evaluates the match via O.6's
                   engine logic (or a thin re-implementation if cross-compiling the engine into the Action
                   is impractical — state which and why), and either runs inline SAST or fires
                   `repository_dispatch`/signed webhook. `workflow-template.yml` includes the split
                   push-branches/push-tags/release/workflow_dispatch/schedule trigger blocks, correct
                   `permissions`, and `fetch-depth: 0` / `fetch-tags: true` on `actions/checkout` with a
                   comment explaining why (ties to O.7). `README.md` reproduces GitHub's self-hosted-on-
                   public-repos warning verbatim and documents restricting via runner groups to private
                   repos only.
Validation/evidence required: A workflow-template lint (actionlint or equivalent) passes; a test dispatch
                   against a scratch/private repo confirms the delta-SAST path runs inline and the
                   full/DAST path fires `repository_dispatch` without downloading weights.
Stop condition:    Lint passes; both dispatch paths verified in a scratch-repo smoke test; self-hosted
                   warning present verbatim in README.
Why this model:    Direct implementation against fully-specified research findings (research/09 §3) —
                   sonnet's default lane.
```

```
Step ID:          O.16
Phase/group:      parallel group 4
Depends on:        O.3, O.13
Backend/model:    Claude Code subagent (sonnet)
Objective:        Build the TWO static Go binary targets — `cmd/anvil` (core) and `cmd/anvil-dast` —
                   CGO_ENABLED=0, cross-compilation matrix, wiring the scan controller and queue packages
                   into the core entrypoint; plus the import-graph guard that keeps them separate.
Scope and files:  WRITE: cmd/anvil/main.go, cmd/anvil/split_test.go, cmd/anvil-dast/main.go,
                   Makefile (or equivalent build script) targets for linux/amd64, linux/arm64 at minimum
                   for BOTH binaries. READ: internal/scanctl/, internal/queue/ (O.3,
                   O.13 outputs), plan/00-SPINE.md S12, S9-AMENDED.
Forbidden actions: Do not introduce any cgo dependency (verify with `CGO_ENABLED=0 go build`, not just by
                   omission). Do not link `mattn/go-sqlite3` — S12 mandates `modernc.org/sqlite`. Do not
                   re-litigate the Go-vs-Python decision. **Do not import any `internal/dast/**` package
                   from `cmd/anvil` or anything it reaches** — S9-AMENDED requires the core artifact to
                   have no network-probing capability compiled in, and §2.2 ruled that a config boolean
                   does not satisfy that. Do not satisfy the guard by a build tag or a comment.
Inputs/artifact refs: plan/00-SPINE.md S12 (no cgo, single static binary, modernc.org/sqlite),
                   S9-AMENDED (the two-artifact split), IMPLEMENTATION-PLAN.md §2.2 and §2.9-D6.
Expected output schema: `cmd/anvil/main.go` exposing `anvil scan`, `anvil daemon --loop` (the async
                   fallback for non-systemd hosts per research/09 §1) subcommands; `cmd/anvil-dast/main.go`
                   exposing the dynamic tier's entrypoint behind its explicit attestation gate; Makefile
                   targets `build-linux-amd64`, `build-linux-arm64` and `build-dast-linux-amd64`,
                   `build-dast-linux-arm64`, each producing a binary verified statically linked (`file`
                   shows "statically linked" / no dynamic interpreter); `cmd/anvil/split_test.go` shelling
                   `go list -deps ./cmd/anvil` and failing if any returned package matches
                   `*/internal/dast/*`.
Validation/evidence required: `CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build ./cmd/anvil` and the same
                   for `./cmd/anvil-dast` both succeed; `file` or `ldd` confirms no dynamic libc dependency
                   on either; `go test ./cmd/anvil -run TestSplit` passes; and the guard is proven to work
                   by a negative control — add a temporary `internal/dast` import to `cmd/anvil`, show the
                   test FAILS, then revert. A guard that has never failed has not been tested.
Stop condition:    All four target binaries build and verify static; `anvil scan --help`, `anvil daemon
                   --loop --help`, and `anvil-dast --help` produce output; the import guard passes and its
                   negative control was demonstrated.
Why this model:    Mechanical build wiring against already-built packages and an already-settled language
                   decision — sonnet's default lane.
```

### Parallel group 5

```
Step ID:          O.9
Phase/group:      parallel group 5
Depends on:        O.8
Backend/model:    Claude Code subagent (sonnet)
Objective:        Implement SARIF publish to GitHub Code Scanning with a pre-upload gate that stays inside
                   the 10 MB hard limit and 5,000-result soft limit.
Scope and files:  WRITE: internal/publish/sarif.go, internal/publish/sarif_test.go. READ: action/action.yml
                   (O.8, for the auth/token flow the publisher assumes), research/09 §3 (8 MB/4,000-result
                   gate, gzip+Base64, poll `/sarifs/{sarif_id}`).
Forbidden actions: Do not upload without gating first — a `413` reaching the user is an explicit failure
                   mode this step exists to prevent. Do not drop findings silently; document which
                   severities were dropped in the publish response.
Inputs/artifact refs: research/09 §3: "Enforce a pre-upload gate at 8 MB and 4,000 results... drop lowest-
                   severity findings first, mirroring Trivy's `limit-severities-for-sarif`."
Expected output schema: `Publish(sarif Document) (Result, error)` that gzip+Base64-encodes, checks size/
                   count against the 8MB/4000 thresholds before any network call, drops lowest-severity
                   findings first when over threshold, POSTs to
                   `/repos/{owner}/{repo}/code-scanning/sarifs`, and polls `/sarifs/{sarif_id}` for
                   `complete`.
Validation/evidence required: A unit test with a mocked endpoint and a synthetic >8MB/>4000-result payload
                   asserts the gate trims before any HTTP call is made, and that dropped findings are
                   listed in the returned `Result`.
Stop condition:    `go test ./internal/publish/...` passes including the oversized-payload gate test.
Why this model:    Direct implementation against fully-specified numeric limits — sonnet's default lane.
```

```
Step ID:          O.10
Phase/group:      parallel group 5
Depends on:        O.8
Backend/model:    Claude Code subagent (sonnet)
Objective:        Implement the GitHub App auth path for fix PRs (JWT → installation token), with a
                   permission set that structurally excludes merge/approve capability — never
                   `GITHUB_TOKEN`.
Scope and files:  WRITE: internal/ghapp/auth.go, internal/ghapp/pr.go, internal/ghapp/auth_test.go. READ:
                   action/action.yml (O.8), research/09 §4, plan/00-SPINE.md S7 (never auto-merge).
Forbidden actions: Do not implement any code path that opens a PR via `GITHUB_TOKEN`. Do not request or
                   accept an App permission scope that includes PR approval or merge rights. Do not embed
                   or log the RSA private key or webhook secret anywhere.
Inputs/artifact refs: research/09 §4 (App ID + PEM key + webhook secret + JWT→installation-token exchange;
                   permissions declared per install; rate limit 5,000–12,500 req/hr vs GITHUB_TOKEN's
                   1,000/hr).
Expected output schema: `AppAuthenticator` producing short-lived installation tokens from a configured App
                   ID + PEM path (read from config/env, never hard-coded); `OpenFixPR(...)` using that
                   token exclusively; a compile-time or init-time assertion that the requested permission
                   set does not include `pull_requests: write` bundled with any approval/merge scope (state
                   the exact check performed).
Validation/evidence required: An integration test against a scratch repo confirms a PR opened via the App
                   token triggers a workflow run (unlike `GITHUB_TOKEN`); a unit test confirms the
                   permission-set assertion rejects a deliberately over-scoped test fixture.
Stop condition:    Both tests pass; no `GITHUB_TOKEN` code path exists in `internal/ghapp/`.
Why this model:    Direct implementation against a fully-specified auth flow — sonnet's default lane; the
                   authorization-scope critique happens next, at O.11.
```

```
Step ID:          O.17
Phase/group:      parallel group 5
Depends on:        O.16
Backend/model:    Claude Code subagent (sonnet)
Objective:        Build the container image and its licence-notice machinery — the image is where LGPL
                   (opengrep) and Apache (Trivy, Nuclei, ZAP) notice-and-offer-source duties actually
                   trigger, per distribution.
Scope and files:  WRITE: Dockerfile, Dockerfile.dast, .dockerignore, LICENSES/
                   directory population script (e.g. scripts/collect-licenses.sh). **READ-ONLY on the root
                   NOTICE** — area 80 owns it (IMPLEMENTATION-PLAN.md §2.7-D3, §2.9-D8). This step VERIFIES
                   NOTICE completeness and fails the build if a baked-in component is missing from it; it
                   does not edit it. Per S9-AMENDED and
                   IMPLEMENTATION-PLAN.md §2.9-D6 these are TWO images: the core image must contain
                   neither the `anvil-dast` binary nor any probing tool (Nuclei, ZAP), and the DAST image
                   is the only one that does. READ: cmd/anvil and cmd/anvil-dast binary targets (O.16),
                   plan/00-SPINE.md S8 (SPDX allowlist reading LICENSE file bodies, not API metadata;
                   manual-override field), S4 (opengrep LGPL-2.1, Trivy Apache-2.0, Nuclei MIT, ZAP
                   Apache-2.0, AikidoSec/opengrep-rules MIT).
Forbidden actions: Do not run systemd inside the container (the container path is the async-loop fallback
                   from O.16, `anvil daemon --loop`, not a systemd-managed process). Do not read licence
                   metadata from package-manager APIs — S8 requires reading LICENSE file bodies directly,
                   because some artifacts return NOASSERTION over a real licence or hide a restrictive one.
Inputs/artifact refs: plan/00-SPINE.md S8 compliance mechanics paragraph in full.
Expected output schema: `Dockerfile` producing a minimal (distroless-or-scratch-class) image running
                   `anvil daemon --loop`; `scripts/collect-licenses.sh` walks every vendored/invoked
                   binary dependency baked into the image, copies each LICENSE file body into `LICENSES/
                   <component>/LICENSE`, and fails the build if any component's licence cannot be located
                   as a file body (not just an API field). `NOTICE` aggregates Apache-2.0 §4 attributions.
                   An explicit comment or doc note states that LGPL-2.1 opengrep's inclusion in this image
                   is the trigger point for offer-source obligations and states where the offer is served
                   (e.g. a `/source-offer` daemon endpoint or a repo pointer — worker picks one and states
                   it).
Validation/evidence required: The build fails closed (non-zero exit) if any baked-in component lacks a
                   located LICENSE file body; `docker build` succeeds otherwise.
Stop condition:    Image builds; `LICENSES/` is populated for every baked-in third-party binary; the LGPL
                   offer-source trigger point is named explicitly, not left implicit.
Why this model:    Mechanical packaging plus a well-specified compliance procedure from S8 — sonnet's
                   default lane; the licence conclusion itself gets a cross-family critic at O.20.
```

```
Step ID:          O.18
Phase/group:      parallel group 5
Depends on:        O.16
Backend/model:    Claude Code subagent (sonnet)
Objective:        Package the systemd unit tarball — the Linux-server default distribution form — wiring
                   in the O.12 slice tree and the O.1-resolved timer schedule.
Scope and files:  WRITE: deploy/systemd/anvil.service, deploy/systemd/anvil-full-scan.timer,
                   deploy/systemd/install.sh, deploy/systemd/anvil.tar (build target, not committed
                   binary — script that assembles it), plus the SEPARATE dast tarball per S9-AMENDED:
                   deploy/systemd/anvil-dast.service and deploy/systemd/install-dast.sh assembling
                   deploy/systemd/anvil-dast.tar. The two tarballs are separately downloadable artifacts;
                   `install.sh` must never install `anvil-dast`, and `install-dast.sh` must refuse to
                   proceed without the explicit attestation S9-AMENDED requires. Tier S simply does not
                   run install-dast.sh. READ: cmd/anvil and cmd/anvil-dast binaries (O.16),
                   deploy/systemd/anvil-*.slice (O.12), research/09 §1 (timer/service ini examples,
                   `Persistent=true`, `RandomizedDelaySec=20min`, non-round `03:17` scheduling).
Forbidden actions: Do not set `CPUQuota=`/`MemoryMax=` on the top-level timer/service ini duplicating
                   numbers already owned by the O.12 slice tree — reference the slice, don't fork the
                   numbers. Do not use a round-hour `OnCalendar=` value (top-of-hour congestion, per
                   research/09 Risks #2).
Inputs/artifact refs: research/09 §1 full timer/service example.
Expected output schema: `anvil-full-scan.timer` with `Persistent=true`, `RandomizedDelaySec=20min`,
                   `FixedRandomDelay=true`, `AccuracySec=1min`, `OnCalendar=*-*-* 03:17:00` (or equivalent
                   non-round time, configurable); `anvil.service` as `Type=oneshot` invoking `anvil scan
                   --policy <path> --depth full`, `Slice=anvil-core.slice` (or the appropriate O.12 slice)
                   rather than redefining cgroup directives inline; `install.sh` places binary + units and
                   runs `systemctl daemon-reload`.
Validation/evidence required: `systemd-analyze verify` passes on both unit files; a clean VM/container
                   smoke test confirms `anvil-full-scan.timer` is active and its next-elapse time is
                   correctly jittered off `03:17`.
Stop condition:    Verify passes; smoke test confirms timer activation.
Why this model:    Direct packaging against a fully-specified example from research/09 — sonnet's default
                   lane.
```

### Parallel group 6

```
Step ID:          O.11
Phase/group:      parallel group 6
Depends on:        O.9, O.10
Backend/model:    OpenCode route openai/gpt-5.5
Objective:        Cross-family critique of the SARIF-publish and GitHub-App authorization surface: confirm
                   the App's permission set cannot become a supply-chain actor, `pull_request_target` is
                   nowhere in scope, and the 1,000 req/hr GITHUB_TOKEN ceiling is never hit by the review-
                   comment path.
Scope and files:  READ ONLY: internal/publish/sarif.go (O.9), internal/ghapp/auth.go, pr.go (O.10),
                   action/action.yml (O.8). WRITE: REVIEW-O.11.md alongside internal/ghapp/.
Forbidden actions: Do not modify any reviewed file. Do not approve an App permission set that includes
                   any approval/merge capability alongside `contents:write`+`pull-requests:write`.
Inputs/artifact refs: research/09 Risks #4, #5, #6, #13 (blank-checks-list safety failure, bot-as-supply-
                   chain-actor, `pull_request_target` prohibition, 1,000 req/hr batching requirement).
Expected output schema: A structured findings list confirming or rejecting: (1) fix PRs trigger CI (not
                   `GITHUB_TOKEN`-authored); (2) the App's declared scopes exclude merge/approve; (3) no
                   shipped workflow uses `pull_request_target`; (4) review comments are batched, not one-
                   call-per-finding.
Validation/evidence required: Each of the four checks cites the specific file/line or config value that
                   satisfies or violates it.
Stop condition:    Findings list delivered with an explicit PASS/FAIL on all four checks; any FAIL is
                   marked blocking.
Why this model:    This is an authorization-decision review — mandatory cross-family critic per 00-ROUTING
                   .md's gate table ("Security... auth... must carry an independent critic, different model
                   family"); gpt-5.5 (not the -fast tier) because a mis-scoped App permission is a real
                   supply-chain risk, not a bounded mechanical check.
```

```
Step ID:          O.19
Phase/group:      parallel group 6
Depends on:        O.17
Backend/model:    Claude Code subagent (haiku)
Objective:        Run the SPDX allowlist licence scan over the container image's baked-in components,
                   reading LICENSE file bodies only, per S8's compliance mechanics.
Scope and files:  READ ONLY: LICENSES/ (O.17 output), Dockerfile. WRITE: a scan report,
                   LICENSE-SCAN-REPORT.md, in the repo root or deploy/docker/ — worker states which.
Forbidden actions: Do not read licence identifiers from package-manager metadata/APIs — file bodies only,
                   per S8's explicit correction (seven artifacts return NOASSERTION over a real licence;
                   one hides a restrictive one).
Inputs/artifact refs: plan/00-SPINE.md S8 (SPDX allowlist gate description); the licence list at S4
                   (opengrep LGPL-2.1, Trivy Apache-2.0, Nuclei MIT, ZAP Apache-2.0, AikidoSec/opengrep-
                   rules MIT).
Expected output schema: A table: component, LICENSE file path checked, detected SPDX identifier (read from
                   the file body's own text, not a manifest field), allowlist verdict (Apache-2.0/MIT/BSD
                   pass; LGPL-2.1 pass-with-notice-obligation flagged; anything else flagged for manual
                   review), matching S4's expected licences or flagged as a discrepancy.
Validation/evidence required: Every baked-in component from O.17's `LICENSES/` tree appears in the table;
                   any mismatch against S4's expected licence is called out explicitly, not silently
                   passed.
Stop condition:    Report complete and covers every component directory under `LICENSES/`.
Why this model:    Bounded, checkable mechanical verification against an already-produced file tree — the
                   haiku lane per 00-ROUTING.md ("fastest worker: repo discovery, extraction... give
                   bounded checkable outputs").
```

### Serial (final)

```
Step ID:          O.20
Phase/group:      serial
Depends on:        O.17, O.19
Backend/model:    OpenCode route openai/gpt-5.5-fast
Objective:        Cross-family critique of the final licence conclusions for the container image
                   distribution form — the notice-and-offer-source trigger point, Apache §4 NOTICE
                   aggregation, and the SPDX allowlist scan's completeness.
Scope and files:  READ ONLY: Dockerfile, NOTICE, LICENSES/ (O.17), LICENSE-SCAN-REPORT.md (O.19). WRITE:
                   REVIEW-O.20.md alongside LICENSE-SCAN-REPORT.md.
Forbidden actions: Do not modify any reviewed file. Do not accept a licence conclusion sourced from
                   package-manager metadata rather than a file body.
Inputs/artifact refs: plan/00-SPINE.md S8 in full.
Expected output schema: A findings list confirming: the LGPL-2.1 offer-source trigger point named in O.17
                   is real and reachable (not aspirational); the NOTICE file's Apache §4 attributions match
                   the actual baked-in Apache-licensed components; the SPDX scan report has no silent gaps
                   against the S4 expected-licence list.
Validation/evidence required: Each confirmation cites the specific file/section checked.
Stop condition:    Findings list delivered with an explicit PASS/FAIL; any FAIL is marked blocking for the
                   orchestrator.
Why this model:    Licence conclusions require an independent, different-family critic per 00-ROUTING.md's
                   gate table; gpt-5.5-fast is justified because the scope is a bounded verification against
                   two already-produced artifacts (O.17, O.19), not open architecture.
```

## Scan Controller State Machine

Owner: the `anvil-scanctl` component (`internal/scanctl`), one process, one state machine, per S10.

| State | Entered when | Exits to | What may consume the record here |
|---|---|---|---|
| `open` | `scan_id` created at scan start (`t=0`); `deadline_at = created_at + deadline` (config, default 8h) | `sast_sealed` when `sast.status → complete` and the SAST half is sealed (`sast.sealed_at` set) · `expired` if `deadline_at` is reached with nothing sealed | Nothing external. Only producers (SAST/DAST workers) may write into the bounded rings feeding this record; no consumer may lease a finding yet. |
| `sast_sealed` | SAST half seals (`sast.sealed_at` set); version bumps once here per S6's ordering rule | `sealed` when `dast.status` reaches a terminal state (`complete`/`failed`/`timed_out`, the latter forced by `dast_deadline`, default 4h) · `expired` if `deadline_at` is reached before DAST terminates | The coding agent may lease and act on findings tagged `static_only` via the handoff table. Findings tagged `requires_dynamic_confirmation` are visible but not leasable. The publish pipeline may emit a partial, SAST-only SARIF projection. |
| `sealed` | Both halves reached a terminal state; this is the **single point** the DB write happens (S6: buffer carries incremental versions, the store carries the settled one) | `expired` only via lease/claim exhaustion of the audit's own retention (archival), not a normal transition — `sealed` is otherwise terminal for the audit lifecycle itself, though handoff leases against it continue until consumed or archived | The coding agent may lease any finding, including `requires_dynamic_confirmation` ones, now that DAST has landed or definitively timed out. The correlator finalizes cross-half correlation. The publish pipeline emits the final unified SARIF. |
| `expired` | `deadline_at` reached without full seal, or `dast_deadline` elapses forcing `dast.status = timed_out` and the controller closes the record regardless of completeness | Terminal — no further transitions | Read-only forensics/audit-log access only. No new lease may be acquired. Any outstanding lease is revoked; a re-entrant reclaim against an `expired` record must fail closed, not silently succeed. |

Cross-cutting rules that hold in every state:
- **Re-entrancy:** all consumption goes through the handoff table's lease protocol (O.3). A consumer that
  dies mid-lease (including one killed by `OOMPolicy=stop`, per the resource-governance section) has its
  lease reclaimed after expiry and re-processing is idempotent, keyed by `(finding_fingerprint,
  record_version)`.
- **Deadline anchoring:** `deadline_at` is anchored to `created_at`, never to the last write — an
  unbounded DAST tail must not silently extend retention (research/21 §5, reason 1).
- **The 6h/5-day/ZAP-runtime collision (O.1):** resolved by construction — the Action that can hit the 6h
  cap never executes the scan itself (thin trigger, fat daemon), self-hosted's 5-day cap is moot because
  self-hosted-on-public-repo is refused, and `dast_deadline` bounds ZAP's ability to outrun the 8h window.
  The residual risk (daemon-side DAST needs to independently manage a GitHub check-run once the triggering
  Action has returned) is not fully designed here — see Open Questions.

## Trigger Policy Schema

The `.anvil/policy.yml` shape (annotated; full JSON Schema shipped by O.5 at
`schemas/policy.schema.json`, also served by the daemon itself at a stable local URL so schema resolution
never depends on live internet access):

```yaml
version: 1                       # schema version, not an Anvil version

defaults:                        # merged with matched scanRules[]; array order, later overrides earlier
  detectors: [sast]               # DAST is opt-in, never a default — enforced by defaults, not by code
  depth: delta
  timeout: 20m
  failOn: high
  publish: [sarif]

scanRules:
  - name: push-delta              # SAST on every push — owner's explicit requirement, expressed as data
    matchEvents: [push]
    matchRefs: ["refs/heads/**"]
    matchPaths: ["**"]
    matchPathsIgnore: ["docs/**", "**/*.md"]
    detectors: [sast]
    depth: delta

  - name: major-release-full      # SAST+DAST only on tagged releases, semver-gated
    matchEvents: [push, release]  # both — >3 tags at once drops plain push events
    matchRefs: ["refs/tags/v*"]
    matchSemverBump: [major]      # computed by Anvil (O.7), never read from the GitHub payload
    detectors: [sast, dast]
    depth: full
    timeout: 90m
    dast: { profile: authenticated, maxDuration: 45m }

  - name: nightly-regression      # the daemon-side systemd clock is authoritative; GitHub schedule: is a
    matchEvents: [schedule]       # mirror only, because it auto-disables after 60 days of inactivity
    schedule: { onCalendar: "*-*-* 03:17:00", persistent: true, randomizedDelay: 20m }
    detectors: [sast]
    depth: full
```

Config search order (O.5, `internal/policy/locate.go`), stop at first match:
`.anvil/policy.yml` → `.anvil/policy.yaml` → `.anvil/policy.toml` → `anvil.toml` → `.github/anvil.yml`.

**Nothing in this shape is hard-coded in Anvil.** Event names, ref globs, semver-bump kinds, cadences,
timeouts, and severity gates are all parsed values; the engine (O.6) is generic over whatever `scanRules`
the file contains. This satisfies the owner's hard constraint directly — a code review that finds a
literal `"push"` or `"major"` string used as a match condition anywhere outside the parser is a defect.

## Resource Profile Per Tier

All numbers below are either **derived** (shown as arithmetic against the S9 tier total) or marked
**MEASURE FIRST**. None are carried forward from research/21's example figures, which the corpus itself
flags as lacking derivation.

### Tier S — 8 GB / 4 core, no GPU (S9: SAST only, coding agent remote, DAST off)

| Slice | Directive | Value | Basis |
|---|---|---|---|
| `anvil-core.slice` | `MemoryLow=` / `MemoryMax=` | 768M / 1.5G | derived: ~12.5–19% of 8G reserved for the must-survive audit path (buffer+DB+API+scheduler), scaled down from a flat percentage-of-total rule rather than copied from a larger tier's absolute number |
| `anvil-detect.slice` | `AllowedCPUs=` / `MemoryHigh=` / `MemoryMax=` | `0-3` (all 4 cores, one socket) / 3G / 3.5G | derived: encoder (~0.2G) + one resident SAST generative verifier at Q4_K_M (~2B params × ~0.6G/B ≈ 1.2G weights) + KV (~0.3–0.5G) ≈ 1.7–1.9G working set, headroom to 3G before throttle |
| `anvil-recall.slice` | `MemoryMax=`, `IOWeight=` | 1.5G / 200 | opengrep/Trivy subprocess bound — **MEASURE FIRST**: no sourced figure for resident memory under a real repo's recall pass exists in the corpus |
| `anvil-scan.slice` | — | **masked/not started** | DAST is off on Tier S per S9 — the unit is disabled, not merely idle |
| `anvil-fix.slice` | `MemoryMax=` / `CPUQuota=` | 256M / 50% | coding agent is remote on Tier S (S9) — this slice runs only a thin HTTP client, no local weights |

Worst-case concurrent total: 1.5 + 3.5 + 1.5 + 0.25 ≈ **6.75G of 8G**, leaving ~1.25G for OS/kernel/page
cache — derived arithmetic, tight by design; the recall figure needs measurement before this is trusted
under load.

### Tier M — 32 GB / 8 core (S9: SAST + DAST against declared ephemeral targets, coding agent remote)

| Slice | Directive | Value | Basis |
|---|---|---|---|
| `anvil-core.slice` | `MemoryLow=` / `MemoryMax=` | 2G / 4G | derived: same ~12.5% reservation ratio as Tier S, applied to 32G |
| `anvil-detect.slice` | `AllowedCPUs=` / `AllowedMemoryNodes=` / `MemoryHigh=` / `MemoryMax=` | `0-7` / `0` / 10G / 12G | derived: two resident detectors now (SAST + DAST share the same base per S4, DAST carries a larger context — 32768 vs 16384 tokens — so roughly double the KV of Tier S's single detector) ≈ 6–8G working set, headroom to 10G |
| `anvil-scan.slice` | `MemoryMax=` / `IOWeight=` | 8G / 150 | DAST dynamic tooling (nuclei always-on, ZAP scheduled full scans) against gVisor-contained ephemeral targets — **MEASURE FIRST** on the target-container + fuzzer-fork memory ceiling; 8G is a budget ceiling, not a derived working-set figure |
| `anvil-recall.slice` | `MemoryMax=` | 3G | derived: same recall role as Tier S, larger ceiling for the larger repos expected on this tier — **MEASURE FIRST** for the real figure |
| `anvil-fix.slice` | `MemoryMax=` | 256M | coding agent remote on Tier M too (S9) — same thin-client budget as Tier S |

Worst-case concurrent total: 4 + 12 + 8 + 3 + 0.25 ≈ **27.25G of 32G**, leaving ~4.75G headroom — derived
arithmetic; the two MEASURE FIRST entries (scan, recall) are the numbers most likely to need revision.

### Tier L — 64 GB+ / GPU (S9: everything local)

| Slice | Directive | Value | Basis |
|---|---|---|---|
| `anvil-core.slice` | `MemoryLow=` / `MemoryMax=` | 4G / 8G | derived: same ~12.5% ratio applied to a 64G floor |
| `anvil-detect.slice` | `MemoryHigh=` / `MemoryMax=` | 14G / 16G | derived, CPU-pinned per research/05 ("keep the detection tier on CPU regardless... put only the coder on GPU") — same two-detector shape as Tier M with more KV headroom |
| `anvil-scan.slice` | `MemoryMax=` | 12G | full local DAST plus S4's sanitizer-instrumented dynamic-analysis path (ASan+UBSan test suites) — **MEASURE FIRST**, same caveat as Tier M |
| `anvil-fix.slice` | all directives | **MEASURE FIRST — do not ship a fixed number yet** | S4 selects Qwen3-Coder-Next (3B active / 80B total, explicitly **RAM-bound, not VRAM-bound**) as the coding model. Research/05's example coder budgets (24G/28G-class figures) were built against 7–27B **dense** models. An 80B-total MoE at Q4_K_M (~0.6G/B) implies a resident-weight footprint that can approach or exceed 48G even though only ~3B parameters are active per token, because MoE serving typically keeps all experts resident in RAM. Against a 64G floor, that leaves little or no room for the 14G/16G detect slice and 12G scan slice running concurrently. This must be measured against the actual shipped quantization before Tier L's fix-slice numbers are fixed — shipping a guessed number here risks exactly the "MemoryHigh looks like a hang" failure mode with no way to tell whether it is throttling or genuinely undersized. |

**Cross-tier note (all tiers):** never combine `--mlock`-equivalent pinning on the resident detector
processes with a `MemoryMax=` on the same slice without slack — locked pages are not reclaimable, so a
unit relying on both converts a graceful `MemoryHigh=` throttle into an immediate OOM kill (research/21 §E).
The `MemoryHigh=` throttle-vs-wedged distinction (O.14's liveness signal) applies identically across all
three tiers and is the reason `OOMPolicy=stop` is set on `anvil-fix.slice`, not left at the default
`continue` — a stopped unit lands cleanly in `oom-kill` failed state where `Restart=` and lease-expiry
reclaim (O.3) can both act on it; `continue` would leave a half-alive coder holding a stale lease.

**What is disabled per tier:**
- **S:** `anvil-scan.slice` (DAST) masked entirely; no local coding-model weights (remote only); no GPU
  partitioning logic applies.
- **M:** no local coding-model weights (remote only, same as S); DAST runs only against declared,
  gVisor-contained ephemeral targets, not as an always-on concurrent default (S9: "DAST is an opt-in tier,
  not a concurrent default"); no GPU partitioning logic applies (no GPU on this tier).
- **L:** nothing structurally disabled — but the fix-slice MEASURE FIRST caveat above means Tier L should
  not be marketed as "everything fits in 64G" until the coder's real footprint is measured; if a single
  GPU is present, keep the detection tier on CPU regardless and reserve the GPU for the coder only
  (research/05).

## Exit Criteria

- State machine: unit tests cover all four states and every valid/invalid transition; a slow/non-
  terminating DAST run still produces `open → sast_sealed → expired` (never stuck `open`).
- Handoff/lease: a test that kills a lease holder mid-claim, expires the lease, reclaims it, and
  re-processes asserts no duplicate side effect and no corruption of an `expired` record's terminal state.
- Policy: a policy fixture expressing "SAST on every push, SAST+DAST only on tagged releases, semver-bump
  gated" round-trips through the JSON Schema and the engine, resolving to the correct detector set per
  event scenario; the five-path config search order resolves correctly including the not-found case.
- Semver bump: the git-plumbing wrapper classifies a real major/minor/patch/prerelease tag sequence
  correctly and fails with a distinct, named error on a shallow checkout rather than a generic git error.
- Action: the delta-SAST path runs inline without downloading weights; the full/DAST path dispatches to
  the daemon without ever blocking the Action's own job past a bounded duration; the self-hosted-on-
  public-repos warning is present verbatim in shipped docs, and no shipped workflow uses
  `pull_request_target`.
- SARIF publish: a synthetic >8MB/>4,000-result payload is trimmed by the pre-upload gate before any
  network call, with dropped severities reported back.
- GitHub App: a PR opened via the App's installation token triggers a workflow run in a scratch-repo
  integration test; the App's declared scopes are asserted (not just documented) to exclude merge/approve.
- Resource governance: `systemd-analyze verify` passes on every unit/slice file for all three tiers; an
  injected-pressure test distinguishes `Throttled` from `Wedged` via the liveness signal; a synthetic OOM
  on the coder unit confirms `OOMPolicy=stop` lands it in `oom-kill` failed state, not `continue`.
  Every numeric directive across all three tiers is either derivation-annotated or MEASURE FIRST-labelled
  — a directive with neither is a failing exit condition, not a style nit.
- Queue/backpressure: a load test past the ring bound shows zero drops with the producer blocking; a load
  test past the admission watermark shows a clean `ErrAtCapacity`/503 with no partial `AuditRecord` left
  behind.
- Distribution: `CGO_ENABLED=0` static binary verified for linux/amd64 and linux/arm64; the container
  image's licence scan (O.19/O.20) shows zero components whose licence was read from package-manager
  metadata rather than a LICENSE file body, and zero unresolved NOASSERTION/restrictive findings; the
  systemd tarball installs and `anvil-full-scan.timer` activates with the correct jittered next-elapse
  time in a clean smoke test.
- All four mandatory cross-family critic steps (O.4, O.11, O.15, O.20) return a findings list with no
  unaddressed blocking finding.

## Pinned Versions And Licences

Scoped to this section's own dependencies (detector/model licensing is owned elsewhere, per S8's
per-component pinning discipline):

| Component | Role here | Licence | Note |
|---|---|---|---|
| systemd | slice tree, timer, service management | LGPL-2.1-or-later | invoked as PID 1's own facility, not linked into the Anvil binary — no obligation triggered |
| Go toolchain / `CGO_ENABLED=0` build | static binary | BSD-3-Clause (Go) | per S12; no cgo, `modernc.org/sqlite` remains the store driver, unchanged by this section |
| Anvil's own Action + daemon code | trigger + orchestration | Apache-2.0 | per S8 core licence posture |
| Renovate `packageRules` naming convention | `.anvil/policy.yml` vocabulary | N/A — convention only | Renovate itself is AGPL-3.0; **no Renovate code is vendored**; copying config-key naming is fine, importing Renovate modules is not (research/09 Risks #9) |
| opengrep engine | invoked by SAST recall (not built here, but the licence trigger point this section's container image (O.17) crosses) | LGPL-2.1 | notice-and-offer-source obligation triggers at container-image distribution, not at binary distribution — O.17 must name the reachable offer point explicitly |
| Trivy, ZAP | invoked by SCA/DAST (not built here) | Apache-2.0 | §4 NOTICE aggregation only |
| Nuclei, AikidoSec/opengrep-rules | invoked by DAST/SAST recall (not built here) | MIT | attribution only |
| GitHub App auth library (Go JWT signing) | O.10 | **TBD at implementation time** | not selected in this packet — the worker executing O.10 must pick one, verify its LICENSE file body per S8's mechanics, and record it in `LICENSES/` at O.17 time even though the App code itself is not baked into the container image (the daemon binary is) |

Exact model-revision SHA pinning (S8's "pin exact model revision SHAs and archive each model's LICENSE at
that revision") is out of scope here — it belongs to the detector/model-serving sections, not the scan
controller/CI/resource section.

## Open Questions

- **Daemon-side check-run reconciliation.** O.1 flags but does not fully design how the daemon updates a
  GitHub check-run/commit-status once the triggering Action has already returned (thin-Action/fat-daemon
  means the Action's own job status cannot represent a multi-hour DAST run). Needs a follow-up design
  spike before the Action/daemon dispatch contract is considered final.
- **Tier L coding-agent footprint.** Whether Qwen3-Coder-Next (80B-total MoE, RAM-bound) actually fits
  alongside a resident detect+scan slice on a 64G floor is unmeasured — flagged MEASURE FIRST throughout
  the Resource Profile section rather than guessed at.
- **`anvil-recall.slice` and `anvil-scan.slice` real memory ceilings** (opengrep/Trivy recall pass; ZAP/
  nuclei/fuzzer dynamic pass) have no sourced figures anywhere in the research corpus for any tier —
  every occurrence in this section is MEASURE FIRST, not derived.
- **`repository_dispatch`'s default-branch-only restriction** (research/09 Risks #12) means a rescan of a
  non-default release branch needs an explicit `client_payload` branch reference and checkout — not fully
  exercised by O.8's scratch-repo smoke test as scoped; worth a dedicated multi-branch integration test
  before this is considered hardened.
- **The OSS-CRS adapter spike** (S11's open thread: whether `crs-bug-finding-template`/`crs-patch-ensemble`
  could be retargeted from OSS-Fuzz-crash input to Anvil's SARIF record) is not addressed by this section
  and remains a bounded spike for whichever section owns the coding-agent/remediation tier, not a blocker
  here.
- **Whether the JSON Schema's "stable URL"** should be a GitHub Pages URL, a project domain, or purely the
  daemon's own self-served `/schemas/policy.v1.json` endpoint was left to O.5's implementer to decide and
  state — not resolved at the planning level, since it does not affect any other step's contract.
- **The Action-side policy engine reimplementation** (O.8) — whether the Action cross-compiles O.6's Go
  engine into a small standalone binary/action or reimplements a subset in the Action's own runtime — is
  left to O.8's implementer to decide and justify; both are consistent with "thin trigger, fat daemon" as
  long as the Action never gains the CVE cache or model weights.

## Conflicts With Spine

- **research/21's primary recommendation (one base model + two vLLM LoRA adapters, one process) is not
  adopted anywhere in this section.** This is not a new conflict — spine S4 ("Not vLLM in v1... its
  multi-LoRA design requires fine-tuned adapters that must not exist before S3") and S12 (Go, no cgo,
  llama.cpp/llama-server) already resolved this in favor of the llama.cpp process model. Recorded here
  only so a reader of research/21 does not wonder why its systemd-slice-tree and queue material was used
  in this section while its serving-engine recommendation was not: the two are separable, and only the
  serving-engine choice was pre-empted by spine.
- **research/21's concrete resource numbers (e.g. `MemoryHigh=18G`/`MemoryMax=22G` on the detect slice)
  are not carried forward.** Per this packet's explicit instruction, they are treated as unsourced and
  potentially in tension with S9's minimal-compute framing; O.12 re-derives every figure from the S9 tier
  matrix instead. This is a resolved discrepancy, not an open conflict — flagged here for traceability.
- **No unresolved contradiction between this section's design and 00-SPINE.md was found.** The one
  genuine tension surfaced during planning — GitHub's 6-hour job cap / self-hosted's 5-day cap / a ZAP
  full scan's ability to outrun the 8-hour retention window — is a research-corpus gap (spine never
  addressed it directly), not a spine conflict, and O.1 resolves it by construction within spine's own
  thin-Action/fat-daemon (S10-consistent) and self-hosted-refusal posture. The one residual piece (check-
  run reconciliation) is carried to Open Questions rather than Conflicts, since it does not contradict any
  spine decision — it is simply undesigned.
