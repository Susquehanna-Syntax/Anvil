# Anvil Implementation — Dynamic Tier

## Overview

This file builds Anvil's dynamic (DAST) tier as an opt-in add-on to the always-on SAST tier (spine S9): a
fail-closed authorization kernel no model can reach, a declared-manifest-only provisioning and gVisor
containment harness, Nuclei-always/ZAP-scheduled probe engines under a pinned and quarantined template
supply chain, a four-tier attack-surface inventory that treats static extraction as candidates and browser
crawling as a scheduled-only last resort, and a confirmation gate that keeps raw response bodies out of any
model prompt before a finding reaches the record. The DAST model is the same base model as the SAST
adjudicator with a larger context and turn budget and a hard turn cap — not more parameters; the one
research branch that argued for 9B rested on a self-reported single-family (Qwen-only) benchmark and a
vendor blog whose aggregate pass rate was computed after the challenge sub-class that scored 0% had been
dropped from the suite, while five other branches independently concluded same-size-or-smaller is
sufficient because detection is done by deterministic engines and the model never holds a network handle.
For most targets — only 56.1% of Dockerfile-bearing repos build, and the best agentic environment builder
reaches 37.7% — the DAST half of the record will be empty, which is why every step below treats "no target
manifest," "target failed to boot," and "scanned clean" as three distinct, distinguishable record states.
Note on terminology: "Nuclei always-on" below describes Nuclei's role *inside* an enabled DAST run relative
to ZAP's scheduled-only role, not the DAST tier's own trigger policy, which stays opt-in per S9 — the two
are different axes and are not in tension. Fuzzing, nmap, and sqlmap are out of scope for this file by
spine directive (S5/S8) and are not designed in below.

---

## Dependency Summary

Assumes the Go module root and `cmd/` layout already established by the core control-plane bootstrap
(out of scope for this file — see `plan/80-compliance.md` for the sibling `cmd/license-gate/` precedent).
All paths below are relative to the repo root.

| Area | Steps | Upstream deps outside this file | Feeds into |
|---|---|---|---|
| Target manifest | D.1 | none | D.10, D.13, D.18, D.26 |
| Authorization kernel | D.2–D.9 | none — foundational, compiled separately per S7 | every step that issues a request: D.14, D.15, D.18, D.23, D.29 |
| Containment (provisioning + network) | D.10–D.13 | D.1, D.9 | D.14, D.15, D.18, D.23 |
| Probe engines | D.14–D.17 | D.9, D.13 | D.18, D.23, D.24, D.27 |
| Attack-surface inventory | D.18–D.25 | D.9, D.13, D.15; **D.19 additionally reads the SAST tier's harvested spec files — a cross-file dependency on the not-yet-written SAST plan** | D.26 |
| Coverage + confirmation + model | D.26–D.30 | D.9, D.13, D.14, D.15, D.18–D.22; **D.29 additionally inherits its base-model pick from the SAST adjudicator selection, owned by the SAST plan** | D.31; the coding agent's consumption path (research 24, not this file) |
| Integration | D.31 | all of the above | none — terminal |

Two coordination points are flagged rather than guessed at: (1) D.19 needs the field name/shape the SAST
tier uses to hand off harvested `openapi.yaml`/`swagger.json`/`*.wsdl`/`schema.graphql`/Postman files inside
the unified audit record — confirm against the SAST plan once it exists, do not invent a shape here; (2)
D.29's model identity (`Qwen3.5-2B` pending text-only-variant verification, or `Gemma 4`, per spine S4) is
whatever the SAST plan's Milestone-0 evaluation (S3) resolves to — this file only adds context/turn-budget/
turn-cap deltas on top of that pick, it does not choose the base model.

---

## Steps

### Parallel group 1 — foundations, no shared state

```
Step ID:          D.1
Phase/group:      parallel group 1
Depends on:       none
Backend/model:    Claude Code subagent (sonnet)
Objective:        Implement the .anvil/target.yaml manifest schema, its strict loader, and the
                   absent-manifest skip path.
Scope and files:  WRITE: internal/dast/target/manifest.go, internal/dast/target/manifest_test.go.
                   READ: 00-SPINE.md S1(#5), S9; research/19-target-environment-and-sandboxing.md
                   Recommendation section (lines 151–182); this file's "Target Manifest Schema" section
                   below (authoritative for field names).
Forbidden actions: No auto-inference of how to run a repo (no Dockerfile sniffing, no framework
                   detection, no "guess the port" fallback). No network calls. Do not invent fields not
                   in the schema below without flagging them as a proposed extension in the PR description.
Inputs/artifact refs: This file's Target Manifest Schema section (below).
Expected output schema: A `Manifest` Go struct matching the YAML schema below, a `Load(path string)
                   (*Manifest, SkipReason, error)` function where a missing file returns
                   `(nil, SkipReasonNoManifest, nil)` — not an error — and a schema-invalid file returns
                   `(nil, SkipReasonInvalidManifest, nil)`. Both skip reasons must serialize directly into
                   the record's `dast_status`/`target_provenance` fields (D.26).
Validation/evidence required: `go test ./internal/dast/target/...` green, including one fixture per skip
                   reason and one fixture for a fully valid manifest with every optional field populated.
Stop condition:    Loader round-trips the example manifest below byte-for-byte on re-marshal, and both
                   skip-reason fixtures pass.
Why this model:    Bounded, well-specified schema + loader implementation — default strong worker per
                   00-ROUTING.md; not architecturally ambiguous enough to justify opus.
```

```
Step ID:          D.2
Phase/group:      parallel group 1
Depends on:       none
Backend/model:    Claude Code subagent (opus)
Objective:        Design and implement the authorization kernel's core types and Phase 0 (build/packaging)
                   gates 1–3, establishing the compiled-separately module boundary every later gate builds on.
Scope and files:  WRITE: internal/dast/authz/kernel.go, internal/dast/authz/types.go,
                   internal/dast/authz/phase0_build.go. READ: 00-SPINE.md S7; research/20-authorization-
                   legality-and-safety.md Recommendation section (lines 135–199), specifically Phase 0
                   (gates 1–3); this file's "Authorization Gate Sequence" section (authoritative).
Forbidden actions: `internal/dast/authz` must import nothing from any inference/model-runtime package —
                   this is the invariant D.9's build-time test later asserts. No gate implementation may
                   read a config key that raises a cap above its coded floor. No `net.Dial`, `http.Client`,
                   or any socket-construction call anywhere in this package (that is Phase 3's job, gated).
Inputs/artifact refs: This file's Authorization Gate Sequence section (below) is authoritative over the
                   research doc's prose for exact gate numbering.
Expected output schema: `Decision(target Target, scope Scope, attestation Attestation, clock Clock)
                   (Allow|Deny, Reason)` as the kernel's pure-function signature (S7). A `Mode` enum
                   {Lab, External} with no `Auto` value. `dast.enabled` defaulting to `false` at the type
                   level (a struct field with no zero-value path to `true`). Gates 1–3 as named functions
                   callable from a build-time test, each returning a typed failure, not a bool.
Validation/evidence required: `go build ./...` and `go vet ./...` clean. A written note (in the PR
                   description, not a new file) confirming zero imports from any package path containing
                   `/inference/`, `/model/`, or `/llm/`.
Stop condition:    Kernel core types compile, gates 1–3 are implemented and unit-tested, and the module
                   boundary is clean enough that D.9's dependency-graph test (written later) has something
                   real to assert against.
Why this model:    This is the one genuinely hard architectural sub-problem in the file — it fixes the
                   pure-function contract, the compiled-separately boundary, and the Mode/Decision shape
                   every other gate step (D.4–D.7) and every engine step inherits. Getting it wrong here
                   propagates. 00-ROUTING.md reserves opus for exactly this: "the one genuinely hard
                   parallel sub-problem," not for bounded chores.
```

### Serial — critic on the kernel foundation

```
Step ID:          D.3
Phase/group:      serial
Depends on:       D.2
Backend/model:    OpenCode route (openai/gpt-5.5)
Objective:        Independently critique the kernel's core types and Phase 0 gates for the specific
                   failure this branch is built to prevent: any path by which a model could end up holding
                   a network handle or influencing the Decision function's inputs without going through
                   Scope/Attestation.
Scope and files:  READ ONLY: internal/dast/authz/kernel.go, internal/dast/authz/types.go,
                   internal/dast/authz/phase0_build.go, research/20-authorization-legality-and-safety.md.
                   WRITE: none (critique returned as text/PR comment, not a file).
Forbidden actions: No code changes. No approval of a design that lets any config key raise a coded floor.
Inputs/artifact refs: D.2's diff.
Expected output schema: A pass/fail verdict plus a numbered list of concrete bypass scenarios attempted
                   (e.g., "can a future gate import authz and also import the model runtime without the
                   build breaking?") and whether each was actually blocked.
Validation/evidence required: Verdict must cite the specific line(s) that enforce or fail to enforce each
                   scenario checked.
Stop condition:    Verdict delivered; if FAIL, D.2 is reopened (reroute once per 00-ROUTING.md rerouting
                   rule) before D.4–D.7 proceed.
Why this model:    Cross-family critique is mandatory for security-relevant code per 00-ROUTING.md's
                   cross-family critique rule — Anthropic-written security code requires an OpenCode/
                   OpenRouter critic from a different model family, not another Anthropic pass.
```

### Parallel group 2 — the remaining 18 gates, disjoint files, same kernel contract

```
Step ID:          D.4
Phase/group:      parallel group 2
Depends on:       D.2, D.3
Backend/model:    Claude Code subagent (sonnet)
Objective:        Implement Phase 1 (run initiation) gates 4–7: scope-file strict parsing, attestation
                   validation, explicit irreversible mode declaration, and CI trigger-provenance checking.
Scope and files:  WRITE: internal/dast/authz/phase1_run.go, internal/dast/authz/phase1_run_test.go.
                   READ: internal/dast/authz/kernel.go, internal/dast/authz/types.go (D.2, do not modify);
                   this file's Authorization Gate Sequence section, gates 4–7.
Forbidden actions: No "auto" mode value anywhere, including as an internal sentinel. No relaxation of gate
                   7's provenance check for a documented "trusted fork" exception — configurability here is
                   limited to which trigger sources are permitted, never to whether provenance is checked.
Inputs/artifact refs: research/20-authorization-legality-and-safety.md lines 171–177 (gates 4–7).
Expected output schema: Four gate functions matching D.2's typed-failure convention; scope-file schema
                   validator that yields zero permitted targets on any malformed/missing/unknown-field
                   input (deny-by-default, never allow-all).
Validation/evidence required: Unit tests: malformed scope file → zero targets; expired attestation →
                   refuse; scope-hash mismatch after scope edit → attestation invalidated; fork-PR-style
                   trigger context → refuse.
Stop condition:    All four gates implemented and tested against the deny-by-default fixtures above.
Why this model:    Bounded implementation against an already-fixed contract (D.2) — default strong worker;
                   the hard architectural call was made in D.2, this is applying it.
```

```
Step ID:          D.5
Phase/group:      parallel group 2
Depends on:       D.2, D.3
Backend/model:    Claude Code subagent (sonnet)
Objective:        Implement Phase 2 (per-target admission) gates 8–12: canonicalization, DNS-resolve-and-
                   pin matching, the non-configurable reserved-range denylist, robots/ToS as additional-
                   deny-only, and security.txt resolved for reporting-channel purposes with admission-
                   function type-level exclusion.
Scope and files:  WRITE: internal/dast/authz/phase2_admission.go, internal/dast/authz/phase2_admission_test.go.
                   READ: internal/dast/authz/kernel.go, internal/dast/authz/types.go.
Forbidden actions: The reserved-range denylist (gate 10) must be an unexported Go `const`/package-level
                   slice with no config-loader path that can append, remove, or shadow an entry. Gate 12's
                   `SecurityTxtResult` type must not appear anywhere in the `Decision(...)` function
                   signature or any type it transitively references — this is the literal "enforce at the
                   type level" instruction from spine S7, not a runtime check to bypass later.
Inputs/artifact refs: research/20-authorization-legality-and-safety.md lines 178–184 (gates 8–12); RFC 9116
                   for security.txt semantics (research 20, S12/S26 — parse Contact/Policy/Encryption/
                   Preferred-Languages, honour /.well-known/ precedence, refuse expired `Expires`).
Expected output schema: `Canonicalize(host string) (string, error)` (IDNA/punycode, case fold, trailing-
                   dot strip, percent-decode, port normalize, IPv4-mapped-IPv6 unwrap); `ResolveAndPin(host
                   string) (net.IP, error)` that connects only to the pinned address, never re-resolving
                   between check and connect; the reserved-range denylist as a named constant; a
                   `FetchSecurityTxt(...) SecurityTxtResult` function whose result is stored only in the
                   audit log path, never threaded into `Decision(...)`.
Validation/evidence required: Unit tests: DNS-rebinding fixture (resolve returns scope-allowed IP, connect
                   time re-resolve returns metadata IP — must use the pinned address); reserved-range probe
                   for all of 127.0.0.0/8, 10/8, 172.16/12, 192.168/16, 169.254/16 (incl. 169.254.169.254),
                   100.64/10, 0.0.0.0/8, ::1, fc00::/7, fe80::/10 rejected in `external` mode; a compile-time
                   or reflection-based test proving `SecurityTxtResult` is unreachable from `Decision`'s
                   argument types.
Stop condition:    All five gates implemented; the security.txt type-separation test and the reserved-range
                   fixture both pass.
Why this model:    Bounded implementation against D.2's fixed contract; the specific type-level-enforcement
                   requirement is a concrete, checkable constraint rather than an open design question.
```

```
Step ID:          D.6
Phase/group:      parallel group 2
Depends on:       D.2, D.3
Backend/model:    Claude Code subagent (sonnet)
Objective:        Implement Phase 3 (per-request enforcement) gates 13–17 — the phase research 20 flags as
                   "the gate that ZAP got wrong": re-validate scope on every request including every
                   redirect hop, hard non-configurable rate/connection/volume caps, the destructive-
                   technique denylist, the target-health circuit breaker, and absolute 429/Retry-After
                   honouring.
Scope and files:  WRITE: internal/dast/authz/phase3_enforcement.go, internal/dast/authz/phase3_enforcement_test.go.
                   READ: internal/dast/authz/kernel.go, internal/dast/authz/phase2_admission.go (D.5, do
                   not modify — call its exported functions).
Forbidden actions: Never follow a cross-host redirect, under any circumstance, including same-registrable-
                   domain-but-different-host cases — the run must record the redirect and stop that branch,
                   not "helpfully" continue. No config key may raise any of the five hard caps (≤10 rps/
                   host, ≤4 concurrent/host, ≤20,000 req/target/run, ≤30 min/target, ≤1 MiB body, ≤3
                   retries) above its coded floor — lowering is the only permitted direction. The
                   destructive-technique classifier must be a static compiled-in list, never a model
                   judgement call.
Inputs/artifact refs: research/20-authorization-legality-and-safety.md lines 186–192 (gates 13–17), and
                   its citation of ZAP issue #2546 (scope as a job-level property, not a per-request one) as
                   the exact failure mode to reproduce-and-block in tests.
Expected output schema: A per-request interceptor that re-runs gates 8–10 (via D.5's exported functions)
                   for every `Location` header, template-supplied absolute URL, WebSocket upgrade, and
                   headless-browser-issued fetch/XHR; a token-bucket rate limiter with the five caps as
                   compiled floors; a static `DestructiveTechniques` list (DoS/resource-exhaustion probes,
                   credential brute force, lockout-triggering sequences, state-changing verbs without a
                   per-endpoint explicit allow, exploitation past proof-of-existence); a health-circuit-
                   breaker tracking 5xx rate / connection-error rate / p95 latency against a first-60-second
                   baseline.
Validation/evidence required: A reproduction test of the ZAP #2546 scenario (scope set to loopback,
                   response 302s to an external host mid-scan) asserting the redirect is refused and
                   logged, not followed. A test asserting no combination of config values can push any of
                   the five caps above its floor. A circuit-breaker test that trips at 5xx>10% or
                   p95>3×baseline sustained 30s and quarantines the target for the rest of the run.
Stop condition:    All five gates implemented; the #2546-reproduction test and the cap-floor test both pass.
Why this model:    Bounded implementation against D.2/D.5's fixed contracts, with a named reproduction
                   target (ZAP #2546) that makes "done" checkable rather than a matter of judgement.
```

```
Step ID:          D.7
Phase/group:      parallel group 2
Depends on:       D.2, D.3
Backend/model:    Claude Code subagent (sonnet)
Objective:        Implement Phase 4 (output/disclosure) gates 18–21: embargo on third-party findings,
                   disclosure state persisted in the DB (not the buffer), no unsolicited fix delivery to
                   third parties, and an immutable audit log of every gate decision.
Scope and files:  WRITE: internal/dast/authz/phase4_disclosure.go, internal/dast/authz/phase4_disclosure_test.go.
                   READ: internal/dast/authz/kernel.go, internal/dast/authz/phase2_admission.go (for gate
                   12's reporting-channel result, consumed here for vendor contact, not for admission).
Forbidden actions: The 45-day CERT/CC embargo default must not be fully disablable by config — only its
                   documented acceleration (active exploitation observed) and extension (standards/core-OS
                   changes) paths may adjust it. No gate-decision write may report "allowed" if the
                   corresponding audit-log write failed — the audit write and the decision are not
                   allowed to be independent of each other's success.
Inputs/artifact refs: research/20-authorization-legality-and-safety.md lines 194–199 (gates 18–21), S1
                   corrected requirement #5 (spine) on the buffer/DB split — the 8-hour figure is a claim
                   timeout, not a deletion policy, which is what makes a 45-day embargo representable at all.
Expected output schema: An `EmbargoState` type with default 45-day clock, acceleration/extension reason
                   codes, and a `disclosure_state` field designed to live in the SQLite record store (per
                   spine S1/S6), never in the tmpfs handoff packet. A `PushGate` function requiring the same
                   `Attestation` as probing before any patch delivery to a non-operator-owned repository. An
                   append-only `GateAudit` writer keyed by attestation ID and scope hash.
Validation/evidence required: Test that a third-party finding cannot reach a "published" state before 45
                   days without an explicit acceleration reason attached; test that an audit-log write
                   failure causes the paired gate decision to fail closed (not silently allow); test that
                   `PushGate` refuses without a valid attestation even when the patch content itself is
                   benign.
Stop condition:    All four gates implemented and tested; audit log demonstrably keyed to attestation ID +
                   scope hash.
Why this model:    Bounded implementation against D.2's fixed contract; disclosure-state design choices are
                   already resolved by spine S1, leaving an implementation task.
```

### Serial — critic on the full gate stack

```
Step ID:          D.8
Phase/group:      serial
Depends on:       D.4, D.5, D.6, D.7
Backend/model:    OpenCode route (openai/gpt-5.5)
Objective:        Cross-family security review of all 21 gates as a stack, focused on gate interactions
                   D.4–D.7 could not see individually: does gate 13's redirect re-validation actually call
                   gate 10's denylist and gate 9's DNS-pinning on every hop, not just the first request; can
                   gate 12's type-level security.txt exclusion be defeated by a Phase-3 code path that reads
                   it anyway; does the reserved-range denylist (gate 10) apply inside `lab` mode where it
                   should not always apply per the gate's own text.
Scope and files:  READ ONLY: internal/dast/authz/**. WRITE: none.
Forbidden actions: No code changes. No sign-off without tracing at least one full request-with-redirect
                   path through the actual code, not the spec prose.
Inputs/artifact refs: This file's Authorization Gate Sequence section; research/20-authorization-legality-
                   and-safety.md Risks section (lines 203–216), specifically the ZAP #2546 pattern and the
                   "security.txt will be misread as permission" risk.
Expected output schema: Pass/fail verdict; a table of the 21 gates with a column for "independently
                   traced through code: yes/no" and "bypass found: yes/no + description."
Validation/evidence required: Every "no bypass found" row must cite the specific function/line that
                   prevents it.
Stop condition:    Verdict delivered; any FAIL reopens the specific offending step (reroute once).
Why this model:    Mandatory cross-family critic for security-relevant, authorization-decision code per
                   00-ROUTING.md; this is precisely the "authorization decision" case the rule names.
```

### Serial — kernel build-time invariants

```
Step ID:          D.9
Phase/group:      serial
Depends on:       D.2, D.3, D.4, D.5, D.6, D.7, D.8
Backend/model:    Claude Code subagent (sonnet)
Objective:        Add the build-time test that fails the build if the authz package's dependency graph
                   ever imports the model/inference runtime, and the CI lint plus runtime-panic test proving
                   zero outbound sockets can be opened outside the kernel.
Scope and files:  WRITE: internal/dast/authz/kernel_depgraph_test.go, internal/dast/authz/egress_chokepoint_test.go,
                   a CI lint config entry (e.g. a `.golangci.yml` rule or custom analyzer banning
                   `net.Dial`/`http.Client`/`http.Get` construction outside `internal/dast/authz`).
                   READ: internal/dast/authz/** (all prior kernel steps).
Forbidden actions: The dependency-graph test must fail the build (non-zero exit), not merely log a
                   warning, on inversion. The lint rule must cover the whole repo, not just the DAST
                   package, since the point is proving no *other* package can bypass the kernel either.
Inputs/artifact refs: spine S7 ("a build-time test that fails if the dependency graph inverts");
                   research/20-authorization-legality-and-safety.md gate 3 (Phase 0).
Expected output schema: A Go test using `go/packages` or `golang.org/x/tools/go/analysis` to walk import
                   graphs and assert no path from `internal/dast/authz` to any `*/inference/*`, `*/model/*`,
                   `*/llm/*` package; a lint rule wired into CI; a runtime test that a raw dial attempt
                   from outside the kernel package panics or returns a typed "use the kernel" error.
Validation/evidence required: Fixture test that deliberately adds a forbidden import and confirms the
                   dependency-graph test fails on it (proves the test isn't a no-op), then removes the
                   fixture and confirms green.
Stop condition:    Dependency-graph test present and demonstrated to fail on the fixture; lint rule active
                   in CI config; egress-chokepoint test green.
Why this model:    Mechanical, well-specified static-analysis + CI wiring task against an already-designed
                   contract — default strong worker, not an open architecture question.
```

### Parallel group 3 — containment

```
Step ID:          D.10
Phase/group:      parallel group 3
Depends on:       D.1
Backend/model:    Claude Code subagent (sonnet)
Objective:        Implement the target provisioning harness: `docker compose up -d` against the manifest's
                   declared Compose file, wait on healthcheck/depends_on:condition:service_healthy with a
                   hard timeout, running the whole Compose project under gVisor `runsc` on the `systrap`
                   platform.
Scope and files:  WRITE: internal/dast/containment/provision.go, internal/dast/containment/provision_test.go.
                   READ: internal/dast/target/manifest.go (D.1, do not modify).
Forbidden actions: No fallback to a non-gVisor runtime if `runsc` is unavailable — provisioning fails
                   closed (no target, `dast_status=failed_to_boot`) rather than silently running unsandboxed.
                   No `--security-opt seccomp=unconfined`, no `docker.sock` mount into the sandbox, no
                   privileged mode. runc hygiene (rootless where possible, `--cap-drop=ALL`, read-only
                   rootfs) applies underneath gVisor regardless.
Inputs/artifact refs: research/19-target-environment-and-sandboxing.md lines 157–164 (concrete v1 stack,
                   steps 1–2).
Expected output schema: `Provision(m *target.Manifest) (*Target, error)` that returns a live `Target`
                   (resolved image digest recorded, not tag — per research 19 risk #3) or a typed
                   `ErrHealthTimeout`/`ErrRunscUnavailable` mapping to `dast_status=failed_to_boot`.
Validation/evidence required: Integration test against a throwaway Compose fixture with a healthcheck,
                   asserting `runsc` is the configured runtime (inspect container `Runtime` field) and that
                   a missing/failing healthcheck produces `ErrHealthTimeout`, not a hang.
Stop condition:    Fixture target provisions successfully under gVisor and the resolved image digest is
                   captured; failure paths map to typed errors.
Why this model:    Bounded implementation against an already-specified stack (research 19's concrete v1
                   recommendation) — default strong worker.
```

```
Step ID:          D.11
Phase/group:      parallel group 3
Depends on:       D.1
Backend/model:    Claude Code subagent (sonnet)
Objective:        Implement the dedicated network namespace with default-deny egress enforced by nftables,
                   cloud-metadata v4+v6 blocking, and an assertion probe that runs on every scan to catch a
                   silent NetworkPolicy-style no-op.
Scope and files:  WRITE: internal/dast/containment/netns.go, internal/dast/containment/netns_test.go.
                   READ: internal/dast/target/manifest.go (D.1, do not modify).
Forbidden actions: Do not rely on Kubernetes NetworkPolicy as the sole enforcement mechanism (research 19
                   risk #5: "no controller → no effect, no error"). Do not skip the assertion probe on any
                   run, including "fast" or "incremental" scan modes — this is the mechanism that makes
                   containment failure loud instead of silent.
Inputs/artifact refs: research/19-target-environment-and-sandboxing.md lines 161–162 (steps 3–4), risk #5,
                   risk #9 (self-hosted runners + public repos).
Expected output schema: `SetupNetns(target *Target) error` that shells out to `nft` (subprocess only,
                   never linked — see Pinned Versions section) to install a default-deny egress ruleset in
                   the target's netns, explicitly denying `169.254.0.0/16`, `fd00:ec2::254`, and the full
                   OWASP SSRF block list (`127.0.0.0/8`, `0.0.0.0/8`, `::1/128`, `10.0.0.0/8`,
                   `172.16.0.0/12`, `192.168.0.0/16`, `224.0.0.0/4`, `ff00::/8`); an `AssertContainment(target
                   *Target) error` that, from inside the sandbox, attempts to reach `169.254.169.254` and
                   `fd00:ec2::254` and fails the run (not a warning) if either succeeds.
Validation/evidence required: A fixture that deliberately installs a broken/empty nftables ruleset and
                   confirms `AssertContainment` catches it and aborts the run (proves the probe is not
                   itself a silent no-op) — this is the concrete answer to research 19 risk #5.
Stop condition:    Default-deny ruleset installs correctly on a real target fixture; the deliberately-broken
                   fixture is caught by the assertion probe every time in a 20-run flake check.
Why this model:    Bounded implementation of an already-specified containment scheme, but the security
                   stakes (this is the control that prevents SSRF-to-cloud-metadata) mean it gets a critic
                   (D.12) rather than shipping on a single pass.
```

### Serial — critic on network containment

```
Step ID:          D.12
Phase/group:      serial
Depends on:       D.11
Backend/model:    OpenCode route (openai/gpt-5.5)
Objective:        Independently verify the assertion probe genuinely fails closed and cannot pass while
                   egress is actually open — the exact "NetworkPolicy failure is silent" failure mode
                   research 19 names as a live risk, not a hypothetical one.
Scope and files:  READ ONLY: internal/dast/containment/netns.go, internal/dast/containment/netns_test.go.
                   WRITE: none.
Forbidden actions: No sign-off without running (or requesting evidence of) the deliberately-broken-fixture
                   test from D.11 and confirming it actually aborts.
Inputs/artifact refs: research/19-target-environment-and-sandboxing.md risk #5, risk #4 (runc escapes as a
                   live recurring event, not a tail risk).
Expected output schema: Pass/fail verdict with specific attention to: does `AssertContainment` run before
                   or after the probe engines start firing (must be before); does a probe-timeout count as
                   pass or fail (must count as fail); is IPv6 metadata (`fd00:ec2::254`) actually exercised
                   or only IPv4.
Validation/evidence required: Verdict must state explicitly whether the IPv6 metadata path was checked.
Stop condition:    Verdict delivered; FAIL reopens D.11 (reroute once).
Why this model:    Mandatory cross-family critic — this is the control that stands between a probe engine
                   and cloud credential theft via SSRF; it meets 00-ROUTING.md's "security-relevant" bar
                   directly.
```

### Serial — reset lifecycle

```
Step ID:          D.13
Phase/group:      serial
Depends on:       D.10
Backend/model:    Claude Code subagent (sonnet)
Objective:        Implement destroy-and-recreate state reset between scan phases (`docker compose down -v`
                   then re-provision), never snapshot/restore.
Scope and files:  WRITE: internal/dast/containment/reset.go, internal/dast/containment/reset_test.go.
                   READ: internal/dast/containment/provision.go (D.10, do not modify).
Forbidden actions: No snapshot/restore state-reset path in this file — research 19 reserves that for a
                   future Firecracker tier and flags it as insecure for anything holding a real credential
                   ("we consider resuming execution from the same state more than once insecure").
Inputs/artifact refs: research/19-target-environment-and-sandboxing.md line 163 (step 5), risk #6.
Expected output schema: `Reset(target *Target) (*Target, error)` that tears down and re-provisions via
                   D.10's `Provision`, returning a fresh `Target` with a new resolved image digest.
Validation/evidence required: Test asserting no state (files written to the target's writable layer,
                   database rows if the target has a DB) survives a `Reset` call.
Stop condition:    Reset produces a target indistinguishable from a first-provision, verified by the state-
                   survival test.
Why this model:    Small, bounded implementation directly following the research's concrete recommendation.
```

### Parallel group 4 — probe engine drivers

```
Step ID:          D.14
Phase/group:      parallel group 4
Depends on:       D.9, D.13
Backend/model:    Claude Code subagent (sonnet)
Objective:        Implement the Nuclei driver via the Go SDK, with PDCPUpload explicitly disabled,
                   interactsh/OAST disabled by default, `code:` protocol templates rejected at template-load
                   time, and all requests routed through the authorization kernel as request proposals only.
Scope and files:  WRITE: internal/dast/engines/nuclei.go, internal/dast/engines/nuclei_test.go.
                   READ: internal/dast/authz/kernel.go (D.2–D.9, do not modify — call it, never bypass it).
Forbidden actions: Never call `WithPDCPUpload(scanID, teamID)`. Never enable interactsh/OAST by default
                   (`-ni`/`-no-interactsh` equivalent must be the default). Any template using the `code:`
                   protocol must be rejected at load time, not merely skipped at match time — this is a
                   hard exclusion per spine S5, not a tunable. The driver must construct a request
                   *proposal* object and pass it to the kernel; it must not hold or construct a raw socket
                   itself (spine S7: "no model ever holds a network handle" extends to the engine driver
                   layer that sits behind the model — the driver is the thing the kernel actually gates).
Inputs/artifact refs: research/15-dast-tooling-landscape.md lines 139–146 (Nuclei primary pick); spine S5
                   (`code:` protocol Nuclei templates hard exclusion — 251 exist).
Expected output schema: `type Driver struct{...}` wrapping the Nuclei Go SDK's `ExecuteCallbackWithCtx`,
                   a `LoadTemplates(dir string) ([]Template, []RejectedTemplate, error)` that separates out
                   any `code:` protocol template into `RejectedTemplate` with reason, and a `Fire(proposal
                   RequestProposal) (Finding, error)` that routes every request through
                   `authz.Decision(...)` before it leaves the process.
Validation/evidence required: Test with a synthetic `code:` protocol template asserting it is rejected at
                   `LoadTemplates` time and never reaches `Fire`; test asserting `PDCPUpload` is never
                   invoked (mock SDK client, assert method not called); test asserting interactsh callback
                   URLs are absent from generated requests by default.
Stop condition:    Driver fires against a fixture target through the kernel, code: templates are
                   demonstrably rejected at load, and PDCPUpload/interactsh are demonstrably off.
Why this model:    Bounded SDK-integration work against an already-fixed kernel contract — default strong
                   worker; supply-chain and safety defaults here are concrete and testable, not open design.
```

```
Step ID:          D.15
Phase/group:      parallel group 4
Depends on:       D.9, D.13
Backend/model:    Claude Code subagent (sonnet)
Objective:        Implement the ZAP driver for scheduled full scans only, via the Automation Framework YAML
                   plan, with SARIF + Traditional JSON (request/response) report output and every ZAP
                   attack-strength/duration cap set explicitly (none left at ZAP's unlimited default).
Scope and files:  WRITE: internal/dast/engines/zap.go, internal/dast/engines/zap_test.go.
                   READ: internal/dast/authz/kernel.go (D.2–D.9, do not modify).
Forbidden actions: Do not run ZAP in the always-on/incremental path — it is gated to scheduled full scans
                   only, enforced by the caller's trigger-policy check, not by this driver refusing to run
                   (the driver itself should be trigger-agnostic; the gating is a config/scheduling
                   concern). Do not leave `delayInMs`, `maxScanDurationInMins`, `maxRuleDurationInMins`, or
                   `threadPerHost` at ZAP's defaults — every one of ZAP's four attack-strength caps defaults
                   to unlimited per research 19 and must be set explicitly.
Inputs/artifact refs: research/15-dast-tooling-landscape.md lines 147–152 (ZAP runner-up); research/19-
                   target-environment-and-sandboxing.md line 164 (step 6, "every one defaults to unlimited").
Expected output schema: `type ZapDriver struct{...}` running `./zap.sh -cmd -autorun zap.yaml`; a Go-
                   templated `zap.yaml` generator taking the four caps as required (non-optional) struct
                   fields with no zero-value default that means "unlimited"; report generation using the
                   SARIF JSON Report template plus the Traditional JSON Report with Requests and Responses
                   template.
Validation/evidence required: Test asserting the generated `zap.yaml` always contains explicit non-zero,
                   non-"unlimited" values for all four caps; test asserting `X-Anvil-Scan: <run-id>` and
                   `injectPluginIdInHeader: true` are present so operators can identify Anvil traffic.
Stop condition:    Driver produces both report formats against a fixture target with all four caps
                   demonstrably bounded.
Why this model:    Bounded implementation against an already-specified engine and report format — default
                   strong worker.
```

### Serial — critic on engine drivers

```
Step ID:          D.16
Phase/group:      serial
Depends on:       D.14, D.15
Backend/model:    OpenCode route (openai/gpt-5.5)
Objective:        Cross-family review of both engine drivers for supply-chain and safety-default violations:
                   confirm `code:` template rejection is unbypassable, PDCPUpload/interactsh are off by
                   default with no easy config flip, and ZAP's four caps cannot silently fall back to
                   unlimited.
Scope and files:  READ ONLY: internal/dast/engines/nuclei.go, internal/dast/engines/zap.go and their tests.
                   WRITE: none.
Forbidden actions: No sign-off without tracing the actual template-rejection code path for `code:`
                   templates, not just reading the test name.
Inputs/artifact refs: spine S5, S7; research/23-dast-signal-sources.md Risks item 3 (`code:` templates
                   "run arbitrary commands on the scanner").
Expected output schema: Pass/fail verdict with an explicit line-by-line trace of the `code:` rejection path.
Validation/evidence required: Verdict must name the exact function where rejection happens.
Stop condition:    Verdict delivered; FAIL reopens the offending driver (reroute once).
Why this model:    Mandatory cross-family critic for a supply-chain/RCE-adjacent control (`code:` templates
                   execute arbitrary commands on the Anvil host per spine S7) — squarely security-relevant.
```

### Serial — supply-chain pinning job

```
Step ID:          D.17
Phase/group:      serial
Depends on:       D.14, D.16
Backend/model:    Claude Code subagent (sonnet)
Objective:        Implement the nuclei-templates corpus pinning and diff-before-promotion job: fetch the
                   corpus at a specific commit SHA, diff against the currently-pinned SHA, and require an
                   explicit promotion step before the diffed templates become live.
Scope and files:  WRITE: cmd/anvil-dast/pin-templates.go, cmd/anvil-dast/pin-templates_test.go,
                   data/LICENSES/nuclei-templates/LICENSE (archived at pin time).
                   (Was cmd/anvil/ — moved by orchestrator ruling D7, IMPLEMENTATION-PLAN.md §2.9: a
                   package-main file under cmd/anvil that references internal/dast compiles the DAST tier
                   into the core binary, which S9-AMENDED forbids. O.16's import guard enforces this.)
                   READ: internal/dast/engines/nuclei.go (D.14, for the `LoadTemplates` interface it must
                   feed).
Forbidden actions: No automatic promotion on a clean diff — a human or an explicitly-configured policy
                   must approve promotion; this job produces a diff artifact, it does not apply it silently.
                   No tracking of a moving branch ref as the "pinned" source of truth — always a commit SHA.
Inputs/artifact refs: spine S7 ("Pin nuclei-templates by commit SHA and diff before promotion");
                   research/23-dast-signal-sources.md Recommendation item 1 (track `main` for the *fetch*,
                   but pin by SHA for what actually ships) and Risk #3 (supply-chain poisoning via the
                   corpus).
Expected output schema: A CLI subcommand invoked by a systemd timer (per spine S4 scheduling) that (1)
                   fetches `nuclei-templates` at `main`, (2) computes the diff against the last-pinned SHA,
                   (3) rejects any new `code:` protocol template in the diff outright (feeding D.14's
                   rejection list), (4) writes a diff report requiring explicit promotion, (5) on promotion,
                   updates the pinned SHA and archives the LICENSE file body (not API metadata) into
                   `data/LICENSES/nuclei-templates/`.
Validation/evidence required: Test with a synthetic upstream diff containing a new `code:` template
                   asserting it is flagged and blocked from auto-promotion.
Stop condition:    Pinning job runs end-to-end against a fixture repo, diff report is generated, and a
                   `code:`-template diff is demonstrably blocked.
Why this model:    Bounded CLI/CI tooling task against an already-specified policy (pin by SHA, diff before
                   promotion) — default strong worker.
```

### Parallel group 5 — attack-surface inventory, Tiers 0–2

```
Step ID:          D.18
Phase/group:      parallel group 5
Depends on:       D.9, D.13
Backend/model:    Claude Code subagent (sonnet)
Objective:        Implement Tier 0 of the inventory pipeline: probe a configurable list of well-known spec
                   endpoints on the running target (OpenAPI, springdoc, GraphQL introspection, gRPC
                   reflection) and parse the returned spec into the inventory format.
Scope and files:  WRITE: internal/dast/inventory/tier0_runtime.go, internal/dast/inventory/tier0_runtime_test.go.
                   READ: internal/dast/authz/kernel.go (route probes through it), internal/dast/containment/provision.go.
Forbidden actions: The spec-endpoint probe list must be config, never hard-coded (spine's "nothing about
                   trigger/policy may be hard-coded" constraint, applied here to the endpoint list itself).
Inputs/artifact refs: research/22-attack-surface-discovery.md lines 319–323 (Tier 0).
Expected output schema: `ProbeRuntimeSpecs(target *Target, endpoints []string) ([]Route, error)` where
                   every returned `Route` is tagged `inventory_provenance: runtime_spec, status: confirmed`
                   (a spec straight from the running service is definitionally confirmed, not a candidate).
Validation/evidence required: Test against a fixture target exposing `/openapi.json` asserting full
                   parameter-typed route extraction.
Stop condition:    Tier 0 probe returns a fully-typed route list from a fixture target.
Why this model:    Bounded, single-request-shape implementation — default strong worker.
```

```
Step ID:          D.19
Phase/group:      parallel group 5
Depends on:       none (cross-file dependency on the SAST tier's output shape, not on any step in this file)
Backend/model:    Claude Code subagent (sonnet)
Objective:        Implement Tier 1: consume checked-in spec files (`openapi.yaml`/`swagger.json`/`*.wsdl`/
                   `schema.graphql`/AsyncAPI/Postman) harvested by the SAST pass, converting Postman
                   collections to OpenAPI at ingest since Nuclei's `-im` import modes do not include Postman.
Scope and files:  WRITE: internal/dast/inventory/tier1_repospec.go, internal/dast/inventory/tier1_repospec_test.go.
                   READ: the unified audit record's spec-harvest field, once the SAST plan defines it —
                   until then, treat the input as an injected `[]SpecFile{Path, Format, Content}` slice and
                   flag the exact record field name as a TODO for reconciliation with the SAST plan.
Forbidden actions: Do not have this step or its dependents re-derive spec harvesting from the repo
                   directly — that is explicitly the SAST tier's job (spine: SAST model already reads the
                   repo); this step only consumes what SAST already harvested.
Inputs/artifact refs: research/22-attack-surface-discovery.md lines 325–328 (Tier 1).
Expected output schema: `IngestRepoSpecs(specs []SpecFile) ([]Route, error)` where every returned `Route`
                   is tagged `inventory_provenance: repo_spec, status: confirmed` (a spec checked into the
                   repo is authoritative for what the developer intended, though still worth Tier-0
                   cross-checking where both exist).
Validation/evidence required: Test with one fixture per format (OpenAPI YAML, Swagger JSON, WSDL,
                   GraphQL SDL, Postman-converted-to-OpenAPI) asserting correct route extraction.
Stop condition:    All five input formats parse to `Route` lists; Postman-to-OpenAPI conversion verified
                   against a fixture collection.
Why this model:    Bounded parser/adapter implementation across known formats — default strong worker.
```

```
Step ID:          D.20
Phase/group:      parallel group 5
Depends on:       none
Backend/model:    Claude Code subagent (sonnet)
Objective:        Vendor `antst/go-apispec` (Apache-2.0, NOTICE duty) and use its pipeline (package load +
                   type check → AST traversal → call graph from router registration to handler → OpenAPI
                   emission) for static route extraction on Go frameworks: chi, gin, net/http, echo, fiber,
                   gorilla/mux.
Scope and files:  WRITE: internal/dast/inventory/tier2_go_extract.go, internal/dast/inventory/tier2_go_extract_test.go,
                   third_party/go-apispec/ (vendored copy), NOTICE (append go-apispec's NOTICE content —
                   see Pinned Versions And Licences section below for the exact text to reproduce).
                   READ: none from this file's other steps.
Forbidden actions: Do not mark any Tier 2 output as `status: confirmed` at extraction time — every route
                   from this step is `status: candidate` until D.22 confirms it via live probe. Do not ship
                   without reproducing go-apispec's NOTICE file per Apache-2.0 §4(d) — this is a real,
                   already-verified obligation (`plan/spine-b-open-licences.md`), not a formality to skip.
Inputs/artifact refs: research/22-attack-surface-discovery.md lines 330–341 (Tier 2), specifically the
                   instruction "Do not use the SAST LLM to enumerate routes — use deterministic AST
                   tooling"; `plan/spine-b-open-licences.md` lines 42–66 (go-apispec licence confirmation
                   and NOTICE text).
Expected output schema: `ExtractGoRoutes(repoPath string) ([]Route, error)` wrapping go-apispec's
                   pipeline, every `Route` tagged `inventory_provenance: static_extraction, status:
                   candidate` and `framework: <chi|gin|net_http|echo|fiber|gorilla_mux>`.
Validation/evidence required: Test against a fixture repo per supported framework, asserting extracted
                   routes match a known-good route table; a NOTICE-file diff check confirming the vendored
                   copy's NOTICE content is byte-present in the aggregated Anvil NOTICE file.
Stop condition:    All six Go frameworks produce candidate route lists from fixtures; NOTICE aggregation
                   verified.
Why this model:    Vendoring + wiring an existing library against six known framework shapes is bounded,
                   well-specified implementation work — default strong worker.
```

```
Step ID:          D.21
Phase/group:      parallel group 5
Depends on:       none
Backend/model:    Claude Code subagent (sonnet)
Objective:        Build non-Go static route extractors — Express, Flask/FastAPI, Django, Spring, Rails —
                   modelled on go-apispec's pipeline shape (parse/type-check where possible → route-
                   registration traversal → candidate route emission).
Scope and files:  WRITE: internal/dast/inventory/tier2_other_extract.go, internal/dast/inventory/tier2_other_extract_test.go.
                   READ: internal/dast/inventory/tier2_go_extract.go (D.20, for the shared `Route` type and
                   pipeline shape only — do not modify).
Forbidden actions: Same as D.20 — every route here is `status: candidate`, never `confirmed`, at
                   extraction time. Do not silently drop a framework's reflection-based or computed-path
                   routes without recording that they are invisible to static extraction (research 22
                   explicitly notes go-apispec-style tooling cannot see these) — surface a `coverage_caveat`
                   field per framework instead of pretending completeness.
Inputs/artifact refs: research/22-attack-surface-discovery.md lines 330–341 (Tier 2), and Risk #2 (Alpha-
                   quality commercial equivalents for this exact problem — Flask/Micronaut/NodeJS/Play at
                   Alpha, ASP.NET Core unsupported, Django/FastAPI/Rails/Go absent even from the best-funded
                   attempt) — set expectations accordingly, this is inherently a best-effort candidate list.
Expected output schema: `ExtractRoutes(repoPath string, framework Framework) ([]Route, error)` per
                   framework, all tagged `inventory_provenance: static_extraction, status: candidate`.
Validation/evidence required: Test against one fixture repo per framework; each test must include at
                   least one intentionally-invisible route (reflection-based or computed path) and assert
                   the extractor reports a non-empty `coverage_caveat` rather than silently under-reporting.
Stop condition:    Five frameworks produce candidate route lists with honest coverage caveats on fixtures.
Why this model:    Bounded, repeated implementation pattern across five frameworks — default strong worker;
                   this is applying a known shape (D.20/go-apispec), not inventing one.
```

### Serial — Tier 2 confirmation, Tier 3 crawl, auth helper

```
Step ID:          D.22
Phase/group:      serial
Depends on:       D.18, D.20, D.21
Backend/model:    Claude Code subagent (sonnet)
Objective:        Merge Tier 0/1/2 candidate and confirmed routes, and promote Tier 2 `candidate` routes to
                   `confirmed` only on a non-404 response from the live target.
Scope and files:  WRITE: internal/dast/inventory/tier2_confirm.go, internal/dast/inventory/tier2_confirm_test.go.
                   READ: internal/dast/inventory/tier0_runtime.go, tier2_go_extract.go, tier2_other_extract.go
                   (do not modify any of them — call their exported types only).
Forbidden actions: A candidate route that never gets probed (e.g., budget-exhausted) must remain
                   `candidate`, never silently default to `confirmed`. Do not treat a non-404 as sufficient
                   on its own without recording the actual status code observed — a 500 is "route exists,
                   handler errors," not "route works," and both are still more informative than 404.
Inputs/artifact refs: research/22-attack-surface-discovery.md line 339 ("Confirm each candidate by probing
                   the running target; promote to confirmed only on a non-404 response"), Risk #4 ("more
                   endpoints can mean less coverage" — phpBB regression from timeout exhaustion) — this
                   informs the per-endpoint probe budget this step must enforce.
Expected output schema: `MergeAndConfirm(tiers ...[]Route) ([]Route, error)` producing a deduplicated,
                   provenance-preserving union with a bounded per-target probe budget (config, not
                   hard-coded) so a large candidate list cannot silently starve the confirmed-route count.
Validation/evidence required: Test reproducing the phpBB-style regression scenario (candidate list larger
                   than probe budget) and asserting the budget is respected rather than exceeded, with
                   unconfirmed candidates explicitly marked, not dropped.
Stop condition:    Merge+confirm produces a route list where every route carries provenance + status, and
                   the probe-budget test passes.
Why this model:    Bounded aggregation/confirmation logic against already-fixed types from D.18/D.20/D.21.
```

```
Step ID:          D.23
Phase/group:      serial
Depends on:       D.15, D.22
Backend/model:    Claude Code subagent (sonnet)
Objective:        Implement Tier 3: ZAP Client Spider (never the AJAX Spider) as the browser-driven crawl,
                   gated to scheduled full scans only, always excluding Swagger UI and GraphQL playground
                   routes.
Scope and files:  WRITE: internal/dast/inventory/tier3_crawl.go, internal/dast/inventory/tier3_crawl_test.go.
                   READ: internal/dast/engines/zap.go (D.15, call it, do not modify); internal/dast/inventory/tier2_confirm.go
                   (D.22, for the exclusion seed list).
Forbidden actions: Do not run this tier on incremental/tag-triggered scans — it fires on scheduled full
                   scans only, per the same trigger-policy gate that controls D.15. Do not crawl Swagger
                   UI or GraphQL playground routes even if discovered by the crawl itself (they are
                   meta-surface, not application surface, and crawling them wastes the tightest budget in
                   the pipeline).
Inputs/artifact refs: research/22-attack-surface-discovery.md lines 342–347 (Tier 3), citing ZAP's own 2026
                   recommendation of Client Spider over AJAX Spider on scaling grounds (linear vs rapidly
                   degrading).
Expected output schema: `CrawlWithClientSpider(target *Target, exclude []string) ([]Route, error)`
                   producing `inventory_provenance: crawl, status: candidate` routes (crawl-discovered
                   routes still get the same non-404 confirmation treatment as Tier 2, via D.22's merge
                   logic re-invoked).
Validation/evidence required: Test asserting Swagger UI / GraphQL playground paths are excluded even when
                   present in the fixture target's link graph; test asserting this tier does not execute
                   when the run's trigger type is "incremental."
Stop condition:    Client Spider crawl runs against a fixture target, respects exclusions, and is
                   demonstrably skipped on an incremental-trigger fixture.
Why this model:    Bounded driver-integration work against an already-built ZAP driver (D.15) and an
                   already-specified gating rule.
```

```
Step ID:          D.24
Phase/group:      serial
Depends on:       D.15, D.23
Backend/model:    Claude Code subagent (sonnet)
Objective:        Integrate ZAP's Authentication Helper (Browser Based Authentication, explicit
                   AUTO_STEPS/CLICK/CUSTOM_FIELD/TOTP_FIELD/WAIT step list — never autodetection), enable
                   the authentication report on every run, and implement a session-liveness check between
                   scan phases with forced re-login on failure.
Scope and files:  WRITE: internal/dast/inventory/auth_helper.go, internal/dast/inventory/auth_helper_test.go.
                   READ: internal/dast/engines/zap.go (D.15, call it, do not modify); internal/dast/target/manifest.go
                   (D.1, for the optional `auth` block).
Forbidden actions: Do not rely on ZAP's autodetection for login flows — an explicit step list is required.
                   Do not rely on ZAP's logout-avoidance option as a substitute for a real liveness check —
                   research 22 states it does not cover the Client Spider. Credentials referenced by the
                   manifest's `auth` block must never be logged in plaintext, including in the
                   authentication report's stored artifacts.
Inputs/artifact refs: research/22-attack-surface-discovery.md lines 355–362 (Authentication section) and
                   Risk #7 ("Auth remains the failure mode most likely to silently zero out a scan" — ZAP's
                   own characterization is "hard. Really hard.").
Expected output schema: `AuthenticateAndMonitor(target *Target, steps AuthSteps) (*Session, error)` plus
                   a `CheckLiveness(session *Session) (bool, error)` called between scan phases, forcing
                   `AuthenticateAndMonitor` again on failure; every run stores the authentication report
                   (screenshots + HTTP + storage) for diagnosability.
Validation/evidence required: Test reproducing a mid-scan logout (session fixture invalidated between
                   phases) and asserting `CheckLiveness` detects it and forced re-login succeeds before the
                   next probe phase runs; test asserting no credential value appears in any stored log or
                   report artifact in plaintext.
Stop condition:    Fixture login + mid-scan logout + forced re-login all pass; credential-leak test passes.
Why this model:    Bounded driver-integration work, but credential handling and session state make this
                   security-adjacent enough to route a critic (D.25) before it ships.
```

### Serial — critic on crawl + auth

```
Step ID:          D.25
Phase/group:      serial
Depends on:       D.23, D.24
Backend/model:    OpenCode route (openai/gpt-5.5)
Objective:        Cross-family review of the browser-crawl and authentication-helper integration for two
                   specific failure modes: does the Client Spider's request traffic route through the same
                   authorization kernel as every other engine (redirect re-validation, cap enforcement), and
                   is there any path by which a credential from the manifest's `auth` block reaches a log,
                   report artifact, or (later) a model prompt in plaintext.
Scope and files:  READ ONLY: internal/dast/inventory/tier3_crawl.go, internal/dast/inventory/auth_helper.go
                   and their tests. WRITE: none.
Forbidden actions: No sign-off without confirming, by reading the code, that ZAP's Client Spider requests
                   are subject to the same per-request kernel gates (D.6) as Nuclei's — a headless-browser-
                   issued fetch/XHR was explicitly named in gate 13's scope.
Inputs/artifact refs: research/20-authorization-legality-and-safety.md gate 13 text ("each fetch/XHR issued
                   by a headless browser component"); research/22-attack-surface-discovery.md Risk #7.
Expected output schema: Pass/fail verdict addressing both failure modes explicitly, with citations to the
                   specific code paths checked.
Validation/evidence required: Verdict must state whether it traced an actual ZAP-Client-Spider-issued
                   request through to a kernel gate call, or is inferring from driver structure alone.
Stop condition:    Verdict delivered; FAIL reopens D.23 or D.24 as applicable (reroute once).
Why this model:    Mandatory cross-family critic — credential handling and kernel-bypass risk both meet
                   00-ROUTING.md's security-relevant bar.
```

### Serial — coverage, confirmation gate, model role

```
Step ID:          D.26
Phase/group:      serial
Depends on:       D.13, D.18, D.19, D.20, D.21, D.22
Backend/model:    Claude Code subagent (sonnet)
Objective:        Implement the coverage/record schema fields — `dast_status`, `dast_coverage`,
                   `target_provenance`, `endpoint_coverage`, `server_line_coverage`, `inventory_provenance`
                   — as defined in this file's Coverage Reporting Contract section below, and wire the
                   provisioning-skip and failed-boot paths (D.1, D.10) into `dast_status`.
Scope and files:  WRITE: internal/dast/record/coverage.go, internal/dast/record/coverage_test.go.
                   READ: internal/dast/target/manifest.go (SkipReason), internal/dast/containment/provision.go
                   (health-timeout error), internal/dast/inventory/tier2_confirm.go (route provenance/status).
Forbidden actions: Never compute `endpoint_coverage` from a request count — it is confirmed-probed
                   endpoints ÷ union of the Tier 0–2 inventory, per research 22's explicit correction of the
                   weaker "source-lines denominator" pattern. Never let a `no_target_manifest` skip and a
                   `tested_and_clean` result be representable by the same enum value or the same absence of
                   a field — they must be distinguishable by construction, not by convention.
Inputs/artifact refs: spine S6 (required record fields); research/22-attack-surface-discovery.md lines
                   364–374 (the three coverage fields); research/23-dast-signal-sources.md Risk #1
                   ("Anvil must never report '0 DAST findings' as 'no dynamic vulnerabilities'").
Expected output schema: A `dast_status` enum {`skipped_no_manifest`, `failed_to_boot`, `partial`, `clean`,
                   `findings`} — five distinct values, no overloading; `target_provenance` enum
                   {`ephemeral_manifest`, `live_url_authorized`}; `endpoint_coverage float64` computed as
                   specified; `server_line_coverage *float64` (nullable — only populated on scheduled full
                   scans per research 22); `inventory_provenance` as a per-route field already produced by
                   D.18–D.22, aggregated here into the record-level summary.
Validation/evidence required: Test asserting a manifest-absent run produces `dast_status:
                   skipped_no_manifest` and is never equal-comparable to a `clean` run in any downstream
                   consumer's naive equality check; test computing `endpoint_coverage` against a known
                   fixture inventory and confirming it is not a request count.
Stop condition:    All six fields populate correctly across skip/failed-boot/partial/clean/findings
                   fixtures.
Why this model:    Bounded schema-and-wiring implementation against fields this file's Coverage Reporting
                   Contract section (below) already fully specifies.
```

```
Step ID:          D.27
Phase/group:      serial
Depends on:       D.14, D.15, D.26
Backend/model:    Claude Code subagent (sonnet)
Objective:        Implement the DAST confirmation gate: re-probe every candidate finding to confirm before
                   it reaches the record, hash-and-reference the response body by default, and inline only
                   a regex-extracted evidence span — never the raw body.
Scope and files:  WRITE: internal/dast/record/confirm_gate.go, internal/dast/record/confirm_gate_test.go.
                   READ: internal/dast/engines/nuclei.go, internal/dast/engines/zap.go (finding shapes, do
                   not modify), internal/dast/record/coverage.go (D.26, for the record fields it writes into).
Forbidden actions: The raw HTTP response body must never be assigned to any field that is documented (in
                   the coding-agent-consumption research, branch 24, or the eventual record schema) as
                   prompt-bound. This gate's output type must make "the model reads the raw body" a type
                   error, not a discipline problem. No finding reaches `dast_status: findings` without
                   having passed a re-probe confirmation step — a first-seen finding from an engine is
                   provisional until confirmed.
Inputs/artifact refs: spine S7 ("The DAST response body is the highest-risk injection channel... Hash-and-
                   reference by default; inline only a regex-extracted evidence span"); research/15-dast-
                   tooling-landscape.md Risks item on ZAP's 88 phantom SQL-injection findings (the concrete
                   scenario this gate exists to catch); research/23-dast-signal-sources.md Risk #2
                   (`detection_method`, `confidence` fields required).
Expected output schema: `type Finding struct { Evidence EvidenceRef; DetectionMethod string; Confidence
                   float64; ... }` where `EvidenceRef` is `{BodyHash string; ExtractedSpan string}` and
                   there is no field carrying the full body; `ConfirmFinding(candidate RawFinding) (*Finding,
                   error)` that re-fires the probe and only promotes to a `Finding` on reproduction, else
                   demotes/drops with a logged reason.
Validation/evidence required: A fixture reproducing something shaped like the 88-phantom-SQLi ZAP scenario
                   (an engine emits N candidate SQLi findings against a target known not to have them) and
                   asserting the confirmation gate demotes/drops the false positives rather than passing
                   them through; a reflection-based test confirming no `Finding`-reachable field can hold a
                   value longer than the regex-extracted-span length limit (proving raw-body inlining is
                   structurally impossible, not just avoided by convention).
Stop condition:    Phantom-finding fixture is demoted/dropped; reflection test confirms no raw-body path
                   exists in the `Finding` type.
Why this model:    Bounded implementation against an already-specified contract, but this is the
                   highest-risk injection channel in the system per spine S7 — it gets a critic (D.28)
                   before shipping regardless of how bounded the implementation looks.
```

### Serial — critic on confirmation gate

```
Step ID:          D.28
Phase/group:      serial
Depends on:       D.27
Backend/model:    OpenCode route (openai/gpt-5.5)
Objective:        Independently verify that no code path — including future ones a naive extension might
                   add — can route a raw DAST response body into a model-prompt-bound field, and that the
                   confirmation gate's re-probe logic cannot itself be gamed by a target that behaves
                   differently under re-probe (e.g., rate-limits the second request and gets misread as "not
                   reproduced" when it actually is vulnerable).
Scope and files:  READ ONLY: internal/dast/record/confirm_gate.go and its test. WRITE: none.
Forbidden actions: No sign-off that treats "the test suite passes" as sufficient without also reasoning
                   about the type-level guarantee (or its absence) against a hypothetical future caller.
Inputs/artifact refs: spine S7 (DAST response body as highest-risk injection channel); research/15-dast-
                   tooling-landscape.md's 88-phantom-SQLi citation.
Expected output schema: Pass/fail verdict, explicitly addressing (a) the type-level raw-body guarantee and
                   (b) the re-probe-false-negative risk (rate-limited second probe read as "not confirmed").
Validation/evidence required: Verdict must state whether (b) is mitigated (e.g., a re-probe that gets a
                   429 should be retried or marked `unconfirmed_inconclusive`, not silently dropped as
                   disproven) and cite the relevant code.
Stop condition:    Verdict delivered; FAIL reopens D.27 (reroute once).
Why this model:    Mandatory cross-family critic on the system's highest-risk injection channel per spine
                   S7 — this is the clearest possible case for the cross-family critique rule.
```

```
Step ID:          D.29
Phase/group:      serial
Depends on:       D.9, D.27
Backend/model:    Claude Code subagent (sonnet)
Objective:        Configure the DAST model's runtime role: same base model as the SAST adjudicator, with a
                   larger context window and larger turn budget plus a hard turn cap, constrained to nuclei
                   template selection and parameter mutation only (no free-form payloads), producing request
                   proposals the kernel independently validates — never a network handle.
Scope and files:  WRITE: internal/dast/model/dast_model.go, internal/dast/model/dast_model_test.go.
                   READ: internal/dast/authz/kernel.go (RequestProposal type, D.2), internal/dast/record/confirm_gate.go
                   (D.27, EvidenceRef type — this is the only DAST-body-derived data the model may ever see).
Forbidden actions: No free-form payload generation — constrained to the pinned nuclei template set (D.17)
                   plus parameter mutation, per research 17's own recommendation ("that is the 0% regime").
                   No path by which the model's output type can hold or invoke a network primitive — the
                   model may only construct a `RequestProposal` value, which is inert data until the kernel
                   accepts it. No path by which a raw DAST response body reaches the model's prompt context
                   — only `EvidenceRef` (hash + extracted span) from D.27 may be included. Turn budget is
                   per-finding, not per-scan (research 17: TrustedSec's failures were almost entirely
                   `exhausted_turns`), and the cap is hard — no config path raises it mid-run.
Inputs/artifact refs: spine S4 ("DAST model: same base as SAST, larger context + turn budget, hard turn
                   cap"); research/17-dast-model-selection.md Recommendation section's *configuration*
                   guidance (turn caps, template-only constraint, `unconfirmed` for oracle-less classes) —
                   note: this file inherits the *model-sizing* correction from spine S4, not research 17's
                   9B pick; only the operational configuration advice (turn caps, template constraint,
                   unconfirmed-class handling) is adopted from research 17.
Expected output schema: A `RequestProposal` type with no method that performs I/O (verifiable by
                   reflection: no method returns an error from an actual dial, no embedded `net.Conn`/
                   `http.Client`); a `TurnBudget` type scoped per-finding with a hard ceiling; a
                   `ClassifyFinding` path that marks findings in oracle-less classes (authorization, IDOR
                   chains, business logic) as `unconfirmed` rather than asserting or dropping them.
Validation/evidence required: Reflection/static-analysis test proving `RequestProposal` has zero I/O-
                   capable methods or fields; test asserting a turn-budget-exhausted run stops cleanly and
                   records the exhaustion rather than silently truncating; test asserting an oracle-less
                   finding class is tagged `unconfirmed`, never silently dropped or silently asserted.
Stop condition:    All three tests pass; the model's context/turn-budget deltas over the SAST adjudicator's
                   configuration are documented as config, not hard-coded.
Why this model:    Bounded configuration/wiring work against an already-fixed kernel contract (D.2) and an
                   already-fixed evidence contract (D.27) — default strong worker; the hard sizing/safety
                   decision was already made at the spine level, this step implements it.
```

### Serial — critic on model boundary

```
Step ID:          D.30
Phase/group:      serial
Depends on:       D.29
Backend/model:    OpenCode route (openai/gpt-5.5)
Objective:        Independently verify the DAST model genuinely cannot perform I/O and genuinely never
                   receives a raw response body — the two guarantees spine S7 treats as load-bearing for the
                   whole safety design ("the size of the DAST model is irrelevant to safety, because the
                   model is never the enforcement point").
Scope and files:  READ ONLY: internal/dast/model/dast_model.go and its test. WRITE: none.
Forbidden actions: No sign-off that accepts "the model is instructed not to" as a substitute for a
                   structural guarantee — the whole point of this design is that instructions are not the
                   control.
Inputs/artifact refs: spine S7.
Expected output schema: Pass/fail verdict stating explicitly whether the I/O-incapability guarantee is
                   structural (type system / reflection-provable) or merely conventional (a comment saying
                   "don't do this").
Validation/evidence required: Verdict must name the specific mechanism (or its absence) that makes the
                   guarantee structural.
Stop condition:    Verdict delivered; FAIL reopens D.29 (reroute once).
Why this model:    Mandatory cross-family critic — this is the single most safety-load-bearing claim in the
                   entire DAST tier per spine S7, and it gets independent verification, not a second
                   Anthropic pass.
```

### Serial — integration

```
Step ID:          D.31
Phase/group:      serial
Depends on:       D.9, D.13, D.17, D.22, D.24, D.26, D.27, D.29 (transitively, all prior steps)
Backend/model:    Claude Code subagent (sonnet)
Objective:        Build the end-to-end fixture-test harness proving the whole tier's exit criteria (below)
                   objectively, in one place, rather than trusting each step's isolated tests to compose
                   correctly.
Scope and files:  WRITE: test/integration/dast_e2e_test.go. READ: all packages under internal/dast/ (no
                   modifications to any of them — this step is test-only).
Forbidden actions: Do not modify any production code to make a test pass — a failing integration test at
                   this stage means reopening the specific upstream step, not patching around it here.
Inputs/artifact refs: This file's Exit Criteria section (below) — every bullet there must have a
                   corresponding assertion in this harness.
Expected output schema: One Go test file with one subtest per Exit Criteria bullet, each independently
                   runnable and independently attributable to a failing upstream step.
Validation/evidence required: `go test ./test/integration/... -run DAST` green, with every Exit Criteria
                   bullet mapped to a named subtest in the PR description.
Stop condition:    All Exit Criteria bullets have a passing, named subtest.
Why this model:    Integration/verification work spanning many packages but no new architectural decisions
                   — default strong worker; this is proving what was already built, not designing anything.
```

---

## Authorization Gate Sequence

Every gate is fail-closed: failure aborts the run and writes a refusal record (gate 21 makes this durable).
No gate marked "no" in the Configurable column may be disabled by an environment variable, CLI flag, config
key, or model-authored value — per spine S7 and the task's floor requirement.

**Phase 0 — build and packaging**

| # | Gate checks | Fail-closed behaviour | Configurable? |
|---|---|---|---|
| 1 | DAST ships disabled (`dast.enabled=false`, no default target/scope) | No target, no scope, no example resolves to a real host | Enabling requires an explicit non-defaulted write; the disabled default itself is **not** configurable |
| 2 | Kernel compiled separately, zero imports from inference layer | Build fails on dependency-graph inversion (D.9) | No |
| 3 | Egress choke point proven by test | CI fails on a direct `net.Dial`/`http.Client` outside the kernel; runtime dial attempt from outside panics | No |

**Phase 1 — run initiation**

| # | Gate checks | Fail-closed behaviour | Configurable? |
|---|---|---|---|
| 4 | Scope file exists, parses strictly, schema-valid | Missing/malformed/unknown-field → zero permitted targets, never allow-all | Scope *content* is configurable (that's its purpose); the deny-by-default schema behaviour is not |
| 5 | Affirmative attestation present, valid, unexpired, scope-hash-bound | Refuse to probe without a live attestation; scope edit invalidates it | Expiry ceiling may be lowered from the 30-day recommended default; presence/validity checking is not optional |
| 6 | Mode declaration explicit and irreversible for the run (`lab` \| `external`) | Refuse if absent; no `auto` value exists | No — there is no configurable "auto" path, ever |
| 7 | Trigger provenance check (CI-initiated runs verify write-authority principal) | Refuse fork PRs / untrusted `pull_request_target` contexts | Which trigger sources are *permitted* is configurable; *whether* provenance is checked is not |

**Phase 2 — per-target admission**

| # | Gate checks | Fail-closed behaviour | Configurable? |
|---|---|---|---|
| 8 | Canonicalize before matching (IDNA, case fold, trailing dot, percent-decode, port norm, IPv4-mapped-IPv6 unwrap) | Reject if canonical form diverges from literal form unexpectedly; log both | No |
| 9 | Resolve DNS in kernel, match resolved IP against scope, pin and connect to pinned address | Reject if resolved IP outside scope; never re-resolve between check and connect (closes DNS rebinding/TOCTOU) | No |
| 10 | Non-configurable reserved-range denylist in `external` mode | Hard-refuse loopback/RFC1918/link-local/metadata/multicast ranges | **No — a compiled constant, not a config key.** Only `lab` mode may reach these, only for addresses explicitly enumerated in scope |
| 11 | Robots/ToS deny signals as additional denies only | Restrictive `robots.txt`/no-scan statement removes paths from scope; permissive adds nothing | No — asymmetric by design |
| 12 | `security.txt` fetched for reporting-channel resolution only | Result recorded in the audit log; **structurally excluded from the admission decision's input type** | No — enforced at the type level, not by convention |

**Phase 3 — per-request enforcement**

| # | Gate checks | Fail-closed behaviour | Configurable? |
|---|---|---|---|
| 13 | Re-validate scope on every request including every redirect hop | Cross-host redirects never followed; run records the redirect and stops that branch | No |
| 14 | Hard token-bucket caps: ≤10 rps/host, ≤4 concurrent/host, ≤20,000 req/target/run, ≤30 min/target, ≤1 MiB body, ≤3 retries | Requests over any cap are blocked | Caps may only be **lowered**; no combination of settings raises any cap above its coded floor |
| 15 | Destructive-technique denylist (compiled-in, static) | No DoS/brute-force/lockout/state-changing-without-allow/exploitation-past-proof-of-existence | No — a static list, never a model judgement |
| 16 | Target-health circuit breaker (5xx rate, connection-error rate, p95 latency vs. 60s baseline) | Trip at 5xx>10% or p95>3× baseline sustained 30s; quarantine target for rest of run; write incident | Thresholds may be tightened; the floor is not configurable upward |
| 17 | `429`/`Retry-After` honoured as absolute | Full backoff for the duration; three `429`s abort the target | No |

**Phase 4 — output and disclosure**

| # | Gate checks | Fail-closed behaviour | Configurable? |
|---|---|---|---|
| 18 | No auto-publication of third-party findings | Default 45-day embargo from first vendor contact | Acceleration (active exploitation) / extension (core-OS changes) are documented, config-driven exceptions; disabling the embargo outright is not configurable |
| 19 | Disclosure state lives in the DB, not the tmpfs handoff buffer | `disclosure_state` persisted in the SQLite record store | No |
| 20 | No unsolicited fixes pushed to third parties | Patch delivery to a non-operator-owned repo requires the same attestation as probing, plus the gate-12 reporting channel | No |
| 21 | Immutable audit of every gate decision | Every allow/deny/redirect-refusal/circuit-breaker-trip logged, keyed to attestation ID + scope hash; **a gate decision is not "allowed" if its paired audit write fails** | No |

---

## Target Manifest Schema (`.anvil/target.yaml`)

Declared only — Anvil never infers how to run a repo. Absence of this file is not an error: the scan
proceeds SAST-only and `dast_status` is set to `skipped_no_manifest`.

```yaml
schema_version: 1

# Path to the Compose file that defines the target stack, relative to repo root. Required.
compose_file: ./docker-compose.anvil.yaml

# Name of the Compose service Anvil is authorized to attack. Required. Every other service in the
# Compose file is provisioned (for realistic dependencies) but is not itself a probe target.
service: web

health:
  url: http://web:8080/healthz     # Required. No health definition means no DAST — provisioning aborts.
  timeout_seconds: 120              # Hard timeout on Compose `service_healthy` wait.
  interval_seconds: 5

seed:                               # Optional. Run once after health passes, before any probe fires.
  command: ["make", "seed"]
  timeout_seconds: 60

reset:
  strategy: destroy_recreate        # The only supported value in v1 (research 19: snapshot/restore is
                                     # reserved for a future Firecracker tier and is unsafe for anything
                                     # holding a real credential). Explicit so a future value never
                                     # silently changes behaviour by omission.

auth:                               # Optional. Consumed by the ZAP Authentication Helper (Tier 3 only).
  method: browser
  steps_ref: ./.anvil/auth-steps.yaml   # AUTO_STEPS/CLICK/CUSTOM_FIELD/TOTP_FIELD/WAIT list — never
                                         # autodetection.

inventory:
  runtime_spec_endpoints:           # Optional override of the Tier 0 probe list; config, never hard-coded.
    - /openapi.json
    - /v3/api-docs
    - /graphql

scope:
  additional_egress_allow: []       # Optional, empty by default. Anything listed here still passes
                                     # through the kernel's non-configurable reserved-range denylist
                                     # (gate 10) — this field cannot punch a hole in that floor; it only
                                     # narrows what the *scope layer* permits within what the kernel
                                     # already allows.
```

If `compose_file` is present but does not exist, or `health.url` is missing, the manifest is
schema-invalid and the loader (D.1) returns `SkipReasonInvalidManifest` — same downstream effect as a
missing file (`dast: skipped`), but recorded with a distinct reason string so operators can tell "we
forgot to write one" from "we wrote a broken one."

---

## Coverage Reporting Contract

Per spine S6/S9: a target that failed to boot must be distinguishable from "scanned clean," and none of
these fields may be a request count.

| Field | Type | Source step | Semantics |
|---|---|---|---|
| `dast_status` | enum {`skipped_no_manifest`, `failed_to_boot`, `partial`, `clean`, `findings`} | D.1 (skip), D.10 (boot), D.31 (aggregate) | Five mutually exclusive, distinctly-named states. `skipped_no_manifest` ≠ `clean` — the coding agent must never read absence of DAST activity as absence of vulnerabilities. |
| `target_provenance` | enum {`ephemeral_manifest`, `live_url_authorized`} | D.10 / external-mode gate 6 | Which of the two provisioning paths produced this scan. |
| `dast_coverage` | struct | D.26 | Wraps `endpoint_coverage`, `server_line_coverage`, `inventory_provenance` below. |
| `endpoint_coverage` | float64, [0,1] | D.26 | confirmed-probed endpoints ÷ union of the Tier 0–2 inventory. **Never a raw request count.** |
| `server_line_coverage` | *float64 (nullable), [0,1] | D.26 | Populated on scheduled full scans only, via a language coverage agent inside the sandbox (Xdebug/pcov, JaCoCo, coverage.py, Go cover, Istanbul/nyc as applicable). `null` on incremental scans — not `0`. |
| `inventory_provenance` | per-route enum {`runtime_spec`, `repo_spec`, `static_extraction`, `crawl`} + `confirmed`/`candidate` | D.18–D.25 | Per-endpoint, aggregated to a record-level summary in D.26. This is what makes the SAST→DAST handoff auditable. |
| `detection_method` | enum {`template`, `differential`, `model_inference`} | D.27 | Per-finding; required by research 23's mitigation for the 18–45% invalid-finding risk. |
| `confidence` | float64, [0,1] | D.27, D.29 | Per-finding; oracle-less classes (authorization, IDOR, business logic) are tagged `unconfirmed` rather than asserted or dropped. |
| `evidence` | struct `{body_hash string, extracted_span string}` | D.27 | **Never the raw response body.** The extracted span comes from a regex over the body, applied before anything is prompt-bound. |

---

## Exit Criteria

All objectively checkable via the D.31 integration harness:

1. A repo with no `.anvil/target.yaml` produces `dast_status: skipped_no_manifest` and the SAST half of
   the record is unaffected (D.1, D.31).
2. A repo with a `.anvil/target.yaml` whose Compose service never passes its healthcheck produces
   `dast_status: failed_to_boot`, distinct from both `skipped_no_manifest` and `clean` (D.10, D.26).
3. `go build ./...` fails if any package outside `internal/dast/authz` is edited to import the kernel
   internals in a way that would let it construct a raw socket, and fails if `internal/dast/authz` is
   edited to import anything under `*/inference/*`, `*/model/*`, `*/llm/*` (D.9).
4. A fixture reproducing ZAP issue #2546 (mid-scan redirect to a host outside scope) is refused and
   logged, never followed (D.6, D.31).
5. No combination of config values raises any of the five Phase-3 hard caps above its coded floor (D.6).
6. The reserved-range denylist (loopback, RFC1918, link-local, `169.254.169.254`, `fd00:ec2::254`, etc.)
   is unreachable in `external` mode regardless of scope-file content (D.5).
7. `security.txt`'s parsed result is unreachable from the admission `Decision(...)` function's argument
   types by static/reflection analysis, not merely by convention (D.5, D.8).
8. A deliberately-broken nftables ruleset fixture is caught by the containment assertion probe and aborts
   the run in 20/20 flake-check runs — proving the probe is not a silent no-op (D.11, D.12).
9. Cloud metadata (`169.254.169.254` and `fd00:ec2::254`) is unreachable from inside the sandbox on every
   run, verified by the assertion probe, not assumed from ruleset intent (D.11).
10. A synthetic `code:` protocol Nuclei template is rejected at template-load time, before it ever reaches
    `Fire` (D.14, D.16).
11. `WithPDCPUpload` is never invoked and no interactsh callback URL appears in a default-configuration
    request (D.14).
12. `nuclei-templates` corpus promotion is blocked when the diff contains a new `code:` template (D.17).
13. Every Tier 2/3-discovered route is `status: candidate` at extraction time and only becomes `confirmed`
    after a live non-404 probe recorded by D.22 (D.20, D.21, D.22).
14. The Tier 3 browser crawl does not execute on an incremental-trigger fixture and does execute on a
    scheduled-full-scan fixture (D.23).
15. A mid-scan session logout is detected by the liveness check and triggers forced re-login before the
    next probe phase (D.24).
16. `endpoint_coverage` computed against a fixture inventory is not equal to a raw request count in any
    test case where the two would otherwise coincide by accident (D.26).
17. A fixture reproducing the ZAP 88-phantom-SQLi shape (candidate findings against a target known not to
    have them) results in those findings being demoted or dropped by the confirmation gate before
    `dast_status: findings` is set (D.27, D.28).
18. No field reachable from a `Finding` value can hold more than the regex-extracted-span length limit —
    proven by reflection, not by test coverage alone (D.27).
19. The `RequestProposal` type has zero methods or fields capable of performing network I/O, proven by
    reflection/static analysis (D.29, D.30).
20. A turn-budget-exhausted DAST model run stops cleanly, records the exhaustion, and does not silently
    truncate or fabricate a result (D.29).

---

## Pinned Versions And Licences

| Component | Version / pin strategy | Licence | Notes |
|---|---|---|---|
| gVisor (`runsc`) | latest stable at build time, `systrap` platform | Apache-2.0 (some files MIT/BSD — audit if vendoring) | No `/dev/kvm` required; works in nested VMs/CI runners |
| Nuclei engine | Go SDK, pin at build time | MIT | `WithPDCPUpload` must never be enabled |
| `nuclei-templates` | pinned by commit SHA, diffed before promotion (D.17) | MIT | Vendor a dated snapshot; MIT is irrevocable for code already released even if upstream relicenses |
| OWASP ZAP | Automation Framework + Authentication Helper v0.40.0; OpenAPI add-on v57, GraphQL add-on v0.33.0 (alpha), SOAP add-on v31, gRPC add-on v0.2.0 (alpha) | Apache-2.0 | Alpha add-ons (GraphQL, gRPC) must degrade to "surface known but not exercised," never a silent clean report |
| `antst/go-apispec` | vendor at a pinned commit | Apache-2.0, **NOTICE duty** | NOTICE must be reproduced verbatim (confirmed `plan/spine-b-open-licences.md` lines 42–66: "Copyright 2025 Ehab Terra / Copyright 2025-2026 Anton Starikov") |
| Docker Compose (`docker/compose`) | pinned CLI version | Apache-2.0 | NOTICE duty if redistributed as a binary |
| CISA KEV | daily pull, `known_exploited_vulnerabilities.json` | CC0-1.0 | Public domain; irrevocable — the safe floor if EPSS terms ever tighten |
| EPSS | daily CSV pull (never the live API) | Free, terms-of-use page, **not** a LICENSE file | Weaker guarantee than KEV's CC0 — do not depend on it alone for gating |
| SecLists | pinned snapshot | MIT | Payload/dictionary layer |
| CWE | CWE 4.20 per spine S1 | Custom ToU, free | Classification key, not redistributed as prose |
| disclose.io `dioterms` | current | CC0-1.0 | Source of Anvil's own VDP text / safe-harbour clause / report template (gate 12/18 support) |
| `nftables` (`nft` CLI) | distro-provided, subprocess only | GPL-2.0 | **Invoked as a subprocess, never linked** — same boundary discipline as the sqlmap/nmap subprocess rule (spine S8), though nftables carries no derivative-work-via-subprocess clause the way NPSL/sqlmap do |

**Explicitly not pinned or adopted in this file:** nmap (spine S8 — open decision, not an approved
dependency; not designed in here), sqlmap (spine S8 — GPL-3.0 separately-distributed plugin, core-in-scope
work stops at "the interface is a documented tool-agnostic data contract," building the plugin itself is
out of this file's scope), AFL++/honggfuzz or any fuzzing harness (out of the scan loop by directive —
belongs to a future opt-in decoupled campaign, not designed here).

**DAST model licence:** inherited from the SAST adjudicator's Milestone-0 pick (spine S3/S4) — either
`Qwen3.5-2B` (Apache-2.0, pending confirmation a text-only variant exists) or `Gemma 4` (Apache-2.0,
confirmed 2026-08-06 per spine S4 and `plan/spine-b-open-licences.md` lines 13, 33–38). This file adds
context-window, turn-budget, and turn-cap configuration on top of that pick; it does not select the model.

---

## Open Questions

- **DAST-as-separate-package vs. config flag.** See Conflicts With Spine below — unresolved at the plan
  level, needs an orchestrator decision before D.14/D.15 ship a build target.
- **Which base model the DAST tier actually inherits** (`Qwen3.5-2B` text-only variant existence
  unverified, vs. `Gemma 4`) is gated on the SAST plan's Milestone-0 evaluation (spine S3), not on
  anything in this file. D.29 is written to be agnostic to the answer, but cannot be finished until the
  SAST plan resolves it.
- **D.19's exact input shape** (the unified audit record's field carrying SAST-harvested spec files) is
  a placeholder pending the SAST/record-schema plan. Reconcile before D.19 is executed, not after.
- **No current measurement of how many repos in Anvil's actual prospective user base ship a
  `docker-compose.yml` with a healthcheck.** Research 19 flags this as the single most useful missing
  number for sizing the DAST tier's real-world coverage and notes it is directly measurable against
  Anvil's own candidate repos before the tier is built. Recommend doing that measurement alongside
  Milestone 0, not as part of this implementation file.
- **ZAP's JVM memory footprint is unquantified** (research 15's own gap) — affects whether tier M
  hardware (spine S9, 32 GB/8 core) genuinely accommodates a scheduled full scan alongside SAST and the
  coding agent. A single `docker stats` run during a representative scheduled scan would settle it;
  recommend doing so before finalizing tier-M sizing documentation.
- **The nftables assertion probe's exact mechanism** (D.11) is specified at the behavioural level
  (attempt to reach metadata addresses from inside the sandbox on every run, abort if reachable) but the
  concrete implementation — a canary process inside the netns vs. a host-side probe against the netns —
  is left to the implementing worker; a bounded design spike may be warranted before D.11 if the two
  approaches have materially different assertion latency.
- **Legal review of `external` mode is out of scope for this file, deliberately.** Research 20 is explicit
  that its authorization kernel is a *technical* control, and whether it constitutes a *legal* defense
  under CFAA/CMA/EU Directive 2013/40 is unresolved in the research corpus and was never in scope for an
  implementation worker to answer. Recommend counsel review gate `external` mode's release, independent
  of this file's engineering completeness.
- **Whether `go-apispec`'s maintenance state and test coverage justify vendoring vs. forking** was not
  independently assessed here; D.20 vendors it as specified by research 22, but a bounded spike on its
  issue tracker / commit cadence before committing to long-term maintenance would be prudent.

---

## Conflicts With Spine

- **Packaging split for legal-exposure reduction (research 20's runner-up) vs. spine S9's single-system,
  config-gated tier model.** Research 20's primary recommendation — the fail-closed kernel — is what this
  file implements (D.2–D.9), and there is no conflict there. But research 20's *runner-up* recommendation
  is to ship DAST as a **legally separate, opt-in distributed package** (`anvil` — static-only, no network
  probing — versus `anvil-dast` — a separate release requiring explicit installation and attestation),
  specifically to reduce UK CMA s.3A(2) "supply" exposure on the main artifact, and gives distro packagers
  a clean choice. Spine S9's hardware-tier table (S/M/L) instead models DAST purely as a config-gated
  capability within one system (`dast.enabled=false` at tier S — Gate 1 in this file implements exactly
  that), with no mention of a separately-distributed artifact. This file implements the config-gated model
  because that is what spine S9 specifies and what Gate 1 (Phase 0) is written against — but the
  *distribution-law* concern research 20 raised is not addressed by a config flag inside one binary, only
  by an actually-separate release artifact. This plan does not resolve which model is correct; it flags
  the tension for the orchestrator to decide before a v1 release artifact is cut, since retrofitting a
  package split after users depend on a single binary is materially more expensive than deciding now.
