# REVIEW-O.4 — critique of the scan controller core (O.1 deadlines, O.2 state machine, O.3 handoff adapter) and O.5/O.6/O.7 policy

**Verdict: FAIL — 2 blockers, 5 majors, 6 minors.**

**This was a SAME-FAMILY critic.** O.4's packet routes this step to OpenCode `openai/gpt-5.5`; that
route is WITHDRAWN by the OWNER DECISION block at the top of `plan/00-ROUTING.md` (2026-08-07,
external routes copy private project files to a third party). The cross-family guarantee O.4 was
written to obtain **was not obtained and is still owed**. A later reader must not record this file as
"cross-family critic: PASS". The compensation applied was method, not model: every claim in the
reviewed files was re-checked against the source, and every behavioural finding below is backed by a
probe I wrote and ran myself rather than by reading. Reported output was treated as unevidenced
throughout.

---

## 1. Method

- Read in full: `internal/scanctl/deadlines.go` (730 lines), `statemachine.go` (1061),
  `handoff.go` (701), plus `statemachine_test.go` and `handoff_test.go`; and, as the frozen
  substrate they claim to consume, `internal/record/{contract.go,sealing.go}` and
  `internal/handoff/{claim.go,reaper.go,state_machine.go}`.
- Also reviewed, per the dispatch: `internal/policy/{locate.go,engine.go,semver.go}` (O.5/O.6/O.7)
  and `schemas/policy.schema.json`.
- Probes were compiled into the packages under review via `go test -overlay=…`, so **no file was
  added to or modified in the repository** by this review other than this one. `git status --short`
  before and after is unchanged (`?? internal/policy/`, `?? internal/scanctl/`,
  `?? schemas/policy.schema.json`).
- Every probe named below is reproducible: the probe sources are transient, but each finding states
  the exact construction, and each was run with `-count=1`.

### The four required gates, run by me, real output

```
$ go version
go version go1.26.5 windows/amd64

$ gofmt -l .
(no output)

$ go build ./...
OK

$ go vet ./...
OK

$ go test -count=1 ./...
ok      github.com/Susquehanna-Syntax/Anvil/cmd/anvil           0.392s
?       github.com/Susquehanna-Syntax/Anvil/cmd/anvil-dast      [no test files]
?       github.com/Susquehanna-Syntax/Anvil/internal/buildpin   [no test files]
ok      github.com/Susquehanna-Syntax/Anvil/internal/handoff    1.162s
ok      github.com/Susquehanna-Syntax/Anvil/internal/policy     7.605s
ok      github.com/Susquehanna-Syntax/Anvil/internal/record     1.261s
ok      github.com/Susquehanna-Syntax/Anvil/internal/scanctl    1.340s
ok      github.com/Susquehanna-Syntax/Anvil/internal/store      0.302s

$ go test -count=1 -race ./internal/scanctl/
runtime/cgo: C:\Program Files\Go\pkg\tool\windows_amd64\cgo.exe: exit status 2
FAIL    github.com/Susquehanna-Syntax/Anvil/internal/scanctl [build failed]
```

**The suite is green and the findings below are all in territory the suite does not enter.** That is
the reason a green suite is not evidence here: three of the seven confirmed defects are reached only
by holding an `AuditRecord` across a state change, and every test in the package constructs a fresh
one and immediately consumes it.

---

## 2. What I tried to break and could not — stated so a later reader knows what was actually checked

These are not concessions; each was attacked with a specific probe or a mechanical scan, and each
held.

| Claim | How I attacked it | Result |
|---|---|---|
| **No second state machine (ruling G2).** | Grepped the whole package for `DeriveState`, a transition table, a seal ordering, or any assignment to `State`/`Status`/`SealedAt`/`DastStatus` outside `project`. | **HOLDS.** `project()` (statemachine.go:1023) is the only writer of all five lifecycle fields, and its only input is a `record.AuditSeal`. The three occurrences of the string `DeriveState` in the package are all in comments. `EventKind`'s six literals are checked against every frozen enum by `TestEventKindsDoNotCollideWithFrozenEnums` and none collides. |
| **No second handoff/lease API, no second migration (ruling G9).** | Grepped for `CREATE TABLE`, `ALTER TABLE`, `migration`, `database/sql`, `internal/store`, and SQL keywords across all three files. | **HOLDS.** Zero hits outside comments. `handoff.go` re-exports nothing it does not delegate, `handoff.ExhaustedState` is referenced rather than re-picked (handoff.go:638), and `Queue()` is an honest escape hatch rather than a wall. |
| **No bare enum string literal.** | Ran my own regex for all 60-odd frozen literals across the three non-test files, independent of the package's own guard. | **HOLDS.** One hit, and it is prose inside a doc comment (statemachine.go:357, `"started" is not "sealed"`). |
| **No hard-coded trigger policy.** | Grepped `internal/scanctl` for event names, ref patterns, branch names, cron/`OnCalendar` strings and file globs. Read `internal/policy/engine.go` end to end for a decision that cannot be moved by editing `policy.yml`. | **HOLDS, and it is genuinely well done.** `Evaluate` injects no built-in detector, depth or failOn (probe P7: an empty `version: 1` policy resolves to `detectors=[] depth=""`), `Schedule.OnCalendar` is passed through verbatim without parsing, and `searchOrder` is file *locations* with the distinction argued in place (locate.go:55-66). The `dast` warning at engine.go:504 emits text and changes no decision. |
| **Deadlines not recomputable by a late write (clock 2).** | Probe P10, second half: pushed `rec.Deadlines.DeadlineAt` to `t+100h` and ticked at `t+9h`. | **HOLDS.** `record.Sealer.ExpireIfDue` owns clock 2 against its own immutable `deadlineAt`; the audit expired anyway. Clock 3 does **not** hold — see O4-B2. |
| **Claim timeout not treated as a deletion or confidentiality control (S1 #5).** | Read deadlines.go:71-75 and every use of `ClaimTimeout`/`DeadlineAt`. | **HOLDS.** Nothing deletes, nothing is described as retention, and the file says so in its own words rather than by omission. |
| **`settled` / `acceptsWrites` are not read-gate re-derivations.** | Traced every caller. | **HOLDS.** `settled` (statemachine.go:665) feeds only `DurableWriteDue`; `acceptsWrites` (682) feeds only the two write guards. Neither is consulted by `Findings`. `TestAcceptsWritesAgreesWithTheSealer` drives a real Sealer through all six states and compares against `ErrAuditTerminal` — a real test, not a tautology. |
| **Map iteration where order matters.** | Grepped every `range` in the four non-test files of both packages. | **HOLDS.** The only map range in either package is `policy.checkKeys` (engine.go:1115), and it sorts before reporting with the reason written down. `FieldSources` is deliberately a struct and not a map. |
| **Tests that assert nothing.** | Read the source-guard tests and the crash/reclaim test. | **HOLDS.** `TestTheAdapterOpensNoDatabaseAndWritesNoSQL` and `TestTheAdapterUsesNoBareEnumLiteral` both carry negative controls that trip the same predicate. `TestCrashedHolderIsReclaimedAndReprocessedWithoutDoubleApplying` counts *distinct* side effects and asserts both attempts really ran, which is what makes the "exactly one" assertion mean something. No golden is regenerated by its own test. |
| **The four-state machine is gone.** | Checked the vocabulary literal by literal against §6 G2/G5. | **HOLDS.** No `open`, no `complete` anywhere in the package. Transitions key on `record.HalfStatusSealed` and terminality on `record.IsTerminalHalfStatus`. |
| **A stalled GitHub check cannot corrupt or stall the record.** | Checked for any GitHub coupling or fourth clock. | **HOLDS STRUCTURALLY.** `internal/scanctl` imports only `errors`/`fmt`/`time`/`context` plus `internal/record` and `internal/handoff`. There is no publisher, no token, no retry loop, and therefore no path by which a check-run update can block a transition. deadlines.go:235-280 states the residual risk as OPEN and names the invariant. **But:** the isolation is asserted by absence and by prose, and there is no test named for the invariant; and O4-B2 below is precisely the mechanism by which a future publisher handed an `AuditRecord` *could* move a deadline. See §5. |

---

## 3. Blocking findings

### O4-B1 — BLOCKER. The read gate is evaluated against a snapshot the caller owns, so an expired audit's findings are readable. `statemachine.go:532-580`

`AuditRecord.HalfSeal` builds the `record.HalfSeal` the gate takes out of **two fields of the caller's
own value** — `h.Status` from `r.Sast`/`r.Dast`, and `AuditState` from `r.State`. `Findings` then
calls `record.HalfReadGate` on it. The gate is called, and neither arm is reimplemented; the header's
claim on that point is true. What is not true is that the answer is the system's answer. The gate is
being asked about a value that stopped tracking the Sealer the moment the caller stopped calling
`Transition`, and **there is no refresh path**: `Controller` exposes `Policy`, `Watermarks`, `Sealer`,
`Begin`, `Transition`, `NextWake` and nothing that re-projects an existing record.

Probe P3, run against the package:

```
=== RUN   TestProbeP3StaleRecordDefeatsTheReadGate
    record.Sealer.ReadHalf refuses: record: read of sast half of audit "P3" refused:
      status is "sealed", state is "expired"; the claim timeout elapsed and the payload
      was dropped (the gate opens only at anvil/status="sealed")
    PROBE HIT: 1 finding(s) read out of an EXPIRED audit through the stale record;
      AuditRecord.Readable()=true, errors.Is(err, ErrHalfNotSealed)=false
```

Construction: `Begin` → one SAST finding → seal SAST → keep the returned record (`stale`) → advance
the clock past the 8h claim window → `TickEvent` on a *different* copy → the Sealer is now
`expired` and `ReadHalf` refuses → `stale.Findings(sast)` returns the finding.

This is CRITIQUE-03 M1's outcome — "an EXPIRED audit was fully readable and handed a coding agent
actionable task cards against a claim window that had already closed" — reached by a new route. It is
not the same bug (that one checked one arm; this one checks both arms of a stale input), which is
exactly why the three guards in `internal/record` cannot see it: `TestReadGateArmsAppearOnlyInsideTheGate`
calls `parser.ParseDir(fset, ".", …)` and scans **only `internal/record`**, and the two behavioural
guards live in `readpath_test.go` and cover that package's entry points. Nothing watches this package.

`TestReadableAgreesWithFindingsEverywhere` and `TestFindingsAreGatedInEveryUnreadableShape` pass
because `driveToState` (statemachine_test.go:393) always returns the record produced by the last
transition. The suite never holds a record across a state change.

**Proposed fix (design, not text):** make the result surface a `Controller` method, not an
`AuditRecord` method — `func (c *Controller) Findings(rec AuditRecord, half record.Half) ([]record.Result, error)`
that re-`Inspect`s the Sealer and builds the `HalfSeal` from the live `AuditSeal` before calling
`record.HalfReadGate`. Keep `AuditRecord.Findings` only if it is unexported or documented as
snapshot-scoped, and add a regression test named for this shape.

### O4-B2 — BLOCKER. Clock 3 has no authoritative substrate: a late write moves the DAST deadline by plain field assignment. `statemachine.go:965`, `deadlines.go:558-564`

`Deadlines`' contract is unambiguous: *"THE ONLY WAY TO CHANGE A DEADLINE IS TO START A NEW SCAN. No
seal, no write, no publication, no consumer read and no GitHub round-trip moves either field."* The
supporting argument is that `Deadlines` "is a value … and there is no method on it that mutates
anything". That is true of methods and irrelevant to fields: `AuditRecord.Deadlines` is exported,
`clone()` copies it verbatim, and `project()` never touches it. `applyTick` then reads clock 3 out of
that caller-owned field.

Probe P10:

```
=== RUN   TestProbeP10ClockThreeIsCallerMutable
    sealer holds startedAt=2026-08-07T09:00:00Z dastDeadlineSeconds=14400 (immutable)
    record holds DastDeadlineAt=2026-08-07T13:00:00Z
    at t+5h with the deadline moved to t+7h59m: dast=running dastStatus=running state=collecting
    PROBE HIT: clock 3 was moved by assigning to AuditRecord.Deadlines and the forced seal
      did not fire; DAST half is "running". The Sealer still holds the true
      dast_deadline_seconds=14400 and AuditSeal exposes it, but project() never re-derives
      Deadlines from it.
    clock 2 with DeadlineAt pushed to t+100h: state=expired (Sealer.ExpireIfDue is unfooled: true)
```

The last line is the point. Clock 2 shrugs the attack off **because the Sealer owns a private copy**.
Clock 3 does not, even though `record.AuditSeal` already carries `StartedAt` and
`DastDeadlineSeconds` (sealing.go, `AuditSeal`) — every input needed to re-derive it is right there in
the value `project()` already receives, and `project()` ignores both.

Why this is blocking rather than a footgun: clock 3 is the *only* thing that forces a
never-terminating DAST half terminal (Constraint Resolution (c)). Moving it past
`DeadlineAt` is exactly the configuration `DastDeadlineBinds` warns costs "the SAST findings are then
lost to the claim window rather than handed over" — and here it can happen at runtime, from any code
holding the record, with no policy change and no diagnostic. It is also the concrete counterexample
to §5's isolation invariant: a future check-run publisher handed an `AuditRecord` is one assignment
away from moving a deadline.

**Proposed fix:** re-derive `Deadlines` inside `project()` from `record.AuditSeal.StartedAt` +
`ClaimTimeoutSeconds`/`DastDeadlineSeconds`, so the Sealer is the substrate for both clocks; or
unexport the field behind an accessor. Add a test `TestClockThreeCannotBeMovedByAssignment` mirroring
the second half of P10.

---

## 4. Major findings

### O4-M1 — MAJOR. A redelivered seal event bumps `audit_version` although the Sealer treated it as a no-op. `statemachine.go:842-848`

`record.Sealer.SealHalf` is documented idempotent — "Re-sealing a half with the IDENTICAL status is a
no-op and preserves the original SealedAt, so a retried store write cannot move a seal timestamp" —
and returns `nil`. `Transition` cannot tell that `nil` from a real seal and calls `c.publish(&out)`
unconditionally.

```
=== RUN   TestProbeP1DuplicateSealEventBumpsVersion
    after first seal:  version=2 state=both_sealed
    after second seal: version=3 ; after third: version=4
    PROBE HIT: version 2 -> 3 -> 4 on redelivered seals that changed nothing
      (Sealer.SealHalf is documented idempotent and returned nil each time); VersionBumped=true
```

The cost is not cosmetic and is paid in two other packages. Every bump obliges S6's queue re-cut
(R.11) — the file says so itself at `VersionBumped`. Worse, `internal/handoff` re-checks
`audit_record.audit_version` on **every** mutation through `checkRecordVersion` (claim.go:641) and
answers `ErrRecordVersionChanged`; `Task.RecordVersion`'s own doc in handoff.go:281-286 says "work
against a stale version is refused rather than applied". So one duplicated worker message — the
ordinary consequence of at-least-once delivery, a retried store write, or two workers fanning the
same seal in — invalidates every in-flight lease on that audit and forces a full re-cut, for a
transition that changed nothing. `TestVersionIsMonotonic` checks monotonicity, which this does not
violate; nothing checks that a bump corresponds to a change.

**Proposed fix:** have `Transition` compare the `record.AuditSeal` before and after the Sealer call
and publish only on a real difference. `Inspect` is already called at the top of `Transition` (line
823) and its result is discarded — the before-image is free.

### O4-M2 — MAJOR. The write guards consult the caller's stale `anvil/state`, so findings and correlation land on an expired audit. `statemachine.go:905, 998`

`applyFindings` and `applyCorrelation` reach no Sealer entry point, so they carry their own
`acceptsWrites(out.State)` guard — and `out.State` is `rec.State`, the caller's copy, not the
Sealer's. The mirror is faithful (M2's own test proves `acceptsWrites` agrees with
`ErrAuditTerminal`); the *input* is not.

```
=== RUN   TestProbeP2StaleRecordAcceptsWritesAfterExpiry
    sealer state = expired ; stale copy state = dast_sealed
    PROBE HIT: findings accepted onto an EXPIRED audit via a stale record;
      projected state=expired, buffered sast findings=1
    PROBE HIT: correlation accepted onto an EXPIRED audit; state=expired clusters=1
```

`acceptsWrites`' own doc names the failure it is there to prevent — "without this, findings would
keep piling onto an expired audit that record has already given up on" — and it does not prevent it.
Combined with O4-B1, findings buffered after expiry are also *readable* through the same stale record.

**Proposed fix:** the same one-line change as O4-M1 — keep the `record.AuditSeal` from the `Inspect`
at line 823 and project it onto `out` **before** the switch, so every guard in this file reads the
Sealer's answer.

### O4-M3 — MAJOR. Concurrent fan-in silently loses findings; the documented failure mode understates it. `statemachine.go:699-706`

`Controller`'s doc: *"two goroutines transitioning the same audit will each get a consistent record,
but the LAST writer's version counter wins. A caller that fans events in from several workers should
serialise Transition per audit; the Sealer will still refuse an illegal seal either way, so the
failure mode is a skipped version bump, not a corrupt lifecycle."*

The mitigating instruction is present. The characterisation of the consequence is wrong, and it is
the characterisation an implementer will act on:

```
=== RUN   TestProbeP11ConcurrentFanInLosesFindings
    8 workers x 3 DAST findings = 24 expected; the surviving record holds 3
      (pendingDast=3 version=1)
    PROBE HIT: 21 of 24 findings lost.
```

The lifecycle is indeed not corrupted — the Sealer's mutex sees to that. But `findings[]`,
`Correlation`, `Version`, `PublishedAt` and `PendingDastFindings` live on the caller-owned value with
no mutex anywhere, so fan-in loses *results*, on a security scanner, silently. "A skipped version
bump" and "seven eighths of the DAST findings are gone" are not the same warning.

There are **zero** concurrency tests in `internal/scanctl` (`grep -nE "go func|sync\.|WaitGroup|Parallel"`
over both test files returns nothing), and `-race` cannot run on this host, so CI is the only place
this could ever have surfaced — and CI would not surface it either, because no test creates a second
goroutine.

**Proposed fix:** either move the findings/correlation buffers into the `Controller` behind the same
lock discipline as the Sealer, or restate the doc as "fan-in loses findings; serialise per audit" and
add `TestConcurrentFanInIsSerialisedPerAudit` as a live probe of whichever choice is made.

### O4-M4 — MAJOR. Glob matching is super-polynomial and unbounded, and the pattern comes from the scanned repository. `internal/policy/engine.go:706-736`

`matchSegments` handles `**` by recursing over every split point with no memoisation, so `k`
independent `**` segments against an `n`-segment path costs O(n^k). `validateGlob` bounds nothing but
syntax, `schemas/policy.schema.json` carries no `maxItems`/`maxLength` anywhere (its only `pattern`
is the duration regex on line 50), and `Evaluate` applies no budget.

```
=== RUN   TestProbeP6GlobBlowup
    path segments=20  `**` count= 6  elapsed=2.6212ms
    path segments=20  `**` count= 8  elapsed=28.8407ms
    path segments=20  `**` count=10  elapsed=285.0843ms
    path segments=20  `**` count=11  elapsed=796.8441ms
    path segments=30  `**` count= 6  elapsed=19.0663ms
    path segments=30  `**` count= 8  elapsed=487.639ms
    path segments=30  `**` count= 9  elapsed=2.0743738s
    path segments=30  `**` count=10  elapsed=8.50591s
    PROBE HIT: path segments=30, `**` count=11: MatchGlob did not return within 20s for ONE
      pattern against ONE path (pattern = "**/**/**/**/**/**/**/**/**/**/**/zzz")

=== RUN   TestProbeP6bRuleLevelBlowup
    ScanRule.Matches over 200 changed paths, 8 `**`: match=false err=<nil> elapsed=29.3382633s
    PROBE HIT: one rule, one pattern, 200 changed paths = 29.3382633s of CPU inside Evaluate
```

An earlier run of the same probe at 12 `**` segments **exceeded a ten-minute test timeout**.

`Matches` loops `anyGlobMatches` per changed path (engine.go:585, 601), so the per-path cost is
multiplied by the change set, and `Evaluate` loops that per rule. Eight `**` segments is a typable
pattern, not an adversarial one, and 200 changed paths is a small PR. The failure mode is a wedged
`Evaluate`, and this package's own header says the policy file "decides whether a security scan
happens at all" — a scan that never starts because the evaluator is spinning is
research/09 Risk #4's failure mode again (a reviewer reads no signal as no problem). The file is read
from the repository under scan, which on the public-repo path is not fully trusted input.

**Proposed fix:** the standard linear `**` walk (advance greedily with one backtrack point per `**`,
or memoise on `(len(pat), len(seg))`). Either is a small, testable change; the current recursion is
the only part of an otherwise disciplined engine that is not bounded. Add a benchmark or a bounded
`-timeout` test with a 12-`**` pattern as the regression.

### O4-M5 — MAJOR. Clock 2's store-side sweep has no caller: the in-memory expiry and the durable expiry are never driven together. `handoff.go`, `deadlines.go:53-54`

deadlines.go names two owners for clock 2's due-check: *"record.Sealer.ExpireIfDue in memory, and
handoff.Queue.ExpireClaimTimeouts against the store."* `applyTick` drives the first (statemachine.go:983).
Nothing drives the second:

```
$ grep -rn "ExpireClaimTimeouts\|\.Reap(\|Queue.Run" --include=*.go . | grep -v internal/handoff/
./internal/scanctl/deadlines.go:54:   //   handoff.Queue.ExpireClaimTimeouts against the store. This file supplies
./internal/scanctl/deadlines.go:574:  // memory and handoff.Queue.ExpireClaimTimeouts owns it in the store, and
./internal/scanctl/deadlines.go:595:  // false }`) and the same one handoff.Queue.ExpireClaimTimeouts makes (`if
./internal/scanctl/deadlines.go:691:  // handoff.Queue.ExpireClaimTimeouts decide that, and a live claim is never
```

Four comments, no call. `Consumer` (handoff.go:567) surfaces `ReclaimExpired` — clock 1 only — and
neither `ExpireClaimTimeouts` nor `Reap` (which runs both sweeps in the load-bearing order,
reaper.go:371) nor `Run`. The adapter is the *only* file in the tree that sees both clocks, and it
neither wires nor documents who drives the store-side one.

The resulting divergence is the exact shape §6 ruling G10 catalogues: the controller marks an audit
`expired` in memory while its `handoff` rows remain `'ready'` and keep being leased, because
"40's ready-set index still sees the finding as 'ready', so it is re-leased forever". The escape
hatch (`Queue()`) makes the fix reachable, but reachable is not wired, and nothing in the reviewed
files says whose job it is.

**Proposed fix:** either have `Consumer` expose `Reap`/`Run` and state that a daemon must drive it on
the same schedule as `NextWake`, or add an explicit "who runs the reaper" section to handoff.go's
header naming the owning step. A comment that names an owner four times without a call site is a
coordination gap, not documentation.

---

## 5. Minor findings

- **O4-m1.** `applyTick` (statemachine.go:957) can mutate the Sealer and *then* return an error: it
  calls `SealHalf(dast, timed_out)` and `publish`, and only afterwards calls `ExpireIfDue`, whose
  error path returns before `project`. `Transition`'s contract — *"A refused transition changes
  nothing, in the Sealer or in the returned value"* — is therefore not total. Reachability is low
  (`ExpireIfDue` errors only on `ErrUnknownAudit`, i.e. a concurrent `Forget`), but when it happens
  the version bump is lost and the caller's record permanently disagrees with the Sealer about the
  DAST half. Either make the statement conditional or capture the seal before the second call.
- **O4-m2.** The source guards are narrower than the code they defend.
  `TestTheAdapterUsesNoBareEnumLiteral` and `TestTheAdapterOpensNoDatabaseAndWritesNoSQL` call
  `parseAdapter`, which parses **`handoff.go` only** (handoff_test.go:919) — `statemachine.go` and
  `deadlines.go` are unguarded (they are clean today; I checked by hand). And
  `internal/record`'s `TestReadGateArmsAppearOnlyInsideTheGate` parses `"."`, so nothing prevents a
  future author adding a `== record.StateExpired` comparison to a readability path *in this package*.
  Given O4-B1, that guard is worth extending here.
- **O4-m3.** `applyCorrelation` (statemachine.go:1005) **replaces** `Correlation` wholesale rather
  than appending. research/21 §5 describes correlation as "populated as both sides land", which reads
  incremental; if R.12's correlator emits partial batches, the SAST-side clusters are discarded when
  the DAST-side batch arrives. Neither `CorrelateEvent` nor `AuditRecord.Correlation` states which
  contract the correlator must honour, and `TestCorrelationIsCopiedNotAliased` only checks aliasing.
  Document it and test the two-batch case.
- **O4-m4.** `Controller.SetClock` (statemachine.go:755) writes `c.now` with no lock while
  `Transition`, `applyTick`, `publish` and `NextWake` read it. `record.Sealer.SetClock` takes its
  mutex for the same assignment. Construction-time use is safe; a daemon that re-clocks at runtime
  has a data race that this host's `-race` ban means only CI can see.
- **O4-m5.** `DeadlinePolicy.Resolve` (deadlines.go:442-446) returns early when `DastEnabled` is
  false and never validates `DastDeadlineSeconds`, so a policy with `dastDeadlineSeconds: -1` and DAST
  off resolves clean. Harmless today; it means a config error survives until the tier is installed.
- **O4-m6.** No test in the package creates a goroutine, and `-race` cannot run on the dev host. The
  package's central type carries an explicit concurrency contract (statemachine.go:699-706) with zero
  coverage. Given that `internal/handoff/reaper.go:415` records a real concurrency bug that "reproduced
  on ubuntu-latest under `-race` while passing every run on the Windows dev host", the absence here is
  a coverage gap, not a style note.

---

## 6. The packet's four required coverage points, answered directly

1. **Re-entrancy races — two consumers racing an expired lease.** *No new defect.* The adapter adds
   no second lease clock, no second reaper and no Go-side re-check of the consumption gate; every
   mutation is `internal/handoff`'s compare-and-swap on `(state='leased', claimed_by,
   lease_expires_at)`, and `Task` keeps the `handoff.Handle` unexported so the CAS cannot be routed
   around (verified: `taskOf` is the only constructor, and `TestAHandBuiltTaskGrantsNothing` covers
   the forgery path). The idempotency key is stable across reclaim and this is properly tested with a
   distinct-side-effect counter. **Caveat:** the guarantee is inherited, not demonstrated here — no
   scanctl test races two consumers, and O4-M1 supplies a *new* way to break an in-flight lease
   (a spurious version bump ⇒ `ErrRecordVersionChanged` on renew, release and packet read).
   Proposed scenario: two `ConsumeOne` goroutines on one fingerprint after `f.clock.advance(lease+1)`,
   asserting exactly one `Applied` outcome and `attempts == 2`.
2. **Deadline anchoring — scan start, not last write.** Clock 2: **correct and defended in depth**;
   the anchor resolution against `audit_record.created_at` (deadlines.go:83-124) is the best-argued
   passage in the three files, and probe P10 confirms the Sealer is unfoolable. Clock 3: **O4-B2**,
   blocking — same anchor on paper, no immutable substrate in practice.
3. **Completeness of the state machine against the four states.** The four-state machine is correctly
   *absent*; §6 G2 struck it and O.2 emits R.1's six values via `record.DeriveState` only.
   `TestEverySixthStateIsReachable` and `driveToState` cover all six, `TestSettledIsTotalOverTheStateEnum`
   fails if R.1 changes arity, and no `complete`/`open` token survives anywhere. **PASS.**
4. **Is the residual check-run risk isolated from the daemon-side record?** Structurally yes — there
   is no GitHub coupling of any kind in the package, so a stalled, rate-limited or rejected check-run
   update has no path into a transition. Two qualifications, neither of which I would call blocking on
   its own: the invariant is asserted by prose and by absence with no test named for it; and O4-B2 is
   the concrete mechanism by which the isolation would fail the moment a publisher is handed an
   `AuditRecord`, because `Deadlines` is writable from anywhere holding one. Fixing O4-B2 converts
   this from "isolated because nothing does it yet" to "isolated by construction".

---

## 7. Unverified — items I could not close, stated so the orchestrator re-runs them

- **`go test -race` was not run.** `cgo.exe: exit status 2` on this Windows host, as the dispatch
  predicted. Every concurrency statement above (O4-M3, O4-m4, and the re-entrancy assessment) is
  based on reading and on single-process behavioural probes, not on the race detector. Given that
  `internal/handoff/reaper.go:415` records a real bug that only CI's Linux `-race` caught, **treat the
  local green as provisional for anything in §4 and §5 touching concurrency.**
- **Probe reproduction.** My probes were injected with `go test -overlay` and are not in the tree, per
  my write restriction. Each finding states its construction precisely enough to re-create, but a
  re-runner must write them; there is no artifact to execute.
- **Fork-PR threat model for O4-M4.** I established that the glob cost is unbounded and that the
  pattern comes from the scanned repository. I did **not** establish which ref's `.anvil/policy.yml`
  the Action or the daemon actually evaluates for a fork PR — that is O.8's and O.11's territory. If
  the base-branch policy is always used, O4-M4 is a self-inflicted-hang bug; if a PR head's policy is
  ever evaluated, it is untrusted input. The fix is the same either way; the severity is not.
- **`schemas/policy.schema.json` conformance.** I read it for bounds (`maxItems`/`maxLength`: none
  anywhere) and spot-checked it against `keysPolicy`/`keysSettings`/`keysScanRule`. I did not audit it
  clause by clause against `FromDocument`; `TestDecoderKeySetsMatchSchema` claims to, and I did not
  independently re-derive that claim.
- **`internal/policy/semver.go` (O.7)** was read for hard-coded policy (`gitTimeout`, `maxTagWalk` are
  guards with derivations, correctly labelled) and for a second enum (none — it returns `BumpKind`).
  Its git plumbing, shallow-checkout detection and semver parser were **not** exercised against a real
  repository by me; `semver_test.go` is 524 lines and I read only its function list.
- **CRITIQUE-01/02/03 open items** were read for overlap and none of the findings above duplicates or
  worsens one. I did not re-verify their open items themselves.
