# CRITIQUE-02 — Critic Gate 2 (R.10): sealing, handoff/claim, masking

**Verdict: FAIL.** Two of the five required verdicts fail, on defects reproduced by executed tests,
not by reading.

> ## SAME-FAMILY CRITIC. READ THIS BEFORE QUOTING THE VERDICT.
>
> `plan/00-ROUTING.md` originally required a **different model family** for this gate, precisely so a
> shared blind spot could not survive review. The owner withdrew external routes on 2026-08-07
> because running them copies private files to a third party (see the OWNER DECISION block at the top
> of `00-ROUTING.md`). This critique was therefore produced by a critic of the **same family as the
> implementer**.
>
> A later reader must not record this as a cross-family review. The guarantee obtained here is
> weaker: shared inductive biases between author and critic are *not* controlled for. Every finding
> below is backed by an executed reproduction so that at least the positive claims do not depend on
> the critic's judgement — but the *absence* of further findings carries less weight than a
> cross-family PASS would.

---

## 1. The five required verdicts

| # | Verdict required by the R.10 packet | Result |
|---|---|---|
| (a) | Lease vs. claim-timeout independence | **PASS** |
| (b) | No secure-deletion claims present | **PASS** |
| (c) | Masking runs before both sinks | **FAIL** — F3, F4 |
| (d) | Re-entrant consumer never reads an unsealed half | **FAIL** — F2, F5, F6 |
| (e) | Reaper never drops a live claim | **PASS** |

Independently of (a)–(e), **F1 is a blocker in its own right**: the claim protocol can grant two
live leases on one finding at one record version.

The packet's stop condition is "all-PASS". It is not met.

---

## 2. Method

Everything below was re-derived from the files, not from the implementer's prose. The tree was
copied to a scratch directory and probe tests were written and executed there; **nothing was written
into the repository except this file**.

Toolchain, run against the working tree (Go 1.26.5, windows/amd64):

```
$ gofmt -l .
(no output)

$ go vet ./...
(no output)

$ go build ./...
(no output)

$ go test -count=1 ./...
ok      github.com/Susquehanna-Syntax/Anvil/cmd/anvil          0.385s
?       github.com/Susquehanna-Syntax/Anvil/cmd/anvil-dast     [no test files]
?       github.com/Susquehanna-Syntax/Anvil/internal/buildpin  [no test files]
ok      github.com/Susquehanna-Syntax/Anvil/internal/handoff   0.501s
ok      github.com/Susquehanna-Syntax/Anvil/internal/record    0.650s
ok      github.com/Susquehanna-Syntax/Anvil/internal/store     0.754s
```

The shipped suites are green and are, on inspection, substantive — see §5. The defects below are
cases the suites do not construct.

`go test -race` **could not be run on this host**: it needs cgo and there is no C toolchain
(`cgo.exe` exits 2). That is pre-existing and host-wide, not specific to these packets. CI runs
`-race` on Linux; the concurrency claims in §4 (a) and (e) are therefore verified by reasoning and by
single-threaded reproduction only.

---

## 3. Blocking findings

### F1 — BLOCKER. Two live leases on one finding at one record version.

`plan/40-record-and-storage.md` and this package's own doc make the reclaim/idempotency key
**(fingerprint, record version)**. The durable table does not enforce that key. `schema.sql` declares
`UNIQUE (finding_id, audit_record_id)`, and a re-scan produces a *new* `audit_record` row (its
`scan_run_id` is `UNIQUE`), each with `audit_version` defaulting to 1. So one fingerprint gets one
row per audit record, all of them at record version 1, and each row is independently leasable.

The two entry points then actively diverge onto different rows:

- `AcquireLeaseContext` — `ORDER BY h.created_at, h.handoff_id` → the **oldest** (stale) row.
- `ClaimContext` — `ORDER BY h.audit_record_id DESC, h.handoff_id DESC` → the **newest** row.

`checkRecordVersion` cannot catch this: it compares the Handle against *its own* row's
`audit_record.audit_version`, which never moved. `ErrRecordVersionChanged` only fires when
`audit_version` is bumped **in place** on one `audit_record` — which is the only case
`TestRecordVersionBumpVoidsTheLease` constructs (`internal/handoff/handoff_test.go:944`).

Reproduced:

```
=== RUN   TestProbeDoubleGrantAcrossAuditRecords
    two rows for ONE fingerprint: handoff_id 1 (audit 1) and 2 (audit 2)
    worker-1 holds fp=0707...0707 handoff=1 recordVersion=1 idem=e73d9f0882ac7411
    worker-2 holds fp=0707...0707 handoff=2 recordVersion=1 idem=3cf550b5f68f70b6
    DOUBLE GRANT: two live leases on the same (fingerprint=0707...0707, recordVersion=1)
    the two competing leases carry DIFFERENT idempotency keys, so no downstream dedup
      can suppress the duplicate
    both workers independently recorded 'validated' for the same defect
--- FAIL: TestProbeDoubleGrantAcrossAuditRecords (0.02s)
```

Both workers renewed, both released, both wrote `validated`. This is exactly the outcome
research/08 §4 point 2 is quoted as forbidding in `reaper.go:31`: *"Expiring it would let a second
agent write a competing fix for the same defect."* The mechanism is different from the one that
quote anticipates; the outcome is the one it forbids.

Aggravating: the two competing leases carry **different** `idempotency_key` values (see F7), so the
downstream duplicate-suppression the `Handle` doc promises cannot catch it either.

The queue re-cut that would mark the stale row `superseded` is R.11, which does not exist yet, and
even once it does there is a window. The invariant must be enforced where it is claimed — one live
lease per `(fingerprint, record version)` — not left to a later step's punctuality.

`internal/handoff/claim.go:113` (`eligibleFrom`), `:168`, `:213`; `internal/store/schema.sql`
`UNIQUE (finding_id, audit_record_id)`.

---

### F2 — BLOCKER. `audit_record.state = 'consumed'` shuts the queue, and the reaper then expires what is left.

`eligibleFrom` gates on `a.state IN ('sast_sealed','both_sealed')` for `static_only` and
`a.state = 'both_sealed'` for `requires_dynamic_confirmation`. `'consumed'` is in neither set, and
`'consumed'` is a legal `audit_record.state` (`ck_audit_record_state`) that R.6's `Sealer.Consume`
sets.

R.6 is explicit in the other direction — `sealing.go:775`: *"A consumed audit is still readable:
plan/00-SPINE.md S1 requires a RE-ENTRANT consumer, so taking the record once must not shut the
gate."* The queue shuts it.

Reproduced:

```
=== RUN   TestProbeConsumedAuditShutsTheQueue
    Claim after audit_record.state='consumed' -> handoff: fingerprint 0a0a...0a0a is ready
      but its static_only gate is shut: handoff: finding has not passed its consumption gate
    RE-ENTRANCY BROKEN: a still-ready sibling finding is unclaimable once the audit is consumed
    AcquireLease after consumed -> handoff: no claimable finding
    after the claim window closes: 1 rows expired
--- FAIL: TestProbeConsumedAuditShutsTheQueue (0.01s)
```

One `audit_record` fans out to many `handoff` rows. The first consumption pass marking the audit
`consumed` therefore strands **every sibling finding still in `ready`** — permanently unclaimable,
then swept to `'expired'` by `ExpireClaimTimeouts` at the deadline. The row is kept (so this is not
data *deletion*), but the finding is never handed to an agent in this scan. That is silent work loss
on the exact axis S1 names.

No test in `handoff_test.go` ever sets `record.StateConsumed` — `grep -n "StateConsumed"
internal/handoff/handoff_test.go` returns nothing. The gap is untested, not merely unhandled.

`internal/handoff/claim.go:119-120`, `eligibleArgs()` at `:126`.

---

### F3 — BLOCKER. Masking's discovery surface omits two fields that routinely carry live credentials, so an unmasked secret reaches the store.

`Masker.Mask` pass 1 inspects exactly `result.webRequest.{headers,parameters,target}` and
`result.webResponse.headers`. Pass 2 propagates only values pass 1 *discovered*. Anything carrying a
credential that pass 1 never looks at, and whose value appears nowhere in a header pass 1 does look
at, survives into the record — and the record is what goes to the store.

Two concrete, non-hypothetical carriers:

**(i) `anvil/repro.curl`.** A full curl command line, including `-H 'Authorization: Bearer …'`.

```
=== RUN   TestProbeReproCurlIsNeverMasked
    after MaskRecord, anvil/repro.curl still carries "ghp_LIVETOKEN00000000..."
    AssertMasked also returned nil on that record
--- FAIL: TestProbeReproCurlIsNeverMasked (0.00s)
```

**(ii) `anvil/target.repoUrl` and `.runtimeBaseUrl`.** `https://x-access-token:<token>@github.com/…`
is the *standard* GitHub Actions checkout URL. `maskURL` — which already knows how to strip userinfo
passwords — is applied only to `webRequest.target`, never to these.

```
=== RUN   TestProbeTargetRepoURLCredentialSurvives
    after MaskRecord, anvil/target carries a live credential:
      https://x-access-token:ghp_LIVETOKEN00000000...@github.com/org/repo.git
    AssertMasked returned nil anyway
--- FAIL: TestProbeTargetRepoURLCredentialSurvives (0.00s)
```

This is the R.10 packet's named Forbidden action: a design that *"leaves any code path capable of
persisting an unmasked secret."* It is not the documented body-only limitation — `mask.go:106-114`
disclaims *shape-based body scanning*, which is a different thing. `repoUrl` and `repro.curl` are
structured fields with a known credential position, exactly what structural masking is for.

`internal/record/mask.go:378-392` (pass 1's four call sites).

---

## 4. Major findings

### F4 — MAJOR. `AssertMasked`, the enforceable sink gate, is weaker than `Mask` and fails open on the URL surface.

`mask.go:996` justifies `AssertMasked` as S7's *"enforce in code, not documentation"*: a sink *"can
call it and refuse the record rather than trusting that some earlier step remembered to mask."* It
checks headers, parameters and body caps. It never checks `webRequest.target` — which `Mask` **does**
mask.

```
=== RUN   TestProbeAssertMaskedIgnoresTargetURL
    AssertMasked returned nil on a record whose webRequest.target still carries
      "ghp_LIVETOKEN0000000000000000000000000000"
--- FAIL: TestProbeAssertMaskedIgnoresTargetURL (0.00s)

=== RUN   TestProbeMaskDoesCleanTargetURL
    after MaskRecord target = https://app.invalid/v1/orders?api_key=***REDACTED***
--- PASS
```

So a record that skipped masking, whose only credential is in the URL query, fragment or userinfo,
passes the gate that exists to catch exactly that. `TestAssertMaskedIsTheSinkGate`
(`mask_test.go:771`) has three "put the secret back" sub-cases — header, parameter, oversized body —
and no URL sub-case. Adding one turns it red.

### F5 — MAJOR. `ReadPacket`/`WritePacket` are entirely ungated.

Enumerating every exported function in `internal/handoff` that can return a half's *results* (not
metadata): `ReadPacket` is the only one, and it checks nothing — not seal state, not audit state, not
lease ownership. `WritePacket` likewise materialises a packet for an audit that has sealed nothing.

```
=== RUN   TestProbePacketReadIsUngated
    Claim refused, as designed: ... static_only gate is shut ...
    WritePacket succeeded on an UNSEALED audit: .../packets/1515...1515.sarif
    ReadPacket returned 43 bytes of an unsealed half's results with no lease and no seal check
--- FAIL: TestProbePacketReadIsUngated (0.02s)
```

The claim gate correctly refuses the same fingerprint one line earlier. The packet is called a cache,
but it is a cache *of the payload*, and R.6's read gate means nothing if the bytes are reachable
beside it. (Credit where due: expiry **does** unlink the packet — `TestProbePacketReadAfterExpiry`
passes.)

### F6 — MAJOR. `Sealer.Inspect` bypasses the expiry arm of the read gate.

`ReadHalf` refuses an expired audit with a `*ReadGateError`. `Inspect` returns the *same* `HalfSeal`
values with no state check at all, and `HalfSeal.Readable()` is exported.

```
=== RUN   TestProbeInspectBypassesTheReadGate
    ReadHalf correctly refused: record: read of sast half of audit "a1" refused: status is
      "sealed", state is "expired"; ... (the gate opens only at anvil/status="sealed")
    Inspect on the SAME expired audit returned Sast={Half:sast Status:sealed
      SealedAt:2026-08-08 09:00:00 +0000 UTC} Readable()=true
    Inspect reports the SAST half readable on an expired audit that ReadHalf refuses
--- FAIL: TestProbeInspectBypassesTheReadGate (0.00s)
```

`ReadyForConsumption` checks `StateExpired`; `Inspect` does not. Two exported readiness paths, two
answers. Note also the structural point for verdict (d): `ReadHalf` returns no results at all —
`HalfSeal` is `{Half, Status, SealedAt}`, all of which `Inspect` hands out ungated — so as
implemented the gate is advisory, and R.13 will have to re-implement it over the actual results
rather than inherit it.

### F7 — MAJOR. `IdempotencyKey` is keyed on a rowid, so it does not survive the case it is documented to survive.

`claim.go:646` computes `sha256(audit_record_id ‖ fingerprint ‖ base_commit_sha)` while its own doc
and `schema.sql` say `sha256(audit_id ‖ finding_fingerprint ‖ base_commit_sha)`. `audit_record_id` is
an autoincrement rowid, not the audit identity.

Consequences: (1) a re-scan of the same commit produces a new `audit_record` and therefore a *new*
key for the same finding at the same base commit, so the agent-side git-trailer dedup the function
exists to serve cannot recognise the repeat; (2) it is what makes F1 undetectable downstream
(different keys on the two competing leases); (3) the exported value that "the coding agent writes
into a git trailer" is an internal database rowid, which is not a portable identity.

The `Handle.IdempotencyKey` doc claim — *"stable across crash and reclaim"* — is true, because the
row survives reclaim. The stronger reading a reader will take from it is not.

### F8 — MAJOR. `completed_clean` is reachable for a DAST half that found things.

`RecordDastOutcome` refuses after the half seals ("its outcome is frozen"), so the finding count must
be known *before* the seal. But provenance (from the target harness) and the finding count (from the
DAST worker) arrive at different times and share one struct, and the zero value of `FindingCount`
is 0.

```
=== RUN   TestProbeDastCleanByOrdering
    post-seal RecordDastOutcome -> record: RecordDastOutcome("a2") half=dast state=dast_sealed
      status=sealed: the DAST half has already sealed; its outcome is frozen
    anvil/dastStatus = "completed_clean", MeansDynamicallyScannedClean = true
    a DAST half with 3 findings reports "completed_clean"
--- FAIL: TestProbeDastCleanByOrdering (0.00s)
```

`completed_clean` is the one value contract.go permits a consumer to read as *"dynamically scanned,
no findings"*, and research/23 Risk #1 is quoted in contract.go as *"Anvil must never report '0 DAST
findings' as 'no dynamic vulnerabilities'."* An API whose only defence against that is call ordering
is not enough. `DeriveDastStatus` itself is sound; the hazard is `DastOutcome` conflating two facts
with different arrival times. Making the finding count an explicit argument of the DAST seal, or
requiring it non-zero-valued (an `*int`), would close it.

`internal/record/sealing.go:237` (`DastOutcome`), `:612` (`RecordDastOutcome`).

### F9 — MAJOR. Nothing stops a `requires_dynamic_confirmation` finding being recorded `validated` with no dynamic evidence.

`ReleaseLease` accepts `HandoffStateValidated` from any lease holder regardless of the Handle's own
`ConsumptionClass` and `DastStatus`.

```
=== RUN   TestProbeValidatedWithoutDynamicEvidence
    claimed a requires_dynamic_confirmation finding with DastStatus="not_run"
    a requires_dynamic_confirmation finding was recorded 'validated' while dast_status="not_run"
      (no reproduction can exist)
--- FAIL: TestProbeValidatedWithoutDynamicEvidence (0.01s)
```

On the S7 question the packet actually asks — *does a lease grant more than "may act on this
finding"?* — the answer is **no**, and that part is clean: `Handle` carries no merge field, no scope
field and no verdict field, nothing in either package merges anything, and `state_machine.go:40-44`
states the limit correctly. But `state_machine.go` also says *"Only a DAST reproduction that now
fails earns 'verified fixed', and that judgement is made elsewhere"* — and `handoff.state =
'validated'` is written **here**, by the claimant, unchecked. `DastStatus` on the Handle is
documented as advisory ("so a consumer can *see*"). Either the check belongs on `ReleaseLease`, or
the "made elsewhere" owner must be named.

---

## 5. Minor findings

- **F10.** `ReleaseLease(h, ready)` clears the lease but does not restore the attempt it consumed.
  Two voluntary hand-backs with `max_attempts = 2` strand the row: `state=ready attempts=2/2`, then
  `Claim` → `ErrExhausted`, forever, with no crash having occurred
  (`TestProbeReleaseToReadyBurnsAttempts`). `attempts` is deliberately "attempts started", which is
  right for the crash path; a voluntary hand-back is not an attempt started and should not be
  counted like one.
- **F11.** The flagship masking test's `Repro.Curl` coverage is incidental. `dastFixture`
  (`mask_test.go:210`) puts `plantedBearer` in *both* the `Authorization` header and the curl string,
  so `TestMaskRecordLeavesNoPlantedSecretAnywhere` passes via propagation from the header. It reads
  as proof that `repro.curl` is masked. It is not — see F3(i). The fixture should carry a
  curl-only secret.
- **F12.** `ReadHalf` on an unknown audit returns a `*SealingError` wrapping `ErrUnknownAudit`, so
  `errors.Is(err, ErrHalfNotSealed)` is false. A consumer branching on the gate sentinel — the
  documented way to detect a refusal — will not classify it as one.
- **F13.** `Dispose(id, HandoffStateExpired)` is legal: `CheckTransition(ready, expired)` passes and
  `DisposeContext` rejects only `to == leased`. Any caller can set the claim-timeout terminal state
  without a deadline having passed, from outside the reaper that owns that clock. (Code-read; not
  executed.)
- **F14.** `explainUnclaimable` returns `ErrAlreadyClaimed` if **any** row for the fingerprint is
  leased, even when the row that was actually ineligible failed for a different reason. Misreports
  the cause across the multi-audit-record shape of F1.

---

## 6. What survived the attack — recorded so the PASSes are not read as unexamined

These were probed and held.

- **(a) Two clocks, genuinely independent.** `handoff.lease_expires_at` (Options.Lease, default 20m)
  and `audit_record.deadline_at` (`scan_run.started_at + claim_timeout_seconds`) are separate
  columns, separate sweeps, separate transitions. `ComputeDeadline` is the only formula, called once
  in `BeginAudit`; nothing else writes `deadlineAt`. `SealHalf` never touches it — a late seal moves
  it by nothing. `Options.Lease` is never derived from `claim_timeout_seconds` anywhere.
- **(e) The reaper never drops a live claim, structurally.** `ExpireClaimTimeouts` selects
  `WHERE h.state = 'ready'`, so a leased row is not a candidate at all — a query-level guarantee, not
  a check someone can forget. `legalTransitions` has no `leased → expired` edge.
  `ReclaimExpiredContext` decides expiry in Go against parsed times (not TEXT comparison) and
  CAS-updates on the exact `(state, claimed_by, lease_expires_at)` triple, so a heartbeat that lands
  between SELECT and UPDATE preserves the live claim. `Reap` runs leases first, which is the right
  order.
- **Reclaim idempotency, in the crash sense.** Every mutation is a CAS on the exact lease, so a
  second sweep matches nothing and a resurrected OOM-killed holder gets `ErrLeaseLost` rather than
  overwriting its successor. Attempt arithmetic is consistent: incremented at claim, compared
  `attempts >= max_attempts` in the reaper and `attempts < max_attempts` in the eligibility query, so
  exactly one retry with the default of 2 and no infinite re-lease (the §6 G10 failure).
- **(b) No secure-deletion claim anywhere.** `SECRETS.md` §2 is an explicit denial, §4 names the
  LUKS2/fscrypt alternative, §8 is a claim-to-source table. `DropPacket`'s doc says plainly it is
  *"an unlink, not an erasure"*. `TestNoSecureDeletionClaimOrCall` (`handoff_test.go:1229`) is a real
  AST + prose scan over non-test files, including an `os/exec` import ban — not a token gesture.
- **No bare enum literals.** Grepping every frozen literal across `sealing.go`, `mask.go`,
  `claim.go`, `state_machine.go`, `reaper.go` returns **only three hits, all inside comments**
  (`sealing.go:180`, `:662`, `:978`). Every value that reaches SQL goes through
  `string(record.<Constant>)`, including all eight of `eligibleArgs()`.
  `TestNoBareEnumLiteralsInPackageCode` enforces it by AST.
- **Masking fails closed on unexpected header shape.** Probed with a trailing-space name, an empty
  name, a CRLF-smuggled value, and a Cyrillic homoglyph `Cооkie` — all four redacted, while an
  ordinary `Content-Length: 42` survived intact. `isHTTPFieldName`/`isTChar` are checked *before* the
  denylist, and the deliberate refusal of `strings.EqualFold` (U+212A) is correct reasoning.
- **Ordering inside the masker is right.** Structural → propagate over the untruncated record →
  truncate. The spill digest is therefore over masked bytes, and a secret past the 32 KB cap is
  scrubbed from the spilled blob too. `secretSet.values()` sorts longest-first, which is genuinely
  load-bearing and correctly justified.
- **Test quality.** No golden file regenerates itself (`os.WriteFile` appears in no test), no update
  flag exists, and the assertions sampled are real — `TestMaskRecordLeavesNoPlantedSecretAnywhere`
  first asserts the fixture *contains* each planted value before asserting absence, which is exactly
  the guard that keeps an absence test from being vacuous. F11 is the one place the coverage is
  narrower than it reads.

---

## 7. Unverified

- `go test -race` was not run: no C toolchain on this Windows host (`cgo.exe` exit 2), pre-existing
  and host-wide. The concurrency arguments in §6 (a) and (e) rest on reading plus single-threaded
  reproduction. CI must confirm on Linux.
- F13 is read from source, not executed.
- **Verdict (c) cannot be evidenced by wiring even where masking is correct.** `grep -rn
  "MaskRecord\|AssertMasked" --include=*.go . | grep -v _test.go` finds **no production caller** —
  only the definitions. The store writer that would call it is a later step. So "masking runs before
  both sinks" is today a property of intent, not of the tree; it will need re-verification when the
  writer lands. F3 and F4 are failures of the masker itself and stand independently of that.
- Whether R.11's queue re-cut is intended to `Dispose(..., superseded)` every stale row of a bumped
  audit is not stated in anything R.6–R.8 owns. F1 is a defect regardless — the invariant must not
  depend on another step's timeliness — but the intended division of labour should be confirmed by
  the orchestrator before F1 is fixed, so the fix lands in the right packet.

---

## 8. Recommendation

Re-route **R.7** (F1, F2, F7, F9, F10) and **R.8** (F3, F4), and take F6/F8 back to **R.6**. F5 spans
R.6 and R.7 and needs an owner assigned before it is fixed.

Per the R.10 packet: *"All five verdicts PASS, or R.6/R.7/R.8/R.9 rerouted and re-reviewed."* Two
verdicts fail. Reroute.

R.9 (`SECRETS.md`) is the one reviewed artifact with no findings against it.
