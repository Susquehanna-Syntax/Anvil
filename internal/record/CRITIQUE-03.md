# CRITIQUE-03 — Critic Gate 3 (step R.15)

**Scope reviewed:** R.11 `internal/store/queue.go` (+ test), R.12 `internal/record/correlation.go`
(+ test), R.13 `internal/record/readpath.go` / `taskcard.go` (+ test), R.14
`internal/record/sarif_github.go` (+ test).

**Verdict: FAIL.** One blocker, four majors, four minors. The three verdicts R.15's packet
names are recorded separately in §1 and are (a) PASS, (b) PASS-with-caveat, (c) PASS; the
blocker is outside that list but inside `plan/IMPLEMENTATION-PLAN.md` §6, which the
orchestrator's instruction makes binding over the packet.

---

## 0. What kind of critic this was — read this before trusting the verdict

**This was a SAME-FAMILY adversarial critic.** `plan/00-ROUTING.md`'s cross-family critique
rule was *not* satisfied here and this document does not claim it was. The OWNER DECISION
block dated 2026-08-07 at the top of `00-ROUTING.md` withdrew all OpenCode/OpenRouter routes
because running one copies private repository contents to a third-party provider; R.15's
packet still says `OpenCode route (openai/gpt-5.5)` and that route is dead.

The replacement is an Anthropic subagent given an explicit instruction to **refute rather than
assess**, with named failure modes to hunt. That narrows the shared-blind-spot gap; it does not
close it. **Do not read this file as "cross-family critic: PASS."** It is a same-family critic,
and a later reader deciding whether the cross-family gate has been met should treat it as
unmet.

To compensate, nothing below rests on the implementer's own reported output. Every claim is
either (i) reproduced by a probe test I wrote and ran, or (ii) produced by a **mutation test** —
I broke the implementation in a scratch copy and confirmed the existing suite goes red, which is
the only way to tell an assertion from a tautology. Probes and mutations were run in
`…/scratchpad/mut`, a copy of the tree; **the repository was not modified** except for this
file.

---

## 1. The three verdicts R.15's packet requires

| # | Claim | Verdict |
|---|---|---|
| (a) | `correlation.go` carries a code comment pointing at `plan/40-record-and-storage.md`'s patent Open Question **without attempting to resolve it** | **PASS** |
| (b) | `sarif_github.go` cannot exceed GitHub's caps on any tested input | **PASS, with a recorded caveat** (finding M4) |
| (c) | `queue.go`'s reservation fraction is config-driven | **PASS** |

### (a) Patent flag — PASS

`correlation.go` lines 40–58 name **US10043004B2** (priority 2015-01-30, granted 2018-08-07,
assignee Denim Group Ltd. / Coalfire Systems), state precisely which three implemented signals
are materially similar to the patent's claims (`CorrelationSignalRouteTable`,
`CorrelationSignalParameterName`, `CorrelationSignalCweMatch`), point at
`plan/40-record-and-storage.md` Open Questions #1 by name, quote research/18 Risk #1's
instruction verbatim ("Escalate to the owner; do not assume this is fine"), and say "It is
flagged, not settled." It records that Open Questions #1 requires owner escalation **before the
output ships in a release**. No resolution is attempted; no licence conclusion is drawn.
`TestPatentRiskIsFlaggedInSource` reads the source and fails if the three markers disappear.

I confirmed the pointed-at text exists: `plan/40-record-and-storage.md` line 968 ff., Open
Questions #1, and `plan/00-SPINE.md` S8. **I am not resolving the patent question and this
document takes no position on it** — that is an owner/legal decision and out of scope for R.15.

### (b) GitHub caps — PASS, with a caveat

Every returned file is re-checked by `GitHubSarifFile.WithinCaps()` inside `ProjectForGitHub`
before return, and a violation is an error, not a log line. Results are never truncated: the
count cap splits greedily at 25,000, the gzip cap splits by bisection, and the one unsplittable
case (a single result whose own file exceeds 10 MB gzipped) is **dropped with a ledger entry**
(`GitHubDropExceedsFileSizeCap`) rather than allowed to break the cap. The gzip bytes returned
are the exact bytes measured (`gzipBytes` at `BestCompression`, kept on the file), so the caller
cannot re-compress at a different level and invalidate the guarantee.

Mutation-verified: removing the count-cap split (`if len(results) > GitHubMaxResultsPerRun` →
`if false`) turns `TestGitHubShardsBeyondResultsPerRunCap` red.

**Caveat:** `relatedLocations` are not counted against `GitHubMaxLocationsPerResult`. See
finding **M4** — I could not verify from the sources in-tree whether GitHub's "1,000 locations
per result" figure includes `relatedLocations`, so I am not calling it a cap violation.

### (c) Reservation is config-driven — PASS

`RecutConfig.DastReserveFraction` is a `*float64` so that `0` is expressible (a plain float with
"zero means default" would make the control arm unreachable — a genuinely good call).
`DefaultDastReserveFraction = 0.5` is a default, not the value. `queue_test.go` drives 50 %,
25 % and 0 % and asserts the **row states** change, not merely a reported float. Nothing in the
file hardcodes 0.5 in the arithmetic; `performCut` reads `r.cfg.reserveFraction()`.

---

## 2. Priority failure modes — what I hunted and what I found

| # | Failure mode | Result |
|---|---|---|
| 1 | 50 % reservation backwards, or not applied on a re-cut | **Not present.** Mutation-proved (§3). |
| 2 | Queue not re-cut on a version bump, or fighting `checkRecordVersion` / one-live-lease | **Not present.** Mutation-proved and interaction-proved (§3, §4). |
| 3 | Correlation that merges, fires on one signal, or reimplements sufficiency | **Not present** in `correlation.go`. One related read-path gap: finding **m2**. |
| 4 | Tier 0 exceeding its budget on a realistic record | **Budget is never exceeded** — I measured it myself at ten sizes. But the *way* it stays under budget is a real defect: finding **M3**. |
| 5 | `remediable_by_agent` true on a host finding | **Not present.** Clamped in `taskcard.go`, mutation-proved. |
| 6 | GitHub projection dropping something silently | Whole-result drops are all ledgered. But the ledger **over-reports** one strip class: finding **M2**. And it publishes unsealed halves: **B1**. |
| 7 | Bare enum string literals instead of `contract.go` constants | **None.** §5. |
| 8 | Tests that assert nothing | **None found.** Nine mutations, nine kills. §3. |

---

## 3. Mutation testing — the existing suites are not tautologies

I copied the tree to a scratch directory, broke one thing at a time, and ran
`go test -count=1`. A test that stays green under the mutation it claims to cover is asserting
nothing. All nine mutations were killed.

| Mutation | Tests that went red |
|---|---|
| **A** — reservation removed (`if cut.LateDastArrivalsPossible` → `if false`) | `TestRecutInvertsPriority…/the_default_reservation_prevents_it`, `TestRecutReserveIsConfigDriven` (×3), `TestRecutGivesDastConfirmedAtLeastTheReservation` (×2), `TestRecutReservesFromRemainingNotTotalBudget`, +2 |
| **B** — reservation **inverted** (`charge` reserves for non-`dast_confirmed`) | same four top-level tests + 1 |
| **C** — version bump ignored (never re-cut after the first cut) | six tests |
| **D** — version guard removed (re-cut on every call) | `TestRecutTriggersOnVersionBumpAndNotOnHandoffWrites` |
| **E** — `validateCorrelation` gate dropped from `buildLink` | `TestCweOnlyMatchProducesZeroClusters`, `TestASingleSignalNeverLinksEvenTheStrongestOne`, +3 |
| **F** — `Verified` set from confidence instead of signal kind | `TestVerifiedRequiresAStackTraceOrRerunFlipSignalSpecifically`, +4 |
| **G** — `Merged: true` | `TestMergedIsUnconditionallyFalse` |
| **H** — host clamp removed from the card + `isActionable` | `TestHostFindingIsNeverHandedOutAsActionable` |
| **I** — Tier-0 budget enforcement skipped | `TestOversizeTier0NeedsAnExplicitLoggedOverride` |
| **J** — seal read gate removed from `readOrder` | `TestUnsealedHalfYieldsNoCardsButIsStillReported` |
| **K** — ledger `dropResult` made a no-op (silent loss) | `TestGitHubDastOnlyExclusionIsCountedNotSilent`, `TestGitHubLedgerReconciles`, +2 |
| **L** — no-sharding on the results-per-run cap | `TestGitHubShardsBeyondResultsPerRunCap` |

Mutation **B** is the one R.15's packet specifically asks for: the reservation test does not
merely pass with the reservation present, it **fails when the reservation is pointed the wrong
way**. The `queue_test.go` design that makes this work is `runArrivalSequence(fraction, …)` —
one knob, identical fixture, identical arrival order — plus a `ReserveFraction(0)` control arm
that reproduces S6's inversion end to end. That is the right shape and I could not break it.

---

## 4. The queue re-cut vs `internal/handoff` — probed, and clean

R.15's failure mode 2 asks whether the re-cut fights `checkRecordVersion` or the one-live-lease
guard. I wrote an interaction probe **in `internal/handoff`** (which can import `internal/store`
— the edge only runs one way) driving `store.Recutter` against the real `Queue`:

```
leased handoff 1 at record version 1
cut: performed=true inFlight=10000 reserved=0 open=20000 admitted=1 deferred=3 contended=0
Claim(1): fingerprint 0101… is held by "w1" until 2026-08-08T09:20:00.000000000Z: finding is already claimed
Claim(3): fingerprint 0303… is terminal (skipped_budget): finding has not passed its consumption gate
Claim(4): fingerprint 0404… is terminal (skipped_budget): …
Claim(5): fingerprint 0505… is terminal (skipped_budget): …
--- PASS: TestR15RecutVersusHandoffGuards
```

- the live lease taken at `audit_version` 1 **survives** a version-bump re-cut, holder intact
  (research/08 §4 point 2, and CRITIQUE-02 verdict (e) stays PASS);
- the stale `Handle` still gets `ErrRecordVersionChanged` from `RenewLease` — the re-cut has not
  papered over handoff's own guard;
- rows the re-cut deferred are **genuinely unclaimable through the real `Claim` path**, not
  merely marked deferred in the `Cut` report.

`ready → skipped_budget` is a legal edge of `legalTransitions` and `skipped_budget` is terminal
there, so the cut is monotone. The decision recorded in `queue.go`'s header — that a re-cut
never writes `superseded` and never touches a leased row — is the right call and it closes
CRITIQUE-02 §7's open question in the safe direction.

One residual I am flagging as an observation, not a finding: `internal/store` writes
`handoff.state` with raw SQL, outside `internal/handoff`'s state machine, because the import
edge forbids the call. The guard is `WHERE state = 'ready'`, which reproduces the machine's edge
correctly today. Nothing enforces that it keeps doing so — there is no DB trigger over
`handoff.state` transitions. It is a second writer to a protocol another package owns, which is
the shape §6 G9/G10 exist to prevent, even though this instance is currently correct.

---

## 5. Enum discipline — clean

I grepped all nine reviewed files for every literal of the ten frozen §6 enums plus the
`evidenceClass` / `consumptionClass` / `correlationSignal` sets. **No bare enum literal is used
as a value anywhere in R.11–R.14.** The only hits are:

- `queue_test.go:786` — a `map[string]int64` whose keys are *test labels*, not values;
- `correlation_test.go:832` — `"sast" + FingerprintFieldSeparator + "1"`, a deliberately
  malformed finding **id**;
- two prose comments.

Two things go further than "no literals" and deserve credit, because they make the next enum
addition safe rather than merely correct today:

- `queue.go`'s `evidenceClassRanks` is **derived** from `record.EvidenceClassValues()`, so the
  rank order is not a second copy of the strength order.
- `LateDastArrivalsPossible` switches over all ten `dastStatus` values with no silent default,
  and `TestLateDastArrivalsPossibleIsTotalOverTheFrozenEnum` fails if the enum grows to eleven.
  It is also correctly kept **distinct** from `handoff.HasDynamicEvidence`, with the four
  disagreements individually justified.

---

## 6. Findings

### B1 — BLOCKER: the GitHub projection ignores the per-half seal read gate

**Where:** `internal/record/sarif_github.go`, `ProjectForGitHub` / `projectResults` — no call to
`IsReadableHalfStatus` anywhere in the file.

`plan/IMPLEMENTATION-PLAN.md` §6 ruling **G5** is explicit: *"`sealed` is load-bearing: R.6
makes it the hard read gate ('do not allow a consumer to read a half's results before that
half's `status` equals `sealed`')."* `readpath.go` enforces it (`readOrder` skips any run whose
`Properties.Status` is not `HalfStatusSealed`, and mutation **J** proves the test covers it).
`sarif_github.go` never asks. It projects every run in `l.Runs` unconditionally.

Probe (`TestR15ProbeGitHubProjectsUnsealedHalves`), one run, one result, varying only
`run.Properties.Status`:

```
half status running   readable=false -> GitHub projection carries 1 results, 0 dropped
half status failed    readable=false -> GitHub projection carries 1 results, 0 dropped
half status timed_out readable=false -> GitHub projection carries 1 results, 0 dropped
half status skipped   readable=false -> GitHub projection carries 1 results, 0 dropped
half status sealed    readable=true  -> GitHub projection carries 1 results, 0 dropped
  ... and the projected bytes carry the source snippet verbatim
```

Consequences, in order of how much they matter:

1. **Mid-scan findings are publishable.** A half at `running` has not concluded; its results may
   still be revised or withdrawn. GitHub code scanning is the most visible consumer Anvil has,
   and an alert there is seen by humans and by branch-protection rules.
2. **A `failed` half's results are published as if they were an analysis.** §6's whole reason
   for keeping `completed_failed` distinct from `completed_partial` is that a half that
   *crashed* is materially different from one that *covered part of the surface*. That
   distinction is discarded here.
3. **Uploading is keyed on `runAutomationDetails.id`.** A premature upload of a `running` half,
   followed by the real upload after the seal, means the second replaces the first — the
   projection's own header explains exactly this hazard for shards. The seal gate is what stops
   the same thing happening across time.
4. The loss ledger records **zero** drops in every unsealed case, so the loss is not merely
   permitted, it is invisible.

The projection also does not call `AssertMasked`, where `readpath.go` refuses an unmasked record
outright with the reasoning "the read path feeds a repo-credentialed agent; masking is R.8's
step and runs before this one". I could **not** demonstrate a secret leak through this second
gap — every surface `MaskRecord` covers (headers, parameters, URL, command line, bodies) is
independently stripped from the GitHub projection — so I am recording it as part of this finding
rather than as its own, and as *unverified* harm. The point is structural: the projection's
safety currently rests on the strip list staying exhaustive, and the day a carried field is
added the masking post-condition is not there to catch it.

**Proposed fix:** in `projectResults`, skip runs where `!IsReadableHalfStatus(src.Properties.Status)`
and record the loss — a new `GitHubDropReason` (e.g. `half_not_sealed`) so the count is
enumerable exactly like every other refusal, with the run's `anvil/status` in the ledger entry.
Add `AssertMasked` at the top of `ProjectForGitHub` for the same reason `readpath.go` has it.
Note the interaction with §6 G5 in the file header, which already documents every other
external constraint it honours.

---

### M1 — MAJOR: an expired audit is still fully readable through the read path

**Where:** `internal/record/readpath.go` — `readOrder` (line ~550) and `ManifestFromLog`
(line ~754) both compute readability as `IsReadableHalfStatus(run.Properties.Status)` alone,
ignoring `l.Properties.State`.

`sealing.go` defines the whole gate as `IsReadableHalfStatus(h.Status) && h.AuditState !=
StateExpired`, and its comment on `HalfSeal.AuditState` says why in as many words:

> CRITIQUE-02 F6: ReadHalf refuses an expired audit and Inspect handed out the same HalfSeal
> values with no state check at all, so `Inspect(...).Sast.Readable()` said true on an audit
> ReadHalf refused. `Readable()` is exported and is what a caller branches on; two exported
> readiness paths giving two answers is a gate that is only advisory.

`readpath.go` reintroduces exactly that shape. Probe
(`TestR15ProbeExpiredAuditIsStillReadableViaTheReadPath`), fixture identical except
`Properties.State = StateExpired`:

```
sealing.HalfSeal.Readable() on the same (status=sealed, state=expired) pair = false
manifest half sast: Readable=true   <- DISAGREEMENT
manifest half dast: Readable=true   <- DISAGREEMENT
cards emitted from an expired audit: 9, actionable: 6
```

`StateExpired` means the claim window closed. Handing a coding agent six actionable task cards
against a window that has already closed is not a cosmetic disagreement: the handoff rows behind
them are subject to `ReclaimExpired`, and the agent's work has nowhere legal to land.

**Proposed fix:** `readOrder` and `ManifestHalf.Readable` should consult
`HalfSeal{Status: …, AuditState: l.Properties.State}.Readable()` — reuse sealing.go's predicate
rather than re-deriving half of it. The manifest should still *report* the expired half and its
result count (the same reason it reports an unsealed half), so "expired" and "empty" stay
distinguishable.

---

### M2 — MAJOR: the GitHub loss ledger over-reports `unreferenced_rule`

**Where:** `internal/record/sarif_github.go`, `projectRules` (called from `tryBuild`, i.e. once
per shard) tallies `GitHubStripUnreferencedRule` for every rule not referenced by *that shard*.
The per-shard tallies are then summed into one whole-projection ledger by `commit`.

A rule referenced only by shard 2 is counted as "stripped" while building shard 1 — even though
it **is** delivered to GitHub in shard 2. Probe
(`TestR15ProbeUnreferencedRuleCountAcrossShards`): 25,010 results across 2 shards, 4 rules in the
source run, `rule.0` referenced by shard 1 and `rule.3` by shard 2:

```
rules delivered to GitHub across shards: map[rule.0:true rule.3:true]
StripCounts[unreferenced_rule] = 6   (there are only 4 rules in the source run)
truly lost rules = 2, ledger says 6
```

Six > four is by itself proof that the number is not a count of anything real; it scales with
shard count. This contradicts the file's own stated principle, in the `ghStripTally` comment:

> a ledger that over-reports loss is as untrustworthy as one that under-reports it.

The ledger is the entire mechanism by which R.14 answers research/18 Risk #6 ("if anyone treats
the GitHub UI as the audit…"). A number that inflates with sharding makes the honest answer
unavailable on precisely the large audits the ledger exists for.

**Proposed fix:** compute `unreferenced_rule` once per source run against the union of rules
referenced by **any** kept shard, not per shard; or make it a whole-projection reconciliation in
the final loop of `ProjectForGitHub`, where the delivered rule set is already knowable. A
per-shard rule count, if it is wanted, belongs on `GitHubSarifFile`, not in the shared ledger.

Related, much smaller: `projectRules` drops a duplicate rule descriptor
(`if _, dup := index[rule.ID]; dup { continue }`) with no tally at all. Harmless today, but it
is the one silent drop in the file.

---

### M3 — MAJOR: Tier 0 degrades all-or-nothing, evicting the read order and wasting 78 % of its budget

**Where:** `internal/record/readpath.go`, `fitManifest`.

The budget is **never exceeded** — I measured it rather than trusting the report. Ten sizes,
same realistic fixture (one cluster, SCA, host, DAST-only) plus N extra static findings on
realistic paths:

```
findings=  9 bytes= 3007 spills=[]
findings= 19 bytes= 5342 spills=[]
findings= 29 bytes= 7672 spills=[]
findings= 39 bytes= 8045 spills=[anvil/index.byPath]
findings= 49 bytes= 1776 spills=[byPath byCwe byCluster anvil/cards]
findings= 59 bytes= 1776 spills=[byPath byCwe byCluster anvil/cards]
findings=129 bytes= 1785 spills=[byPath byCwe byCluster anvil/cards]
findings=409 bytes= 1786 spills=[byPath byCwe byCluster anvil/cards]
```

(The two figures asserted in `readpath.go`'s header — 3,007 bytes at nine findings, 1,786 at
409 — reproduce exactly. Failure mode 4 is **not** present.)

The defect is what happens at the crossover. Each shrink step removes a **whole** field, so at
~40–49 findings the manifest goes from just-over-8,192 to **1,776 bytes** in one step: the
materialised read order leaves Tier 0 entirely, and **6.4 KB of the 8 KB budget is then unused
forever**. Every audit above roughly fifty findings gets the same near-empty manifest.
research/24 Table 3's own working example is 433 alarms, so this is the normal case, not the
tail.

Two consequences:

1. Tier 0 is documented as "always read … tells the agent what exists and in what order to
   work". Above the crossover it tells the agent counts and seal states and nothing else; the
   order requires a Tier-2 fetch. R.13's forbidden action ("do not have the default read order
   be anything other than clusters → SAST-by-rank → DAST-by-rank") is *not* violated — the order
   is preserved in the blob — but the tier stops doing its job while three-quarters of its
   budget sits idle.
2. **The default `Reader` does not persist the blob.** `NewReader` leaves `Blobs BlobSink` nil.
   The spilled bytes are returned only in `Manifest.Blobs`, which is `json:"-"`. A caller that
   marshals the manifest and drops the struct — the obvious thing to do — ships a Tier-0
   manifest whose most load-bearing content is a dangling `sha256:` reference. The hazard *is*
   documented in `BlobSink`'s comment, which is why this is a major and not a blocker, but the
   default path walks straight into it.

**Proposed fix:** make the `anvil/cards` step **partial** — keep the highest-ranked card refs
inline up to the remaining budget and spill the tail, recording `Items` as the spilled count
(the `TierSpill` type already carries `Items`). The agent then gets its first N tasks with no
Tier-2 round trip, which is what the tier is for, and the budget is actually spent. Separately,
consider making `Reader.Blobs` required (or having `NewReader` default it to an in-memory sink
the caller must drain) so a spill cannot silently become a dangling reference.

---

### M4 — MAJOR: `relatedLocations` are not counted against the locations-per-result cap

**Where:** `internal/record/sarif_github.go`, `projectResult`. `out.Locations` is truncated to
`GitHubMaxLocationsPerResult` with a `GitHubStripLocationsOverCap` tally;
`out.RelatedLocations` is appended without limit. `WithinCaps` checks only `len(res.Locations)`.

Probe (`TestR15ProbeRelatedLocationsAreUncapped`), one result with 3,000 repo-relative entries
in each array:

```
locations kept = 1000 (cap 1000), relatedLocations kept = 3000 (uncapped)
```

research/18 line 116 records the limit as **"1,000 locations per result (100 displayed)"**
sourced to [S2]. **I could not verify from anything in the tree whether GitHub counts
`relatedLocations` toward that figure**, and I am not going to assert a cap violation I cannot
source — which is why verdict (b) is PASS-with-caveat rather than FAIL. But the file's own
promise is "no returned file exceeds a documented cap on any input", and it applies a documented
cap to one of the two location arrays with no note explaining the asymmetry. Either reading
needs an action:

- if `relatedLocations` do count, this is a cap violation reachable on any fan-out finding;
- if they do not, the file should say so, next to the `GitHubMaxLocationsPerResult` constant,
  with the same sourcing rigour every other number in that block has.

**Proposed fix:** apply the cap to `len(out.Locations) + len(out.RelatedLocations)` and count the
overflow under the existing `GitHubStripLocationsOverCap`, unless [S2] can be checked and
documented to say otherwise. Add the corresponding check to `WithinCaps`.

---

### m1 — MINOR: both members of one cluster are independently actionable and point at the same line

**Where:** `internal/record/taskcard.go`, `buildCard`'s peer-borrowing loop and `cardLocus`.

A DAST-only member of a cluster borrows its SAST peer's file, line range, enclosing symbol and
code snippet. The record is untouched and each finding keeps its own card, so this is **not** a
merge in R.12's sense and the forbidden action is not breached. But the read-side effect is a
duplicated patch task. Probe (`TestR15ProbeClusterPeerEvidenceBorrowing`) on the fixture's own
cluster:

```
SAST card: actionable=true locus={Path:app/db.py StartLine:412 …} writeBackTo=/runs/0/results/0/fixes
DAST card: actionable=true locus={Path:app/db.py StartLine:412 …} writeBackTo=/runs/1/results/0/fixes
DAST card borrowed static evidence from finding "sast:0001", file "app/db.py"
actionable cards in cluster 9f2c…: 2
```

Nothing on either card marks one as the patch site and the other as corroborating evidence. An
agent walking the read order gets two tasks for one defect, writing two proposals into two
different `fixes` arrays. `group_id` is the mechanism that would collapse them, and
`taskcard.go` says correctly that it is "RESERVED and assigned by the coding-agent consumption
pipeline, not here" — so today it is empty and nothing collapses them. The same double-count
reaches `queue.go`: two `handoff` rows, charged twice against the budget the reservation is
dividing.

**Proposed fix:** the borrowing card should carry a flag (or use `CardCorrelation.Role`) to
mark that its locus came from a peer, and `isActionable` should withhold the borrowed side —
a card may withhold an action the record allows, which `taskcard.go`'s own header names as the
one legal direction of divergence. At minimum, record the intended behaviour in the header so
the downstream grouping step knows it inherits a duplicate.

### m2 — MINOR: the card re-enforces the host gate a third time but takes `correlation.verified` on trust

**Where:** `internal/record/taskcard.go`, `cardCorrelation` — `Verified: co.Verified`, copied
without re-checking `CorrelationSignal.SufficientForVerified` over `co.Signals`.

`taskcard.go`'s header argues, correctly, that the host gate is enforced a third time *because
the card is what the agent receives* and "if a record reaches this package with a host finding
marked remediable — a malformed producer, a hand-edited row, a future column default — the card
must still not hand the agent a task it is forbidden to perform." The `verified` bit is the same
class of S7 gate and gets no such treatment. Probe
(`TestR15ProbeCardTrustsRecordVerifiedWithoutRechecking`):

```
contract.go Validate() rejects it: anvil/correlation.verified is true but no "responseStackTrace"
  or "rerunFlip" signal is present; confidence alone never qualifies (00-SPINE.md S7)
card correlation: verified=true signals=[cweMatch parameterName]
CheckAgainstRecord reports no disagreement
```

`Validate()` catches it on the record, so this needs a malformed record to reach the read path —
hence minor. But `CheckAgainstRecord` is the function whose stated job is to name every place the
card contradicts the record, and it stays silent here.

**Proposed fix:** clamp in `cardCorrelation` (`Verified: co.Verified && anySufficient(co.Signals)`),
using `contract.go`'s predicate, never a second copy of it; and add the corresponding check to
`CheckAgainstRecord`.

### m3 — MINOR: a card can assert a verified link to a peer the reader cannot fetch

**Where:** `internal/record/taskcard.go`, `cardCorrelation`; `internal/record/readpath.go`,
`readOrder`.

When one half has not sealed, its results correctly produce no cards — but the *other* half's
card still names them as peers, with `verified: true`. Probe
(`TestR15ProbeUnsealedHalfIsReportedNotHidden`):

```
half sast status=sealed  readable=true  results=7 cards=7
half dast status=running readable=false results=2 cards=0
card sast:0001 correlation peers=[dast:0101] verified=true
  peer "dast:0101" is named on a card but no card exists for it
```

The manifest does report the half as unreadable, so a diligent consumer can work it out. But the
card is documented as **self-contained**, and this one asserts a verified link to evidence that
is, by the read gate's own rule, not yet readable.

**Proposed fix:** mark unreachable peers on the card (a `peersUnreadable` list, or omit them and
say why in `Caveat`). The existing `Caveat` field is the natural home and is already
Anvil-generated text.

### m4 — MINOR: the gzip-cap bisection re-marshals and re-gzips discarded candidates

**Where:** `internal/record/sarif_github.go`, `shard` → `tryBuild`.

Every bisection step marshals the whole candidate and gzips it at `gzip.BestCompression`, and a
candidate that does not fit is discarded. A 25,000-result run that needs *k* size splits does
O(n log n) bytes of `BestCompression` work near the 10 MB boundary. Correctness is unaffected —
the tally discipline (`ghStripTally`, committed only on keep) is exactly right and I could not
break it — but this is a plausible wall-clock problem on the audits that need sharding most.

**Proposed fix:** estimate the split point from the uncompressed size on the first failure
instead of halving blindly, or gzip at a cheaper level for the *probe* and only re-compress the
kept candidate at `BestCompression` (measuring the kept one, so the guarantee is preserved).

---

## 7. Things I tried to break and could not

Recorded so a later reader knows which parts were actually attacked rather than skimmed.

- **The reservation arithmetic.** Two pools, `dast_confirmed` draws reserve-then-open, everything
  else draws open only; `chargeInFlight` drains but never goes negative and never touches the
  reserve for a non-`dast_confirmed` lease. `floor`, not round, so the component cannot outvote
  its configuration by a token. The reserve is released when `LateDastArrivalsPossible` is false,
  which is the right call — holding budget for a class that provably cannot arrive starves the
  classes that did.
- **"A cut, not a knapsack."** Once a pool cannot pay for the next candidate in rank order the
  pool closes and later candidates are deferred even if cheaper. That is deliberate, documented,
  and tested (`TestRecutCostFuncIsConfigurable` proves a knapsack would have behaved
  differently). Continuing to scan for something that fits is genuinely how a budget re-orders
  itself behind the priority scheme's back.
- **`ResolveAuditRecordID`.** Rejects the empty string, blanks, `0`, negatives, a UUID, and
  `"1; DROP TABLE handoff"`. Correctly distinguished from CRITIQUE-02 F7 (that was about
  *exporting* a rowid as portable identity; this is a local lookup key that is never emitted).
- **Correlation determinism.** Union-find with a lexicographic tie-break, sorted root iteration,
  signals ordered by the enum's own declaration order rather than by map iteration,
  `deriveClusterID` a derived RFC 9562 v8 UUID. I checked the version and variant nibbles by
  hand on a real output (`a13af410-f67f-8e7e-bc94-…`: version `8`, variant `10x`). Correct.
- **Untrusted bytes in correlation.** Response text and parameter *values* are read only to
  compute booleans; CWE ids are re-checked to be decimal before being echoed. The one honest
  admission in the file — that an attacker who controls the response body can print a fabricated
  stack trace naming any repo path and thereby manufacture the signal that sets `Verified` — is
  stated plainly with its partial mitigations named as partial. That is the right way to record
  an unclosed threat and I am not treating it as a finding.
- **`relatedLocations` as correlation evidence.** Deliberately *not* read
  (`newFindingView` uses `Locations` only), with the circularity argument spelled out. Correct
  and non-obvious.
- **`capCardText`'s truncation arithmetic.** The notice length is computed with `limit` and
  regenerated with `len(inline)`; since `len(inline) <= limit` the regenerated notice can only be
  shorter, so the cap cannot be breached. Probed with every inline cap maxed simultaneously:
  largest card 3,278 bytes against a 7,500-byte budget.
- **`measureManifest` / `measureCard` self-report convergence.** Writing the byte count into the
  object changes the object's byte count; both loops re-measure to a fixed point with a bound.
  This is the kind of thing that normally ships broken.
- **Enum totality.** `LateDastArrivalsPossible` and `GitHubDropReasonValues` /
  `GitHubStripReasonValues` are all exhaustive and tested for exhaustiveness.

---

## 8. Verification evidence

All four commands run on the repository as reviewed, branch `feat/phase1-queue-readpath`,
Go 1.26.5 windows/amd64. Real output:

```
$ gofmt -l .
(no output — clean)

$ go vet ./...
(no output — clean)

$ go build ./...
(no output — clean)

$ go test -count=1 ./...
ok      github.com/Susquehanna-Syntax/Anvil/cmd/anvil           0.359s
?       github.com/Susquehanna-Syntax/Anvil/cmd/anvil-dast      [no test files]
?       github.com/Susquehanna-Syntax/Anvil/internal/buildpin   [no test files]
ok      github.com/Susquehanna-Syntax/Anvil/internal/handoff    2.420s
ok      github.com/Susquehanna-Syntax/Anvil/internal/record     1.457s
ok      github.com/Susquehanna-Syntax/Anvil/internal/store       0.490s
```

`-count=1` on every run, including every mutation run. Test counts in the reviewed files:
`queue_test.go` 17 top-level, `correlation_test.go` 22, `readpath_test.go` 22,
`sarif_github_test.go` 15; 467 passing assertions-with-subtests in `internal/record` and 29 in
the `internal/store` re-cut subset.

**No golden file is regenerated by any test in scope.** The only `os.WriteFile` in either
package's tests is `migrate_test.go:505`, which deliberately occupies a path to test a failure
mode. `TestPatentRiskIsFlaggedInSource` reads `correlation.go` as data, which is a legitimate
source assertion, not a self-regenerating golden.

### `unverified` — what I could not check

1. **`go test -race` cannot run on this host.** `runtime/cgo: cgo.exe: exit status 2` — no C
   toolchain. Every concurrency claim below is therefore **unverified under the race detector**:
   `Recutter`'s mutex covering the whole cut including its database work; the
   `loadRows` → `applyDeferrals` window (guarded by `WHERE state = 'ready'`, and I verified the
   claim-race path deterministically in §4, but not under `-race`); and `ghProjector`'s
   `shardSeq`/tally state. CI runs `-race` on Linux and has caught a real bug there that passed
   locally on this project; a green local run is not final for any of the above.
2. **Whether GitHub counts `relatedLocations` toward "1,000 locations per result"** — see M4. I
   could not source this from anything in the tree and did not fetch [S2].
3. **Whether an unmasked record can leak a secret through the GitHub projection** — I could not
   construct one (every `MaskRecord` surface is independently stripped), so the masking half of
   B1 is recorded as a structural gap with *unverified* harm.
4. **The `MaxTier1CardTokens` ↔ real-tokenizer relationship.** `ApproxBytesPerToken = 3` is
   argued to be an upper bound on mainstream BPE tokenizers. I did not run a real tokenizer
   against a card; I verified only that the ratio is applied consistently and pessimistically.
5. **Multi-process re-cut.** `Recutter.lastCut` is per-process. The argument that a repeated cut
   is safe (pure function of candidate set, budget and config; only write is
   `ready → skipped_budget`; monotone) held up under reading and under the single-process
   probes, but I did not run two processes against one database file.
6. **`plan/00-SPINE.md` S6's exact wording** is quoted from `queue.go`'s header and from the R.11
   packet; I read the packet and §6 directly but did not re-read `00-SPINE.md` in full.

---

## 9. Recommendation

**R.14 (`sarif_github.go`) does not pass.** B1 is a §6 G5 violation and §6 wins over the packet.
M2 and M4 are in the same file. Reroute R.14 with B1, M2 and M4 in the packet; the caps, the
strip discipline, the shard policy and the loss vocabulary are otherwise well built and should
be kept — this is a fix, not a rewrite.

**R.13 (`readpath.go` / `taskcard.go`) needs a second pass** for M1 and M3, both of which are
gate/degradation defects rather than structural ones. m1, m2 and m3 can ride along.

**R.11 (`queue.go`) passes.** The reservation is correct, config-driven, applied to *remaining*
budget on every re-cut, triggered only by an `audit_version` bump, and it does not fight
`internal/handoff`. Mutation-proved in four directions and interaction-proved against the real
claim protocol.

**R.12 (`correlation.go`) passes.** Links, never merges; the ≥2-signal rule and the CWE-only ban
are enforced by `contract.go`'s own `validateCorrelation` rather than by a second copy;
`Verified` asks `SufficientForVerified` and nothing else; the patent is flagged and not resolved.
Mutation-proved in three directions.

**The patent question (Open Questions #1) remains open and is escalated, not answered here.**
Per `plan/40-record-and-storage.md`, it must reach the owner before R.12's output ships in a
release.

**And once more, because the routing file asks for it explicitly: this gate was satisfied by a
SAME-FAMILY adversarial critic. The cross-family requirement in `plan/00-ROUTING.md` is not
met by this document.**
