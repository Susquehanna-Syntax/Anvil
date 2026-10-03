# REVIEW-A.20 — independent review of A.19 record emission

**Verdict: FAIL.** One blocker, two majors, three minors.

**This was a SAME-FAMILY critic.** The packet routes A.20 to OpenCode `openai/gpt-5.5`; that route is
withdrawn per the OWNER DECISION block atop `plan/00-ROUTING.md`. This review was performed by a Claude
subagent — the same family that wrote A.19 — and therefore carries none of the independence the
cross-family guard was written to buy. Do **not** record this as "cross-family critic: PASS". To
compensate, every claim below is backed by a probe I wrote and ran against the committed code, not by
reading A.19's own tests. Nine probes were written; six passed, three failed. The probes were deleted
after the run and the tree is unmodified apart from this file.

Reviewed at `74dee08` + untracked `internal/record/lanea/`, Go 1.26.5, Windows.
`gofmt -l` clean · `go vet` clean · `go build ./...` clean · `go test -count=1 ./...` **all green**.
`go test -race` was not run: cgo is unavailable on this host (`cgo.exe` exit 2). Noted, not waived.

---

## Priority 1 — Can a host finding ever carry `remediable_by_agent = true`?

**On the literal question asked by the packet: no. This part is earned.**

I probed the bytes rather than the struct, per A.9's lesson. For a host `MatchResult` whose own
`RemediableByAgent` field asserts `true`, I marshalled every shape that leaves this package and walked
the decoded JSON for any key matching `remediable`:

| shape | JSON pointer | value |
|---|---|---|
| `Emission` | `/remediableByAgent` | `false` |
| `Emission` | `/result/properties/anvil/remediableByAgent` | `false` |
| `*Emission` | both of the above | `false` |
| `Emission.Result` | `/properties/anvil/remediableByAgent` | `false` |
| `Results()[0]` | `/properties/anvil/remediableByAgent` | `false` |
| sealed `record.SARIFLog` | `/runs/0/results/0/properties/anvil/remediableByAgent` | `false` |
| `record.TaskCard` | `/remediableByAgent` | `false` |

No outbound shape omits the key, so the "what does a consumer default to" question does not arise on
the happy path. I checked the zero value anyway: `contract.go:1527` carries no `omitempty`, and
unmarshalling `{"properties":{}}` into a `record.Result` yields `RemediableByAgent = false` — omission
defaults to the safe answer in Go and in every JSON binding that maps absent-bool to false.

The branch I exhaustively checked is `remediableByAgent` at `emit.go:676-693`. It is a genuine
allowlist over five inputs: `collector == match.CollectorRepoSCA` **and** `kind == DetectorKindSCA`
**and** `class == EvidenceClassSCA` **and** `fixedVersion != ""` **and** `!parseDegraded`. It takes no
options struct, reads no config, holds no clock, and is called from exactly one site (`emit.go:848`).
`detectorFor` (`emit.go:702-711`) re-derives kind and class from the collector rather than copying them
off the `MatchResult`, and `Emit` refuses a disagreement at `emit.go:752-757` — so the "reaching a gate
is not obeying it" defect from `internal/scanctl` does not recur here. `record.Result.validate`
(`contract.go:2341-2348`) refuses the combination from the other side, and I confirmed it fires: see
finding 2 below.

**But the guard is narrower than the file claims, and the gap is reachable — see finding 2.**

## Priority 2 — Is a second fingerprint computed anywhere?

**No. This is clean.** I reflected over the marshalled `Emission` for both collectors and collected
every `[0-9a-f]{32,}` run in every string value, plus every field whose path contains
`digest`/`fingerprint`/`findingId`:

```
/result/partialFingerprints/anvilFindingId/v1  = e5c9c775…5e08   ← record.Host()
/result/properties/anvil/findingId             = e5c9c775…5e08   ← same value
/result/properties/anvil/advisory/snapshotDigest = "sha256:zzsnapshotqx"  ← copied from the row, not derived
```

Every digest-shaped value in the emitted bytes is the one `internal/record` computed. There is no hash
import, no digest arithmetic, and `record.Host` / `record.Sca` are the only producers. The golden
comparison in `emit_test.go:648` reads `testdata/fingerprint_corpus/*.golden`, which
`scripts/compute_golden_fingerprints.py` produced from `FINGERPRINT-SPEC.md` — so that test's corpus
does not come from the implementation. The named cross-area edge holds.

## Priority 3 — Is `anvil/trust` correct on every externally-originating string?

**Substantially yes.** I injected a distinctive marker into every caller-supplied slot and enumerated
where it surfaced in the emitted JSON:

```
/result/ruleId · /result/message/text · /result/locations/0/…/uri
/result/properties/anvil/detector/advisoryItemId
/result/properties/anvil/advisory/{ids/0,sourceFeed,snapshotDigest,licenseSpdx,excerpt/text}
/licenseManualNote/text
```

All ten are covered by `Trust.Default = untrusted`, which `emit.go:1192-1198` enforces on the emitted
value rather than trusting the contract — and that enforcement is load-bearing, because
`ValidateResultTrust`'s external-pointer loop (`contract.go:2092`) iterates
`Result.ExternalStringPointers()`, which is **empty** for an SCA/host result. A.19 states this
explicitly at `emit.go:1180-1191` instead of implying the contract covers it. That is the right call
and it is unusual to see stated rather than assumed.

The one `anvil_generated` label is on `/properties/anvil~1reasoning`, and it is true by construction:
`composeReasoning` (`emit.go:600-619`) refuses any part outside a closed constant vocabulary or a
base-10 integer, the guard is driven RED by `TestComposeReasoningRefusesAnExternalString` including
near-misses (`"+3600"`, `"3600.0"`, Arabic-Indic digits), and my injection probe confirmed the marker
never reaches the reasoning string. `anvil_generated` on the advisory row is refused
(`emit.go:797-802`). This is not the defect area B shipped.

Two residual gaps, both minor, at findings 4 and 5.

## Priority 4 — Do `as_of` and `staleness_seconds` reflect the feed watermark or emission time?

**Neither, and that is the blocker. See finding 1.**

## Priority 5 — Bare enum string literals

**None.** I walked `emit.go`'s AST and compared every `BasicLit` string against the full value sets of
`DetectorKind`, `EvidenceClass`, `Trust`, `Verdict` and the two collector constants. Zero hits. The
literals `"apt"`, `"rpm"`, `"apk"` in `hostPackageManagers` (`emit.go:523-527`) are anvil-fp locator
segments, not contract enum members, and their keys are `match.Ecosystem*` constants. The `"apt"`
choice is pinned against the frozen corpus rather than against the map, which is the correct direction.

---

# Findings

## 1. BLOCKER — `staleness_seconds` measures the wrong interval, and a three-week-old cache emits as fresh

`emit.go:903-904`, `emit.go:850`, `emit.go:470-473`.

The frozen contract defines the field it is filling (`contract.go:1631-1634`):

> `StalenessSeconds` is S6's `staleness_seconds`: **record-assembly time minus AsOf**. Carried
> explicitly so a consumer never has to know the assembly clock.

A.19 fills it with something else. `AdvisoryRow.StalenessSeconds` is documented at `emit.go:375-378` as
"`advisory.staleness_seconds`, the age ingestion stamped at write time … carried through unmodified",
and that column is defined by `internal/ingest/delta/delta.go:1158-1180` as *the age of the DATA at
write time* — publisher lag, measured against `Last-Modified` at the instant of the last successful
sync. Meanwhile `advisory.as_of` is the **write** timestamp (`upsert.go:352-353`, bound at
`upsert.go:494` from `Apply`'s `asOf`, which `delta.go:863` passes as `now`), not "when this advisory
data was current".

So two producers now write one named field under two different definitions. That is the same class of
defect as two `/v1` fingerprint algorithms under one name, in the freshness dimension instead of the
identity dimension, and S6's "defined once" rule is the rule it breaks.

The consequence is exactly the one the priority list names. A 304 or a failed poll writes nothing
(`delta.go:857-861`), so during an outage both columns freeze. I built that state and read the emitted
values:

```
input : as_of = now-21d   staleness_seconds = 3600   freshness_slo = 86400
output: asOf              = 2026-08-01T06:24:36Z
        stalenessSeconds  = 3600
        beyondFreshnessSlo= false
        reasoning         = "… Age is measured from the ingestion cache watermark,
                             not from the emission clock. Staleness in seconds: 3600"
        TRUE age of the data = 1 818 000 s (21.0 days)
        contract's definition (assembly − asOf) = 1 814 400 s
```

A finding resting on twenty-one-day-old feed data reports one hour of staleness, declares itself inside
a one-day SLO, and says so in the prose a human reads. `BeyondFreshnessSLO()` — the only
machine-readable SLO statement on the crossing artifact — is wrong by a factor of 504. Both errors
point the same way: fresher than reality.

**A.19's Validation item 2 is therefore not met.** The packet requires "a test asserting a stale
advisory produces a Record that surfaces that staleness rather than silently reporting clean". The test
that claims it, `TestStaleAdvisorySurfacesItsStalenessRatherThanReportingClean` (`emit_test.go:487`),
sets `a.StalenessSeconds = 21*24*3600` **on the input row** and asserts that value appears on the
output. It proves copy-through. It cannot fail for the outage case, because the outage case is the one
where the input row's number stays small.

**The suite already contains the contradiction and asserts both halves of it.** `fixtureWatermark` is
frozen at `2026-07-01` (`emit_test.go:75`). At review time that is **52.3 days** ago. The same test
asserts at line 504 that `time.Since(as_of) >= 24h` — "it must be the watermark" — and then at line
530-534 asserts, on an emission carrying that same 52-day-old watermark and an 86400-second SLO, that
`beyondFreshnessSlo == false`, commenting it as "data one hour into a one-day SLO". Under the frozen
contract's definition of the field, those two assertions cannot both be correct. Probe:

```
PROBE5b: fixture as_of is 52.3 days old; emitted stalenessSeconds = 3600;
         SLO = 86400; beyondFreshnessSlo = false
```

**Note for whoever fixes this:** it cannot be fixed inside the package as currently shaped. A.19's
"this package reads no clock" property (`emit.go:104-110`, pinned by `TestThisPackageReadsNoClock`) is
a good property and I would not trade it away, but it means the assembly-relative age must arrive as an
input. The minimal shape is for `AdvisoryRow` to carry the scan's `as_of` — the value O.2 already holds
— or for the caller to supply `StalenessSeconds` already computed as `scanAsOf − (row.as_of −
row.staleness_seconds)`. Either way the emitted `asOf` should be *when the data was current*
(`row.as_of − row.staleness_seconds`), not the write instant, or the two fields will keep disagreeing
with each other by exactly the publisher lag. This is a contract-semantics question that reaches
`internal/ingest` and `internal/record`, so it is above this packet's write scope and belongs to the
orchestrator.

## 2. MAJOR — the allowlist does not cover the ecosystem, so an OS package labelled `repo-sca` is emitted as agent-remediable

`emit.go:676-693`, against the claim at `emit.go:55-62`.

The package header claims the guard "fails closed for any collector, detector kind or evidence class
that arrives later". The ecosystem is a fourth dimension and it is not covered. I emitted a `repo-sca`
match whose ecosystem is a host ecosystem:

```
PROBE8 deb: EMITTED, remediableByAgent(top)=true nested=true detectorKind=sca
PROBE8 rpm: EMITTED, remediableByAgent(top)=true nested=true detectorKind=sca
PROBE8 apk: EMITTED, remediableByAgent(top)=true nested=true detectorKind=sca
```

`record.Validate` accepts all three, because from the record's point of view they are ordinary SCA
findings. The coding agent is handed "bump `openssl` in `Dockerfile`" as actionable work against an
`apt` package. That is the same authorization defect S7 exists to prevent, arriving through the
collector label rather than through the collector.

It is not reachable *today*: `internal/collector/repo/trivy.go:771-782` refuses Trivy's `os-pkgs`
class outright, counting it rather than emitting it, with a comment naming this exact laundering risk.
So the guarantee holds end-to-end — but it holds **one lane up**, not here, and this package's own doc
claims it holds here. A guard whose correctness depends on an invariant enforced in another package,
while documenting itself as self-contained, is the shape that fails the next time someone adds an SBOM
or container collector under the `repo-sca` label.

The fix is one condition using a map this file already owns: refuse, or clamp to non-remediable, a
`repo-sca` match whose `Ecosystem` has an entry in `hostPackageManagers`. Cost is a line; it converts
the ecosystem dimension from denylist-by-omission to allowlist.

Strictly, the packet's question — "no code path allows a **host-collector-sourced** Record to carry
`remediable_by_agent = true`" — is answered *no*, correctly. I am reporting this because the finding it
produces is a host **package**, and the authorization consequence is identical.

## 3. MAJOR — `Emission.RemediableByAgent()`'s doc claims a re-clamp that the crossing bytes do not perform

`emit.go:452-462`. The doc says:

> Reading the record and clamping again also means a Result that arrived from somewhere other than
> `Emit` — hand-built, deserialised, or **mutated after emission** — cannot present a host finding as
> actionable.

The clamp applies to the top-level mirror only. The nested canonical record inside the same JSON object
is not re-clamped, and neither is `Results()` (`emit.go:495-501`), which is the documented projection
onto the `record.Result`s a `Run` carries — i.e. the artifact that actually reaches the store and the
SARIF log. Probe, mutating a host emission after `Emit` returned:

```
PROBE2 Emission top-level remediableByAgent          = false
PROBE2 Emission nested result anvil/remediableByAgent = true    ← disagrees
PROBE2 Results()[0] anvil/remediableByAgent           = true    ← disagrees
```

The consequence is contained: `record.Validate` refuses the assembled log —

```
runs[0]: results[0]: anvil/remediableByAgent must be false for a host finding
(00-SPINE.md S7: the host agent is read-only)
```

— and `CardsFromLog` clamps again at `taskcard.go:550`. So this is not an authorization hole. It is a
false claim in the doc comment of the authorization guard, and the standard this project has already
paid for is that such a claim is deleted rather than qualified. Either narrow the sentence to the
top-level mirror, or make `Results()` clamp so the sentence becomes true.

Related, smaller: `MarshalJSON` at `emit.go:483-490` says "the serialised form cannot disagree with the
method". It cannot disagree at the top level; the probe above shows the object as a whole disagreeing
with itself.

## 4. MINOR — the advisory excerpt's bound and sanitisation are asserted, never checked

`emit.go:392-396` claims the excerpt is "pre-trimmed (<= `record.MaxAdvisoryExcerptTokens`), already
sanitised by A.3 at ingest". Nothing verifies either, and `excerpt()` (`emit.go:1097-1102`) copies the
string through. Probe:

```
PROBE9: EMITTED an excerpt of 24034 bytes (record.MaxAdvisoryExcerptBytes = 2400);
        contains U+200B = true, U+202E = true
        record.Validate ACCEPTED it
```

Exposure is bounded downstream — `taskcard.go:893` caps the card's excerpt at
`MaxAdvisoryExcerptBytes`, so the agent-facing artifact is trimmed — but the 24 KB string with the
zero-width space and the RTL override persists in the record and the store, and **no component anywhere
in `internal/record` re-checks invisible characters** (`internal/ingest/invisible` exists and is not
reachable from here). This package refuses on fifteen lesser invariants, including two that only a
malformed caller could trip; trusting an unverified claim about the highest-risk external field on the
record is inconsistent with its own posture. Either check the byte length and reject, or delete the
"already sanitised" clause so the reader knows it is an assumption.

## 5. MINOR — `TrustVerified` passes through with no validation step named

`emit.go:1097-1112` copies `AdvisoryRow.Trust` onto the excerpt and the licence note. The contract says
of that value (`contract.go:636-639`): "the bytes originated outside Anvil AND passed an explicit
validation step **that is named in the record** … Never a default." A row asserting `verified` produces
a record labelling advisory prose `verified` with no validation step named anywhere:

```
PROBE6 with row trust=verified: excerpt trust = verified
```

Not live today — `internal/ingest/delta/upsert.go:494` always binds `cache.AdvisoryTrustDefault`
(`untrusted`), and the column's CHECK permits only `untrusted|verified`. So this is forward-looking:
the moment a signature-checked snapshot path lands, `verified` will reach the record without the
naming the contract requires. Either refuse `verified` here until there is a slot to name the step in,
or carry the step's identity alongside it.

## 6. MINOR — two tests cannot fail for the reason they claim

- `TestStaleAdvisorySurfacesItsStalenessRatherThanReportingClean` (`emit_test.go:487`) asserts an
  input value reappears on the output. Its corpus is its own assertion. See finding 1.
- The "fresh" control at `emit_test.go:528-534` is time-dependent through the hard-coded
  `fixtureWatermark`. It passes today only because the field it exercises ignores the interval that
  makes it stale; under a corrected `staleness_seconds` it becomes a test that fails on a wall-clock
  date rather than on a code change.

---

# What I checked that came back clean

Recorded so the next reviewer does not re-run it: the fifteen refusal reasons are each driven RED by
`TestEveryRefusalReasonIsReachable`; `EmitAll` refuses rather than skipping on an unresolvable advisory
row (`emit.go:952-963`) — a silent drop there would be indistinguishable from a clean scan; emission is
deterministic across repeated calls; `CvssV4Base` is populated only for a `CVSS:4.0/` vector, leaving
the slot null for a v3.1 row rather than writing a number that is wrong in a way no consumer can
detect; `Result.Level` is deliberately unset with the reason stated rather than a severity vocabulary
invented; the import allowlist is pinned by AST, not by grep; the `deb → apt` locator choice is pinned
against the independently-produced golden rather than against the map that makes it.

The three DEVIATIONS declared in the package header (`emit.go:123-151`) are all real, all reported
rather than applied quietly, and all in the safe direction. Deviation 3 in particular — `parse_degraded`
clamping `remediable_by_agent` to `false` — can only move an authorization answer from yes to no, and
the finding is still emitted as report-only rather than dropped. I would keep all three.

# Gate

Finding 1 blocks A.21. The conformance harness would otherwise pin the wrong `staleness_seconds`
semantics into a two-run byte-identity assertion, at which point correcting it becomes a change to a
frozen conformance expectation rather than a change to one field. Findings 2 and 3 should land in the
same pass; 4, 5 and 6 can follow.
