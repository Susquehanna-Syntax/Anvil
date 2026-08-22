# REVIEW-A.18 — critique of the deterministic comparator (A.17: `internal/match/**`)

**Verdict: FAIL — 3 blockers, 6 majors, 5 minors.**

**This was a SAME-FAMILY critic.** A.18's packet routes this step to OpenCode `openai/gpt-5.5`. That
route is **WITHDRAWN** by the OWNER DECISION block at the top of `plan/00-ROUTING.md` (2026-08-07:
external routes copy private project files to a third party). The cross-family guarantee A.18 was
written to obtain **was not obtained and is still owed**. A later reader must not record this file as
"cross-family critic: PASS". The compensation applied was method, not model: every claim in the
reviewed files was re-checked against the source, every gate was re-run locally with `-count=1`, and
**every finding below is backed by a probe I wrote and executed**. Prose in the reviewed files was
treated as a claim, not as evidence.

---

## 0. The one-paragraph answer

**The comparator is deterministic, it never falls back, and its three version algorithms are
right. The layer above them is where the false answers live.** Priority 1 (non-determinism) and
priority 3 (silent fallback) are clean, and I could not break either: eight separate OS processes
produced one digest over a 121-package corpus, and `Compare` refuses every unimplemented scheme with
a typed reason and a non-usable zero. Priority 2 found one real scheme defect (apk's uncited
equalities, §4.5) and one real matching defect that is not a scheme defect at all: **an epoch
spelled on the installed version but not on the advisory endpoint produces zero findings, no
refusal, `Complete: true`, and `AssertNotSilentlyClean() == nil` — a patched-looking "clean host"
verdict on a vulnerable one** (§3.2). Two more silent-clean paths reach the same place: an empty
advisory cache over 400 well-formed packages passes `AssertNotSilentlyClean` (§3.1), and a package
name whose case the identity check *deliberately accepts* is then used verbatim as the advisory
lookup key, so it matches nothing (§3.3). Rule 3 of the package doc — "ZERO FINDINGS IS NOT CLEAN" —
is the rule this package fails at, three separate ways, while passing every rule it wrote a guard
for.

---

## 1. Method

- Read in full: `comparator.go` (1556), `purl.go` (584), `dpkg_compare.go` (330),
  `rpm_compare.go` (342), `apk_compare.go` (402), `comparator_test.go` (2007). Read as context:
  `plan/00-SPINE.md` S1/S4/S6, `plan/20-lane-a-ingestion-sca.md` A.17/A.18, `plan/00-ROUTING.md`.
- `dpkg_compare.go`'s `verrevcmp`/`order` and `rpm_compare.go`'s `rpmvercmp` were compared
  statement-by-statement against the upstream C (dpkg `lib/dpkg/version.c`, rpm
  `rpmio/rpmvercmp.c`). Both are faithful ports, including the two early returns that make `^`
  the mirror of `~` and the "segment kind is chosen by the first string only" asymmetry.
- **No repository file was modified by this review other than this one.** Probes were built as three
  separate Go modules **outside the repository**, in the session scratchpad, each with a module path
  under `github.com/Susquehanna-Syntax/Anvil/` and a `replace` onto the working tree — which is
  enough to satisfy Go's `internal/` visibility rule without adding a file to the repo. No probe
  file was ever written inside `internal/match/`. `git status --short` before and after this review
  is identical (`?? internal/match/`), and `ls internal/match/` is the five sources plus
  `comparator_test.go`.
- Gates re-run locally, all with `-count=1`: `gofmt -l internal/match/` clean, `go vet
  ./internal/match/` clean, `go build ./...` clean, `go test -count=1 ./internal/match/` **ok**,
  `go test -count=1 ./...` **all ok**. `go test -race` **could not be run on this Windows host**
  (cgo unavailable); the race gate for this package is therefore unverified — though it is a package
  with no goroutines, no shared mutable state and no locks, so the gate has little to find.
- Probe artefacts (scratchpad, not in the repo):
  `…/scratchpad/probe/main.go` (P1–P8 + the cross-process digest),
  `…/scratchpad/probe2/main.go` (Q1–Q6), `…/scratchpad/probe3/main.go` (R1–R3).

---

## 2. Priority 1 — non-determinism. **PASS, and I tried to break it.**

### 2.1 Code reading

The only two map ranges in non-test code are `comparator.go:959` (`NewStaticSource` sorting each
bucket **in place** — order-independent) and `comparator.go:1551` (`sortedKeys`, which sorts before
returning). `evaluatePackage`'s `groups`/`groupOrder` maps are only ever indexed by keys that were
collected into a slice and then `sort.Strings`-ed (`comparator.go:1367`) before use. No `time`, no
`math/rand`, no pointer formatting, no goroutine, no locale-dependent call — `strings.EqualFold` at
`comparator.go:1231` is Unicode-simple-fold but *not* locale-dependent (it is, however, a defect for
a different reason: §3.3). Every reported slice is sorted by a total key that includes every field.

### 2.2 The proof, in eight separate processes

The repo's own `TestCorpusIsStableAcrossProcesses` re-execs the test binary twice, which is the
right shape. I did not trust it and built my own: a 121-record inventory across 15 ecosystems (12 of
them unsupported, so the refusal path and `EcosystemsRefused` participate) against 72 advisory
ranges (24 vendor, 24 upstream, 24 deliberately malformed), digesting findings + every
`CoverageReport` field + every `Refusal`/`Defence`/`UpstreamOnlyAdvisory` sort key.

```
$ for i in 1..8; do ./probe.exe digest; done | sort | uniq -c
      8 a688ccc6fec77d313c9cabf5ba8b6c379785bc90e2c39344dde51efbc32374fc
```

Eight distinct OS processes, eight distinct map seeds, one digest. **Nothing to report here.** This
is the one part of A.17 that is exactly as strong as it claims to be.

---

## 3. Blockers

### 3.1 BLOCKER — an empty advisory cache is reported as a clean host

`CoverageReport.AssertNotSilentlyClean` (`comparator.go:902–924`) branches on four things:
`PackagesSubmitted == 0`, `PackagesEvaluated == 0`, `len(SourceErrors) > 0`, `!Complete`. It **never
reads `PackagesWithNoAdvisoryData`** — the field whose own doc comment at `comparator.go:852–855`
says, verbatim:

> A high count here with zero findings means the cache is empty, not that the host is clean.

Probe R1 — 400 well-formed Debian packages, an advisory source with zero rows:

```
   findings=0 err=<nil>
   submitted=400 evaluated=400 unidentifiable=0 refusedScheme=0 refusedVersion=0 noAdvisoryData=400
   rangesConsidered=0 rangesRefused=0 complete=true
   AssertNotSilentlyClean: nil  <-- READ AS A CLEAN HOST
```

`Complete` is *true* (nothing was refused, nothing errored, ≥1 package evaluated), so the single
flag the doc tells a caller to read — "the single flag a caller may read to know whether 'no
findings' is an answer or an absence" (`comparator.go:881–884`) — says the absence is an answer.
This is the exact state of a deployment where A.5's bootstrap has not run, or has run and produced
nothing, or where ingestion normalised ecosystem strings into a vocabulary the `affected` rows do
not use. Lane A exit criterion 20 and the package doc's Rule 3 are both defeated in the most likely
failure mode of the whole lane.

Note that `TestSilentCleanGuardFiresOnEveryEmptyShape` cannot catch this: its "genuinely clean run"
case is `{PackagesSubmitted: 100, PackagesEvaluated: 100, Complete: true}` — which is byte-identical
to the empty-cache case, because the field that distinguishes them is not in the struct literal and
not in the function.

**Fix:** `AssertNotSilentlyClean` must refuse when `PackagesWithNoAdvisoryData == PackagesEvaluated`
(and probably when it exceeds some fraction), and `Complete` should not be true when `RangesConsidered
== 0`. Add the case to `TestSilentCleanGuardFiresOnEveryEmptyShape` as its own row.

### 3.2 BLOCKER — an epoch on one side only silently clears a real vulnerability

`compareRPMParsed` (`rpm_compare.go`) and `compareDebParsed` (`dpkg_compare.go`) treat a missing
epoch as 0. That is correct dpkg/rpm semantics and I am not disputing it as an *ordering*. It is
catastrophic as a *range predicate*, because installed EVRs carry the epoch and advisory endpoints
frequently do not.

Probe P5 — a Red Hat glibc, which carries epoch 2 on every RHEL 9 host, against the same advisory
spelled two ways:

```
A) fixed=2.34-100.el9 (NO epoch), installed=2:2.34-60.el9 -- host IS vulnerable
  findings=0 err=<nil> complete=true evaluated=1 refusals=0 defences=0
    AssertNotSilentlyClean: nil  <-- reported as a CLEAN host

B) same advisory WITH the epoch spelled (2:2.34-100.el9) -- control
  findings=1 err=<nil> complete=true evaluated=1 refusals=0 defences=0
    FINDING redhat-csaf/RHSA-x glibc CVE-2023-4911 installed=2:2.34-60.el9 range=[0, 2:2.34-100.el9)

C) deb: installed 1:1.2.11.dfsg-2 vs fixed 1.2.13 (no epoch)
  findings=0 err=<nil> complete=true evaluated=1 refusals=0 defences=0
    AssertNotSilentlyClean: nil  <-- reported as a CLEAN host
```

The vulnerable host is reported clean, with **no refusal, no coverage entry, no defence row and
`Complete: true`**. This is a silently wrong CVE match in the false-negative direction — the outcome
the package doc's opening paragraph names as "the worst output this lane can produce", and the
outcome A.17's own packet calls "a missed vulnerability".

Three things make this a blocker rather than an acceptable inherited semantic:

1. **The comparator already captured the signal and threw it away.** `rpmVersion.EpochPresent`
   (`rpm_compare.go:61–64`) is set at line 122 and **never read anywhere in the package** (verified
   by grep). Its doc says it exists "so a refusal message can say what it saw". No refusal message
   ever says what it saw.
2. **The refusal policy is inconsistent.** This package refuses a range that names both `Fixed` and
   `LastAffected` because "they differ by exactly one version and this comparator will not pick one".
   An epoch difference is an unbounded difference and it picks one silently.
3. **The corpus enshrines the wrong direction as correct.** `comparator_test.go:839` is
   `{"an epoch bump clears the range", …Introduced:"1.0", Fixed:"2.0"…, "1:0.1", false}` — an
   installed version with an epoch, a range without, asserted `want: false`. That is the
   implementation's behaviour written down as the expectation. Nothing in `plan/`, `research/` or
   this package acknowledges the hazard (grep for "epoch" across both trees returns only ML training
   epochs and the ordering vectors above).

**Fix:** a range endpoint whose epoch-presence differs from the installed version's must be a typed
refusal (a new allowlist member, e.g. `epoch_presence_mismatch`), counted in `CoverageReport`, not
an ordering. If the orchestrator judges that ingestion should normalise epochs instead, that is a
legitimate answer — but then A.17 must *say* so and refuse until it holds, because today the gap is
invisible.

### 3.3 BLOCKER — the identity check accepts a name spelling it then fails to look up

`identify` (`comparator.go:1231`) accepts a reported `Name` that differs from the purl's name under
`strings.EqualFold`, on the stated grounds that "the purl specification defines deb/rpm/apk names as
case-insensitive with a **lowercase canonical form**". It then **keeps the reported spelling**
(`name` is only replaced by `pu.Name` when it was empty, lines 1242–1244) and `Match` uses it as the
advisory lookup key at `comparator.go:1080`: `m.src.AffectedRanges(ctx, id.Ecosystem, id.Name)`.

Probe R2 — identical inputs except the case of `Name`:

```
-- Name=OpenSSL, purl name=openssl, advisory package=openssl
   findings=0  evaluated=1  noAdvisoryData=1  rangesConsidered=0  complete=true
   AssertNotSilentlyClean: nil  <-- READ AS A CLEAN HOST

-- control: Name=openssl
   findings=1  evaluated=1  noAdvisoryData=0  rangesConsidered=1  complete=true
```

The identity layer declares the two spellings the same package and the lookup layer declares them
different packages. The result lands in `PackagesWithNoAdvisoryData`, which §3.1 has already shown
is not wired to anything.

It is worse than case. `strings.EqualFold` performs **Unicode simple case folding**, not the ASCII
lowercasing the comment claims. Probe R3:

```
-- Name="opensſl" vs purl name openssl        (U+017F LATIN SMALL LETTER LONG S)
   findings=0  noAdvisoryData=1  complete=true
   AssertNotSilentlyClean: nil  <-- READ AS A CLEAN HOST
```

`ſ` folds to `s`, so `RefusalIdentityConflict` does not fire, and the mangled name becomes the
lookup key. `internal/ingest/cache`'s trust model says package-name strings originate outside Anvil
and are untrusted; this is a name-shaped string from an untrusted source that walks past an identity
guard and silently zeroes that package's findings. That is the same shape as the three defeats this
project has already paid for: the guard matched a spelling instead of enforcing a canonical form.

**Fix:** canonicalise. If the purl's name is authoritative for spelling (it is — that is what
"lowercase canonical form" means), set `name = pu.Name` whenever a purl is present, and compare with
an explicit ASCII fold, not `EqualFold`. Alternatively refuse any non-identical spelling. Either
way, `identity.Name` must be the string the advisory index is keyed by, and a probe asserting
`AffectedRanges` was called with the canonical spelling belongs in the suite.

---

## 4. Majors

### 4.1 MAJOR — a refused range still decides, by absence, and re-arms the false positive

`evaluatePackage`'s doc (`comparator.go:1307–1310`) states the invariant:

> Refused ranges … DO NOT participate — an unparseable range must not be able to decide anything,
> **in either direction**.

It does decide, in the direction that matters. Probe P7 — the CVE-2022-2068 backport fixture with
the *vendor* range carrying one malformed endpoint:

```
vendor range MALFORMED (fixed=v1.1.1n-0+deb11u3), upstream range valid
  findings=1 complete=false refusals=1 defences=0
    FINDING ghsa/GHSA-1 openssl CVE-2022-2068 installed=1.1.1n-0+deb11u4 range=[0, 3.0.4)
    refusal ... the fixed endpoint is not a valid deb version: upstream version "v1.1.1n" ...
```

The vendor range's refusal removed it from the precedence group, so the upstream range won by
default and emitted the exact false positive the vendor-first policy exists to prevent — on a host
that carries the backported fix. `Complete` goes false and the refusal is recorded, which is the
mitigation, but nothing on the **finding** says "this exists only because a vendor range failed to
parse", and a consumer that reads findings without reading `Refusals` sees a confident false
positive. Given how much of A.17 is built on the premise that this false-positive class destroys the
tool's audience, an unparseable vendor row should suppress the group's findings (or mark them), not
silently hand the group to upstream.

### 4.2 MAJOR — the vendor-first defence silently does not apply when the vendor row has no CVE alias

`advisoryKey` (`comparator.go:489–494`) groups by `CVEID` when present and by `(Source, SourceID)`
otherwise. The doc explains this in terms of GHSA rows lacking a CVE. The unstated consequence is
the reverse case: if the **vendor** row lacks the alias, the vendor and upstream rows land in two
different precedence groups and the displacement never happens.

Probe Q4 — same fixture, vendor `CVEID: ""`:

```
vendor row has no CVEID, upstream has one -> different advisory groups
   findings=1 complete=true refusals=0 defences=0 upstreamOnly=1
      FINDING src=ghsa/GHSA-2 cve=CVE-2022-2068 range=[0, 3.0.4) ...
```

The false positive returns. `UpstreamOnlyAdvisories` does record the residue (`upstreamOnly=1`),
which is genuinely to the implementation's credit and is the difference between this being a major
and a blocker — but the precondition itself ("the defence requires the CVE alias populated on both
rows") is nowhere stated, and Debian DSA rows commonly enumerate several CVEs per advisory rather
than carrying one alias. Since `internal/ingest/cache` owns whether that column is populated, this
is a cross-step contract that A.17 assumes and does not assert. State it, and ideally add a
`(ecosystem, package, source-family)` fallback grouping or a coverage counter for "vendor rows that
could not be grouped".

### 4.3 MAJOR — advisory-group dedupe silently picks a remediation target by source name

At most one `MatchResult` is emitted per advisory group, and the survivor is the first range in
`sortKey()` order — which begins with `Source`. When two feeds carry the same CVE for the same
package, the alphabetically-first source wins and the other advisory's `Fixed` is discarded. Probe
Q1, on a **repo-sca** row where `FixedVersion` becomes the coding agent's bump target:

```
-- both sources present (ghsa fixed=1.1.1n-0+deb11u5, cvelistv5 fixed=9.9.9)
      FINDING src=cvelistv5/CVE-2022-2068 range=[0, 9.9.9) FixedVersion="9.9.9" remediable=true
-- ghsa alone
      FINDING src=ghsa/GHSA-1 range=[0, 1.1.1n-0+deb11u5) FixedVersion="1.1.1n-0+deb11u5" remediable=true
```

`"cvelistv5" < "ghsa"`, so the coarser CVE-list range wins and the agent is dispatched to bump to
`9.9.9`. The choice is deterministic — it is not a determinism defect — but it is arbitrary with
respect to advisory quality, and nothing in the doc or the tests says the dedupe exists or how it
picks. Either pick the **narrowest** range (lowest `Fixed`) within a group and say so, or emit one
result per `(source, source_id)` and let the record layer dedupe on the fingerprint.

### 4.4 MAJOR — a purl version that disagrees with the version column is not an identity conflict

`identify`'s documented rules (`comparator.go:1134–1148`) refuse a purl/ecosystem disagreement and a
purl/name disagreement. **The purl's `version` is parsed and then dropped on the floor.** Probe P6,
both directions:

```
purl@3.0.11-1 (patched) but Version=1.0.0-1 (vulnerable); advisory fixed 2.0
  findings=1  FINDING ghsa/GHSA-q openssl CVE-9999-1 installed=1.0.0-1 range=[0, 2.0)

purl@1.0.0-1 (vulnerable) but Version=3.0.11-1 (patched); advisory fixed 2.0
  findings=0  complete=true
    AssertNotSilentlyClean: nil  <-- reported as a CLEAN host
```

One direction is a false positive, the other a silent clean. Two identity sources disagree about the
one string the whole lane compares, and the package that refuses `RefusalIdentityConflict` for a
name mismatch takes the column's word for it. A stale purl next to a fresh version column (or the
reverse) is exactly what a re-scanned SBOM looks like. This must be `RefusalIdentityConflict`, and
the rule list at 1134–1148 must gain a rule 6.

### 4.5 MAJOR — apk asserts as fact the same mechanism it refuses as unknowable

`apk_compare.go` R7a refuses `1.00`, `1.000`, `00.1` because "apk's tokeniser gives leading-zero
parts a special negative weight that the published grammar does not describe, and no published
vector this file could cite pins it down". It then asserts R2 (`1.0 == 1`, `1.0 == 1.0.0`) and R6
(`1.0 == 1.0-r0`) as written rules. Probe P4:

```
apk  1.0        vs 1          -> +0
apk  1.0        vs 1.0.0      -> +0
apk  1.0        vs 1.0-r0     -> +0
apk  ValidVersion("1.00")   -> refused: numeric field "00" has a leading zero ... not implemented
apk  ValidVersion("0.1")    -> <nil>
```

These are the same mechanism. In apk-tools' `src/version.c` a numeric part that is a run of zeros is
consumed by the `TOKEN_DIGIT_OR_ZERO` branch — the negative-weight branch R7a refuses to model —
and the absence of a further part is `TOKEN_END`, which carries its own token value. The `0` in
`1.0` goes through the refused branch; the file accepts it and additionally asserts it equals
absence. So either the negative weight is knowable (and R7a's refusal is over-cautious) or it is not
(and R2/R6 are guesses in the one place the file promised not to guess). Both cannot hold.

The file *does* flag R2/R6 as uncited, in a source comment, and the corresponding vectors carry
`provRule`. That is honest and it is why this is a major and not a blocker. But two further things
are not honest enough:

- The suffix-chain vectors (`comparator_test.go:283–293`) are tagged **`provVector`** while citing
  "apk suffix table" — a *rule*, not `test/version.data`. `provVector` is defined in the same file
  as "transcribed from an upstream project's own published comparison test suite". Ten vectors are
  labelled one grade stronger than their citation supports, in the scheme the file itself calls the
  weakest of the three.
- The consequence is reachable: probe Q2 shows `last_affected=1.2` matching installed `1.2.0` as
  vulnerable purely because R2 declares them equal. If apk orders them the other way, that is a
  false positive on a patched Alpine host.

**Fix:** either cite `test/version.data` lines for R2/R6 (which requires network access this host
does not have — say so in `unverified`), or refuse a comparison whose operands differ in numeric-part
count / revision presence, consistently with R7a. And re-tag the suffix chain `provRule`.

### 4.6 MAJOR — the rpm corpus stops exactly where the implementation would fail

`comparator_test.go`'s header claims the rpm vectors come from `tests/rpmvercmp.at`, "including its
tilde, caret and **RhBug:178798 sections**", "transcribed as written there". The RhBug:178798 section
of `rpmvercmp.at` continues past where the corpus stops, with separator-only versions. Probe P3 runs
the remainder:

```
REFUSED  rpm  +_   +_   want +0   err=... version segment "+_" contains no alphanumeric, '~' or '^' character
REFUSED  rpm  _+   +_   want +0   err=... same
REFUSED  rpm  _+   _+   want +0   err=... same
REFUSED  rpm  _    +    want +0   err=... same
```

Four published vectors from the suite the corpus names are refused by the implementation, and the
corpus contains exactly the prefix of that section which passes. `rpm_compare.go` argues the refusal
(a segment of pure separators "is not a version; it is a parse failure upstream of here") and I do
not think the refusal is wrong. **The provenance claim is wrong.** A corpus that is the published
suite minus the rows the implementation fails is a corpus filtered by the implementation, which is
the circularity this file's first 35 lines exist to prevent. Add the four vectors with an explicit
`want: refused` expectation and a sentence saying rpm orders them equal and Anvil declines to.

All other transcribed rpm vectors I spot-checked against `rpmvercmp.at` are correct, including six
that are *not* in the corpus and that I ran independently (`1.0~rc1 < 1.0arc1`, `1.0^ < 1.0^git1`,
`5.5p10 > 5.5p1`, `xyz10.1 > xyz10`, `20101122 > 20101121`, `1.0^git1 > 1.0^`) — all pass. The
`deb-version(7)` published sort order `~~ < ~~a < ~ < <empty> < a` passes as a full 10-pair matrix
(probe P1). dpkg's `0:0 == 0:0-0`, `0:0-00 == 0:00-0`, the last-hyphen revision split and the `+`
rule all pass (probe P2). **The three ordering algorithms are the strongest part of this packet.**

---

## 5. Minors

1. **`UpstreamOnlyAdvisories` under-reports.** `comparator.go:1409` appends only when `hit != nil`.
   An upstream range that decided *not affected* for a package with vendor coverage is not in the
   residue, though the doc (`comparator.go:807–810`) says "an advisory that was decided by an
   upstream range". A non-match is a decision. The list is the packet-scoped view an operator is
   meant to review; it currently shows only the half that produced findings.
2. **`Defence` always cites `vendor[0]`** (`comparator.go:1442–1444`), regardless of which vendor
   range in the group actually governed. With more than one vendor row the defence names the
   alphabetically-first one, which may not be the one whose bound mattered.
3. **A source failure discards results already computed.** `Match` returns `nil, cov, err` at
   `comparator.go:1090`. The doc stresses that the report survives the error; the findings do not.
   For a 5000-package host inventory where the cache drops on package 4999, everything found is
   thrown away. Returning `results` alongside the error costs nothing and the `Complete: false` flag
   already tells the caller not to trust the set as exhaustive.
4. **`rpmVersion.EpochPresent` is dead state** whose doc comment describes a behaviour that does not
   exist (see §3.2). Either wire it into a refusal or delete it; a field that documents an
   unimplemented control is how a reader concludes the control exists.
5. **`Purl.String()` writes `Subpath` un-encoded** (`purl.go`, `String()`) while every other
   component goes through `purlEncode`. `identity.Purl` is this re-rendered form and it lands in
   `MatchResult.Purl`, so a subpath containing a reserved byte does not round-trip. *Read-only
   observation — not probed, and no collector currently emits a subpath.*

---

## 6. The three checks A.18's packet names, answered directly

**(1) No LLM / model / network call anywhere in the match path — PASS.** Verified independently of
the package's own guards:
- `go list -deps -f '{{.ImportPath}} {{.Standard}}' ./internal/match` returns exactly two non-standard
  packages: `internal/match` and `internal/record`. Nothing else, at any depth.
- Direct imports across the five sources are `context`, `sort`, `strconv`, `strings` and
  `internal/record`. No `time`, no `math/rand`, no `os`, no `net/*`, no `database/sql`.
- An AST scan for `time.Now`, `rand.*`, `os.Getenv`, `exec.Command` in the five non-test files
  returns nothing (`TestNoSourceFileReachesForAClockOrARandomSource`, re-run and independently
  reproduced).
- `grep -rn "t.Skip" internal/match/` — **none**. No new entry is owed to
  `internal/SKIPPED-CONTROLS.md`.
- Both of the package's own guards (G1 import allowlist, G5 dependency graph) carry working RED
  controls, and G5's negative control genuinely observes `modernc.org/…` under
  `internal/ingest/cache`. These are real guards, not decorative ones.

**(2) Vendor-advisory-first precedence correctly implemented — PARTIAL / FAIL.** The canonical
CVE-2023-32681 / RHSA-2023:4520 shape works, the defence is recorded rather than silent, and the
G4 RED control (`TestBackportRegressionIsNotVacuous`) genuinely proves the fixture would otherwise
produce the false positive — that is the right way to build this test and it was built that way. But
the precedence is defeated by an unparseable vendor range (§4.1) and by an empty vendor `CVEID`
(§4.2), and neither precondition is stated. Separately, the packet's Forbidden-actions line scopes
the precedence to the **package**; A.17 scoped it to the **advisory** and reported the deviation in
its own package doc (`comparator.go:76–89`) with an argument I find correct — a package-scoped
suppression would be an unbounded false-negative generator, and the residue is reported through
`UpstreamOnlyAdvisories`. **This deviation needs the orchestrator's explicit ratification**; it is
not a defect, but a packet requirement was deliberately not implemented as written and that cannot
be ratified by the implementer.

**(3) `CoverageReport` populated on every call, not only on the happy path — PASS on population,
FAIL on what is built on it.** Probe Q6 confirms population on all three non-happy exits:

```
cancelled ctx:    err=context canceled  submitted=1 evaluated=0 schemes=[deb rpm apk] complete=false
empty inventory:  err=<nil>             submitted=0            schemes=[deb rpm apk] complete=false
source failure:   err=cache unavailable SourceErrors=1                               complete=false
```

All three populate, all three refuse `AssertNotSilentlyClean`. The failure is §3.1: the *happy* path
is where the report goes wrong, because `Complete: true` over an empty advisory set reads as a clean
host.

**Priority 3 (silent fallback) — PASS, explicitly.** Probe P8: `Compare` refuses `""`, `npm`,
`pypi`, `golang`, `maven`, `semver` and `"deb "` (trailing space), returns `0` alongside every
refusal so an error-swallowing caller gets nothing usable, and `SchemeForEcosystem` refuses `Maven`,
`Debian:11` and `""` while accepting only the exact three. A Maven bracket range has no field to
arrive in and its ecosystem is refused by name; PEP 440 and Go pseudo-versions are refused at the
ecosystem gate; a malformed string and an empty string are both `RefusalMalformedVersion`. There is
no lexical fallback and no semver fallback anywhere. **This is the thing A.17 most needed to get
right and it got it right.**

**Priority 4 (range boundaries) — PASS except where §3.2 reaches it.** Inclusive `Introduced`,
exclusive `Fixed`, inclusive `LastAffected`, both-named refused, no-bound refused, `AllVersions`
required to be explicit, `Introduced == Fixed` refused as an empty range (probe P7), open-ended
ranges evaluated on the open side. Endpoints in different *declared* schemes are refused; endpoints
in different *undeclared* schemes are only caught when the foreign string fails to parse — a deb
range with `Fixed: "2.31.0"` (a PyPI version that happens to be a legal deb version) is evaluated
without complaint (probe P7). That is inherent and I do not think it is fixable inside this package,
but it belongs in the package doc's list of reported gaps.

---

## 7. What must change before A.21 unblocks

| # | Severity | Change |
|---|---|---|
| §3.1 | blocker | `AssertNotSilentlyClean` must refuse on `PackagesWithNoAdvisoryData == PackagesEvaluated`; add the case to the G3 table |
| §3.2 | blocker | Refuse (or normalise, and say which) an epoch-presence mismatch between an installed version and a range endpoint; wire `EpochPresent`; delete or invert `comparator_test.go:839` |
| §3.3 | blocker | Canonicalise `identity.Name` to the purl's name; replace `EqualFold` with an explicit ASCII fold; assert the lookup key |
| §4.1 | major | An unparseable vendor range must not hand its group to upstream unmarked |
| §4.2 | major | State (and counter-count) the vendor-precedence dependence on the `CVEID` alias |
| §4.3 | major | Define and test the within-group dedupe; do not let source name pick the remediation target |
| §4.4 | major | Purl version vs `Version` disagreement is `RefusalIdentityConflict` |
| §4.5 | major | Resolve the R7a/R2 contradiction one way; re-tag the apk suffix chain `provRule` |
| §4.6 | major | Add the four refused `rpmvercmp.at` RhBug:178798 vectors with `want: refused`; correct the provenance sentence |
| §5.1–5.5 | minor | As listed |

**Unverified by this review:** `go test -race` (cgo unavailable on this Windows host); whether
apk-tools' `test/version.data` actually contains the ten suffix-chain rows tagged `provVector`, and
whether apk orders `1.0` above, below or equal to `1` — both need network access to the upstream
suites, which the test environment forbids. §4.5 and §4.6 are argued from internal contradiction and
from the transcribed rows present, not from a fetched diff.
