# Skipped controls: a repository-wide inventory of `t.Skip`

## Why this document exists

A test that skips still lets its package print `ok`. A reviewer reading a green
run sees no gap, because there is nothing red to see. That is not a theoretical
concern here — it has happened twice, to two unrelated packages, for two
different reasons:

1. **`TestSymlinkedCacheRootIntoTheQuarantineIsRefused`**
   (`internal/mirror/accelerator`). The test created its bypass with
   `os.Symlink`, which on Windows needs `SeCreateSymbolicLinkPrivilege`
   (Developer Mode or an elevated shell). On an ordinary Windows dev host the
   call failed and the test skipped — all four subtests, every run. The control
   it exists to hold is the share-alike licence quarantine: nothing the
   accelerator downloads may land in `mirror/tier2`. With the guard unverified
   on Windows, a **directory junction** (`mklink /J`, which needs no privilege
   at all) walked straight through it. `filepath.EvalSymlinks` keys off
   `os.ModeSymlink` and does not follow a junction, so `guardCacheRoot` was
   handed a path that looked like an ordinary cache root and returned `nil`.
   Nobody noticed, because the package said `ok`.

2. **`TestPackageDependenciesStayCollectorShaped`**
   (`internal/collector/host`). The dependency-shape guard shells out to
   `go list -deps .` and used to `t.Skipf` when that command could not run. The
   only test standing between the shipped collector binary and
   `modernc.org/sqlite`, `net/http` and `internal/store` therefore reported
   SUCCESS in exactly the environments where it could not check: a hermetic
   build, a container with no toolchain, a CI job with a broken `PATH`. It now
   `t.Fatalf`s, and its comment (A.12 m4) records why.

The shape is the same in both cases and it is worth naming precisely: **a guard
that vanishes silently when it cannot run is worse than no guard, because the
green tick is read as an answer.** This file is the standing inventory that
makes every remaining skip visible, so the third instance is caught by reading
one document rather than by an incident.

A skip for a genuinely platform-specific case is fine and stays. It just has to
be listed here.

## Method

The **"skips here"** column is **measured, not reasoned**: `go test -count=1 -v
./...` was run on the Windows dev host and the `--- SKIP` lines were read out of
the output. The **"skips in CI"** column *is* reasoned, from the condition plus
`.github/workflows/ci.yml` (`runs-on: ubuntu-latest`, `go test -race -count=1
./...`, no Trivy install, no `ANVIL_TRIVY_E2E`, no acquired licence bodies —
CI is always a fresh clone). Where the reasoning does not settle it, the column
says so rather than guessing.

- Host measured: `go1.26.5 windows/amd64`, Windows 11, non-elevated,
  Developer Mode **off**.
- Suite state after the changes below: `gofmt` clean, `go vet` clean,
  `go build ./...` clean, `go test -count=1 ./...` **green** (17 packages).
- Sites before: **19**. Sites after: **12**. Seven skip sites removed.

---

# HAZARDS

Seven of the nine hazards were closed by an edit to a `_test.go` file. Two are
recorded as needing a change outside the test tree; they are listed at the end
of this section.

## H1 — `TestSymlinkedCacheRootIntoTheQuarantineIsRefused` (incident 1)

| | |
|---|---|
| **File** | `internal/mirror/accelerator/accelerator_test.go:1141` (before the fix) |
| **Trigger** | `os.Symlink` returned an error **and** `runtime.GOOS == "windows"` |
| **Skipped here?** | **YES — measured.** All 4 subtests (`direct`, `tier root`, `case varied`, `trailing dot`) skipped on every run |
| **Skips in CI?** | No. `os.Symlink` works unprivileged on `ubuntu-latest` |
| **Property unverified** | A `.cache` directory that passes every path-string check but *resolves* into `mirror/tier2` must be refused |
| **Security control?** | **YES.** The share-alike licence quarantine — the guard that keeps foreign, differently-licensed data out of tier 2 |
| **Verdict** | **HAZARD** |

The platform *can* express the case; the test simply used the one link
primitive Windows restricts. Windows has two directory reparse points and only
`mklink /D` needs a privilege — `mklink /J` needs none, which makes the
junction the link an *ordinary* user (or a careless build script) can actually
create. Testing only the privileged kind left the unprivileged kind unchecked.

**Change made.** `linkInto` now creates the strongest link the host permits —
symlink first, junction via `cmd /c mklink /J` as the Windows fallback — and
**never skips**. A host that can create neither now fails, because "the bypass
is impossible here" is a claim that must be proven rather than assumed.

**What running it proved.** On first run the un-skipped test **failed on all
four spellings**: `a .cache junction into mirror\tier2\ubuntu was accepted:
<nil>`. The defect was live at that moment, not merely historical. It has since
been fixed outside the test tree — see *Concurrent non-test change* below — and
the test now passes on this host, exercising the junction path.

## H2 — quarantine-fixture setup failure reported as a skip

| | |
|---|---|
| **File** | `internal/mirror/accelerator/accelerator_test.go:1132` (before the fix) |
| **Trigger** | `os.MkdirAll(quarantine)` returned an error |
| **Skipped here?** | **No — measured.** All four spellings created cleanly, including `mirror/tier2.` (Windows silently strips the trailing dot) |
| **Skips in CI?** | No |
| **Property unverified** | Whichever spelling failed to create — that subtest's whole assertion |
| **Security control?** | **YES.** Same control as H1 |
| **Verdict** | **HAZARD** (latent) |

This is the incident pattern in its purest form: the *test's own setup* failing
is reported as "nothing to check". It never fired, but it was one filesystem
change away from retiring a spelling of a security control with a green tick.

**Change made.** `t.Skipf` → `t.Fatalf`. A setup step that fails is a failure.

## H3 — the end-to-end Trivy scan skipped even when it was explicitly requested

| | |
|---|---|
| **File** | `internal/collector/repo/trivy_test.go:1006` (before the fix) |
| **Trigger** | `ResolveBinary("")` failed — checked **before** the opt-in env var |
| **Skipped here?** | **YES — measured.** Trivy is not installed |
| **Skips in CI?** | **Yes.** No CI step installs Trivy |
| **Property unverified** | That a real scanner run against a fixture repo with a known-vulnerable pinned dependency does not come back clean (`AssertNotSilentlyEmpty`) |
| **Security control?** | **YES.** Silent-clean is the classic scanner false negative |
| **Verdict** | **HAZARD** |

The ordering was the hazard. Two absences meant opposite things and were
treated identically:

- `ANVIL_TRIVY_E2E` unset → nobody asked for a real scan. Skipping is honest.
- `ANVIL_TRIVY_E2E=1` and no binary → somebody **did** ask, and the install step
  that was supposed to provide it did not. This skipped, so the run configured
  to exercise the control reported success without exercising it.

**Change made.** The opt-in gate is now consulted first. With the gate off the
test skips (and the message states plainly that no machine proves this control
today). With the gate on and no binary, it **fails**.

**Residual, needs a non-test change** — see N1.

## H4 — a catch-all skip over the "validated requires dynamic evidence" gate

| | |
|---|---|
| **File** | `internal/handoff/critique02_regression_test.go:485` (before the fix) |
| **Trigger** | `f.tryNewAudit(...)` returned **any** error |
| **Skipped here?** | **No — measured.** The schema admits every `dast_status` today |
| **Skips in CI?** | No — the condition is platform-independent and the schema is checked in |
| **Property unverified** | M5: a `requires_dynamic_confirmation` finding must not reach `validated` when no DAST reproduction can exist |
| **Security control?** | **YES.** It is the integrity gate behind "verified fixed" (`plan/00-SPINE.md` S7) |
| **Verdict** | **HAZARD** |

The sibling test `TestValidatedRequiresDynamicEvidence`
(`handoff_test.go:1895`) already narrowed its skip to the one known
schema-constraint gap. This probe did not: **any** fixture breakage retired M5
and the package still printed `ok`.

**Change made.** Narrowed to match the sibling — only a
`ck_audit_record_dast_status` constraint error skips; every other error is
`t.Fatalf`.

## H5 / H6 — a toolchain table's absence disables the invisible-character sweep

| | |
|---|---|
| **Files** | `internal/ingest/sanitize/sanitize_test.go:948`, `internal/ingest/invisible/invisible_test.go:570` (before the fix) |
| **Trigger** | `unicode.Properties["Other_Default_Ignorable_Code_Point"]` (and `["Variation_Selector"]`) is `nil` |
| **Skipped here?** | **No — measured.** `go1.26.5` ships both |
| **Skips in CI?** | No. CI resolves its toolchain from the same `go.mod` |
| **Property unverified** | H5: every default-ignorable code point is removed by `Sanitize` and rejected by `AssertSanitized`. H6: the 3,738 *reserved* default-ignorables are in the invisible class and do not split a licence marker |
| **Security control?** | **YES.** Invisible-character injection — a code point that renders as nothing but splits a share-alike marker, or smuggles text past the sanitizer |
| **Verdict** | **HAZARD** |

These are not platform facts. Every Go toolchain that has shipped
`unicode.Properties` has carried these tables; their absence means the toolchain
changed shape, and "the sweep could not be checked" is a reason to go red, not
a reason to pass. A toolchain bump would otherwise have retired both sweeps
silently.

**Change made.** Both `t.Skip` → `t.Fatal`, each naming this document. Neither
fires today, so the suite stays green.

## H7 — a dropped SARIF result turned a cap failure into a skip

| | |
|---|---|
| **File** | `internal/record/critique03_regression_test.go:318` (before the fix) |
| **Trigger** | `ProjectForGitHub` returned zero results for the case — **unconditionally**, for any subtest |
| **Skipped here?** | **YES — measured**, for `loc0_rel3000` only |
| **Skips in CI?** | Yes, same subtest. The condition is pure logic, platform-independent |
| **Property unverified** | That `locations` + `relatedLocations` respect `GitHubMaxLocationsPerResult`, and that the overflow is **counted** rather than silently truncated |
| **Security control?** | No — it is a reporting-integrity control (silent loss of findings on the way to GitHub) |
| **Verdict** | **HAZARD** |

The excuse was correct for `loc0_rel3000`: a result with no locations is dropped
by a *different* rule and never reaches the cap. But the skip was not scoped to
that case. The day `ProjectForGitHub` started dropping results it should have
kept, **every** subtest here would have turned green-by-skip and the truncation
ledger would have gone unchecked.

**Change made.** A dropped result is now tolerated only when `tc.locs == 0`;
for any other case it is `t.Fatalf`. Even in the excused case the drop must be
ledgered (`TotalDropped() != 0`) before the skip is allowed.

## H8 / H9 — a checked-in fixture's absence reported as a verified edge

| | |
|---|---|
| **File** | `internal/ingest/cache/cache_test.go:967` and `:970` (before the fix) |
| **Trigger** | `config.Load("../config/feeds.example.yaml")` failed; or the table declared no feeds |
| **Skipped here?** | **No — measured.** The file is checked in and parses |
| **Skips in CI?** | No |
| **Property unverified** | That `feed_state` accepts every `feed_id` the shipped config declares — the produce/consume edge between A.1 and A.2 |
| **Security control?** | **No** — a data-integrity contract between two packages |
| **Verdict** | **HAZARD** |

`feeds.example.yaml` is checked in at a fixed relative path. It is not an
optional artefact and not a platform fact, so a skip here reports "the edge was
verified" whenever the file moves, is renamed, or stops parsing.

**Change made.** Both → `t.Fatalf` / `t.Fatal`. `internal/ingest/config`'s own
tests already fail on an empty table; these now agree.

---

## Hazards that need a change outside the test tree

### N1 — no CI job runs the real Trivy scan

After H3, `TestRealTrivyScansAFixtureRepo` skips honestly on any machine that
did not ask for it. But **no machine asks**: `.github/workflows/ci.yml` neither
installs Trivy nor sets `ANVIL_TRIVY_E2E`, so the silent-clean control is
proven nowhere. Closing this needs a workflow step (install the pinned Trivy
release, warm the DB cache via A.11's accelerator, export `ANVIL_TRIVY_E2E=1`).
`.github/` is out of scope for this sweep, so it is reported, not changed.

### N2 — junction resolution in the write-path guard

The defect H1 exposed lives in `internal/mirror/accelerator/trivydb.go`
(non-test): `guardCacheRoot` resolved indirection with `filepath.EvalSymlinks`,
which does not follow a Windows junction. Fixing it required non-test source and
was therefore out of scope for this sweep. **It has since been fixed by a change
made outside this session** — see below — so no action remains.

---

## Concurrent non-test change (recorded for honesty, not claimed as this work)

While this sweep was running, `internal/mirror/accelerator/reparse.go` was
**created** (mtime `17:12:51`) and `trivydb.go` **modified** (mtime `17:13:34`)
by something other than this session. `guardCacheRoot` now calls a new
`resolveRealPath`, which resolves both kinds of Windows reparse point via
`os.Readlink` and `os.ModeIrregular` rather than relying on
`filepath.EvalSymlinks`. The new file documents the same defect independently,
as "blocker A-1".

Sequence, for the record:

| Time | Event |
|---|---|
| ~17:10 | H1's skip removed; test re-run; **fails on all four spellings** — junction accepted, `err == nil` |
| 17:12:51 | `reparse.go` created (not by this session) |
| 17:13:34 | `trivydb.go` modified (not by this session) |
| ~17:16 | Same test re-run; **passes**, exercising the junction path |

No non-test source was edited by this sweep. The test-side change stands on its
own merits: it is the permanent guard that keeps the junction case checked on
Windows, and it is what turns a regression in `resolveRealPath` back into a red
run instead of a skip.

---

# LEGITIMATE

These stay. Each is a case that genuinely cannot exist where it skips, and each
is covered elsewhere.

## L1 — `TestCollectAgainstTheRealHost`

| | |
|---|---|
| **File** | `internal/collector/host/collect_test.go:3967` |
| **Trigger** | `runtime.GOOS != "linux"` |
| **Skipped here?** | **YES — measured.** `no native package manager on windows` |
| **Skips in CI?** | No. `ubuntu-latest` is Linux |
| **Property unverified** | Real `dpkg-query`/`rpm`/`apk` enumeration against a live host |
| **Security control?** | No — a collector coverage claim |
| **Verdict** | **LEGITIMATE.** Windows has no dpkg/rpm/apk; the exec paths are fixture-driven throughout the rest of the file, and CI runs the real thing |

## L2 — `TestCollectAgainstTheRealHost`, inner guard

| | |
|---|---|
| **File** | `internal/collector/host/collect_test.go:3976` |
| **Trigger** | Linux, but none of `dpkg-query`/`rpm`/`apk` resolves |
| **Skipped here?** | No — unreachable on Windows (L1 returns first) |
| **Skips in CI?** | No. `ubuntu-latest` ships `dpkg-query` |
| **Property unverified** | As L1 |
| **Security control?** | No |
| **Verdict** | **LEGITIMATE.** A Linux host with no package manager genuinely has nothing to enumerate |

## L3 — `TestCollectRunsWithoutRoot`

| | |
|---|---|
| **File** | `internal/collector/host/collect_test.go:3462` |
| **Trigger** | `runtime.GOOS != "windows" && os.Geteuid() == 0` |
| **Skipped here?** | No — measured. `os.Geteuid()` is `-1` on Windows, so the condition is short-circuited |
| **Skips in CI?** | No. GitHub's `ubuntu-latest` runs as the non-root `runner` user. **Would** skip in a root container |
| **Property unverified** | Successful enumeration under a non-root UID |
| **Security control?** | Partly — the root-free-by-design claim |
| **Verdict** | **LEGITIMATE.** A uid-0 process cannot demonstrate a non-root run, and the skip message names `TestNothingBranchesOnBeingRoot`, which asserts the same design property unconditionally |

## L4 — `TestRealTrivyScansAFixtureRepo`, opt-in gate

| | |
|---|---|
| **File** | `internal/collector/repo/trivy_test.go:1020` |
| **Trigger** | `ANVIL_TRIVY_E2E` unset |
| **Skipped here?** | **YES — measured** |
| **Skips in CI?** | **Yes** — see N1 |
| **Property unverified** | The end-to-end real-scanner claim |
| **Security control?** | Yes, but this is the deliberate opt-in half |
| **Verdict** | **LEGITIMATE as a gate.** A real `trivy fs` needs a vulnerability database, which is a network acquisition that belongs to A.11's accelerator, not to a unit test. The *coverage gap* it leaves is tracked as N1 |

## L5 — `TestBothConsumersAgree`

| | |
|---|---|
| **File** | `internal/ingest/invisible/invisible_test.go:524` |
| **Trigger** | Unconditional `t.Skip` |
| **Skipped here?** | **YES — measured** |
| **Skips in CI?** | Yes, unconditionally |
| **Property unverified** | The **unrestricted** claim that `sanitize` and `license` drop exactly the same code points over the whole code space |
| **Security control?** | No — the claim is false *by design* |
| **Verdict** | **LEGITIMATE.** This is the opposite of a silent skip |

The skip message is a measured six-line report (959,049 code points, every one
in the same direction, with a breakdown and the span), the doc comment is a
45-line explanation of why the two consumers are *supposed* to differ outside
the invisible class, and it ends with "delete this line to see the failure".
The property that actually matters — both consumers honour the shared invisible
class — is held by `TestBothConsumersDropEveryMemberOfTheClass` and
`TestNoVisibleCodePointIsDroppedByEitherConsumer`, both green over their whole
domain. Nobody can cite a green run for the broad claim, which is exactly what
the skip is for.

## L6 — `TestFreshCloneAdmitsNoFeed`, per-feed

| | |
|---|---|
| **File** | `internal/ingest/license/gate_test.go:2049` |
| **Trigger** | That feed's licence body is acquired **and** pinned |
| **Skipped here?** | No — measured. Nothing is acquired in this tree |
| **Skips in CI?** | No. CI is a fresh clone |
| **Property unverified** | The fresh-clone refusal, for a feed that is no longer in the fresh-clone state |
| **Security control?** | Yes — but inapplicable by construction |
| **Verdict** | **LEGITIMATE.** Once an operator has acquired the text, this is not a fresh clone and the assertion is not about it. That state is covered by `TestPinnedLicenceBodiesMatchTheirPins` |

## L7 — `TestPinnedLicenceBodiesMatchTheirPins`

| | |
|---|---|
| **File** | `internal/ingest/license/gate_test.go:2119` |
| **Trigger** | `BodyState` is anything but `BodyVerified` or `BodyMismatch` — i.e. `BodyUnpinned` or `BodyMissing` |
| **Skipped here?** | **YES — measured.** All 11 feeds |
| **Skips in CI?** | **Yes**, all 11. CI is a fresh clone with no acquired bodies |
| **Property unverified** | That an acquired licence text matches its pinned sha256, carries a recognised obligation, and sits at the right tier |
| **Security control?** | Yes — licence-compliance integrity |
| **Verdict** | **LEGITIMATE.** There is genuinely nothing to verify, and the control itself is covered hermetically |

Two things make this safe rather than hazardous. `BodyMismatch` — the dangerous
state — is `t.Fatalf`, never skipped. And the state machine itself
(`BodyVerified` / `BodyMismatch` / `BodyUnpinned` / `BodyMissing`) is proven
against fixtures by `TestMirrorStatusExplainsEveryState` in
`manifest_test.go:160`, which runs everywhere. The skip message names the exact
missing artefact and the command that produces it.

## L8 — `requireGit`

| | |
|---|---|
| **File** | `internal/policy/semver_test.go:58` |
| **Trigger** | `git` not on `PATH` |
| **Skipped here?** | No — measured. `git` is present |
| **Skips in CI?** | No. `actions/checkout` requires `git` |
| **Property unverified** | O.7's tag-ordering behaviour |
| **Security control?** | No |
| **Verdict** | **LEGITIMATE.** O.7 is defined only in terms of real `git`; there is nothing to fall back to, and the condition cannot hold in CI |

## L9 — `TestExampleEPSSIsUndeclared`

| | |
|---|---|
| **File** | `internal/ingest/config/feeds_test.go:183` |
| **Trigger** | The example table carries no `epss` row |
| **Skipped here?** | No — measured. The row is present |
| **Skips in CI?** | No — same checked-in file |
| **Property unverified** | That EPSS is never described as open-licensed (`license_spdx` none, tier 3, not enabled) |
| **Security control?** | No — a licence-representation constraint |
| **Verdict** | **LEGITIMATE.** The example table is an *example*; a row it does not carry is a row with nothing to constrain. Worth revisiting if EPSS ever becomes mandatory in the shipped table |

## L10 — `TestValidatedRequiresDynamicEvidence`

| | |
|---|---|
| **File** | `internal/handoff/handoff_test.go:1895` |
| **Trigger** | The error names `ck_audit_record_dast_status` — the frozen `schema.sql` cannot hold a `dast_status` that `internal/record` has added |
| **Skipped here?** | No — measured. The schema admits every value today |
| **Skips in CI?** | No — platform-independent, and the schema is checked in |
| **Property unverified** | The `validated`-requires-evidence gate, for the one status the DDL cannot store |
| **Security control?** | Yes |
| **Verdict** | **LEGITIMATE.** The skip is narrow (one named constraint, not any error), the DDL gap is reported to the orchestrator, and the classification is asserted without a database by `TestHasDynamicEvidenceClassifiesEveryDastStatus`. H4 was the same test's *un-narrowed* twin |

## L11 — `TestXVM3RelatedLocationsAreCapped/loc0_rel3000`

| | |
|---|---|
| **File** | `internal/record/critique03_regression_test.go:336` (after the H7 fix) |
| **Trigger** | The projection dropped the result **and** the case declared zero locations **and** the drop was ledgered |
| **Skipped here?** | **YES — measured**, this subtest only |
| **Skips in CI?** | Yes, same subtest — the condition is pure logic |
| **Property unverified** | The location cap, for an input that never reaches the cap |
| **Security control?** | No |
| **Verdict** | **LEGITIMATE after H7.** GitHub requires a physical location, so a result with an empty `locations` array is dropped by a different rule and cannot exercise the cap. The cap itself is proven by the other four subtests, all passing, and the drop must now be ledgered before the skip is permitted |

---

## Summary

| | Count |
|---|---|
| `t.Skip` / `t.Skipf` / `t.SkipNow` sites before | 19 |
| Sites after | 12 |
| Hazards found | 9 |
| Hazards closed by a test-only change | 9 (7 sites removed, 2 narrowed) |
| Hazards needing a non-test change | 2 (N1 open, N2 closed elsewhere) |
| Legitimate skips, left in place | 11 |
| Skips that fire on the Windows dev host | 4 tests / 15 subtest lines |
| `t.SkipNow` sites | 0 |

Skips still firing on this host, all classified LEGITIMATE above:
`TestCollectAgainstTheRealHost` (L1), `TestRealTrivyScansAFixtureRepo` (L4),
`TestBothConsumersAgree` (L5), `TestPinnedLicenceBodiesMatchTheirPins` ×11
(L7), `TestXVM3RelatedLocationsAreCapped/loc0_rel3000` (L11).
