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

### N3 — CI had only a `-race` lane, so `!race` controls ran nowhere — **CLOSED**

`.github/workflows/ci.yml` ran `go test -race -count=1 ./...` and nothing else.
G4-1's harness is `//go:build !race`, so CI never compiled it and
`TestScopeBytesAreReadOnceUnderAConcurrentWriter` — the behavioural control
with the real numbers — existed in zero CI lanes.

**Change made.** Two steps added to the `go` job:

- `go test -count=1 ./...` with no `-race`, which is the only lane that
  compiles a `//go:build !race` file. Any future `!race` control gets this lane
  for free.
- An assertion that the named harness actually **ran and passed**, because
  `go test -run <pattern>` matching NOTHING exits 0 and prints
  `no tests to run` — which is exactly how this lane would rot if the file were
  renamed or the tag spread. The step greps for the `--- PASS:` line and for a
  `(cached)` replay, and fails the job on either.

**Both branches of the assertion were exercised before it was committed**, on
this host, against the real workflow fragment:

```
$ <the step, with the real pattern>
--- PASS: TestScopeBytesAreReadOnceUnderAConcurrentWriter (0.31s)
    entries and hash agreed on all 200 constructed Scopes (benign=88 evil=112 torn=0)
confirmed ... exit=0

$ <the step, pattern renamed so it matches nothing>
testing: warning: no tests to run
ok  ... [no tests to run]
::error::TestScopeBytesAreReadOnceUnderAConcurrentWriter did not run.
exit=1

$ <the step, with an assertion inside the harness mutated to fail>
--- FAIL: TestScopeBytesAreReadOnceUnderAConcurrentWriter (0.33s)
::error::the !race concurrency harness FAILED
exit=1
```

The mutation was reverted and the file re-hashed to confirm a byte-for-byte
restore (`sha256 8e17068...0dd1` before and after).

That `-race` genuinely does not compile the file was confirmed the same way:
`go test -race -count=1 -v -run TestScopeBytesAreReadOnceUnderAConcurrentWriter
./internal/dast/authz/` reports `[no tests to run]`.

### N4 — every CI job was `ubuntu-latest`, so the containment platform refusal ran nowhere — **CLOSED**

`SystemCommander` refuses on any non-Linux GOOS, and that refusal is what stops
Anvil reporting a sandbox as contained on a platform where it cannot check
anything — the claim that authorizes firing DAST probes at all. Its only guard,
`TestSystemCommanderRefusesOffLinux`, branches on `runtime.GOOS`: on Linux it
asserts a `Commander` comes back, off Linux it asserts a refusal. All five CI
jobs ran on `ubuntu-latest`, so only the Linux branch was ever taken and
deleting the `runtime.GOOS != "linux"` check would have left every lane green.

**Change made.** A `containment-non-linux` job on `windows-latest` running
`internal/dast/containment` with `-count=1`, plus a step asserting the named
test actually ran and passed (a `-run` pattern matching nothing exits 0 and
prints `no tests to run`, which is how this lane would rot) and a `(cached)`
check, plus a negative control that deletes the platform check, requires the
guard to go RED **for the right reason**, restores the file with
`git checkout --` and requires `git diff --exit-code` to be clean.

No `-race` in this lane: the detector needs a gcc toolchain on Windows and the
`ubuntu-latest` job already runs the whole tree under it.

**The negative control was exercised on this host before it was committed**,
from Git Bash, against the real mutation the step applies:

```
$ sed -i 's/if runtime.GOOS != "linux" {/if false {/' internal/dast/containment/netns.go
$ go test -count=1 -run TestSystemCommanderRefusesOffLinux ./internal/dast/containment/
exit=1
--- FAIL: TestSystemCommanderRefusesOffLinux (0.00s)
    netns_test.go:173: on windows SystemCommander returned a Commander. A containment
    layer that reports success on a platform with no network namespaces is the
    silent-clean failure this package exists to prevent
```

which is the string the step greps for. The file was restored and re-hashed to
confirm a byte-for-byte revert (sha256
`57725537B7B0FEA878F59B5A29D9F0CBCFA277E3B23EBE90A124408ADC03F726` before and
after).

**What this lane does NOT do:** it does not prove anything about a kernel. The
Linux branch of that same test still asserts only that a `Commander` comes
back. U1 remains open.

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

# CONTROLS WITH NOTHING BEHIND THEM

A `t.Skip` is one way a green run gets read as an answer. Here is the other: a
gate that is fully written, fully tested on its refusal paths, and has **no
implementation of the thing it is a rule about**. The package prints `ok`, the
refusals are all real, and the control is still unproven end to end.

These are listed here rather than in a separate file because the failure mode
is identical to the one this document exists for, and because a reviewer
looking for "what does the green tick not cover" should find one document.

## G19-1 — gate 19 has no disclosure store

| | |
|---|---|
| **File** | `internal/dast/authz/phase4_disclosure.go`, the `DisclosureStore` interface and `persistDisclosureState` |
| **Trigger** | Not conditional. There is no production implementation of `DisclosureStore` in this repository |
| **Skipped here?** | No — nothing skips. Every gate-19 test passes |
| **Skips in CI?** | No |
| **Property unverified** | That a finding's disclosure state — the 45-day embargo clock — actually survives a process restart, because it was written to the SQLite store of record rather than the tmpfs handoff packet |
| **Security control?** | **YES.** Gate 19 is what makes gate 18's embargo a durable fact. `plan/00-SPINE.md` S1 is explicit that the handoff buffer's "8 hours" is a claim timeout, not a deletion policy, and tmpfs does not survive a reboot at all. An embargo that forgets itself is an embargo that publishes |
| **Verdict** | **UNPROVEN CONTROL** |

**What is proven.** Every refusal: a nil store, a store declaring
`tmpfs_handoff_buffer`, `process_memory`, the empty medium or any unrecognised
one, an unconstructed `DisclosureRecord`, a write that errors, a write that
returns sequence 0, a store that assigns a row id and then fails to commit, and
a store that answers the medium question twice with two different answers. Also
proven structurally: `DisclosureRecord` has no exported field, so
`json.Marshal` of a fully populated one produces `{}` and a handoff-packet
builder that embeds one serialises no disclosure state.

**What is not.** The **allow**. `PersistedDisclosure` — the proof gate 18
demands before it will permit publication — has only ever been minted against a
test fake. `grep -rn PutDisclosureState` over the repository returns the
interface declaration, its one call site, and three fakes in
`phase4_disclosure_test.go`. Nothing writes a disclosure row to SQLite, so
today disclosure state lives **nowhere**, and the sentence gate 19 enforces —
"it lives in the DB, not the buffer" — has no positive instance.

**The false attribution that used to stand here.** The doc comment on
`DisclosureStore` read "D.9/D.10 implement it over the SQLite record store".
That is not what those steps are. `plan/50-dast.md:317-348` makes D.9 the
build-invariant packet — a dependency-graph test and an egress lint — and
`:349-378` makes D.10 container provisioning under gVisor `runsc`. Neither
writes a disclosure row, and no other step in the plan schedules one. The
attribution has been deleted and replaced with a plain statement of the gap.

**What would settle it.** A plan step that owns a `disclosure_state` table in
`internal/record` (area 40 owns every shared enum per
`plan/IMPLEMENTATION-PLAN.md` section 6, so the `DisclosureState` literals
currently declared in `phase4_disclosure.go` should move there and be aliased),
an implementation of `DisclosureStore` over `internal/store`, and one
integration test that: opens an embargo, persists it, **closes and reopens the
database handle**, reads the row back, and asserts the deadline survived. The
reopen is the whole test — a store that keeps the row in a map passes every
assertion that does not close the handle.

**Scope note.** Writing that store was outside this packet's write scope
(`internal/dast/authz/phase4_disclosure.go` and its test). Inventing one would
have produced exactly the thing this document is against: an implementation
nobody scheduled, proving a control nobody asked it to prove.

**Update — the interface grew a READ, and this entry grew with it.**
`DisclosureStore` now also declares
`DisclosureStateFor(FindingID) (DisclosureState, error)`. It was added because
a write-only store cannot back a state machine: gate 18's `withheld` check read
only the `PersistedDisclosure` its caller handed it, so persisting `withheld`
and then persisting `embargoed` for the same finding produced a second valid
proof and the publication proceeded. Gate 18 now asks the store, and gate 19
refuses a write that leaves `withheld` without an allowlisted release reason
and evidence.

This does not shrink the gap above and in one respect widens it: there is now a
second method with **no production implementation**, and the integration test
this entry asks for must now also cover the read — open an embargo, persist
`withheld`, **close and reopen the database handle**, and assert
`DisclosureStateFor` still answers `withheld`. A store that answers from an
in-memory map passes every assertion that does not close the handle, and a
store that forgets across a restart turns the new refusal into a silent allow.
Still no store was written here, for the reason above.

## G4-1 — the concurrent-writer harness cannot run in the `-race` lane

| | |
|---|---|
| **File** | `internal/dast/authz/phase1_scopebytes_race_test.go` (whole file, `//go:build !race`) |
| **Trigger** | The `race` build tag. Under `go test -race` the file is not compiled |
| **Skipped here?** | Not a `t.Skip`. It is a build-tag exclusion, which is why it is listed: the effect on a `-race`-only CI lane is identical |
| **Skips in CI?** | **No, as of the N3 fix.** `.github/workflows/ci.yml` now runs a second, non-`-race` step, and a third step that fails the job unless this exact test reports `--- PASS:`. It ran in zero CI lanes before that |
| **Property unverified in the `-race` lane** | That a `Scope` built while a concurrent writer rewrites the caller's buffer carries one document's entries under **that** document's hash |
| **Security control?** | **YES.** It is gate 5's scope binding: "editing the scope file invalidates the attestation" is only true while the hash is a hash of the entries |
| **Verdict** | **LEGITIMATE EXCLUSION, CI GAP NOW CLOSED** — see N3 |

**Why it cannot be a `-race` test, measured rather than asserted.** The harness
works by racing a writer against the caller's buffer. That is not incidental to
it: a concurrent write is the only thing that can make one read of the buffer
differ from another, so there is no race-free Go program that can distinguish a
build which reads the buffer once from a build which reads it twice. The
harness is therefore a data race **by construction**, and the race detector
reports it against the *fix* on a correct tree. Measured by deleting the build
tag on the shipped tree and running
`go test -race -count=1 -run TestScopeBytesAreReadOnceUnderAConcurrentWriter`:

```
WARNING: DATA RACE
Write at 0x00c00020c000 by goroutine 10:
  runtime.slicecopy()
      C:/Program Files/Go/src/runtime/slice.go:392 +0x0
  ...authz.TestScopeBytesAreReadOnceUnderAConcurrentWriter.func1()
      .../internal/dast/authz/phase1_scopebytes_race_test.go:120 +0x106

Previous read at 0x00c00020c000 by goroutine 9:
  runtime.slicecopy()
      C:/Program Files/Go/src/runtime/slice.go:392 +0x0
  ...authz.CheckGate4ScopeFile()
      .../internal/dast/authz/phase1_run.go:559 +0x2db
  ...authz.NewScope()
      .../internal/dast/authz/types.go:859 +0xd0
```

`phase1_run.go:559` is `raw = append([]byte(nil), raw...)` — the one-read copy
that is the fix. The race the detector reports is a write racing THE FIX. A
test that goes red on a correct tree measures nothing.

**What the exclusion is NOT.** It is not the previous round's claim that
"`go test -race` cannot build here". That claim was false and has been deleted
from the tree: `go test -race -count=1 ./...` is green across all 26 test-
bearing packages on this host. (It fails only inside one sandboxed shell, with
`ThreadSanitizer failed to allocate ... (error code: 87)`, which is a shadow-
memory mapping refusal in that shell, not a toolchain fact.)

**What still holds the property in every lane.**
`TestGate4ReadsTheCallersScopeBytesExactlyOnce` parses `phase1_run.go` and
asserts the source-level shape — the parameter is rebound to a copy of itself
before any use other than `len` — with five positive controls and one negative
control. It starts no goroutines and runs under `-race`.

**Measured numbers for the excluded harness**, 200 constructed `Scope`s per run:

| tree | mismatched |
|---|---|
| shipped | **0** of 200 |
| copy deleted | 89 of 200 |
| copy replaced by `rawAlias := raw[:]` | 102 of 200 |

The third row is the mutation that defeated the *earlier*, denylist-shaped
version of the source-level pin while the whole repository suite stayed green.
Both guards catch it now.

## G18-2 — two run initiations with divergent clocks

| | |
|---|---|
| **File** | `internal/dast/authz/phase4_disclosure.go`, the gate 18 embargo comparisons; `internal/dast/authz/types.go`, `RunClock` |
| **Trigger** | Not conditional. It is a residual of having no trusted time source |
| **Skipped here?** | No — nothing skips. Every gate-18 test passes |
| **Skips in CI?** | No |
| **Property unverified** | That the instant a run says it is happening at is the instant it is actually happening at |
| **Security control?** | **YES.** The 45-day CERT/CC embargo |
| **Verdict** | **UNPROVEN RESIDUAL, NOT BOUNDED BY ANYTHING IN THIS REPOSITORY** |

**What is closed.** A run has exactly one clock. `RunClock` is sealed by an
unexported constructor and the only exported route to one is
`RunInitiation.RunClock`, so every Phase 4 decision reads the run's instant
instead of accepting a "now": `PublicationRequest` and `PushRequest` have no
clock field, and `GateAudit` carries the run's. The consistently-told lie —
contact dated 3 January against a 3 January "now" (a back-date of zero, so
`MaxVendorContactBackdate` never engaged), embargo opened at the same January
clock, publication at the real August present, every gate green — is no longer
spellable in one run.
`TestGate18TheConsistentClockLieIsRefusedInBothDirections` runs both halves.

Note what that sentence does and does not say. The caller still CHOOSES the
run's instant: `RunRequest.Clock` is an exported, settable field and
`InitiateRun` copies it verbatim into the seal. What the seal removes is the
ability to supply a DIFFERENT instant to each decision. A previous version of
this entry, and of the file header, said "a run has exactly one clock, and it
is not a parameter". The second half was not true and has been deleted rather
than qualified.

**What is not closed.** A run's clock is still the instant the operator's
harness handed `InitiateRun`. `plan/00-SPINE.md` S7 makes the kernel a pure
function of `(target, scope, attestation, clock)`, so this package reads no
ambient time and cannot. An operator who initiates **two** runs — one claiming
January, one claiming August — can still assemble the sequence across them.

### THE COST THIS ENTRY USED TO CLAIM, AND WHY IT WAS DELETED

The previous version said the attack costs "two attestations that are live at
instants seven months apart", implying the attacker must obtain something. It
implied a price that is not charged, and it was the justification for ACCEPTING
this residual rather than closing it, so it had to be either true or gone. It
is gone. Both halves were checked:

**Half one — "two attestations" is not a cost, because an attestation is
unsigned text the attacker writes.** An attestation reaches this kernel as
bytes and is parsed; nothing verifies an issuer. Measured, over every non-test
`.go` file in the repository:

```
$ grep -rniE "ed25519|ecdsa|crypto/rsa|crypto/x509|\bjws\b|\bjwt\b|cosign|sigstore|minisign|gpg|openpgp" --include=*.go . | grep -v _test.go
./internal/collector/host/rpm.go:58:            // gpg-pubkey pseudo-packages carry no architecture...
./internal/dast/authz/phase2_admission.go:1854:            if !securityTxtURIOK(value, []string{"https:", "dns:", "openpgp4fpr:"}) {
./internal/mirror/accelerator/trivydb.go:102:// ... No cosign/sigstore verification is performed ...
./internal/mirror/accelerator/trivydb.go:898:  "whoever answered that request chose the digest. No signature (cosign/sigstore) was checked, "
./internal/record/mask.go:111:// NO SHAPE-BASED BODY SCANNING. There is no "looks like a JWT" ...
```

Four of the five hits are a Red Hat pseudo-package name, a URI-scheme
allowlist, and two comments that say in so many words that no signature is
checked. **There is no cryptographic verification anywhere in this repository.**
Writing a second attestation file with different dates costs the operator one
text editor. Gate 5's 30-day ceiling bounds the DISTANCE between an
attestation's own two dates; it does not make an attestation hard to produce.

**Half two — "the divergence is visible in the audit log" is not true of the
log this code writes.** The two runs leave one gate-19 allow and one gate-18
allow. A `GateRecord` carries `Gate`, `Outcome`, `Reason`, `Detail`,
`AttestationID`, `ScopeHash`, `Mode`, `Target` and `At`, and for an ALLOW the
`Detail` is the literal string `"<gate> permitted this decision"` — no first
contact, no deadline, no adjustment count. Two allows against a finding, at two
attestation IDs, are byte-for-byte what honest coordinated disclosure across a
long embargo also looks like. Nothing joins the two rows, and nothing compares
either `At` against anything outside the run that supplied it. A reviewer
cannot see the lie in that log because the lie is not in it.

There is a further reason not to lean on the log at all: **no production
`AuditSink` exists in this tree.** `grep -rn WriteGateDecision --include=*.go`
outside tests returns the interface declaration and its two call sites and
nothing else, exactly as G19-1 records for `DisclosureStore`. A bound that
rests on a log nobody writes is not a bound.

### WHAT ACTUALLY REMAINS TRUE

Only this, and it is a property of the kernel rather than a price the attacker
pays: **within one run the lie cannot be told inconsistently.** The attacker
must produce two coherent runs, each internally consistent, rather than one run
with three different answers to "what time is it". That is a real narrowing of
the attack surface and it is why the seal was worth adding. It is not a bound
on the attack, and this entry no longer says it is.

**So: the residual is UNBOUNDED by anything in this repository**, and it is
accepted for one reason — the kernel is a pure function of its inputs by S7, so
the fix cannot live in this package. It has to live in what an attestation IS.

**What would bound it,** each of which is a change to gate 5's file and another
packet's scope:

1. **A signature on the attestation** over its own `not_before`/`expires`, with
   the verifying key configured out of band. This is the one that turns "the
   attacker writes a second attestation" back into a cost. Nothing in this
   repository verifies a signature today, so it is a new dependency and a new
   key-management story, not a one-line change.
2. **A monotonic counter in the SQLite store of record** that run initiation
   must advance, so two runs cannot both claim to be the earlier one. This
   catches the January/August ordering without any cryptography, and it is the
   cheapest of the three — but it needs the store G19-1 says does not exist.
3. **An RFC 3161 timestamp token** on the attestation, which is (1) with the
   trust anchor outside the operator entirely.

**What would make the log worth citing,** independent of the above: put the
first-contact instant, the deadline and the adjustment count on the gate-18
allow row's `Detail`, so that two allows for one finding at inconsistent
deadlines are distinguishable from one honest disclosure. That is a change to
`GateAudit.Record`'s allow-row construction and is worth doing regardless of
which of the three lands, because it costs nothing and today the allow row
records only that a gate said yes.
## U1 — DAST network containment (D.11) has never run against a kernel

| | |
|---|---|
| **File** | `internal/dast/containment/netns.go`, `internal/dast/containment/netns_test.go` |
| **`t.Skip` sites** | **Zero.** Every test in the package runs and asserts on every platform. This entry is here because a green package is still not a proven control |
| **Skipped here?** | N/A — nothing skips. What is missing is not a test, it is a kernel |
| **Skips in CI?** | N/A — same |
| **Property unverified** | That `nft` installs the generated ruleset; that a Linux kernel actually drops a packet addressed to `169.254.169.254` / `fd00:ec2::254` from inside the namespace; that the `ConnectProbe` implementation (owned by the anvil-dast binary, D.14/D.15 — it does not exist yet) turns a real dropped connect into the `DialFailure` this package's classifier expects; that `ip netns exec` places the canary where `ReadNetnsInode` stat'd |
| **Security control?** | **Yes, and it is the one that authorizes probing at all.** "The sandbox is contained" is the claim that lets Anvil fire a DAST probe. A containment layer that reported contained-when-unverified is the failure that gets someone breached |
| **Verdict** | **OPEN. Not legitimate, not accepted — unexecuted.** |

### What the suite does prove, on Windows and on Linux alike

The package is split so that everything except the `exec` is a pure function,
and all of it is tested:

- `BuildRuleset` is pure. A golden test pins the entire generated `nft` script,
  and `TestMetadataDropsPrecedeEveryAcceptRule` pins the *order* — nftables
  evaluates top to bottom, so a suite that only asserted "the drop is present"
  and "the accept is present" would pass on a ruleset with them the wrong way
  round, which is a ruleset where the metadata endpoint is reachable.
- `TestDenySetIsNeverWeakerThanGateTenAtSixteenBitGranularity` sweeps 393,264
  addresses (measured, after the D.12 fix round) and asserts
  `authz.AddressIsReserved(a) ⇒ DeniedByRuleset(a)`. 36,112 of them are
  reserved, so the implication is not vacuous, and the test fails if that count
  reaches zero. The generator now also emits ZONED and IPv4-MAPPED spellings;
  before it did, it could not construct the input that broke the relation, and
  it swept 393,226 addresses green while `DeniedByRuleset` returned false for
  every zoned address.
- `EvaluateCanaryReport` is pure, and every branch of it is exercised:
  reachable, missing probe, duplicate probe, absent outcome, unrecognised
  outcome, indeterminate outcome, wrong namespace, the *host* namespace,
  unrequested extras, an empty probe list, an outcome that disagrees with the
  reported `DialFailure`, and a silent timeout that did not wait out its
  declared bound.
- `TestABrokenRulesetFixtureIsCaughtOnEveryOneOfTwentyRuns` is the SECOND HALF
  of D.11's stop condition and only the second half: 20 runs against a canary
  reporting `reachable` (the empty-ruleset fixture, research 19 risk #5's
  shape), 20 aborts; then 20 runs against a correctly blocked report, 20
  passes, so the first half is not passing because the function refuses
  everything. **The stop condition's FIRST clause — "Default-deny ruleset
  installs correctly on a real target fixture" — is NOT met and cannot be met
  on this host**: nothing here installs a ruleset anywhere, and item (1) below
  is what would settle it. This entry previously claimed the whole stop
  condition was met, which is how a gap ships.
- `SystemCommander` **refuses** on any non-Linux GOOS and
  `TestSystemCommanderRefusesOffLinux` asserts that refusal on this host. There
  is no no-op Commander, so there is no path by which Windows returns "contained".
  **That guard now runs in a CI lane**: `containment-non-linux` in
  `.github/workflows/ci.yml` runs the package on `windows-latest`, asserts the
  named test actually executed and passed, then DELETES the
  `runtime.GOOS != "linux"` check, requires the guard to go red naming the
  returned Commander, and restores the file. Until that lane existed, all five
  CI jobs were `ubuntu-latest`, only the Linux branch was ever taken, and
  deleting the refusal would have left every lane green.

### What it does not prove, and exactly what would settle it

Everything above is a statement about Anvil's decision logic. None of it is a
statement about a kernel. Windows has no network namespaces and no nftables;
WSL2 is present on the dev host and is **not** the target runtime, so it does
not settle this either.

What would settle it, in order of decreasing cost:

1. **A privileged Linux CI lane.** `runs-on: ubuntu-latest` with
   `nftables` and `iproute2` installed and the job running as root (or with
   `CAP_NET_ADMIN` + `CAP_SYS_ADMIN`). The lane creates a namespace, calls
   `SetupNetns`, then calls `AssertContainment` and requires it to pass — and
   then, as the negative control the house style requires, flushes the table
   (`ip netns exec <ns> nft flush ruleset`) and requires `AssertContainment` to
   **fail**. Without that second half the lane proves nothing: a lane where the
   probe cannot fail is not a check. **This is the one that closes the entry.**
2. **The errno half alone**, cheaper and partial: on any Linux runner, without
   privileges, dial a blackholed address and record which errno a real
   `connect` delivers, to confirm the `ConnectProbe` implementation's errno
   table maps it to `DialFailureSilentTimeout` / `DialFailureNoRoute` rather
   than to `DialFailureUnclassified`. **This one cannot run until the
   implementation exists**: gate 3 forbids a socket inside `internal/dast`, so
   `internal/dast/containment` ships the interface, the classification rules
   and the verdict, and nothing that can connect.
3. **A `docker run --network none` smoke test**, cheapest and weakest: proves a
   canary in a namespace with no route reports `blocked`, which exercises the
   plumbing but not the nftables ruleset, because there is nothing to filter.

### The open dependency

`AssertContainment` execs the canary through `Commander` (os/exec, which gate 3
treats as inert and whose justification line already names D.11). The canary
itself is `CanaryMain`, which lives here — but the `ConnectProbe` it needs is
**not implemented anywhere in the tree**, because gate 3 refuses a socket
inside `internal/dast` and there is no allowlist for it. The implementation
belongs to the anvil-dast binary and will be flagged by gate 3's tier 2, which
means it must be added to `nonKernelEgressAllowlist` in `phase0_build.go` with
a written justification. That edit is the review gate 3 exists to force and it
is deliberately not made here.

**Until that lands, D.11 is a specification plus a verdict, not a running
probe.** `AssertContainment` fails closed in the meantime — a canary that
cannot run is refused, not waved through — so the failure direction is safe,
but no scan can pass the containment gate at all yet.

Until (1) exists, **`internal/dast/containment` is a control that runs in zero
CI lanes against a kernel**, and this entry is the standing record of that.
`AssertContainment` must not be wired into a scan path that treats its absence
as success; it returns an error on every platform where it cannot check.

### U1a — the canary proves the `output` path; the `forward` path is proved only on paper

Opened by the D.12 critic's finding that the generated ruleset hooked `output`
only, which does not see forwarded traffic. The ruleset now installs the
identical rule list into an `egress` chain at `output` and an `egress_forward`
chain at `forward`, because a Compose project on a bridge inside the namespace
has its egress FORWARDED, not output — and `provision.go`'s own `NetworkMode`
assertion requires exactly that bridge arrangement.

**The asymmetry that remains, stated because it is easy to miss.** The canary
runs under `ip netns exec`, so it is a process holding a socket IN the
namespace and its dials traverse the `output` hook. It therefore exercises the
`output` chain and **not** the `forward` chain. So even on the privileged Linux
lane item (1) describes, a passing canary would be evidence about the path the
TARGET DOES NOT USE.

**What would settle it:** the same privileged lane, with the canary run from
inside a container attached to a bridge in the namespace rather than by `ip
netns exec` — so that its packets are forwarded, exactly as the target's are.
Cheaper and partial: on that lane, `nft list ruleset` inside the namespace,
asserting both chains are present with the same rules and both at `policy
drop`. That is a configuration check and marking your own homework, which is
why it is the partial one.

Today the forward chain is pinned by
`TestTheRulesetHooksForwardAndNotOnlyOutput` and
`TestEveryHookedChainCarriesTheIdenticalRuleList`, which parse the emitted
script back with a reader separate from the writer. Both are statements about
the text, not about a kernel.

### U1b — the canary's timing evidence is self-reported

The verdict `DialFailureSilentTimeout ⇒ blocked` is only sound if the probe
waited out `DefaultCanaryDialTimeout`; nothing enforced or observed that, and
the report carried no timing at all, so a `ConnectProbe` built with a 50ms
dialer would have turned every silent timeout into "blocked" and the whole
assertion into a green function that could not fail. `Attempt` now carries
`elapsed_ms` (measured by `RunCanary` around the call it does not control) and
the raw `failure`, and `EvaluateCanaryReport` refuses a silent timeout below
1,900 ms (measured floor: `DefaultCanaryDialTimeout` 2s minus a 100 ms
tolerance) and any outcome that disagrees with `ClassifyDialFailure` of the
reported reason.

**What that does NOT buy:** the canary is the untrusted half. A substituted or
malicious binary can write any number it likes, and this package cannot
authenticate it. What the check buys is that the ORDINARY way this control
rots — an honest `ConnectProbe` with a dialer shorter than the declared bound
— now fails loudly. **What would settle the rest:** the same privileged lane,
comparing the reported `elapsed_ms` against the lane's own wall clock, plus the
errno measurement item (2) already names.

### U1c — the two halves of this package do not compose, and nothing calls either

**Recorded here so it cannot be forgotten. It is NOT this package's to fix.**

`Provision` seals a `Target` with `booted_clean` without any network namespace
being involved: it never calls `SetupNetns` and never calls
`AssertContainment`. A repository-wide grep finds no caller of `Provision`,
`SetupNetns` or `AssertContainment` anywhere outside this package's own tests.
So today a target can be provisioned, sealed and recorded `booted_clean` with
no egress containment installed and no containment assertion run.

The failure direction is currently safe only because nothing runs any of it.
The moment a scan path calls `Provision` and fires probes, `booted_clean` would
mean "the container is contained by gVisor" and would NOT mean "its egress is
default-deny and the metadata endpoint is unreachable" — which is what a
reader of that value will assume.

**Whose it is:** the integration packet (D.31) plus the scan path, not D.10 or
D.11. **What would settle it:** a wiring point that (a) builds the `Netns`,
(b) calls `SetupNetns`, (c) calls `AssertContainment` and refuses on error,
BEFORE any probe engine starts, and a test asserting that ordering by call log
— D.12's verdict criterion is explicit that `AssertContainment` must run
before the probe engines fire, and today there is nothing to assert that
against.

## U2 — DAST target provisioning (D.10) has never run against a Docker daemon

| | |
|---|---|
| **File** | `internal/dast/containment/provision.go`, `internal/dast/containment/provision_test.go` |
| **`t.Skip` sites** | **Zero.** `TestThisPackageSkipsNothing` reads the test file and fails if one appears. This entry is here because a green package is still not a proven control |
| **Skipped here?** | N/A — nothing skips. What is missing is not a test, it is a container engine |
| **Skips in CI?** | N/A — same |
| **Property unverified** | That a real implementation of the `Docker` seam produces the shapes this package decides on. Specifically: that `docker compose up` applies `UpRequest.Runtime` to **every** service; that a real container's `HostConfig.Runtime` reads `runsc`; that a real `docker info` can report the gVisor **platform** at all; that a real runner can tell a build failure from a start failure from a health timeout; and that `ProbeHealth` issues its probe from the probe engine's namespace rather than from inside the target |
| **Security control?** | **Yes.** "The target ran under gVisor with no host bind mounts" is the claim that makes firing probes at it acceptable, and `booted_clean` is the value that lets the record read as a real scan |
| **Verdict** | **OPEN. Not legitimate, not accepted — unexecuted.** |

**Docker is not installed on the host this packet was written on.** Measured,
not assumed: `Get-Command docker` and `Get-Command runsc` both return nothing
on `go1.26.5 windows/amd64`, Windows 11.

**Nothing in the tree implements the `Docker` interface.** A repository-wide
grep for `ComposeUp` and `EngineInfo(` finds the interface, its call sites in
`provision.go`, and the test fake — no production implementation. So the seam's
contract (written out in the `Docker` doc comment as five numbered obligations)
is today enforced by nobody.

### What the suite does prove, on Windows and on Linux alike

Everything except the engine call is a pure function of a recorded shape, and
all of it is tested — 112 passing assertions, 0 skips, clean under `go test
-race` from PowerShell:

- `Stage.Provenance()` is total over all 14 stages, and
  `TestStageValuesCoversEveryDeclaredStage` reads `provision.go`'s own source
  so a stage added to the const block and left out of `StageValues()` is caught.
- `TestNoStageCanBeReadAsScannedClean` sweeps all 14 stages × all 5
  `HalfStatus` values through `record.DeriveDastStatus` and asserts none
  derives a status where `MeansDynamicallyScannedClean()` holds. That pins the
  *relation* S6 requires, not the literals.
- Each of the five `record.TargetProvenance` values has its own test, and the
  two failure families are separated by 6 + 16 recorded-shape cases.
- `containmentViolations` is pure. 21 cases break one guard each, with an
  unmutated control asserting the fixture reports zero violations — so a guard
  that rejected everything would not pass the suite.
- The gVisor runtime assertion is made against **every** container in the
  project, including exited ones and dependencies, and a broken-runtime
  dependency is one of the 16 boot-failure cases.

### What it does not prove, and exactly what would settle it

In order of decreasing cost:

1. **A Linux CI lane with Docker Engine and gVisor.** Install gVisor and
   register the runtime (`runsc install --runtime=runsc -- --platform=systrap`,
   then restart the daemon). Check in a throwaway Compose fixture with two
   services — `web` (with a `healthcheck:`) and `db` (without one) — and a real
   `Docker` implementation. The lane then asserts, **positively**:
   - `docker compose -p anvil-<hash> -f fixture.yaml up -d --wait
     --force-recreate --remove-orphans` succeeds;
   - `docker inspect --format '{{.HostConfig.Runtime}}' <web>` prints `runsc`,
     **and the same for `<db>`** — this is obligation 2 of the seam contract
     and is the one this package cannot check for itself;
   - `docker inspect --format '{{index .Config.Labels
     "com.docker.compose.service"}}' <web>` prints `web`;
   - `Provision` returns a `Target` with `Provenance() == booted_clean` and an
     `ImageDigest()` matching `^sha256:[0-9a-f]{64}$`.

   And **negatively**, without which the lane proves nothing:
   - the same fixture with `healthcheck:` deleted from `web` must refuse with
     `ErrNotHealthy` at `StageHealth` — this is the case where `up --wait`
     returns success instantly and the whole `HealthNone` zero-value trap
     exists to catch it;
   - the same lane with the `runsc` runtime unregistered must refuse with
     `ErrRunscUnavailable` at `StagePreflightRuntime` **and `docker compose up`
     must never appear in the daemon log**;
   - a fixture whose `web` service adds `volumes: ["/var/run/docker.sock:/var/run/docker.sock"]`
     must refuse at `StageContainment`.
   **This is the one that closes the entry.**
2. **The failure-classification half alone**, cheaper and partial: on any host
   with Docker and no gVisor, run three fixtures — one whose `build:` stage
   exits non-zero, one whose image is fine and whose `command:` is a nonexistent
   binary, and one whose healthcheck never passes — and record what a real
   `docker compose up --wait` returns for each. That is the only evidence that
   `UpStatusBuildFailed` / `UpStatusStartFailed` / `UpStatusHealthTimeout` are
   distinguishable in practice, and the build/boot provenance split depends on
   them being distinguishable.
3. **The platform half alone**, cheapest: on a host with gVisor, confirm that
   the engine exposes the configured `--platform` at all (via `docker info` or
   `/etc/docker/daemon.json` `runtimeArgs`). If it does not, `RuntimeInfo.Platform`
   can only ever be empty and this package refuses every provision — which is
   fail-closed and useless, and would need the check moved to `runsc --version`.

### U2a — the build budget and the health budget are two numbers no runner has ever honoured

Opened by the D.12 critic's finding that `health.timeout_seconds` was applied
as the total budget for build + pull + create + start + health, with the
DEADLINE checked ahead of the runner's own reported status — so a seam
answering `UpStatusBuildFailed` after the deadline was recorded `boot_failed`.
A slow image build is the ordinary case on a cold cache, and the two outcomes
send the operator to two different files.

Two things changed. `refuseAfterUp` now consults the runner's reported status
FIRST and lets the clock decide only when the runner named no phase at all (a
distinct `StageUpBudget` / `ErrUpBudgetExhausted`, whose message states that
which phase consumed the budget is UNKNOWN rather than guessing). And the
budgets are split: `UpRequest.BuildTimeout` carries `DefaultBuildBudget` (15
minutes) for build/pull/create/start, `UpRequest.Timeout` carries the declared
health timeout for the health wait alone, and the enforced context deadline is
their sum so a runner that ignores both cannot hang the call.

**Unproven, and this is the honest part.** `DefaultBuildBudget` is a POLICY
BOUND, chosen and not measured — no cold-cache build has been timed on this
host, because this host has no Docker. And nothing anywhere applies the two
budgets to the two phases: this package cannot, because the phase boundary is
inside `docker compose up`, and no implementation of the seam exists. The split
is today a contract written in the `Docker` interface doc and enforced by
nobody.

**What would settle it:** the Linux+Docker lane in item (1), with a fixture
whose `build:` stage sleeps past `DefaultBuildBudget` and a separate fixture
whose healthcheck never passes, asserting that the first refuses at
`StageBuild` and the second at `StageHealth` — and, for the budget split
specifically, that the first fixture is NOT cut off at
`health.timeout_seconds`. Item (2) already collects the raw material for the
first half.

Until (1) exists, **`Provision` is a control that runs in zero CI lanes against
a container engine**, and this entry is the standing record of that. No caller
may treat a `*ProvisionError` as advisory: it is the only thing standing
between an unprovable boot and a record that says `booted_clean`.

---

## U3 — DAST target reset (D.13) has never destroyed a real container, and cannot replay a seed at all

| | |
|---|---|
| **File** | `internal/dast/containment/reset.go`, `internal/dast/containment/reset_test.go` |
| **`t.Skip` sites** | **Zero.** `TestResetFileSkipsNothing` reads the test file and fails if one appears |
| **Skipped here?** | N/A — nothing skips. Two separate things are missing: a container engine, and a component that does not exist yet |
| **Skips in CI?** | N/A — same |
| **Property unverified** | (a) That a real `docker compose down -v` removes what the verification then asserts is gone, and that a real `docker volume ls --filter label=com.docker.compose.project=<p>` can answer the volume question at all. (b) That a manifest declaring `seed:` can be reset — it cannot, and `NewResetter` refuses it |
| **Security control?** | **Yes, indirectly and strongly.** Reset is what makes probe *k+1* an independent observation of probe *k*'s target. A reset that quietly half-succeeded makes every finding after it a claim about an application nobody can name, and the record still says `booted_clean` |
| **Verdict** | **OPEN. Not legitimate, not accepted — (a) unexecuted, (b) unimplemented and refused loudly.** |

**Docker is not installed on the host this packet was written on** — the same
measurement recorded in U2 above. `internal/dast/containment` still implements
no production `Docker`, and now also no production `VolumeInspector`.

### What the suite does prove, on Windows and on Linux alike

The decision logic is a pure function of recorded shapes, and it is driven by a
world model that actually destroys and actually recreates, so the failure modes
are exercised rather than described:

- **The stop condition, directly.** `TestNoStateSurvivesAReset` writes a marker
  to the authorized service's writable layer and to its volume, resets, and
  asserts neither is reachable.
  `TestTheStateSurvivalCheckCanSeeSurvivingState` is its negative control: the
  same harness, with the `-v` dropped, must still SEE the marker and the reset
  must refuse. Without that second test the first one asserts nothing.
- **The order, not only the calls.**
  `TestResetVerifiesTheDestroyBeforeReProvisioning` pins the exact call
  sequence — `down`, then both listings, then D.10's `Provision` unchanged.
  Moving the verification after the re-provision was tried, live: it does not
  merely stop catching the damage, it reports a false positive, because the
  containers it sees are the ones `up` just made.
- **Both halves of "indistinguishable from a first provision".** Same project,
  service, image ref, digest, health URL, runtime, platform and provisioning
  path; DIFFERENT container id for the authorized service AND for every other
  container in the project. `TestVerifyFreshChecksEveryDeclaredField` breaks
  one field per case with an unmutated control, so a verifier that rejected
  everything would not pass.
- **`Provenance()` is total over the reset stages, no stage maps to
  `booted_clean`, and `TestNoResetStageCanBeReadAsScannedClean` sweeps every
  stage × every `record.HalfStatus` through `record.DeriveDastStatus` asserting
  none derives a status where `MeansDynamicallyScannedClean()` holds.**
- **Fifteen guards were broken one at a time, watched go red, and restored
  byte-for-byte** (SHA-256 `9369CE4D…6EBE` before and after each).

### What it does not prove, and exactly what would settle it

1. **A Linux CI lane with Docker Engine and gVisor** — the same lane U2 needs,
   extended. On top of U2's assertions it must run, **positively**: provision
   the two-service fixture, `docker exec` a write into the `web` container's
   writable layer *and* an `INSERT` into the `db` service's named volume,
   `Reset`, then assert (i) `docker ps -a --filter
   label=com.docker.compose.project=anvil-<hash>` is empty *between* the down
   and the up, (ii) `docker volume ls --filter
   label=com.docker.compose.project=anvil-<hash>` is empty at the same moment,
   (iii) the file and the row are both gone from the new containers, and (iv)
   every container id differs from the pre-reset set while `ImageDigest()` is
   byte-identical.
   And **negatively**, without which the lane proves nothing:
   - the same reset driven with `down` **without** `-v` must refuse at
     `ResetStageDestroyUnverified` naming the surviving volume — this is the
     one failure the container listing cannot see and it is the reason
     `VolumeInspector` exists;
   - a `docker volume ls` that errors (e.g. the daemon socket closed
     mid-teardown) must refuse, not read as "there are none".
   **This is the one that closes half (a).**
2. **A seed-execution component.** `NewResetter` refuses any manifest with a
   `seed:` section (`ErrResetSeedNotReplayable`), because a destroy-and-recreate
   discards the seed's effects and nothing in this tree replays them: the
   target it would hand back is an *unseeded* one, and calling that "the
   declared initial state" is precisely the silent substitution D.13 exists to
   prevent. plan/50-dast.md declares `seed.command` at line 1106 and assigns no
   packet to execute it. What settles this: a component that runs
   `seed.command` in exec form after health passes, plus a seam here that
   replays it after each re-provision **with evidence that it ran** — the same
   standard the four observations already meet, not an exit code alone. Until
   then this is a REFUSAL, not a gap: no seeded manifest can be silently
   half-reset, it simply cannot be reset.
3. **`Target` invalidation under concurrency**, cheapest and narrowest.
   `invalidate` writes `Target.sealed` and `Target` carries no mutex, so a
   caller resetting one target while another goroutine reads the same handle is
   a data race. plan/50-dast.md places D.13 in the **serial** group and nothing
   in this package resets two targets at once, so no test exercises it and
   `go test -race` (PowerShell, 26 packages, 0 races) says nothing about it.
   What would settle it: a mutex on `Target` — an edit to `provision.go`, which
   is outside D.13's write scope — or a documented single-owner contract
   enforced at the call site when the probe engine (D.14+) lands.

Until (1) exists, **`Reset` is a control that runs in zero CI lanes against a
container engine**, and this entry is the standing record of that.

---

## U4 — the Nuclei driver (D.14) has never executed an engine, and cannot yet fire a single request through the kernel

| | |
|---|---|
| **File** | `internal/dast/engines/nuclei.go`, `internal/dast/engines/nuclei_test.go` |
| **`t.Skip` sites** | **Zero.** `TestThisFileSkipsNothing` parses the test file and fails if one appears |
| **Skipped here?** | N/A — nothing skips. Two separate things are missing: the engine, and a route to an `authz.Authorization` |
| **Skips in CI?** | N/A — same. `.github/workflows/ci.yml` installs no probe engine |
| **Property unverified** | (a) That a real Nuclei engine, handed a `RunPlan`, honours `TargetSpec.PinnedAddr` instead of re-resolving `TargetSpec.URL`. (b) That `Driver.Fire` admits and issues a request end to end — the admit-and-issue path has **never executed**, because no `Authorization` can be minted from outside package `authz` today |
| **Security control?** | **Yes, and it is the whole packet.** The driver exists to make it structurally impossible to point Nuclei anywhere the kernel has not admitted |
| **Verdict** | **OPEN. (a) unexecuted and unenforceable from here; (b) BLOCKED on a kernel decision, not on this host.** |

### (a) nuclei is not installed, and no adapter exists

**Measured** on the development host: `Get-Command nuclei` finds nothing, and
`go list -m all` contains no `projectdiscovery` module. `SystemEngine()`
therefore returns `*EngineUnavailableError` on **every** host — it never
returns a no-op engine — and `ScanResult.AssertNotSilentlyEmpty` refuses to let
an empty finding list be read as clean when nothing was issued.

The unenforceable half is stated in the `Engine` interface's own doc comment
and repeated here so it is not lost: `TargetSpec` carries both a `URL` (the
canonical host from gate 8) and a `PinnedAddr` (gate 9's pinned address). An
implementation **must** dial `PinnedAddr` and must not resolve the URL's host.
Anvil's own egress path makes that structural — `authz.PinnedDialAddress`
returns a `netip.AddrPort` with no hostname in it, so a dialer built on it
*cannot* re-resolve — but an external engine is a process this package does not
control. **Nothing in `internal/dast/engines` enforces it.**

### (b) The blocker is gate 11, and it is measured rather than assumed

`authz.Adjudicate` is the only mint for an `authz.Authorization`.
`authz.admissionChain` contains `Gate11RobotsDeny`, and **nothing is
registered for it** — `kernel.go`'s own comment says robots.txt is a property
of an origin *and a path*, that a `gateFunc` receives no path, and that "a
missing gate is a REFUSAL, never a skipped step", leaving the decision on where
the robots policy enters the kernel to the orchestrator.

The consequence for D.14 is exact: **`NewTargetSpec`, `NewDriver`,
`Driver.Fire` and `Driver.Run` cannot be exercised on their success path from
outside package `authz`.** Every test that would need one instead asserts the
refusal, and `TestNoAuthorizationCanBeMintedUntilGate11IsRegistered` runs the
real Phase 1 gates and the real admission chain and pins **where** the chain
stops. When gate 11 is registered, that test fails and its message lists the
five tests that must then be written.

### What the suite does prove, on any host

- **The `code:` protocol is rejected at load, not skipped at match time**, and
  the assertion is against `TemplateSet.Lookup` — the function `Fire` actually
  calls — rather than against a comment.
- **The protocol list is an ALLOWLIST.** A table drives `javascript`, `flow`,
  `headless`, `self-contained`, `dns`, `network`, `tcp`, `file`, `ssl`,
  `websocket`, `whois`, `requests` and an invented `quantumteleport` through
  it; none of them contains the substring "code", so a denylist of one passes
  the first row and fails the rest.
- **The structural analysis is not defeated by syntax**: quoted keys, a wholly
  indented document, tabs, a flow mapping, a second YAML document, a `code:`
  inside an indented block scalar, a `code:` in a comment, CRLF, a BOM, a
  duplicate key, a top-level sequence — sixteen rows, with four admitted
  controls so a loader that refused everything would fail.
- **`WithPDCPUpload` appears in no call expression in the package**, proven by
  reading the package's own syntax tree, with an anti-vacuity check that the
  identifier is still *declared* somewhere so a rename cannot silently retire
  the guard. The spy's call count is the second, weaker half.
- **Interactsh/OAST is off structurally**, not by default value: this driver
  proposes only three of the kernel's six request origins, and the three it
  omits are exactly the three whose protocols the template allowlist refuses.
  There is no argument to any constructor that turns the other three on.
- **`RequestProposal` holds nothing that could open a socket**, proven by a
  recursive reflection walk over its fields and its methods' return types
  (plan/50-dast.md exit criterion 19, done early). `net/netip` is the one
  stop-point, by package path, for the reason `authz` lists it inert.
- **Twelve guards were broken one at a time, watched go red, and restored
  byte-for-byte** — `nuclei.go` SHA-256 `31FBF061…232A` before and after every
  one. Two of them are worth naming: replacing the walk's link check with
  `d.Type()&os.ModeSymlink != 0` makes the **Windows directory junction** walk
  straight through (this host reports a junction as `os.ModeIrregular`,
  `IsDir()==false`, symlink bit **clear** — the H1 primitive again), and adding
  `net/http` to the package is caught both by the local echo *and* by D.9's
  authoritative tier-1 scanner over the real tree.

### What it does not prove, and exactly what would settle it

1. **Register gate 11 (or rule it out of the admission chain).** This is the
   orchestrator's decision and it is not D.14's to make. It is the single
   change that turns five refusal-only tests into end-to-end ones. **This is
   the one that closes half (b), and it is a kernel edit, not a host problem.**
2. **A CI lane with the pinned Nuclei engine, and an `Engine` adapter.** It
   must run, **positively**: load the pinned `nuclei-templates` snapshot
   (D.17), execute against a fixture target, and assert
   `AssertNotSilentlyEmpty` returns nil *and* at least one known finding
   appears. And **negatively**, without which it proves nothing:
   - the same lane with the engine binary removed must exit
     `ExitCodeArtefactAbsent` (2) and must **not** report a clean target;
   - the same lane with an empty template directory must fail with
     `ErrNoTemplates`;
   - a fixture template pointing at a host **outside** the scope file must
     produce a kernel refusal and reach the `Issuer` zero times.
3. **Template provenance.** Upstream templates carry a trailing `# digest:`
   line signed by projectdiscovery. **Nothing here verifies it**, and no
   assumption is made that anything did: every template is analysed
   structurally regardless of source, and a SHA-256 of its exact bytes is
   recorded so D.17's pin can be checked against what was actually loaded.
   What would settle it: projectdiscovery's public key plus their verifier,
   wired into D.17's promotion step — and, in the meantime, D.17's
   diff-before-promotion is the control, not this package.
4. **`internal/ingest/sanitize` is out of reach**, so this package carries a
   deliberately smaller local scrub. **Measured**: `go test -run
   TestGate2NoDastPackageReachesTheInferenceLayer ./internal/dast/authz/`
   fails on an import of it, because every package under `internal/dast` may
   link only the stdlib, the DAST tree and `kernelImportAllowlist` (one entry:
   `internal/record`). The scrub removes controls, bidi, zero-width, tag
   characters and invalid UTF-8 and bounds the length; it does **not** do
   sanitize's hidden-markup analysis. What would settle it: an entry for
   `internal/ingest/sanitize` in `kernelImportAllowlist` — a `phase0_build.go`
   edit, which is D.9's write scope — or moving the shared scrub into
   `internal/record`, which is already on the list.

Until (1) exists, **the Nuclei driver's admit-and-issue path runs in zero CI
lanes and zero local ones**, and this entry is the standing record of that.

---

## U5 — the ZAP driver (D.15) has never started a JVM, and ZAP's memory footprint is still unquantified

| | |
|---|---|
| **File** | `internal/dast/engines/zap.go`, `internal/dast/engines/zap_test.go` |
| **`t.Skip` sites** | **Zero.** `nuclei_test.go`'s `TestThisFileSkipsNothing` walks every `.go` file in the package, so it covers `zap_test.go` and would fail if one appeared |
| **Skipped here?** | N/A — nothing skips. Three separate things are missing: ZAP, a route to an `authz.Authorization`, and any measurement of the JVM |
| **Skips in CI?** | N/A — same. `.github/workflows/ci.yml` installs no ZAP and no ZAP add-ons |
| **Property unverified** | (a) That the generated `zap.yaml` is one ZAP accepts, and that the four caps and the two report templates are the keys ZAP actually reads. (b) That a ZAP driven through `env.proxy` really has no other egress. (c) `ZapDriver.Fire`'s admit-and-issue path, blocked on gate 11 exactly as U4(b) is. (d) **ZAP's JVM memory footprint, which plan/50-dast.md:1253 asks for by name and which this packet deliberately did not guess at.** |
| **Security control?** | **Yes.** The proxy requirement is the only thing that puts Anvil's kernel in front of a request ZAP makes, and the four caps are the only thing between a scheduled scan and ZAP's unlimited defaults |
| **Verdict** | **OPEN. (a) and (b) unexecuted on this host; (c) BLOCKED on the same kernel decision as U4; (d) UNMEASURED and recorded as unmeasured.** |

### (d) first, because it is the one the plan asked for

plan/50-dast.md:1253 records ZAP's JVM memory footprint as unquantified
(research 15's own gap) and notes it decides whether tier-M hardware (spine S9,
32 GB / 8 core) accommodates a scheduled full scan alongside SAST and the
coding agent.

**It is still unquantified, and no number appears anywhere in D.15.** That is a
decision, not an omission: a figure invented here would become the figure
tier-M sizing is documented against, and it would be documented against
nothing. `TestTheJVMFootprintIsNotFabricatedAnywhereInThisPackage` reads
`zap.go` and fails if one appears, and also fails if the word "unquantified"
leaves the file — so filling the gap and updating this entry have to happen in
the same commit.

**What would settle it, and what stops it here.** The plan's own suggestion is
one `docker stats` run during a representative scheduled scan.
**MEASURED 2026-08-22, PowerShell, on the development host:**

```
Get-Command docker  -> NOT FOUND
Get-Command zap.sh  -> NOT FOUND
Get-Command zap     -> NOT FOUND
Get-Command zap.bat -> NOT FOUND
Get-Command java    -> C:\Program Files\Common Files\Oracle\Java\javapath\java.exe
java -version       -> 23.0.2 2025-01-21 (HotSpot 23.0.2+7-58)
```

So **both halves of the suggested measurement are unavailable here**: no ZAP to
run and no Docker to measure it with. A **JVM is present**, which narrows the
gap usefully — this host is not disqualified by a missing runtime, only by a
missing application — but a `java -Xshare` heap figure from a JVM running
nothing is not a ZAP scan's RSS and would be worse than no number.

The measurement that settles it, stated so it can be executed without
re-deriving it:

1. On a Linux host with Docker, run the pinned ZAP image against a fixture
   target using the plan `ZapAutomationPlan.YAML()` produces, with the four
   caps at `ZapCapsAtKernelCeiling(authz.CodedCaps())` (today: `threadPerHost`
   4, `delayInMs` 400, `maxScanDurationInMins` 30, `maxRuleDurationInMins` 30).
2. Sample `docker stats --no-stream` at least once a minute for the whole scan
   and record **peak** RSS, not mean — tier-M sizing is a peak question.
3. Record the figure, the ZAP version, the add-on versions and the target in
   this entry, and only then in any sizing document.
4. Re-run it with SAST and the coding agent resident, because the plan's
   question is about **coexistence**, not about ZAP alone.

### (a) ZAP is not here, and the driver says so rather than passing

`SystemZapRunner()` returns `*ZapUnavailableError` on **every** host — it never
returns a no-op — and that error unwraps to `ErrEngineUnavailable` and reports
`ExitCodeArtefactAbsent` (2), which is D.14's constant and not a second one.
`ZapScanResult.AssertNotSilentlyEmpty` refuses to let an empty finding list be
read as clean.

**Two strings in `zap.go` are transcribed rather than measured**, and there is
no ZAP here to check them against: the report template names `sarif-json` and
`traditional-json-plus`, and the Automation Framework key names in the
generated plan (`replacer`/`req_header`, `passiveScan-config`,
`activeScan`'s four cap keys, `env.proxy.hostname`/`port`). What would settle
it: one `zap.sh -cmd -autorun` against the generated plan on a host with ZAP,
asserting a zero exit **and** that both report files appear. `Autorun` already
refuses a zero exit with a missing report, so that lane's negative control is
built.

### (b) the proxy is required, and nothing here proves ZAP honours it

This is the substantive difference between D.14 and D.15 and the reason U5 is
not just "U4 with a different binary". Nuclei is driven in-process and gate 3
tier 1 makes it *structurally* unable to dial from `internal/dast/engines`.
**ZAP is a JVM with its own HTTP stack**, so the containment argument is:

- `NewZapAutomationPlan` refuses without a `ZapProxy`; `NewZapProxy` refuses
  any address that is not a loopback literal; `Verify` refuses a rendered
  document whose proxy block is missing or altered. All three are tested,
  including by deleting each check and watching the suite go red.
- Anvil's egress layer assigns `authz.RefuseAllRedirects` to its client's
  `CheckRedirect`, so Anvil never follows a `Location` automatically. ZAP
  receives the 3xx; if ZAP follows it, that is a **new request to the proxy**
  and arrives at gate 13 with `OriginRedirect` and `Hop+1`.

**What none of that proves:** that a ZAP process actually honours `env.proxy`
for every request, that it has no second egress path (add-on update checks, the
ZAP API port, an OAST callback from an alpha add-on), and that a runner does
not leave it able to dial directly. **Nothing in `internal/dast/engines`
enforces the last one** — it is stated as an obligation on the `ZapRunner`
implementer in that interface's doc comment. On Linux the enforcement is D.11's
netns with default-deny egress; on a host without one it is unenforced. **A
lane that closes this must include the negative control: a fixture target
reachable ONLY through the proxy, plus a second address reachable only
directly, and an assertion that the second one was never contacted.**

### (c) the same gate-11 blocker as U4

`NewZapDriver` builds its `TargetSpec` through `NewTargetSpec`, so it cannot be
constructed without an `authz.Authorization` — and none can be minted from
outside package `authz` today. `TestNewZapDriverRefusesEveryUnauthorizedRoute`
asserts the refusal; `nuclei_test.go`'s
`TestNoAuthorizationCanBeMintedUntilGate11IsRegistered` is the tripwire that
pins **where** the chain stops, and it covers this file too rather than being
duplicated. Registering gate 11 unblocks both drivers at once.

### The scheduled-only rule is enforced NOWHERE in this package, by instruction

plan/50-dast.md D.15's forbidden actions require the driver to be
**trigger-agnostic**: ZAP is gated to scheduled full scans "enforced by the
caller's trigger-policy check, not by this driver refusing to run". So there is
no trigger field and no trigger check in `ZapConfig` or `ZapPlanFacts`, and
`TestThisDriverIsTriggerAgnosticByInstruction` fails if one appears — turning
the absence into a recorded decision rather than an oversight somebody later
"fixes" in the wrong layer.

**The consequence is that today nothing anywhere stops ZAP being driven from
the always-on path**, because the caller that would carry the trigger-policy
check does not exist yet. That is this entry's, not D.15's, to keep visible
until it does.

### What the suite does prove, on any host

- **All four caps are explicit, bare positive integers, appear exactly once,
  and equal the sealed `ZapCaps` gate 14 checked** — so "unlimited", `0`,
  `-1`, `0400`, `"400"`, `1_000`, `400ms`, `null`, a duplicate key and a
  *different but bounded* value are each a separate refusal.
- **The caps' PRODUCT is checked, not only each cap.** The same
  `ZapCapFacts` is accepted against `authz.CodedCaps()` and refused against a
  kernel whose requests-per-target-run was lowered — nothing about the four
  numbers changed, so only the product check can produce the difference.
- **`ZapCapsAtKernelCeiling` reads the kernel rather than returning
  constants**, proved by lowering gate 14's floors and requiring every derived
  value to move.
- **The run id is an allowlist**, `[A-Za-z0-9._-]`, because it becomes an HTTP
  header value: CRLF, LF, CR, quote, backslash, space, colon, NUL, tab, DEL,
  non-ASCII, zero-width, bidi and tag characters are eighteen separate rows.
- **The context include pattern is `\Q…\E`-quoted** and the URL is re-checked
  against gate 8's canonical-host grammar, so a host carrying a `\E` cannot
  end the quote early.
- **The argv is a vector of exactly four elements and never a shell string**,
  and `Argv()` is a real copy.
- **`Verify` runs inside the constructor**, proved through an unexported
  renderer seam: a renderer that drops one line yields **no plan**, for each of
  ten lines in turn. Without the seam that call was untestable and deleting it
  left the whole suite green.
- **Sixteen guards were broken one at a time, watched go red, and restored
  byte-for-byte** — `zap.go` SHA-256 `A456F9A5…0942` before and after every
  one. Two are worth naming. (i) The plan-digest check in `Fire` **passed while
  deleted**: the fixture driver holds a zero `Authorization`, so the proposal
  fell through to `authz.RequireAuthorization` and was refused by a different
  control. The test now asserts both digests appear in the message. (ii) The
  first `ZapAutomationPlan` stored `reports []ZapReportTemplate`, and because
  the type is passed by value a copy shared the backing array — the field is
  gone and the type now carries no reference field at all.

### What it does not prove, and exactly what would settle it

1. **Register gate 11 (or rule it out of the admission chain).** Same item as
   U4(1), same owner, and it unblocks both drivers.
2. **A CI lane with ZAP and the pinned add-ons.** Positively: render the plan,
   run `zap.sh -cmd -autorun`, assert exit 0, both report files non-empty, and
   `AssertNotSilentlyEmpty` returning nil. Negatively, without which it proves
   nothing: the same lane with ZAP removed must exit `2` and must not report a
   clean target; a plan whose report directory is unwritable must fail with
   `ErrZapReportMissing` rather than clean; and a fixture redirect to a host
   outside the scope file (ZAP #2546's shape) must be refused at gate 13 and
   reach the target zero times.
3. **A containment lane proving `env.proxy` is ZAP's ONLY egress**, with the
   second-address negative control described in (b).
4. **The JVM footprint measurement in (d)**, before any tier-M sizing document
   quotes a number.

Until (1) and (2) exist, **the ZAP driver has never rendered a plan that a ZAP
process read**, and this entry is the standing record of that.

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
| Hazards needing a non-test change | 4 (N1 closed by CI, N2 closed elsewhere, N3 closed, N4 closed) |
| Legitimate skips, left in place | 11 |
| Skips that fire on the Windows dev host | 4 tests / 15 subtest lines |
| `t.SkipNow` sites | 0 |

Skips still firing on this host, all classified LEGITIMATE above:
`TestCollectAgainstTheRealHost` (L1), `TestRealTrivyScansAFixtureRepo` (L4),
`TestBothConsumersAgree` (L5), `TestPinnedLicenceBodiesMatchTheirPins` ×11
(L7), `TestXVM3RelatedLocationsAreCapped/loc0_rel3000` (L11).

Controls with **zero** skips and still nothing behind them: G19-1, G4-1,
G18-2, U1 (+U1a, U1b, U1c), U2 (+U2a), U3, U4, U5.

U5 carries the one open question plan/50-dast.md asked a worker to answer and
that this host cannot: **ZAP's JVM memory footprint (plan/50-dast.md:1253),
which decides tier-M sizing.** No number was invented; the entry states what
measuring it takes and a test fails if a figure appears in `zap.go`. U5 also
records the rule that is enforced nowhere today — ZAP is **scheduled-scans
only**, and the caller that would carry that check does not exist yet.

U4 is the one to read next after U1c, and its blocker is **not** this host.
`authz.Gate11RobotsDeny` has no implementation registered, so the admission
chain refuses every target there and **no `authz.Authorization` can be minted
from outside package `authz` at all**. That makes D.14's driver — and every
later packet that needs to issue a request — testable only on its refusal
paths. Registering gate 11, or ruling it out of the admission chain, is an
orchestrator decision and is the single change that unblocks the whole
admit-and-issue path.

U1 (`internal/dast/containment`, D.11 network containment) is the
highest-stakes of them: the package is green on Windows and has never run
against a Linux kernel. See its entry for the privileged Linux CI lane that
would close it, and U1a/U1b for the two things that lane would still not
settle on its own.

U1c is the one to read first if you are wiring DAST into a scan path.
`Provision` seals `booted_clean` without any network namespace, nothing in the
tree calls `Provision`, `SetupNetns` or `AssertContainment`, and the two halves
of the containment story therefore do not compose yet. That is D.31's, not
D.10's or D.11's — it is recorded here so it cannot be forgotten.
