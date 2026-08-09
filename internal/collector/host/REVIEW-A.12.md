# REVIEW-A.12 — critique of the host read-only boundary (A.9: `internal/collector/host/**`, `deploy/systemd/anvil-host-collector.service`)

**Verdict: FAIL — 2 blockers, 5 majors, 7 minors.**

**This was a SAME-FAMILY critic.** A.12's packet routes this step to OpenCode `openai/gpt-5.5`; that
route is **WITHDRAWN** by the OWNER DECISION block at the top of `plan/00-ROUTING.md` (2026-08-07,
external routes copy private project files to a third party). The cross-family guarantee A.12 was
written to obtain **was not obtained and is still owed**. A later reader must not record this file as
"cross-family critic: PASS". `plan/IMPLEMENTATION-PLAN.md` §0.2 reserved the strongest available
reviewer for exactly this class — a security gate where a miss is unrecoverable — and that reviewer
did not run. The compensation applied was method, not model: every claim in the reviewed files was
re-checked against the source, every gate was re-run locally with `-count=1`, and **every finding
below is backed by a probe I wrote and executed**. Reported output was treated as unevidenced.

---

## 0. The one-paragraph answer

**The shipped code does not mutate the host. The mechanism that was supposed to make that
structural does not hold.** A.9's entire claim — restated three times in `collect.go`'s package
comment — is that "the mutating invocation cannot be expressed", enforced by an AST guard in
`collect_test.go`. I defeated that guard with a one-line import alias, and separately with a
function value and no alias at all. With two host-mutating exec call sites compiled into the
package (`rpm --rebuilddb`, `dpkg --configure -a`), `gofmt -l` is clean, `go vet` is clean and
`go test -count=1 ./internal/collector/host/` is **`ok`**. A second, independent hole exists in the
deployment artifact: the unit-file test scans `ExecStart=` and nothing else, so
`ExecStartPre=/usr/bin/apt-get install -y …` in Anvil's own systemd unit passes the suite. A.12's
question was *cannot*, not *does not*. The answer today is *does not*.

---

## 1. Method

- Read in full: `collect.go` (1060), `dpkg.go` (120), `rpm.go` (87), `apk.go` (169),
  `collect_test.go` (2085), `deploy/systemd/anvil-host-collector.service` (123). Read as context:
  `plan/00-SPINE.md` S1/S4/S5/S7/S8/S12, `plan/20-lane-a-ingestion-sca.md` A.9/A.12 and exit
  criteria 13/14/20/21, `internal/ingest/cache/schema.go` (the `finding_host_not_remediable` CHECK).
- **No repository file was modified by this review other than this one.** Probes were compiled into
  the package with `go test -overlay=…`, except for the two whole-suite probes in §2.1, which
  required real files on disk (the guard calls `parser.ParseDir(fset, ".", …)`, which reads the
  filesystem and is blind to an overlay). Those two files were added, the suite was run, and they
  were deleted. `git status --short` before and after is identical:
  `?? deploy/`, `?? internal/collector/`, `?? internal/ingest/bootstrap/`, `?? internal/ingest/poller/`,
  `?? internal/mirror/`; `ls internal/collector/host/` is `apk.go collect.go collect_test.go dpkg.go rpm.go`.

### The four gates, run by me, real output

```
$ go version
go version go1.26.5 windows/amd64

$ gofmt -l .
(no output)

$ go vet ./...
(no output)

$ go build ./...
(no output)

$ go test -count=1 ./internal/collector/host/
ok  	github.com/Susquehanna-Syntax/Anvil/internal/collector/host	0.814s
```

`go test -count=1 ./...` is **NOT** fully green, for reasons that belong to siblings, not to A.9:
`internal/ingest/sanitize` fails `TestNoProductionImporterYet` (that test is a tripwire that now
correctly fires because A.9, A.10, A.14 and the poller import `sanitize` — the fix is to delete the
tripwire and update `sanitize.go`'s KNOWN LIMITS item 1), and `internal/mirror/accelerator` fails on
`zz_a13_probe_test.go`, a sibling critic's probe file left in the working tree. Neither touches
this packet.

`go test -race` **cannot run on this Windows host**: `ThreadSanitizer failed to allocate 0x4a30000
bytes (error code: 87)`. CI runs `-race` on `ubuntu-latest` (`.github/workflows/ci.yml`).

---

## 2. The enumeration A.12 demands: every subprocess call site with its argv

The packet requires the verdict to **list every call site, not summarise**. There is exactly one in
the package, and one more that is test-only.

| # | File:line | Call | Reachable argv |
|---|---|---|---|
| 1 | `collect.go:416` | `exec.CommandContext(ctx, bin, argv[1:]...)` in `runQuery` | the four constants below |
| 2 | `collect_test.go:2008` | `exec.Command("go", "list", "-deps", ".")` | **test-only**, not linked into the collector |

Call site 1's complete reachable argv set, from the `const` block at `collect.go:236-246` via
`queryID.argv` at `collect.go:269-281`:

| queryID | argv[0] | arguments | verdict |
|---|---|---|---|
| `queryDpkgList` | `dpkg-query` | `-W`, `-f`, `${binary:Package}\t${Version}\t${Architecture}\t${db:Status-Abbrev}\n` | enumeration; `dpkg-query` has **no** mutating mode |
| `queryRPMList` | `rpm` | `-qa`, `--qf`, `%{NAME}\t%{EPOCH}:%{VERSION}-%{RELEASE}\t%{ARCH}\n` | enumeration; see **M2** on rpmdb side-effects |
| `queryAPKList` | `apk` | `list`, `--installed` | enumeration; `--installed` is a filter on `list`, not the verb `install` |
| `queryAPKInfo` | `apk` | `info`, `-v` | enumeration — but **unreachable in production**, see **M3** |

Child process shape at `collect.go:416-423`: `bin` = `resolveBinary(argv[0])`, an absolute path
resolved against the constant list `/usr/bin:/bin:/usr/sbin:/sbin` (`$PATH` is never consulted);
`cmd.Env` = the constant `["LC_ALL=C","LANG=C","PATH=/usr/bin:/bin:/usr/sbin:/sbin"]` (no
inheritance); `cmd.Dir` = `/`; `cmd.Stdin` = nil; stdout/stderr capped at 64 MiB / 4 KiB;
`context.WithTimeout`. **No mutating verb is present. No shell is present.**

### What I verified holds (stated so the FAIL is not over-read)

- **No shell, anywhere.** No `sh -c`, no `cmd /c`, no string split on spaces re-parsed as a command.
  `exec.CommandContext` is handed a resolved path and a vector.
- **No caller-supplied value reaches an argv.** `Options` has exactly two fields (`Timeout`,
  `Now`); no exported function takes a string, `[]string` or `...string`; the `collector.run` seam
  is `func(context.Context, queryID)` and cannot express an argv.
- **No flag, config key, env var or build tag turns mutation on.**
  `grep -n "Getenv\|LookupEnv\|os.Args\|flag\.\|//go:build\|// +build" internal/collector/host/*.go`
  (non-test) returns only the string `not behind a flag` inside a doc comment. There is no config
  file read, no build tag, and no `init()`.
- **Root is genuinely optional, not a hidden fallback.** `os.Geteuid()` is called once
  (`collect.go:712`) and its value is only stored in `Provenance.EUID`. Nothing branches on it;
  `TestNothingBranchesOnBeingRoot` enforces that against the AST and I confirmed the analyser fires
  on a synthetic branch. The unit uses `DynamicUser=yes`, `CapabilityBoundingSet=`,
  `AmbientCapabilities=`, `SecureBits=noroot-locked`.
- **No second fingerprint.** `Inventory` and `FindingSeed` carry no digest field;
  `TestFindingSeedsProjectTheInventory` rejects `Fingerprint`/`ID`/`Source`/`SourceID`. The named
  cross-area edge is respected.
- **Dependency shape holds.** `go list -deps ./internal/collector/host | grep -E
  "sqlite|database/sql|net/http|os/user|internal/store"` is empty.
- **`remediable_by_agent` is a `const false` with no assignable location**, exposed as a method on
  both `Inventory` and `FindingSeed`, and the serialised `Inventory` carries
  `"remediable_by_agent":false`. (One gap — **m2**.)
- **Not a daemon.** No goroutine, no `select`, no unbounded `for`, no ticker; `Type=oneshot`, no
  `Restart=`.

---

## 3. BLOCKERS

### B1 — The mutation guard is defeated by an import alias or a function value. Two host-mutating exec sites pass the entire suite.

**Where:** `collect_test.go:127-142` (`calleeName`), `:190-241` (`spawnCallees` / `findSpawnSites`),
`:650-712` (`checkExecProvenance`, which iterates `findSpawnSites`), `:989-1015`
(`TestParsersImportNothingThatCanSpawn`, indexed on three hard-coded filenames).

`calleeName` renders a call as its **source spelling** — `exec.Command`, `pkg.F`, `f` — and
`spawnCallees` is keyed on those spellings. Three consequences, all demonstrated:

1. `import xc "os/exec"` → the callee renders as `xc.Command`, which is not in the map.
2. `import . "os/exec"` → renders as `Command`.
3. `spawn := exec.Command; spawn(...)` → the spawn function appears as a `SelectorExpr` in an
   assignment, never as a `CallExpr`, and the call renders as `spawn`. **No alias required.**

`TestParsersImportNothingThatCanSpawn` does not close this, because it checks the import set of
`dpkg.go`, `rpm.go` and `apk.go` only. A fifth file in the package is import-checked by nothing.
`checkExecProvenance` does not close it either: it iterates the sites `findSpawnSites` returned, so
an invisible site is an unanalysed site.

**Probe, run by me — the analysers, via `-overlay`:**

```
=== RUN   TestProbe_SpawnGuardIsDefeatedByAnImportAlias/aliased_import
    PROBE CONFIRMED: findSpawnSites saw NO spawn site in:
        package host
        import xc "os/exec"
        func rebuild() error { return xc.Command("/usr/bin/rpm", "--rebuilddb").Run() }
=== RUN   TestProbe_SpawnGuardIsDefeatedByAnImportAlias/dot_import          → PROBE CONFIRMED
=== RUN   TestProbe_SpawnGuardIsDefeatedByAnImportAlias/function_value      → PROBE CONFIRMED
=== RUN   TestProbe_SpawnGuardIsDefeatedByAnImportAlias/function_value_on_a_struct_field → PROBE CONFIRMED
```

**Probe, run by me — the whole suite, with real files on disk.** I wrote these two files into
`internal/collector/host/` and deleted them afterwards:

```go
// zz_probeA_alias.go
package host
import xc "os/exec"
func probeRebuildRPMDB() error { return xc.Command("/usr/bin/rpm", "--rebuilddb").Run() }

// zz_probeB_funcvalue.go
package host
import "os/exec"
func probeReconfigureAll() error {
	spawn := exec.Command
	return spawn("/usr/bin/dpkg", "--configure", "-a").Run()
}
```

```
$ gofmt -l internal/collector/host
(no output)
$ go vet ./internal/collector/host/
(no output)
$ go test -count=1 ./internal/collector/host/
ok  	github.com/Susquehanna-Syntax/Anvil/internal/collector/host	0.903s
```

**`rpm --rebuilddb` rewrites `/var/lib/rpm`. `dpkg --configure -a` runs every pending maintainer
script — which is `research/12` Hard boundary #1's failure mode verbatim, the one that restarted
`systemd-networkd` on live instances.** Both are in the package. The suite is green.

**Control, run by me** — the spelling the negative controls were calibrated on:

```go
// zz_probeC.go
package host
import "os/exec"
func probeApkAdd() error { return exec.Command("/sbin/apk", "add", "curl").Run() }
```

```
--- FAIL: TestThereIsExactlyOneExecCallSiteAndItIsRunQuery
      exec.CommandContext in runQuery (collect.go:416:9)
      exec.Command in probeApkAdd (zz_probeC.go:10:9)
--- FAIL: TestNoMutatingVerbAppearsInAnyStringLiteral
      zz_probeC.go:10:35: "add" contains [add]
--- FAIL: TestNothingCallerSuppliedReachesTheExecCall
```

So the guard works for exactly the spelling its author tried, and for no other. `collect_test.go`'s
own header says *"this repo has already had one guard defeated by an input its author never tried"*
and cites `internal/record/readpath_test.go`. The lesson was written down and then not applied here.

**Fix.** Resolve identifiers through each file's **import table**, not their spelling: build
`localName -> importPath` per `*ast.File` (handling `_`, `.` and aliases), and flag any selector
whose base resolves to `os/exec`, `syscall`, `os` (`StartProcess`), `plugin`, or
`golang.org/x/sys/*`. Flag a **reference**, not only a call — an `exec.Command` appearing anywhere
other than the single sanctioned call expression is a finding, because a function value is a call
site with the call moved. Apply the import allowlist to **every** file in the package (invert it:
only `collect.go` may import `os/exec`; every other file, present or future, may not). Then add all
four spellings above to `TestTheExecGuardCatchesASecondCallSite` — a negative control that does not
include the bypass is not a negative control.

---

### B2 — The systemd unit guard scans `ExecStart=` and nothing else. A mutating `ExecStartPre=` ships green.

**Where:** `collect_test.go:1918-1920` (`if key == "ExecStart" { execStart = append(...) }`) and
`:1977-1992` (the verb and shell checks, applied to `execStart[0]` alone).

systemd runs `ExecStartPre=`, `ExecStartPost=`, `ExecReload=` and `ExecStopPost=` with the same
identity and privileges as `ExecStart=`. None of them is collected into `execStart`, so none is
verb-checked and none is shell-checked. `deploy/systemd/anvil-host-collector.service` is a file
Anvil ships and an operator installs; a mutating line in it is `plan/00-SPINE.md` S7 violated at the
deployment layer, not behind a flag.

**Probe, run by me** (the test's own parser, replayed verbatim over a synthetic unit body — I did
not modify the real unit file; `grep -n ExecStart deploy/systemd/anvil-host-collector.service` still
returns exactly one line, 35):

```
=== RUN   TestProbe_UnitGuardOnlyScansExecStart
    PROBE CONFIRMED: the unit guard reports 0 violations for a unit whose ExecStartPre is
    ["/usr/bin/apt-get install -y anvil-host-deps"], whose ExecStartPost goes through /bin/sh,
    and whose ExecStopPost is ["/usr/bin/dpkg --configure -a"]
    unscanned ExecStartPre="/usr/bin/apt-get install -y anvil-host-deps" -> mutatingTokens=[install -y]
    unscanned ExecStartPost="/bin/sh -c \"apk upgrade --no-cache\""     -> mutatingTokens=[upgrade --no-cache]
    unscanned ExecStopPost="/usr/bin/dpkg --configure -a"               -> mutatingTokens=[]
--- FAIL: TestProbe_UnitGuardOnlyScansExecStart
```

Note the third line: `dpkg --configure -a` is not caught **even when it is scanned** — that is M1.

**Fix.** Apply `mutatingTokens` and the shell check to every `Exec*=` directive
(`ExecStart`, `ExecStartPre`, `ExecStartPost`, `ExecCondition`, `ExecReload`, `ExecStop`,
`ExecStopPost`), after stripping systemd's `-`, `@`, `:`, `+`, `!`, `!!` prefixes — and note that
`+`, `!` and `!!` **escalate privilege past `NoNewPrivileges=` and the capability bounding set**, so
their presence should itself be a failure in this unit.

---

## 4. MAJORS

### M1 — The verb denylist misses the mutating verbs of all three package managers, and a flag token is never checked against `denyVerbs` at all.

**Where:** `collect_test.go:316-343` (`denyVerbs`, `denyLongFlags`, `denyShortFlags`) and
`:357-389` (`mutatingTokens`).

Exit criterion 13 calls this "A.9/A.12's **allowlist** test". It is a **denylist**. The argv
constants are a genuine allowlist and that part holds; this belt does not.

Two independent gaps, both probed.

**(a) Missing verbs.** 18 real, host-mutating command lines, none flagged:

```
mutatingTokens("rpm --rebuilddb")        = []   # rewrites /var/lib/rpm
mutatingTokens("rpm --initdb")           = []
mutatingTokens("rpm --setperms -a")      = []   # rewrites perms of every installed file
mutatingTokens("rpm --setugids -a")      = []   # rewrites ownership of every installed file
mutatingTokens("rpm --restore -a")       = []
mutatingTokens("rpm --import /tmp/key")  = []   # writes a gpg-pubkey pseudo-package
mutatingTokens("dpkg --unpack /tmp/x.deb") = [] # unpacks a package onto the filesystem
mutatingTokens("dpkg --configure -a")    = []   # runs every pending maintainer script
mutatingTokens("dpkg --set-selections")  = []
mutatingTokens("dpkg-reconfigure openssh-server") = []
mutatingTokens("apt-get clean")          = []
mutatingTokens("apt-mark hold openssl")  = []
mutatingTokens("apk cache clean")        = []
mutatingTokens("apk --update-cache list")= []   # fetches and writes APKINDEX
mutatingTokens("dnf clean all")          = []
mutatingTokens("dnf history rollback last") = []
mutatingTokens("zypper verify")          = []   # installs missing dependencies
mutatingTokens("systemctl restart systemd-networkd") = []
```

**(b) The flag/verb asymmetry.** `mutatingTokens` branches on `strings.HasPrefix(tok, "-")`
(`:363`) and, for a flag, checks `denyShortFlags` then `denyLongFlags` — and then `continue`s.
`denyVerbs` and its hyphen-splitting fallback (`:381-386`) are **never applied to a flag token**.
Every verb in `denyVerbs` is therefore evaded by spelling it with two dashes:

```
mutatingTokens("--autoremove")   = []  even though denyVerbs["autoremove"]   is true
mutatingTokens("--dist-upgrade") = []  even though denyVerbs["dist-upgrade"] is true
mutatingTokens("--del")          = []  even though denyVerbs["del"]          is true
mutatingTokens("--add")          = []  even though denyVerbs["add"]          is true
mutatingTokens("--downgrade") --distupgrade --full-upgrade --build-dep --refresh
--update --delete --localinstall --groupremove --fix   : all = []
```

`apk --no-cache add`, `zypper --non-interactive install` and `dnf --assumeyes upgrade` are caught by
their verbs; `apt-get remove --auto-remove` is caught by `remove`. But `dpkg --configure -a`,
`dpkg --unpack` and `rpm --rebuilddb` are caught by nothing, and those are the ones that actually run
maintainer scripts and rewrite the package database.

**Fix.** Check every token against the union: for a flag, strip leading dashes and test against
`denyLongFlags` **and** `denyVerbs` **and** the hyphen-split parts. Add at least
`rebuilddb, initdb, setperms, setugids, restore, import, unpack, configure, set-selections,
reconfigure, clean, hold, mark, rollback, undo, verify, dup, patch, in, rm, up` and treat any
unrecognised token in an argv position as a failure rather than a pass — an allowlist, which is what
exit criterion 13 says this is.

---

### M2 — `rpm -qa` is not a filesystem-read-only operation on a Berkeley-DB rpmdb.

**Where:** `collect.go:240` (`argvRPMList`), and the package comment at `collect.go:80-85` — *"Every
query here reads a world-readable package database"* — plus `rpm.go:9-10`.

On RHEL/CentOS 7 and 8, SLES, and any host whose rpmdb is still BDB-backed, opening the database
creates and updates the shared-region files `/var/lib/rpm/__db.001`…`__db.003` **when the calling
process has write access to that directory**, i.e. when it runs as root. A non-root caller falls
back to a private mapping and writes nothing — which is another reason root-free matters here — but
this package deliberately **cannot** refuse to run as root: `TestNothingBranchesOnBeingRoot` forbids
any branch on the effective uid, so a root operator who runs the collector outside the systemd unit
gets host writes from a component documented as read-only.

The shipped unit does block this — `ProtectSystem=strict` makes `/var` read-only and `DynamicUser=yes`
means the process is never uid 0 — but **the unit is not the only deployment**, and there is no
binary or container entrypoint that guarantees it is used (see M4).

**Confidence: this is the one finding below not proved by a probe on this host** — it needs a real
BDB-backed RPM host, which Windows is not. It is stated as a documented property of rpm's BDB
backend and marked for verification. I flag it because A.12's attack #6 is explicitly "does anything
write to the filesystem outside a scratch dir", and the honest answer for `rpm -qa` as root is *yes,
on a large installed base*.

**Fix.** Either document the constraint precisely in `collect.go` and `rpm.go` (replacing the
unconditional "reads" claim), or add the rpmdb-writable case to the coverage report so a reader can
see it, or ship a container/entrypoint that guarantees the confinement. Do **not** fix it by
branching on uid — that would trade this finding for a worse one.

---

### M3 — The documented `apk info -v` fallback is unreachable. Alpine hosts with older apk-tools report zero packages.

**Where:** `collect.go:244-245` (`argvAPKInfo`, *"the fallback for apk builds predating `apk list`"*),
`collect.go:722-727` (`familyPlan`), `collect.go:828-855` (`collectFamily`).

`collectFamily` advances to the next query in a chain **only** when the error is
`errBinaryNotFound` (`collect.go:830`). Any other error `return`s immediately with
`FamilyFailed`. An apk-tools build that predates `apk list` **has** the `apk` binary; it fails with
`ERROR: Not a valid command: list` and a non-zero exit, which is not `errBinaryNotFound`. And both
chain entries resolve the same binary, so if `apk` is genuinely absent both report
`errBinaryNotFound` and neither runs. **`queryAPKInfo` cannot execute under any input.**

**Probe, run by me:**

```
=== RUN   TestProbe_APKFallbackIsUnreachable
    PROBE CONFIRMED: `apk list` failed with a non-binary-missing error and `apk info -v` was
    never tried; the Alpine family reports "failed" with 0 packages while two packages were
    available from the documented fallback
```

This is a Lane A **coverage** defect, not a safety one: exit criterion 20's "never a silent clean"
still holds (the family is `failed`, not `absent`, and `ParseDegraded` is set), so nothing is
silently wrong. But an entire ecosystem's inventory is lost on hosts the fallback was written for,
and `TestTheInvocableCommandListIsExactlyTheEnumerationQueries` gives `queryAPKInfo` full green
coverage while it is dead code — which is why nothing surfaced it.

**Fix.** Advance the chain on any error, not only `errBinaryNotFound`, recording the first error;
report `FamilyFailed` only when every entry in the chain failed. Add a test asserting the fallback
fires on a non-`errBinaryNotFound` failure.

---

### M4 — There is no collector binary, and no fixture run for the rpm or apk families.

`deploy/systemd/anvil-host-collector.service:35` is `ExecStart=/usr/lib/anvil/anvil-host-collector`.
`ls cmd/` is `anvil`, `anvil-dast`. **No such main package exists.** The unit therefore cannot be
installed and A.9's stop condition — *"Collector runs to completion and exits under a non-root UID on
at least one fixture per family"* — is unmet for all three families as an artifact question, and
A.12's own Expected output ("confirmation the binary runs successfully as a non-root user in the
test fixture") cannot be given: **there is no binary to confirm.**

The exec path itself is exercised only by `TestCollectAgainstTheRealHost` (`collect_test.go:2042`),
which `t.Skip`s on anything but Linux and on any Linux host without a package manager. In practice
that means it runs on CI's `ubuntu-latest` runner (non-root, `dpkg-query` present) and covers the
**deb family only**. The rpm and apk exec paths have never been executed anywhere — including in the
run that produced A.9's evidence, since that ran on this Windows host, where the test skips.

**Fix.** Add `cmd/anvil-host-collector` (out of A.9's scope, so this is a plan-sequencing gap the
owner should schedule, not a defect the author introduced), and add a CI matrix job running the
collector in `debian:12`, `rockylinux:9` and `alpine:3.20` containers as a non-root user. Until then
exit criterion 13's second clause and A.9's stop condition should be recorded as **not met**.

---

### M5 — No guard forbids a filesystem write in the package.

A read-only collector that drops a file on the host has mutated it. The package writes nothing
today — I confirmed that against the AST — but nothing stops it:

```
=== RUN   TestProbe_NothingForbidsAFilesystemWrite
    PROBE CONFIRMED (structural): os.WriteFile to /etc passes every analyser in collect_test.go
```

`findSpawnSites`, `findMutatingLiterals` and `findDaemonConstructs` all return empty for
`os.WriteFile("/etc/anvil-was-here", nil, 0o644)`. Given that the package already imports `os` for
`os.ReadFile`, `os.Stat`, `os.Hostname` and `os.Geteuid`, a write is one line and one review away.

**Fix.** Add a `TestCollectorNeverWritesToTheFilesystem` AST guard over `os.WriteFile`, `os.Create`,
`os.OpenFile` (any mode but `O_RDONLY`), `os.Mkdir*`, `os.Remove*`, `os.Rename`, `os.Chmod`,
`os.Chown`, `os.Symlink`, `os.Truncate`, with a negative control. This is the same shape as the
guards already present and costs nothing.

---

## 5. MINORS

**m1 — The per-query deadline does not actually bound `cmd.Run`.** `collect.go:416-425` sets no
`cmd.WaitDelay`. Because `cmd.Stdout`/`cmd.Stderr` are `io.Writer`s rather than `*os.File`s,
`os/exec` allocates a pipe and a copying goroutine, and `cmd.Wait` blocks until **every** writer end
closes. `context.WithTimeout` kills the direct child only; a grandchild inheriting the pipe holds
`runQuery` open indefinitely, which is exactly the "collector that hangs on a wedged rpmdb" the
constant's own doc comment says must not happen. `TimeoutStartSec=300` backstops it under the unit
and nowhere else. Probed (`TestProbe_NoWaitDelayOnTheExecCall`). Fix: `cmd.WaitDelay = 5 * time.Second`.

**m2 — `FindingSeed` JSON omits `remediable_by_agent`; `Inventory` emits it.** Probed:

```
{"collector":"host","ecosystem":"deb","package":"openssl","installed_version":"3.0.11-1",
 "inventory_trust":"untrusted","as_of":"…","staleness_seconds":0,"detected_at":"…"}
```

`FindingSeed` is the artifact that crosses to A.17. A.12's checklist item 7 says *check the emission,
not the comment* — the emission is present on `Inventory` (`MarshalJSON`, `collect.go:612-618`) and
absent on `FindingSeed`. Risk is bounded because `internal/ingest/cache/schema.go:383-384` carries
`CONSTRAINT finding_host_not_remediable CHECK (collector <> 'host' OR remediable_by_agent = 0)`, and
because Go's `json.Unmarshal` leaves a missing bool false. Fix: give `FindingSeed` the same
`MarshalJSON`, and extend `TestSerialisedInventoryCarriesRemediableFalse` to cover it.

**m3 — The unit test never asserts the unit's own network and syscall controls.** Probed: it asserts
23 directives and never checks `RestrictAddressFamilies`, `SystemCallFilter`, `SecureBits`, `UMask`,
`PrivateDevices`, `ProtectProc`, `ProtectKernelLogs`, `ProtectClock`, `ProtectHostname`,
`RestrictRealtime` or `TimeoutStartSec`. The unit's comment claims *"The collector makes NO network
calls"* and rests that claim on `RestrictAddressFamilies=AF_UNIX` — a line that can be deleted with
the suite staying green. Fix: assert them, and consider `PrivateNetwork=yes`, which is the directive
that makes "no network" structural rather than filtered.

**m4 — The dependency-shape guard skips silently.** `collect_test.go:2015` `t.Skipf`s when `go list`
fails. That is the only test standing between the shipped collector and `modernc.org/sqlite`,
`net/http` or `internal/store`, and in an environment where `go` is not on `PATH` it reports success.
Fix: `t.Fatal` unless an explicit opt-out env var is set.

**m5 — Dead branch.** `collect.go:858-860`: `if lastErr != nil { cov.Status = FamilyAbsent }` — `cov`
was initialised to `FamilyAbsent` at `:820`. Harmless, but it is in the exact function whose fallback
logic is wrong (M3), and it reads as a leftover from a version that distinguished the two cases.

**m6 — `spawnCallees` contains a symbol that does not exist.** `collect_test.go:203`:
`"exec.CommandContextRun": true`. There is no such function in `os/exec`. Also `"os.Executable":
false` sits in a map used as a set, which works but documents-by-comment inside data. Both suggest
the list was written from memory rather than from `os/exec`'s actual surface — the same root cause
as B1.

**m7 — No `.timer` unit ships.** The unit's header says a `.timer` supplies the cadence and none is
in `deploy/systemd/`. Not in A.9's scope; recorded so it is not lost.

---

## 6. What this review did NOT establish

- **`-race` was not run** on this host (`ThreadSanitizer failed to allocate … error code: 87`). CI
  runs it on Linux and has previously caught a real concurrency bug that passed locally.
- **M2 was not reproduced.** It requires a BDB-backed RPM host with a root caller. Windows cannot
  provide one. Treat it as a claim to verify, not a confirmed defect.
- **No real exec ran.** `TestCollectAgainstTheRealHost` skips on Windows, so every behavioural
  finding here concerns the fixture path and the source; the actual `dpkg-query`/`rpm`/`apk`
  invocations were reviewed by reading, not by running.
- **`apk list --installed` and repository access.** apk loads `/etc/apk/repositories` even for a
  local listing. Whether it can attempt a fetch (and therefore fail under
  `RestrictAddressFamilies=AF_UNIX`, or emit warnings the parser then classes as noise) was not
  tested. `parseAPKList` does handle `WARNING:` lines, so the design anticipated something here;
  it is worth a container test.
- **Cross-package reachability.** The analysis covers this package's surface. `queryID` is
  unexported and no exported function takes an argv, so no other package can widen it — but I did
  not audit callers, because there are none: `grep -rn "collector/host"` outside the package returns
  only plan documents.

---

## 7. Stop condition

A.12's stop condition is *"any mutating-capable call site found blocks this collector from being
wired into A.17/A.21 until fixed and re-reviewed."*

**No mutating call site exists in the shipped source.** But B1 and B2 mean the guard that is supposed
to keep it that way does not work, and A.12 was commissioned to answer *cannot*, not *does not*.
**Recommend: do not wire this collector into A.17 or A.21 until B1 and B2 are fixed and the
negative-control suites are re-run with the four bypass spellings and the `Exec*=` directive set
included.** M1 should land with them. M3 and M4 gate exit criterion 13's second clause
("completes successfully under a non-root UID against a fixture") independently of the safety
question.
