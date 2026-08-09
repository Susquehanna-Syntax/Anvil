// Package host is Anvil's READ-ONLY host package collector (step A.9 of
// plan/20-lane-a-ingestion-sca.md).
//
// It enumerates the packages a Linux host has installed by asking the native
// package database — `dpkg-query -W`, `rpm -qa`, `apk list --installed` /
// `apk info -v` — reads /etc/os-release, and returns an Inventory. It then
// exits. That is the whole product.
//
// # The read-only boundary, and why it is built this way
//
// plan/00-SPINE.md S7 states the rule without an exception clause:
//
//	The host agent is read-only — no package manager in a mutating mode,
//	not behind a flag.
//
// research/12-linux-host-scanning.md Hard boundary #1 gives the reasoning:
// `unattended-upgrades` pulling in `libsystemd-network` restarted
// `systemd-networkd` on live instances, and a 36-minute archive outage
// cascaded into multi-day breakage. An agent that applies package updates is
// a different and far more dangerous product than an agent that reports them.
// A mutating host agent converts Anvil from a security tool into an
// availability risk on servers people depend on.
//
// "Not behind a flag" is a statement about SHAPE, not about defaults. Anything
// enforced by a default, a config key or a code review is enforced by
// convention, and this package is instead built so that the mutating
// invocation cannot be expressed:
//
//   - THERE IS NO ARGV PARAMETER ANYWHERE. Nothing exported takes a command,
//     a subcommand, an argument slice or a binary name. Options carries a
//     timeout and a clock and nothing else, and TestOptionsCarriesNoCommandSurface
//     fails if a field is ever added to it.
//   - THE ARGV IS A COMPILE-TIME CONSTANT. Each invocation is a single Go
//     `const` string with its arguments separated by U+001F (see argvDpkgList
//     and friends). A Go constant cannot be reassigned, appended to, or
//     patched at runtime by any code in any package. queryID.argv() splits a
//     fresh slice off one of those constants and returns it; there is no
//     table to edit and no package-level variable to overwrite.
//   - THE EXEC WRAPPER TAKES A CLOSED ENUM. runQuery's only selector is an
//     unexported queryID whose members are the four enumeration queries above.
//     queryID is unexported, so no other package can even name a fifth value,
//     and argv() returns nil for one — which runQuery refuses.
//   - THERE IS EXACTLY ONE EXEC CALL SITE, in runQuery, in this file. dpkg.go,
//     rpm.go and apk.go are pure parsers and do not import os/exec.
//   - NO SHELL. exec.CommandContext is handed a resolved absolute path and an
//     argument vector. There is no `sh -c`, so no quoting, expansion,
//     substitution or `;` chaining is reachable — which is also why the argv
//     constants carry no shell quotes even though research/12 §2 shows them
//     with quotes; the quotes there are an artifact of pasting into a shell.
//   - NO $PATH. resolveBinary searches a constant list of absolute system
//     directories, so an operator (or an attacker) who controls PATH cannot
//     redirect `rpm` at something else. The child's environment is replaced,
//     not inherited.
//
// collect_test.go then walks this package's own AST and fails if a second
// process-spawning REFERENCE appears, if any file writes to the filesystem, if
// a command line outside the allowlist is spelled, if a shell is named, or if
// argv() stops being a switch over those constants. Its spawn analyser
// resolves identity through each file's import table rather than matching the
// source spelling, because an alias, a dot import and a function value are
// three ways to spell the same call and A.12's review defeated the previous
// guard with all three. It carries negative controls: synthetic sources
// containing `apk add`, `rpm -U`, `dpkg -i`, `apt-get install -y`, an aliased
// `xc.Command`, a dot-imported `Command`, a function-value `spawn :=
// exec.Command` and an argv assembled from a parameter are fed to the same
// analysis, which must reject every one. A guard that has never failed has not
// been tested.
//
// # dpkg-query, not dpkg
//
// The Debian query is `dpkg-query`, a binary with NO mutating mode at all —
// `dpkg -i` installs, `dpkg-query -i` does not exist. `rpm` and `apk` do have
// mutating modes, which is what the verb guard is for.
//
// # Not a daemon
//
// research/12 Recommendation, "Host agent: don't build a daemon — build a
// collector": no resident process, no watchdog, no scheduler. Collect()
// returns; deploy/systemd/anvil-host-collector.service is Type=oneshot and a
// timer supplies the cadence. Exit criterion 14 requires that "no
// watchdog/loop code exists in internal/collector/host/", and
// TestCollectorIsNotAResidentDaemon enforces it against the AST.
//
// # WHAT "READ-ONLY" CLAIMS HERE, AND THE ONE PLACE THE WIDER CLAIM IS FALSE
//
// The claim this package can demonstrate is narrow and exact:
//
//	No mutating package-manager command line can be expressed by this
//	collector. Every argv it can execute is one of four enumeration forms
//	fixed at compile time, and collect_test.go checks each against an
//	ALLOWLIST of permitted argv forms rather than against a list of verbs
//	somebody remembered to deny.
//
// That is NOT the same as "running this collector changes no byte on the
// host". An earlier draft of this comment said the wider thing. It is DELETED
// rather than qualified, because it is false on distributions Anvil targets:
//
// RPMDB WRITE SIDE EFFECT. `rpm -qa` is not a filesystem-read-only operation
// on a Berkeley-DB-backed rpmdb. On RHEL/CentOS 7 and 8, SLES 12 and 15,
// Amazon Linux 2, and any host whose /var/lib/rpm holds BDB files (`Packages`,
// `Basenames`, …) rather than RHEL 9+/Fedora 33+'s `rpmdb.sqlite`, OPENING the
// database creates and updates the Berkeley DB shared-region files
// /var/lib/rpm/__db.001, __db.002 and __db.003 whenever the calling process
// can write that directory — which in practice means whenever it runs as root.
// A caller that cannot write /var/lib/rpm gets a private mapping and writes
// nothing, and the query still succeeds.
//
// Anvil cannot make rpm stop doing that. There is no rpm flag that opens the
// database without a writable environment, and this collector will not branch
// on the effective uid to decide: a privileged code path is a worse defect
// than the one it would paper over (TestNothingBranchesOnBeingRoot forbids it).
//
// SO THE MITIGATION IS NOT IN THIS PACKAGE, AND THIS IS WHERE IT LIVES:
// deploy/systemd/anvil-host-collector.service runs the collector under
// DynamicUser=yes (never uid 0) with ProtectSystem=strict (/var read-only at
// the kernel), and under that unit the side effect cannot occur — the write is
// refused before rpm attempts it and the query proceeds on the private
// mapping. cmd/anvil-host-collector's own doc comment repeats the requirement,
// because a launcher that reproduces neither property re-opens the hole.
//
// LIMITS OF THIS STATEMENT, so it is not over-read in the other direction:
// this is a documented property of rpm's BDB backend, recorded because A.12's
// review found the unconditional claim and could not reproduce the behaviour
// on a Windows development host. It has NOT been reproduced by this repository
// on a BDB host, and the sqlite and ndb backends' sidecar behaviour
// (`rpmdb.sqlite-wal`, `-shm`) has not been examined at all. Nothing is
// asserted about them in either direction.
//
// # Root-free
//
// research/12 §6: "Root is not required for the useful 90%" — Vuls documents
// Fast Scan as "Scan without root privilege, no dependencies". The three
// databases read here — /var/lib/dpkg/status, /var/lib/rpm and
// /lib/apk/db/installed — are world-readable, so no query needs privilege to
// succeed. Nothing in this package tests for, requests, or requires uid 0; the
// effective uid is RECORDED in the provenance so a reader can tell which run
// produced which coverage, and that is the only place it appears. The rpmdb
// note above is the reason a non-root run is worth more than a convenience.
//
// # Host findings are never remediable by an agent
//
// plan/00-SPINE.md S6 and Lane A exit criterion 21: `remediable_by_agent` is
// false for 100% of host-collector-sourced records, "with no code path, flag,
// or config key capable of overriding it". Here it is the untyped constant
// RemediableByAgent, which is false and cannot be otherwise; Inventory and
// FindingSeed expose it as a METHOD rather than a field so there is no
// assignable location to override. internal/ingest/cache's DDL carries the
// matching CHECK, and collect_test.go asserts the two still agree.
//
// # Trust
//
// Every string in the Inventory except Anvil's own labels came off a host
// Anvil does not control, through a parser, so it is record.TrustUntrusted
// (plan/00-SPINE.md S6: the field is required "on every string originating
// outside Anvil"). Each one passes through internal/ingest/sanitize before it
// is stored, and Collect fails closed if AssertSanitized then rejects it.
//
// # What this package does NOT do
//
// It does not match advisories (A.17's comparator does), does not open a
// database, and does not POST. It deliberately does not import
// internal/ingest/cache: that package links modernc.org/sqlite, and a
// collector shipped onto a customer's production server has no business
// carrying a SQL driver. The `finding`-column vocabulary it must agree with is
// asserted against cache's DDL by a TEST-ONLY import instead, so drift is
// caught without the dependency.
package host

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/Susquehanna-Syntax/Anvil/internal/ingest/sanitize"
	"github.com/Susquehanna-Syntax/Anvil/internal/record"
)

// ---------------------------------------------------------------------------
// Constants that are load-bearing rather than merely convenient
// ---------------------------------------------------------------------------

// RemediableByAgent is the value every record sourced from this collector
// carries for `remediable_by_agent`, and it is a constant because Lane A exit
// criterion 21 requires that no code path, flag or config key be capable of
// overriding it. A `const` is the only construct in Go that makes that claim
// true rather than asserted: there is no assignable location to write to.
//
// plan/00-SPINE.md S6 says host findings are false; the coding agent's write
// surface is the git repository only (research/12 Hard boundary #2), so
// handing it a host finding as actionable asks it to do something it cannot do
// and must not try.
const RemediableByAgent = false

// ReadOnly records, in the emitted provenance, the claim the package comment's
// "WHAT READ-ONLY CLAIMS HERE" section makes and no more: NO MUTATING PACKAGE
// MANAGER COMMAND LINE IS EXPRESSIBLE BY THIS COLLECTOR. It does not claim
// that a run changes no byte on the host — see RPMDB WRITE SIDE EFFECT in that
// section, which is why the wider sentence was deleted from this comment
// rather than softened.
//
// It is a constant for the same reason RemediableByAgent is: a field would be
// a place to write `false`.
const ReadOnly = true

// InventorySchemaVersion is the version of the Inventory shape below. It is
// emitted so a consumer reading an archived inventory can tell which shape it
// is looking at.
const InventorySchemaVersion = 1

// Collector is the `finding.collector` value for rows derived from this
// collector. It duplicates internal/ingest/cache's CollectorHost by VALUE
// rather than by import — see the package comment on why the SQLite-linking
// cache package is not a dependency of a production-server collector — and
// TestCollectorValueMatchesTheCacheSchema imports cache from the test binary
// to prove the two have not drifted.
const Collector = "host"

// The ecosystem vocabulary for host packages, matching the values
// internal/ingest/cache's `affected.ecosystem` / `finding.ecosystem` columns
// document ('deb' | 'rpm' | 'apk' | ...). Ecosystem is not one of the record
// contract's six frozen enums, so declaring the Lane-A-local members here does
// not violate plan/IMPLEMENTATION-PLAN.md §6's single-owner rule — exactly as
// cache declares CollectorHost. They exist so no caller writes a bare literal.
const (
	// EcosystemDeb is Debian/Ubuntu and derivatives, enumerated by dpkg-query.
	EcosystemDeb = "deb"
	// EcosystemRPM is RHEL/Fedora/SUSE and derivatives, enumerated by rpm.
	EcosystemRPM = "rpm"
	// EcosystemAPK is Alpine and derivatives, enumerated by apk.
	EcosystemAPK = "apk"
)

// DefaultTimeout bounds a single package-manager query. A collector that hangs
// on a wedged rpmdb is a collector that never reports, and the systemd unit's
// MemoryHigh= throttle makes a slow run slower still, so the bound must exist.
const DefaultTimeout = 2 * time.Minute

// maxQueryOutputBytes caps how much of one query's stdout is retained. A large
// Debian host emits a few megabytes; the cap is generous enough that reaching
// it means something is wrong, and it exists so that a hostile or corrupt
// package database cannot drive the collector past the unit's MemoryMax= and
// summon the OOM killer — which would make an Anvil scan CAUSE an incident
// rather than report one (research/12 §6 design note).
const maxQueryOutputBytes = 64 << 20

// maxStderrBytes caps the diagnostic tail retained from a failing query.
const maxStderrBytes = 4 << 10

// queryWaitDelay bounds how long cmd.Wait will keep waiting after the context
// deadline has killed the direct child.
//
// It is NOT redundant with the deadline. cmd.Stdout and cmd.Stderr here are
// io.Writers rather than *os.File, so os/exec allocates a pipe and a copying
// goroutine, and Wait blocks until every writer end of that pipe closes.
// Killing the child does not close a copy the child's own GRANDCHILD inherited
// — a package manager that forked a helper — so without WaitDelay the deadline
// bounds the child and not the call, and runQuery hangs exactly where
// DefaultTimeout's comment says it must not.
const queryWaitDelay = 5 * time.Second

// ---------------------------------------------------------------------------
// The closed set of read-only invocations
// ---------------------------------------------------------------------------

// argvSep separates the elements of an argv constant. U+001F UNIT SEPARATOR is
// not a legal byte in a package name, a version, a dpkg format directive or an
// rpm query tag, so no argument can smuggle a split past it.
const argvSep = "\x1f"

// dpkgFormat is the --showformat given to dpkg-query, from research/12 §2
// ("Native queries"). db:Status-Abbrev is what lets parseDpkg drop the `rc`
// rows — packages removed but with config files left behind, which are NOT
// installed and would otherwise be reported as vulnerable software that is not
// present.
//
// research/12 shows this as `-f='...'` because it is showing a shell command
// line. There is no shell here, so there are no quotes: the format is one
// argv element.
const dpkgFormat = "${binary:Package}\t${Version}\t${Architecture}\t${db:Status-Abbrev}\n"

// rpmFormat is the --queryformat given to rpm, from research/12 §2. EPOCH
// prints "(none)" when the package has none; normaliseRPMVersion handles that.
const rpmFormat = "%{NAME}\t%{EPOCH}:%{VERSION}-%{RELEASE}\t%{ARCH}\n"

// THE COMPLETE SET OF COMMAND LINES THIS BINARY CAN EXECUTE.
//
// Each is one Go constant holding a whole argv. Constants are fixed at compile
// time: no code in this package or any other can append an argument, rewrite
// an element, or substitute a different binary, because there is no storage to
// write to. This is the "compile-time constant list" A.9's Expected output
// schema asks for, and it is the list collect_test.go greps.
//
// Every verb here is an ENUMERATION verb. dpkg-query has no mutating mode at
// all. `rpm -qa` queries. `apk list` and `apk info` query — note that
// `--installed` is a filter on `apk list` and is not the verb `install`, a
// distinction the verb guard makes by comparing whole tokens.
const (
	// argvDpkgList enumerates installed Debian packages.
	argvDpkgList = "dpkg-query" + argvSep + "-W" + argvSep + "-f" + argvSep + dpkgFormat
	// argvRPMList enumerates installed RPM packages.
	argvRPMList = "rpm" + argvSep + "-qa" + argvSep + "--qf" + argvSep + rpmFormat
	// argvAPKList enumerates installed Alpine packages WITH their
	// architecture. Preferred over argvAPKInfo, which does not report one.
	argvAPKList = "apk" + argvSep + "list" + argvSep + "--installed"
	// argvAPKInfo is the fallback for apk builds predating `apk list`.
	argvAPKInfo = "apk" + argvSep + "info" + argvSep + "-v"
)

// queryID names one of those invocations. It is UNEXPORTED, so no package
// outside this one can construct a query at all, let alone a new one.
type queryID int

const (
	queryDpkgList queryID = iota
	queryRPMList
	queryAPKList
	queryAPKInfo
	// numQueries is the count, not a query. argv() returns nil for it.
	numQueries
)

// argv returns a fresh copy of the complete command line for q: element 0 is
// the binary name and the rest are its arguments.
//
// It is a switch over a closed set of constants and nothing else. There is no
// append, no formatting, no environment lookup and no caller-supplied input:
// the only way to change what this binary can execute is to edit a constant
// above and get the change past collect_test.go's verb guard and past A.12's
// review. An unknown queryID yields nil, which runQuery refuses.
func (q queryID) argv() []string {
	switch q {
	case queryDpkgList:
		return strings.Split(argvDpkgList, argvSep)
	case queryRPMList:
		return strings.Split(argvRPMList, argvSep)
	case queryAPKList:
		return strings.Split(argvAPKList, argvSep)
	case queryAPKInfo:
		return strings.Split(argvAPKInfo, argvSep)
	}
	return nil
}

// ecosystem is the package ecosystem q enumerates.
func (q queryID) ecosystem() string {
	switch q {
	case queryDpkgList:
		return EcosystemDeb
	case queryRPMList:
		return EcosystemRPM
	case queryAPKList, queryAPKInfo:
		return EcosystemAPK
	}
	return ""
}

// String renders the invocation for the coverage report and for error
// messages. It is display text derived from the same constants.
func (q queryID) String() string {
	argv := q.argv()
	if len(argv) == 0 {
		return "<unknown query>"
	}
	return strings.Join(argv, " ")
}

// parse dispatches q's raw stdout to its parser. The parsers live in dpkg.go,
// rpm.go and apk.go and are pure functions over bytes.
func (q queryID) parse(out []byte) ([]Package, parseReport) {
	switch q {
	case queryDpkgList:
		return parseDpkg(out)
	case queryRPMList:
		return parseRPM(out)
	case queryAPKList:
		return parseAPKList(out)
	case queryAPKInfo:
		return parseAPKInfo(out)
	}
	return nil, parseReport{Degraded: true}
}

// ---------------------------------------------------------------------------
// Where binaries are looked up — deliberately not $PATH
// ---------------------------------------------------------------------------

// pathListSep separates entries in the two constant path lists below.
const pathListSep = ":"

// binSearchPath is the constant, absolute list of directories a package-query
// binary may be resolved from. $PATH is NOT consulted: PATH is attacker- and
// operator-controlled, and resolving `rpm` through it would let an unprivileged
// user on the host decide what this collector executes.
const binSearchPath = "/usr/bin" + pathListSep + "/bin" + pathListSep + "/usr/sbin" + pathListSep + "/sbin"

// osReleaseSearchPath is the constant list of os-release locations, in the
// order os-release(5) specifies: /etc/os-release first, /usr/lib/os-release as
// the vendor fallback.
const osReleaseSearchPath = "/etc/os-release" + pathListSep + "/usr/lib/os-release"

// childEnv is the COMPLETE environment handed to a query. The parent
// environment is not inherited: LC_ALL/LANG are pinned so a locale cannot
// reformat rpm's output out from under the parser, and PATH is pinned so a
// query that spawns a helper cannot be redirected either.
const childEnv = "LC_ALL=C" + argvSep + "LANG=C" + argvSep + "PATH=" + binSearchPath

// errBinaryNotFound reports that a package manager is simply not installed,
// which is the ordinary case on any host (a Debian box has no rpm). It is
// distinguished from a query failure so the coverage report can say "absent"
// rather than "failed".
var errBinaryNotFound = errors.New("host: package-query binary not found")

// ErrNoPackageManager reports that no supported package manager was found at
// all. The Inventory is still returned alongside it, populated with a coverage
// report: Lane A exit criterion 20's rule is that a run never reports a silent
// "clean", and an empty package list with no error would be exactly that.
var ErrNoPackageManager = errors.New("host: no supported package manager found on this host")

// resolveBinary finds name in binSearchPath and returns its absolute path.
//
// It requires a regular file with an execute bit. A directory, a socket or a
// non-executable file named `rpm` is skipped rather than executed.
//
// The returned path is ABSOLUTE, which is also what stops Go's os/exec from
// consulting $PATH: exec.Command only runs LookPath for a name containing no
// path separator. Resolving here rather than there is what makes the search
// list a constant instead of an environment variable.
func resolveBinary(name string) (string, error) {
	// The name comes from an argv constant, so it is one of three bare
	// binary names — but a bare name is a precondition of the search below,
	// not an observation about it, so it is checked rather than assumed.
	if name == "" || strings.ContainsAny(name, `/\`) || name == "." || name == ".." {
		return "", fmt.Errorf("host: %q is not a bare binary name; the search list is a constant and takes no paths", name)
	}
	for _, dir := range strings.Split(binSearchPath, pathListSep) {
		candidate := filepath.Join(dir, name)
		info, err := os.Stat(candidate)
		if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o111 == 0 {
			continue
		}
		return candidate, nil
	}
	return "", fmt.Errorf("%w: %s (searched %s)", errBinaryNotFound, name, binSearchPath)
}

// ---------------------------------------------------------------------------
// The one exec call site
// ---------------------------------------------------------------------------

// runQuery executes one read-only enumeration query and returns its stdout.
//
// THIS IS THE ONLY FUNCTION IN THIS PACKAGE THAT EXECUTES ANYTHING, and its
// only selector is a queryID. It takes no binary name, no subcommand, no
// argument slice and no format string, so there is no channel through which a
// caller — in this package or any other, now or later — can influence what
// runs. collect_test.go fails the build's test run if a second exec call site
// appears anywhere in the package.
//
// The child gets: an absolute resolved path, an argv split off a constant, a
// replaced environment, a closed stdin, a working directory of "/", a capped
// stdout and a deadline.
func runQuery(ctx context.Context, q queryID, timeout time.Duration) ([]byte, error) {
	argv := q.argv()
	if len(argv) == 0 {
		return nil, fmt.Errorf("host: query %d has no command line; refusing to execute", int(q))
	}
	bin, err := resolveBinary(argv[0])
	if err != nil {
		return nil, err
	}
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, bin, argv[1:]...)
	cmd.Env = strings.Split(childEnv, argvSep)
	cmd.Dir = string(filepath.Separator)
	cmd.Stdin = nil
	stdout := &cappedBuffer{limit: maxQueryOutputBytes}
	stderr := &cappedBuffer{limit: maxStderrBytes}
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	cmd.WaitDelay = queryWaitDelay

	runErr := cmd.Run()
	if runErr != nil {
		msg := strings.TrimSpace(stderr.buf.String())
		if msg == "" {
			msg = "(no stderr)"
		}
		clean, _ := sanitize.Sanitize(msg)
		return stdout.buf.Bytes(), fmt.Errorf("host: %q failed: %w: %s", q.String(), runErr, clean)
	}
	if stdout.truncated {
		return stdout.buf.Bytes(), fmt.Errorf("host: %q produced more than %d bytes of output; refusing the remainder", q.String(), maxQueryOutputBytes)
	}
	return stdout.buf.Bytes(), nil
}

// cappedBuffer accumulates at most limit bytes and reports whether more
// arrived. It never grows past the cap, which is the point: the systemd unit
// throttles at MemoryHigh=256M and kills at MemoryMax=512M.
type cappedBuffer struct {
	buf       bytes.Buffer
	limit     int
	truncated bool
}

func (c *cappedBuffer) Write(p []byte) (int, error) {
	remaining := c.limit - c.buf.Len()
	if remaining <= 0 {
		c.truncated = true
		return len(p), nil
	}
	if len(p) > remaining {
		c.buf.Write(p[:remaining])
		c.truncated = true
		return len(p), nil
	}
	c.buf.Write(p)
	return len(p), nil
}

var _ io.Writer = (*cappedBuffer)(nil)

// ---------------------------------------------------------------------------
// The emitted record
// ---------------------------------------------------------------------------

// Package is one installed package. This is the `{ecosystem, package, version,
// arch}` shape A.9's Expected output schema names, with JSON keys matching
// internal/ingest/cache's `finding` column names where they correspond.
type Package struct {
	// Ecosystem is EcosystemDeb, EcosystemRPM or EcosystemAPK.
	Ecosystem string `json:"ecosystem"`
	// Name is the package name, sanitised. For Debian multi-arch, the
	// `:arch` qualifier is moved into Arch rather than left on the name, so
	// that a comparator matching advisory package names does not miss
	// `libc6` because the host called it `libc6:amd64`.
	Name string `json:"package"`
	// Version is the installed version, verbatim from the package database
	// apart from sanitising and the RPM epoch normalisation documented on
	// normaliseRPMVersion. It is NOT parsed or re-rendered here: version
	// comparison is A.17's, and a collector that reformats a version has
	// already lost the comparison.
	Version string `json:"version"`
	// Arch is the package architecture, empty when the source did not report
	// one (`apk info -v` does not).
	Arch string `json:"arch,omitempty"`
}

// OSRelease is the subset of os-release(5) Lane A matching needs: `ID` and
// `VERSION_ID` select the distro advisory feed, and `ID_LIKE` is the fallback
// when a derivative has no feed of its own.
type OSRelease struct {
	ID              string   `json:"id,omitempty"`
	IDLike          []string `json:"idLike,omitempty"`
	VersionID       string   `json:"versionId,omitempty"`
	VersionCodename string   `json:"versionCodename,omitempty"`
	Name            string   `json:"name,omitempty"`
	PrettyName      string   `json:"prettyName,omitempty"`
	// Path is the file the fields above were read from, or empty if none was
	// readable. An empty Path with a non-empty Packages list means the host
	// is enumerable but unidentifiable, which a consumer must be able to see.
	Path string `json:"path,omitempty"`
}

// FamilyStatus is what happened to one package-manager family during a run.
type FamilyStatus string

const (
	// FamilyAbsent: the binary is not installed on this host. Expected.
	FamilyAbsent FamilyStatus = "absent"
	// FamilyCollected: the query ran and its output was parsed.
	FamilyCollected FamilyStatus = "collected"
	// FamilyFailed: the binary exists but the query did not complete. The
	// host may have packages this run did not see.
	FamilyFailed FamilyStatus = "failed"
)

// FamilyCoverage is the per-family outcome. plan/00-SPINE.md S6 requires
// `inventory_provenance` and Lane A exit criterion 20 requires that a run
// never report a silent "clean": a zero-package inventory that says every
// family was absent means something completely different from one that says
// rpm failed, and a consumer must not have to guess which it is holding.
type FamilyCoverage struct {
	Ecosystem string       `json:"ecosystem"`
	Query     string       `json:"query"`
	Status    FamilyStatus `json:"status"`
	Packages  int          `json:"packages"`
	// Lines and Skipped come from the parser: Skipped > 0 means output was
	// seen that this parser did not understand.
	Lines   int `json:"lines"`
	Skipped int `json:"skipped"`
	// NotInstalled counts rows the package database reported in a
	// not-installed state (dpkg's `rc`), which are correctly excluded.
	NotInstalled int `json:"notInstalled"`
	// Degraded is the parser's own verdict that it did not fully understand
	// this family's output, or collectFamily's that an earlier entry in the
	// fallback chain failed before a later one succeeded.
	Degraded bool `json:"degraded"`
	// Err is the sanitised failure reason: the reason the family failed when
	// Status is FamilyFailed, and — when Status is FamilyCollected — the
	// reason the PREFERRED query failed before a fallback carried the family.
	// A collected family with a non-empty Err is a family whose best query did
	// not run, which a consumer must be able to see.
	Err string `json:"error,omitempty"`
}

// Provenance is the `inventory_provenance` plan/00-SPINE.md S6 requires.
type Provenance struct {
	// Method is always the native-query method; this collector has one.
	Method string `json:"method"`
	// ReadOnly is the constant ReadOnly, emitted so a downstream reader sees
	// the claim in the data and not only in the documentation. Read its
	// declaration for what it does and does not assert: it says no mutating
	// command line is expressible, NOT that the run wrote nothing anywhere.
	ReadOnly bool `json:"readOnly"`
	// Hostname is the host's own name, sanitised, or empty if unavailable.
	Hostname string `json:"hostname,omitempty"`
	// EUID is the effective uid the collection ran under, or -1 where the OS
	// has no such concept. It is REPORTED, never REQUIRED: research/12 §6
	// records that root is not needed for the useful 90%, and no code path
	// here branches on this value.
	EUID int `json:"euid"`
	// GOOS is the operating system the collector was built for.
	GOOS string `json:"goos"`
	// Timeout is the per-query deadline that was in force.
	Timeout string `json:"queryTimeout"`
}

// Inventory is one host's package inventory: the artifact A.9 produces and
// A.17's version comparator consumes.
//
// It is not a finding and carries no fingerprint. anvil-fp/v1 is defined once,
// in internal/record (FINGERPRINT-SPEC.md is authoritative), and Lane A must
// not invent a second one — two producers emitting different digests under one
// name breaks regression matching forever with nothing surfacing it
// (plan/00-SPINE.md S6).
type Inventory struct {
	SchemaVersion int    `json:"schemaVersion"`
	Collector     string `json:"collector"`
	// Trust is record.TrustUntrusted, always. Every package name, version
	// and os-release value below came off a host Anvil does not control.
	// Anvil fetched and parsed them, and none of that changes who wrote the
	// bytes (plan/00-SPINE.md S6).
	Trust      record.Trust     `json:"trust"`
	OSRelease  OSRelease        `json:"osRelease"`
	Packages   []Package        `json:"packages"`
	Coverage   []FamilyCoverage `json:"coverage"`
	Provenance Provenance       `json:"provenance"`
	// ParseDegraded is true when any output line was not understood or any
	// query failed. plan/00-SPINE.md S6 lists `parse_degraded` as required,
	// and internal/ingest/cache carries the matching column: degraded data is
	// PERSISTED and flagged, never dropped.
	ParseDegraded bool `json:"parseDegraded"`
	// Sanitizer is internal/ingest/sanitize's per-category removal counts
	// across every string in this inventory. A.3's contract forbids dropping
	// characters without a count.
	Sanitizer map[string]int `json:"sanitizer,omitempty"`
	// CollectedAt and AsOf are the same instant for a fresh collection;
	// StalenessSeconds is therefore 0 here and grows downstream.
	CollectedAt      time.Time `json:"collectedAt"`
	AsOf             time.Time `json:"asOf"`
	StalenessSeconds int       `json:"stalenessSeconds"`
}

// RemediableByAgent reports the constant RemediableByAgent — false.
//
// It is a METHOD and not a field on purpose. A field is an assignable
// location, and Lane A exit criterion 21 requires that no code path, flag or
// config key be capable of setting this true. A method over an untyped
// constant has no such location.
func (Inventory) RemediableByAgent() bool { return RemediableByAgent }

// MarshalJSON emits the Inventory with `remediable_by_agent: false` included,
// so that the guarantee travels with the serialised record rather than
// depending on every consumer knowing to call the method.
func (inv Inventory) MarshalJSON() ([]byte, error) {
	type alias Inventory
	return json.Marshal(struct {
		alias
		RemediableByAgent bool `json:"remediable_by_agent"`
	}{alias(inv), RemediableByAgent})
}

// FindingSeed is the subset of internal/ingest/cache's `finding` columns this
// collector is entitled to fill. It is deliberately NOT a finding: `source`,
// `source_id` and the decision that a package is affected at all belong to
// A.17's version comparator, which is the only component that has read an
// advisory.
type FindingSeed struct {
	Collector        string `json:"collector"`
	Ecosystem        string `json:"ecosystem"`
	Package          string `json:"package"`
	InstalledVersion string `json:"installed_version"`
	// InventoryTrust describes the PACKAGE AND VERSION STRINGS, which came
	// from outside Anvil and are therefore record.TrustUntrusted. It is
	// deliberately not called `anvil_trust`: the `finding` row's own
	// anvil_trust is A.17's to set once the comparator has concluded
	// something, and cache.FindingTrustDefault is the value for that.
	InventoryTrust   record.Trust `json:"inventory_trust"`
	AsOf             time.Time    `json:"as_of"`
	StalenessSeconds int          `json:"staleness_seconds"`
	DetectedAt       time.Time    `json:"detected_at"`
}

// RemediableByAgent reports the constant RemediableByAgent — false. See
// Inventory.RemediableByAgent for why this is a method.
func (FindingSeed) RemediableByAgent() bool { return RemediableByAgent }

// MarshalJSON emits the seed with `remediable_by_agent: false` included.
//
// This is the artifact that CROSSES to A.17 — the Inventory is this
// collector's own record, the seed is what another component consumes — so it
// is the one that most needs the guarantee to travel in the bytes rather than
// in a method a consumer has to know to call. A.12's review found the field on
// Inventory and missing here, which is the wrong way round.
func (seed FindingSeed) MarshalJSON() ([]byte, error) {
	type alias FindingSeed
	return json.Marshal(struct {
		alias
		RemediableByAgent bool `json:"remediable_by_agent"`
	}{alias(seed), RemediableByAgent})
}

// FindingSeeds projects the inventory into one seed per package, in the
// inventory's own deterministic order.
func (inv Inventory) FindingSeeds() []FindingSeed {
	seeds := make([]FindingSeed, 0, len(inv.Packages))
	for _, p := range inv.Packages {
		seeds = append(seeds, FindingSeed{
			Collector:        Collector,
			Ecosystem:        p.Ecosystem,
			Package:          p.Name,
			InstalledVersion: p.Version,
			InventoryTrust:   record.TrustUntrusted,
			AsOf:             inv.AsOf,
			StalenessSeconds: inv.StalenessSeconds,
			DetectedAt:       inv.CollectedAt,
		})
	}
	return seeds
}

// ---------------------------------------------------------------------------
// Collection
// ---------------------------------------------------------------------------

// Options are the caller's knobs. THERE ARE TWO AND THEY ARE A DEADLINE AND A
// CLOCK. There is deliberately no binary path, no argument list, no extra-args
// escape hatch and no "mode": plan/00-SPINE.md S7's "not behind a flag" is a
// statement about what may exist, and TestOptionsCarriesNoCommandSurface
// fails if a third field is ever added here.
type Options struct {
	// Timeout bounds one package-manager query. Zero means DefaultTimeout.
	Timeout time.Duration
	// Now supplies the clock, so a test gets a deterministic inventory. Nil
	// means time.Now.
	Now func() time.Time
}

// collector is the assembled run. Its seams are unexported and in-package,
// which is what lets collect_test.go exercise parsing and assembly on a host
// with no dpkg — note that `run`'s signature is (context, queryID), so even
// this seam cannot express an argv, and any implementation of it that wanted
// to execute something would have to call os/exec itself, which the AST guard
// forbids outside runQuery.
type collector struct {
	run            func(ctx context.Context, q queryID) ([]byte, error)
	osReleaseFiles []string
	now            func() time.Time
	hostname       func() (string, error)
	euid           func() int
	timeout        time.Duration
}

func newCollector(opts Options) *collector {
	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	now := opts.Now
	if now == nil {
		now = time.Now
	}
	return &collector{
		run: func(ctx context.Context, q queryID) ([]byte, error) {
			return runQuery(ctx, q, timeout)
		},
		osReleaseFiles: strings.Split(osReleaseSearchPath, pathListSep),
		now:            now,
		hostname:       os.Hostname,
		euid:           os.Geteuid,
		timeout:        timeout,
	}
}

// familyPlan is the fixed order in which families are attempted, and the
// fallback chain within a family. It is a function returning a fresh slice
// rather than a package-level variable so that nothing can reorder or extend
// it at runtime.
func familyPlan() [][]queryID {
	return [][]queryID{
		{queryDpkgList},
		{queryRPMList},
		{queryAPKList, queryAPKInfo},
	}
}

// Collect enumerates the host's installed packages and returns the inventory.
// It runs to completion and returns; it does not loop, wait, schedule or
// linger (research/12: build a collector, not a daemon).
//
// It returns ErrNoPackageManager when no supported package manager was found,
// AND the Inventory alongside it, populated with a coverage report. A caller
// must never read a zero-length Packages slice as "this host is clean": that
// is what Coverage is for.
//
// A family that fails does not fail the run — the other families' results are
// still worth having — but it is recorded as FamilyFailed and sets
// ParseDegraded.
func Collect(ctx context.Context, opts Options) (*Inventory, error) {
	if ctx == nil {
		return nil, errors.New("host: Collect requires a non-nil context")
	}
	return newCollector(opts).collect(ctx)
}

func (c *collector) collect(ctx context.Context) (*Inventory, error) {
	now := c.now().UTC()
	var stats sanitize.SanitizeStats

	inv := &Inventory{
		SchemaVersion: InventorySchemaVersion,
		Collector:     Collector,
		Trust:         record.TrustUntrusted,
		Packages:      []Package{},
		Coverage:      []FamilyCoverage{},
		Provenance: Provenance{
			Method:   "native-package-query",
			ReadOnly: ReadOnly,
			EUID:     c.euid(),
			GOOS:     goos(),
			Timeout:  c.timeout.String(),
		},
		CollectedAt:      now,
		AsOf:             now,
		StalenessSeconds: 0,
	}

	if name, err := c.hostname(); err == nil {
		clean, st := sanitize.Sanitize(name)
		stats.Merge(st)
		inv.Provenance.Hostname = clean
	}

	osr, osStats, osDegraded := c.readOSRelease()
	stats.Merge(osStats)
	inv.OSRelease = osr
	if osDegraded {
		inv.ParseDegraded = true
	}

	anyPresent := false
	for _, chain := range familyPlan() {
		cov, pkgs, chainStats, present := c.collectFamily(ctx, chain)
		stats.Merge(chainStats)
		inv.Coverage = append(inv.Coverage, cov)
		inv.Packages = append(inv.Packages, pkgs...)
		if present {
			anyPresent = true
		}
		if cov.Status == FamilyFailed || cov.Skipped > 0 || cov.Degraded {
			inv.ParseDegraded = true
		}
	}

	sortPackages(inv.Packages)
	if counts := stats.Counts(); len(counts) > 0 {
		inv.Sanitizer = counts
	}

	// Fail closed. A.3's AssertSanitized is the check that a string actually
	// went through Sanitize; running it over the assembled record means a
	// future field added without sanitising is caught here rather than in the
	// cache, in a prompt, or not at all.
	if err := inv.assertSanitized(); err != nil {
		return nil, err
	}
	if !anyPresent {
		return inv, ErrNoPackageManager
	}
	return inv, nil
}

// collectFamily runs one family's fallback chain: the first query that
// SUCCEEDS is the one used, and a later entry is a fallback for an older
// package-manager build, not a second source of the same packages.
//
// The chain advances on ANY error, not only on a missing binary. A.12's review
// found that advancing only on errBinaryNotFound made argvAPKInfo unreachable
// under every possible input: the fallback exists for apk-tools builds that
// predate `apk list`, and such a build HAS the apk binary — it fails with
// "ERROR: Not a valid command: list" and a non-zero exit, which is not
// errBinaryNotFound. Alpine hosts running those builds reported zero packages
// through a documented fallback that could never fire.
//
// What the two error kinds still decide is the STATUS, which is the thing a
// consumer reads:
//
//   - every entry said its binary was missing        -> FamilyAbsent, present=false
//   - some entry ran and failed, none then succeeded -> FamilyFailed, present=true
//   - some entry succeeded                           -> FamilyCollected
//
// A failure BEFORE a success is not discarded: it sets Degraded and is
// reported in Err, because "the fallback carried this family" is exactly the
// kind of thing exit criterion 20 forbids a run from swallowing.
func (c *collector) collectFamily(ctx context.Context, chain []queryID) (FamilyCoverage, []Package, sanitize.SanitizeStats, bool) {
	var stats sanitize.SanitizeStats
	cov := FamilyCoverage{Status: FamilyAbsent}
	if len(chain) == 0 {
		return cov, nil, stats, false
	}
	cov.Ecosystem = chain[0].ecosystem()
	cov.Query = chain[0].String()

	// firstErr is the first error from a query whose binary EXISTED. It is
	// what makes the family "present but failed" rather than "absent", and it
	// is what a successful fallback still has to report.
	var firstErr error
	var firstErrQuery queryID
	for _, q := range chain {
		out, err := c.run(ctx, q)
		if err != nil {
			if !errors.Is(err, errBinaryNotFound) && firstErr == nil {
				firstErr, firstErrQuery = err, q
			}
			continue
		}
		pkgs, rep := q.parse(out)
		cleaned, cleanStats := sanitisePackages(pkgs)
		stats.Merge(cleanStats)
		cov.Query = q.String()
		cov.Status = FamilyCollected
		cov.Packages = len(cleaned)
		cov.Lines = rep.Lines
		cov.Skipped = rep.Skipped
		cov.NotInstalled = rep.NotInstalled
		cov.Degraded = rep.Degraded || len(cleaned) != len(pkgs)
		if firstErr != nil {
			// The preferred query failed and a fallback carried the family.
			// The packages are real, but the run is not clean and must not
			// read as clean.
			cov.Degraded = true
			clean, st := sanitize.Sanitize(firstErr.Error())
			stats.Merge(st)
			cov.Err = clean
		}
		return cov, cleaned, stats, true
	}
	if firstErr != nil {
		// The binary exists, so the family is PRESENT even though no query
		// completed; that is exactly the case a coverage report has to keep
		// distinct from "absent".
		cov.Query = firstErrQuery.String()
		cov.Status = FamilyFailed
		clean, st := sanitize.Sanitize(firstErr.Error())
		stats.Merge(st)
		cov.Err = clean
		return cov, nil, stats, true
	}
	// Every query in the chain reported its binary missing: the family is not
	// installed on this host, which is the ordinary case and not an error.
	// cov.Status is already FamilyAbsent.
	return cov, nil, stats, false
}

// sanitisePackages runs every externally-sourced field through A.3's
// Sanitize. Package names and versions are the fields the comparator matches
// on, and research/12's own reasoning applies: a zero-width character inside
// a package name means the comparator MISSES a match, which is quieter than
// an injection and worse for Lane A.
func sanitisePackages(pkgs []Package) ([]Package, sanitize.SanitizeStats) {
	var stats sanitize.SanitizeStats
	out := make([]Package, 0, len(pkgs))
	for _, p := range pkgs {
		name, st := sanitize.Sanitize(p.Name)
		stats.Merge(st)
		version, st := sanitize.Sanitize(p.Version)
		stats.Merge(st)
		arch, st := sanitize.Sanitize(p.Arch)
		stats.Merge(st)
		if name == "" || version == "" {
			// Sanitising emptied a field the comparator needs. Dropping the
			// row silently would be the failure A.3 forbids; the removal is
			// counted in stats, which the Inventory carries.
			continue
		}
		out = append(out, Package{Ecosystem: p.Ecosystem, Name: name, Version: version, Arch: arch})
	}
	return out, stats
}

// sortPackages gives the inventory a total, deterministic order so that two
// runs over an unchanged host produce byte-identical output — the property
// Lane A exit criterion 18 asks of the comparator and that a diffable
// inventory needs for the same reason.
func sortPackages(pkgs []Package) {
	sort.Slice(pkgs, func(i, j int) bool {
		a, b := pkgs[i], pkgs[j]
		if a.Ecosystem != b.Ecosystem {
			return a.Ecosystem < b.Ecosystem
		}
		if a.Name != b.Name {
			return a.Name < b.Name
		}
		if a.Version != b.Version {
			return a.Version < b.Version
		}
		return a.Arch < b.Arch
	})
}

// assertSanitized re-checks every externally-sourced string in the assembled
// record. It is the fail-closed half of A.3's contract: Sanitize() is what a
// writer is supposed to call, and AssertSanitized() is what proves it did.
func (inv *Inventory) assertSanitized() error {
	fields := map[string]string{
		"provenance.hostname":       inv.Provenance.Hostname,
		"osRelease.id":              inv.OSRelease.ID,
		"osRelease.versionId":       inv.OSRelease.VersionID,
		"osRelease.versionCodename": inv.OSRelease.VersionCodename,
		"osRelease.name":            inv.OSRelease.Name,
		"osRelease.prettyName":      inv.OSRelease.PrettyName,
	}
	for i, v := range inv.OSRelease.IDLike {
		fields[fmt.Sprintf("osRelease.idLike[%d]", i)] = v
	}
	for i, p := range inv.Packages {
		fields[fmt.Sprintf("packages[%d].package", i)] = p.Name
		fields[fmt.Sprintf("packages[%d].version", i)] = p.Version
		fields[fmt.Sprintf("packages[%d].arch", i)] = p.Arch
	}
	for i, c := range inv.Coverage {
		fields[fmt.Sprintf("coverage[%d].error", i)] = c.Err
	}
	if err := sanitize.AssertAllSanitized(fields); err != nil {
		return fmt.Errorf("host: refusing to emit an unsanitised inventory: %w", err)
	}
	return nil
}

// ---------------------------------------------------------------------------
// os-release
// ---------------------------------------------------------------------------

// readOSRelease reads the first readable file in osReleaseFiles and parses it
// per os-release(5). A missing file is not an error: a host with no
// os-release is still enumerable, and OSRelease.Path stays empty so the
// consumer can see that the distro is unidentified rather than assume one.
func (c *collector) readOSRelease() (OSRelease, sanitize.SanitizeStats, bool) {
	var stats sanitize.SanitizeStats
	for _, path := range c.osReleaseFiles {
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		osr, st, degraded := parseOSRelease(data)
		stats.Merge(st)
		osr.Path = path
		return osr, stats, degraded
	}
	return OSRelease{}, stats, false
}

// parseOSRelease parses os-release(5) KEY=VALUE lines. Only the keys Lane A
// matching needs are kept; the rest are ignored rather than carried, because
// an inventory is not a place to accumulate unbounded host-controlled text.
func parseOSRelease(data []byte) (OSRelease, sanitize.SanitizeStats, bool) {
	var osr OSRelease
	var stats sanitize.SanitizeStats
	degraded := false

	for _, line := range splitLines(data) {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, rawValue, found := strings.Cut(line, "=")
		if !found {
			degraded = true
			continue
		}
		key = strings.TrimSpace(key)
		value, st := sanitize.Sanitize(unquoteOSRelease(strings.TrimSpace(rawValue)))
		stats.Merge(st)
		switch key {
		case "ID":
			osr.ID = value
		case "ID_LIKE":
			for _, f := range strings.Fields(value) {
				osr.IDLike = append(osr.IDLike, f)
			}
		case "VERSION_ID":
			osr.VersionID = value
		case "VERSION_CODENAME":
			osr.VersionCodename = value
		case "NAME":
			osr.Name = value
		case "PRETTY_NAME":
			osr.PrettyName = value
		}
	}
	return osr, stats, degraded
}

// unquoteOSRelease undoes os-release(5)'s shell-compatible quoting: values may
// be wrapped in " or ', and a double-quoted value may contain backslash
// escapes. This is a value DECODER, not an evaluator — nothing here executes,
// expands `$VAR`, or runs a command substitution, because the file is
// host-controlled text and the only safe reading of it is as data.
func unquoteOSRelease(v string) string {
	if len(v) < 2 {
		return v
	}
	quote := v[0]
	if quote != '"' && quote != '\'' || v[len(v)-1] != quote {
		return v
	}
	inner := v[1 : len(v)-1]
	if quote == '\'' {
		return inner
	}
	var b strings.Builder
	b.Grow(len(inner))
	for i := 0; i < len(inner); i++ {
		if inner[i] == '\\' && i+1 < len(inner) {
			i++
			b.WriteByte(inner[i])
			continue
		}
		b.WriteByte(inner[i])
	}
	return b.String()
}

// ---------------------------------------------------------------------------
// Shared parser helpers
// ---------------------------------------------------------------------------

// parseReport is what a parser saw, so that FamilyCoverage can say it. A
// parser NEVER drops a line without counting it: exit criterion 20's
// no-silent-clean rule and A.3's no-silent-drop rule are the same rule applied
// to two different pipelines.
type parseReport struct {
	Lines        int
	Skipped      int
	NotInstalled int
	Degraded     bool
}

// splitLines splits raw command output into lines, tolerating \n and \r\n and
// a missing trailing newline.
func splitLines(data []byte) []string {
	text := strings.ReplaceAll(string(data), "\r\n", "\n")
	text = strings.TrimSuffix(text, "\n")
	if text == "" {
		return nil
	}
	return strings.Split(text, "\n")
}

// goos returns the build target OS for the provenance record.
func goos() string { return runtime.GOOS }
