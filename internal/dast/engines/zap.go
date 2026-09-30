// This file is the ZAP driver.
//
// It shares package `engines` with the nuclei driver (nuclei.go) DELIBERATELY AND
// COMPLETELY. Every type that describes a request, an authorization, a
// finding or an absence is the nuclei driver's, reused rather than re-declared:
// TargetSpec, RequestProposal, AdmittedRequest, Issuer, ProbeResult, Finding,
// scrub, ExitCodeArtefactAbsent and ErrEngineUnavailable. A second engine that
// invented its own seam would be a second contract that can disagree with the
// first, and two disagreeing contracts is how "the scan ran" comes to mean two
// different things in one report.
//
// What is NOT reused is stated where it happens and why, in three places:
// EngineUnavailableError (its message hard-codes nuclei's InstallHint),
// Coverage (its ProbedNothing is template-shaped and ZAP has no templates),
// and ScanResult.AssertNotSilentlyEmpty (its absence message names nuclei by
// const). Each of those is a nuclei.go edit that is outside the ZAP driver's write
// scope, so this file declares a sibling and says so rather than quietly
// producing a message that names the wrong engine.
//
// # The one structural difference from the nuclei driver, and it is the whole file
//
// Nuclei is driven in-process through an interface: the driver proposes a
// request, the kernel gates it, and an Issuer supplied from outside
// internal/dast puts it on the wire. Nothing ZAP does works that way. ZAP is
// a JVM process with its own HTTP stack, its own connection pool and its own
// redirect follower, and if it is handed a target and started, it will reach
// that target without asking Anvil anything.
//
// That is not a limitation to work around. It is the threat, and this file's
// answer to it is one sentence:
//
//	ZAP IS NOT GIVEN EGRESS. IT IS GIVEN A PROXY, AND THE PROXY IS ANVIL'S
//	KERNEL CHOKEPOINT.
//
// The generated Automation Framework plan carries a REQUIRED `env.proxy`
// block. NewZapAutomationPlan refuses to render without one, NewZapProxy
// refuses any address that is not a loopback literal, and
// ZapAutomationPlan.Verify re-reads the rendered document and refuses it if
// the proxy block is missing or altered. So every request ZAP makes is a
// request to Anvil's egress layer, which is where authz.Governor lives, and
// gate 13 re-validates it like any other.
//
// # Redirects, which is the specific thing this packet was told to get right
//
// plan/design/dynamic-tier.md's gate 13 is named after the bug ZAP shipped: issue #2546,
// scope treated as a job-level property rather than a per-request one, so a
// mid-scan redirect walked out of scope. An http.Client with a nil
// CheckRedirect follows up to ten hops silently; ZAP's own client follows too.
//
// WHAT THE PROXY ENFORCES, WITHOUT DEPENDING ON A ZAP SETTING:
//
//   - Anvil's egress layer assigns authz.RefuseAllRedirects to its client's
//     CheckRedirect. Anvil therefore NEVER follows a Location header
//     automatically — not even a same-host one — so the 3xx comes back
//     through the proxy instead of being chased inside Anvil's own client.
//   - ZAP, receiving the 3xx, may choose to follow it. Its follow-up is a NEW
//     REQUEST TO THE PROXY, and gate 13 re-validates SCOPE on every request
//     that arrives, whatever that request says it is. A follow-up to a host
//     the scope and attestation do not cover is refused on its DESTINATION,
//     so the out-of-scope half of #2546 does not rest on the follow-up being
//     recognised as a redirect at all. Driven through a real authz.Governor by
//     TestGate13JudgesTheDestinationWhateverTheRequestClaimsToBe.
//   - If ZAP is ever run WITHOUT the proxy, none of the above applies and
//     nothing in this file can make it apply. That is why the proxy is
//     required at construction rather than defaulted, and why
//     internal/SKIPPED-CONTROLS.md U5 records that no run on this host has
//     ever demonstrated the proxied path end to end.
//
// # WHAT IS NOT ENFORCED — read this before relying on the hop bound
//
// NOTHING MAKES ZAP'S OWN REDIRECT FOLLOWING ARRIVE LABELLED AS A REDIRECT.
//
// An earlier version of this comment said the follow-up "arrives at gate 13 as
// an ordinary request with OriginRedirect and Hop+1", bounded by authz's
// maxRedirectHops. It does not, and the kernel is explicit about who has to
// make it so: authz.NewRequestIntent REFUSES OriginRedirect at Hop 0
// (phase3_enforcement.go:376) and REFUSES any other origin at a non-zero Hop
// (:370), so the origin and the depth are neither inferred nor defaulted —
// they are supplied by whoever fills a ZapProposalFacts, which is the
// component that runs the proxy. RefuseAllRedirects' own doc names the same
// owner: "the egress layer records the hop, and a same-host hop is re-issued
// as a fresh request with OriginRedirect and Hop+1"
// (phase3_enforcement.go:605). Neither this file nor the kernel implements
// that component, and nothing either of them can see distinguishes a
// truthfully-labelled hop from a mislabelled one.
//
// So for a proxy that labels every request `initial` at Hop 0:
//
//	scope, robots, method, technique, gate 14 caps
//	                       STILL ENFORCED, per request, on the destination
//	authz's maxRedirectHops NEVER REACHED. A hop that is not labelled as one
//	                       carries no depth to bound, so a same-host redirect
//	                       chain is bounded only by gate 14's rate and volume
//	                       caps. MEASURED: at one instant the real Governor
//	                       admitted 10 such requests before gate 14 refused
//	                       the 11th, against a labelled-hop bound of 5. The
//	                       test is named at the end of this section.
//	the gate-21 audit row  CANNOT SHOW EITHER WAY. authz.GateRecord
//	                       (kernel.go:708) has no origin field and no hop
//	                       field, so no row distinguishes a first request
//	                       from a hop whether the label was right or wrong,
//	                       and the chain cannot be reconstructed from the log
//	                       to check.
//
// Two tests demonstrate those rows rather than this comment asserting them:
// TestNothingInThisPackageMakesARedirectArriveLabelledAsOne, and
// TestAnUnlabelledRedirectChainIsBoundedByGate14AndNotByTheHopBound, which is
// where the 10-against-5 measurement above comes from.
//
// The missing control is a redirect policy owned by the proxy — it is the only
// component that holds the 3xx it just returned and can therefore say "this
// request is the follow-up to that one" and fill Origin and Hop in
// accordingly. That is a change to whoever builds the Issuer and the proxy; it
// is outside this file, it is outside internal/dast/authz, and until it exists
// the hop bound is not a control this driver may be described as having.
//
// This file references authz.RefuseAllRedirects by name and does not wrap it:
// its signature is func(*http.Request, []*http.Request) error, and importing
// net/http here fails gate 3 tier 1 and the local echo of it in
// nuclei_test.go. The wiring belongs to whoever builds the Issuer.
//
// # Every one of ZAP's four caps defaults to UNLIMITED
//
// research/19-target-environment-and-sandboxing.md line 164 step 6: "Set all
// four ZAP caps explicitly, because every one defaults to unlimited."
// delayInMs, maxScanDurationInMins, maxRuleDurationInMins and threadPerHost.
// A Go struct whose zero value is 0 maps onto ZAP's "unlimited" exactly, which
// makes the forgotten-field case the maximally dangerous one.
//
// So there is no ZapCaps literal anybody can write. NewZapCaps takes an
// authz.Caps — gate 14's coded floors, which no configuration may raise — and
// four required values, and it refuses:
//
//	any value <= 0                       (0 IS "unlimited" in ZAP)
//	threadPerHost   > gate 14 concurrent-per-host
//	scanDuration    > gate 14 wall-clock-per-target
//	ruleDuration    > scanDuration       (a rule cap above the scan cap is not a cap)
//	delayInMs       < the delay gate 14's rps/host implies for that thread count
//	projected volume > gate 14 requests-per-target-run
//
// That last one is the relation rather than the values: four individually
// legal caps can still multiply out to more requests than gate 14 permits in
// a run, and a check that only looked at each number would pass the
// combination.
//
// # ZAP is not installed on the host this was written on
//
// MEASURED 2026-08-22, PowerShell, on the development host:
//
//	Get-Command zap.sh   -> NOT FOUND
//	Get-Command zap      -> NOT FOUND
//	Get-Command zap.bat  -> NOT FOUND
//	Get-Command docker   -> NOT FOUND
//	Get-Command java     -> C:\Program Files\Common Files\Oracle\Java\javapath\java.exe
//	java -version        -> 23.0.2 2025-01-21 (HotSpot 23.0.2+7-58)
//
// A JVM is present; ZAP is not. SystemZapRunner therefore returns a typed
// refusal on every host — never a no-op runner that would let a scan come back
// clean — and the report-artifact check below refuses a run that wrote no
// report even when ZAP exits 0.
//
// # The open question this packet was told to answer, answered by NOT guessing
//
// plan/design/dynamic-tier.md:1253 records ZAP's JVM memory footprint as unquantified
// (research 15's own gap), and notes it decides whether tier M hardware
// (the spine's hardware-tier table, 32 GB / 8 core) accommodates a scheduled
// full scan alongside SAST and the coding agent.
//
// IT IS STILL UNQUANTIFIED AND THIS FILE STATES NO NUMBER. There is no ZAP on
// this host to run and no Docker to run `docker stats` against, so any figure
// here would be fabricated — and a fabricated figure is worse than the
// acknowledged gap, because tier-M sizing would then be documented against it.
// internal/SKIPPED-CONTROLS.md U5 records what measuring it takes.
package engines

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/netip"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"github.com/Susquehanna-Syntax/Anvil/internal/dast/authz"
)

// ---------------------------------------------------------------------------
// Identity, the absence contract, and what is shared with the nuclei driver
// ---------------------------------------------------------------------------

// ZapEngineName is the probe engine this driver wraps.
const ZapEngineName = "zap"

// ZapInstallHint is printed inside every ZAP-absent error.
//
// It carries NO VERSION LITERAL. plan/design/dynamic-tier.md's Pinned Versions And
// Licences table (line 1215) pins ZAP's ADD-ONS — Automation Framework +
// Authentication Helper, OpenAPI, GraphQL, SOAP, gRPC — but names no version
// for the ZAP core itself, so neither does this constant. Inventing one would
// put a number into an error message that no build ever produced.
const ZapInstallHint = "OWASP ZAP (Apache-2.0) is not present and this module registers no " +
	"ZapRunner. Install ZAP with the Automation Framework add-on on the host that runs the " +
	"DAST tier and wire a ZapRunner that executes the argv ZapInvocation.Argv() returns, or " +
	"run the scheduled full scan on a host where ZAP is available"

// ZapAutorunArgs is the fixed flag pair from research 15's ZAP entry:
// `./zap.sh -cmd -autorun zap.yaml`. It is a var of a function rather than a
// slice so that no caller can write through it.
func ZapAutorunArgs() []string { return []string{"-cmd", "-autorun"} }

var (
	// ErrZapCapUnbounded: one of ZAP's four caps was absent, zero, negative,
	// or looser than the gate-14 floor it must sit under. Zero is ZAP's
	// "unlimited", so a forgotten field lands here.
	ErrZapCapUnbounded = errors.New("engines: a ZAP scan cap was left unbounded")

	// ErrZapPlanUnverified: the rendered automation plan did not survive
	// re-reading. Either the generator changed and a required key stopped
	// being emitted, or a value in the document disagrees with the sealed
	// ZapCaps it was rendered from.
	ErrZapPlanUnverified = errors.New("engines: the generated ZAP automation plan failed verification")

	// ErrZapReportMissing: the runner reported success and did not write one
	// of the declared reports. A scan with no report produced no evidence,
	// and no evidence is not a clean target.
	ErrZapReportMissing = errors.New("engines: a declared ZAP report was not written")
)

// ZapUnavailableError is the typed absence for ZAP.
//
// # Why this is a second type and not EngineUnavailableError
//
// It reports ExitCodeArtefactAbsent — the nuclei driver's constant, not a second one — and
// it unwraps to ErrEngineUnavailable, so `errors.Is(err, ErrEngineUnavailable)`
// and a type assertion to `interface{ ExitCode() int }` both work across the
// two drivers. THAT is the shared contract, and zap_test.go asserts it holds
// for both.
//
// What is not shared is the message: EngineUnavailableError.Error()
// interpolates InstallHint, which is nuclei's, unconditionally. Reusing it
// here would print "the Nuclei Go SDK is not in this module's dependency
// graph" to an operator whose actual problem is a missing JVM application.
// Giving EngineUnavailableError a Hint field is the better fix and it is an
// edit to nuclei.go, which the ZAP driver may not write — see notes to the orchestrator.
type ZapUnavailableError struct {
	// Name is the engine that is missing, always ZapEngineName.
	Name string
	// Detail is what was looked for and not found.
	Detail string
}

func (e *ZapUnavailableError) Error() string {
	return fmt.Sprintf(
		"engines: the %s engine is not available (%s). This is NOT a clean target: no scan "+
			"ran, so no result — empty or otherwise — was produced. To fix: %s. "+
			"A wrapping command must exit %d for this condition.",
		e.Name, e.Detail, ZapInstallHint, ExitCodeArtefactAbsent)
}

// Unwrap ties this to the nuclei driver's sentinel so one errors.Is covers both engines.
func (e *ZapUnavailableError) Unwrap() error { return ErrEngineUnavailable }

// ExitCode reports the process exit code a wrapping command must use. It is
// the nuclei driver's constant, deliberately: one code across Anvil for "the engine or the
// ruleset is not present".
func (e *ZapUnavailableError) ExitCode() int { return ExitCodeArtefactAbsent }

// ---------------------------------------------------------------------------
// The runner seam
// ---------------------------------------------------------------------------

// ZapReportArtifact is one report file the runner says ZAP wrote.
type ZapReportArtifact struct {
	// Template is the report template that produced it.
	Template ZapReportTemplate
	// Path is where the runner says it landed.
	Path string
	// Bytes is its size. Zero means the file exists and holds nothing, which
	// is treated as not written: an empty SARIF document is not a report.
	Bytes int64
}

// ZapRunOutcome is what one autorun produced.
type ZapRunOutcome struct {
	// ExitCode is ZAP's process exit code.
	ExitCode int
	// Reports is every report artifact the runner observed.
	Reports []ZapReportArtifact
	// Stderr is diagnostic prose from the far side. Scrubbed before it is
	// retained: it is engine-authored text and this package treats all of
	// that as hostile input.
	Stderr string
}

// ZapRunner is the ZAP process, as much of it as this driver uses.
//
// # The obligations an implementation takes on
//
//  1. Execute EXACTLY the argv ZapInvocation.Argv() returns, as an argument
//     vector. Never join it into a shell string. The plan path and the zap.sh
//     path are both validated here, but a shell would re-interpret bytes this
//     package deliberately allowed through (a Windows path's backslashes, for
//     one), and argument construction is a security boundary.
//  2. Write ZapInvocation.PlanYAML() to ZapInvocation.PlanPath() verbatim.
//     A runner that regenerates or edits the plan defeats every check in this
//     file, because Verify ran against the text this package produced.
//  3. Give ZAP NO network access other than the proxy the plan names. The
//     plan's env.proxy block routes ZAP's HTTP through Anvil's chokepoint; a
//     runner that also leaves ZAP able to dial directly has reintroduced the
//     bypass the proxy exists to close. On Linux this is network containment's netns; on a
//     host without one it is unenforced, and U5 records that.
//
// Obligations 1 and 3 are STATED HERE AND ENFORCED NOWHERE IN THIS FILE.
// They are contracts on the implementer, recorded in
// internal/SKIPPED-CONTROLS.md U5 as the specific things an integration lane
// must prove.
type ZapRunner interface {
	Autorun(ctx context.Context, inv ZapInvocation) (ZapRunOutcome, error)
}

// SystemZapRunner returns the ZAP runner this host can run.
//
// It ALWAYS returns an error on every host, today. There is no runner adapter
// in this module, and returning a no-op that reported zero findings would be
// exactly the silent-clean failure this file's doc comment opens with. It
// never returns (nil, nil).
func SystemZapRunner() (ZapRunner, error) {
	return nil, &ZapUnavailableError{
		Name: ZapEngineName,
		Detail: "no ZapRunner adapter is compiled into this module, and no zap.sh, zap or " +
			"zap.bat was on PATH when this package was written (measured 2026-08-22 on " +
			"the development host; a JVM was present, ZAP was not)",
	}
}

// ---------------------------------------------------------------------------
// Report templates
// ---------------------------------------------------------------------------

// ZapReportTemplate is a ZAP report add-on template name.
type ZapReportTemplate string

// The two templates research/15-dast-tooling-landscape.md line 150 requires:
// "the SARIF JSON Report template plus Traditional JSON Report with Requests
// and Responses ... the first for the interchange envelope, the second because
// SARIF drops the request/response evidence the coding agent needs."
//
// THESE TWO STRINGS ARE UNVERIFIED AGAINST AN INSTALLED ZAP. There is no ZAP
// on this host to enumerate `zap.sh -cmd -autorun` report templates against,
// so they are transcribed from the report add-on's documented template ids and
// recorded in internal/SKIPPED-CONTROLS.md U5 as a thing a real lane settles
// in one command. What IS enforced here is that both are declared, both are
// rendered into the plan, and a run that fails to write either one is a
// refusal rather than a clean report.
const (
	// ZapReportUnspecified is the zero value and names no template.
	ZapReportUnspecified ZapReportTemplate = ""
	// ZapReportSARIF is the SARIF JSON Report template — the interchange
	// envelope, per research 15's unified-audit-record section.
	ZapReportSARIF ZapReportTemplate = "sarif-json"
	// ZapReportTraditionalJSONPlus is the Traditional JSON Report WITH
	// Requests and Responses. The "-plus" variant is the point: the plain
	// traditional-json template drops the request/response evidence.
	ZapReportTraditionalJSONPlus ZapReportTemplate = "traditional-json-plus"
)

// RequiredZapReportTemplates is the set every generated plan must declare.
// It is a function returning a fresh slice so nothing can shorten it.
func RequiredZapReportTemplates() []ZapReportTemplate {
	return []ZapReportTemplate{ZapReportSARIF, ZapReportTraditionalJSONPlus}
}

// fileStem is the report file stem for a template. It is derived from the
// template name rather than supplied, so no caller can point two templates at
// one file and lose the first.
func (t ZapReportTemplate) fileStem() string { return "anvil-zap-" + string(t) }

// ---------------------------------------------------------------------------
// The four caps
// ---------------------------------------------------------------------------

// ZapCapFacts is the four caps as required inputs.
//
// EVERY FIELD IS REQUIRED. There is no "leave it and get a sensible default",
// because ZAP's default for all four is unlimited and Go's zero value for all
// four is 0, which is how ZAP spells unlimited. A struct somebody forgot to
// fill in must therefore be a refusal, and NewZapCaps makes it one.
type ZapCapFacts struct {
	// DelayInMs is the per-request delay ZAP's active scanner inserts.
	DelayInMs int
	// MaxScanDurationInMins bounds the whole active scan.
	MaxScanDurationInMins int
	// MaxRuleDurationInMins bounds any single scan rule.
	MaxRuleDurationInMins int
	// ThreadPerHost is ZAP's per-host concurrency.
	ThreadPerHost int
}

// ZapCaps is the four caps, sealed and checked against gate 14.
//
// The zero value is not one: Constructed reports false and every accessor
// returns an error, so a ZapCaps nobody built cannot be rendered into a plan.
type ZapCaps struct {
	delayMs  int
	scanMins int
	ruleMins int
	threads  int
	sealed   bool
}

// zapMinDelayInMs is the smallest delayInMs that keeps `threads` workers
// under `rps` requests per second.
//
// threads workers each sleeping d milliseconds between requests issue
// threads*1000/d requests per second. Requiring that to be <= rps gives
// d >= 1000*threads/rps, rounded UP — rounding down would put the scan over
// the cap by a fraction of a request per second, every second, for the whole
// run.
func zapMinDelayInMs(threads, rps int) (int, error) {
	if threads <= 0 || rps <= 0 {
		return 0, fmt.Errorf("engines: %w: a minimum delay cannot be derived from "+
			"threads=%d rps=%d; both must be positive", ErrZapCapUnbounded, threads, rps)
	}
	num := 1000 * threads
	d := num / rps
	if num%rps != 0 {
		d++
	}
	if d <= 0 {
		d = 1
	}
	return d, nil
}

// zapProjectedRequests is how many requests the four caps permit in one run:
// threads workers, one request every delayMs, for scanMins minutes.
//
// This is the RELATION rather than the values. Four individually legal caps
// can multiply out past gate 14's requests-per-target-run floor, and a check
// that only looked at each number in isolation would pass the combination.
func zapProjectedRequests(threads, delayMs, scanMins int) (int64, error) {
	if threads <= 0 || delayMs <= 0 || scanMins <= 0 {
		return 0, fmt.Errorf("engines: %w: a projected request volume cannot be derived "+
			"from threads=%d delayInMs=%d scanMins=%d; all three must be positive",
			ErrZapCapUnbounded, threads, delayMs, scanMins)
	}
	return (int64(threads) * 60000 * int64(scanMins)) / int64(delayMs), nil
}

// NewZapCaps checks four required caps against gate 14's coded floors.
//
// kernel is authz.Caps — CodedCaps, possibly already lowered by configuration.
// It cannot be raised (authz.Cap.Lower refuses anything above the current
// effective value, including a sequence of calls walking one back up), so the
// bounds this function enforces are the kernel's, not a second copy of them.
//
// Every refusal names the ZAP key, the value, the gate-14 quantity it violated
// and the number it had to sit under, because "cap out of range" sends an
// operator to the wrong file.
func NewZapCaps(kernel authz.Caps, f ZapCapFacts) (ZapCaps, error) {
	if !kernel.Constructed() {
		return ZapCaps{}, fmt.Errorf("engines: %w: the ZAP caps were checked against an "+
			"authz.Caps that authz.CodedCaps never built. A zero Caps has no effective "+
			"value for anything, so there would be no floor to check against and every "+
			"ZAP cap would be accepted", ErrZapCapUnbounded)
	}

	// Positivity first, one field at a time, because 0 is exactly ZAP's
	// "unlimited" and the forgotten-field case must name the field.
	for _, c := range []struct {
		key string
		v   int
	}{
		{"delayInMs", f.DelayInMs},
		{"maxScanDurationInMins", f.MaxScanDurationInMins},
		{"maxRuleDurationInMins", f.MaxRuleDurationInMins},
		{"threadPerHost", f.ThreadPerHost},
	} {
		if c.v <= 0 {
			return ZapCaps{}, fmt.Errorf("engines: %w: %s was %d. ZAP treats 0 as "+
				"UNLIMITED for all four of these keys (research/19 line 164 step 6), and "+
				"Go's zero value for an int is 0 — so a field nobody filled in is a scan "+
				"with no bound at all. There is no default here on purpose",
				ErrZapCapUnbounded, c.key, c.v)
		}
	}

	concurrent, err := kernel.ConcurrentPerHost()
	if err != nil {
		return ZapCaps{}, fmt.Errorf("engines: %w: gate 14's concurrent-per-host cap is "+
			"undeclared: %w", ErrZapCapUnbounded, err)
	}
	if f.ThreadPerHost > concurrent {
		return ZapCaps{}, fmt.Errorf("engines: %w: threadPerHost=%d exceeds gate 14's "+
			"concurrent-connections-per-host cap of %d. ZAP's thread count IS the "+
			"concurrency the target sees, so a plan above this cap puts the kernel's "+
			"number and the scanner's number in disagreement",
			ErrZapCapUnbounded, f.ThreadPerHost, concurrent)
	}

	wall, err := kernel.WallClockPerTarget()
	if err != nil {
		return ZapCaps{}, fmt.Errorf("engines: %w: gate 14's wall-clock cap is undeclared: %w",
			ErrZapCapUnbounded, err)
	}
	wallMins := int(wall.Minutes())
	if wallMins <= 0 {
		return ZapCaps{}, fmt.Errorf("engines: %w: gate 14's wall-clock cap is %s, which is "+
			"under one minute. ZAP's duration caps are expressed in whole minutes, so "+
			"there is no value this driver can emit that honours it",
			ErrZapCapUnbounded, wall)
	}
	if f.MaxScanDurationInMins > wallMins {
		return ZapCaps{}, fmt.Errorf("engines: %w: maxScanDurationInMins=%d exceeds gate "+
			"14's wall-clock-per-target cap of %s (%d whole minutes)",
			ErrZapCapUnbounded, f.MaxScanDurationInMins, wall, wallMins)
	}
	if f.MaxRuleDurationInMins > f.MaxScanDurationInMins {
		return ZapCaps{}, fmt.Errorf("engines: %w: maxRuleDurationInMins=%d exceeds "+
			"maxScanDurationInMins=%d. A per-rule cap above the whole-scan cap never "+
			"binds, so it is a cap in name only",
			ErrZapCapUnbounded, f.MaxRuleDurationInMins, f.MaxScanDurationInMins)
	}

	rps, err := kernel.RequestsPerSecondPerHost()
	if err != nil {
		return ZapCaps{}, fmt.Errorf("engines: %w: gate 14's requests-per-second cap is "+
			"undeclared: %w", ErrZapCapUnbounded, err)
	}
	minDelay, err := zapMinDelayInMs(f.ThreadPerHost, rps)
	if err != nil {
		return ZapCaps{}, err
	}
	if f.DelayInMs < minDelay {
		return ZapCaps{}, fmt.Errorf("engines: %w: delayInMs=%d is below %d, the smallest "+
			"delay that keeps %d ZAP thread(s) under gate 14's %d requests/second/host. "+
			"ZAP's delay is PER THREAD, so the rate the target sees is threads*1000/delay "+
			"and a delay chosen without reference to the thread count silently multiplies",
			ErrZapCapUnbounded, f.DelayInMs, minDelay, f.ThreadPerHost, rps)
	}

	volume, err := kernel.RequestsPerTargetRun()
	if err != nil {
		return ZapCaps{}, fmt.Errorf("engines: %w: gate 14's requests-per-target-run cap is "+
			"undeclared: %w", ErrZapCapUnbounded, err)
	}
	projected, err := zapProjectedRequests(f.ThreadPerHost, f.DelayInMs, f.MaxScanDurationInMins)
	if err != nil {
		return ZapCaps{}, err
	}
	if projected > int64(volume) {
		return ZapCaps{}, fmt.Errorf("engines: %w: threadPerHost=%d at delayInMs=%d for "+
			"maxScanDurationInMins=%d projects %d requests, over gate 14's %d "+
			"requests/target/run. Each of the four caps is individually legal here; it is "+
			"their PRODUCT that is not, which is why this check exists separately",
			ErrZapCapUnbounded, f.ThreadPerHost, f.DelayInMs, f.MaxScanDurationInMins,
			projected, volume)
	}

	return ZapCaps{
		delayMs:  f.DelayInMs,
		scanMins: f.MaxScanDurationInMins,
		ruleMins: f.MaxRuleDurationInMins,
		threads:  f.ThreadPerHost,
		sealed:   true,
	}, nil
}

// ZapCapsAtKernelCeiling derives the LOOSEST four caps gate 14 permits.
//
// It exists so that a caller with no opinion still gets bounded values rather
// than reaching for a literal, and so that tests have a reference point that
// moves when the kernel's floors move. It is not a recommendation: this file
// makes no claim about what ratio of rule-duration to scan-duration is good
// scanning practice, only about what is bounded. A caller that wants tighter
// numbers passes them to NewZapCaps and they are checked the same way.
func ZapCapsAtKernelCeiling(kernel authz.Caps) (ZapCaps, error) {
	if !kernel.Constructed() {
		return ZapCaps{}, fmt.Errorf("engines: %w: no ceiling can be derived from an "+
			"authz.Caps that authz.CodedCaps never built", ErrZapCapUnbounded)
	}
	threads, err := kernel.ConcurrentPerHost()
	if err != nil {
		return ZapCaps{}, fmt.Errorf("engines: %w: %w", ErrZapCapUnbounded, err)
	}
	rps, err := kernel.RequestsPerSecondPerHost()
	if err != nil {
		return ZapCaps{}, fmt.Errorf("engines: %w: %w", ErrZapCapUnbounded, err)
	}
	wall, err := kernel.WallClockPerTarget()
	if err != nil {
		return ZapCaps{}, fmt.Errorf("engines: %w: %w", ErrZapCapUnbounded, err)
	}
	volume, err := kernel.RequestsPerTargetRun()
	if err != nil {
		return ZapCaps{}, fmt.Errorf("engines: %w: %w", ErrZapCapUnbounded, err)
	}
	delay, err := zapMinDelayInMs(threads, rps)
	if err != nil {
		return ZapCaps{}, err
	}

	mins := int(wall.Minutes())
	// The volume relation binds independently of the wall clock, so take
	// whichever gives fewer minutes. Integer division floors, which is the
	// safe direction.
	byVolume := (int64(volume) * int64(delay)) / (int64(threads) * 60000)
	if byVolume < int64(mins) {
		mins = int(byVolume)
	}
	if mins <= 0 {
		return ZapCaps{}, fmt.Errorf("engines: %w: gate 14's caps (wall clock %s, %d "+
			"requests/run, %d threads, %d rps) leave no whole minute of scanning. ZAP's "+
			"duration caps are whole minutes, so there is no bounded plan to emit",
			ErrZapCapUnbounded, wall, volume, threads, rps)
	}

	return NewZapCaps(kernel, ZapCapFacts{
		DelayInMs:             delay,
		MaxScanDurationInMins: mins,
		MaxRuleDurationInMins: mins,
		ThreadPerHost:         threads,
	})
}

// Constructed reports whether c came from NewZapCaps.
func (c ZapCaps) Constructed() bool {
	return c.sealed && c.delayMs > 0 && c.scanMins > 0 && c.ruleMins > 0 && c.threads > 0
}

// DelayInMs is ZAP's per-request delay.
func (c ZapCaps) DelayInMs() int { return c.delayMs }

// MaxScanDurationInMins bounds the whole active scan.
func (c ZapCaps) MaxScanDurationInMins() int { return c.scanMins }

// MaxRuleDurationInMins bounds any single scan rule.
func (c ZapCaps) MaxRuleDurationInMins() int { return c.ruleMins }

// ThreadPerHost is ZAP's per-host concurrency.
func (c ZapCaps) ThreadPerHost() int { return c.threads }

// ---------------------------------------------------------------------------
// The proxy — the reason ZAP has no egress of its own
// ---------------------------------------------------------------------------

// ZapProxy is the address of Anvil's kernel chokepoint, as ZAP must see it.
//
// It is a VALUE, not a connection: this package cannot dial and must not be
// able to. netip is on the kernel's inert list for exactly this reason — it
// holds an address and confers no capability.
//
// NewZapProxy refuses anything that is not a loopback literal. An off-box
// proxy address in this field would send every request ZAP makes to a host
// Anvil does not control, which is an exfiltration channel wearing a
// containment control's clothes.
type ZapProxy struct {
	host   string
	port   uint16
	sealed bool
}

// NewZapProxy seals a loopback proxy address.
func NewZapProxy(addr netip.AddrPort) (ZapProxy, error) {
	if !addr.IsValid() {
		return ZapProxy{}, fmt.Errorf("engines: %w: the ZAP proxy address is not a valid "+
			"netip.AddrPort. Without a proxy, ZAP dials the target itself and no gate in "+
			"the kernel ever sees the request", ErrRefused)
	}
	ip := addr.Addr().Unmap()
	if !ip.IsLoopback() {
		return ZapProxy{}, fmt.Errorf("engines: %w: the ZAP proxy address %s is not a "+
			"loopback address. Anvil's egress chokepoint runs in this process tree; a "+
			"proxy anywhere else is a third party receiving every request the scan makes",
			ErrRefused, addr)
	}
	if addr.Port() == 0 {
		return ZapProxy{}, fmt.Errorf("engines: %w: the ZAP proxy port is 0, which is not "+
			"a port a listener can be reached on. A zero here is an unset field, and an "+
			"unset field must not mean 'no proxy'", ErrRefused)
	}
	return ZapProxy{host: ip.String(), port: addr.Port(), sealed: true}, nil
}

// Constructed reports whether p came from NewZapProxy.
func (p ZapProxy) Constructed() bool { return p.sealed && p.host != "" && p.port != 0 }

// Host is the proxy hostname ZAP is told to use.
func (p ZapProxy) Host() string { return p.host }

// Port is the proxy port ZAP is told to use.
func (p ZapProxy) Port() uint16 { return p.port }

// ---------------------------------------------------------------------------
// Scalar encoding: argument construction as a security boundary
// ---------------------------------------------------------------------------

// maxZapScalarBytes bounds any single value interpolated into the plan.
const maxZapScalarBytes = 1024

// yamlScalar renders s as a double-quoted YAML scalar, or refuses.
//
// # Why an allowlist and not an escaper
//
// An escaper answers "how do I encode this byte safely". An allowlist answers
// "is this byte allowed to be here at all", and only the second one is a
// control. A run id containing CR LF would, escaped, become a legal YAML
// string — and would then be written by ZAP into an HTTP header value, which
// is request splitting. So the bytes that could do that never reach the
// escaper: this function permits printable ASCII and nothing else, and the
// two characters that are special INSIDE a double-quoted YAML scalar are
// escaped after the allowlist has already run.
//
// Backslash is permitted because a Windows report directory is full of them,
// and it is escaped; a double quote is refused outright rather than escaped,
// because no value this package interpolates has a legitimate reason to
// contain one and refusing is the smaller surface.
func yamlScalar(s string) (string, error) {
	if s == "" {
		return "", fmt.Errorf("engines: %w: an empty value cannot be rendered into the "+
			"ZAP plan; an empty scalar is indistinguishable from a key nobody set",
			ErrRefused)
	}
	if len(s) > maxZapScalarBytes {
		return "", fmt.Errorf("engines: %w: a value of %d bytes exceeds the %d-byte bound "+
			"on any single scalar in the ZAP plan", ErrRefused, len(s), maxZapScalarBytes)
	}
	var b strings.Builder
	b.Grow(len(s) + 8)
	b.WriteByte('"')
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '"':
			return "", fmt.Errorf("engines: %w: the value %q contains a double quote at "+
				"byte %d. No value this package interpolates has a reason to, and "+
				"refusing is a smaller surface than escaping", ErrRefused, s, i)
		case c == '\\':
			b.WriteString(`\\`)
		case c < 0x20 || c > 0x7E:
			return "", fmt.Errorf("engines: %w: the value contains byte 0x%02X at offset "+
				"%d, which is outside printable ASCII. Control bytes here become an HTTP "+
				"header value ZAP sends, and CR/LF in a header value is request splitting",
				ErrRefused, c, i)
		default:
			b.WriteByte(c)
		}
	}
	b.WriteByte('"')
	return b.String(), nil
}

// slicesEqual compares two string slices element by element, in order.
// `slices` is not on this package's inert import list (see
// TestThisPackageConstructsNoSocket in nuclei_test.go).
func slicesEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// bareUint parses a YAML integer scalar the strict way: decimal digits only,
// no sign, no leading zero, no underscores, no suffix.
//
// It exists because Verify must be able to tell 30 from "30", from +30, from
// 030, from 3_0 and from "unlimited" — and a permissive parse that accepted
// any of those would let a plan through whose cap ZAP might read differently.
// strconv would be the obvious tool and is not on this package's inert import
// list (see TestThisPackageConstructsNoSocket in nuclei_test.go).
func bareUint(s string) (int, bool) {
	if s == "" || len(s) > 9 {
		return 0, false
	}
	if len(s) > 1 && s[0] == '0' {
		return 0, false
	}
	n := 0
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c < '0' || c > '9' {
			return 0, false
		}
		n = n*10 + int(c-'0')
	}
	return n, true
}

// zapContextName is the single Automation Framework context this driver
// declares. It is a const rather than a parameter: a caller-supplied context
// name is one more string interpolated into the plan for no benefit, and the
// plan declares exactly one context by construction.
const zapContextName = "anvil-target"

// zapScanHeader is the attribution header research/19 line 173 requires:
// "add a static X-Anvil-Scan: <run-id> header ... A production operator must
// be able to distinguish Anvil from an attacker in their logs at 3am."
const zapScanHeader = "X-Anvil-Scan"

// maxZapRunIDLen bounds a run id.
const maxZapRunIDLen = 128

// validZapRunID is the allowlist for a run id.
//
// It is narrower than yamlScalar's because a run id has a second destination:
// it is the VALUE of an HTTP header ZAP attaches to every request. RFC 9110
// permits a wider field-value grammar than this; this package permits less,
// because the run id is generated by Anvil and has no reason to contain
// anything else, and a narrow allowlist is a control where a wide one is a
// formality.
func validZapRunID(s string) error {
	if s == "" {
		return fmt.Errorf("engines: %w: the run id is empty. %s is how an operator tells "+
			"Anvil's traffic from an attacker's in their own logs, and a blank one tells "+
			"them nothing", ErrRefused, zapScanHeader)
	}
	if len(s) > maxZapRunIDLen {
		return fmt.Errorf("engines: %w: the run id is %d bytes, over the %d-byte bound",
			ErrRefused, len(s), maxZapRunIDLen)
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		ok := (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
			c == '-' || c == '_' || c == '.'
		if !ok {
			return fmt.Errorf("engines: %w: the run id contains byte 0x%02X at offset %d. "+
				"Only [A-Za-z0-9._-] is permitted, because this value becomes the %s "+
				"header on every request ZAP sends", ErrRefused, c, i, zapScanHeader)
		}
	}
	return nil
}

// zapOriginPattern turns a TargetSpec URL into a ZAP context include pattern
// and refuses anything that is not the exact shape NewTargetSpec produces.
//
// ZAP context includePaths are java.util.regex patterns. Interpolating a URL
// into one without quoting means every metacharacter in the host is live —
// a dot matches any character, so an include for "a.example.com" also
// includes "aXexample.com". \Q...\E is the regex-literal quote, and the
// validation below is what makes it safe to rely on: the URL is re-checked
// against the grammar NewTargetSpec emits (scheme://host:port, host from a
// narrow byte set) so it cannot contain a \E that would end the quote early.
func zapOriginPattern(url string) (string, error) {
	rest := ""
	switch {
	case strings.HasPrefix(url, "https://"):
		rest = url[len("https://"):]
	case strings.HasPrefix(url, "http://"):
		rest = url[len("http://"):]
	default:
		return "", fmt.Errorf("engines: %w: the target URL %q does not begin with a scheme "+
			"NewTargetSpec emits. Only a URL this package built may be turned into a scope "+
			"pattern", ErrRefused, url)
	}
	i := strings.LastIndexByte(rest, ':')
	if i <= 0 || i == len(rest)-1 {
		return "", fmt.Errorf("engines: %w: the target URL %q carries no host:port. "+
			"NewTargetSpec always emits one", ErrRefused, url)
	}
	host, portStr := rest[:i], rest[i+1:]
	if _, ok := bareUint(portStr); !ok {
		return "", fmt.Errorf("engines: %w: the target URL %q has a port that is not a "+
			"bare decimal integer", ErrRefused, url)
	}
	for j := 0; j < len(host); j++ {
		c := host[j]
		ok := (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '.' || c == '-'
		if !ok {
			return "", fmt.Errorf("engines: %w: the target URL's host %q contains byte "+
				"0x%02X at offset %d. Gate 8 canonicalises a host to lowercase "+
				"letters, digits, dot and hyphen; anything else did not come from there, "+
				"and interpolating it into a regex would make it a metacharacter",
				ErrRefused, host, c, j)
		}
	}
	return `\Q` + url + `\E.*`, nil
}

// ---------------------------------------------------------------------------
// The automation plan
// ---------------------------------------------------------------------------

// ZapPlanFacts is everything the plan generator needs. Every field is
// required.
type ZapPlanFacts struct {
	// Spec is the authorized destination. Only NewTargetSpec builds one, and
	// it does so only from an authz.Authorization, so a plan cannot name a
	// host the kernel did not admit.
	Spec TargetSpec
	// Caps are the four bounded caps.
	Caps ZapCaps
	// Proxy is Anvil's chokepoint. Required: without it ZAP has its own
	// egress and the kernel is not in the path.
	Proxy ZapProxy
	// RunID is the value of the X-Anvil-Scan header on every request.
	RunID string
	// ReportDir is an ABSOLUTE directory the runner will write reports into.
	ReportDir string
}

// ZapAutomationPlan is a rendered, re-verified `zap.yaml`.
//
// The zero value is not one. NewZapAutomationPlan renders the document AND
// re-reads it; if the re-read disagrees with the sealed ZapCaps it was
// rendered from, or a required key is absent, NO PLAN IS RETURNED. So a
// generator edit that dropped `delayInMs` is a construction failure in
// production code, not only a red test.
// It carries NO REFERENCE FIELD — no slice, no map, no pointer. That is
// checked by a test and it is not tidiness: a ZapAutomationPlan is passed by
// value, and a value copy of a struct holding a slice shares that slice's
// backing array. A holder of a copy could then rewrite what the original
// declares, and Verify would have run against one document while ZAP was
// handed the consequences of another. The declared report set is therefore
// derived from RequiredZapReportTemplates on every read rather than stored.
type ZapAutomationPlan struct {
	yaml   string
	digest string
	caps   ZapCaps
	proxy  ZapProxy
	runID  string
	target string
	sealed bool
}

// NewZapAutomationPlan renders and verifies the plan.
func NewZapAutomationPlan(f ZapPlanFacts) (ZapAutomationPlan, error) {
	return newZapAutomationPlan(renderZapPlan, f)
}

// newZapAutomationPlan is NewZapAutomationPlan with the renderer supplied.
//
// The seam is unexported and its only production caller passes the real
// renderer, so nothing can hand this constructor a document it did not
// generate. It exists because the Verify call at the end is otherwise
// UNTESTABLE: every negative test for Verify forges a plan and calls Verify
// directly, so deleting the constructor's call would leave the whole suite
// green while shipping unverified documents. This is the same device the
// kernel's build-time guard uses for gate 1's zero-value survey, and for the
// same reason.
func newZapAutomationPlan(render func(ZapPlanFacts) (string, error), f ZapPlanFacts) (ZapAutomationPlan, error) {
	if !f.Spec.Constructed() {
		return ZapAutomationPlan{}, fmt.Errorf("engines: %w: the plan names a destination "+
			"NewTargetSpec never built, so no authorization was ever checked for it",
			ErrUnconstructed)
	}
	if !f.Caps.Constructed() {
		return ZapAutomationPlan{}, fmt.Errorf("engines: %w: the plan was handed a ZapCaps "+
			"NewZapCaps never built. Its four fields would all be 0, and 0 is how ZAP "+
			"spells unlimited", ErrZapCapUnbounded)
	}
	if !f.Proxy.Constructed() {
		return ZapAutomationPlan{}, fmt.Errorf("engines: %w: the plan was handed a ZapProxy "+
			"NewZapProxy never built. Without env.proxy, ZAP opens its own connections to "+
			"the target and Anvil's kernel — gate 13 included — is not in the path at all. "+
			"There is no unproxied mode here", ErrRefused)
	}
	if err := validZapRunID(f.RunID); err != nil {
		return ZapAutomationPlan{}, err
	}
	if !filepath.IsAbs(f.ReportDir) {
		return ZapAutomationPlan{}, fmt.Errorf("engines: %w: the report directory %q is not "+
			"absolute. A relative path resolves against whatever working directory the ZAP "+
			"process happens to have, which is a different directory from the one this "+
			"driver would later look in", ErrRefused, f.ReportDir)
	}

	body, err := render(f)
	if err != nil {
		return ZapAutomationPlan{}, err
	}

	sum := sha256.Sum256([]byte(body))
	p := ZapAutomationPlan{
		yaml:   body,
		digest: hex.EncodeToString(sum[:]),
		caps:   f.Caps,
		proxy:  f.Proxy,
		runID:  f.RunID,
		target: f.Spec.URL(),
		sealed: true,
	}
	if err := p.Verify(); err != nil {
		return ZapAutomationPlan{}, err
	}
	return p, nil
}

// renderZapPlan builds the document.
//
// # Why this is a strings.Builder and not text/template
//
// The ZAP driver's design says "a Go-templated zap.yaml generator". This is a
// deliberate deviation and the reason is measured, not stylistic:
// nuclei_test.go's TestThisPackageConstructsNoSocket enumerates every import
// this package may carry, `text/template` is not on it, and nuclei_test.go is
// outside the ZAP driver's write scope. Adding the import turns a green suite red in a
// file this packet may not edit.
//
// The substantive point is unaffected and arguably improved. text/template's
// escaping knows nothing about YAML, so every interpolated value would need
// exactly the validation it gets below anyway; doing it in the constructor
// means an invalid value is a refusal BEFORE any rendering rather than a
// well-formed document containing a bad string.
func renderZapPlan(f ZapPlanFacts) (string, error) {
	targetURL, err := yamlScalar(f.Spec.URL())
	if err != nil {
		return "", err
	}
	pattern, err := zapOriginPattern(f.Spec.URL())
	if err != nil {
		return "", err
	}
	patternScalar, err := yamlScalar(pattern)
	if err != nil {
		return "", err
	}
	proxyHost, err := yamlScalar(f.Proxy.Host())
	if err != nil {
		return "", err
	}
	runID, err := yamlScalar(f.RunID)
	if err != nil {
		return "", err
	}
	reportDir, err := yamlScalar(f.ReportDir)
	if err != nil {
		return "", err
	}
	ctxName, err := yamlScalar(zapContextName)
	if err != nil {
		return "", err
	}
	headerName, err := yamlScalar(zapScanHeader)
	if err != nil {
		return "", err
	}

	var b strings.Builder
	w := func(format string, args ...any) { fmt.Fprintf(&b, format+"\n", args...) }

	w("# Generated by Anvil (the ZAP driver). Do not edit: this file is regenerated from")
	w("# internal/dast/engines/zap.go and re-verified on every construction.")
	w("#")
	w("# env.proxy is REQUIRED and is the whole containment story: ZAP is given no")
	w("# egress of its own, so every request it makes -- including every redirect it")
	w("# chooses to follow -- arrives at Anvil's authorization kernel as a fresh")
	w("# request and is re-validated by gate 13.")
	w("env:")
	w("  contexts:")
	w("    - name: %s", ctxName)
	w("      urls:")
	w("        - %s", targetURL)
	w("      includePaths:")
	w("        - %s", patternScalar)
	w("      excludePaths: []")
	w("  parameters:")
	w("    failOnError: true")
	w("    failOnWarning: false")
	w("    progressToStdout: true")
	w("  proxy:")
	w("    hostname: %s", proxyHost)
	w("    port: %d", f.Proxy.Port())
	w("jobs:")
	w("  # The attribution header goes first so it is in place before any job runs.")
	w("  - type: replacer")
	w("    rules:")
	w("      - description: %s", `"anvil-scan-attribution"`)
	w("        url: %s", patternScalar)
	w("        matchType: %s", `"req_header"`)
	w("        matchString: %s", headerName)
	w("        matchRegex: false")
	w("        replacementString: %s", runID)
	w("        tokenProcessing: false")
	w("  - type: passiveScan-config")
	w("    parameters:")
	w("      scanOnlyInScope: true")
	w("  - type: activeScan")
	w("    parameters:")
	w("      context: %s", ctxName)
	w("      # All four of these default to UNLIMITED in ZAP")
	w("      # (research/19-target-environment-and-sandboxing.md line 164, step 6).")
	w("      # Each is checked against a gate 14 coded floor by NewZapCaps.")
	w("      delayInMs: %d", f.Caps.DelayInMs())
	w("      maxScanDurationInMins: %d", f.Caps.MaxScanDurationInMins())
	w("      maxRuleDurationInMins: %d", f.Caps.MaxRuleDurationInMins())
	w("      threadPerHost: %d", f.Caps.ThreadPerHost())
	w("      # X-ZAP-Scan-ID on every request, so an operator can attribute a single")
	w("      # request to the rule that made it (research/19 line 173).")
	w("      injectPluginIdInHeader: true")
	w("      addQueryParam: false")
	w("      handleAntiCSRFTokens: false")
	w("      scanHeadersAllRequests: false")
	for _, tpl := range RequiredZapReportTemplates() {
		name, err := yamlScalar(string(tpl))
		if err != nil {
			return "", err
		}
		stem, err := yamlScalar(tpl.fileStem())
		if err != nil {
			return "", err
		}
		w("  - type: report")
		w("    parameters:")
		w("      template: %s", name)
		w("      reportDir: %s", reportDir)
		w("      reportFile: %s", stem)
	}
	return b.String(), nil
}

// zapRequiredScalars is every key Verify insists on finding exactly once,
// with the literal value it must carry.
//
// It is a function returning a fresh slice so that nothing can shorten the
// list at run time — a verification whose expectations can be edited by the
// thing it verifies is not a verification.
func (p ZapAutomationPlan) zapRequiredScalars() []struct{ key, want string } {
	return []struct{ key, want string }{
		{"injectPluginIdInHeader", "true"},
		{"scanOnlyInScope", "true"},
		{"failOnError", "true"},
		{"addQueryParam", "false"},
		{"handleAntiCSRFTokens", "false"},
		{"matchType", `"req_header"`},
		{"matchString", `"` + zapScanHeader + `"`},
		{"replacementString", `"` + p.runID + `"`},
		{"hostname", `"` + p.proxy.Host() + `"`},
		{"context", `"` + zapContextName + `"`},
	}
}

// Verify re-reads the rendered document and refuses it if anything a scan's
// safety rests on is absent, duplicated, or disagrees with the sealed values
// the plan was built from.
//
// # Why this exists when a test already asserts the same things
//
// A test asserts that the generator produced the right document ONCE, for the
// inputs the test chose. Verify asserts it for the document that is about to
// be handed to ZAP. The two failures it is built to catch are (a) an edit to
// renderZapPlan that drops a line — caught here at construction, in
// production, not only in CI — and (b) a rendered value that does not match
// the sealed ZapCaps, which is the case where the checked-and-validated caps
// and the caps ZAP will actually read have come apart.
//
// It is exported so a caller holding a plan across a boundary can re-run it.
func (p ZapAutomationPlan) Verify() error {
	if !p.sealed || p.yaml == "" {
		return fmt.Errorf("engines: %w: an unconstructed plan has no document to verify",
			ErrZapPlanUnverified)
	}

	// Mapping keys, gathered by name. A sequence entry whose item is a bare
	// scalar (`- "https://host:443"`) is NOT a mapping and is skipped: it
	// contains a colon, and splitting it on that colon would invent a key
	// named `"https` whose presence or absence nothing should depend on.
	// Sequence entries that ARE mappings (`- name: "x"`) keep their key.
	seen := map[string][]string{}
	scalars := map[string]bool{}
	present := map[string]bool{}
	for _, line := range strings.Split(p.yaml, "\n") {
		t := strings.TrimSpace(line)
		if t == "" || strings.HasPrefix(t, "#") {
			continue
		}
		if strings.HasPrefix(t, "- ") {
			item := strings.TrimSpace(t[2:])
			if strings.HasPrefix(item, `"`) {
				scalars[item] = true
				continue
			}
			t = item
		}
		i := strings.IndexByte(t, ':')
		if i <= 0 {
			continue
		}
		key := t[:i]
		if strings.ContainsAny(key, ` "'`) {
			continue
		}
		present[key] = true
		val := strings.TrimSpace(t[i+1:])
		if val == "" {
			continue
		}
		seen[key] = append(seen[key], val)
	}

	// The structural keys. A key whose value is a nested block carries no
	// scalar, so it is invisible to the value checks below; without this
	// list, deleting `includePaths:` would leave its child scalar dangling
	// under `urls:` and every value check would still pass. A CHECK THAT
	// CANNOT SEE THE DAMAGE IS NOT A CHECK.
	for _, key := range []string{
		"env", "contexts", "urls", "includePaths", "excludePaths", "parameters",
		"proxy", "jobs", "rules",
	} {
		if !present[key] {
			return fmt.Errorf("engines: %w: the rendered plan carries no %q key. "+
				"renderZapPlan emits one, so a document without it is a document whose "+
				"generator changed", ErrZapPlanUnverified, key)
		}
	}

	// The jobs, in order. ZAP runs them in the order they appear, and the
	// replacer must run BEFORE the active scan or the attribution header is
	// attached to nothing.
	wantJobs := []string{"replacer", "passiveScan-config", "activeScan", "report", "report"}
	if gotJobs := seen["type"]; !slicesEqual(gotJobs, wantJobs) {
		return fmt.Errorf("engines: %w: the rendered plan's jobs are %v; they must be %v, "+
			"in that order. ZAP runs jobs in document order, so a replacer after the "+
			"active scan attaches the %s header to requests that have already been made",
			ErrZapPlanUnverified, gotJobs, wantJobs, zapScanHeader)
	}

	only := func(key string) (string, error) {
		vs := seen[key]
		switch len(vs) {
		case 1:
			return vs[0], nil
		case 0:
			return "", fmt.Errorf("engines: %w: the rendered plan carries no %q key. "+
				"renderZapPlan emits one; a document without it is a document whose "+
				"generator changed", ErrZapPlanUnverified, key)
		default:
			return "", fmt.Errorf("engines: %w: the rendered plan carries %d %q keys. "+
				"ZAP reads one of them and this driver cannot say which, so a duplicate "+
				"is a plan whose effective value is unknown",
				ErrZapPlanUnverified, len(vs), key)
		}
	}

	// The four caps: present, exactly once, a bare positive integer, and
	// EQUAL to the sealed ZapCaps. That last clause is the one that matters:
	// a document whose caps are bounded but different from the ones
	// NewZapCaps checked has not been checked.
	for _, c := range []struct {
		key  string
		want int
	}{
		{"delayInMs", p.caps.DelayInMs()},
		{"maxScanDurationInMins", p.caps.MaxScanDurationInMins()},
		{"maxRuleDurationInMins", p.caps.MaxRuleDurationInMins()},
		{"threadPerHost", p.caps.ThreadPerHost()},
	} {
		raw, err := only(c.key)
		if err != nil {
			return fmt.Errorf("%w (this is one of ZAP's four caps, every one of which "+
				"defaults to UNLIMITED)", err)
		}
		got, ok := bareUint(raw)
		if !ok {
			return fmt.Errorf("engines: %w: %s is %q, which is not a bare positive decimal "+
				"integer. ZAP would read an unparseable or non-numeric cap as its default, "+
				"and its default is unlimited", ErrZapPlanUnverified, c.key, raw)
		}
		if got <= 0 {
			return fmt.Errorf("engines: %w: %s is %d. Zero IS unlimited in ZAP",
				ErrZapPlanUnverified, c.key, got)
		}
		if got != c.want {
			return fmt.Errorf("engines: %w: %s is %d in the rendered plan but %d in the "+
				"ZapCaps NewZapCaps checked against gate 14. The value ZAP will read has "+
				"come apart from the value that was validated",
				ErrZapPlanUnverified, c.key, got, c.want)
		}
	}

	for _, want := range p.zapRequiredScalars() {
		got, err := only(want.key)
		if err != nil {
			return err
		}
		if got != want.want {
			return fmt.Errorf("engines: %w: %s is %s in the rendered plan; it must be %s",
				ErrZapPlanUnverified, want.key, got, want.want)
		}
	}

	// The proxy port is an integer and must equal the sealed one.
	rawPort, err := only("port")
	if err != nil {
		return fmt.Errorf("%w (env.proxy is what puts Anvil's kernel in front of every "+
			"request ZAP makes)", err)
	}
	gotPort, ok := bareUint(rawPort)
	if !ok || gotPort != int(p.proxy.Port()) {
		return fmt.Errorf("engines: %w: the rendered proxy port is %q; the sealed ZapProxy "+
			"says %d", ErrZapPlanUnverified, rawPort, p.proxy.Port())
	}

	// Both report templates, each exactly once. A plan that declares one
	// report produces one artifact, and the SARIF envelope without the
	// traditional-json-plus variant loses the request/response evidence the
	// coding agent needs (research/15 line 150).
	tpls := seen["template"]
	want := RequiredZapReportTemplates()
	if len(tpls) != len(want) {
		return fmt.Errorf("engines: %w: the rendered plan declares %d report template(s); "+
			"it must declare exactly %d", ErrZapPlanUnverified, len(tpls), len(want))
	}
	got := append([]string(nil), tpls...)
	sort.Strings(got)
	expect := make([]string, 0, len(want))
	for _, t := range want {
		expect = append(expect, `"`+string(t)+`"`)
	}
	sort.Strings(expect)
	for i := range expect {
		if got[i] != expect[i] {
			return fmt.Errorf("engines: %w: the rendered plan's report templates are %v; "+
				"they must be %v", ErrZapPlanUnverified, got, expect)
		}
	}

	// The target's own origin must appear as the context URL, and the
	// include pattern must be the regex-quoted form of THAT SAME origin. A
	// plan that scopes ZAP to a different origin than the one the kernel
	// authorized is the ZAP #2546 shape at generation time rather than at
	// redirect time; a plan whose include pattern does not match its own
	// context URL is the same bug one line lower down.
	if !scalars[`"`+p.target+`"`] {
		return fmt.Errorf("engines: %w: the rendered plan's context does not list the "+
			"authorized origin %q. A ZAP context scoped to anything else is a scan of "+
			"something the kernel did not admit", ErrZapPlanUnverified, p.target)
	}
	pattern, err := zapOriginPattern(p.target)
	if err != nil {
		return fmt.Errorf("engines: %w: %w", ErrZapPlanUnverified, err)
	}
	quoted, err := yamlScalar(pattern)
	if err != nil {
		return fmt.Errorf("engines: %w: %w", ErrZapPlanUnverified, err)
	}
	if !scalars[quoted] {
		return fmt.Errorf("engines: %w: the rendered plan's includePaths does not carry "+
			"%s, the regex-quoted form of the authorized origin. An include pattern that "+
			"is not \\Q...\\E-quoted lets every metacharacter in the host match — a dot "+
			"matches any byte, so a scope for a.example.com also covers aXexample.com",
			ErrZapPlanUnverified, quoted)
	}
	if got := seen["url"]; len(got) != 1 || got[0] != quoted {
		return fmt.Errorf("engines: %w: the replacer rule's url is %v; it must be %s so "+
			"the %s header is attached to in-scope requests only",
			ErrZapPlanUnverified, got, quoted, zapScanHeader)
	}
	return nil
}

// Constructed reports whether p came from NewZapAutomationPlan.
func (p ZapAutomationPlan) Constructed() bool { return p.sealed && p.yaml != "" }

// YAML is the rendered, verified document.
func (p ZapAutomationPlan) YAML() string { return p.yaml }

// Digest is the SHA-256 of the exact rendered bytes, hex-encoded.
//
// It is the ZAP analogue of a Nuclei template digest: the identity a finding
// is attributed to. A request that claims to come from this scan carries this
// digest, and ZapDriver.Fire refuses one that carries a different value —
// which is the same by-identity-never-by-position rule the nuclei driver's Lookup enforces.
func (p ZapAutomationPlan) Digest() string { return p.digest }

// Caps returns the four bounded caps this plan was rendered from.
func (p ZapAutomationPlan) Caps() ZapCaps { return p.caps }

// ReportTemplates returns the templates this plan declares, as a fresh slice.
//
// The set is not stored on the plan (see the type's doc comment) — it is
// RequiredZapReportTemplates, and Verify has already confirmed the rendered
// document declares exactly it. An unconstructed plan declares nothing.
func (p ZapAutomationPlan) ReportTemplates() []ZapReportTemplate {
	if !p.Constructed() {
		return nil
	}
	return RequiredZapReportTemplates()
}

// ---------------------------------------------------------------------------
// The invocation
// ---------------------------------------------------------------------------

// ZapInvocation is one `./zap.sh -cmd -autorun <plan>` call, sealed.
//
// The argv is unexported and Argv returns a copy, so a runner cannot append a
// flag to the vector it was handed. That matters more here than it looks:
// ZAP's command line carries `-config` overrides that can re-enable anything
// the plan turned off, and an argv a caller can extend is an argv whose
// effective configuration this package does not know.
type ZapInvocation struct {
	argv     []string
	planPath string
	planYAML string
	sealed   bool
}

// Invocation builds the argv for this plan.
//
// zapSh and planPath must both be absolute. The plan path must end in .yaml,
// which is not decoration: `-autorun` takes a path and a runner that was
// handed a directory or a flag-shaped string would have ZAP interpret it.
func (p ZapAutomationPlan) Invocation(zapSh, planPath string) (ZapInvocation, error) {
	if !p.Constructed() {
		return ZapInvocation{}, fmt.Errorf("engines: %w: an unconstructed plan has no "+
			"invocation", ErrUnconstructed)
	}
	for _, a := range []struct{ name, v string }{{"zap.sh", zapSh}, {"the plan", planPath}} {
		if a.v == "" {
			return ZapInvocation{}, fmt.Errorf("engines: %w: the path to %s is empty",
				ErrRefused, a.name)
		}
		if !filepath.IsAbs(a.v) {
			return ZapInvocation{}, fmt.Errorf("engines: %w: the path to %s (%q) is not "+
				"absolute. A relative path resolves against the runner's working "+
				"directory, which this package does not know", ErrRefused, a.name, a.v)
		}
		if strings.HasPrefix(a.v, "-") {
			return ZapInvocation{}, fmt.Errorf("engines: %w: the path to %s (%q) begins "+
				"with a hyphen, so ZAP would read it as a flag rather than a path",
				ErrRefused, a.name, a.v)
		}
		for i := 0; i < len(a.v); i++ {
			if c := a.v[i]; c < 0x20 || c == 0x7F {
				return ZapInvocation{}, fmt.Errorf("engines: %w: the path to %s contains "+
					"control byte 0x%02X at offset %d", ErrRefused, a.name, c, i)
			}
		}
	}
	if !strings.HasSuffix(planPath, ".yaml") {
		return ZapInvocation{}, fmt.Errorf("engines: %w: the plan path %q does not end in "+
			".yaml", ErrRefused, planPath)
	}

	argv := append([]string{zapSh}, ZapAutorunArgs()...)
	argv = append(argv, planPath)
	return ZapInvocation{
		argv:     argv,
		planPath: planPath,
		planYAML: p.YAML(),
		sealed:   true,
	}, nil
}

// Constructed reports whether i came from ZapAutomationPlan.Invocation.
func (i ZapInvocation) Constructed() bool { return i.sealed && len(i.argv) == 4 }

// Argv is the argument vector, as a FRESH SLICE. It is never a shell string.
func (i ZapInvocation) Argv() []string { return append([]string(nil), i.argv...) }

// PlanPath is where the runner must write the plan.
func (i ZapInvocation) PlanPath() string { return i.planPath }

// PlanYAML is the exact bytes the runner must write, unmodified.
func (i ZapInvocation) PlanYAML() string { return i.planYAML }

// ---------------------------------------------------------------------------
// Proposals
// ---------------------------------------------------------------------------

// zapProposalOrigins is the allowlist of origins this driver will propose.
//
// It is NARROWER than the nuclei driver's, which is narrower than the kernel's, and the
// narrowing is the point:
//
//	OriginInitial            ZAP's first request to the target
//	OriginRedirect           a hop ZAP chose to follow after Anvil's client
//	                         refused to follow it automatically
//	                         (authz.RefuseAllRedirects), and which the PROXY
//	                         labelled as a hop. Nothing in this package can
//	                         apply that label or check it — see this file's
//	                         header, "WHAT IS NOT ENFORCED".
//
// and NOT:
//
//	OriginTemplateURL        this driver has no templates
//	OriginBrowserFetch       needs the Client Spider, which is the crawl and not
//	                         this packet. When the crawl lands it must widen this
//	                         list, and widening it is the review that widening
//	                         should be.
//	OriginWebSocketUpgrade   no job in the generated plan makes one
//	OriginOutOfBandCallback  no job in the generated plan makes one
//
// # Both entries are REACHABLE, and that is a test rather than a claim
//
// An origin in an allowlist that no caller can construct is a claim nothing
// exercises. TestEveryOriginThisDriverAllowsIsConstructibleAllTheWayToAnIntent
// iterates THIS FUNCTION — not a copy of its contents — and for each entry
// builds a RequestProposal through NewZapRequestProposal and then a sealed
// authz.RequestIntent from it. An entry added here that cannot make that trip
// fails that test, which is the review that widening this list should be.
//
// The rule id is required for BOTH, OriginInitial included: zapRuleIdentity
// refuses an empty RuleID under every origin, so a ZAP request that arrives at
// the proxy with no X-ZAP-Scan-ID cannot be proposed at all. That is the
// fail-closed direction and it is deliberate — injectPluginIdInHeader is on in
// every plan this package generates so that "every request carries
// X-ZAP-Scan-ID" (research/19-target-environment-and-sandboxing.md, the
// attribution bullet), and a request that does not carry one is a request this
// driver cannot attribute rather than one it attributes to nothing.
func zapProposalOrigins() []authz.RequestOrigin {
	return []authz.RequestOrigin{authz.OriginInitial, authz.OriginRedirect}
}

// maxZapRuleIDLen bounds a ZAP rule (plugin) id.
const maxZapRuleIDLen = 64

// zapRuleIdentity turns a ZAP scan-rule id into the template-identity string
// the shared RequestProposal carries.
//
// ZAP's analogue of a Nuclei template is a scan rule, and
// injectPluginIdInHeader puts its id on every request as X-ZAP-Scan-ID. So a
// ZAP request IS attributable, and it is attributed the same way a Nuclei one
// is: by an identity pair, never by position.
func zapRuleIdentity(ruleID string) (string, error) {
	if ruleID == "" {
		return "", fmt.Errorf("engines: %w: the proposal names no ZAP scan rule. "+
			"injectPluginIdInHeader is on in every plan this package generates precisely "+
			"so that every request is attributable; a request with no rule id is one this "+
			"driver cannot attribute", ErrRefused)
	}
	if len(ruleID) > maxZapRuleIDLen {
		return "", fmt.Errorf("engines: %w: the ZAP rule id is %d bytes, over the %d-byte "+
			"bound", ErrRefused, len(ruleID), maxZapRuleIDLen)
	}
	for i := 0; i < len(ruleID); i++ {
		c := ruleID[i]
		ok := (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
			c == '-' || c == '_' || c == '.'
		if !ok {
			return "", fmt.Errorf("engines: %w: the ZAP rule id contains byte 0x%02X at "+
				"offset %d; only [A-Za-z0-9._-] is permitted", ErrRefused, c, i)
		}
	}
	return "zap:rule:" + ruleID, nil
}

// ZapProposalFacts is one request ZAP wants to make.
type ZapProposalFacts struct {
	// Plan is the automation plan the request belongs to. Its digest is the
	// identity the proposal carries, so a request from a different plan
	// cannot be fired by this driver.
	Plan ZapAutomationPlan
	// Spec is the authorized destination.
	Spec TargetSpec
	// RuleID is ZAP's scan-rule (plugin) id, as injectPluginIdInHeader emits
	// it.
	RuleID string
	// Origin, Method, Path, Technique, Hop and Attempt are the request.
	Origin    authz.RequestOrigin
	Method    authz.Method
	Path      string
	Technique authz.Technique
	Hop       int
	Attempt   int
}

// NewZapRequestProposal builds the nuclei driver's sealed RequestProposal from ZAP facts.
//
// It reuses RequestProposal rather than declaring a second proposal type, so
// that plan/design/dynamic-tier.md exit criterion 19 — "zero methods or fields capable of
// performing network I/O, proven by reflection" — is proved once for both
// engines by the test the nuclei driver already wrote.
func NewZapRequestProposal(f ZapProposalFacts) (RequestProposal, error) {
	if !f.Plan.Constructed() {
		return RequestProposal{}, fmt.Errorf("engines: %w: the proposal names no automation "+
			"plan. A ZAP request that cannot be traced to the plan that configured the "+
			"scan has unknown provenance, exactly as an unattributable Nuclei result does",
			ErrUnconstructed)
	}
	allowed := false
	for _, o := range zapProposalOrigins() {
		if o == f.Origin {
			allowed = true
			break
		}
	}
	if !allowed {
		return RequestProposal{}, fmt.Errorf("engines: %w: this driver does not propose "+
			"requests of origin %q. The ZAP driver generates an active-scan plan and nothing else: "+
			"there is no template, no headless browser, no WebSocket job and no "+
			"out-of-band callback in it, so there is no request of those origins for it "+
			"to propose. The crawl's Client Spider is what widens this",
			ErrRefused, redactIdentifier(string(f.Origin)))
	}
	id, err := zapRuleIdentity(f.RuleID)
	if err != nil {
		return RequestProposal{}, err
	}
	return NewRequestProposal(ProposalFacts{
		Spec:           f.Spec,
		Origin:         f.Origin,
		Method:         f.Method,
		Path:           f.Path,
		Technique:      f.Technique,
		TemplateID:     id,
		TemplateDigest: f.Plan.Digest(),
		Hop:            f.Hop,
		Attempt:        f.Attempt,
	})
}

// ---------------------------------------------------------------------------
// The driver
// ---------------------------------------------------------------------------

// ZapConfig is everything a ZapDriver needs. Every field is required except
// Runner and Issuer, and each of those being absent is a LOUD refusal at the
// point it is needed rather than a quiet clean result.
type ZapConfig struct {
	// Governor is the kernel's per-request interceptor for this target.
	Governor *authz.Governor
	// Audit is gate 21's writer, coupled to the interceptor by AuditedAdmit.
	Audit *authz.GateAudit
	// Authorization is the kernel token for Target.
	Authorization authz.Authorization
	// Target is the admitted target this driver scans.
	Target authz.Target
	// Caps are the four bounded ZAP caps.
	Caps ZapCaps
	// Proxy is Anvil's chokepoint, which is ZAP's only route out.
	Proxy ZapProxy
	// RunID is the X-Anvil-Scan value.
	RunID string
	// ReportDir is the absolute directory reports land in.
	ReportDir string
	// Runner is the ZAP process seam. A nil Runner is legal to construct and
	// produces *ZapUnavailableError at Autorun.
	Runner ZapRunner
	// Issuer is the egress layer, shared with the nuclei driver. A nil Issuer is legal to
	// construct and produces ErrNoEgress at Fire.
	Issuer Issuer
}

// ZapDriver is the ZAP driver.
//
// # It is trigger-agnostic, and that is the ZAP driver's instruction rather than an
// # oversight
//
// The ZAP driver's forbidden actions: "Do not run ZAP in the always-on
// /incremental path — it is gated to scheduled full scans only, enforced by
// the caller's trigger-policy check, not by this driver refusing to run (the
// driver itself should be trigger-agnostic; the gating is a config/scheduling
// concern)."
//
// So there is no trigger check here and no field for one. WHERE THAT
// SCHEDULED-ONLY RULE IS ENFORCED: nowhere in this package. That is stated
// rather than implied, and internal/SKIPPED-CONTROLS.md U5 records it as an
// unenforced contract with the name of the check that must exist elsewhere.
type ZapDriver struct {
	mu       sync.Mutex
	cfg      ZapConfig
	spec     TargetSpec
	plan     ZapAutomationPlan
	cov      ZapCoverage
	findings []Finding
	sealed   bool
}

// NewZapDriver assembles the driver.
//
// It builds the TargetSpec here — so a ZapDriver that exists at all is one
// whose target passed gates 8, 9 and 10 — and it renders and verifies the
// automation plan here, so a driver that exists at all has a plan whose four
// caps are bounded. Neither is deferred to first use: a driver that constructs
// and then refuses at scan time is a scan window spent discovering a
// configuration error.
func NewZapDriver(cfg ZapConfig) (*ZapDriver, error) {
	if !cfg.Governor.Constructed() {
		return nil, fmt.Errorf("engines: %w: the driver was handed a Governor "+
			"authz.NewGovernor never built. A nil governor enforces nothing, and enforcing "+
			"nothing is not admitting everything", ErrUnconstructed)
	}
	if !cfg.Audit.Constructed() {
		return nil, fmt.Errorf("engines: %w: the driver was handed a GateAudit "+
			"authz.NewGateAudit never built. Gate 21 requires every decision recorded, and "+
			"a driver with no audit writer records none", ErrUnconstructed)
	}
	spec, err := NewTargetSpec(cfg.Authorization, cfg.Target)
	if err != nil {
		return nil, err
	}
	plan, err := NewZapAutomationPlan(ZapPlanFacts{
		Spec:      spec,
		Caps:      cfg.Caps,
		Proxy:     cfg.Proxy,
		RunID:     cfg.RunID,
		ReportDir: cfg.ReportDir,
	})
	if err != nil {
		return nil, err
	}
	return &ZapDriver{
		cfg:  cfg,
		spec: spec,
		plan: plan,
		cov: ZapCoverage{
			PlanVerified:    true,
			RunnerWired:     cfg.Runner != nil,
			IssuerWired:     cfg.Issuer != nil,
			ReportsDeclared: len(plan.ReportTemplates()),
		},
		sealed: true,
	}, nil
}

// Constructed reports whether d came from NewZapDriver.
func (d *ZapDriver) Constructed() bool { return d != nil && d.sealed }

// Spec returns the authorized destination this driver scans.
func (d *ZapDriver) Spec() TargetSpec {
	if !d.Constructed() {
		return TargetSpec{}
	}
	return d.spec
}

// Plan returns the verified automation plan.
func (d *ZapDriver) Plan() ZapAutomationPlan {
	if !d.Constructed() {
		return ZapAutomationPlan{}
	}
	return d.plan
}

func (d *ZapDriver) count(f func(*ZapCoverage)) {
	d.mu.Lock()
	defer d.mu.Unlock()
	f(&d.cov)
}

// Fire routes one request ZAP made through the kernel and, only if the kernel
// admits it, issues it.
//
// It is the same order as the nuclei driver's Fire, with one substitution: where the Nuclei
// driver looks the proposal's template up in its admitted set, this one checks
// the proposal's digest against the plan it rendered. Both are "attributed by
// identity, never by position", and both exist for the same reason — without
// the check, a request from a scan configuration this driver did not build
// would still reach the kernel, and the kernel would admit it, because the
// kernel gates destinations and not provenance.
func (d *ZapDriver) Fire(ctx context.Context, p RequestProposal, now authz.Clock) (Finding, error) {
	if !d.Constructed() {
		return Finding{}, fmt.Errorf("engines: %w: Fire was called on a ZapDriver "+
			"NewZapDriver never built", ErrUnconstructed)
	}
	if !p.Constructed() {
		d.count(func(c *ZapCoverage) { c.RequestsRefused++ })
		return Finding{}, fmt.Errorf("engines: %w: the proposal was not built by "+
			"NewZapRequestProposal", ErrUnconstructed)
	}

	id, digest := p.TemplateIdentity()
	if digest != d.plan.Digest() {
		d.count(func(c *ZapCoverage) { c.RequestsRefused++ })
		// The proposal's digest is whatever the caller put on it and has
		// matched nothing, so it is REDACTED. The driver's own is the digest
		// it computed over the bytes it rendered, so it is not.
		return Finding{}, fmt.Errorf("engines: %w: the proposal carries plan digest %s and "+
			"this driver rendered %s. A request from a scan configuration this driver did "+
			"not build has unknown caps and unknown scope, and the kernel would admit it "+
			"anyway because the kernel gates destinations, not provenance",
			ErrRefused, redactIdentifier(digest), d.plan.Digest())
	}
	if !strings.HasPrefix(id, "zap:rule:") {
		d.count(func(c *ZapCoverage) { c.RequestsRefused++ })
		return Finding{}, fmt.Errorf("engines: %w: the proposal's identity %q is not a ZAP "+
			"rule identity. Only NewZapRequestProposal mints one", ErrRefused,
			redactIdentifier(id))
	}

	if err := authz.RequireAuthorization(d.cfg.Authorization, p.Spec().Target()); err != nil {
		d.count(func(c *ZapCoverage) { c.RequestsRefused++ })
		return Finding{}, fmt.Errorf("engines: %w: %w", ErrRefused, err)
	}

	intent, err := authz.NewRequestIntent(authz.RequestFacts{
		Origin:   p.Origin(),
		Admitted: d.cfg.Target,
		Next:     p.Spec().Target(),
		Method:   p.Method(),
		Path:     p.Path(),
		Hop:      p.Hop(),
		Attempt:  p.Attempt(),
	})
	if err != nil {
		d.count(func(c *ZapCoverage) { c.RequestsRefused++ })
		return Finding{}, fmt.Errorf("engines: %w: %w", ErrRefused, err)
	}

	lease, res := d.cfg.Audit.AuditedAdmit(d.cfg.Governor, intent, p.Technique(), now)
	if !res.Passed() {
		d.count(func(c *ZapCoverage) { c.RequestsRefused++ })
		return Finding{}, fmt.Errorf("engines: %w: the kernel refused this request at %s: %w",
			ErrRefused, res.Gate(), res.Err())
	}
	defer lease.Release()

	seq := d.cfg.Audit.LastSeq()

	if d.cfg.Issuer == nil {
		d.count(func(c *ZapCoverage) { c.RequestsAdmitted++ })
		return Finding{}, fmt.Errorf("engines: %w: the kernel admitted a request to %s and "+
			"there is nowhere to send it. This is a refusal and not a clean probe: gate 3 "+
			"forbids this package from constructing the socket itself, so an unwired "+
			"Issuer means the request DID NOT RUN", ErrNoEgress, p.Spec().URL())
	}

	req := AdmittedRequest{proposal: p, auth: d.cfg.Authorization, seq: seq, sealed: true}
	out, ierr := d.cfg.Issuer.Issue(ctx, req)
	if ierr != nil {
		d.count(func(c *ZapCoverage) { c.RequestsAdmitted++ })
		return Finding{}, fmt.Errorf("engines: issuing an admitted request to %s: %w",
			p.Spec().URL(), ierr)
	}

	evidence, stats := scrub(out.Evidence)
	d.count(func(c *ZapCoverage) {
		c.RequestsAdmitted++
		c.RequestsIssued++
		c.Evidence.Merge(stats)
		if out.Matched {
			c.Matches++
		}
	})

	f := Finding{
		TemplateID:     id,
		TemplateDigest: d.plan.Digest(),
		TemplatePath:   "",
		Target:         p.Spec().Target().String(),
		Method:         p.Method(),
		Path:           p.Path(),
		Technique:      p.Technique(),
		Origin:         p.Origin(),
		Status:         out.Status,
		Matched:        out.Matched,
		BodyBytes:      out.BodyBytes,
		Evidence:       evidence,
		AuditSeq:       seq,
		At:             now.Instant(),
	}
	if out.Matched {
		d.mu.Lock()
		d.findings = append(d.findings, f)
		d.mu.Unlock()
	}
	return f, nil
}

// Autorun hands the plan to the runner and refuses everything that looks like
// a scan but was not one.
//
// # The three ways "ZAP succeeded" is a lie, and what each returns
//
//	no runner wired          *ZapUnavailableError, exit code 2. Nothing ran.
//	non-zero exit code       an error naming the code and the scrubbed stderr.
//	exit 0, report missing   ErrZapReportMissing. ZAP can exit 0 having
//	                         produced no report — a failed report job, a
//	                         report directory it could not write — and the
//	                         resulting finding list is byte-identical to a
//	                         clean target's.
//
// It does NOT increment RequestsIssued, for the same reason the nuclei driver's Run does
// not: this driver does not observe what ZAP put on the wire, and counting a
// request it did not see would invent the one number
// ZapScanResult.AssertNotSilentlyEmpty rests on. The requests are counted
// where they are actually seen, in Fire, at the proxy.
func (d *ZapDriver) Autorun(ctx context.Context, zapSh, planPath string) error {
	if !d.Constructed() {
		return fmt.Errorf("engines: %w: Autorun was called on a ZapDriver NewZapDriver "+
			"never built", ErrUnconstructed)
	}
	if d.cfg.Runner == nil {
		return &ZapUnavailableError{
			Name: ZapEngineName,
			Detail: "the driver was constructed with no ZapRunner, so `zap.sh -cmd " +
				"-autorun` was never executed and no scan rule ever ran",
		}
	}
	// Re-verify immediately before handing the document over. The plan was
	// verified at construction; this catches a plan that travelled through a
	// value copy that zeroed something, and costs one pass over a few KiB.
	if err := d.plan.Verify(); err != nil {
		return err
	}
	inv, err := d.plan.Invocation(zapSh, planPath)
	if err != nil {
		return err
	}

	out, rerr := d.cfg.Runner.Autorun(ctx, inv)
	stderr, stats := scrub(out.Stderr)
	d.count(func(c *ZapCoverage) {
		c.Evidence.Merge(stats)
		c.ExitCode = out.ExitCode
		c.RunAttempted = true
	})
	if rerr != nil {
		return fmt.Errorf("engines: running %s: %w", ZapEngineName, rerr)
	}
	if out.ExitCode != 0 {
		return fmt.Errorf("engines: %w: %s exited %d. A non-zero exit is not an empty "+
			"finding list; it is a scan that did not complete. stderr: %s",
			ErrRefused, ZapEngineName, out.ExitCode, stderr)
	}

	written := map[ZapReportTemplate]bool{}
	for _, r := range out.Reports {
		if r.Bytes > 0 && r.Path != "" {
			written[r.Template] = true
		}
	}
	var missing []string
	for _, want := range d.plan.ReportTemplates() {
		if !written[want] {
			missing = append(missing, string(want))
		}
	}
	d.count(func(c *ZapCoverage) { c.ReportsWritten = len(written) })
	if len(missing) > 0 {
		return fmt.Errorf("engines: %w: %s exited 0 and wrote no non-empty report for "+
			"template(s) %s. A scan whose report never landed produces the same empty "+
			"finding list a clean target produces, and the two must not be reported alike",
			ErrZapReportMissing, ZapEngineName, strings.Join(missing, ", "))
	}
	return nil
}

// Result returns what this driver has done so far.
func (d *ZapDriver) Result() ZapScanResult {
	if !d.Constructed() {
		return ZapScanResult{}
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	out := ZapScanResult{
		Coverage: d.cov,
		Target:   d.spec.Target().String(),
	}
	if d.findings != nil {
		out.Findings = make([]Finding, len(d.findings))
		copy(out.Findings, d.findings)
	}
	return out
}

// ---------------------------------------------------------------------------
// Coverage and the anti-vacuity predicate
// ---------------------------------------------------------------------------

// ZapCoverage is what actually ran.
//
// # Why this is not the nuclei driver's Coverage
//
// Coverage.ProbedNothing is `TemplatesAdmitted == 0 || RequestsIssued == 0`,
// and ZAP has no templates. Embedding it would make ProbedNothing true for
// every ZAP scan that ever ran, which is a guard that fires always — and a
// guard that fires always gets suppressed, which is worse than not having it.
// Setting TemplatesAdmitted to a number ZAP does not have would be a lie in a
// field the report prints. So this is a sibling type with the same shape and a
// predicate that means something here.
type ZapCoverage struct {
	// RequestsAdmitted is how many proposals the kernel let through.
	RequestsAdmitted int
	// RequestsRefused is how many it refused, plus those this driver refused
	// before asking.
	RequestsRefused int
	// RequestsIssued is how many actually left the process, counted at the
	// proxy in Fire. It is the number that decides whether an empty finding
	// list means anything.
	RequestsIssued int
	// Matches is how many issued requests came back a match.
	Matches int
	// ReportsDeclared and ReportsWritten are the report artifacts the plan
	// asked for and the ones the runner observed.
	ReportsDeclared int
	ReportsWritten  int
	// RunAttempted records whether a runner was actually invoked, and
	// ExitCode what it returned. Both are zero for a scan that never ran,
	// and RunAttempted is what tells that apart from a scan that ran and
	// exited 0.
	RunAttempted bool
	ExitCode     int
	// PlanVerified records that the automation plan survived Verify. It is
	// false on the zero value, which is the fail-closed direction.
	PlanVerified bool
	// RunnerWired and IssuerWired record whether the two seams had
	// implementations at all.
	RunnerWired bool
	IssuerWired bool
	// Evidence is the merged scrub report over every external string this
	// driver retained — ZAP's stderr and any evidence prose from the Issuer.
	Evidence EvidenceStats
}

// ScannedNothing reports whether this run put no request on the wire.
//
// TRUE for the zero value, which is the fail-closed direction: a ZapCoverage
// nobody filled in describes a scan nobody ran.
func (c ZapCoverage) ScannedNothing() bool {
	return !c.PlanVerified || c.RequestsIssued == 0
}

// ZapScanResult is one ZAP driver's run.
type ZapScanResult struct {
	// Findings is the driver's output.
	Findings []Finding
	// Coverage is populated on every run, including the zero-findings case.
	Coverage ZapCoverage
	// Target is the kernel's rendering of the target.
	Target string
}

// AssertNotSilentlyEmpty refuses to let a caller read "no findings" as "no
// vulnerabilities" when in fact nothing was scanned.
//
// Call it before reporting a clean target. It is the same refusal as
// ScanResult.AssertNotSilentlyEmpty and internal/collector/repo's, with ZAP's
// own failure modes named — in particular the one neither of the others has:
// ZAP exiting 0 having written no report.
func (r ZapScanResult) AssertNotSilentlyEmpty() error {
	c := r.Coverage
	switch {
	case !c.PlanVerified:
		return fmt.Errorf("%w: no verified ZAP automation plan exists for %q, so the four "+
			"scan caps were never checked and no scan was ever configured. An empty "+
			"finding list here records that nothing was set up",
			ErrNothingProbed, r.Target)
	case !c.RunnerWired && !c.RunAttempted:
		return fmt.Errorf("%w: no ZAP runner was wired and none was invoked against %q. "+
			"`%s` is not installed on this host and this driver registers no default "+
			"adapter, so an empty finding list here records the absence of a scanner, not "+
			"the absence of findings", ErrNothingProbed, r.Target, ZapEngineName)
	case c.ReportsDeclared > 0 && c.ReportsWritten < c.ReportsDeclared:
		return fmt.Errorf("%w: %d of %d declared ZAP report(s) were written for %q. ZAP can "+
			"exit 0 having produced no report, and a run with no report produces the same "+
			"empty finding list a clean target produces",
			ErrNothingProbed, c.ReportsWritten, c.ReportsDeclared, r.Target)
	case c.RequestsIssued == 0:
		return fmt.Errorf("%w: zero requests reached the wire for %q (%d admitted by the "+
			"kernel, %d refused). Every request ZAP makes goes through Anvil's proxy and "+
			"is counted there, so zero here means ZAP either never started or was not "+
			"proxied — and an unproxied ZAP is a scan the kernel never saw",
			ErrNothingProbed, r.Target, c.RequestsAdmitted, c.RequestsRefused)
	}
	return nil
}
