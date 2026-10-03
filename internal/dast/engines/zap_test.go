// The ZAP driver's evidence.
//
// ===========================================================================
// WHAT THIS SUITE CAN PROVE ON THIS HOST, AND WHAT IT CANNOT
// ===========================================================================
//
// ZAP is NOT INSTALLED here. MEASURED 2026-08-22 from PowerShell on the
// Windows 11 development machine (re-measured 2026-10-03 on the Debian one:
// zap.sh, docker and java are all absent there):
//
//	Get-Command zap.sh  -> NOT FOUND
//	Get-Command zap     -> NOT FOUND
//	Get-Command zap.bat -> NOT FOUND
//	Get-Command docker  -> NOT FOUND
//	Get-Command java    -> C:\Program Files\Common Files\Oracle\Java\javapath\java.exe
//	java -version       -> 23.0.2 2025-01-21 (HotSpot 23.0.2+7-58)
//
// A JVM is present and ZAP is not, so no test here runs ZAP and none pretends
// to. The process is behind an interface, driven by recorded shapes, and
// SystemZapRunner refuses on every host rather than returning a no-op that
// would let a scan come back clean.
//
// The SECOND gap was the nuclei driver's and it is now CLOSED. Gate 11 used to sit in
// authz.admissionChain with no implementation, so the chain refused every
// target there, so authz.Adjudicate - the only mint for an
// authz.Authorization - could never mint one, and no ZapDriver could be built
// through the production route at all.
//
// nuclei_test.go's TestNoAuthorizationCanBeMintedUntilGate11IsRegistered was
// the tripwire for that condition. It fired. Gate 11 is now a SCOPE NARROWING
// (authz.NarrowScopeToRobots, applied once at run initiation over bytes the
// target served), admissionChain is {4,5,6,8,9,10}, and the kernel admits.
//
// So TestZapFireAdmitsAndIssuesEndToEndWithOneAuditRowPerGate and
// TestZapFireRefusesAnOutOfScopeRedirectAndIssuesNothing drive NewZapDriver
// against a REAL authz.Authorization, end to end, through Fire to the Issuer.
// They are the first evidence that this driver admits anything as well as
// refusing; U5(c) recorded the blocker and is closed by them.
//
// Where a test below needs a sealed TargetSpec and does NOT need a kernel, it
// still FORGES one with a composite literal, which is possible only because
// this is an in-package test. That is the same device nuclei_test.go uses and
// it is stated rather than hidden: no code outside package engines can do it,
// and the tests that exercise the authorization boundary itself now use the
// production route in both directions.
//
// docs/controls.md U5 records what remains unexecuted, including
// the one plan/design/dynamic-tier.md explicitly asked this step to answer — ZAP's JVM
// memory footprint â€” which is NOT answered here, because there is no ZAP to
// measure and a fabricated number would become tier-M sizing documentation.
//
// This file contains no t.Skip. nuclei_test.go's TestThisFileSkipsNothing and
// TestThisPackageConstructsNoSocket both walk every .go file in this package,
// so they cover this file automatically; that is why this file adds neither.
package engines

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/Susquehanna-Syntax/Anvil/internal/dast/authz"
)

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

const zapFixtureRunID = "anvil-run-2026-08-22-001"

// The fixture paths are BUILT FOR THE RUNNING PLATFORM, not written as
// literals.
//
// filepath.IsAbs is what ZapAutomationPlan.Invocation checks, and on Windows
// "/opt/zap/zap.sh" is rooted but NOT absolute â€” it names no volume â€” so a
// Unix-shaped literal makes every invocation test assert a refusal it did not
// intend on this host while passing on a Linux runner. MEASURED: that is
// exactly what the first run of this suite did, on this machine, from
// PowerShell.
//
// Nothing here has to exist on disk: Invocation validates the shape of a path
// and never touches the filesystem, which is the correct division â€” a runner
// that cannot find zap.sh reports that itself.
var (
	zapFixtureDir    = filepath.Join(os.TempDir(), "anvil-zap-fixture")
	zapFixtureZapSh  = filepath.Join(zapFixtureDir, "zap.sh")
	zapFixturePlanAt = filepath.Join(zapFixtureDir, "zap.yaml")
)

// TestTheFixturePathsAreAbsoluteOnThisPlatform. Without this, a platform where
// os.TempDir returned something filepath.IsAbs rejects would turn every
// invocation test into a vacuous refusal.
func TestTheFixturePathsAreAbsoluteOnThisPlatform(t *testing.T) {
	for _, p := range []string{zapFixtureDir, zapFixtureZapSh, zapFixturePlanAt} {
		if !filepath.IsAbs(p) {
			t.Fatalf("the fixture path %q is not absolute on %s, so every Invocation "+
				"test below would assert a refusal it did not intend", p, runtime.GOOS)
		}
	}
	if !strings.HasSuffix(zapFixturePlanAt, ".yaml") {
		t.Fatalf("the fixture plan path %q does not end in .yaml", zapFixturePlanAt)
	}
}

// zapSpec forges a sealed TargetSpec.
//
// It is kept, and it is no longer the only option. NewTargetSpec is the
// production route and it requires an authz.Authorization, which USED to be
// unmintable from outside package authz; gate 11 is now a scope narrowing and
// one can be minted, so TestZapFireAdmitsAndIssuesEndToEndWithOneAuditRowPerGate
// drives NewZapDriver against a real token and a real spec.
//
// This forgery stays for the tests BELOW the authorization boundary — plan
// rendering, invocation shape, report checking — which do not need a kernel
// and should not pay for one. A composite literal works here ONLY because this
// is an in-package test; TestNoStringLiteralTargetReachesTheEngine in
// nuclei_test.go asserts that the implementation writes these fields in
// exactly one place, so this forgery cannot be mirrored by production code.
func zapSpec(t *testing.T) TargetSpec {
	t.Helper()
	return TargetSpec{
		url:    "https://" + fixtureHost + ":443",
		pinned: "203.0.113.7:443",
		target: mustBareTarget(t),
		sealed: true,
	}
}

func zapProxy(t *testing.T) ZapProxy {
	t.Helper()
	p, err := NewZapProxy(netip.AddrPortFrom(mustAddr(t, "127.0.0.1"), 8081))
	if err != nil {
		t.Fatalf("NewZapProxy on loopback: %v", err)
	}
	return p
}

func zapCeilingCaps(t *testing.T) ZapCaps {
	t.Helper()
	c, err := ZapCapsAtKernelCeiling(authz.CodedCaps())
	if err != nil {
		t.Fatalf("ZapCapsAtKernelCeiling(authz.CodedCaps()): %v", err)
	}
	return c
}

func zapPlan(t *testing.T) ZapAutomationPlan {
	t.Helper()
	p, err := NewZapAutomationPlan(ZapPlanFacts{
		Spec:      zapSpec(t),
		Caps:      zapCeilingCaps(t),
		Proxy:     zapProxy(t),
		RunID:     zapFixtureRunID,
		ReportDir: t.TempDir(),
	})
	if err != nil {
		t.Fatalf("NewZapAutomationPlan on a wholly valid fixture: %v. Every negative case "+
			"in this file rests on this one constructing, so a failure here means the "+
			"negatives are passing vacuously", err)
	}
	return p
}

func intp(v int) *int { return &v }

// yamlValue pulls the value of a `key:` line out of a rendered plan. It fails
// unless the key appears exactly once, because a test that read the first of
// two would silently stop checking the second.
func yamlValue(t *testing.T, doc, key string) string {
	t.Helper()
	var found []string
	for _, line := range strings.Split(doc, "\n") {
		s := strings.TrimSpace(line)
		if strings.HasPrefix(s, "#") {
			continue
		}
		s = strings.TrimPrefix(s, "- ")
		if strings.HasPrefix(s, key+":") {
			found = append(found, strings.TrimSpace(s[len(key)+1:]))
		}
	}
	if len(found) != 1 {
		t.Fatalf("the rendered plan carries %d %q line(s); want exactly 1.\n---\n%s\n---",
			len(found), key, doc)
	}
	return found[0]
}

// ---------------------------------------------------------------------------
// The ZAP driver's first named validation: all four caps, always explicit and bounded
// ---------------------------------------------------------------------------

// TestTheFourZapCapsAreExplicitNonZeroAndBoundedInEveryGeneratedPlan is
// the ZAP driver's design "Test asserting the generated zap.yaml always
// contains explicit non-zero, non-'unlimited' values for all four caps".
//
// It asserts more than presence. Each cap must parse as a bare positive
// decimal integer (so "unlimited", "0", "-1", "030" and a quoted "400" all
// fail), must appear exactly once (so ZAP cannot read a second one this
// driver did not choose), and must EQUAL the sealed ZapCaps that NewZapCaps
// checked against gate 14 â€” which is the case where the validated number and
// the number ZAP reads have come apart.
func TestTheFourZapCapsAreExplicitNonZeroAndBoundedInEveryGeneratedPlan(t *testing.T) {
	caps := zapCeilingCaps(t)
	plan, err := NewZapAutomationPlan(ZapPlanFacts{
		Spec:      zapSpec(t),
		Caps:      caps,
		Proxy:     zapProxy(t),
		RunID:     zapFixtureRunID,
		ReportDir: t.TempDir(),
	})
	if err != nil {
		t.Fatalf("NewZapAutomationPlan: %v", err)
	}
	doc := plan.YAML()

	for _, c := range []struct {
		key  string
		want int
	}{
		{"delayInMs", caps.DelayInMs()},
		{"maxScanDurationInMins", caps.MaxScanDurationInMins()},
		{"maxRuleDurationInMins", caps.MaxRuleDurationInMins()},
		{"threadPerHost", caps.ThreadPerHost()},
	} {
		raw := yamlValue(t, doc, c.key)
		got, ok := bareUint(raw)
		if !ok {
			t.Fatalf("%s rendered as %q, which is not a bare positive decimal integer. "+
				"research/19 line 164 step 6: every one of ZAP's four caps defaults to "+
				"UNLIMITED, so a value ZAP cannot parse is a value ZAP does not bound",
				c.key, raw)
		}
		if got <= 0 {
			t.Fatalf("%s rendered as %d. Zero IS unlimited in ZAP", c.key, got)
		}
		if got != c.want {
			t.Fatalf("%s rendered as %d but the sealed ZapCaps says %d. The value ZAP "+
				"reads has come apart from the value gate 14 checked", c.key, got, c.want)
		}
		if strings.Contains(strings.ToLower(raw), "unlimited") {
			t.Fatalf("%s rendered as %q", c.key, raw)
		}
	}

	// The relation, not only the values. Every cap is derived from gate 14's
	// coded floors, so pin the derivation rather than four literals.
	wantThreads := authz.CodedMaxConcurrentPerHost
	if caps.ThreadPerHost() != wantThreads {
		t.Fatalf("threadPerHost = %d; the ceiling must be gate 14's "+
			"CodedMaxConcurrentPerHost = %d", caps.ThreadPerHost(), wantThreads)
	}
	wantDelay := (1000*wantThreads + authz.CodedMaxRequestsPerSecondPerHost - 1) /
		authz.CodedMaxRequestsPerSecondPerHost
	if caps.DelayInMs() != wantDelay {
		t.Fatalf("delayInMs = %d; %d thread(s) under gate 14's %d rps/host needs %d",
			caps.DelayInMs(), wantThreads, authz.CodedMaxRequestsPerSecondPerHost, wantDelay)
	}
	if wantDelay != 400 {
		t.Fatalf("the derived delay is %d ms, not the 400 ms that 4 threads at 10 rps "+
			"gives. Gate 14's floors moved; that is not a failure by itself, but this "+
			"line is here so the change is seen rather than absorbed", wantDelay)
	}
	if caps.MaxScanDurationInMins() != int(authz.CodedMaxWallClockPerTarget.Minutes()) {
		t.Fatalf("maxScanDurationInMins = %d; gate 14's wall clock is %s",
			caps.MaxScanDurationInMins(), authz.CodedMaxWallClockPerTarget)
	}
}

// TestEveryOneOfTheFourCapsRefusesItsOwnZero is the forgotten-field case, one
// field at a time.
//
// Go's zero value for an int is 0 and ZAP reads 0 as unlimited, so the two
// line up exactly: a struct somebody half-filled produces a scan with no
// bound. Each row zeroes ONE field and asserts the refusal names it. The
// final row zeroes nothing and asserts construction succeeds, without which
// every other row would pass against a constructor that refused everything.
func TestEveryOneOfTheFourCapsRefusesItsOwnZero(t *testing.T) {
	kernel := authz.CodedCaps()
	good := ZapCapFacts{
		DelayInMs:             400,
		MaxScanDurationInMins: 30,
		MaxRuleDurationInMins: 5,
		ThreadPerHost:         4,
	}
	if _, err := NewZapCaps(kernel, good); err != nil {
		t.Fatalf("the all-good row was refused: %v. Every negative row below would then "+
			"pass vacuously", err)
	}

	for _, tc := range []struct {
		name  string
		mut   func(*ZapCapFacts)
		named string
	}{
		{"delayInMs", func(f *ZapCapFacts) { f.DelayInMs = 0 }, "delayInMs"},
		{"maxScanDurationInMins", func(f *ZapCapFacts) { f.MaxScanDurationInMins = 0 }, "maxScanDurationInMins"},
		{"maxRuleDurationInMins", func(f *ZapCapFacts) { f.MaxRuleDurationInMins = 0 }, "maxRuleDurationInMins"},
		{"threadPerHost", func(f *ZapCapFacts) { f.ThreadPerHost = 0 }, "threadPerHost"},
		{"delayInMs negative", func(f *ZapCapFacts) { f.DelayInMs = -1 }, "delayInMs"},
		{"threadPerHost negative", func(f *ZapCapFacts) { f.ThreadPerHost = -4 }, "threadPerHost"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := good
			tc.mut(&f)
			_, err := NewZapCaps(kernel, f)
			if err == nil {
				t.Fatalf("NewZapCaps accepted %+v. ZAP reads 0 as unlimited for all four "+
					"of these keys", f)
			}
			if !errors.Is(err, ErrZapCapUnbounded) {
				t.Fatalf("error does not wrap ErrZapCapUnbounded: %v", err)
			}
			if !strings.Contains(err.Error(), tc.named) {
				t.Fatalf("the refusal does not name %q, so an operator cannot tell which "+
					"field they left out: %v", tc.named, err)
			}
		})
	}

	// A ZapCaps nobody built must not be renderable either.
	if (ZapCaps{}).Constructed() {
		t.Fatal("the zero ZapCaps reports Constructed() == true, so four unlimited caps " +
			"would render")
	}
	_, err := NewZapAutomationPlan(ZapPlanFacts{
		Spec:      zapSpec(t),
		Caps:      ZapCaps{},
		Proxy:     zapProxy(t),
		RunID:     zapFixtureRunID,
		ReportDir: t.TempDir(),
	})
	if !errors.Is(err, ErrZapCapUnbounded) {
		t.Fatalf("a plan was rendered from a zero ZapCaps: err = %v", err)
	}
}

// TestNoZapCapCanExceedTheGate14FloorItSitsUnder.
//
// Gate 14's floors are consts no configuration may raise (authz.Cap.Lower
// refuses anything above the current effective value, and refuses a SEQUENCE
// of calls walking one back up). These four checks are what stops a ZAP plan
// disagreeing with them.
func TestNoZapCapCanExceedTheGate14FloorItSitsUnder(t *testing.T) {
	kernel := authz.CodedCaps()

	for _, tc := range []struct {
		name string
		f    ZapCapFacts
		want string
	}{
		{
			name: "threadPerHost above concurrent-per-host",
			f:    ZapCapFacts{DelayInMs: 1000, MaxScanDurationInMins: 30, MaxRuleDurationInMins: 5, ThreadPerHost: authz.CodedMaxConcurrentPerHost + 1},
			want: "concurrent-connections-per-host",
		},
		{
			name: "maxScanDurationInMins above wall clock",
			f:    ZapCapFacts{DelayInMs: 400, MaxScanDurationInMins: int(authz.CodedMaxWallClockPerTarget.Minutes()) + 1, MaxRuleDurationInMins: 5, ThreadPerHost: 4},
			want: "wall-clock-per-target",
		},
		{
			name: "maxRuleDurationInMins above maxScanDurationInMins",
			f:    ZapCapFacts{DelayInMs: 400, MaxScanDurationInMins: 10, MaxRuleDurationInMins: 11, ThreadPerHost: 4},
			want: "never binds",
		},
		{
			name: "delayInMs below what the thread count implies",
			f:    ZapCapFacts{DelayInMs: 399, MaxScanDurationInMins: 30, MaxRuleDurationInMins: 5, ThreadPerHost: 4},
			want: "requests/second/host",
		},
		{
			name: "delayInMs legal for one thread but not for four",
			f:    ZapCapFacts{DelayInMs: 100, MaxScanDurationInMins: 30, MaxRuleDurationInMins: 5, ThreadPerHost: 4},
			want: "PER THREAD",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := NewZapCaps(kernel, tc.f)
			if err == nil {
				t.Fatalf("NewZapCaps accepted %+v", tc.f)
			}
			if !errors.Is(err, ErrZapCapUnbounded) {
				t.Fatalf("error does not wrap ErrZapCapUnbounded: %v", err)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("the refusal does not mention %q: %v", tc.want, err)
			}
		})
	}

	// The one-thread case must be ACCEPTED at 100 ms, or the row above
	// proves nothing about the thread count and only that 100 is small.
	if _, err := NewZapCaps(kernel, ZapCapFacts{
		DelayInMs: 100, MaxScanDurationInMins: 30, MaxRuleDurationInMins: 5, ThreadPerHost: 1,
	}); err != nil {
		t.Fatalf("100 ms with ONE thread is exactly gate 14's 10 rps and must be "+
			"accepted: %v", err)
	}

	// A kernel nobody built must not be a floor of zero that accepts
	// everything.
	if _, err := NewZapCaps(authz.Caps{}, ZapCapFacts{
		DelayInMs: 1, MaxScanDurationInMins: 1, MaxRuleDurationInMins: 1, ThreadPerHost: 1,
	}); !errors.Is(err, ErrZapCapUnbounded) {
		t.Fatalf("a zero authz.Caps was accepted as a floor: err = %v", err)
	}
}

// TestTheCapPRODUCTIsCheckedAndNotOnlyEachCapAlone.
//
// PIN THE RELATION, NOT ONLY THE VALUES. Four caps that are each individually
// under their gate-14 floor can still multiply out to more requests than gate
// 14 permits in one run against one target. The fixture below is the same
// ZapCapFacts twice: accepted against the coded floors, refused against a
// kernel whose requests-per-target-run has been LOWERED. Nothing about the
// four numbers changed, so the only thing that can produce the difference is
// the product check.
func TestTheCapPRODUCTIsCheckedAndNotOnlyEachCapAlone(t *testing.T) {
	f := ZapCapFacts{
		DelayInMs:             400,
		MaxScanDurationInMins: 30,
		MaxRuleDurationInMins: 5,
		ThreadPerHost:         4,
	}
	if _, err := NewZapCaps(authz.CodedCaps(), f); err != nil {
		t.Fatalf("the coded floors must accept %+v; if they do not, the contrast below "+
			"proves nothing: %v", f, err)
	}

	tight, res := authz.CodedCaps().Lower(authz.CapOverrides{RequestsPerTargetRun: intp(10000)})
	if !res.Passed() {
		t.Fatalf("lowering requests-per-target-run to 10000 was refused: %v", res.Err())
	}

	_, err := NewZapCaps(tight, f)
	if err == nil {
		t.Fatalf("4 threads at 400 ms for 30 minutes projects 18000 requests, which is " +
			"over a 10000-request run cap, and NewZapCaps accepted it. Each of the four " +
			"caps is individually legal here â€” it is their product that is not")
	}
	if !errors.Is(err, ErrZapCapUnbounded) {
		t.Fatalf("error does not wrap ErrZapCapUnbounded: %v", err)
	}
	for _, want := range []string{"18000", "10000", "PRODUCT"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("the refusal does not mention %q, so a reader cannot see which "+
				"combination was rejected: %v", want, err)
		}
	}

	// And the arithmetic itself, pinned separately so a refactor of the
	// formula is visible rather than absorbed into a message string.
	got, err := zapProjectedRequests(4, 400, 30)
	if err != nil {
		t.Fatalf("zapProjectedRequests: %v", err)
	}
	if got != 18000 {
		t.Fatalf("zapProjectedRequests(4, 400, 30) = %d; 4 threads issuing one request "+
			"every 400 ms for 1800 seconds is 18000", got)
	}
}

// TestTheKernelCeilingTracksTheKernelAndNotALiteral.
//
// ZapCapsAtKernelCeiling exists so a caller with no opinion still gets bounded
// values. If it returned constants it would be a literal in a helper's
// clothing, and it would keep returning 4/400/30/30 after gate 14's floors
// were tightened. So: tighten them, and require every derived value to move.
func TestTheKernelCeilingTracksTheKernelAndNotALiteral(t *testing.T) {
	base := zapCeilingCaps(t)

	tight, res := authz.CodedCaps().Lower(authz.CapOverrides{
		ConcurrentPerHost:        intp(2),
		RequestsPerSecondPerHost: intp(5),
	})
	if !res.Passed() {
		t.Fatalf("lowering concurrency to 2 and rps to 5 was refused: %v", res.Err())
	}
	got, err := ZapCapsAtKernelCeiling(tight)
	if err != nil {
		t.Fatalf("ZapCapsAtKernelCeiling on a lowered kernel: %v", err)
	}
	if got.ThreadPerHost() != 2 {
		t.Fatalf("threadPerHost = %d after lowering concurrency to 2; the ceiling is not "+
			"reading the kernel", got.ThreadPerHost())
	}
	if want := 400; got.DelayInMs() != want {
		t.Fatalf("delayInMs = %d; 2 threads under 5 rps needs %d", got.DelayInMs(), want)
	}
	if got.ThreadPerHost() == base.ThreadPerHost() {
		t.Fatal("the lowered kernel produced the same thread count as the coded one, so " +
			"this test cannot tell a derived value from a constant")
	}

	// The volume relation must bind the ceiling too, independently of the
	// wall clock.
	vol, res := authz.CodedCaps().Lower(authz.CapOverrides{RequestsPerTargetRun: intp(6000)})
	if !res.Passed() {
		t.Fatalf("lowering requests-per-target-run to 6000 was refused: %v", res.Err())
	}
	capped, err := ZapCapsAtKernelCeiling(vol)
	if err != nil {
		t.Fatalf("ZapCapsAtKernelCeiling on a volume-limited kernel: %v", err)
	}
	if capped.MaxScanDurationInMins() >= base.MaxScanDurationInMins() {
		t.Fatalf("maxScanDurationInMins stayed at %d after the run cap fell to 6000; the "+
			"ceiling is honouring the wall clock and ignoring the volume relation",
			capped.MaxScanDurationInMins())
	}
	// Whatever it produced must itself survive the full check.
	if _, err := NewZapCaps(vol, ZapCapFacts{
		DelayInMs:             capped.DelayInMs(),
		MaxScanDurationInMins: capped.MaxScanDurationInMins(),
		MaxRuleDurationInMins: capped.MaxRuleDurationInMins(),
		ThreadPerHost:         capped.ThreadPerHost(),
	}); err != nil {
		t.Fatalf("the ceiling produced caps its own validator refuses: %v", err)
	}
}

// ---------------------------------------------------------------------------
// The ZAP driver's second named validation: attribution
// ---------------------------------------------------------------------------

// TestTheAttributionHeaderAndThePluginIdAreInEveryGeneratedPlan is
// the ZAP driver's design "Test asserting that X-Anvil-Scan: <run-id> and
// injectPluginIdInHeader: true are present so operators can identify Anvil
// traffic". research/19 line 173: "A production operator must be able to
// distinguish Anvil from an attacker in their logs at 3am."
func TestTheAttributionHeaderAndThePluginIdAreInEveryGeneratedPlan(t *testing.T) {
	doc := zapPlan(t).YAML()

	if got := yamlValue(t, doc, "injectPluginIdInHeader"); got != "true" {
		t.Fatalf("injectPluginIdInHeader = %s; want true. Without it no request carries "+
			"X-ZAP-Scan-ID and no single request can be attributed to the rule that "+
			"made it", got)
	}
	if got := yamlValue(t, doc, "matchString"); got != `"X-Anvil-Scan"` {
		t.Fatalf("the replacer rule's matchString = %s; want \"X-Anvil-Scan\"", got)
	}
	if got := yamlValue(t, doc, "matchType"); got != `"req_header"` {
		t.Fatalf("the replacer rule's matchType = %s; want \"req_header\". Any other "+
			"match type edits a body or a response, not the request header", got)
	}
	if got := yamlValue(t, doc, "replacementString"); got != `"`+zapFixtureRunID+`"` {
		t.Fatalf("the replacer rule's replacementString = %s; want the run id %q",
			got, zapFixtureRunID)
	}
	if got := yamlValue(t, doc, "matchRegex"); got != "false" {
		t.Fatalf("matchRegex = %s; a header name matched as a regex is a header name "+
			"whose dots and hyphens are metacharacters", got)
	}
	if got := yamlValue(t, doc, "scanOnlyInScope"); got != "true" {
		t.Fatalf("scanOnlyInScope = %s; the passive scanner must not record findings "+
			"about hosts the kernel did not admit", got)
	}
}

// TestARunIDCannotSmuggleAHeaderOrAYAMLLine.
//
// The run id has two destinations: a YAML scalar and an HTTP header VALUE
// that ZAP attaches to every request. CR or LF in a header value is request
// splitting, and a quote or a newline in a YAML scalar is a second key. So
// the allowlist is [A-Za-z0-9._-] and nothing else, and this table is the
// evidence that it is an allowlist rather than a denylist of the two
// characters somebody thought of.
func TestARunIDCannotSmuggleAHeaderOrAYAMLLine(t *testing.T) {
	for _, tc := range []struct {
		name string
		id   string
	}{
		{"empty", ""},
		{"CRLF", "run\r\nX-Forwarded-For: 10.0.0.1"},
		{"bare LF", "run\nfoo"},
		{"bare CR", "run\rfoo"},
		{"double quote", `run"`},
		{"backslash", `run\`},
		{"space", "run 1"},
		{"colon", "run:1"},
		{"NUL", "run\x00"},
		{"tab", "run\t1"},
		{"DEL", "run\x7f"},
		{"non-ASCII", "run-Ã©"},
		{"zero width", "run\u200b1"},
		{"bidi override", "run\u202e1"},
		{"tag character", "run\U000E0041"},
		{"over the length bound", strings.Repeat("a", maxZapRunIDLen+1)},
		{"YAML flow mapping", "{a: b}"},
		{"comment", "run #x"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := validZapRunID(tc.id); err == nil {
				t.Fatalf("validZapRunID(%q) accepted it", tc.id)
			}
			_, err := NewZapAutomationPlan(ZapPlanFacts{
				Spec:      zapSpec(t),
				Caps:      zapCeilingCaps(t),
				Proxy:     zapProxy(t),
				RunID:     tc.id,
				ReportDir: t.TempDir(),
			})
			if err == nil {
				t.Fatalf("a plan was rendered with run id %q", tc.id)
			}
			if !errors.Is(err, ErrRefused) {
				t.Fatalf("the refusal does not wrap ErrRefused: %v", err)
			}
		})
	}

	// Anti-vacuity: the four characters the allowlist DOES permit must all
	// still work, or the rows above only prove the constructor refuses.
	for _, ok := range []string{"a", "A9", "run-1", "run_1", "run.1", strings.Repeat("z", maxZapRunIDLen)} {
		if err := validZapRunID(ok); err != nil {
			t.Fatalf("validZapRunID(%q) refused a legal id: %v", ok, err)
		}
	}
}

// ---------------------------------------------------------------------------
// Verify is a check that can see the damage
// ---------------------------------------------------------------------------

// TestVerifyRefusesTheRemovalOfEveryLineItGuards.
//
// A GUARD THAT HAS NEVER FAILED HAS NOT BEEN TESTED. This deletes each
// guarded line from an otherwise-good document, one at a time, and requires
// Verify to refuse â€” so the guard is exercised once per line it claims to
// cover rather than once in total.
//
// It runs against a FORGED plan (the yaml field replaced in place), which is
// possible only in an in-package test. That is the point: production code
// cannot reach the field, so the only way this document shape ever changes in
// production is by editing renderZapPlan, and then Verify runs against the
// result at construction time.
func TestVerifyRefusesTheRemovalOfEveryLineItGuards(t *testing.T) {
	good := zapPlan(t)
	if err := good.Verify(); err != nil {
		t.Fatalf("the unmodified plan failed Verify: %v", err)
	}

	guarded := []string{
		"delayInMs:",
		"maxScanDurationInMins:",
		"maxRuleDurationInMins:",
		"threadPerHost:",
		"injectPluginIdInHeader:",
		"scanOnlyInScope:",
		"failOnError:",
		"addQueryParam:",
		"handleAntiCSRFTokens:",
		"matchType:",
		"matchString:",
		"replacementString:",
		"hostname:",
		"port:",
		"context:",
		"url:",
		"includePaths:",
	}
	for _, key := range guarded {
		t.Run(strings.TrimSuffix(key, ":"), func(t *testing.T) {
			p := good
			p.yaml = dropLines(good.yaml, key)
			if p.yaml == good.yaml {
				t.Fatalf("no line containing %q was found to delete, so this row tested "+
					"nothing", key)
			}
			if err := p.Verify(); err == nil {
				t.Fatalf("Verify accepted a plan with every %q line removed", key)
			} else if !errors.Is(err, ErrZapPlanUnverified) {
				t.Fatalf("the refusal does not wrap ErrZapPlanUnverified: %v", err)
			}
		})
	}

	// Both report templates, each deleted in turn.
	for _, tpl := range RequiredZapReportTemplates() {
		t.Run("report_"+string(tpl), func(t *testing.T) {
			p := good
			p.yaml = dropLines(good.yaml, `template: "`+string(tpl)+`"`)
			if p.yaml == good.yaml {
				t.Fatalf("no template line for %q was found", tpl)
			}
			if err := p.Verify(); !errors.Is(err, ErrZapPlanUnverified) {
				t.Fatalf("Verify accepted a plan declaring only one report: %v", err)
			}
		})
	}

	// And the context URL itself.
	t.Run("context_url", func(t *testing.T) {
		p := good
		p.yaml = strings.Replace(good.yaml, `- "`+p.target+`"`, `- "https://elsewhere.invalid:443"`, 1)
		if p.yaml == good.yaml {
			t.Fatal("the context URL line was not found")
		}
		if err := p.Verify(); !errors.Is(err, ErrZapPlanUnverified) {
			t.Fatalf("Verify accepted a plan scoping ZAP to a host the kernel did not "+
				"admit: %v", err)
		}
	})
}

// TestTheConstructorItselfRefusesAnUnverifiableDocument.
//
// Every other Verify test forges a plan and calls Verify directly, so deleting
// the Verify call at the end of newZapAutomationPlan would leave all of them
// green while shipping unverified documents to ZAP. This drives the
// constructor through its renderer seam with a renderer that drops one line,
// and requires NO PLAN to come back.
//
// The final row renders the real document through the same seam, so a
// constructor that refused everything would fail here rather than pass.
func TestTheConstructorItselfRefusesAnUnverifiableDocument(t *testing.T) {
	facts := ZapPlanFacts{
		Spec:      zapSpec(t),
		Caps:      zapCeilingCaps(t),
		Proxy:     zapProxy(t),
		RunID:     zapFixtureRunID,
		ReportDir: t.TempDir(),
	}

	for _, drop := range []string{
		"delayInMs:", "threadPerHost:", "maxScanDurationInMins:",
		"maxRuleDurationInMins:", "injectPluginIdInHeader:", "matchString:",
		"hostname:", "port:", "includePaths:", "type: replacer",
	} {
		t.Run("dropped_"+strings.TrimSuffix(strings.ReplaceAll(drop, " ", "_"), ":"), func(t *testing.T) {
			sabotaged := func(f ZapPlanFacts) (string, error) {
				body, err := renderZapPlan(f)
				if err != nil {
					return "", err
				}
				out := dropLines(body, drop)
				if out == body {
					t.Fatalf("the renderer emitted no line containing %q, so this row "+
						"tested nothing", drop)
				}
				return out, nil
			}
			p, err := newZapAutomationPlan(sabotaged, facts)
			if err == nil {
				t.Fatalf("newZapAutomationPlan returned a plan whose document has no %q "+
					"line. The Verify call at the end of the constructor is what stops "+
					"an unverified document reaching ZAP", drop)
			}
			if !errors.Is(err, ErrZapPlanUnverified) {
				t.Fatalf("the refusal does not wrap ErrZapPlanUnverified: %v", err)
			}
			if p.Constructed() {
				t.Fatal("a refused construction returned a constructed plan")
			}
		})
	}

	// A renderer that returns an error is propagated, not swallowed.
	boom := errors.New("renderer failed")
	if _, err := newZapAutomationPlan(
		func(ZapPlanFacts) (string, error) { return "", boom }, facts,
	); !errors.Is(err, boom) {
		t.Fatalf("a renderer error was swallowed: %v", err)
	}

	// Anti-vacuity: the real renderer through the same seam must succeed.
	if _, err := newZapAutomationPlan(renderZapPlan, facts); err != nil {
		t.Fatalf("the real renderer through the seam was refused: %v. Every row above "+
			"would then pass against a constructor that refuses unconditionally", err)
	}
}

func dropLines(doc, contains string) string {
	var out []string
	for _, line := range strings.Split(doc, "\n") {
		if strings.Contains(line, contains) && !strings.HasPrefix(strings.TrimSpace(line), "#") {
			continue
		}
		out = append(out, line)
	}
	return strings.Join(out, "\n")
}

// TestTheReplacerJobMustRunBeforeTheActiveScan.
//
// ZAP runs Automation Framework jobs in document order. The replacer is what
// attaches X-Anvil-Scan; if it runs after the active scan, the header is
// attached to requests that have already been made and the operator's 3am log
// shows unattributed traffic. So the job list is checked as an ORDERED
// sequence, not as a set.
func TestTheReplacerJobMustRunBeforeTheActiveScan(t *testing.T) {
	good := zapPlan(t)
	doc := good.YAML()

	iRep := strings.Index(doc, "- type: replacer")
	iScan := strings.Index(doc, "- type: activeScan")
	if iRep < 0 || iScan < 0 {
		t.Fatalf("the rendered plan is missing a job:\n%s", doc)
	}
	if iRep > iScan {
		t.Fatal("the replacer job is emitted after the active scan, so the attribution " +
			"header is attached to requests that have already been made")
	}

	// Reordering the jobs must be refused, not merely noticed.
	repBlock := doc[iRep:iScan]
	reordered := strings.Replace(doc, repBlock, "", 1)
	reordered = strings.Replace(reordered, "  - type: report", repBlock+"  - type: report", 1)
	p := good
	p.yaml = reordered
	if err := p.Verify(); !errors.Is(err, ErrZapPlanUnverified) {
		t.Fatalf("Verify accepted a plan whose replacer runs after the active scan: %v", err)
	}

	// So must an EXTRA job nobody declared — a spider or an ajaxSpider added
	// to the document would crawl, and the ZAP driver is not the crawler; the crawl step is.
	p2 := good
	p2.yaml = strings.Replace(doc, "  - type: activeScan",
		"  - type: spider\n  - type: activeScan", 1)
	if err := p2.Verify(); !errors.Is(err, ErrZapPlanUnverified) {
		t.Fatalf("Verify accepted a plan carrying a job this driver did not emit: %v", err)
	}
}

// TestVerifyRefusesEveryShapeOfAnUnboundedCap.
//
// ZAP's default for all four caps is unlimited, so the failure this catches is
// not "a wrong number" but "a number ZAP will not read as a number". Each row
// replaces one cap's rendered value; a permissive parse of any of them would
// let a plan through whose effective cap is ZAP's default.
func TestVerifyRefusesEveryShapeOfAnUnboundedCap(t *testing.T) {
	good := zapPlan(t)
	delay := good.Caps().DelayInMs()
	from := fmt.Sprintf("delayInMs: %d", delay)

	for _, tc := range []struct{ name, to string }{
		{"zero", "delayInMs: 0"},
		{"negative", "delayInMs: -1"},
		{"the word unlimited", "delayInMs: unlimited"},
		{"quoted", `delayInMs: "400"`},
		{"leading zero", "delayInMs: 0400"},
		{"underscored", "delayInMs: 1_000"},
		{"signed", "delayInMs: +400"},
		{"float", "delayInMs: 400.0"},
		{"suffixed", "delayInMs: 400ms"},
		{"null", "delayInMs: null"},
		{"a different bounded value", "delayInMs: 401"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := good
			p.yaml = strings.Replace(good.yaml, from, tc.to, 1)
			if p.yaml == good.yaml {
				t.Fatalf("the substitution %q -> %q changed nothing", from, tc.to)
			}
			if err := p.Verify(); err == nil {
				t.Fatalf("Verify accepted %q", tc.to)
			} else if !errors.Is(err, ErrZapPlanUnverified) {
				t.Fatalf("the refusal does not wrap ErrZapPlanUnverified: %v", err)
			}
		})
	}

	// A DUPLICATED cap is its own failure: ZAP reads one of them and this
	// driver cannot say which.
	t.Run("duplicated", func(t *testing.T) {
		p := good
		p.yaml = strings.Replace(good.yaml, from, from+"\n      "+from, 1)
		if err := p.Verify(); !errors.Is(err, ErrZapPlanUnverified) {
			t.Fatalf("Verify accepted a plan carrying delayInMs twice: %v", err)
		}
	})

	// Anti-vacuity: substituting the SAME value must still verify, or every
	// row above is only proving that string replacement happened.
	t.Run("unchanged", func(t *testing.T) {
		p := good
		p.yaml = strings.Replace(good.yaml, from, from, 1)
		if err := p.Verify(); err != nil {
			t.Fatalf("Verify refused an unmodified document: %v", err)
		}
	})
}

// TestBareUintIsStrict pins the parser Verify rests on, separately, because a
// permissive integer parse is how "0400" or "400ms" would come to mean 400.
func TestBareUintIsStrict(t *testing.T) {
	for _, s := range []string{"", " ", "0400", "+4", "-4", "4.0", "4ms", "1_0", "0x10",
		"ï¼”ï¼ï¼", "4 ", " 4", "unlimited", "1234567890"} {
		if n, ok := bareUint(s); ok {
			t.Errorf("bareUint(%q) = %d, true; want refused", s, n)
		}
	}
	for _, tc := range []struct {
		s string
		n int
	}{{"0", 0}, {"1", 1}, {"400", 400}, {"20000", 20000}, {"999999999", 999999999}} {
		n, ok := bareUint(tc.s)
		if !ok || n != tc.n {
			t.Errorf("bareUint(%q) = %d, %v; want %d, true", tc.s, n, ok, tc.n)
		}
	}
}

// ---------------------------------------------------------------------------
// Containment: ZAP gets a proxy, not egress
// ---------------------------------------------------------------------------

// TestZapIsGivenAProxyAndNeverEgressOfItsOwn.
//
// This is the difference between the nuclei driver and the ZAP driver in one test. Nuclei is driven
// in-process and physically cannot dial from this package (gate 3 tier 1).
// ZAP is a JVM with its own HTTP stack, so the only thing that puts Anvil's
// kernel in front of its requests is env.proxy â€” and if that block can be
// absent, defaulted, or pointed off-box, gate 13 never sees a single request.
func TestZapIsGivenAProxyAndNeverEgressOfItsOwn(t *testing.T) {
	// No proxy at all is a refusal, not a direct-connect default.
	_, err := NewZapAutomationPlan(ZapPlanFacts{
		Spec:      zapSpec(t),
		Caps:      zapCeilingCaps(t),
		Proxy:     ZapProxy{},
		RunID:     zapFixtureRunID,
		ReportDir: t.TempDir(),
	})
	if err == nil {
		t.Fatal("a plan was rendered with no env.proxy. ZAP would then open its own " +
			"connections to the target and the kernel would never see a request")
	}
	if !errors.Is(err, ErrRefused) {
		t.Fatalf("the refusal does not wrap ErrRefused: %v", err)
	}
	if (ZapProxy{}).Constructed() {
		t.Fatal("the zero ZapProxy reports Constructed() == true")
	}

	// Only loopback.
	for _, tc := range []struct {
		name string
		addr string
		port uint16
	}{
		{"public IPv4", "93.184.216.34", 8081},
		{"RFC1918", "10.0.0.5", 8081},
		{"link local", "169.254.169.254", 80},
		{"unspecified v4", "0.0.0.0", 8081},
		{"public IPv6", "2606:2800:220:1:248:1893:25c8:1946", 8081},
		{"unspecified v6", "::", 8081},
		{"loopback with port zero", "127.0.0.1", 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := NewZapProxy(netip.AddrPortFrom(mustAddr(t, tc.addr), tc.port))
			if err == nil {
				t.Fatalf("NewZapProxy accepted %s:%d. Every request the scan makes would "+
					"go to that address", tc.addr, tc.port)
			}
			if !errors.Is(err, ErrRefused) {
				t.Fatalf("the refusal does not wrap ErrRefused: %v", err)
			}
		})
	}
	if _, err := NewZapProxy(netip.AddrPort{}); !errors.Is(err, ErrRefused) {
		t.Fatalf("the zero netip.AddrPort was accepted as a proxy: %v", err)
	}

	// Anti-vacuity: both loopback families, and the v4-mapped-v6 form.
	for _, ok := range []string{"127.0.0.1", "127.0.0.53", "::1", "::ffff:127.0.0.1"} {
		p, err := NewZapProxy(netip.AddrPortFrom(mustAddr(t, ok), 8081))
		if err != nil {
			t.Fatalf("NewZapProxy refused loopback %s: %v", ok, err)
		}
		if !p.Constructed() {
			t.Fatalf("NewZapProxy(%s) returned an unconstructed proxy", ok)
		}
	}

	// And it lands in the document, where Verify checks it.
	doc := zapPlan(t).YAML()
	if got := yamlValue(t, doc, "hostname"); got != `"127.0.0.1"` {
		t.Fatalf("the rendered proxy hostname is %s", got)
	}
	if got := yamlValue(t, doc, "port"); got != "8081" {
		t.Fatalf("the rendered proxy port is %s", got)
	}
}

// TestTheIncludePatternIsRegexQuotedAgainstTheAuthorizedOrigin.
//
// ZAP context includePaths are java.util.regex patterns. An unquoted URL makes
// every metacharacter in the host live: a dot matches any byte, so a scope for
// "a.example.com" also covers "aXexample.com". \Q...\E is the literal quote,
// and the URL grammar check is what makes relying on it safe â€” a URL carrying
// a \E would end the quote early and everything after it would be a pattern.
func TestTheIncludePatternIsRegexQuotedAgainstTheAuthorizedOrigin(t *testing.T) {
	spec := zapSpec(t)
	pattern, err := zapOriginPattern(spec.URL())
	if err != nil {
		t.Fatalf("zapOriginPattern(%q): %v", spec.URL(), err)
	}
	if want := `\Q` + spec.URL() + `\E.*`; pattern != want {
		t.Fatalf("zapOriginPattern = %q; want %q", pattern, want)
	}
	doc := zapPlan(t).YAML()
	if !strings.Contains(doc, `\\Q`) {
		t.Fatalf("the rendered plan carries no \\Q quote, so the host's dots are regex "+
			"metacharacters:\n%s", doc)
	}

	for _, tc := range []struct{ name, url string }{
		{"no scheme", fixtureHost + ":443"},
		{"unknown scheme", "gopher://" + fixtureHost + ":443"},
		{"no port", "https://" + fixtureHost},
		{"non numeric port", "https://" + fixtureHost + ":https"},
		{"regex alternation in host", "https://a|b.example.com:443"},
		{"quote terminator in host", `https://a\Eevil.*:443`},
		{"uppercase host", "https://TARGET.example.com:443"},
		{"underscore in host", "https://tar_get.example.com:443"},
		{"space in host", "https://target example.com:443"},
		{"empty", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := zapOriginPattern(tc.url); err == nil {
				t.Fatalf("zapOriginPattern(%q) accepted it", tc.url)
			}
		})
	}

	// A forged spec whose URL is hostile must not render a plan either â€” the
	// refusal has to be on the generation path, not only in the helper.
	bad := TargetSpec{
		url:    `https://a\Eevil.*:443`,
		pinned: "203.0.113.7:443",
		target: mustBareTarget(t),
		sealed: true,
	}
	if _, err := NewZapAutomationPlan(ZapPlanFacts{
		Spec:      bad,
		Caps:      zapCeilingCaps(t),
		Proxy:     zapProxy(t),
		RunID:     zapFixtureRunID,
		ReportDir: t.TempDir(),
	}); err == nil {
		t.Fatal("a plan was rendered from a target URL that breaks out of the regex quote")
	}
}

// TestYamlScalarIsAnAllowlistAndNotAnEscaper.
//
// An escaper answers "how do I encode this byte safely"; an allowlist answers
// "may this byte be here at all". Only the second is a control. Every row here
// is a byte that would survive escaping into a legal YAML string and then do
// something in a second interpreter.
func TestYamlScalarIsAnAllowlistAndNotAnEscaper(t *testing.T) {
	for _, tc := range []struct{ name, in string }{
		{"empty", ""},
		{"LF", "a\nb"},
		{"CR", "a\rb"},
		{"NUL", "a\x00b"},
		{"DEL", "a\x7fb"},
		{"double quote", `a"b`},
		{"non-ASCII", "cafÃ©"},
		{"zero width", "a\u200bb"},
		{"bidi", "a\u202eb"},
		{"tag character", "a\U000E0041b"},
		{"over the bound", strings.Repeat("a", maxZapScalarBytes+1)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got, err := yamlScalar(tc.in); err == nil {
				t.Fatalf("yamlScalar(%q) = %s, nil", tc.in, got)
			}
		})
	}
	for _, tc := range []struct{ in, want string }{
		{"a", `"a"`},
		{"a b", `"a b"`},
		{`C:\anvil\reports`, `"C:\\anvil\\reports"`},
		{"/var/lib/anvil", `"/var/lib/anvil"`},
		{`\Qhttps://h:443\E.*`, `"\\Qhttps://h:443\\E.*"`},
	} {
		got, err := yamlScalar(tc.in)
		if err != nil {
			t.Fatalf("yamlScalar(%q): %v", tc.in, err)
		}
		if got != tc.want {
			t.Fatalf("yamlScalar(%q) = %s; want %s", tc.in, got, tc.want)
		}
	}
}

// ---------------------------------------------------------------------------
// Reports, and the difference between "ran and found nothing" and "was not there"
// ---------------------------------------------------------------------------

type spyZapRunner struct {
	calls   int
	lastArg []string
	lastPln string
	out     ZapRunOutcome
	err     error
}

func (s *spyZapRunner) Autorun(_ context.Context, inv ZapInvocation) (ZapRunOutcome, error) {
	s.calls++
	s.lastArg = inv.Argv()
	s.lastPln = inv.PlanYAML()
	return s.out, s.err
}

var _ ZapRunner = (*spyZapRunner)(nil)

// zapDriverWithRunner forges a ZapDriver around a real plan.
//
// An authz.Authorization can now be minted (gate 11 is a scope narrowing), and
// TestZapFireAdmitsAndIssuesEndToEndWithOneAuditRowPerGate drives NewZapDriver
// with one. This forgery stays for what does not need a kernel and should not
// pay for one. Everything below the authorization
// boundary â€” the plan, the invocation, the runner seam, the report check â€” is
// exercised here against a driver built by composite literal, and the
// authorization half is asserted as a refusal in
// TestNewZapDriverRefusesEveryUnauthorizedRoute.
func zapDriverWithRunner(t *testing.T, r ZapRunner, out ZapRunOutcome, err error) (*ZapDriver, *spyZapRunner) {
	t.Helper()
	plan := zapPlan(t)
	spy, _ := r.(*spyZapRunner)
	if spy == nil {
		spy = &spyZapRunner{out: out, err: err}
		r = spy
	}
	d := &ZapDriver{
		cfg:  ZapConfig{Runner: r},
		spec: zapSpec(t),
		plan: plan,
		cov: ZapCoverage{
			PlanVerified:    true,
			RunnerWired:     r != nil,
			ReportsDeclared: len(plan.ReportTemplates()),
		},
		sealed: true,
	}
	return d, spy
}

func bothReports(dir string) []ZapReportArtifact {
	var out []ZapReportArtifact
	for _, tpl := range RequiredZapReportTemplates() {
		out = append(out, ZapReportArtifact{
			Template: tpl,
			Path:     filepath.Join(dir, tpl.fileStem()+".json"),
			Bytes:    2048,
		})
	}
	return out
}

// TestARunThatWroteNoReportIsNotACleanScan.
//
// ZAP can exit 0 having produced no report â€” a failed report job, a report
// directory it could not write, an add-on that is not installed. The finding
// list that comes back is byte-identical to a clean target's. This is the
// guard that separates them, and every row is a way the report can be missing.
func TestARunThatWroteNoReportIsNotACleanScan(t *testing.T) {
	dir := t.TempDir()

	for _, tc := range []struct {
		name    string
		out     ZapRunOutcome
		wantErr error
	}{
		{"no reports at all", ZapRunOutcome{ExitCode: 0}, ErrZapReportMissing},
		{
			name:    "only SARIF",
			out:     ZapRunOutcome{ExitCode: 0, Reports: bothReports(dir)[:1]},
			wantErr: ErrZapReportMissing,
		},
		{
			name: "both declared but one is empty",
			out: ZapRunOutcome{ExitCode: 0, Reports: []ZapReportArtifact{
				{Template: ZapReportSARIF, Path: "a.json", Bytes: 1024},
				{Template: ZapReportTraditionalJSONPlus, Path: "b.json", Bytes: 0},
			}},
			wantErr: ErrZapReportMissing,
		},
		{
			name: "both declared but one has no path",
			out: ZapRunOutcome{ExitCode: 0, Reports: []ZapReportArtifact{
				{Template: ZapReportSARIF, Path: "a.json", Bytes: 1024},
				{Template: ZapReportTraditionalJSONPlus, Path: "", Bytes: 1024},
			}},
			wantErr: ErrZapReportMissing,
		},
		{
			name:    "non-zero exit",
			out:     ZapRunOutcome{ExitCode: 3, Reports: bothReports(dir)},
			wantErr: ErrRefused,
		},
		{
			name: "both written",
			out:  ZapRunOutcome{ExitCode: 0, Reports: bothReports(dir)},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d, spy := zapDriverWithRunner(t, nil, tc.out, nil)
			err := d.Autorun(context.Background(), zapFixtureZapSh, zapFixturePlanAt)
			if tc.wantErr == nil {
				if err != nil {
					t.Fatalf("Autorun on a complete run: %v", err)
				}
			} else {
				if err == nil {
					t.Fatalf("Autorun returned nil for %+v", tc.out)
				}
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("error does not wrap the expected sentinel: %v", err)
				}
			}
			if spy.calls != 1 {
				t.Fatalf("the runner was called %d time(s); want 1", spy.calls)
			}
			if spy.lastPln != d.Plan().YAML() {
				t.Fatal("the runner was handed a document that is not the verified plan")
			}
		})
	}

	// A missing report must also make AssertNotSilentlyEmpty refuse, or the
	// error above could be swallowed by a caller and the empty list reported.
	d, _ := zapDriverWithRunner(t, nil, ZapRunOutcome{ExitCode: 0}, nil)
	_ = d.Autorun(context.Background(), zapFixtureZapSh, zapFixturePlanAt)
	if err := d.Result().AssertNotSilentlyEmpty(); !errors.Is(err, ErrNothingProbed) {
		t.Fatalf("AssertNotSilentlyEmpty after a report-less run: %v; want ErrNothingProbed", err)
	}
}

// TestBothReportTemplatesAreDeclaredInEveryPlan. research/15 line 150 requires
// both: SARIF for the interchange envelope, traditional-json-plus because
// SARIF drops the request/response evidence the coding agent needs.
func TestBothReportTemplatesAreDeclaredInEveryPlan(t *testing.T) {
	doc := zapPlan(t).YAML()
	for _, tpl := range RequiredZapReportTemplates() {
		if !strings.Contains(doc, `template: "`+string(tpl)+`"`) {
			t.Fatalf("the rendered plan does not declare the %q report template:\n%s", tpl, doc)
		}
	}
	if got := strings.Count(doc, "  - type: report"); got != 2 {
		t.Fatalf("the rendered plan carries %d report job(s); want 2", got)
	}
	// The two must write to different files, or the second overwrites the
	// first and the run reports one artifact where it declared two.
	if ZapReportSARIF.fileStem() == ZapReportTraditionalJSONPlus.fileStem() {
		t.Fatal("both report templates derive the same file stem, so one would overwrite " +
			"the other")
	}
}

// ---------------------------------------------------------------------------
// The absence contract, shared with the nuclei driver
// ---------------------------------------------------------------------------

// TestSystemZapRunnerRefusesRatherThanReturningANoOp.
//
// ZAP is not installed on the development host (measured; see this file's
// header). A SystemZapRunner that returned a no-op would make every scan come
// back with an empty finding list, which is what a clean target looks like.
func TestSystemZapRunnerRefusesRatherThanReturningANoOp(t *testing.T) {
	r, err := SystemZapRunner()
	if err == nil {
		t.Fatal("SystemZapRunner returned a runner. There is no ZAP adapter in this " +
			"module, so a non-nil runner here is a no-op that reports clean")
	}
	if r != nil {
		t.Fatal("SystemZapRunner returned both a runner and an error")
	}
	var ue *ZapUnavailableError
	if !errors.As(err, &ue) {
		t.Fatalf("SystemZapRunner's error is not a *ZapUnavailableError: %v", err)
	}
	if ue.Name != ZapEngineName {
		t.Fatalf("the error names engine %q; want %q", ue.Name, ZapEngineName)
	}
	for _, want := range []string{"NOT a clean target", ZapInstallHint} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("the absence message does not contain %q: %v", want, err)
		}
	}
}

// TestBothDriversShareOneArtefactAbsentContract.
//
// The nuclei driver and the ZAP driver are two engines in one package and an
// operator's wrapper must not need a per-engine table. The contract is three
// things: the same sentinel, the same exit code, and the same method to read it
// by. This asserts all three across both error types, so a future divergence is
// a test failure rather than a silent drift.
func TestBothDriversShareOneArtefactAbsentContract(t *testing.T) {
	zapErr := &ZapUnavailableError{Name: ZapEngineName, Detail: "fixture"}
	nucErr := &EngineUnavailableError{Name: EngineName, Detail: "fixture"}

	for _, err := range []error{zapErr, nucErr} {
		if !errors.Is(err, ErrEngineUnavailable) {
			t.Fatalf("%T does not unwrap to ErrEngineUnavailable", err)
		}
		coded, ok := err.(interface{ ExitCode() int })
		if !ok {
			t.Fatalf("%T does not implement interface{ ExitCode() int }, so a wrapping "+
				"command has to re-derive the exit code from an error string", err)
		}
		if got := coded.ExitCode(); got != ExitCodeArtefactAbsent {
			t.Fatalf("%T.ExitCode() = %d; want %d", err, got, ExitCodeArtefactAbsent)
		}
	}

	// The two messages must NOT be interchangeable: a ZAP absence that
	// printed nuclei's install hint would send an operator to the wrong
	// tool. This is why ZapUnavailableError is a second type.
	if strings.Contains(zapErr.Error(), InstallHint) {
		t.Fatal("the ZAP absence message carries nuclei's install hint")
	}
	if strings.Contains(nucErr.Error(), ZapInstallHint) {
		t.Fatal("the nuclei absence message carries ZAP's install hint")
	}
}

// TestAutorunWithoutARunnerIsAnAbsenceAndNotAnEmptyResult.
func TestAutorunWithoutARunnerIsAnAbsenceAndNotAnEmptyResult(t *testing.T) {
	plan := zapPlan(t)
	d := &ZapDriver{
		cfg:    ZapConfig{},
		spec:   zapSpec(t),
		plan:   plan,
		cov:    ZapCoverage{PlanVerified: true, ReportsDeclared: len(plan.ReportTemplates())},
		sealed: true,
	}
	err := d.Autorun(context.Background(), zapFixtureZapSh, zapFixturePlanAt)
	if err == nil {
		t.Fatal("Autorun with no ZapRunner returned nil")
	}
	var ue *ZapUnavailableError
	if !errors.As(err, &ue) {
		t.Fatalf("the error is not a *ZapUnavailableError: %v", err)
	}
	if ue.ExitCode() != ExitCodeArtefactAbsent {
		t.Fatalf("ExitCode() = %d; want %d", ue.ExitCode(), ExitCodeArtefactAbsent)
	}
	if d.Result().Coverage.RunAttempted {
		t.Fatal("Coverage.RunAttempted is true after a run that never happened")
	}
	if err := d.Result().AssertNotSilentlyEmpty(); !errors.Is(err, ErrNothingProbed) {
		t.Fatalf("AssertNotSilentlyEmpty: %v; want ErrNothingProbed", err)
	}
}

// TestZapAssertNotSilentlyEmptyRefusesEveryWayNothingRan.
//
// This is the predicate a caller consults before writing "clean". Each row is
// a distinct way a run produces an empty finding list without having tested
// anything, and the last row is the ONLY shape that may be read as clean â€”
// without it, a predicate that refused unconditionally would pass every row
// above.
func TestZapAssertNotSilentlyEmptyRefusesEveryWayNothingRan(t *testing.T) {
	full := ZapCoverage{
		PlanVerified:    true,
		RunnerWired:     true,
		IssuerWired:     true,
		RunAttempted:    true,
		ReportsDeclared: 2,
		ReportsWritten:  2,
		RequestsIssued:  17,
	}

	for _, tc := range []struct {
		name string
		cov  ZapCoverage
		want string
	}{
		{"the zero value", ZapCoverage{}, "no verified ZAP automation plan"},
		{
			name: "no plan",
			cov:  func() ZapCoverage { c := full; c.PlanVerified = false; return c }(),
			want: "no verified ZAP automation plan",
		},
		{
			name: "no runner and none invoked",
			cov:  func() ZapCoverage { c := full; c.RunnerWired = false; c.RunAttempted = false; return c }(),
			want: "not installed on this host",
		},
		{
			name: "reports declared, none written",
			cov:  func() ZapCoverage { c := full; c.ReportsWritten = 0; return c }(),
			want: "declared ZAP report",
		},
		{
			name: "one report of two",
			cov:  func() ZapCoverage { c := full; c.ReportsWritten = 1; return c }(),
			want: "declared ZAP report",
		},
		{
			name: "reports written but nothing reached the wire",
			cov:  func() ZapCoverage { c := full; c.RequestsIssued = 0; return c }(),
			want: "zero requests reached the wire",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := ZapScanResult{Coverage: tc.cov, Target: "https://t:443"}.AssertNotSilentlyEmpty()
			if err == nil {
				t.Fatalf("AssertNotSilentlyEmpty returned nil for %+v", tc.cov)
			}
			if !errors.Is(err, ErrNothingProbed) {
				t.Fatalf("error does not wrap ErrNothingProbed: %v", err)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("the refusal does not mention %q: %v", tc.want, err)
			}
			if !tc.cov.ScannedNothing() && tc.cov.RequestsIssued == 0 {
				t.Fatal("ScannedNothing disagrees with AssertNotSilentlyEmpty")
			}
		})
	}

	if err := (ZapScanResult{Coverage: full, Target: "https://t:443"}).AssertNotSilentlyEmpty(); err != nil {
		t.Fatalf("a complete run was refused: %v. Every row above would then pass against "+
			"a predicate that refuses unconditionally", err)
	}
	if full.ScannedNothing() {
		t.Fatal("ScannedNothing() is true for a run that issued 17 requests")
	}
	if !(ZapCoverage{}).ScannedNothing() {
		t.Fatal("the zero ZapCoverage reports ScannedNothing() == false, so a coverage " +
			"nobody filled in describes a scan somebody ran")
	}
}

// ---------------------------------------------------------------------------
// Argument construction is a security boundary
// ---------------------------------------------------------------------------

// TestTheInvocationIsAVectorAndNeverAShellString.
//
// ZAP's command line carries `-config` overrides that can re-enable anything
// the plan turned off. So the argv is exactly four elements, in a fixed order,
// and Argv returns a copy â€” a runner that could append to the slice it was
// handed would be a runner whose effective configuration this package does not
// know.
func TestTheInvocationIsAVectorAndNeverAShellString(t *testing.T) {
	plan := zapPlan(t)
	inv, err := plan.Invocation(zapFixtureZapSh, zapFixturePlanAt)
	if err != nil {
		t.Fatalf("Invocation: %v", err)
	}
	want := []string{zapFixtureZapSh, "-cmd", "-autorun", zapFixturePlanAt}
	if !reflect.DeepEqual(inv.Argv(), want) {
		t.Fatalf("Argv() = %q; want %q (research/15 line 148: `./zap.sh -cmd -autorun "+
			"zap.yaml`)", inv.Argv(), want)
	}
	if inv.PlanYAML() != plan.YAML() {
		t.Fatal("PlanYAML() is not the verified document")
	}
	if inv.PlanPath() != zapFixturePlanAt {
		t.Fatalf("PlanPath() = %q", inv.PlanPath())
	}
	if !inv.Constructed() {
		t.Fatal("a constructed invocation reports itself unconstructed")
	}

	// Argv is a fresh slice every call.
	a := inv.Argv()
	a[0] = "/bin/sh"
	a[3] = "; rm -rf /"
	if b := inv.Argv(); !reflect.DeepEqual(b, want) {
		t.Fatalf("Argv() = %q after a caller wrote through the slice it was handed; the "+
			"copy is not real", b)
	}
	if !reflect.DeepEqual(ZapAutorunArgs(), []string{"-cmd", "-autorun"}) {
		t.Fatalf("ZapAutorunArgs() = %q", ZapAutorunArgs())
	}
	f := ZapAutorunArgs()
	f[0] = "-daemon"
	if got := ZapAutorunArgs(); got[0] != "-cmd" {
		t.Fatalf("ZapAutorunArgs() = %q after a caller wrote through it", got)
	}

	for _, tc := range []struct{ name, sh, path string }{
		{"relative zap.sh", "zap.sh", zapFixturePlanAt},
		{"relative plan", zapFixtureZapSh, "zap.yaml"},
		{"empty zap.sh", "", zapFixturePlanAt},
		{"empty plan", zapFixtureZapSh, ""},
		{"flag-shaped zap.sh", "-daemon", zapFixturePlanAt},
		{"flag-shaped plan", zapFixtureZapSh, "-config"},
		{"plan is not yaml", zapFixtureZapSh, filepath.Join(zapFixtureDir, "zap.txt")},
		{"plan is a directory name", zapFixtureZapSh, zapFixtureDir},
		{"newline in plan path", zapFixtureZapSh, filepath.Join(zapFixtureDir, "a\nb.yaml")},
		{"NUL in zap.sh", filepath.Join(zapFixtureDir, "\x00zap.sh"), zapFixturePlanAt},
		{"DEL in plan path", zapFixtureZapSh, filepath.Join(zapFixtureDir, "a\x7f.yaml")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := plan.Invocation(tc.sh, tc.path); err == nil {
				t.Fatalf("Invocation(%q, %q) was accepted", tc.sh, tc.path)
			}
		})
	}

	if _, err := (ZapAutomationPlan{}).Invocation(zapFixtureZapSh, zapFixturePlanAt); !errors.Is(err, ErrUnconstructed) {
		t.Fatalf("an unconstructed plan produced an invocation: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Provenance and origins
// ---------------------------------------------------------------------------

// TestOnlyTwoOriginsCanBeProposedByTheZapDriver.
//
// The ZAP driver generates an active-scan plan and nothing else: no template, no
// headless browser, no WebSocket job, no out-of-band callback. So four of the
// kernel's six origins have no job in the plan that could produce them, and
// proposing one would be describing a request this configuration cannot make.
// The crawl's Client Spider is what widens this, and widening it is the review that
// widening should be.
func TestOnlyTwoOriginsCanBeProposedByTheZapDriver(t *testing.T) {
	plan := zapPlan(t)
	base := ZapProposalFacts{
		Plan:      plan,
		Spec:      zapSpec(t),
		RuleID:    "40018",
		Method:    authz.MethodGet,
		Path:      "/",
		Technique: authz.TechniqueProofOfExistence,
	}

	permitted := map[authz.RequestOrigin]bool{}
	for _, o := range zapProposalOrigins() {
		permitted[o] = true
	}
	if len(permitted) != 2 {
		t.Fatalf("zapProposalOrigins() has %d entries; the ZAP driver proposes exactly initial and "+
			"redirect", len(permitted))
	}

	for _, o := range []authz.RequestOrigin{
		authz.OriginInitial,
		authz.OriginRedirect,
		authz.OriginTemplateURL,
		authz.OriginBrowserFetch,
		authz.OriginWebSocketUpgrade,
		authz.OriginOutOfBandCallback,
		authz.RequestOrigin("invented"),
		authz.RequestOrigin(""),
	} {
		t.Run(string(o)+"_", func(t *testing.T) {
			f := base
			f.Origin = o
			if o == authz.OriginRedirect {
				f.Hop = 1
			}
			_, err := NewZapRequestProposal(f)
			if permitted[o] {
				if err != nil {
					t.Fatalf("origin %q must be proposable: %v", o, err)
				}
				return
			}
			if err == nil {
				t.Fatalf("origin %q was accepted. No job in the generated plan makes a "+
					"request of that origin", o)
			}
			if !errors.Is(err, ErrRefused) {
				t.Fatalf("the refusal does not wrap ErrRefused: %v", err)
			}
		})
	}
}

// TestAZapProposalMustNameThePlanThatConfiguredTheScan.
//
// The Nuclei driver refuses a proposal whose template it did not admit,
// because the kernel gates destinations and not provenance. The same hole
// exists here in a different shape: a request configured by some OTHER ZAP
// plan â€” different caps, different scope, different proxy â€” would be admitted
// by the kernel on the destination alone. The plan digest is the identity, and
// Fire checks it before it touches the Governor.
func TestAZapProposalMustNameThePlanThatConfiguredTheScan(t *testing.T) {
	plan := zapPlan(t)

	// A second, DIFFERENT plan: same target, different run id.
	other, err := NewZapAutomationPlan(ZapPlanFacts{
		Spec:      zapSpec(t),
		Caps:      zapCeilingCaps(t),
		Proxy:     zapProxy(t),
		RunID:     "anvil-run-somebody-elses",
		ReportDir: t.TempDir(),
	})
	if err != nil {
		t.Fatalf("NewZapAutomationPlan: %v", err)
	}
	if other.Digest() == plan.Digest() {
		t.Fatal("two plans with different run ids produced the same digest, so the digest " +
			"is not over the rendered bytes")
	}

	p, err := NewZapRequestProposal(ZapProposalFacts{
		Plan:      other,
		Spec:      zapSpec(t),
		RuleID:    "40018",
		Origin:    authz.OriginInitial,
		Method:    authz.MethodGet,
		Path:      "/",
		Technique: authz.TechniqueProofOfExistence,
	})
	if err != nil {
		t.Fatalf("NewZapRequestProposal against the other plan: %v", err)
	}

	sink := &countingSink{}
	d := &ZapDriver{cfg: ZapConfig{}, spec: zapSpec(t), plan: plan, sealed: true}
	_, err = d.Fire(context.Background(), p, mustClock(t))
	if err == nil {
		t.Fatal("Fire accepted a proposal carrying another plan's digest")
	}
	if !errors.Is(err, ErrRefused) {
		t.Fatalf("the refusal does not wrap ErrRefused: %v", err)
	}
	// The refusal must be THE DIGEST refusal, named by both digests.
	//
	// This assertion exists because the test without it PASSED WITH THE
	// DIGEST CHECK DELETED: the driver in this fixture has a zero
	// Authorization, so with the digest check gone the proposal fell through
	// to authz.RequireAuthorization and was refused there instead — a
	// different control, a green test, and no coverage at all for the one
	// under test. MEASURED, by deleting the check and watching this test go
	// `ok`.
	for _, want := range []string{other.Digest(), plan.Digest(), "unknown caps"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("the refusal does not mention %q, so it may be some other control "+
				"refusing for some other reason: %v", want, err)
		}
	}
	if sink.n != 0 {
		t.Fatal("a proposal refused before the kernel was asked still wrote an audit row")
	}
	if got := d.Result().Coverage.RequestsRefused; got != 1 {
		t.Fatalf("Coverage.RequestsRefused = %d after one refusal; want 1. A refusal that "+
			"does not move the counter is invisible to AssertNotSilentlyEmpty", got)
	}
	if d.Result().Coverage.RequestsIssued != 0 {
		t.Fatal("a refused proposal was counted as issued")
	}

	// A proposal that was never built by NewZapRequestProposal is refused
	// too, and does not reach the digest check.
	if _, err := d.Fire(context.Background(), RequestProposal{}, mustClock(t)); !errors.Is(err, ErrUnconstructed) {
		t.Fatalf("Fire accepted an unconstructed proposal: %v", err)
	}

	// A proposal carrying THIS driver's digest but a foreign identity — a
	// Nuclei template id, say, since both engines share RequestProposal — is
	// refused by the prefix check. Without it, the digest check alone would
	// admit anything that happened to quote the right digest.
	foreign, err := NewRequestProposal(ProposalFacts{
		Spec:           zapSpec(t),
		Origin:         authz.OriginInitial,
		Method:         authz.MethodGet,
		Path:           "/",
		Technique:      authz.TechniqueProofOfExistence,
		TemplateID:     "CVE-2021-44228",
		TemplateDigest: plan.Digest(),
	})
	if err != nil {
		t.Fatalf("NewRequestProposal for the foreign-identity fixture: %v", err)
	}
	if _, err := d.Fire(context.Background(), foreign, mustClock(t)); err == nil {
		t.Fatal("Fire accepted a proposal whose identity is not a ZAP rule identity")
	} else if !errors.Is(err, ErrRefused) {
		t.Fatalf("the refusal does not wrap ErrRefused: %v", err)
	} else if !strings.Contains(err.Error(), "not a ZAP rule identity") {
		t.Fatalf("the refusal is not the identity refusal, so this row may be measuring "+
			"some other control: %v", err)
	}
	// Three refusals so far: the foreign digest, the unconstructed proposal,
	// and this foreign identity. Every one of them must be counted, because a
	// refusal that does not move the counter is invisible to
	// AssertNotSilentlyEmpty.
	if got := d.Result().Coverage.RequestsRefused; got != 3 {
		t.Fatalf("Coverage.RequestsRefused = %d after three refusals; want 3", got)
	}

	// And a proposal that names no plan cannot be built at all.
	if _, err := NewZapRequestProposal(ZapProposalFacts{
		Spec:      zapSpec(t),
		RuleID:    "40018",
		Origin:    authz.OriginInitial,
		Method:    authz.MethodGet,
		Path:      "/",
		Technique: authz.TechniqueProofOfExistence,
	}); !errors.Is(err, ErrUnconstructed) {
		t.Fatalf("a proposal was built with no automation plan: %v", err)
	}
}

// TestTheZapRuleIdentityIsAnAllowlist. injectPluginIdInHeader is on in every
// generated plan so that every request is attributable; a rule id that could
// carry arbitrary bytes would put those bytes into a Finding's TemplateID,
// which is a field a report prints.
func TestTheZapRuleIdentityIsAnAllowlist(t *testing.T) {
	for _, bad := range []string{"", "40018 ", "4:0", "40018\n", "a/b", "a\\b", "Ã©",
		strings.Repeat("9", maxZapRuleIDLen+1), "<script>"} {
		if got, err := zapRuleIdentity(bad); err == nil {
			t.Errorf("zapRuleIdentity(%q) = %q, nil", bad, got)
		}
	}
	for _, ok := range []string{"40018", "pscan-10096", "a.b_c-d"} {
		got, err := zapRuleIdentity(ok)
		if err != nil {
			t.Fatalf("zapRuleIdentity(%q): %v", ok, err)
		}
		if want := "zap:rule:" + ok; got != want {
			t.Fatalf("zapRuleIdentity(%q) = %q; want %q", ok, got, want)
		}
	}
}

// ---------------------------------------------------------------------------
// The authorization boundary
// ---------------------------------------------------------------------------

// TestNewZapDriverRefusesEveryUnauthorizedRoute.
//
// This is the fail-closed half of the boundary and it is fully testable
// today. No ZapDriver exists without a TargetSpec, and no TargetSpec exists
// without an authz.Authorization the kernel minted for exactly that target.
func TestNewZapDriverRefusesEveryUnauthorizedRoute(t *testing.T) {
	for _, tc := range []struct {
		name string
		cfg  ZapConfig
	}{
		{"everything zero", ZapConfig{}},
		{
			name: "a target but no authorization",
			cfg:  ZapConfig{Target: mustBareTarget(t)},
		},
		{
			name: "caps and proxy but no authorization",
			cfg: ZapConfig{
				Target:    mustBareTarget(t),
				Caps:      zapCeilingCaps(t),
				Proxy:     zapProxy(t),
				RunID:     zapFixtureRunID,
				ReportDir: t.TempDir(),
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d, err := NewZapDriver(tc.cfg)
			if err == nil {
				t.Fatal("NewZapDriver built a driver with no Governor, no GateAudit and " +
					"no Authorization")
			}
			if d != nil {
				t.Fatal("NewZapDriver returned both a driver and an error")
			}
		})
	}

	// An unconstructed driver must not answer anything either.
	var d *ZapDriver
	if d.Constructed() {
		t.Fatal("a nil *ZapDriver reports Constructed() == true")
	}
	empty := &ZapDriver{}
	if empty.Plan().Constructed() || empty.Spec().Constructed() {
		t.Fatal("an unconstructed driver handed out a plan or a spec")
	}
	if err := empty.Autorun(context.Background(), zapFixtureZapSh, zapFixturePlanAt); !errors.Is(err, ErrUnconstructed) {
		t.Fatalf("Autorun on an unconstructed driver: %v", err)
	}
	if _, err := empty.Fire(context.Background(), RequestProposal{}, mustClock(t)); !errors.Is(err, ErrUnconstructed) {
		t.Fatalf("Fire on an unconstructed driver: %v", err)
	}
	if err := empty.Result().AssertNotSilentlyEmpty(); !errors.Is(err, ErrNothingProbed) {
		t.Fatalf("an unconstructed driver's result was readable as clean: %v", err)
	}
}

// ---------------------------------------------------------------------------
// The admit-and-issue path, which is new
// ---------------------------------------------------------------------------
//
// The ZAP driver's Fire has the same shape as the nuclei driver's and was
// blocked on the same thing: NewZapDriver needs an authz.Authorization, and
// until gate 11 became a scope narrowing none could be minted from outside
// package authz. zapSpec and zapDriverWithRunner forge their values by
// composite literal for exactly that reason, and every test that used them
// proved something BELOW the authorization boundary.
//
// The two tests here are the ones that could not be written: a ZapDriver built
// by NewZapDriver from a real token, fired end to end, and the same driver
// refusing a real kernel refusal without issuing anything. They are the ZAP
// counterparts of nuclei_test.go's items (2) and (3), and the docs/controls.md
// entry they close is U5(c), which recorded this blocker as shared with U4(b).

// mustZapDriver assembles a ZapDriver against the real kernel: a real
// Authorization, a real Governor, a real gate-21 writer.
func mustZapDriver(t *testing.T, a admission, scope authz.Scope, sink authz.AuditSink, iss Issuer) *ZapDriver {
	t.Helper()
	d, err := NewZapDriver(ZapConfig{
		Governor:      mustGovernor(t, a, scope, authz.RobotsNotFound(fixtureHost, 443)),
		Audit:         mustGateAudit(t, a, sink),
		Authorization: a.auth,
		Target:        a.target,
		Caps:          zapCeilingCaps(t),
		Proxy:         zapProxy(t),
		RunID:         zapFixtureRunID,
		ReportDir:     t.TempDir(),
		Issuer:        iss,
	})
	if err != nil {
		t.Fatalf("NewZapDriver against a real Authorization: %v", err)
	}
	return d
}

// TestZapFireAdmitsAndIssuesEndToEndWithOneAuditRowPerGate is the ZAP driver's positive
// control, and the first time a ZapDriver has existed without being forged.
//
// It asserts the same three things the nuclei driver's does, because they are the same
// three properties: the whole path runs, gate 21 gets ONE ROW PER GATE in
// authz.GovernorGateOrder() rather than one row naming the last gate, and
// ZapCoverage.RequestsIssued moves.
func TestZapFireAdmitsAndIssuesEndToEndWithOneAuditRowPerGate(t *testing.T) {
	a := admitTarget(t, mustCanonicalTarget(t))

	sink := &recordingSink{}
	iss := &spyIssuer{out: ProbeResult{
		Status:    200,
		Matched:   true,
		BodyBytes: 256,
		Evidence:  "the active scan rule reported a match",
	}}
	d := mustZapDriver(t, a, a.scope, sink, iss)

	// The spec came from NewTargetSpec this time, so it carries gate 8's
	// canonical host and gate 9's pinned address rather than zapSpec's
	// literals.
	if got, want := d.Spec().URL(), "https://"+fixtureHost+":443"; got != want {
		t.Fatalf("ZapDriver.Spec().URL() = %q; want %q", got, want)
	}
	if got, want := d.Spec().PinnedAddr(), fixturePinned+":443"; got != want {
		t.Fatalf("ZapDriver.Spec().PinnedAddr() = %q; want %q", got, want)
	}
	if before := d.Result().Coverage.RequestsIssued; before != 0 {
		t.Fatalf("ZapCoverage.RequestsIssued = %d before anything fired; want 0", before)
	}

	p, err := NewZapRequestProposal(ZapProposalFacts{
		Plan:      d.Plan(),
		Spec:      d.Spec(),
		RuleID:    "40018",
		Origin:    authz.OriginInitial,
		Method:    authz.MethodGet,
		Path:      "/",
		Technique: authz.TechniqueProofOfExistence,
	})
	if err != nil {
		t.Fatalf("NewZapRequestProposal against an admitted destination: %v", err)
	}

	f, err := d.Fire(context.Background(), p, mustClock(t))
	if err != nil {
		t.Fatalf(`ZapDriver.Fire REFUSED a request the kernel should admit: %v

This is the ZAP driver's positive control. Every other assertion about this driver is
about a refusal, and a stack only ever shown to refuse is indistinguishable
from a stack that is broken.`, err)
	}

	if len(iss.calls) != 1 {
		t.Fatalf("the Issuer was called %d time(s); want exactly 1", len(iss.calls))
	}
	if !iss.calls[0].Constructed() {
		t.Fatal("the Issuer was handed an AdmittedRequest that reports itself unconstructed")
	}

	want := authz.GovernorGateOrder()
	got := sink.gates()
	if len(got) != len(want) {
		t.Fatalf(`the admission wrote %d audit row(s) and authz.GovernorGateOrder() has %d gates.

wrote: %v
want:  %v

Gate 21 is "an immutable audit of every gate decision", and a count that does
not match the gate list means a gate was consulted and not recorded.`,
			len(got), len(want), got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("audit row %d names %s; the interceptor's gate at that position is %s\n"+
				"wrote: %v\nwant:  %v", i, got[i], want[i], got, want)
		}
		if sink.rows[i].Outcome != authz.OutcomeAllow {
			t.Fatalf("audit row %d (%s) records outcome %q on an ADMITTED request",
				i, sink.rows[i].Gate, string(sink.rows[i].Outcome))
		}
	}

	cov := d.Result().Coverage
	if cov.RequestsIssued != 1 || cov.RequestsAdmitted != 1 || cov.RequestsRefused != 0 {
		t.Fatalf("ZapCoverage after one issued request: issued=%d admitted=%d refused=%d; "+
			"want 1/1/0", cov.RequestsIssued, cov.RequestsAdmitted, cov.RequestsRefused)
	}
	if f.AuditSeq == 0 || f.AuditSeq != iss.calls[0].AuditSeq() {
		t.Fatalf("the Finding's AuditSeq (%d) and the AdmittedRequest's (%d) disagree, or "+
			"are zero", f.AuditSeq, iss.calls[0].AuditSeq())
	}
	if f.TemplateDigest != d.Plan().Digest() {
		t.Fatalf("the Finding is attributed to plan digest %q; the driver rendered %q",
			f.TemplateDigest, d.Plan().Digest())
	}
}

// TestZapFireRefusesAnOutOfScopeRedirectAndIssuesNothing is the nuclei driver's item (3)
// for the ZAP driver: a REAL kernel refusal, driven by gate 11 in its new form.
//
// The narrowing is the same production shape — robots.txt fetched outside the
// kernel, applied once to the sealed scope, and gate 13 re-validating every
// request against the narrowed one. The assertion that matters is the same
// one: NOTHING REACHED THE ISSUER.
func TestZapFireRefusesAnOutOfScopeRedirectAndIssuesNothing(t *testing.T) {
	a := admitTarget(t, mustCanonicalTarget(t))

	narrowed, res := authz.NarrowScopeToRobots(a.scope, []authz.RobotsDocument{{
		Host:    fixtureHost,
		Port:    443,
		Outcome: authz.RobotsFetchRetrieved,
		Body:    []byte("User-agent: *\nDisallow: /\n"),
	}})
	if !res.Passed() {
		t.Fatalf("authz.NarrowScopeToRobots refused at %s: %v", res.Gate(), res.Err())
	}

	sink := &recordingSink{}
	iss := &spyIssuer{out: ProbeResult{Status: 200, Matched: true}}
	d := mustZapDriver(t, a, narrowed, sink, iss)

	p, err := NewZapRequestProposal(ZapProposalFacts{
		Plan:      d.Plan(),
		Spec:      d.Spec(),
		RuleID:    "40018",
		Origin:    authz.OriginRedirect,
		Method:    authz.MethodGet,
		Path:      "/",
		Technique: authz.TechniqueProofOfExistence,
		Hop:       1,
	})
	if err != nil {
		t.Fatalf("NewZapRequestProposal for a redirect hop: %v", err)
	}

	if _, err := d.Fire(context.Background(), p, mustClock(t)); err == nil {
		t.Fatal("ZapDriver.Fire ADMITTED a redirect to a destination the scope layer no " +
			"longer permits")
	} else if !errors.Is(err, ErrRefused) {
		t.Fatalf("the refusal does not unwrap to ErrRefused: %v", err)
	} else if !strings.Contains(err.Error(), authz.Gate13RevalidateEveryRequest.String()) {
		t.Fatalf(`ZapDriver.Fire refused, but NOT at gate 13: %v

A refusal from one of the driver's own preconditions would pass an assertion
that only checked for an error and would prove nothing about the gate stack.`,
			err)
	}

	if len(iss.calls) != 0 {
		t.Fatalf(`the Issuer was called %d time(s) on a REFUSED request.

A refusal that still issues the request is a scope bypass with an audit row
saying it did not happen.`, len(iss.calls))
	}
	cov := d.Result().Coverage
	if cov.RequestsIssued != 0 || cov.RequestsRefused != 1 {
		t.Fatalf("ZapCoverage after one refusal: issued=%d refused=%d; want 0/1",
			cov.RequestsIssued, cov.RequestsRefused)
	}
	if err := d.Result().AssertNotSilentlyEmpty(); err == nil {
		t.Fatal("a run that issued nothing reported itself readable as clean")
	}
	if sink.n == 0 {
		t.Fatal("the refused admission wrote zero audit rows. Gate 21 logs every deny")
	}
	last := sink.rows[len(sink.rows)-1]
	if last.Outcome != authz.OutcomeDeny || last.Gate != authz.Gate13RevalidateEveryRequest {
		t.Fatalf("the last audit row is %s/%q; want %s/deny",
			last.Gate, string(last.Outcome), authz.Gate13RevalidateEveryRequest)
	}
	if len(sink.rows) >= len(authz.GovernorGateOrder()) {
		t.Fatalf("%d audit rows for a chain that refused at gate 13; the full chain has "+
			"%d gates: %v. A refused request that still consulted gate 14 has spent rate "+
			"budget on a request that was never issued",
			len(sink.rows), len(authz.GovernorGateOrder()), sink.gates())
	}
}

// ---------------------------------------------------------------------------
// Defensive copies
// ---------------------------------------------------------------------------

// TestEveryZapDefensiveCopyIsReal.
//
// A TEST THAT MUTATES ONLY THE FIELD WHERE THE COPY IS REAL PROVES NOTHING.
// This codebase has already shipped that defect twice (Scope.Ports, then
// Target.Containers), so every accessor that returns a slice is exercised
// here, not a representative one.
func TestEveryZapDefensiveCopyIsReal(t *testing.T) {
	plan := zapPlan(t)

	t.Run("ZapAutomationPlan.ReportTemplates", func(t *testing.T) {
		got := plan.ReportTemplates()
		if len(got) != 2 {
			t.Fatalf("ReportTemplates() has %d entries", len(got))
		}
		got[0] = "clobbered"
		got = append(got, "extra")
		_ = got
		again := plan.ReportTemplates()
		if !reflect.DeepEqual(again, RequiredZapReportTemplates()) {
			t.Fatalf("ReportTemplates() = %v after a caller wrote through it", again)
		}
	})

	t.Run("RequiredZapReportTemplates", func(t *testing.T) {
		a := RequiredZapReportTemplates()
		a[0] = "clobbered"
		if RequiredZapReportTemplates()[0] != ZapReportSARIF {
			t.Fatal("RequiredZapReportTemplates() is a shared slice")
		}
	})

	t.Run("zapProposalOrigins", func(t *testing.T) {
		a := zapProposalOrigins()
		a[0] = authz.OriginOutOfBandCallback
		if zapProposalOrigins()[0] != authz.OriginInitial {
			t.Fatal("zapProposalOrigins() is a shared slice, so a caller could add an " +
				"out-of-band origin to the allowlist")
		}
	})

	t.Run("ZapScanResult.Findings", func(t *testing.T) {
		d := &ZapDriver{
			cfg:    ZapConfig{},
			spec:   zapSpec(t),
			plan:   plan,
			sealed: true,
		}
		d.findings = []Finding{{TemplateID: "zap:rule:40018"}}
		r := d.Result()
		if len(r.Findings) != 1 {
			t.Fatalf("Result().Findings has %d entries", len(r.Findings))
		}
		r.Findings[0].TemplateID = "clobbered"
		if d.Result().Findings[0].TemplateID != "zap:rule:40018" {
			t.Fatal("Result().Findings aliases the driver's slice")
		}
	})

	t.Run("ZapInvocation.Argv", func(t *testing.T) {
		inv, err := plan.Invocation(zapFixtureZapSh, zapFixturePlanAt)
		if err != nil {
			t.Fatalf("Invocation: %v", err)
		}
		a := inv.Argv()
		for i := range a {
			a[i] = "clobbered"
		}
		for i, got := range inv.Argv() {
			if got == "clobbered" {
				t.Fatalf("Argv()[%d] was written through by a caller", i)
			}
		}
	})

	t.Run("ZapCaps is a value type with no reference fields", func(t *testing.T) {
		v := reflect.TypeOf(ZapCaps{})
		for i := 0; i < v.NumField(); i++ {
			switch k := v.Field(i).Type.Kind(); k {
			case reflect.Int, reflect.Bool:
			default:
				t.Fatalf("ZapCaps.%s is a %s. A reference field here would let a caller "+
					"write through a sealed cap after NewZapCaps validated it",
					v.Field(i).Name, k)
			}
		}
	})

	t.Run("ZapProxy is a value type with no reference fields", func(t *testing.T) {
		v := reflect.TypeOf(ZapProxy{})
		for i := 0; i < v.NumField(); i++ {
			switch k := v.Field(i).Type.Kind(); k {
			case reflect.String, reflect.Uint16, reflect.Bool:
			default:
				t.Fatalf("ZapProxy.%s is a %s", v.Field(i).Name, k)
			}
		}
	})
}

// TestTheAutomationPlanCarriesNoReferenceAWriterCouldReach.
//
// ZapAutomationPlan is passed by value everywhere. If it held a slice or a map
// that a caller could write through, Verify would have run against one
// document and ZAP would read another. `reports` is the one slice, and
// ReportTemplates copies it; this asserts there is no second one.
func TestTheAutomationPlanCarriesNoReferenceAWriterCouldReach(t *testing.T) {
	// This started as a FAILING test. The first version of
	// ZapAutomationPlan stored `reports []ZapReportTemplate`, and because the
	// type is passed by value everywhere, a copy shared that slice's backing
	// array â€” so a holder of a copy could rewrite what the original declared,
	// after Verify had already run. The field is gone; the assertion that no
	// reference field comes back is what remains.
	v := reflect.TypeOf(ZapAutomationPlan{})
	for i := 0; i < v.NumField(); i++ {
		f := v.Field(i)
		switch f.Type.Kind() {
		case reflect.String, reflect.Bool, reflect.Struct:
		default:
			t.Fatalf("ZapAutomationPlan.%s is a %s. A slice, pointer, map or channel here "+
				"is shared by every value copy of the plan, which is a route to the "+
				"verified document that Verify cannot see", f.Name, f.Type.Kind())
		}
	}

	// A copy of a plan is independent of the original, including through
	// everything it hands out.
	a := zapPlan(t)
	b := a
	tpls := b.ReportTemplates()
	tpls[0] = "clobbered"
	if a.ReportTemplates()[0] != ZapReportSARIF {
		t.Fatal("writing through a copy's ReportTemplates() changed the original's")
	}
	if b.YAML() != a.YAML() || b.Digest() != a.Digest() {
		t.Fatal("a value copy of a plan is not equal to its original")
	}
	if (ZapAutomationPlan{}).ReportTemplates() != nil {
		t.Fatal("an unconstructed plan declares report templates")
	}
}

// ---------------------------------------------------------------------------
// The scheduled-only rule, and what is NOT enforced here
// ---------------------------------------------------------------------------

// TestThisDriverIsTriggerAgnosticByInstruction records, executably, that this
// package carries no trigger check.
//
// The ZAP driver's forbidden actions: ZAP "is gated to scheduled full
// scans only, enforced by the caller's trigger-policy check, not by this
// driver refusing to run (the driver itself should be trigger-agnostic; the
// gating is a config/scheduling concern)."
//
// So the absence of a check here is CORRECT, and this test exists so that the
// absence is a recorded decision rather than an oversight somebody later
// "fixes" by adding a check in the wrong layer. It fails if a trigger ever
// appears in this driver's configuration surface, which is the moment to
// reconcile with the ZAP driver's instruction rather than to discover it.
//
// WHERE THE SCHEDULED-ONLY RULE IS ENFORCED: nowhere in this package.
// docs/controls.md U5 records it as an unenforced contract.
func TestThisDriverIsTriggerAgnosticByInstruction(t *testing.T) {
	v := reflect.TypeOf(ZapConfig{})
	for i := 0; i < v.NumField(); i++ {
		name := strings.ToLower(v.Field(i).Name)
		if strings.Contains(name, "trigger") || strings.Contains(name, "schedule") {
			t.Fatalf("ZapConfig.%s exists. The ZAP driver's design requires this driver to be "+
				"trigger-agnostic and puts the scheduled-only gate in the caller's "+
				"trigger-policy check. If that instruction has changed, change "+
				"docs/controls.md U5 in the same commit", v.Field(i).Name)
		}
	}
	f := reflect.TypeOf(ZapPlanFacts{})
	for i := 0; i < f.NumField(); i++ {
		name := strings.ToLower(f.Field(i).Name)
		if strings.Contains(name, "trigger") || strings.Contains(name, "schedule") {
			t.Fatalf("ZapPlanFacts.%s exists; see above", f.Field(i).Name)
		}
	}
}

// TestTheJVMFootprintIsNotFabricatedAnywhereInThisPackage.
//
// plan/design/dynamic-tier.md:1253 records ZAP's JVM memory footprint as unquantified and
// notes that it decides whether tier-M hardware (the spine's hardware-tier table, 32 GB / 8 core)
// accommodates a scheduled full scan alongside SAST and the coding agent.
//
// It CANNOT be measured here: there is no ZAP on this host and no Docker to
// run `docker stats` against (both measured 2026-08-22, PowerShell). A number
// invented in a comment would become the number tier-M sizing is documented
// against, which is worse than the acknowledged gap.
//
// So this test reads the package's own source and fails if a memory quantity
// appears in it. It is a guard against a future contributor filling the gap
// with a plausible-looking figure rather than a measurement.
func TestTheJVMFootprintIsNotFabricatedAnywhereInThisPackage(t *testing.T) {
	// It scans the IMPLEMENTATION only. Scanning this test file too would
	// mean this table matching itself, and the self-exclusion needed to
	// avoid that is exactly the kind of special case a guard gets defeated
	// through.
	forbidden := []string{
		"Xmx", "Xms", "-XX:", "MaxRAM", "heap size", "GB of RAM", "GiB of RAM",
		"MB heap", "MiB heap", "resident set", "footprint of",
	}
	path := filepath.Join(thisPackageDir(t), "zap.go")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading %s: %v. A guard that reads no source has not passed, it has "+
			"not run", path, err)
	}
	body := string(raw)
	if !strings.Contains(body, "unquantified") {
		t.Fatal("zap.go no longer records ZAP's JVM footprint as unquantified. If it was " +
			"MEASURED, this test and docs/controls.md U5 both change in the " +
			"same commit as the measurement")
	}
	for _, f := range forbidden {
		if strings.Contains(body, f) {
			t.Errorf("zap.go contains %q. ZAP's JVM footprint is UNQUANTIFIED "+
				"(plan/design/dynamic-tier.md:1253) and cannot be measured on this host: there is no "+
				"ZAP and no Docker (both measured 2026-08-22, PowerShell). A figure here "+
				"becomes tier-M sizing documentation. Settle it with a `docker stats` run "+
				"during a representative scheduled scan and record the measurement in "+
				"docs/controls.md U5", f)
		}
	}
}

// TestTheRenderedPlanIsStableAndItsDigestIsOverItsExactBytes.
//
// The digest is the identity a request is attributed to, so it must be a
// function of the bytes and nothing else. Two renders of identical facts agree;
// one changed byte anywhere produces a different digest.
func TestTheRenderedPlanIsStableAndItsDigestIsOverItsExactBytes(t *testing.T) {
	dir := t.TempDir()
	mk := func(runID string) ZapAutomationPlan {
		t.Helper()
		p, err := NewZapAutomationPlan(ZapPlanFacts{
			Spec:      zapSpec(t),
			Caps:      zapCeilingCaps(t),
			Proxy:     zapProxy(t),
			RunID:     runID,
			ReportDir: dir,
		})
		if err != nil {
			t.Fatalf("NewZapAutomationPlan(%q): %v", runID, err)
		}
		return p
	}
	a, b := mk(zapFixtureRunID), mk(zapFixtureRunID)
	if a.YAML() != b.YAML() {
		t.Fatal("two renders of identical facts produced different documents")
	}
	if a.Digest() != b.Digest() {
		t.Fatalf("two identical documents produced different digests: %s vs %s",
			a.Digest(), b.Digest())
	}
	if len(a.Digest()) != 64 {
		t.Fatalf("the digest is %d hex characters; a SHA-256 is 64", len(a.Digest()))
	}
	if c := mk(zapFixtureRunID + "x"); c.Digest() == a.Digest() {
		t.Fatal("changing the run id did not change the digest")
	}

	// Caps() round-trips the sealed value.
	if a.Caps().DelayInMs() != zapCeilingCaps(t).DelayInMs() {
		t.Fatal("Caps() does not return the caps the plan was rendered from")
	}
	if (ZapAutomationPlan{}).Constructed() {
		t.Fatal("the zero ZapAutomationPlan reports Constructed() == true")
	}
	if err := (ZapAutomationPlan{}).Verify(); !errors.Is(err, ErrZapPlanUnverified) {
		t.Fatalf("the zero plan verified: %v", err)
	}
}

// TestTheReportDirectoryMustBeAbsolute. A relative path resolves against
// whatever working directory the ZAP process happens to have, which is a
// different directory from the one this driver would later look in â€” and a
// report this driver cannot find is a report that was not written.
func TestTheReportDirectoryMustBeAbsolute(t *testing.T) {
	for _, dir := range []string{"", "reports", "./reports", "../reports"} {
		_, err := NewZapAutomationPlan(ZapPlanFacts{
			Spec:      zapSpec(t),
			Caps:      zapCeilingCaps(t),
			Proxy:     zapProxy(t),
			RunID:     zapFixtureRunID,
			ReportDir: dir,
		})
		if err == nil {
			t.Fatalf("a plan was rendered with report directory %q", dir)
		}
		if !errors.Is(err, ErrRefused) {
			t.Fatalf("the refusal does not wrap ErrRefused: %v", err)
		}
	}
}

// TestAutorunReVerifiesBeforeHandingTheDocumentOver.
//
// The plan is verified at construction. Autorun verifies it again immediately
// before the runner sees it, so a plan that travelled through a value copy
// that zeroed something is caught at the last moment rather than executed.
func TestAutorunReVerifiesBeforeHandingTheDocumentOver(t *testing.T) {
	plan := zapPlan(t)
	broken := plan
	broken.yaml = dropLines(plan.yaml, "delayInMs:")

	spy := &spyZapRunner{out: ZapRunOutcome{ExitCode: 0}}
	d := &ZapDriver{
		cfg:    ZapConfig{Runner: spy},
		spec:   zapSpec(t),
		plan:   broken,
		cov:    ZapCoverage{PlanVerified: true, RunnerWired: true, ReportsDeclared: 2},
		sealed: true,
	}
	err := d.Autorun(context.Background(), zapFixtureZapSh, zapFixturePlanAt)
	if !errors.Is(err, ErrZapPlanUnverified) {
		t.Fatalf("Autorun ran a plan with no delayInMs: %v", err)
	}
	if spy.calls != 0 {
		t.Fatalf("the runner was invoked %d time(s) with an unverified plan", spy.calls)
	}
}

// TestARunnerErrorIsNotAnEmptyFindingList.
func TestARunnerErrorIsNotAnEmptyFindingList(t *testing.T) {
	boom := errors.New("the JVM did not start")
	spy := &spyZapRunner{err: boom}
	d, _ := zapDriverWithRunner(t, spy, ZapRunOutcome{}, nil)
	err := d.Autorun(context.Background(), zapFixtureZapSh, zapFixturePlanAt)
	if !errors.Is(err, boom) {
		t.Fatalf("Autorun swallowed the runner's error: %v", err)
	}
	if !d.Result().Coverage.RunAttempted {
		t.Fatal("Coverage.RunAttempted is false after the runner was actually invoked; " +
			"that is what tells a failed run apart from a run that never started")
	}
	if err := d.Result().AssertNotSilentlyEmpty(); !errors.Is(err, ErrNothingProbed) {
		t.Fatalf("AssertNotSilentlyEmpty after a failed run: %v", err)
	}
}

// TestZapStderrIsScrubbedBeforeItIsRetained. ZAP's stderr is prose from
// outside Anvil; the spine's safety section puts prompt-injection defence at ingest,
// and this driver's report is an ingest point.
func TestZapStderrIsScrubbedBeforeItIsRetained(t *testing.T) {
	hostile := "ZAP failed\u202eSTOP\u200b\U000E0041\x07"
	spy := &spyZapRunner{out: ZapRunOutcome{ExitCode: 4, Stderr: hostile}}
	d, _ := zapDriverWithRunner(t, spy, ZapRunOutcome{}, nil)
	err := d.Autorun(context.Background(), zapFixtureZapSh, zapFixturePlanAt)
	if err == nil {
		t.Fatal("a non-zero exit returned nil")
	}
	for _, r := range []string{"\u202e", "\u200b", "\U000E0041", "\x07"} {
		if strings.Contains(err.Error(), r) {
			t.Fatalf("the error message carries %q unscrubbed", r)
		}
	}
	ev := d.Result().Coverage.Evidence
	if !ev.Modified() {
		t.Fatalf("EvidenceStats reports nothing removed from %q: %s", hostile, ev)
	}
	if ev.Bidi == 0 || ev.ZeroWidth == 0 || ev.Tag == 0 || ev.Controls == 0 {
		t.Fatalf("EvidenceStats did not count every class: %s", ev)
	}
}

// TestTheDriverAndThePlanAgreeOnTheAuthorizedOrigin is a small consistency
// check with a large consequence: a driver whose spec and whose plan named
// different origins would scan one host and report the other.
func TestTheDriverAndThePlanAgreeOnTheAuthorizedOrigin(t *testing.T) {
	spec := zapSpec(t)
	plan := zapPlan(t)
	if !strings.Contains(plan.YAML(), `- "`+spec.URL()+`"`) {
		t.Fatalf("the plan's context does not name %q", spec.URL())
	}
	if plan.target != spec.URL() {
		t.Fatalf("the plan's sealed target is %q; the spec's URL is %q", plan.target, spec.URL())
	}
	// The pinned address must NOT appear: ZAP is proxied, and Anvil's egress
	// layer is what dials the pinned address. A pinned IP in the plan would
	// be ZAP resolving and connecting on its own.
	if strings.Contains(plan.YAML(), spec.PinnedAddr()) {
		t.Fatalf("the rendered plan carries the pinned dial address %q. ZAP goes through "+
			"the proxy; the pinned address is the egress layer's business and putting it "+
			"in ZAP's plan would be ZAP dialling it directly", spec.PinnedAddr())
	}
}

// TestZapCoverageIsNotDNucleiCoverage records why the two types are separate,
// executably.
//
// Coverage.ProbedNothing is `TemplatesAdmitted == 0 || RequestsIssued == 0`.
// ZAP has no templates, so embedding Coverage would make ProbedNothing true
// for every ZAP scan that ever ran â€” a guard that fires always, which gets
// suppressed, which is worse than not having it.
func TestZapCoverageIsNotDNucleiCoverage(t *testing.T) {
	c := Coverage{RequestsIssued: 17}
	if !c.ProbedNothing() {
		t.Fatal("Coverage.ProbedNothing no longer keys off TemplatesAdmitted. If ZAP can " +
			"now share it, ZapCoverage should be deleted rather than kept in parallel")
	}
	z := ZapCoverage{PlanVerified: true, RequestsIssued: 17}
	if z.ScannedNothing() {
		t.Fatal("ZapCoverage.ScannedNothing() is true for a scan that issued 17 requests")
	}
}

// ---------------------------------------------------------------------------
// Redirects: what the proxy enforces, and what nothing enforces
// ---------------------------------------------------------------------------

// zapOffScopeTarget builds a Target on a DIFFERENT host from the fixture, so
// that an intent naming it is the cross-host redirect gate 13 exists for.
func zapOffScopeTarget(t *testing.T) authz.Target {
	t.Helper()
	const other = "attacker.example.net"
	tgt, err := authz.NewTarget(authz.SchemeHTTPS, other, other, 443, mustAddr(t, "198.51.100.9"))
	if err != nil {
		t.Fatalf("authz.NewTarget for the off-scope host: %v", err)
	}
	return tgt
}

// zapIntent builds a RequestIntent from the fixture target to next.
func zapIntent(t *testing.T, o authz.RequestOrigin, next authz.Target, hop int) (authz.RequestIntent, error) {
	t.Helper()
	return authz.NewRequestIntent(authz.RequestFacts{
		Origin:   o,
		Admitted: mustBareTarget(t),
		Next:     next,
		Method:   authz.MethodGet,
		Path:     "/",
		Hop:      hop,
	})
}

// TestNothingInThisPackageMakesARedirectArriveLabelledAsOne is the evidence
// for this file's header section "WHAT IS NOT ENFORCED".
//
// # Why this test exists at all
//
// The header used to state, as fact, that a redirect ZAP chooses to follow
// "arrives at gate 13 as an ordinary request with OriginRedirect and Hop+1"
// and that authz's maxRedirectHops bounds it. That described a control that
// would be sufficient if it existed, which is the most expensive kind of
// comment to be wrong: a reader who believes it stops looking for the missing
// piece.
//
// Each subtest below is one sentence of the replacement text, measured.
func TestNothingInThisPackageMakesARedirectArriveLabelledAsOne(t *testing.T) {
	next := mustBareTarget(t) // same host: this is about the LABEL, not scope.

	// 1. The kernel neither infers the label nor defaults it. Both halves of
	//    the pair have to be supplied together and consistently, so no
	//    component can accidentally end up with a correctly-labelled hop.
	t.Run("the kernel refuses every half-supplied label", func(t *testing.T) {
		if _, err := zapIntent(t, authz.OriginRedirect, next, 0); !errors.Is(err, authz.ErrRefused) {
			t.Fatalf(`authz.NewRequestIntent ACCEPTED OriginRedirect at hop 0 (%v).

The header's claim rests on the opposite: because the kernel refuses this
shape, a hop's depth cannot be left at its zero value, and therefore SOMETHING
outside the kernel must be choosing it. If the kernel now defaults the depth,
this file's "WHAT IS NOT ENFORCED" section needs rewriting, not deleting.`, err)
		}
		if _, err := zapIntent(t, authz.OriginInitial, next, 1); !errors.Is(err, authz.ErrRefused) {
			t.Fatalf("authz.NewRequestIntent accepted OriginInitial carrying redirect depth "+
				"1: %v. Only a redirect hop has a depth", err)
		}
	})

	// 2. The hop bound is real, and it is DISCOVERED here rather than written
	//    as a literal — authz's maxRedirectHops is unexported, and a literal
	//    copied into this file would be a second number that can drift.
	bound := 0
	t.Run("a labelled hop is bounded", func(t *testing.T) {
		for hop := 1; hop <= 1000; hop++ {
			if _, err := zapIntent(t, authz.OriginRedirect, next, hop); err != nil {
				bound = hop - 1
				break
			}
		}
		if bound == 0 {
			t.Fatal("no redirect depth in 1..1000 was refused, so the kernel has no hop " +
				"bound and the whole point of labelling a hop is gone")
		}
		t.Logf("MEASURED: the kernel accepts a labelled redirect hop at depth 1..%d and "+
			"refuses %d", bound, bound+1)
	})

	// 3. And this is the finding. An UNLABELLED request carries no depth for
	//    that bound to apply to, so the same chain runs as far as the caller
	//    cares to drive it. Every one of these is a request the kernel seals
	//    and gate 13 will judge on its destination — the bound is what is
	//    missing, not the gate.
	t.Run("an unlabelled hop is bounded by nothing here", func(t *testing.T) {
		if bound == 0 {
			t.Fatal("the bound was never measured, so this row would compare against zero")
		}
		for i := 0; i < (bound+1)*20; i++ {
			in, err := zapIntent(t, authz.OriginInitial, next, 0)
			if err != nil {
				t.Fatalf("request %d of an unlabelled same-host chain was refused: %v. If "+
					"the kernel now bounds these, the header's WHAT IS NOT ENFORCED section "+
					"is out of date", i, err)
			}
			if in.Hop() != 0 {
				t.Fatalf("an unlabelled request reports redirect depth %d", in.Hop())
			}
		}
		t.Logf("MEASURED: %d consecutive requests labelled %q at depth 0 were all sealed. "+
			"The %d-hop bound never applies to any of them", (bound+1)*20,
			string(authz.OriginInitial), bound)
	})

	// 4. And the audit cannot settle it after the fact. The header says a
	//    gate-21 row shows neither the origin nor the depth, so a
	//    mislabelled hop leaves no trace to find later. That is a claim about
	//    a kernel type, so it is read off the type.
	t.Run("no gate-21 row carries an origin or a hop", func(t *testing.T) {
		rec := reflect.TypeOf(authz.GateRecord{})
		if rec.NumField() == 0 {
			t.Fatal("authz.GateRecord has no fields, so this check would pass over anything")
		}
		for i := 0; i < rec.NumField(); i++ {
			switch n := rec.Field(i).Name; n {
			case "Origin", "Hop", "RequestOrigin", "RedirectDepth":
				t.Fatalf(`authz.GateRecord now carries %q.

This file's header says a gate-21 row shows neither the origin nor the depth,
and therefore cannot be used to tell a mislabelled hop from a first request
after the fact. With that field present the row CAN show it, and the header's
audit row must be rewritten to say what the log now proves.`, n)
			}
		}
	})

	// 5. And the driver is a pass-through for both fields: it copies Origin
	//    and Hop out of the facts it was handed and checks neither against
	//    anything it observed, because it observed nothing. This is what makes
	//    3 reachable in production rather than only in a test.
	t.Run("the driver copies the label it is given and checks nothing", func(t *testing.T) {
		plan := zapPlan(t)
		for _, tc := range []struct {
			origin authz.RequestOrigin
			hop    int
		}{
			{authz.OriginInitial, 0},
			{authz.OriginRedirect, 1},
			{authz.OriginRedirect, bound},
		} {
			p, err := NewZapRequestProposal(ZapProposalFacts{
				Plan:      plan,
				Spec:      zapSpec(t),
				RuleID:    "40018",
				Origin:    tc.origin,
				Method:    authz.MethodGet,
				Path:      "/",
				Technique: authz.TechniqueProofOfExistence,
				Hop:       tc.hop,
			})
			if err != nil {
				t.Fatalf("NewZapRequestProposal(%q, hop %d): %v", tc.origin, tc.hop, err)
			}
			if p.Origin() != tc.origin || p.Hop() != tc.hop {
				t.Fatalf("the proposal carries (%q, %d); it was handed (%q, %d). If the "+
					"driver has started deriving either field, it now owns redirect policy "+
					"and the header must say so",
					p.Origin(), p.Hop(), tc.origin, tc.hop)
			}
		}
	})
}

// zapKernel wires a REAL Governor and GateAudit over the fixture scope and
// attestation. Nothing here is a double: gates 6, 4, 5 and 7 run inside
// initiateRun, and the governor consults the real per-request chain.
func zapKernel(t *testing.T) (*authz.GateAudit, *authz.Governor, *countingSink) {
	t.Helper()
	init := initiateRun(t)
	scope, err := init.Scope()
	if err != nil {
		t.Fatalf("init.Scope: %v", err)
	}
	att, err := init.Attestation()
	if err != nil {
		t.Fatalf("init.Attestation: %v", err)
	}
	key, res := authz.NewAuditKey(att, scope)
	if !res.Passed() {
		t.Fatalf("authz.NewAuditKey: %v", res.Err())
	}
	runClock, err := init.RunClock()
	if err != nil {
		t.Fatalf("init.RunClock: %v", err)
	}
	sink := &countingSink{}
	audit, res := authz.NewGateAudit(sink, key, runClock)
	if !res.Passed() {
		t.Fatalf("authz.NewGateAudit: %v", res.Err())
	}
	gov, res := authz.NewGovernor(authz.GovernorConfig{
		Target:      mustBareTarget(t),
		Scope:       scope,
		Attestation: att,
		Caps:        authz.CodedCaps(),
		Thresholds:  authz.CodedHealthThresholds(),
		Robots:      authz.RobotsNotFound(fixtureHost, 443),
		Start:       mustClock(t),
	})
	if !res.Passed() {
		t.Fatalf("authz.NewGovernor: %v", res.Err())
	}
	return audit, gov, sink
}

// TestAnUnlabelledRedirectChainIsBoundedByGate14AndNotByTheHopBound is the
// residual risk itself, run through the real kernel.
//
// This file's header says that for a proxy which labels every request
// `initial` at depth 0, "a same-host redirect chain is bounded only by gate
// 14's request count and wall clock". That is the sentence a reader would most
// like to disbelieve, so it is measured: the chain is driven through a real
// Governor until something refuses it, and both WHICH gate refused and HOW
// MANY got through first are asserted against the hop bound the kernel applies
// to a chain that IS labelled.
func TestAnUnlabelledRedirectChainIsBoundedByGate14AndNotByTheHopBound(t *testing.T) {
	audit, gov, _ := zapKernel(t)
	now := mustClock(t)

	// The bound that applies when the label is present, measured the same way
	// the sibling test measures it.
	hopBound := 0
	for hop := 1; hop <= 1000; hop++ {
		if _, err := zapIntent(t, authz.OriginRedirect, mustBareTarget(t), hop); err != nil {
			hopBound = hop - 1
			break
		}
	}
	if hopBound == 0 {
		t.Fatal("no labelled redirect depth was refused, so there is no bound to compare to")
	}

	admitted := 0
	stopped := authz.GateUnspecified
	for i := 0; i < 20*(hopBound+1); i++ {
		in, err := zapIntent(t, authz.OriginInitial, mustBareTarget(t), 0)
		if err != nil {
			t.Fatalf("sealing unlabelled request %d: %v", i, err)
		}
		lease, res := audit.AuditedAdmit(gov, in, authz.TechniqueProofOfExistence, now)
		lease.Release()
		if !res.Passed() {
			stopped = res.Gate()
			break
		}
		admitted++
	}

	if stopped == authz.GateUnspecified {
		t.Fatalf("%d unlabelled same-host requests were admitted at one instant and nothing "+
			"ever refused one. Gate 14's caps are then not being applied either, which is a "+
			"bigger finding than the one this test was written for", admitted)
	}
	if stopped != authz.Gate14HardCaps {
		t.Fatalf(`the unlabelled chain was stopped at %s after %d admissions, not at gate 14.

This test exists to show that the ONLY thing bounding a mislabelled redirect
chain is gate 14. A stop at some other gate means something else is now
bounding it, and this file's header must be corrected to say what.`, stopped, admitted)
	}
	if admitted <= hopBound {
		t.Fatalf(`%d unlabelled requests were admitted and the labelled hop bound is %d.

With admitted <= the hop bound this test proves nothing: the two bounds would
be indistinguishable, and the header's claim that the hop bound "never applies"
would be unsupported by it.`, admitted, hopBound)
	}
	t.Logf("MEASURED: a chain labelled %q at depth 0 was admitted %d times before %s "+
		"refused it. A chain labelled %q cannot be sealed past depth %d at all",
		string(authz.OriginInitial), admitted, stopped, string(authz.OriginRedirect), hopBound)
}

// TestGate13JudgesTheDestinationWhateverTheRequestClaimsToBe is the other half:
// the control that DOES hold, driven through a real authz.Governor.
//
// ZAP issue #2546 is a mid-scan redirect walking out of scope. That failure is
// prevented by gate 13 judging the DESTINATION of every request that arrives,
// which does not depend on the request being recognised as a redirect. This
// test drives an intent that is a mislabelled hop — an out-of-scope
// destination wearing OriginInitial at depth 0, which is exactly what an
// unattributed ZAP follow-up looks like — and asserts the kernel refuses it at
// gate 13 anyway.
func TestGate13JudgesTheDestinationWhateverTheRequestClaimsToBe(t *testing.T) {
	audit, gov, sink := zapKernel(t)

	// The mislabelled hop.
	off, err := zapIntent(t, authz.OriginInitial, zapOffScopeTarget(t), 0)
	if err != nil {
		t.Fatalf("building the off-scope intent: %v. It must SEAL — the whole point is "+
			"that nothing about it looks wrong until a gate reads its destination", err)
	}
	lease, res := audit.AuditedAdmit(gov, off, authz.TechniqueProofOfExistence, mustClock(t))
	lease.Release()
	if res.Passed() {
		t.Fatal("the kernel ADMITTED a request to a host the scope does not name, because " +
			"the request called itself an initial request. That is ZAP issue #2546 with " +
			"Anvil's name on it")
	}
	if res.Gate() != authz.Gate13RevalidateEveryRequest {
		t.Fatalf(`the off-scope request was refused at %s, not at gate 13.

This test's claim is specifically that GATE 13 reads the destination of every
request whatever the request says it is. A refusal at some other gate is still
a refusal, but it does not measure that, and this file's header cites this test
by name for it. Refusal was: %v`, res.Gate(), res.Err())
	}
	if sink.n == 0 {
		t.Fatal("the refusal wrote no audit row. Gate 21 records every deny, and a deny " +
			"nobody logged is the control failing in the direction nobody looks at")
	}

	// The control row, without which the assertion above would pass over a
	// governor that refuses everything: the SAME label and depth, to the host
	// the scope does name, must not be refused at gate 13. It may well be
	// refused later — gate 11 has nothing registered — and that is fine here;
	// what must not happen is gate 13 turning it away.
	in, err := zapIntent(t, authz.OriginInitial, mustBareTarget(t), 0)
	if err != nil {
		t.Fatalf("building the in-scope intent: %v", err)
	}
	lease, res = audit.AuditedAdmit(gov, in, authz.TechniqueProofOfExistence, mustClock(t))
	lease.Release()
	if !res.Passed() && res.Gate() == authz.Gate13RevalidateEveryRequest {
		t.Fatalf(`gate 13 refused the IN-SCOPE destination too (%v).

Then the off-scope row above proves nothing: a gate that refuses every
destination would satisfy it while enforcing no scope at all.`, res.Err())
	}
	t.Logf("MEASURED: in-scope, same label: passed=%v, stopped at %s", res.Passed(), res.Gate())
}

// TestEveryOriginThisDriverAllowsIsConstructibleAllTheWayToAnIntent.
//
// An unreachable entry in an allowlist is a claim nothing can exercise, and it
// reads as a control while doing nothing. This iterates zapProposalOrigins()
// ITSELF — not a copy of its contents — and requires each entry to survive the
// whole production route: ZapProposalFacts -> NewZapRequestProposal -> a sealed
// authz.RequestIntent. An origin added to that list which cannot make the trip
// fails here.
func TestEveryOriginThisDriverAllowsIsConstructibleAllTheWayToAnIntent(t *testing.T) {
	origins := zapProposalOrigins()
	if len(origins) == 0 {
		t.Fatal("zapProposalOrigins() is empty, so this test would sweep nothing")
	}
	plan := zapPlan(t)
	seen := map[authz.RequestOrigin]bool{}

	for _, o := range origins {
		t.Run(string(o), func(t *testing.T) {
			// Only a redirect carries a depth (phase3_enforcement.go:370,
			// :376), so the depth is derived from the origin rather than
			// tabulated — a new origin then needs no edit here, which is what
			// makes this test able to fail for one.
			hop := 0
			if o == authz.OriginRedirect {
				hop = 1
			}
			p, err := NewZapRequestProposal(ZapProposalFacts{
				Plan:      plan,
				Spec:      zapSpec(t),
				RuleID:    "40018",
				Origin:    o,
				Method:    authz.MethodGet,
				Path:      "/",
				Technique: authz.TechniqueProofOfExistence,
				Hop:       hop,
			})
			if err != nil {
				t.Fatalf(`NewZapRequestProposal REFUSED origin %q, which zapProposalOrigins()
says this driver proposes: %v

Either this origin is reachable and something now refuses it, or it is not
reachable and does not belong in the allowlist. An origin that nothing can
construct is not a narrower allowlist, it is a line of documentation.`, o, err)
			}
			if !p.Constructed() {
				t.Fatalf("the proposal for origin %q reports itself unconstructed", o)
			}
			in, err := authz.NewRequestIntent(authz.RequestFacts{
				Origin:   p.Origin(),
				Admitted: mustBareTarget(t),
				Next:     p.Spec().Target(),
				Method:   p.Method(),
				Path:     p.Path(),
				Hop:      p.Hop(),
				Attempt:  p.Attempt(),
			})
			if err != nil {
				t.Fatalf("the proposal for origin %q built, but the kernel refused the "+
					"intent made from it: %v. Reaching the kernel and being refused by it "+
					"is the same dead end", o, err)
			}
			if !in.Constructed() || in.Origin() != o || in.Hop() != hop {
				t.Fatalf("the sealed intent carries origin %q at depth %d; want %q at %d",
					in.Origin(), in.Hop(), o, hop)
			}
			seen[o] = true
		})
	}

	// The rule id is required under EVERY origin, OriginInitial included. That
	// is the fail-closed direction and it is the reason a ZAP request with no
	// X-ZAP-Scan-ID cannot be proposed at all.
	for _, o := range origins {
		if !seen[o] {
			t.Fatalf("origin %q was never demonstrated", o)
		}
		_, err := NewZapRequestProposal(ZapProposalFacts{
			Plan:      plan,
			Spec:      zapSpec(t),
			RuleID:    "",
			Origin:    o,
			Method:    authz.MethodGet,
			Path:      "/",
			Technique: authz.TechniqueProofOfExistence,
		})
		if !errors.Is(err, ErrRefused) {
			t.Fatalf("origin %q was proposed with NO rule id (%v). Then a request the "+
				"driver cannot attribute reaches the kernel under that origin", o, err)
		}
	}
}

// TestGate14sWallClockIsAtLeastOneWholeMinute pins the unit assumption this
// package's duration arithmetic rests on. ZAP's duration caps are whole
// minutes; a gate-14 wall-clock floor under a minute would floor to zero, and
// zero is ZAP's unlimited.
func TestGate14sWallClockIsAtLeastOneWholeMinute(t *testing.T) {
	if authz.CodedMaxWallClockPerTarget < time.Minute {
		t.Fatalf("authz.CodedMaxWallClockPerTarget is %s. ZAP's duration caps are whole "+
			"minutes, so anything under one minute floors to 0 â€” and 0 is unlimited",
			authz.CodedMaxWallClockPerTarget)
	}
	sub, res := authz.CodedCaps().Lower(authz.CapOverrides{
		WallClockPerTarget: func() *time.Duration { d := 30 * time.Second; return &d }(),
	})
	if !res.Passed() {
		t.Fatalf("lowering the wall clock to 30s was refused: %v", res.Err())
	}
	if _, err := ZapCapsAtKernelCeiling(sub); !errors.Is(err, ErrZapCapUnbounded) {
		t.Fatalf("a sub-minute wall clock produced caps rather than a refusal: %v", err)
	}
	if _, err := NewZapCaps(sub, ZapCapFacts{
		DelayInMs: 400, MaxScanDurationInMins: 1, MaxRuleDurationInMins: 1, ThreadPerHost: 4,
	}); !errors.Is(err, ErrZapCapUnbounded) {
		t.Fatalf("a one-minute scan cap was accepted under a 30-second wall clock: %v", err)
	}
}
