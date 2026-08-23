// D.15's evidence.
//
// ===========================================================================
// WHAT THIS SUITE CAN PROVE ON THIS HOST, AND WHAT IT CANNOT
// ===========================================================================
//
// ZAP is NOT INSTALLED here. MEASURED 2026-08-22 from PowerShell on the
// development host (Windows 11, go1.26.5 windows/amd64):
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
// The SECOND gap is D.14's and it is unchanged: authz.Adjudicate is the only
// mint for an authz.Authorization, authz.admissionChain contains
// Gate11RobotsDeny, and nothing is registered for it â€” so from outside package
// authz there is NO WAY TO OBTAIN AN Authorization, and therefore no way to
// build a TargetSpec, a ZapDriver or a proposal carrying a real destination
// through the production route. nuclei_test.go's
// TestNoAuthorizationCanBeMintedUntilGate11IsRegistered runs the real Phase 1
// gates and the real admission chain and pins where the chain stops; that
// tripwire covers this file too and is not duplicated here.
//
// Where a test below needs a sealed TargetSpec it FORGES one with a composite
// literal, which is possible only because this is an in-package test. That is
// the same device nuclei_test.go uses and it is stated rather than hidden: no
// code outside package engines can do it, and every test that could assert a
// production-route refusal instead of forging does so.
//
// internal/SKIPPED-CONTROLS.md U5 records what remains unexecuted, including
// the one plan/50-dast.md explicitly asked this packet to answer â€” ZAP's JVM
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
// NewTargetSpec is the only production route to one and it requires an
// authz.Authorization, which cannot be minted from outside package authz
// today (see this file's header). A composite literal works here ONLY because
// this is an in-package test; TestNoStringLiteralTargetReachesTheEngine in
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
// D.15's first named validation: all four caps, always explicit and bounded
// ---------------------------------------------------------------------------

// TestTheFourZapCapsAreExplicitNonZeroAndBoundedInEveryGeneratedPlan is
// plan/50-dast.md D.15's "Test asserting the generated zap.yaml always
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
// D.15's second named validation: attribution
// ---------------------------------------------------------------------------

// TestTheAttributionHeaderAndThePluginIdAreInEveryGeneratedPlan is
// plan/50-dast.md D.15's "Test asserting that X-Anvil-Scan: <run-id> and
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
	// to the document would crawl, and D.15 is not the crawl (D.23 is).
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
// This is the difference between D.14 and D.15 in one test. Nuclei is driven
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
// NewZapDriver needs an authz.Authorization, which cannot be minted from
// outside package authz (see the header). Everything below the authorization
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
// The absence contract, shared with D.14
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
// D.14 and D.15 are two engines in one package and an operator's wrapper must
// not need a per-engine table. The contract is three things: the same
// sentinel, the same exit code, and the same method to read it by. This
// asserts all three across both error types, so a future divergence is a test
// failure rather than a silent drift.
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
// D.15 generates an active-scan plan and nothing else: no template, no
// headless browser, no WebSocket job, no out-of-band callback. So four of the
// kernel's six origins have no job in the plan that could produce them, and
// proposing one would be describing a request this configuration cannot make.
// D.23's Client Spider is what widens this, and widening it is the review that
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
		t.Fatalf("zapProposalOrigins() has %d entries; D.15 proposes exactly initial and "+
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
// plan/50-dast.md D.15 forbidden actions: ZAP "is gated to scheduled full
// scans only, enforced by the caller's trigger-policy check, not by this
// driver refusing to run (the driver itself should be trigger-agnostic; the
// gating is a config/scheduling concern)."
//
// So the absence of a check here is CORRECT, and this test exists so that the
// absence is a recorded decision rather than an oversight somebody later
// "fixes" by adding a check in the wrong layer. It fails if a trigger ever
// appears in this driver's configuration surface, which is the moment to
// reconcile with D.15's instruction rather than to discover it.
//
// WHERE THE SCHEDULED-ONLY RULE IS ENFORCED: nowhere in this package.
// internal/SKIPPED-CONTROLS.md U5 records it as an unenforced contract.
func TestThisDriverIsTriggerAgnosticByInstruction(t *testing.T) {
	v := reflect.TypeOf(ZapConfig{})
	for i := 0; i < v.NumField(); i++ {
		name := strings.ToLower(v.Field(i).Name)
		if strings.Contains(name, "trigger") || strings.Contains(name, "schedule") {
			t.Fatalf("ZapConfig.%s exists. plan/50-dast.md D.15 requires this driver to be "+
				"trigger-agnostic and puts the scheduled-only gate in the caller's "+
				"trigger-policy check. If that instruction has changed, change "+
				"internal/SKIPPED-CONTROLS.md U5 in the same commit", v.Field(i).Name)
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
// plan/50-dast.md:1253 records ZAP's JVM memory footprint as unquantified and
// notes that it decides whether tier-M hardware (spine S9, 32 GB / 8 core)
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
			"MEASURED, this test and internal/SKIPPED-CONTROLS.md U5 both change in the " +
			"same commit as the measurement")
	}
	for _, f := range forbidden {
		if strings.Contains(body, f) {
			t.Errorf("zap.go contains %q. ZAP's JVM footprint is UNQUANTIFIED "+
				"(plan/50-dast.md:1253) and cannot be measured on this host: there is no "+
				"ZAP and no Docker (both measured 2026-08-22, PowerShell). A figure here "+
				"becomes tier-M sizing documentation. Settle it with a `docker stats` run "+
				"during a representative scheduled scan and record the measurement in "+
				"internal/SKIPPED-CONTROLS.md U5", f)
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
// outside Anvil; plan/00-SPINE.md S7 puts prompt-injection defence at ingest,
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
