package authz

import (
	"errors"
	"strings"
	"testing"
	"time"
)

// ===========================================================================
// FIXTURES
// ===========================================================================
//
// The import graphs and egress scans below are HAND-WRITTEN. None of them is
// produced by running `go list` or by any code in this package: a fixture the
// implementation generated would agree with the implementation's bugs, and the
// point of these tests is to disagree with them.
//
// D.9 owns the test that measures the real graphs. This file owns the proof
// that the gates judging those measurements can fail.

// A plausible cmd/anvil closure: stdlib, plus the core packages the binary
// really links, and nothing under internal/dast.
var cleanCoreDeps = []string{
	"errors",
	"fmt",
	"os",
	"strings",
	"time",
	"github.com/Susquehanna-Syntax/Anvil/internal/record",
	"github.com/Susquehanna-Syntax/Anvil/internal/store",
	"github.com/Susquehanna-Syntax/Anvil/internal/scanctl",
	"modernc.org/sqlite",
	CoreBinaryPackage,
}

// A plausible kernel closure: stdlib only, plus itself.
var cleanKernelDeps = []string{
	"cmp",
	"errors",
	"fmt",
	"net/netip",
	"strconv",
	"strings",
	"time",
	"internal/abi",
	"vendor/golang.org/x/net/dns/dnsmessage",
	KernelPackage,
}

func mustGraph(t *testing.T, root string, deps []string) ImportGraph {
	t.Helper()
	g, err := NewImportGraph(root, deps)
	if err != nil {
		t.Fatalf("NewImportGraph(%q): %v", root, err)
	}
	return g
}

func mustScan(t *testing.T, files int, sites ...EgressCallSite) EgressScan {
	t.Helper()
	s, err := NewEgressScan(files, sites)
	if err != nil {
		t.Fatalf("NewEgressScan: %v", err)
	}
	return s
}

// ===========================================================================
// THE FACT TYPES REFUSE AN UNMEASURED MEASUREMENT
// ===========================================================================

// TestUnmeasuredFactsAreRefused is the guard internal/SKIPPED-CONTROLS.md was
// written about: "a guard that vanishes silently when it cannot run is worse
// than no guard, because the green tick is read as an answer."
func TestUnmeasuredFactsAreRefused(t *testing.T) {
	t.Run("import graph with no root", func(t *testing.T) {
		if _, err := NewImportGraph("", cleanCoreDeps); err == nil {
			t.Fatal("NewImportGraph accepted an unnamed root")
		}
	})
	t.Run("import graph with no deps", func(t *testing.T) {
		_, err := NewImportGraph(CoreBinaryPackage, nil)
		if err == nil {
			t.Fatal("NewImportGraph accepted an empty dependency list. Every Go package " +
				"imports something, so an empty list means `go list -deps` did not run — " +
				"and a gate handed it would pass by finding nothing")
		}
		if !errors.Is(err, ErrNotMeasured) {
			t.Fatalf("the refusal does not unwrap to ErrNotMeasured: %v", err)
		}
	})
	t.Run("import graph with an empty dep", func(t *testing.T) {
		if _, err := NewImportGraph(CoreBinaryPackage, []string{"fmt", "  "}); err == nil {
			t.Fatal("NewImportGraph accepted a blank dependency line")
		}
	})
	t.Run("egress scan over zero files", func(t *testing.T) {
		_, err := NewEgressScan(0, nil)
		if err == nil {
			t.Fatal("NewEgressScan accepted a scan that examined zero files. " +
				"'We found nothing' and 'we did not look' produce identical output and " +
				"opposite conclusions")
		}
		if !errors.Is(err, ErrNotMeasured) {
			t.Fatalf("the refusal does not unwrap to ErrNotMeasured: %v", err)
		}
	})
	t.Run("egress scan with an unattributable site", func(t *testing.T) {
		cases := []EgressCallSite{
			{Package: "", File: "x.go", Line: 1, Symbol: "net.Dial"},
			{Package: "p", File: "", Line: 1, Symbol: "net.Dial"},
			{Package: "p", File: "x.go", Line: 0, Symbol: "net.Dial"},
			{Package: "p", File: "x.go", Line: 1, Symbol: ""},
		}
		for _, c := range cases {
			if _, err := NewEgressScan(10, []EgressCallSite{c}); err == nil {
				t.Errorf("NewEgressScan accepted the incomplete site %+v; a site the gate "+
					"cannot attribute to a package cannot be judged", c)
			}
		}
	})

	// Every Phase 0 gate must refuse the zero-value fact, AND must refuse it
	// for the right reason.
	//
	// The reason assertion is not decoration. Without it this test stayed
	// green when the "was this measured?" branch was deleted from gate 1,
	// because a zero ImportGraph also has the wrong root and the next branch
	// caught it — reporting "you handed me the wrong artifact's graph" for a
	// graph that was never walked. The gate still refused, so a test that
	// only checked Passed() could not see the guard disappear.
	zeroFacts := []struct {
		name   string
		result GateResult
		reason Reason
	}{
		{"gate 1 / unmeasured import graph",
			CheckGate1DastShipsDisabled(ImportGraph{}), ReasonImportGraphNotWalked},
		{"gate 2 / unmeasured import graph",
			CheckGate2KernelCompiledSeparately(ImportGraph{}), ReasonKernelGraphNotWalked},
		{"gate 3 / scan that never ran",
			CheckGate3EgressChokePoint(EgressScan{}), ReasonEgressScanNotRun},
	}
	for _, c := range zeroFacts {
		if c.result.Passed() {
			t.Errorf("%s passed", c.name)
			continue
		}
		if got := c.result.Failure().Reason; got != c.reason {
			t.Errorf("%s refused with reason %q; want %q. A gate that refuses an "+
				"unmeasured fact for some other reason has lost the check that says "+
				"'nobody looked'", c.name, string(got), string(c.reason))
		}
	}
}

// ===========================================================================
// GATE 1
// ===========================================================================

func TestGate1PassesOnACleanCoreGraph(t *testing.T) {
	r := CheckGate1DastShipsDisabled(mustGraph(t, CoreBinaryPackage, cleanCoreDeps))
	if !r.Passed() {
		t.Fatalf("gate 1 refused a clean core import graph: %v", r.Err())
	}
	if r.Gate() != Gate1DastShipsDisabled {
		t.Fatalf("the result is attributed to %s", r.Gate())
	}
	if r.Err() != nil {
		t.Fatalf("a passing gate returned a non-nil error: %v", r.Err())
	}
}

// TestGate1RefusesACoreBinaryThatReachesDAST is the negative control for the
// two-artifact split. Its failure message is what a contributor sees when they
// add the import that CI's artifact-split job also catches.
func TestGate1RefusesACoreBinaryThatReachesDAST(t *testing.T) {
	cases := map[string]string{
		"the kernel itself":  KernelPackage,
		"a DAST subpackage":  modulePath + "/internal/dast/engines",
		"the DAST tree root": dastPackageRoot,
	}
	for name, dep := range cases {
		t.Run(name, func(t *testing.T) {
			deps := append(append([]string(nil), cleanCoreDeps...), dep)
			r := CheckGate1DastShipsDisabled(mustGraph(t, CoreBinaryPackage, deps))
			if r.Passed() {
				t.Fatalf("gate 1 passed with %q in cmd/anvil's import graph. "+
					"plan/00-SPINE.md S9-AMENDED splits Anvil into two artifacts "+
					"precisely so the core binary supplies no probing capability", dep)
			}
			if r.Failure().Reason != ReasonCoreArtifactReachesDAST {
				t.Fatalf("reason %q; want %q",
					string(r.Failure().Reason), string(ReasonCoreArtifactReachesDAST))
			}
			if !strings.Contains(strings.Join(r.Failure().Evidence, "\n"), dep) {
				t.Fatalf("the failure does not name the offending package %q: %v", dep, r.Err())
			}
			if !errors.Is(r.Err(), ErrRefused) {
				t.Fatalf("the failure does not unwrap to ErrRefused: %v", r.Err())
			}
		})
	}
}

// TestGate1RefusesAZeroValueThatWouldAuthorize covers gate 1's second half:
// "no default target, no default scope, no bundled example that resolves to a
// real host."
//
// It drives the arm through the gate1 seam with a synthetic fault, because the
// survey is a pure function of this package's own types and a test cannot make
// it report one. The wiring from CheckGate1DastShipsDisabled to the real
// survey is covered by TestGate1PassesOnACleanCoreGraph, which goes red the
// moment any zero value starts authorizing.
func TestGate1RefusesAZeroValueThatWouldAuthorize(t *testing.T) {
	clean := mustGraph(t, CoreBinaryPackage, cleanCoreDeps)
	if r := gate1(clean, nil); !r.Passed() {
		t.Fatalf("gate 1 refused a clean graph with no zero-value faults: %v", r.Err())
	}
	r := gate1(clean, []string{"the zero Decision reports Allowed() == true"})
	if r.Passed() {
		t.Fatal("gate 1 passed although a zero value in the kernel authorizes something. " +
			"In a Go program the default IS the zero value, so this is what gate 1's " +
			"'ships disabled, no default target, no default scope' means at runtime")
	}
	if r.Failure().Reason != ReasonZeroValueWouldAuthorize {
		t.Fatalf("reason %q; want %q",
			string(r.Failure().Reason), string(ReasonZeroValueWouldAuthorize))
	}
	if !strings.Contains(strings.Join(r.Failure().Evidence, "\n"), "zero Decision") {
		t.Fatalf("the failure does not name the offending construct: %v", r.Err())
	}
}

// TestGate1RefusesTheWrongArtifactsGraph closes the "give the gate an easy
// graph" bypass: anvil-dast is EXPECTED to reach the DAST packages, so a gate
// that judged whatever it was handed could be satisfied by handing it that.
func TestGate1RefusesTheWrongArtifactsGraph(t *testing.T) {
	dastDeps := []string{"fmt", KernelPackage, DastBinaryPackage}
	r := CheckGate1DastShipsDisabled(mustGraph(t, DastBinaryPackage, dastDeps))
	if r.Passed() {
		t.Fatal("gate 1 judged the anvil-dast import graph as though it were the core " +
			"binary's. A gate that accepts any graph can be satisfied by an easy one")
	}
	if r.Failure().Reason != ReasonWrongArtifact {
		t.Fatalf("reason %q; want %q", string(r.Failure().Reason), string(ReasonWrongArtifact))
	}
}

// TestGate1AgreesWithTheShippedSplitTest keeps this gate and
// cmd/anvil/split_test.go from drifting into two different definitions of the
// same rule.
func TestGate1AgreesWithTheShippedSplitTest(t *testing.T) {
	const forbidden = "/internal/dast" // the literal cmd/anvil/split_test.go greps for
	if !strings.HasSuffix(dastPackageRoot, forbidden) {
		t.Fatalf("this package looks for %q and cmd/anvil/split_test.go looks for %q; two "+
			"definitions of one rule is one definition too many", dastPackageRoot, forbidden)
	}
}

// ===========================================================================
// GATE 2
// ===========================================================================

func TestGate2PassesOnAStdlibOnlyKernel(t *testing.T) {
	r := CheckGate2KernelCompiledSeparately(mustGraph(t, KernelPackage, cleanKernelDeps))
	if !r.Passed() {
		t.Fatalf("gate 2 refused a stdlib-only kernel graph: %v", r.Err())
	}
}

// TestGate2RefusesTheInferenceLayer is the failure plan/00-SPINE.md S7 names:
// "No model ever holds a network handle."
func TestGate2RefusesTheInferenceLayer(t *testing.T) {
	cases := map[string]string{
		"/inference/": modulePath + "/internal/inference/runtime",
		"/model/":     modulePath + "/internal/dast/model",
		"/llm/":       modulePath + "/internal/llm/client",
		"third-party": "github.com/example/llm/runtime",
	}
	for name, dep := range cases {
		t.Run(name, func(t *testing.T) {
			deps := append(append([]string(nil), cleanKernelDeps...), dep)
			r := CheckGate2KernelCompiledSeparately(mustGraph(t, KernelPackage, deps))
			if r.Passed() {
				t.Fatalf("gate 2 passed with %q in the kernel's import graph. "+
					"plan/00-SPINE.md S7: the kernel is compiled separately from the "+
					"model runtime, and no model ever holds a network handle", dep)
			}
			if r.Failure().Reason != ReasonKernelImportsInference {
				t.Fatalf("reason %q; want %q — the denylist exists so this specific "+
					"failure gets a specific message",
					string(r.Failure().Reason), string(ReasonKernelImportsInference))
			}
		})
	}
}

// TestGate2RefusesAnythingOffTheAllowlist is the reason the allowlist exists.
//
// None of these package names contains "/inference/", "/model/" or "/llm/", so
// the denylist S7 phrases the rule as would let every one of them through.
// That is what "a denylist loses" means concretely.
func TestGate2RefusesAnythingOffTheAllowlist(t *testing.T) {
	cases := map[string]string{
		"a plausibly-named local runtime": modulePath + "/internal/reasoning",
		"an agent package":                modulePath + "/internal/agent",
		"a DAST engine":                   modulePath + "/internal/dast/engines",
		"a vendored transformer library":  "github.com/example/transformers",
		"a sqlite driver":                 "modernc.org/sqlite",
	}
	for name, dep := range cases {
		t.Run(name, func(t *testing.T) {
			deps := append(append([]string(nil), cleanKernelDeps...), dep)
			r := CheckGate2KernelCompiledSeparately(mustGraph(t, KernelPackage, deps))
			if r.Passed() {
				t.Fatalf("gate 2 passed with %q in the kernel's import graph. None of "+
					"these names matches the /inference/ /model/ /llm/ denylist, which "+
					"is exactly why the allowlist is what holds", dep)
			}
			if r.Failure().Reason != ReasonKernelImportNotAllowed {
				t.Fatalf("reason %q; want %q",
					string(r.Failure().Reason), string(ReasonKernelImportNotAllowed))
			}
			if !strings.Contains(r.Err().Error(), "kernelImportAllowlist") {
				t.Fatalf("the failure does not tell the reader where to add an entry: %v", r.Err())
			}
		})
	}
}

func TestGate2AllowsExactlyTheAllowlistedPackages(t *testing.T) {
	for _, e := range kernelImportAllowlist {
		t.Run(e.path, func(t *testing.T) {
			deps := append(append([]string(nil), cleanKernelDeps...), e.path)
			if r := CheckGate2KernelCompiledSeparately(mustGraph(t, KernelPackage, deps)); !r.Passed() {
				t.Fatalf("gate 2 refused an allowlisted package: %v", r.Err())
			}
			if e.why == "" {
				t.Error("this allowlist entry carries no justification. An allowlist whose " +
					"entries cannot explain themselves becomes a list nobody dares to shorten")
			}
		})
	}
	// A sibling of an exact (non-prefix) entry must NOT be admitted.
	for _, e := range kernelImportAllowlist {
		if e.prefix {
			continue
		}
		deps := append(append([]string(nil), cleanKernelDeps...), e.path+"/internal/detail")
		if r := CheckGate2KernelCompiledSeparately(mustGraph(t, KernelPackage, deps)); r.Passed() {
			t.Errorf("gate 2 admitted %q on the strength of the exact entry %q; an exact "+
				"entry must not cover its subtree", e.path+"/internal/detail", e.path)
		}
	}
}

func TestGate2RefusesTheWrongRoot(t *testing.T) {
	r := CheckGate2KernelCompiledSeparately(mustGraph(t, CoreBinaryPackage, cleanCoreDeps))
	if r.Passed() {
		t.Fatal("gate 2 judged cmd/anvil's graph as though it were the kernel's")
	}
	if r.Failure().Reason != ReasonKernelGraphWrongRoot {
		t.Fatalf("reason %q; want %q",
			string(r.Failure().Reason), string(ReasonKernelGraphWrongRoot))
	}
}

func TestIsStdlibPackage(t *testing.T) {
	stdlib := []string{"fmt", "net/netip", "internal/abi", "vendor/golang.org/x/net/dns/dnsmessage", "C"}
	notStdlib := []string{
		"github.com/Susquehanna-Syntax/Anvil/internal/record",
		"modernc.org/sqlite",
		"golang.org/x/sys/unix",
	}
	for _, p := range stdlib {
		if !isStdlibPackage(p) {
			t.Errorf("%q classified as non-stdlib; the kernel's allowlist would then have "+
				"to enumerate the standard library", p)
		}
	}
	for _, p := range notStdlib {
		if isStdlibPackage(p) {
			t.Errorf("%q classified as stdlib, so it would bypass the kernel import "+
				"allowlist entirely", p)
		}
	}
	if isStdlibPackage("") {
		t.Error("the empty package path classified as stdlib")
	}
}

// ===========================================================================
// GATE 3
// ===========================================================================

func TestGate3PassesWhenOnlyTheKernelDials(t *testing.T) {
	scan := mustScan(t, 412,
		EgressCallSite{Package: KernelPackage, File: "internal/dast/authz/egress.go", Line: 88, Symbol: "net.Dial"},
		EgressCallSite{
			Package: modulePath + "/internal/ingest/poller",
			File:    "internal/ingest/poller/poller.go", Line: 764, Symbol: "http.Client",
		},
	)
	if r := CheckGate3EgressChokePoint(scan); !r.Passed() {
		t.Fatalf("gate 3 refused a scan whose only sites are the kernel and an allowlisted "+
			"Lane A fetcher: %v", r.Err())
	}
}

// TestGate3RefusesASocketInsideDastOutsideTheKernel is tier 1: the absolute
// rule with no allowlist and no code path that could add one.
func TestGate3RefusesASocketInsideDastOutsideTheKernel(t *testing.T) {
	cases := map[string]string{
		"an engine driver": modulePath + "/internal/dast/engines",
		"the crawler":      modulePath + "/internal/dast/inventory",
		"the DAST model":   modulePath + "/internal/dast/model",
		"the tree root":    dastPackageRoot,
	}
	for name, pkg := range cases {
		t.Run(name, func(t *testing.T) {
			scan := mustScan(t, 412,
				EgressCallSite{Package: KernelPackage, File: "internal/dast/authz/egress.go", Line: 88, Symbol: "net.Dial"},
				EgressCallSite{Package: pkg, File: "x.go", Line: 12, Symbol: "http.Client"},
			)
			r := CheckGate3EgressChokePoint(scan)
			if r.Passed() {
				t.Fatalf("gate 3 passed with a socket constructed in %q. There is no "+
					"allowlist for the DAST tree: plan/00-SPINE.md S7 requires that no "+
					"model ever holds a network handle, and a socket the kernel did not "+
					"open is a handle it did not authorize", pkg)
			}
			if r.Failure().Reason != ReasonEgressInsideDastNotAuthz {
				t.Fatalf("reason %q; want %q",
					string(r.Failure().Reason), string(ReasonEgressInsideDastNotAuthz))
			}
		})
	}
}

// TestGate3TierOneIsReportedBeforeTierTwo — a socket inside the DAST tree is
// the failure gate 3 is named for and must not be buried among tier-2
// findings.
func TestGate3TierOneIsReportedBeforeTierTwo(t *testing.T) {
	scan := mustScan(t, 412,
		EgressCallSite{Package: modulePath + "/internal/somewhere", File: "a.go", Line: 3, Symbol: "http.Get"},
		EgressCallSite{Package: modulePath + "/internal/dast/engines", File: "b.go", Line: 4, Symbol: "net.Dial"},
	)
	r := CheckGate3EgressChokePoint(scan)
	if r.Passed() {
		t.Fatal("gate 3 passed with two violations")
	}
	if r.Failure().Reason != ReasonEgressInsideDastNotAuthz {
		t.Fatalf("reason %q; the DAST-tree violation must be reported first",
			string(r.Failure().Reason))
	}
}

// TestGate3RefusesANewFetcherAnywhereInTheRepo is tier 2. D.9's forbidden
// actions require the lint to cover the whole repository, "since the point is
// proving no other package can bypass the kernel either."
func TestGate3RefusesANewFetcherAnywhereInTheRepo(t *testing.T) {
	scan := mustScan(t, 412,
		EgressCallSite{
			Package: modulePath + "/internal/remediation/pusher",
			File:    "internal/remediation/pusher/push.go", Line: 40, Symbol: "http.Client",
		},
	)
	r := CheckGate3EgressChokePoint(scan)
	if r.Passed() {
		t.Fatal("gate 3 passed with a socket constructed in a package that is not on the " +
			"egress allowlist. The scan covers the whole repository on purpose")
	}
	if r.Failure().Reason != ReasonEgressOutsideKernel {
		t.Fatalf("reason %q; want %q",
			string(r.Failure().Reason), string(ReasonEgressOutsideKernel))
	}
	if !strings.Contains(r.Err().Error(), "nonKernelEgressAllowlist") {
		t.Fatalf("the failure does not tell the reader where to add an entry: %v", r.Err())
	}
}

func TestGate3AllowsExactlyTheAllowlistedFetchers(t *testing.T) {
	for _, e := range nonKernelEgressAllowlist {
		t.Run(e.path, func(t *testing.T) {
			scan := mustScan(t, 412,
				EgressCallSite{Package: e.path, File: "x.go", Line: 1, Symbol: "http.Client"})
			if r := CheckGate3EgressChokePoint(scan); !r.Passed() {
				t.Fatalf("gate 3 refused an allowlisted fetcher: %v", r.Err())
			}
			if e.why == "" {
				t.Error("this allowlist entry carries no justification")
			}
		})
	}
}

// TestEgressAllowlistNamesNoDastPackage guards the one way the two tiers could
// be reconciled wrongly: adding a DAST package to the tier-2 allowlist. The
// tier-1 check runs first and would still catch it, and this says so out loud.
func TestEgressAllowlistNamesNoDastPackage(t *testing.T) {
	for _, e := range nonKernelEgressAllowlist {
		if e.path == dastPackageRoot || strings.HasPrefix(e.path, dastPackagePrefix) {
			t.Fatalf("%q is a DAST package and is on the tier-2 egress allowlist. The DAST "+
				"tree has no allowlist: every outbound connection in the dynamic tier goes "+
				"through %s", e.path, KernelPackage)
		}
	}
}

// ===========================================================================
// EnableDAST — gate 1's "explicit, non-defaulted write"
// ===========================================================================

func TestEnableDASTRefusals(t *testing.T) {
	scope := mustScope(t, ModeExternal)
	att := mustAttestation(t, fixtureScopeHash)
	clk := mustClock(t)
	ext, err := DeclareMode(ModeExternal)
	if err != nil {
		t.Fatalf("DeclareMode: %v", err)
	}
	lab, err := DeclareMode(ModeLab)
	if err != nil {
		t.Fatalf("DeclareMode: %v", err)
	}
	staleClock, err := NewClock(fixtureExpires.Add(24 * time.Hour))
	if err != nil {
		t.Fatalf("NewClock: %v", err)
	}

	cases := []struct {
		name     string
		artifact Artifact
		decl     ModeDeclaration
		scope    Scope
		att      Attestation
		clock    Clock
		why      string
	}{
		{"core artifact", ArtifactCore, ext, scope, att, clk,
			"the core binary has no probing capability compiled in (S9-AMENDED)"},
		{"no artifact declared", ArtifactUnset, ext, scope, att, clk,
			"gate 1 requires an explicit, non-defaulted enable"},
		{"invented artifact", Artifact("anvil-pro"), ext, scope, att, clk,
			"the artifact enum is an allowlist of two"},
		{"no mode declared", ArtifactDAST, ModeDeclaration{}, scope, att, clk,
			"gate 6 has no default and no auto"},
		{"no scope", ArtifactDAST, ext, Scope{}, att, clk,
			"gate 4 yields zero permitted targets from a missing scope file"},
		{"mode disagrees with scope", ArtifactDAST, lab, scope, att, clk,
			"gate 6 makes the declaration irreversible; two declarations are refused"},
		{"no attestation", ArtifactDAST, ext, scope, Attestation{}, clk,
			"gate 5 refuses to probe without a live attestation"},
		{"attestation for another scope", ArtifactDAST, ext, scope,
			mustAttestation(t, fixtureOtherHash), clk,
			"editing the scope file invalidates the attestation"},
		{"expired attestation", ArtifactDAST, ext, scope, att, staleClock,
			"gate 5 requires the attestation to be unexpired"},
		{"zero clock", ArtifactDAST, ext, scope, att, Clock{},
			"an unset clock cannot answer whether an attestation is live"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			e, err := EnableDAST(c.artifact, c.decl, c.scope, c.att, c.clock)
			if err == nil {
				t.Fatalf("EnableDAST succeeded with %s: %s", c.name, c.why)
			}
			if e.Enabled() {
				t.Fatalf("EnableDAST returned an ENABLED value alongside an error")
			}
			if !errors.Is(err, ErrRefused) {
				t.Fatalf("the refusal does not unwrap to ErrRefused: %v", err)
			}
		})
	}
}

// TestEnableDASTPositiveControl proves the refusals above are not a function
// that always fails.
func TestEnableDASTPositiveControl(t *testing.T) {
	scope := mustScope(t, ModeExternal)
	att := mustAttestation(t, fixtureScopeHash)
	clk := mustClock(t)
	ext, err := DeclareMode(ModeExternal)
	if err != nil {
		t.Fatalf("DeclareMode: %v", err)
	}
	e, err := EnableDAST(ArtifactDAST, ext, scope, att, clk)
	if err != nil {
		t.Fatalf("EnableDAST refused a fully-specified, attested, in-date external run: %v", err)
	}
	if !e.Enabled() {
		t.Fatal("EnableDAST returned a disabled value with no error")
	}
	if e.Artifact() != ArtifactDAST || e.Mode() != ModeExternal {
		t.Fatalf("the enablement records artifact=%q mode=%q", e.Artifact(), e.Mode())
	}
}

// TestDastEnablementCannotBeForgedByFieldAssignment records what the compiler
// already enforces for other packages, and checks the in-package invariant
// that a partially-filled DastEnablement is still disabled.
func TestDastEnablementCannotBeForgedByFieldAssignment(t *testing.T) {
	cases := map[string]DastEnablement{
		"enabled bit alone":  {enabled: true},
		"core artifact":      {enabled: true, artifact: ArtifactCore, mode: ModeExternal, attestID: "a", scopeHash: fixtureScopeHash},
		"no mode":            {enabled: true, artifact: ArtifactDAST, attestID: "a", scopeHash: fixtureScopeHash},
		"no attestation":     {enabled: true, artifact: ArtifactDAST, mode: ModeExternal, scopeHash: fixtureScopeHash},
		"no scope hash":      {enabled: true, artifact: ArtifactDAST, mode: ModeExternal, attestID: "a"},
		"bad scope hash":     {enabled: true, artifact: ArtifactDAST, mode: ModeExternal, attestID: "a", scopeHash: "short"},
		"auto mode smuggled": {enabled: true, artifact: ArtifactDAST, mode: "auto", attestID: "a", scopeHash: fixtureScopeHash},
	}
	for name, e := range cases {
		if e.Enabled() {
			t.Errorf("a DastEnablement built by field assignment (%s) reports Enabled()", name)
		}
	}
}
