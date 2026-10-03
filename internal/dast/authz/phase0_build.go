// Phase 0 of plan/design/dynamic-tier.md's Authorization Gate Sequence: build and
// packaging. Gates 1, 2 and 3, plus the one function that can turn DAST on.
//
// ===========================================================================
// WHAT PHASE 0 IS FOR
// ===========================================================================
//
// Gates 4–21 decide things about a run. Phase 0 decides things about the
// BINARY, before a run exists — and it is the only phase whose failure mode is
// "this build should not have been shipped" rather than "this request should
// not be sent".
//
// Each gate here is a named function that takes MEASURED FACTS and returns a
// typed GateResult, so that the build-time guard's test can drive it and CI can fail
// on it. They deliberately do not measure anything themselves: measuring means
// shelling out to `go list` and walking the tree, which is the build-time guard's job and which
// would make these functions untestable without a toolchain. The split also
// means the gates cannot lie about their own inputs.
//
// ===========================================================================
// THE FACT TYPES REFUSE TO BE FABRICATED, AND REFUSE TO BE EMPTY
// ===========================================================================
//
// docs/controls.md opens with two incidents in this repository
// where a control that could not run reported success — a symlink test that
// skipped on Windows while a directory junction walked through the guard it
// protected, and a dependency-shape guard that skipped whenever `go list`
// could not run, i.e. in exactly the hermetic environments it mattered in. It
// names the shape: "a guard that vanishes silently when it cannot run is worse
// than no guard, because the green tick is read as an answer."
//
// So ImportGraph and EgressScan both carry an unexported "this was actually
// measured" bit that only their constructors set, and both constructors refuse
// an empty measurement. A zero-value ImportGraph does not mean "nothing was
// imported"; it means "nobody looked", and every gate here refuses it.
//
// ===========================================================================
// GATE 1 IS THE TWO-ARTIFACT SPLIT, NOT A CONFIG KEY
// ===========================================================================
//
// plan/design/dynamic-tier.md's gate 1 row was written against the spine's
// original hardware-tier table, which modelled DAST as `dast.enabled=false`
// inside one binary. That model was AMENDED. The two-artifact split and the
// first plan's two-artifact ruling both rule that a boolean inside a shipped
// binary does not address the concern the gate exists for — UK CMA s.3A(2)
// supply exposure — "because a config flag inside a single shipped binary still
// supplies the probing capability to everyone who installs it."
//
// Anvil therefore ships `anvil` (core, no network-probing capability compiled
// in) and `anvil-dast`. Gate 1 checks the split, and the split is already
// enforced in CI by the artifact-split job in .github/workflows/ci.yml and by
// cmd/anvil/split_test.go. CheckGate1DastShipsDisabled is the same assertion
// in the kernel's own vocabulary, with the second half of gate 1 — "no default
// target, no default scope, no example that resolves to a real host" — added
// as a live check that the zero-value configuration authorizes nothing.

package authz

import (
	"fmt"
	"strings"
)

// ---------------------------------------------------------------------------
// The package paths Phase 0 reasons about
// ---------------------------------------------------------------------------

const (
	// modulePath is Anvil's module path, from go.mod.
	modulePath = "github.com/Susquehanna-Syntax/Anvil"

	// CoreBinaryPackage is `anvil`: the artifact distros package and most
	// users install. It must never reach a DAST package.
	CoreBinaryPackage = modulePath + "/cmd/anvil"

	// DastBinaryPackage is `anvil-dast`: the separately-installed,
	// separately-attested dynamic tier.
	DastBinaryPackage = modulePath + "/cmd/anvil-dast"

	// KernelPackage is this package. It is the ONLY package in Anvil
	// permitted to construct a socket for DAST purposes (gate 3).
	KernelPackage = modulePath + "/internal/dast/authz"

	// dastPackagePrefix matches every DAST package. cmd/anvil's import graph
	// must contain none of them.
	dastPackagePrefix = modulePath + "/internal/dast/"

	// dastPackageRoot is the prefix's parent, matched exactly, so a package
	// literally at internal/dast is caught too.
	dastPackageRoot = modulePath + "/internal/dast"
)

// ---------------------------------------------------------------------------
// Measured facts
// ---------------------------------------------------------------------------

// ImportGraph is a package's transitive import closure, as measured by
// `go list -deps <pkg>`.
//
// The zero value is NOT "a package with no imports" — that package does not
// exist, since everything imports something. It is "nobody measured", and
// every gate refuses it.
type ImportGraph struct {
	root   string
	deps   []string
	walked bool
}

// NewImportGraph records a measured import closure.
//
// deps is the raw output of `go list -deps <root>`, one package path per
// element. It normally contains root itself; that is fine and expected.
func NewImportGraph(root string, deps []string) (ImportGraph, error) {
	if root == "" {
		return ImportGraph{}, fmt.Errorf("import graph: %w: no root package named", ErrNotMeasured)
	}
	if len(deps) == 0 {
		return ImportGraph{}, fmt.Errorf("import graph: %w: the dependency list for %s is "+
			"empty. Every Go package imports something, so an empty list means `go list "+
			"-deps` did not run or its output was discarded — and a gate that accepted it "+
			"would pass by finding nothing", ErrNotMeasured, root)
	}
	clean := make([]string, 0, len(deps))
	for i, d := range deps {
		d = strings.TrimSpace(d)
		if d == "" {
			return ImportGraph{}, fmt.Errorf("import graph: %w: dependency %d of %s is empty",
				ErrNotMeasured, i, root)
		}
		clean = append(clean, d)
	}
	return ImportGraph{root: root, deps: clean, walked: true}, nil
}

// Walked reports whether the graph was measured.
func (g ImportGraph) Walked() bool { return g.walked && g.root != "" && len(g.deps) > 0 }

// Root returns the package the closure was measured from.
func (g ImportGraph) Root() string { return g.root }

// Deps returns a copy of the measured closure.
func (g ImportGraph) Deps() []string {
	if !g.Walked() {
		return nil
	}
	return append([]string(nil), g.deps...)
}

// EgressCallSite is one place in the tree where a socket or an HTTP client is
// constructed, as reported by the build-time guard's repo-wide lint.
type EgressCallSite struct {
	// Package is the full import path of the package the site is in.
	Package string
	// File is the path of the file, relative to the repository root.
	File string
	// Line is the 1-indexed line.
	Line int
	// Symbol is what was constructed: "net.Dial", "http.Client",
	// "http.Get", "tls.Dial", and so on.
	Symbol string
}

// String renders the site for a failure message.
func (s EgressCallSite) String() string {
	return fmt.Sprintf("%s:%d %s (package %s)", s.File, s.Line, s.Symbol, s.Package)
}

// EgressScan is the result of the build-time guard's repo-wide scan for socket construction.
//
// FilesScanned is part of the measurement and not decoration: a scan that
// looked at zero files finds zero violations, and "we found nothing" and "we
// did not look" are the same output with opposite meanings. NewEgressScan
// refuses the second one.
type EgressScan struct {
	filesScanned int
	sites        []EgressCallSite
	ran          bool
}

// NewEgressScan records a completed scan. sites may legitimately be empty;
// filesScanned may not.
func NewEgressScan(filesScanned int, sites []EgressCallSite) (EgressScan, error) {
	if filesScanned <= 0 {
		return EgressScan{}, fmt.Errorf("egress scan: %w: the scan reports %d files "+
			"examined. A scan that looked at nothing finds nothing, and gate 3 would then "+
			"pass on an empty result", ErrNotMeasured, filesScanned)
	}
	for i, s := range sites {
		if s.Package == "" || s.File == "" || s.Line <= 0 || s.Symbol == "" {
			return EgressScan{}, fmt.Errorf("egress scan: %w: site %d is incomplete (%+v); "+
				"a site the gate cannot attribute to a package cannot be judged",
				ErrNotMeasured, i, s)
		}
	}
	return EgressScan{
		filesScanned: filesScanned,
		sites:        append([]EgressCallSite(nil), sites...),
		ran:          true,
	}, nil
}

// Ran reports whether the scan actually ran.
func (s EgressScan) Ran() bool { return s.ran && s.filesScanned > 0 }

// FilesScanned returns how many files the scan examined.
func (s EgressScan) FilesScanned() int { return s.filesScanned }

// Sites returns a copy of the discovered call sites.
func (s EgressScan) Sites() []EgressCallSite {
	if !s.Ran() {
		return nil
	}
	return append([]EgressCallSite(nil), s.sites...)
}

// ---------------------------------------------------------------------------
// The two allowlists
// ---------------------------------------------------------------------------

// allowEntry is one line of an allowlist: a package path, whether the entry
// covers the subtree beneath it, and why it is there.
//
// The "why" is a field rather than a comment because it is printed in the
// failure message. An allowlist whose entries cannot explain themselves
// becomes a list nobody dares to shorten.
type allowEntry struct {
	path   string
	prefix bool
	why    string
}

func (e allowEntry) covers(pkg string) bool {
	if e.prefix {
		return pkg == e.path || strings.HasPrefix(pkg, e.path+"/")
	}
	return pkg == e.path
}

// kernelImportAllowlist is every non-stdlib package the authorization kernel
// is permitted to reach (gate 2).
//
// # Why an allowlist and not a denylist of inference packages
//
// The kernel core's forbidden actions and the spine's safety section both phrase gate 2 as a
// denylist: no imports from "any package path containing /inference/, /model/
// or /llm/". A denylist of three substrings is defeated by naming a package
// anything else — internal/dast/engine, internal/agent, internal/reasoning —
// and by any third-party dependency that vendors a runtime under a name nobody
// listed. The kernel's legitimate dependency surface, by contrast, is tiny and
// known, so it can be enumerated.
//
// The denylist is kept as well, and runs first, purely so that the specific
// failure the spine's safety section names produces a message that says "you imported the inference
// layer" instead of "this package is not on the allowlist". Both refuse.
//
// # Amending this list is a reviewed act
//
// It lives in the kernel core's write scope on purpose: widening the kernel's dependency
// surface should require editing the kernel's own build gate, in a diff whose
// whole subject is that widening. The disclosure phase (the gate-21 audit sink, which will need
// a durable store) and the kernel's build-time guard are the two packets
// expected to need an entry; see the note in the kernel core's report.
var kernelImportAllowlist = []allowEntry{
	{
		path:   modulePath + "/internal/record",
		prefix: false,
		why: "gate 21's audit rows are part of Anvil's audit record, and the record " +
			"package is the single owner of the frozen enums " +
			"(the first plan's shared-vocabulary ruling: 'the record area owns every shared " +
			"enum ... no other area may declare one'). It has no non-stdlib dependencies " +
			"of its own, so admitting it does not widen the surface further.",
	},
}

// inferenceLayerMarkers is the denylist the spine's safety section names verbatim. It is redundant
// against kernelImportAllowlist and is kept for the message it produces.
//
// RESIDUAL RISK, STATED RATHER THAN PAPERED OVER: on its own this list catches
// only packages that happen to be named for what they are. It is the allowlist
// above that actually holds.
var inferenceLayerMarkers = []string{"/inference/", "/model/", "/llm/"}

// nonKernelEgressAllowlist is every package OUTSIDE internal/dast that is
// permitted to construct a socket (gate 3, tier 2).
//
// # The two tiers, and why only one of them has an allowlist
//
// Gate 3's requirement, from the build-time guard's forbidden actions, is that the lint "cover
// the whole repo, not just the DAST package, since the point is proving no
// other package can bypass the kernel either." But Anvil's static half
// legitimately fetches things — advisory feeds, vulnerability databases — and
// those fetches are not probing. So gate 3 asks two different questions:
//
//	Tier 1, absolute: any socket constructed inside internal/dast but outside
//	internal/dast/authz is a FAILURE. There is no allowlist for this tier and
//	no code path that could add one. This is the choke point.
//
//	Tier 2, allowlisted: any socket constructed elsewhere in the repository
//	must be in the list below. A new one anywhere else fails the gate until
//	someone justifies it here.
//
// # Provenance of the entries
//
// MEASURED, not assumed, on 2026-08-22 by grepping the tree for net.Dial,
// http.Client, http.Get, http.Post, http.DefaultClient, http.NewRequest,
// net.Listen and tls.Dial across all non-test .go files. Three packages
// matched, all of them Lane A ingestion or mirror code. The kernel's build-time
// guard owns the lint that keeps this list honest.
var nonKernelEgressAllowlist = []allowEntry{
	{
		path:   modulePath + "/internal/ingest/bootstrap",
		prefix: false,
		why:    "Lane A: bootstraps the advisory corpus over HTTP. Not a probe of a target.",
	},
	{
		path:   modulePath + "/internal/ingest/poller",
		prefix: false,
		why:    "Lane A: polls upstream advisory feeds for deltas. Not a probe of a target.",
	},
	{
		path:   modulePath + "/internal/mirror/accelerator",
		prefix: false,
		why: "Lane A: downloads Trivy and Grype database bundles into the local mirror. " +
			"Not a probe of a target.",
	},
}

// isStdlibPackage reports whether p is a standard-library package.
//
// The rule is the module system's own: a non-stdlib module path must have a
// dot in its first path element, and no stdlib import path does. Vendored
// stdlib dependencies (`vendor/golang.org/x/...` as `go list` prints them) and
// the pseudo-package `C` both fall on the stdlib side, correctly.
func isStdlibPackage(p string) bool {
	if p == "" {
		return false
	}
	first := p
	if i := strings.IndexByte(p, '/'); i >= 0 {
		first = p[:i]
	}
	return !strings.Contains(first, ".")
}

// ---------------------------------------------------------------------------
// GATE 1 — DAST ships disabled: the two-artifact split, and no live defaults
// ---------------------------------------------------------------------------

// CheckGate1DastShipsDisabled checks that the core artifact ships with no DAST
// capability compiled in, and that the kernel's zero-value configuration
// authorizes nothing.
//
// core is the measured import closure of cmd/anvil. Handing it any other
// package's closure is itself a failure: a gate that will judge whatever graph
// you give it can be satisfied by giving it an easy one.
//
// The second half — "no default target/scope, no example resolves to a real
// host" — is checked live rather than asserted in prose. Every zero value in
// the kernel's vocabulary is exercised here, and any one of them permitting
// something fails the gate. That is the check that would catch a future
// contributor adding a `var DefaultScope = ...` or making a zero Decision
// allow.
//
// # WHAT THIS GATE DOES NOT YET PROVE, MEASURED ON 2026-08-22
//
// The negative half — "cmd/anvil does not reach internal/dast" — is currently
// satisfied by EMPTINESS. `go list -deps ./cmd/anvil-dast` does not list
// internal/dast either: NEITHER binary links the kernel today, because nothing
// in cmd/ has a consumer for it yet. So the import-graph comparison passes
// against a graph in which the DAST tree appears nowhere, and it would keep
// passing if the kernel were deleted.
//
// That is a vacuous positive, and it is written down rather than papered over.
// The gate is not fabricated a consumer to satisfy it — a consumer invented to
// make a gate green is the exact shape docs/controls.md records
// this repository shipping twice. The kernel's build-time guard owns the real
// positive control: once cmd/anvil-dast links the kernel, gate 1 needs BOTH
// graphs — anvil-dast MUST contain internal/dast/authz and anvil MUST NOT — so
// that the split is proved by a difference between two measurements rather than
// by the absence of one.
func CheckGate1DastShipsDisabled(core ImportGraph) GateResult {
	return gate1(core, zeroValuesThatWouldAuthorize())
}

// gate1 is CheckGate1DastShipsDisabled with the zero-value survey supplied.
//
// The seam is unexported and its only production caller passes the real
// survey, so nothing can hand this gate a fabricated clean bill of health. It
// exists because the zero-value arm is otherwise untestable: the survey is a
// pure function of the package's own types, so a test cannot make it report a
// fault, and a mutation that deleted the arm entirely stayed green.
func gate1(core ImportGraph, zeroValueFaults []string) GateResult {
	const g = Gate1DastShipsDisabled

	if !core.Walked() {
		return gateFailed(g, ReasonImportGraphNotWalked,
			"the core binary's import graph was never measured. A gate handed an "+
				"unmeasured graph must refuse: finding no DAST packages in a list nobody "+
				"populated is not evidence of anything.")
	}
	if core.Root() != CoreBinaryPackage {
		return gateFailed(g, ReasonWrongArtifact, fmt.Sprintf(
			"gate 1 is about the core artifact and was handed the import graph of %q. "+
				"The graph it must judge is %q; %q is the DAST artifact and is EXPECTED "+
				"to reach the DAST packages.",
			core.Root(), CoreBinaryPackage, DastBinaryPackage))
	}

	var violations []string
	for _, dep := range core.Deps() {
		if dep == dastPackageRoot || strings.HasPrefix(dep, dastPackagePrefix) {
			violations = append(violations, dep)
		}
	}
	if len(violations) > 0 {
		return gateFailed(g, ReasonCoreArtifactReachesDAST, fmt.Sprintf(
			"%s reaches %d DAST package(s) through its import graph. plan/design/spine.md "+
				"The two-artifact split splits Anvil into two artifacts precisely so that the core "+
				"binary supplies no probing capability; the first plan's two-artifact ruling "+
				"rules that a config flag inside one binary does not do that. Move the "+
				"code to %s rather than gating it behind a flag or a build tag.",
			CoreBinaryPackage, len(violations), DastBinaryPackage), violations...)
	}

	if len(zeroValueFaults) > 0 {
		return gateFailed(g, ReasonZeroValueWouldAuthorize,
			"a zero-value construct in the authorization kernel authorizes something. "+
				"Gate 1 requires that DAST ships with no default target and no default "+
				"scope; in a Go program the default is the zero value, so this is what "+
				"'ships disabled' means at runtime.", zeroValueFaults...)
	}
	return gatePassed(g)
}

// zeroValuesThatWouldAuthorize exercises every zero value in the kernel's
// vocabulary and returns a description of any that permits something.
//
// This is gate 1's "no default target, no default scope, no bundled example
// that resolves to a real host" expressed as an executable check rather than a
// claim. It is also the regression test for the single design rule this
// package is built on, run at build time in the shipped binary's own terms.
func zeroValuesThatWouldAuthorize() []string {
	var bad []string
	add := func(what string) { bad = append(bad, what) }

	if Decide(Target{}, Scope{}, Attestation{}, Clock{}).Permits() {
		add("Decide with four zero-value inputs returned a permitting Ruling")
	}
	if Revalidate(Target{}, Scope{}, Attestation{}, Clock{}).Permits() {
		add("Revalidate with four zero-value inputs returned a permitting Ruling")
	}
	if (Decision{}).Allowed() {
		add("the zero Decision reports Allowed() == true")
	}
	if (Authorization{}).Valid() {
		add("the zero Authorization reports Valid() == true")
	}
	if (DastEnablement{}).Enabled() {
		add("the zero DastEnablement reports Enabled() == true, so dast.enabled defaults to on")
	}
	if (ModeDeclaration{}).Declared() {
		add("the zero ModeDeclaration reports Declared() == true, so a run has a default mode")
	}
	if (Scope{}).Constructed() {
		add("the zero Scope reports Constructed() == true")
	}
	if (Scope{}).Permits("example.com", 443) {
		add("the zero Scope permits example.com:443, so there is a default scope")
	}
	if (Attestation{}).Constructed() {
		add("the zero Attestation reports Constructed() == true")
	}
	if (Attestation{}).Live(Clock{}) {
		add("the zero Attestation is live against the zero Clock")
	}
	if (Target{}).Constructed() {
		add("the zero Target reports Constructed() == true, so there is a default target")
	}
	if (Clock{}).Valid() {
		add("the zero Clock reports Valid() == true")
	}
	if (Ruling{}).Permits() {
		add("the zero Ruling permits")
	}
	if (GateResult{}).Passed() {
		add("the zero GateResult reports Passed() == true, so an unrun gate reads as a pass")
	}
	if (Cap[int]{}).Allows(0) {
		add("the zero Cap permits a value, so an uninitialized cap is not a closed one")
	}
	if ModeUnset.Valid() || OutcomeUnset.Allows() || ArtifactUnset.Valid() ||
		SchemeUnset.Valid() || AuthorityUnset.Valid() || GateUnspecified.Valid() {
		add("an enum's zero value validates, so an unset field reads as a legal choice")
	}
	if ReasonUnspecified.Validate() == nil {
		add("the empty Reason validates")
	}
	if _, ok := checkEnablement(DastEnablement{}, Scope{}, Attestation{}); ok {
		add("the zero DastEnablement passes gate 1's adjudication precondition, so a caller " +
			"who never called EnableDAST may mint permission")
	}
	if err := RequireAuthorization(Authorization{}, Target{}); err == nil {
		add("RequireAuthorization accepted a zero Authorization for a zero Target, so the " +
			"egress choke point would open a socket with no decision behind it")
	}
	return bad
}

// ---------------------------------------------------------------------------
// GATE 2 — the kernel is compiled separately, with zero inference imports
// ---------------------------------------------------------------------------

// CheckGate2KernelCompiledSeparately checks that internal/dast/authz's import
// closure contains nothing but the standard library and the explicitly
// allowlisted packages.
//
// The spine's safety section: "The authorization kernel is a pure function of (target,
// scope, attestation, clock), compiled separately from the model runtime, with
// a build-time test that fails if the dependency graph inverts. No model ever
// holds a network handle."
//
// The kernel's build-time guard owns the test that MEASURES the graph and fails
// the build. This function owns what that test asserts.
func CheckGate2KernelCompiledSeparately(kernel ImportGraph) GateResult {
	const g = Gate2KernelCompiledSeparately

	if !kernel.Walked() {
		return gateFailed(g, ReasonKernelGraphNotWalked,
			"the kernel's import graph was never measured. See gate 1: an unmeasured "+
				"graph is not a clean one.")
	}
	if kernel.Root() != KernelPackage {
		return gateFailed(g, ReasonKernelGraphWrongRoot, fmt.Sprintf(
			"gate 2 is about %q and was handed the import graph of %q",
			KernelPackage, kernel.Root()))
	}

	// The denylist runs first so that the specific failure the spine's safety
	// section names gets the specific message. It is redundant against the
	// allowlist below, which is what actually holds.
	var inference []string
	for _, dep := range kernel.Deps() {
		if isStdlibPackage(dep) {
			continue
		}
		probe := dep
		if !strings.HasSuffix(probe, "/") {
			probe += "/"
		}
		for _, marker := range inferenceLayerMarkers {
			if strings.Contains(probe, marker) {
				inference = append(inference, dep+"  (matches "+marker+")")
				break
			}
		}
	}
	if len(inference) > 0 {
		return gateFailed(g, ReasonKernelImportsInference, fmt.Sprintf(
			"the authorization kernel reaches %d inference-layer package(s). "+
				"The spine's safety section requires the kernel to be compiled separately from "+
				"the model runtime and states the reason plainly: no model ever holds a "+
				"network handle. A kernel that links the model runtime has no boundary "+
				"left to enforce.", len(inference)), inference...)
	}

	var offlist []string
	for _, dep := range kernel.Deps() {
		if isStdlibPackage(dep) || dep == KernelPackage {
			continue
		}
		allowed := false
		for _, e := range kernelImportAllowlist {
			if e.covers(dep) {
				allowed = true
				break
			}
		}
		if !allowed {
			offlist = append(offlist, dep)
		}
	}
	if len(offlist) > 0 {
		var b strings.Builder
		b.WriteString("the kernel's permitted non-stdlib imports are:")
		if len(kernelImportAllowlist) == 0 {
			b.WriteString("\n    (none)")
		}
		for _, e := range kernelImportAllowlist {
			b.WriteString("\n    ")
			b.WriteString(e.path)
			if e.prefix {
				b.WriteString("/...")
			}
			b.WriteString(" — ")
			b.WriteString(e.why)
		}
		return gateFailed(g, ReasonKernelImportNotAllowed, fmt.Sprintf(
			"the authorization kernel reaches %d package(s) that are not on its import "+
				"allowlist. This is an allowlist rather than a denylist of inference "+
				"package names because a denylist is defeated by naming a package "+
				"something else. If one of these belongs in the kernel, add it to "+
				"kernelImportAllowlist with a justification — that edit is the review "+
				"this gate exists to force.\n  %s",
			len(offlist), b.String()), offlist...)
	}
	return gatePassed(g)
}

// ---------------------------------------------------------------------------
// GATE 3 — the egress choke point
// ---------------------------------------------------------------------------

// CheckGate3EgressChokePoint checks that no socket is constructed outside the
// kernel.
//
// research/20 gate 3: "A build-time test asserts that zero outbound sockets can
// be opened outside the kernel — e.g. a linter/CI check banning direct
// net.Dial/http.Client/requests construction anywhere but the kernel, plus a
// runtime test that a raw dial attempt from the DAST package panics."
//
// This function is the build-time half. The runtime half is
// RequireAuthorization in kernel.go, which the choke point calls immediately
// before it dials and which refuses any Authorization that does not name
// exactly the target being connected to, pinned address included.
//
// See nonKernelEgressAllowlist for the two tiers and why only one of them has
// an allowlist.
func CheckGate3EgressChokePoint(scan EgressScan) GateResult {
	const g = Gate3EgressChokePoint

	if !scan.Ran() {
		return gateFailed(g, ReasonEgressScanNotRun,
			"the repo-wide egress scan never ran, or ran over zero files. Gate 3 refuses "+
				"an unmeasured scan for the same reason gates 1 and 2 refuse an "+
				"unmeasured import graph: 'we found nothing' and 'we did not look' "+
				"produce identical output and opposite conclusions.")
	}

	var insideDast, elsewhere []string
	for _, s := range scan.Sites() {
		pkg := s.Package
		switch {
		case pkg == KernelPackage:
			// The choke point itself. This is the one place a socket may
			// be constructed for DAST, and gate 3 exists to make it the
			// only one.
		case pkg == dastPackageRoot || strings.HasPrefix(pkg, dastPackagePrefix):
			insideDast = append(insideDast, s.String())
		default:
			allowed := false
			for _, e := range nonKernelEgressAllowlist {
				if e.covers(pkg) {
					allowed = true
					break
				}
			}
			if !allowed {
				elsewhere = append(elsewhere, s.String())
			}
		}
	}

	// Tier 1 is reported first and on its own: a socket inside the DAST tree
	// but outside the kernel is the failure gate 3 is named for, and it must
	// not be buried among tier-2 findings.
	if len(insideDast) > 0 {
		return gateFailed(g, ReasonEgressInsideDastNotAuthz, fmt.Sprintf(
			"%d socket construction(s) inside the DAST tree but outside %s. There is no "+
				"allowlist for this and no code path that can add one. Every outbound "+
				"connection in the dynamic tier goes through the kernel, because "+
				"The spine's safety section requires that no model ever holds a network handle "+
				"and a socket the kernel did not open is a handle it did not authorize. "+
				"Route it through Adjudicate and RequireAuthorization.",
			len(insideDast), KernelPackage), insideDast...)
	}
	if len(elsewhere) > 0 {
		return gateFailed(g, ReasonEgressOutsideKernel, fmt.Sprintf(
			"%d socket construction(s) in package(s) not on the egress allowlist. The "+
				"scan covers the whole repository on purpose: the claim gate 3 makes is "+
				"that no package can bypass the kernel, and that claim is not restricted "+
				"to the DAST tree. If one of these is a legitimate non-probing fetch, add "+
				"it to nonKernelEgressAllowlist with a justification.",
			len(elsewhere)), elsewhere...)
	}
	return gatePassed(g)
}

// ---------------------------------------------------------------------------
// EnableDAST — the only way to a true `dast.enabled`
// ---------------------------------------------------------------------------

// EnableDAST is the explicit, non-defaulted write gate 1 requires before DAST
// is on.
//
// There is no other constructor of an enabled DastEnablement, no exported
// field to set, and no config decoder that can reach one: encoding/json,
// encoding/gob and every other reflective decoder are as unable to write an
// unexported field as a composite literal is. `dast.enabled` therefore defaults
// to false in the only sense that matters at runtime — the zero value — and
// turning it on requires passing all five checks below.
//
// # It has a consumer, and that is what makes it a gate
//
// The kernel-types review reached Adjudicate without ever calling this function, which
// made gate 1 decorative: a write nothing reads is a comment. Adjudicate now
// takes a DastEnablement and refuses when it is not enabled, when it was minted
// against a different scope hash, or when it was minted under a different
// attestation. TestAdjudicateRefusesWithoutAnEnablement is the test that a
// caller who skips this function gets nothing.
//
// The artifact check is the one that carries the two-artifact split: the
// core binary can never enable DAST, whatever its configuration says, because
// `anvil` is the artifact with no probing capability compiled in and gate 2's
// import-graph assertion is what makes that true rather than claimed.
func EnableDAST(
	artifact Artifact,
	decl ModeDeclaration,
	scope Scope,
	attestation Attestation,
	clock Clock,
) (DastEnablement, error) {
	switch artifact {
	case ArtifactDAST:
		// The only artifact that may probe.
	case ArtifactCore:
		return DastEnablement{}, fmt.Errorf("enable dast: %w: %q is the core artifact and "+
			"has no network-probing capability compiled in. The two-artifact split "+
			"and the first plan's two-artifact ruling split the distribution precisely so that "+
			"this cannot be turned on by configuration; install %q instead",
			ErrRefused, ArtifactCore, ArtifactDAST)
	default:
		return DastEnablement{}, fmt.Errorf("enable dast: %w: no artifact was declared. "+
			"Gate 1 requires an explicit, non-defaulted enable, and that starts with "+
			"stating which of %q and %q is running", ErrRefused, ArtifactCore, ArtifactDAST)
	}

	if !decl.Declared() {
		return DastEnablement{}, fmt.Errorf("enable dast: %w: no mode was declared. Gate 6 "+
			"requires an explicit, irreversible declaration of %q or %q and has no `auto`",
			ErrRefused, ModeLab, ModeExternal)
	}
	declared, err := decl.Mode()
	if err != nil {
		return DastEnablement{}, fmt.Errorf("enable dast: %w", err)
	}
	if !scope.Constructed() {
		return DastEnablement{}, fmt.Errorf("enable dast: %w: no scope. Gate 4 yields zero "+
			"permitted targets from a missing scope file, and enabling DAST against zero "+
			"targets with no hash to bind an attestation to is not a state worth "+
			"representing", ErrRefused)
	}
	scopeMode, err := scope.Mode()
	if err != nil {
		return DastEnablement{}, fmt.Errorf("enable dast: %w", err)
	}
	if scopeMode != declared {
		return DastEnablement{}, fmt.Errorf("enable dast: %w: the run declares mode %q and "+
			"the scope was loaded for mode %q. Gate 6 makes the declaration irreversible "+
			"for the run, so two disagreeing declarations are not reconciled — they are "+
			"refused", ErrRefused, declared, scopeMode)
	}
	if !attestation.Constructed() {
		return DastEnablement{}, fmt.Errorf("enable dast: %w: no attestation. Gate 5: Anvil "+
			"refuses to probe any target it does not itself own without a live "+
			"attestation", ErrRefused)
	}
	if !attestation.CoversScope(scope) {
		return DastEnablement{}, fmt.Errorf("enable dast: %w: the attestation is bound to "+
			"scope hash %s and this scope hashes to %s; editing the scope file invalidates "+
			"the attestation, which is what binding it to the hash is for (gate 5)",
			ErrRefused, string(attestation.ScopeHash()), string(scope.Hash()))
	}
	if !attestation.Live(clock) {
		return DastEnablement{}, fmt.Errorf("enable dast: %w: the attestation is not live at "+
			"the supplied instant (gate 5: present, valid, unexpired)", ErrRefused)
	}

	return DastEnablement{
		enabled:   true,
		artifact:  ArtifactDAST,
		mode:      declared,
		attestID:  attestation.ID(),
		scopeHash: scope.Hash(),
	}, nil
}
