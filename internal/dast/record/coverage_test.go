// Tests for D.26, the coverage summary: the packet that produces the number an
// operator trusts.
//
// The suite is organised around the ways the number can look better than the
// evidence, because that is the only direction anybody is rewarded for:
//
//	THE NUMERATOR — asserted counts, never len(x) > 0, and every confirmation
//	traced to a kernel-admitted request that this file's harness actually
//	drove through the real Phase 1 gates.
//
//	THE DENOMINATOR — the half nobody investigates. An unsupported language
//	shrinks it and coverage goes UP; duplicates inflate it and coverage goes
//	DOWN. Both are exercised with fixtures that produce the breaking input
//	rather than with a hand-built result, because a generator that cannot
//	produce the breaking input is the defect.
//
//	ZERO VERSUS UNKNOWN — the failure this packet exists to prevent. Two runs
//	that both render "0.0" and must not be the same fact.
//
//	NULL VERSUS ZERO — server_line_coverage is a pointer for one reason and
//	both sides of it are tested.
//
// The kernel harness is the one tier0_runtime_test.go established, rebuilt
// here because this is a different package: initiateRun drives the real gates
// and authz.Adjudicate is the only mint for an Authorization. The
// EndpointProber is the only double, because D.9's gate 3 forbids a socket
// outside internal/dast/authz.
package record

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/Susquehanna-Syntax/Anvil/internal/dast/authz"
	"github.com/Susquehanna-Syntax/Anvil/internal/dast/inventory"
	rec "github.com/Susquehanna-Syntax/Anvil/internal/record"
)

// ---------------------------------------------------------------------------
// Kernel harness
// ---------------------------------------------------------------------------

const (
	fixtureHost    = "target.example.com"
	fixtureRepo    = "Susquehanna-Syntax/anvil-dast-fixture"
	fixtureNowS    = "2026-08-10T09:00:00Z"
	fixtureIssuedS = "2026-08-01T00:00:00Z"
	fixtureExpires = "2026-08-29T00:00:00Z"
)

func mustAddr(t *testing.T, s string) netip.Addr {
	t.Helper()
	a, err := netip.ParseAddr(s)
	if err != nil {
		t.Fatalf("netip.ParseAddr(%q): %v", s, err)
	}
	return a
}

func mustClock(t *testing.T) authz.Clock {
	t.Helper()
	at, err := time.Parse(time.RFC3339, fixtureNowS)
	if err != nil {
		t.Fatalf("parsing the fixture instant: %v", err)
	}
	c, err := authz.NewClock(at)
	if err != nil {
		t.Fatalf("authz.NewClock: %v", err)
	}
	return c
}

func mustTarget(t *testing.T) authz.Target {
	t.Helper()
	tgt, err := authz.NewTarget(authz.SchemeHTTPS, fixtureHost, fixtureHost, 443,
		mustAddr(t, "198.51.100.7"))
	if err != nil {
		t.Fatalf("authz.NewTarget: %v", err)
	}
	return tgt
}

func scopeFileJSON() []byte {
	return []byte(fmt.Sprintf(
		`{"schema_version":1,"mode":"external","allow":[{"host":%q,"ports":[443]}],"deny":[]}`,
		fixtureHost))
}

func attestationFileJSON(hash authz.ScopeHash) []byte {
	return []byte(fmt.Sprintf(
		`{"schema_version":1,"id":"attest-2026-08-01-018","identity":"Susquehanna Syntax, `+
			`operator of %s","authority":"operator","scope_hash":%q,"issued_at":%q,`+
			`"expires_at":%q}`,
		fixtureHost, string(hash), fixtureIssuedS, fixtureExpires))
}

func initiateRun(t *testing.T) authz.RunInitiation {
	t.Helper()
	raw := scopeFileJSON()
	trigger, err := authz.NewTriggerContext(authz.TriggerFacts{
		Event:            authz.TriggerEventManualOperator,
		Repository:       fixtureRepo,
		Actor:            "operator",
		ActorPermission:  authz.ActorPermissionAdmin,
		PermissionSource: authz.PermissionSourceOperatorLocal,
	})
	if err != nil {
		t.Fatalf("authz.NewTriggerContext: %v", err)
	}
	policy, err := authz.NewTriggerPolicy(authz.TriggerEventManualOperator)
	if err != nil {
		t.Fatalf("authz.NewTriggerPolicy: %v", err)
	}
	init, res := authz.InitiateRun(authz.RunRequest{
		Artifact:                   authz.ArtifactDAST,
		Mode:                       string(authz.ModeExternal),
		ScopeFile:                  raw,
		AttestationFile:            attestationFileJSON(authz.ScopeHashOf(raw)),
		AttestationLifetimeCeiling: authz.MaxAttestationLifetime,
		Trigger:                    trigger,
		TriggerPolicy:              policy,
		ScopeRepository:            fixtureRepo,
		Clock:                      mustClock(t),
	})
	if !res.Passed() {
		t.Fatalf("authz.InitiateRun refused at %s: %v. This harness drives the real Phase 1 "+
			"gates, so a refusal here means the fixture no longer satisfies them",
			res.Gate(), res.Err())
	}
	return init
}

type countingSink struct{ n int }

func (s *countingSink) WriteGateDecision(authz.GateRecord) (authz.AuditSeq, error) {
	s.n++
	return authz.AuditSeq(s.n), nil
}

func kernel(t *testing.T) (*authz.Governor, *authz.GateAudit) {
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
	run, err := init.RunClock()
	if err != nil {
		t.Fatalf("init.RunClock: %v", err)
	}
	audit, res := authz.NewGateAudit(&countingSink{}, key, run)
	if !res.Passed() {
		t.Fatalf("authz.NewGateAudit: %v", res.Err())
	}
	gov, res := authz.NewGovernor(authz.GovernorConfig{
		Target:      mustTarget(t),
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
	return gov, audit
}

func mintAuthorization(t *testing.T) authz.Authorization {
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
	en, err := init.Enablement()
	if err != nil {
		t.Fatalf("init.Enablement: %v", err)
	}
	dec := authz.Adjudicate(&countingSink{}, en, mustTarget(t), scope, att, mustClock(t))
	if !dec.Allowed() {
		t.Fatalf("the admission chain REFUSED the fixture target at %s (%s): %v. "+
			"Every confirmed endpoint in this file's numerator comes from a request that "+
			"passed this chain; if gate 11 is back in kernel.go's admissionChain the whole "+
			"numerator half of this suite becomes unreachable",
			dec.Gate(), dec.Reason(), dec.Err())
	}
	auth, err := dec.Authorization()
	if err != nil {
		t.Fatalf("an allowing Decision handed out no Authorization: %v", err)
	}
	return auth
}

// ---------------------------------------------------------------------------
// Inventory fixtures
// ---------------------------------------------------------------------------

// prober is the egress seam's double. It records what it was handed, so a test
// can assert what actually left rather than what the implementation says.
type prober struct {
	byPath map[string]int
	def    int
	calls  int
}

func (p *prober) ProbeEndpoint(_ context.Context, req inventory.ConfirmRequest) (inventory.ConfirmResponse, error) {
	p.calls++
	if s, ok := p.byPath[req.Path()]; ok {
		return inventory.ConfirmResponse{Status: s, Latency: 3 * time.Millisecond}, nil
	}
	return inventory.ConfirmResponse{Status: p.def, Latency: 3 * time.Millisecond}, nil
}

type advancingClock struct {
	t  *testing.T
	at time.Time
}

func (c *advancingClock) NextInstant() authz.Clock {
	c.at = c.at.Add(time.Second)
	k, err := authz.NewClock(c.at)
	if err != nil {
		c.t.Fatalf("authz.NewClock(%v): %v", c.at, err)
	}
	return k
}

func route(t *testing.T, m authz.Method, path, op string, prov rec.InventoryProvenance) inventory.Route {
	t.Helper()
	rt, err := inventory.NewRoute(inventory.RouteFacts{
		Method:       m,
		Path:         path,
		Target:       mustTarget(t),
		Operation:    op,
		Provenance:   prov,
		Confirmation: inventory.ConfirmationCandidate,
		Trust:        rec.TrustUntrusted,
	})
	if err != nil {
		t.Fatalf("inventory.NewRoute(%s %s): %v", m, path, err)
	}
	return rt
}

// confirming builds the standard confirming configuration: real Governor, real
// GateAudit, real Authorization, one double at the egress seam.
func confirming(t *testing.T, p inventory.EndpointProber, budget int) inventory.ConfirmConfig {
	t.Helper()
	gov, audit := kernel(t)
	return inventory.ConfirmConfig{
		Governor:      gov,
		Audit:         audit,
		Authorization: mintAuthorization(t),
		Target:        mustTarget(t),
		Confirm:       true,
		ProbeBudget:   budget,
		Technique:     authz.TechniqueContentDiscovery,
		Prober:        p,
		Clock:         &advancingClock{t: t, at: mustClock(t).Instant()},
	}
}

func mergeOnly(t *testing.T) inventory.ConfirmConfig {
	t.Helper()
	return inventory.ConfirmConfig{Target: mustTarget(t), Confirm: false}
}

func merge(t *testing.T, cfg inventory.ConfirmConfig, tiers ...[]inventory.Route) *inventory.ConfirmResult {
	t.Helper()
	res, err := inventory.MergeAndConfirm(context.Background(), cfg, mustClock(t), tiers...)
	if err != nil {
		t.Fatalf("inventory.MergeAndConfirm: %v", err)
	}
	return &res
}

// tier0 builds a real Tier 0 result by running the D.18 prober against a
// fetcher that serves the given documents. Nothing here is a hand-built
// struct: DenominatorFloor is only meaningful if the refusals behind it are
// the ones the real parser produced.
type specFetcher struct {
	body map[string]string
}

func (f *specFetcher) FetchSpec(_ context.Context, req inventory.SpecRequest) (inventory.SpecResponse, error) {
	b, ok := f.body[req.Endpoint()]
	if !ok {
		return inventory.SpecResponse{Status: 404}, nil
	}
	return inventory.SpecResponse{
		Status:      200,
		ContentType: "application/json",
		Body:        strings.NewReader(b),
	}, nil
}

func tier0(t *testing.T, endpoints []string, bodies map[string]string) *inventory.Result {
	t.Helper()
	list, err := inventory.NewEndpointList(endpoints)
	if err != nil {
		t.Fatalf("inventory.NewEndpointList: %v", err)
	}
	gov, audit := kernel(t)
	res, err := inventory.ProbeRuntimeSpecs(context.Background(), inventory.Config{
		Governor:      gov,
		Audit:         audit,
		Authorization: mintAuthorization(t),
		Target:        mustTarget(t),
		Endpoints:     list,
		Fetcher:       &specFetcher{body: bodies},
	}, mustClock(t))
	if err != nil && !errors.Is(err, inventory.ErrNothingProbed) {
		t.Fatalf("inventory.ProbeRuntimeSpecs: %v", err)
	}
	return &res
}

func specFile(t *testing.T, uri, body string) inventory.SpecFile {
	t.Helper()
	f, err := inventory.NewSpecFile(inventory.SpecFileFacts{
		Location: rec.ArtifactLocation{URI: uri},
		Content:  rec.ArtifactContent{Text: body},
	})
	if err != nil {
		t.Fatalf("inventory.NewSpecFile(%q): %v", uri, err)
	}
	return f
}

func tier1(t *testing.T, harvest inventory.HarvestOutcome, files ...inventory.SpecFile) *inventory.IngestResult {
	t.Helper()
	res, err := inventory.IngestRepoSpecs(inventory.IngestConfig{
		Target:  mustTarget(t),
		Harvest: harvest,
	}, files)
	if err != nil && !errors.Is(err, inventory.ErrNothingIngested) {
		t.Fatalf("inventory.IngestRepoSpecs: %v", err)
	}
	return &res
}

func sourceFile(t *testing.T, uri, body string) inventory.SourceFile {
	t.Helper()
	f, err := inventory.NewSourceFile(inventory.GoSourceFileFacts{
		Location: rec.ArtifactLocation{URI: uri},
		Content:  rec.ArtifactContent{Text: body},
	})
	if err != nil {
		t.Fatalf("inventory.NewSourceFile(%q): %v", uri, err)
	}
	return f
}

func tier2Other(t *testing.T, harvest inventory.HarvestOutcome, files ...inventory.SourceFile) *inventory.OtherExtractResult {
	t.Helper()
	res, err := inventory.ExtractNonGoRoutes(context.Background(), inventory.OtherExtractConfig{
		Target:  mustTarget(t),
		Harvest: harvest,
	}, files)
	if err != nil {
		t.Fatalf("inventory.ExtractNonGoRoutes: %v", err)
	}
	return &res
}

// openAPI is a minimal served/committed OpenAPI document declaring the given
// GET paths.
func openAPI(paths ...string) string {
	var b strings.Builder
	b.WriteString(`{"openapi":"3.0.0","info":{"title":"f","version":"1"},"paths":{`)
	for i, p := range paths {
		if i > 0 {
			b.WriteString(",")
		}
		fmt.Fprintf(&b, `%q:{"get":{"operationId":"op%d"}}`, p, i)
	}
	b.WriteString(`}}`)
	return b.String()
}

// baseInputs is the standard shape: an incremental scan against a target that
// booted clean under an ephemeral manifest.
func baseInputs(u *inventory.ConfirmResult) Inputs {
	return Inputs{
		Mode:         ScanModeIncremental,
		Union:        u,
		Provenance:   rec.TargetProvenanceBootedClean,
		Provisioning: rec.TargetProvisioningEphemeralManifest,
	}
}

func mustSummarize(t *testing.T, in Inputs) Summary {
	t.Helper()
	s, err := Summarize(in)
	if err != nil {
		t.Fatalf("Summarize: %v", err)
	}
	return s
}

// ---------------------------------------------------------------------------
// The numerator
// ---------------------------------------------------------------------------

// TestEndpointCoverageIsNotARequestCount is plan/50-dast.md:1152 in bold, and
// it is asserted by CONSTRUCTION rather than by reading a doc comment: the
// fixture issues strictly more requests than there are endpoints in the union,
// so any implementation that used the request count would produce a different
// number and this test would name it.
func TestEndpointCoverageIsNotARequestCount(t *testing.T) {
	// Three endpoints, one confirmed, TWO requests issued. The third endpoint
	// is templated and no PathConcretizer is wired, so it stays an honest
	// candidate and is never requested — which is what makes the request
	// count differ from BOTH the numerator and the denominator. A fixture
	// where all three numbers coincide could not tell them apart.
	p := &prober{def: 404, byPath: map[string]int{"/a": 200}}
	u := merge(t, confirming(t, p, 10), []inventory.Route{
		route(t, authz.MethodGet, "/a", "", rec.InventoryProvenanceRuntimeSpec),
		route(t, authz.MethodGet, "/b", "", rec.InventoryProvenanceRepoSpec),
		route(t, authz.MethodGet, "/users/{id}", "", rec.InventoryProvenanceStaticExtraction),
		route(t, authz.MethodGet, "/a", "", rec.InventoryProvenanceRepoSpec),
	})
	s := mustSummarize(t, baseInputs(u))

	if got := s.MergedEndpointCount(); got != 3 {
		t.Fatalf("the union has %d endpoints, want 3 (four routes, two naming /a)", got)
	}
	if got := s.ConfirmedCount(); got != 1 {
		t.Fatalf("%d confirmed, want 1", got)
	}
	if s.RequestsIssued() != 2 {
		t.Fatalf("%d requests issued, want 2. The fixture must issue a DIFFERENT number "+
			"from both the numerator and the denominator or this test cannot tell them "+
			"apart", s.RequestsIssued())
	}
	cov, err := s.Coverage()
	if err != nil {
		t.Fatalf("Coverage: %v", err)
	}
	if cov.ProbedCount != 1 || cov.InventoryUnionCount != 3 {
		t.Fatalf("coverage is %d/%d, want 1/3", cov.ProbedCount, cov.InventoryUnionCount)
	}
	if diff := cov.EndpointCoverage - 1.0/3.0; diff > 1e-9 || diff < -1e-9 {
		t.Fatalf("endpoint_coverage is %v, want 1/3", cov.EndpointCoverage)
	}
	// The two ways a request count could leak in.
	if cov.ProbedCount == p.calls {
		t.Fatalf("ProbedCount equals the number of prober calls (%d). endpoint_coverage's "+
			"numerator is confirmed ENDPOINTS", p.calls)
	}
	if cov.InventoryUnionCount == p.calls {
		t.Fatalf("InventoryUnionCount equals the number of prober calls (%d)", p.calls)
	}
	if err := rec.ValidateDastCoverage(&cov); err != nil {
		t.Fatalf("internal/record's own validator refuses the assembled coverage: %v", err)
	}
}

// TestAConfirmationWithoutAKernelAdmittedObservationNeverReachesTheRecord
// proves the numerator cannot be minted by claiming it. A route that arrives
// already saying "confirmed" is discarded by D.22's merge, and this asserts
// the fact survives all the way into the summary rather than only into D.22.
func TestAConfirmationWithoutAKernelAdmittedObservationNeverReachesTheRecord(t *testing.T) {
	claimed, err := inventory.NewRoute(inventory.RouteFacts{
		Method:       authz.MethodGet,
		Path:         "/claimed",
		Target:       mustTarget(t),
		Provenance:   rec.InventoryProvenanceRepoSpec,
		Confirmation: inventory.ConfirmationConfirmed,
		Trust:        rec.TrustUntrusted,
	})
	if err != nil {
		t.Fatalf("inventory.NewRoute: %v", err)
	}
	// Merge only: nothing is probed, so nothing can honestly be confirmed.
	u := merge(t, mergeOnly(t), []inventory.Route{claimed})
	s := mustSummarize(t, baseInputs(u))

	if s.ConfirmedCount() != 0 {
		t.Fatalf("%d confirmed endpoints from a run that issued %d requests. "+
			"plan/50-dast.md:632-635 calls Tier 1 routes confirmed and that is OVERRIDDEN: "+
			"only an observation Anvil made through the kernel confirms an endpoint",
			s.ConfirmedCount(), s.RequestsIssued())
	}
	if s.Determinacy() != DeterminacyUnknown {
		t.Fatalf("determinacy is %q, want %q: nothing was ever probed, so a numerator of "+
			"zero is a fact about Anvil", s.Determinacy(), DeterminacyUnknown)
	}
	if _, err := s.Coverage(); !errors.Is(err, ErrCoverageNotComputable) {
		t.Fatalf("Coverage returned %v, want ErrCoverageNotComputable", err)
	}
}

// ---------------------------------------------------------------------------
// Zero versus unknown — the fact this packet exists to keep apart
// ---------------------------------------------------------------------------

// TestZeroCoverageAndUnknownCoverageAreDifferentFacts drives the two runs that
// both render as "0.0" and asserts they are distinguishable BY CONSTRUCTION
// rather than by a comment.
func TestZeroCoverageAndUnknownCoverageAreDifferentFacts(t *testing.T) {
	// The routes come from a real Tier 1 ingest, so the summary has the tier
	// facts it needs to call itself a measurement at all.
	t1 := func() *inventory.IngestResult {
		return tier1(t, inventory.HarvestRan, specFile(t, "file:///s.json", openAPI("/a", "/b")))
	}
	withTier := func(u *inventory.ConfirmResult, r *inventory.IngestResult) Inputs {
		in := baseInputs(u)
		in.Tier1 = r
		return in
	}

	// A: the target answered every probe with 404. Nothing confirmed, and
	// that is a MEASUREMENT: this application serves neither path.
	ta := t1()
	answered := mustSummarize(t, withTier(
		merge(t, confirming(t, &prober{def: 404}, 10), ta.Routes()), ta))

	// B: confirmation was never wired. Byte-identical numerator.
	tb := t1()
	unwired := mustSummarize(t, withTier(merge(t, mergeOnly(t), tb.Routes()), tb))

	if answered.ConfirmedCount() != 0 || unwired.ConfirmedCount() != 0 {
		t.Fatalf("the fixture is wrong: both runs must have a zero numerator, got %d and %d",
			answered.ConfirmedCount(), unwired.ConfirmedCount())
	}
	if answered.InventoryUnionCount() != unwired.InventoryUnionCount() {
		t.Fatalf("the fixture is wrong: both runs must have the same denominator, got %d and %d",
			answered.InventoryUnionCount(), unwired.InventoryUnionCount())
	}

	if answered.Determinacy() != DeterminacyMeasured {
		t.Fatalf("the answered run is %q, want %q. The target answered %d probe(s); zero "+
			"confirmations there is a real finding about the application",
			answered.Determinacy(), DeterminacyMeasured, answered.TargetAnswered())
	}
	cov, err := answered.Coverage()
	if err != nil {
		t.Fatalf("the answered run must publish a fraction: %v", err)
	}
	if cov.EndpointCoverage != 0 || cov.ProbedCount != 0 || cov.InventoryUnionCount != 2 {
		t.Fatalf("the answered run is %v (%d/%d), want 0.0 (0/2)",
			cov.EndpointCoverage, cov.ProbedCount, cov.InventoryUnionCount)
	}

	if unwired.Determinacy() != DeterminacyUnknown {
		t.Fatalf("the unwired run is %q, want %q", unwired.Determinacy(), DeterminacyUnknown)
	}
	if _, err := unwired.Coverage(); !errors.Is(err, ErrCoverageNotComputable) {
		t.Fatalf("the unwired run returned %v, want ErrCoverageNotComputable. Emitting 0.0 "+
			"here would tell an operator the surface was probed and found unconfirmable",
			err)
	}

	// The distinguishing fact must survive a naive equality check, which is
	// how a downstream consumer will actually compare them.
	if answered.Determinacy() == unwired.Determinacy() {
		t.Fatal("the two runs report the same Determinacy")
	}
	if reflect.DeepEqual(answered.Qualifiers(), unwired.Qualifiers()) {
		t.Fatal("the two runs report the same qualifiers")
	}
}

// TestAManifestAbsentRunIsNeverEqualComparableToACleanRun is D.26's stated
// validation clause. It checks BOTH halves: the coverage summary and the
// audit-level status the summary derives.
func TestAManifestAbsentRunIsNeverEqualComparableToACleanRun(t *testing.T) {
	// The skip: no manifest, so no inventory was ever built.
	skipped, err := Summarize(Inputs{
		Mode:       ScanModeIncremental,
		Union:      nil,
		Provenance: rec.TargetProvenanceNoTargetDeclared,
		// Provisioning omitted: record.TargetProvisioning has two literals
		// and both assert a target existed.
	})
	if err != nil {
		t.Fatalf("Summarize(skip): %v", err)
	}
	if _, ok := skipped.Provisioning(); ok {
		t.Fatal("a no-manifest skip named a provisioning path. Both literals assert a " +
			"target existed; the field must be omitted")
	}

	// The clean run: everything in the union confirmed, with the tier facts
	// that let the summary call itself a measurement.
	t1 := tier1(t, inventory.HarvestRan, specFile(t, "file:///s.json", openAPI("/a")))
	cleanIn := baseInputs(merge(t, confirming(t, &prober{def: 200}, 10), t1.Routes()))
	cleanIn.Tier1 = t1
	clean := mustSummarize(t, cleanIn)
	if clean.ConfirmedCount() != 1 || clean.InventoryUnionCount() != 1 {
		t.Fatalf("the clean fixture is %d/%d, want 1/1",
			clean.ConfirmedCount(), clean.InventoryUnionCount())
	}
	if clean.PartialCoverage() {
		t.Fatalf("a fully covered run reports PartialCoverage: %s", clean)
	}

	skipStatus, err := skipped.DeriveDastStatus(true, rec.HalfStatusSkipped, 0)
	if err != nil {
		t.Fatalf("DeriveDastStatus(skip): %v", err)
	}
	cleanStatus, err := clean.DeriveDastStatus(true, rec.HalfStatusSealed, 0)
	if err != nil {
		t.Fatalf("DeriveDastStatus(clean): %v", err)
	}
	if skipStatus != rec.DastStatusSkippedNoManifest {
		t.Fatalf("the skip derived %q, want %q", skipStatus, rec.DastStatusSkippedNoManifest)
	}
	if cleanStatus != rec.DastStatusCompletedClean {
		t.Fatalf("the clean run derived %q, want %q", cleanStatus, rec.DastStatusCompletedClean)
	}
	if skipStatus == cleanStatus {
		t.Fatal("a manifest-absent skip and a clean run derived the same anvil/dastStatus")
	}
	if skipStatus.MeansDynamicallyScannedClean() {
		t.Fatalf("%q reports itself as dynamically scanned clean", skipStatus)
	}

	// The equality a naive consumer actually writes.
	if reflect.DeepEqual(skipped, clean) {
		t.Fatal("the two summaries are DeepEqual")
	}
	if _, err := skipped.Coverage(); !errors.Is(err, ErrCoverageNotComputable) {
		t.Fatalf("the skip produced a coverage fraction (%v)", err)
	}
}

// TestATargetThatNeverBootedCannotDeriveClean pins the ordering that makes
// exit criterion 2 hold, from this package's side of it.
func TestATargetThatNeverBootedCannotDeriveClean(t *testing.T) {
	for _, prov := range []rec.TargetProvenance{
		rec.TargetProvenanceBootFailed,
		rec.TargetProvenanceBuildFailed,
		rec.TargetProvenanceUnreachableAtScanTime,
	} {
		s, err := Summarize(Inputs{
			Mode:       ScanModeIncremental,
			Union:      nil,
			Provenance: prov,
		})
		if err != nil {
			t.Fatalf("Summarize(%s): %v", prov, err)
		}
		// A sealed half with zero findings is the exact shape that used to
		// read as clean.
		got, err := s.DeriveDastStatus(true, rec.HalfStatusSealed, 0)
		if err != nil {
			t.Fatalf("DeriveDastStatus(%s): %v", prov, err)
		}
		if got.MeansDynamicallyScannedClean() {
			t.Fatalf("provenance %q with a sealed, findingless half derived %q", prov, got)
		}
		if got == rec.DastStatusSkippedNoManifest {
			t.Fatalf("provenance %q derived %q, which says no manifest was declared", prov, got)
		}
	}
}

// ---------------------------------------------------------------------------
// The denominator
// ---------------------------------------------------------------------------

// TestTheDenominatorAddsSurfaceATierSawAndCouldNotRepresent drives a real Tier
// 1 ingest whose document declares an operation the tier refuses, and asserts
// the refusal RAISES the denominator rather than vanishing.
//
// The count is asserted exactly. A len(x) > 0 check here would pass an
// implementation that added one row where three were required.
func TestTheDenominatorAddsSurfaceATierSawAndCouldNotRepresent(t *testing.T) {
	// TRACE is not on the method allowlist, so the tier sees the operation
	// and cannot represent it: a per-operation refusal.
	doc := `{"openapi":"3.0.0","info":{"title":"f","version":"1"},"paths":{` +
		`"/a":{"get":{"operationId":"a"},"trace":{"operationId":"t"}},` +
		`"/b":{"get":{"operationId":"b"}}}}`
	t1 := tier1(t, inventory.HarvestRan, specFile(t, "file:///spec.json", doc))

	routes := t1.Routes()
	floor := t1.DenominatorFloor()
	if len(routes) != 2 {
		t.Fatalf("the fixture produced %d routes, want 2: %v", len(routes), routes)
	}
	if floor != 3 {
		t.Fatalf("the fixture's DenominatorFloor is %d, want 3 (two routes plus one "+
			"per-operation refusal). Without a refusal this test cannot see the damage",
			floor)
	}

	u := merge(t, confirming(t, &prober{def: 200}, 10), routes)
	in := baseInputs(u)
	in.Tier1 = t1
	s := mustSummarize(t, in)

	if s.MergedEndpointCount() != 2 {
		t.Fatalf("%d merged endpoints, want 2", s.MergedEndpointCount())
	}
	if s.UnrepresentedCount() != 1 {
		t.Fatalf("%d unrepresented endpoints, want 1", s.UnrepresentedCount())
	}
	if s.InventoryUnionCount() != 3 {
		t.Fatalf("the denominator is %d, want 3. Publishing the merge alone (%d) would go "+
			"BELOW Tier 1's own DenominatorFloor of %d, and a denominator below its floor "+
			"is the shrink that makes coverage look better for free",
			s.InventoryUnionCount(), s.MergedEndpointCount(), floor)
	}
	if s.InventoryUnionCount() < floor {
		t.Fatalf("the denominator %d is below Tier 1's floor %d", s.InventoryUnionCount(), floor)
	}
	cov, err := s.Coverage()
	if err != nil {
		t.Fatalf("Coverage: %v", err)
	}
	if cov.ProbedCount != 2 || cov.InventoryUnionCount != 3 {
		t.Fatalf("coverage is %d/%d, want 2/3", cov.ProbedCount, cov.InventoryUnionCount)
	}
	if cov.CandidateCount != 1 {
		t.Fatalf("CandidateCount is %d, want 1: the unrepresented endpoint was certainly "+
			"not confirmed", cov.CandidateCount)
	}
	if err := s.AssertDenominatorDecomposes(); err != nil {
		t.Fatalf("AssertDenominatorDecomposes: %v", err)
	}

	// The decomposition an operator needs to take the number apart.
	var seen bool
	for _, c := range s.TierContributions() {
		if c.Tier != TierRepoSpec {
			continue
		}
		seen = true
		if !c.Ran || c.Routes != 2 || c.Floor != 3 || c.Unrepresented != 1 {
			t.Fatalf("the Tier 1 contribution is %+v, want {Ran:true Routes:2 Floor:3 "+
				"Unrepresented:1}", c)
		}
	}
	if !seen {
		t.Fatal("the denominator does not decompose to a Tier 1 contribution")
	}
	// A tier that did not run is visible as such, not as a tier that found
	// nothing.
	for _, c := range s.TierContributions() {
		if c.Tier == TierRuntimeSpec && c.Ran {
			t.Fatal("Tier 0 did not run and the summary says it did")
		}
	}
}

// TestDuplicateEndpointsAcrossTiersDoNotInflateTheDenominator is the direction
// nobody investigates: an inflated denominator makes coverage look WORSE, so
// nothing flags it. One address is fed in from three tiers under three
// spellings and must be ONE row with THREE provenances.
func TestDuplicateEndpointsAcrossTiersDoNotInflateTheDenominator(t *testing.T) {
	u := merge(t, confirming(t, &prober{def: 200}, 10),
		[]inventory.Route{route(t, authz.MethodGet, "/users/{id}", "", rec.InventoryProvenanceRuntimeSpec)},
		[]inventory.Route{route(t, authz.MethodGet, "/users/:id", "", rec.InventoryProvenanceRepoSpec)},
		[]inventory.Route{route(t, authz.MethodGet, "/users/{id:[0-9]+}", "", rec.InventoryProvenanceStaticExtraction)},
	)
	s := mustSummarize(t, baseInputs(u))

	if s.MergedEndpointCount() != 1 {
		t.Fatalf("three spellings of one address produced %d endpoints, want 1. Counting "+
			"them separately would report %v coverage instead of 1.0",
			s.MergedEndpointCount(), float64(s.ConfirmedCount())/float64(s.MergedEndpointCount()))
	}
	if s.InventoryUnionCount() != 1 {
		t.Fatalf("the denominator is %d, want 1", s.InventoryUnionCount())
	}
	rows := s.Rows()
	if len(rows) != 3 {
		t.Fatalf("%d provenance rows, want 3 — one per tier that named the address", len(rows))
	}
	mix := s.ProvenanceMix()
	for _, p := range []rec.InventoryProvenance{
		rec.InventoryProvenanceRuntimeSpec,
		rec.InventoryProvenanceRepoSpec,
		rec.InventoryProvenanceStaticExtraction,
	} {
		if mix[p] != 1 {
			t.Fatalf("the mix says %d endpoint(s) under %q, want 1", mix[p], p)
		}
	}
	if mix[rec.InventoryProvenanceCrawl] != 0 {
		t.Fatalf("the mix invented %d crawl endpoint(s)", mix[rec.InventoryProvenanceCrawl])
	}
	// The mix sums to more than the denominator, on purpose.
	total := 0
	for _, v := range mix {
		total += v
	}
	if total != 3 {
		t.Fatalf("the mix sums to %d, want 3", total)
	}
	if total == s.InventoryUnionCount() {
		t.Fatal("the mix sums to the denominator, so it is a partition. An endpoint named " +
			"by three tiers must count once under each")
	}
}

// TestAnUnsupportedLanguageQualifiesTheNumberRatherThanShrinkingTheDenominator
// is D.21's handoff. A repository with PHP in it hides an unknown number of
// endpoints; the fraction must say so.
func TestAnUnsupportedLanguageQualifiesTheNumberRatherThanShrinkingTheDenominator(t *testing.T) {
	other := tier2Other(t, inventory.HarvestRan,
		sourceFile(t, "file:///app/routes.php", "<?php Route::get('/admin', 'C@a');"),
		sourceFile(t, "file:///app/server.js",
			"const app = require('express')();\napp.get('/metrics', h);\n"))
	if len(other.UnsupportedLanguages()) != 1 {
		t.Fatalf("the fixture reports %d unsupported language(s), want 1. Without one this "+
			"test cannot see the damage", len(other.UnsupportedLanguages()))
	}
	if got, want := other.DenominatorFloor(), len(other.Routes()); got != want {
		t.Fatalf("D.21's floor is %d and it extracted %d route(s): the unsupported "+
			"language moved the floor. It hides an UNKNOWN number of endpoints and must "+
			"add nothing to any floor — calling that number one is an understatement "+
			"wearing the costume of a measurement", got, want)
	}

	// The same tier also reads a language it DOES support, so the union is
	// non-empty and every offered route is accounted for by a tier result.
	if len(other.Routes()) != 1 {
		t.Fatalf("the fixture produced %d route(s), want 1 (the JS file's): %v",
			len(other.Routes()), other.Routes())
	}
	u := merge(t, confirming(t, &prober{def: 200}, 10), other.Routes())
	in := baseInputs(u)
	in.Tier2Other = other
	s := mustSummarize(t, in)

	var q *Qualifier
	for i := range s.Qualifiers() {
		if got := s.Qualifiers()[i]; got.Reason == QualifierUnsupportedLanguage {
			q = &got
		}
	}
	if q == nil {
		t.Fatalf("no unsupported-language qualifier. The summary is: %s\nqualifiers: %v",
			s, s.Qualifiers())
	}
	if q.Direction() != DirectionOverstates {
		t.Fatalf("the qualifier's direction is %q, want %q: a denominator missing a "+
			"language's endpoints makes the fraction read HIGHER than the truth",
			q.Direction(), DirectionOverstates)
	}
	if q.Count != 1 {
		t.Fatalf("the qualifier counts %d language(s), want 1", q.Count)
	}
	if q.MagnitudeKnown() {
		t.Fatal("the qualifier claims a known magnitude. Count is the number of LANGUAGES; " +
			"the number of hidden endpoints is exactly what nobody knows")
	}
	if s.Determinacy() != DeterminacyQualified {
		t.Fatalf("determinacy is %q, want %q", s.Determinacy(), DeterminacyQualified)
	}
	// A qualified number is still publishable, and it is still partial.
	if _, err := s.Coverage(); err != nil {
		t.Fatalf("a qualified summary refused to publish a fraction: %v", err)
	}
	if !s.PartialCoverage() {
		t.Fatal("a summary with a known-incomplete denominator reports full coverage")
	}
}

// TestBudgetExhaustionUnderstatesAndSaysSo is research/22's Risk #4: a bigger
// candidate list exhausting the budget produces LOWER coverage than a smaller
// one. Publishing that fraction as though every candidate had been asked is
// the failure; this is the line of code that refuses to.
func TestBudgetExhaustionUnderstatesAndSaysSo(t *testing.T) {
	var routes []inventory.Route
	for i := 0; i < 6; i++ {
		routes = append(routes, route(t, authz.MethodGet, fmt.Sprintf("/p%d", i), "",
			rec.InventoryProvenanceRepoSpec))
	}
	u := merge(t, confirming(t, &prober{def: 200}, 2), routes)
	s := mustSummarize(t, baseInputs(u))

	if s.MergedEndpointCount() != 6 {
		t.Fatalf("%d endpoints, want 6", s.MergedEndpointCount())
	}
	if s.RequestsIssued() != 2 {
		t.Fatalf("%d requests issued, want 2 (the configured budget)", s.RequestsIssued())
	}
	var q *Qualifier
	for i := range s.Qualifiers() {
		if got := s.Qualifiers()[i]; got.Reason == QualifierProbeBudgetExhausted {
			q = &got
		}
	}
	if q == nil {
		t.Fatalf("no budget qualifier on a run that starved %d of %d endpoints. %s",
			s.MergedEndpointCount()-s.RequestsIssued(), s.MergedEndpointCount(), s)
	}
	if q.Direction() != DirectionUnderstates {
		t.Fatalf("the budget qualifier's direction is %q, want %q", q.Direction(),
			DirectionUnderstates)
	}
	if q.Count != 4 {
		t.Fatalf("the budget qualifier counts %d starved endpoint(s), want 4", q.Count)
	}
	if s.Determinacy() != DeterminacyQualified {
		t.Fatalf("determinacy is %q, want %q", s.Determinacy(), DeterminacyQualified)
	}
}

// TestOperationsCollapsedOntoOneAddressIsReportedNotPricedIn is the GraphQL
// deflation D.22 hands over as OperationCount(), and this test pins BOTH
// halves of the decision: the operation count never becomes the denominator,
// and the collapse is never silent.
func TestOperationsCollapsedOntoOneAddressIsReportedNotPricedIn(t *testing.T) {
	var routes []inventory.Route
	ops := []string{"createUser", "deleteUser", "listUsers", "updateUser"}
	for _, op := range ops {
		routes = append(routes, route(t, authz.MethodGet, "/graphql", op,
			rec.InventoryProvenanceRuntimeSpec))
	}
	u := merge(t, confirming(t, &prober{def: 200}, 10), routes)
	s := mustSummarize(t, baseInputs(u))

	if s.MergedEndpointCount() != 1 {
		t.Fatalf("%d endpoints, want 1: four operations share one address",
			s.MergedEndpointCount())
	}
	if s.OperationCount() != 4 {
		t.Fatalf("%d operations, want 4", s.OperationCount())
	}
	cov, err := s.Coverage()
	if err != nil {
		t.Fatalf("Coverage: %v", err)
	}
	if cov.InventoryUnionCount != 1 {
		t.Fatalf("the denominator is %d, want 1. Substituting the operation count would "+
			"divide confirmed ENDPOINTS by OPERATIONS, which is not a smaller fraction but "+
			"a type error", cov.InventoryUnionCount)
	}
	if cov.InventoryUnionCount == s.OperationCount() {
		t.Fatal("the operation count became the denominator")
	}
	var q *Qualifier
	for i := range s.Qualifiers() {
		if got := s.Qualifiers()[i]; got.Reason == QualifierOperationsCollapsed {
			q = &got
		}
	}
	if q == nil {
		t.Fatalf("four operations collapsed onto one address and nothing said so. %s", s)
	}
	if q.Direction() != DirectionOverstates {
		t.Fatalf("the collapse qualifier's direction is %q, want %q", q.Direction(),
			DirectionOverstates)
	}
	if q.Count != 3 {
		t.Fatalf("the collapse qualifier counts %d, want 3 (4 operations - 1 address)", q.Count)
	}
	if !strings.Contains(q.Detail, "4 operation(s) share 1 address(es)") {
		t.Fatalf("the qualifier does not carry both numbers: %q", q.Detail)
	}
	// The operations survive into the rows, so the collapse is decomposable.
	rows := s.Rows()
	if len(rows) != 1 {
		t.Fatalf("%d rows, want 1", len(rows))
	}
	if !reflect.DeepEqual(rows[0].Operations, ops) {
		t.Fatalf("the row carries operations %v, want %v", rows[0].Operations, ops)
	}
}

// TestATruncatedTierQualifiesTheNumber, positive control.
//
// D.18/D.19's own suites prove a tier SETS Truncated() at its coded bound.
// They do not prove D.26 consumes it, and an unconsumed flag is the shrink
// that makes coverage look better for free: the routes past the bound are
// missing from the denominator entirely. So the bound is actually reached
// here, from a repo spec declaring more paths than maxRoutesPerSpec.
func TestATruncatedTierRaisesTheTruncationQualifier(t *testing.T) {
	// maxRoutesPerSpec is 10000 and maxSpecFileBytes is 4 MiB; 10010 short
	// paths is roughly 350 KB, so the route bound is what stops this and not
	// the byte bound.
	paths := make([]string, 0, 10010)
	for i := 0; i < 10010; i++ {
		paths = append(paths, fmt.Sprintf("/p%d", i))
	}
	t1 := tier1(t, inventory.HarvestRan, specFile(t, "file:///big.json", openAPI(paths...)))
	if !t1.Truncated() {
		t.Fatalf("a %d-path document was not reported truncated; the fixture no longer "+
			"reaches the coded bound and this control is measuring nothing", len(paths))
	}
	u := merge(t, mergeOnly(t), t1.Routes())
	in := baseInputs(u)
	in.Tier1 = t1
	s := mustSummarize(t, in)

	var q *Qualifier
	for i := range s.Qualifiers() {
		if got := s.Qualifiers()[i]; got.Reason == QualifierTierTruncated {
			q = &got
		}
	}
	if q == nil {
		t.Fatalf("a truncated tier produced no truncation qualifier. Its routes past the "+
			"bound are absent from the denominator, which makes coverage look better. %v",
			s.Qualifiers())
	}
	if q.Direction() != DirectionOverstates {
		t.Fatalf("the truncation direction is %q, want %q", q.Direction(), DirectionOverstates)
	}
	if !strings.Contains(q.Detail, string(TierRepoSpec)) {
		t.Fatalf("the qualifier does not name the tier: %q", q.Detail)
	}
	if q.MagnitudeKnown() {
		t.Fatal("the qualifier claims a known magnitude; how many routes were dropped past " +
			"the bound is exactly what the tier stopped counting")
	}
	if s.MergedEndpointCount() != 10000 {
		t.Fatalf("%d endpoints merged, want 10000 (the coded bound)", s.MergedEndpointCount())
	}
}

// TestATruncatedTierQualifiesTheNumber is the NEGATIVE control for the same
// qualifier: an untruncated tier must produce none, or a qualifier that fires
// on everything carries no information.
func TestATruncatedTierQualifiesTheNumber(t *testing.T) {
	// A repo spec whose declared operations exceed nothing is not truncated;
	// this asserts the CLEAN case so the qualifier's absence is measured
	// rather than assumed, and the positive control lives in D.18/D.19's own
	// suites where the bound is reachable.
	t1 := tier1(t, inventory.HarvestRan, specFile(t, "file:///s.json", openAPI("/a", "/b")))
	if t1.Truncated() {
		t.Fatal("the fixture truncated; it is meant to be the clean control")
	}
	u := merge(t, confirming(t, &prober{def: 200}, 10), t1.Routes())
	in := baseInputs(u)
	in.Tier1 = t1
	s := mustSummarize(t, in)
	for _, q := range s.Qualifiers() {
		if q.Reason == QualifierTierTruncated {
			t.Fatalf("an untruncated tier produced a truncation qualifier: %s", q)
		}
	}
	if s.Determinacy() != DeterminacyMeasured {
		t.Fatalf("determinacy is %q, want %q. %s", s.Determinacy(), DeterminacyMeasured, s)
	}
}

// TestATierWhoseHandoffWasNeverWiredQualifiesTheNumber: a tier that ran
// against nothing contributes an empty share of the denominator, and that
// emptiness is a fact about Anvil rather than about the target.
func TestATierWhoseHandoffWasNeverWiredQualifiesTheNumber(t *testing.T) {
	t1 := tier1(t, inventory.HarvestSkipped)
	if err := t1.AssertNotSilentlyEmpty(); err == nil {
		t.Fatal("the fixture's Tier 1 result reports itself legitimately empty; without a " +
			"refusal this test cannot see the damage")
	}
	t0 := tier0(t, []string{"/openapi.json"},
		map[string]string{"/openapi.json": openAPI("/a")})
	if len(t0.Routes()) != 1 {
		t.Fatalf("Tier 0 produced %d routes, want 1", len(t0.Routes()))
	}
	u := merge(t, confirming(t, &prober{def: 200}, 10), t0.Routes())
	in := baseInputs(u)
	in.Tier0 = t0
	in.Tier1 = t1
	s := mustSummarize(t, in)

	var found bool
	for _, q := range s.Qualifiers() {
		if q.Reason == QualifierTierHandoffUnwired {
			found = true
			if q.Direction() != DirectionOverstates {
				t.Fatalf("the unwired-handoff direction is %q, want %q", q.Direction(),
					DirectionOverstates)
			}
			if !strings.Contains(q.Detail, string(TierRepoSpec)) {
				t.Fatalf("the qualifier does not name the tier: %q", q.Detail)
			}
		}
	}
	if !found {
		t.Fatalf("a tier whose harvest never ran produced no qualifier. %s", s)
	}
	if s.Determinacy() != DeterminacyQualified {
		t.Fatalf("determinacy is %q, want %q", s.Determinacy(), DeterminacyQualified)
	}
}

// TestTierResultsThatDidNotProduceTheUnionAreRefused is the wiring check. The
// unrepresented-surface arithmetic is only sound if the tier route lists are
// exactly what the merge consumed.
func TestTierResultsThatDidNotProduceTheUnionAreRefused(t *testing.T) {
	t1 := tier1(t, inventory.HarvestRan, specFile(t, "file:///s.json", openAPI("/a", "/b")))
	if len(t1.Routes()) != 2 {
		t.Fatalf("the fixture produced %d routes, want 2", len(t1.Routes()))
	}
	// The union is built from ONE of the two routes.
	u := merge(t, confirming(t, &prober{def: 200}, 10), t1.Routes()[:1])
	in := baseInputs(u)
	in.Tier1 = t1
	if _, err := Summarize(in); !errors.Is(err, ErrTiersNotMerged) {
		t.Fatalf("Summarize returned %v, want ErrTiersNotMerged. Left unchecked, the "+
			"denominator would be assembled from two different runs", err)
	}
	// And the matching case is accepted, so the check is not simply always on.
	in.Tier1 = tier1(t, inventory.HarvestRan, specFile(t, "file:///s.json", openAPI("/a")))
	if _, err := Summarize(in); err != nil {
		t.Fatalf("a consistent pairing was refused: %v", err)
	}
}

// TestAnUnsealedTierResultIsRefused: a composite literal reports zero routes
// and a zero floor, which shrinks the denominator.
func TestAnUnsealedTierResultIsRefused(t *testing.T) {
	u := merge(t, mergeOnly(t))
	in := baseInputs(u)
	in.Tier2Go = &inventory.ExtractResult{}
	if _, err := Summarize(in); !errors.Is(err, ErrUnconstructed) {
		t.Fatalf("Summarize returned %v, want ErrUnconstructed", err)
	}
	in.Tier2Go = nil
	in.Union = &inventory.ConfirmResult{}
	if _, err := Summarize(in); !errors.Is(err, ErrUnconstructed) {
		t.Fatalf("Summarize returned %v for an unsealed union, want ErrUnconstructed", err)
	}
}

// ---------------------------------------------------------------------------
// server_line_coverage — null is not zero
// ---------------------------------------------------------------------------

func f64(v float64) *float64 { return &v }

// TestServerLineCoverageIsNullOnIncrementalScansAndNotZero is the whole reason
// the field is a pointer.
func TestServerLineCoverageIsNullOnIncrementalScansAndNotZero(t *testing.T) {
	u := merge(t, confirming(t, &prober{def: 200}, 10),
		[]inventory.Route{route(t, authz.MethodGet, "/a", "", rec.InventoryProvenanceRuntimeSpec)})

	inc := mustSummarize(t, baseInputs(u))
	if inc.ServerLineCoverageMeasured() {
		t.Fatal("an incremental scan reports a server-line measurement")
	}
	if inc.ServerLineCoverage() != nil {
		t.Fatalf("an incremental scan's server_line_coverage is %v, want nil",
			*inc.ServerLineCoverage())
	}
	cov, err := inc.Coverage()
	if err != nil {
		t.Fatalf("Coverage: %v", err)
	}
	if cov.ServerLineCoverage != nil {
		t.Fatalf("the record carries server_line_coverage %v on an incremental scan; NULL "+
			"is the only correct value and 0 would read as \"we measured and covered "+
			"nothing\"", *cov.ServerLineCoverage)
	}

	// A full scan with a MEASURED ZERO. This is the case that collapsing the
	// pointer destroys: it is a real measurement whose value is 0.
	full := baseInputs(u)
	full.Mode = ScanModeScheduledFull
	full.ServerLineCoverage = f64(0)
	fs := mustSummarize(t, full)
	if !fs.ServerLineCoverageMeasured() {
		t.Fatal("a measured zero reports itself unmeasured")
	}
	p := fs.ServerLineCoverage()
	if p == nil || *p != 0 {
		t.Fatalf("the measured zero is %v, want a non-nil 0", p)
	}
	fcov, err := fs.Coverage()
	if err != nil {
		t.Fatalf("Coverage: %v", err)
	}
	if fcov.ServerLineCoverage == nil || *fcov.ServerLineCoverage != 0 {
		t.Fatalf("the record dropped the measured zero: %v", fcov.ServerLineCoverage)
	}
	// The two must be distinguishable, which is the point of the whole field.
	if (cov.ServerLineCoverage == nil) == (fcov.ServerLineCoverage == nil) {
		t.Fatal("an unmeasured incremental scan and a measured zero are indistinguishable")
	}

	// A full scan whose coverage agent did not run is still NULL.
	full.ServerLineCoverage = nil
	ns := mustSummarize(t, full)
	if ns.ServerLineCoverageMeasured() {
		t.Fatal("a full scan with no agent reports a measurement")
	}
}

// TestAnIncrementalScanCarryingLineCoverageIsRefused: dropping the value
// silently and keeping it are both wrong, so the caller decides.
func TestAnIncrementalScanCarryingLineCoverageIsRefused(t *testing.T) {
	u := merge(t, mergeOnly(t))
	in := baseInputs(u)
	in.ServerLineCoverage = f64(0.83)
	_, err := Summarize(in)
	if !errors.Is(err, ErrRefused) {
		t.Fatalf("Summarize returned %v, want ErrRefused", err)
	}
	if !strings.Contains(err.Error(), "scheduled full scans only") {
		t.Fatalf("the refusal does not say why: %v", err)
	}
	// And the same value on a full scan is accepted, so the guard is not
	// simply always on.
	in.Mode = ScanModeScheduledFull
	s, err := Summarize(in)
	if err != nil {
		t.Fatalf("a full scan refused a legal server_line_coverage: %v", err)
	}
	if p := s.ServerLineCoverage(); p == nil || *p != 0.83 {
		t.Fatalf("the full scan's value is %v, want 0.83", p)
	}
}

// TestAnOutOfRangeServerLineCoverageIsRefused pins the [0,1] bound and the
// non-finite cases, because record.ValidateDastCoverage would otherwise catch
// them only at the record boundary.
func TestAnOutOfRangeServerLineCoverageIsRefused(t *testing.T) {
	u := merge(t, mergeOnly(t))
	for _, v := range []float64{-0.001, 1.001, 42} {
		in := baseInputs(u)
		in.Mode = ScanModeScheduledFull
		in.ServerLineCoverage = f64(v)
		if _, err := Summarize(in); !errors.Is(err, ErrRefused) {
			t.Fatalf("Summarize accepted server_line_coverage %v (%v)", v, err)
		}
	}
	// The two boundary values are legal.
	for _, v := range []float64{0, 1} {
		in := baseInputs(u)
		in.Mode = ScanModeScheduledFull
		in.ServerLineCoverage = f64(v)
		if _, err := Summarize(in); err != nil {
			t.Fatalf("Summarize refused the legal boundary value %v: %v", v, err)
		}
	}
}

// TestTheReturnedServerLineCoverageIsACopy: a caller must not be able to reach
// back through the pointer and change what the summary says. This is the
// mutation that a test asserting only on the value would miss.
func TestTheReturnedServerLineCoverageIsACopy(t *testing.T) {
	u := merge(t, mergeOnly(t))
	in := baseInputs(u)
	in.Mode = ScanModeScheduledFull
	v := 0.5
	in.ServerLineCoverage = &v
	s := mustSummarize(t, in)

	// Mutating the INPUT the caller still holds.
	v = 0.99
	if got := s.ServerLineCoverage(); got == nil || *got != 0.5 {
		t.Fatalf("mutating the caller's variable changed the summary to %v", got)
	}
	// Mutating the RETURNED pointer.
	p := s.ServerLineCoverage()
	*p = 0.01
	if got := s.ServerLineCoverage(); *got != 0.5 {
		t.Fatalf("mutating the returned pointer changed the summary to %v", *got)
	}
}

// ---------------------------------------------------------------------------
// The aggregate must decompose
// ---------------------------------------------------------------------------

// TestTheProvenanceSummaryDecomposesIntoItsRows is what makes the SAST->DAST
// handoff auditable. A summary nobody can take apart is a claim, not evidence.
func TestTheProvenanceSummaryDecomposesIntoItsRows(t *testing.T) {
	p := &prober{def: 404, byPath: map[string]int{"/spec-a": 200, "/repo-a": 200}}
	u := merge(t, confirming(t, p, 20),
		[]inventory.Route{
			route(t, authz.MethodGet, "/spec-a", "", rec.InventoryProvenanceRuntimeSpec),
			route(t, authz.MethodGet, "/spec-b", "", rec.InventoryProvenanceRuntimeSpec),
		},
		[]inventory.Route{
			route(t, authz.MethodGet, "/repo-a", "", rec.InventoryProvenanceRepoSpec),
			route(t, authz.MethodGet, "/spec-a", "", rec.InventoryProvenanceRepoSpec),
		},
		[]inventory.Route{
			route(t, authz.MethodGet, "/static-a", "", rec.InventoryProvenanceStaticExtraction),
		},
	)
	s := mustSummarize(t, baseInputs(u))

	if s.MergedEndpointCount() != 4 {
		t.Fatalf("%d endpoints, want 4 (/spec-a /spec-b /repo-a /static-a)",
			s.MergedEndpointCount())
	}
	if s.ConfirmedCount() != 2 {
		t.Fatalf("%d confirmed, want 2", s.ConfirmedCount())
	}
	if err := s.AssertMixDecomposes(); err != nil {
		t.Fatalf("AssertMixDecomposes: %v", err)
	}

	// The whole mix, asserted as a table rather than as a length.
	wantMix := map[rec.InventoryProvenance]int{
		rec.InventoryProvenanceRuntimeSpec:      2,
		rec.InventoryProvenanceRepoSpec:         2,
		rec.InventoryProvenanceStaticExtraction: 1,
	}
	for _, prov := range rec.InventoryProvenanceValues() {
		if s.ProvenanceMix()[prov] != wantMix[prov] {
			t.Fatalf("the mix says %d under %q, want %d",
				s.ProvenanceMix()[prov], prov, wantMix[prov])
		}
	}

	// The number that audits the handoff: static_extraction contributed one
	// candidate and zero confirmations.
	wantConfirmed := map[rec.InventoryProvenance]int{
		rec.InventoryProvenanceRuntimeSpec: 1,
		rec.InventoryProvenanceRepoSpec:    2,
	}
	for _, prov := range rec.InventoryProvenanceValues() {
		if s.ConfirmedProvenanceMix()[prov] != wantConfirmed[prov] {
			t.Fatalf("the confirmed mix says %d under %q, want %d",
				s.ConfirmedProvenanceMix()[prov], prov, wantConfirmed[prov])
		}
	}
	if s.ConfirmedProvenanceMix()[rec.InventoryProvenanceStaticExtraction] != 0 {
		t.Fatal("static_extraction claims a confirmation it did not earn")
	}

	// Every row names an outcome, so an unconfirmed candidate is a diagnosis
	// and not a mystery.
	for _, r := range s.Rows() {
		if r.Outcome == "" {
			t.Fatalf("row %s carries no confirm outcome", r.Key())
		}
	}
	// Row count: 4 endpoints, one of which has two provenances.
	if len(s.Rows()) != 5 {
		t.Fatalf("%d rows, want 5", len(s.Rows()))
	}
}

// TestTheSummaryHandsOutCopies: a consumer must not be able to edit the number
// after the fact. Each accessor is mutated in the field where the copy is
// real, INCLUDING the nested Operations slice, because a test that mutates
// only the outer slice proves nothing about the inner one.
func TestTheSummaryHandsOutCopies(t *testing.T) {
	u := merge(t, confirming(t, &prober{def: 200}, 10),
		[]inventory.Route{
			route(t, authz.MethodGet, "/graphql", "createUser", rec.InventoryProvenanceRuntimeSpec),
			route(t, authz.MethodGet, "/graphql", "listUsers", rec.InventoryProvenanceRepoSpec),
		})
	s := mustSummarize(t, baseInputs(u))

	mix := s.ProvenanceMix()
	mix[rec.InventoryProvenanceCrawl] = 9999
	delete(mix, rec.InventoryProvenanceRuntimeSpec)
	if s.ProvenanceMix()[rec.InventoryProvenanceCrawl] != 0 {
		t.Fatal("editing the returned mix changed the summary")
	}
	if s.ProvenanceMix()[rec.InventoryProvenanceRuntimeSpec] != 1 {
		t.Fatal("deleting from the returned mix changed the summary")
	}

	cmix := s.ConfirmedProvenanceMix()
	cmix[rec.InventoryProvenanceCrawl] = 7
	if s.ConfirmedProvenanceMix()[rec.InventoryProvenanceCrawl] != 0 {
		t.Fatal("editing the returned confirmed mix changed the summary")
	}

	rows := s.Rows()
	if len(rows) == 0 || len(rows[0].Operations) < 2 {
		t.Fatalf("the fixture produced %d row(s) whose first carries %d operation(s); this "+
			"test needs a nested slice to mutate", len(rows), len(rows[0].Operations))
	}
	rows[0].Path = "/tampered"
	rows[0].Operations[0] = "tampered"
	rows = append(rows, ProvenanceRow{Method: "GET", Path: "/injected"})
	for _, r := range s.Rows() {
		if r.Path == "/tampered" || r.Path == "/injected" {
			t.Fatalf("editing the returned rows changed the summary: %v", r)
		}
		for _, op := range r.Operations {
			if op == "tampered" {
				t.Fatal("editing a returned row's nested Operations slice changed the " +
					"summary. This is the mutation a test that only touched the outer " +
					"slice would have missed")
			}
		}
	}

	quals := s.Qualifiers()
	quals = append(quals, Qualifier{Reason: QualifierEmptyUnion})
	if len(s.Qualifiers()) == len(quals) {
		t.Fatal("appending to the returned qualifiers changed the summary")
	}

	tiers := s.TierContributions()
	tiers[0].Routes = 4242
	for _, c := range s.TierContributions() {
		if c.Routes == 4242 {
			t.Fatal("editing the returned tier contributions changed the summary")
		}
	}
}

// TestASummaryWithNoTierFactsIsNotAMeasurement. Without any tier result the
// denominator carries no DenominatorFloor correction: every per-operation
// refusal and every floor-raising caveat is missing from it, by an amount
// nobody knows. That is the shrink direction, so it may not report itself as a
// plain measurement.
func TestASummaryWithNoTierFactsIsNotAMeasurement(t *testing.T) {
	u := merge(t, confirming(t, &prober{def: 200}, 10),
		[]inventory.Route{route(t, authz.MethodGet, "/a", "", rec.InventoryProvenanceRuntimeSpec)})
	s := mustSummarize(t, baseInputs(u))

	var q *Qualifier
	for i := range s.Qualifiers() {
		if got := s.Qualifiers()[i]; got.Reason == QualifierTierFactsAbsent {
			q = &got
		}
	}
	if q == nil {
		t.Fatalf("no tier result was supplied and nothing said so. %s", s)
	}
	if q.Direction() != DirectionOverstates {
		t.Fatalf("direction is %q, want %q", q.Direction(), DirectionOverstates)
	}
	if q.MagnitudeKnown() {
		t.Fatal("the qualifier claims a known magnitude for surface nobody counted")
	}
	if s.Determinacy() != DeterminacyQualified {
		t.Fatalf("determinacy is %q, want %q", s.Determinacy(), DeterminacyQualified)
	}
	if !s.PartialCoverage() {
		t.Fatal("a 1-of-1 union with no tier facts reported full coverage")
	}
	// And supplying the tier that produced the routes removes it, so the
	// qualifier is not simply always on.
	t1 := tier1(t, inventory.HarvestRan, specFile(t, "file:///s.json", openAPI("/a")))
	in := baseInputs(merge(t, confirming(t, &prober{def: 200}, 10), t1.Routes()))
	in.Tier1 = t1
	full := mustSummarize(t, in)
	if full.Determinacy() != DeterminacyMeasured {
		t.Fatalf("a fully accounted run is %q, want %q: %v",
			full.Determinacy(), DeterminacyMeasured, full.Qualifiers())
	}
}

// ---------------------------------------------------------------------------
// Enum hygiene
// ---------------------------------------------------------------------------

// TestEveryQualifierReasonNamesADirection: an unknown distortion is not a
// harmless one. A reason added to the vocabulary without a direction would
// silently report DirectionUnset and count as computable.
func TestEveryQualifierReasonNamesADirection(t *testing.T) {
	for _, r := range QualifierReasonValues() {
		if !r.Recognised() {
			t.Fatalf("%q is in QualifierReasonValues and is not recognised", r)
		}
		d := r.Direction()
		if d != DirectionOverstates && d != DirectionUnderstates && d != DirectionUncomputable {
			t.Fatalf("%q has direction %q, which is not a direction", r, d)
		}
		if !(Qualifier{Reason: r}).Valid() {
			t.Fatalf("a qualifier carrying %q reports itself invalid", r)
		}
	}
	if QualifierUnset.Recognised() {
		t.Fatal("the zero QualifierReason is recognised")
	}
	if (Qualifier{}).Valid() {
		t.Fatal("the zero Qualifier reports itself valid")
	}
	if (Qualifier{}).Direction() != DirectionUnset {
		t.Fatal("the zero Qualifier names a direction")
	}
	// Every reason in the allowlist is reachable through the values list, so
	// the two cannot drift.
	listed := map[QualifierReason]bool{}
	for _, r := range QualifierReasonValues() {
		listed[r] = true
	}
	for r := range qualifierDirections() {
		if !listed[r] {
			t.Fatalf("%q has a direction and is not in QualifierReasonValues", r)
		}
	}
}

// TestTheZeroValuesAreNotValues is the fail-closed floor. A Go zero value must
// never mean "permitted" or "measured".
func TestTheZeroValuesAreNotValues(t *testing.T) {
	if ScanModeUnset.Valid() {
		t.Fatal("the zero ScanMode validates")
	}
	if ScanModeUnset.AllowsServerLineCoverage() {
		t.Fatal("the zero ScanMode permits a server-line measurement")
	}
	if DeterminacyUnset.Valid() {
		t.Fatal("the zero Determinacy validates")
	}
	if DeterminacyUnset.Computable() {
		t.Fatal("the zero Determinacy reports a publishable fraction")
	}
	var s Summary
	if s.Constructed() {
		t.Fatal("the zero Summary reports itself constructed")
	}
	if !s.PartialCoverage() {
		t.Fatal("the zero Summary reports full coverage")
	}
	if _, err := s.Coverage(); !errors.Is(err, ErrUnconstructed) {
		t.Fatalf("the zero Summary produced coverage (%v)", err)
	}
	if _, err := s.DeriveDastStatus(true, rec.HalfStatusSealed, 0); !errors.Is(err, ErrUnconstructed) {
		t.Fatalf("the zero Summary derived a status (%v)", err)
	}
	if err := s.AssertMixDecomposes(); !errors.Is(err, ErrUnconstructed) {
		t.Fatalf("the zero Summary's mix decomposed (%v)", err)
	}
	if err := s.AssertDenominatorDecomposes(); !errors.Is(err, ErrUnconstructed) {
		t.Fatalf("the zero Summary's denominator decomposed (%v)", err)
	}
	if !strings.Contains(s.String(), "unconstructed") {
		t.Fatalf("the zero Summary renders as %q", s.String())
	}
}

// TestSummarizeRefusesAMissingModeOrProvenance: neither has a default, because
// a default in either would be a decision this package is not entitled to
// make.
func TestSummarizeRefusesAMissingModeOrProvenance(t *testing.T) {
	u := merge(t, mergeOnly(t))
	in := baseInputs(u)
	in.Mode = ScanModeUnset
	if _, err := Summarize(in); !errors.Is(err, ErrRefused) {
		t.Fatalf("Summarize accepted an unset mode (%v)", err)
	}
	in = baseInputs(u)
	in.Provenance = ""
	if _, err := Summarize(in); !errors.Is(err, ErrRefused) {
		t.Fatalf("Summarize accepted an empty target provenance (%v)", err)
	}
	in = baseInputs(u)
	in.Provisioning = rec.TargetProvisioning("live_url")
	if _, err := Summarize(in); !errors.Is(err, ErrRefused) {
		t.Fatalf("Summarize accepted a bogus provisioning literal (%v)", err)
	}
}

// TestTheTwoTargetFieldsStayTwoFields. plan/50-dast.md:1150 says
// target_provenance carries {ephemeral_manifest, live_url_authorized}; that is
// stale. Those are anvil/target.provisioning values and the boot outcome is a
// separate field. A summary that merged them would fail here.
func TestTheTwoTargetFieldsStayTwoFields(t *testing.T) {
	u := merge(t, confirming(t, &prober{def: 200}, 10),
		[]inventory.Route{route(t, authz.MethodGet, "/a", "", rec.InventoryProvenanceRuntimeSpec)})
	in := baseInputs(u)
	in.Provisioning = rec.TargetProvisioningLiveURLAuthorized
	s := mustSummarize(t, in)

	if s.Provenance() != rec.TargetProvenanceBootedClean {
		t.Fatalf("target provenance is %q, want %q", s.Provenance(),
			rec.TargetProvenanceBootedClean)
	}
	prov, ok := s.Provisioning()
	if !ok || prov != rec.TargetProvisioningLiveURLAuthorized {
		t.Fatalf("provisioning is (%q,%v), want (%q,true)", prov, ok,
			rec.TargetProvisioningLiveURLAuthorized)
	}
	if string(s.Provenance()) == string(prov) {
		t.Fatal("the two target fields carry the same literal")
	}
	// The two vocabularies must not overlap at all: a merge would be
	// undetectable if they did.
	for _, a := range rec.TargetProvenanceValues() {
		for _, b := range rec.TargetProvisioningValues() {
			if string(a) == string(b) {
				t.Fatalf("%q is in both enums", a)
			}
		}
	}
}

// ---------------------------------------------------------------------------
// End to end
// ---------------------------------------------------------------------------

// TestAFullAggregationAcrossEveryTier is the packet's stop condition: all six
// record fields populate together, over a union built from real tier results.
func TestAFullAggregationAcrossEveryTier(t *testing.T) {
	t0 := tier0(t, []string{"/openapi.json"},
		map[string]string{"/openapi.json": openAPI("/health", "/users")})
	if len(t0.Routes()) != 2 {
		t.Fatalf("Tier 0 produced %d routes, want 2", len(t0.Routes()))
	}
	t1 := tier1(t, inventory.HarvestRan,
		specFile(t, "file:///api/openapi.json", openAPI("/users", "/orders")))
	if len(t1.Routes()) != 2 {
		t.Fatalf("Tier 1 produced %d routes, want 2", len(t1.Routes()))
	}
	t2o := tier2Other(t, inventory.HarvestRan,
		sourceFile(t, "file:///app/server.js",
			"const app = require('express')();\napp.get('/metrics', h);\n"))
	if len(t2o.Routes()) != 1 {
		t.Fatalf("Tier 2 (non-Go) produced %d routes, want 1: %v", len(t2o.Routes()), t2o.Routes())
	}

	p := &prober{def: 404, byPath: map[string]int{"/health": 200, "/users": 200, "/metrics": 200}}
	u := merge(t, confirming(t, p, 20), t0.Routes(), t1.Routes(), t2o.Routes())

	in := Inputs{
		Mode:         ScanModeScheduledFull,
		Union:        u,
		Tier0:        t0,
		Tier1:        t1,
		Tier2Other:   t2o,
		Provenance:   rec.TargetProvenanceBootedClean,
		Provisioning: rec.TargetProvisioningEphemeralManifest,
	}
	s := mustSummarize(t, in)

	// /users arrives from two tiers and is ONE endpoint.
	if s.MergedEndpointCount() != 4 {
		t.Fatalf("%d endpoints, want 4 (/health /users /orders /metrics). Table:\n%s",
			s.MergedEndpointCount(), rowTable(s))
	}
	if s.ConfirmedCount() != 3 {
		t.Fatalf("%d confirmed, want 3. Table:\n%s", s.ConfirmedCount(), rowTable(s))
	}
	cov, err := s.Coverage()
	if err != nil {
		t.Fatalf("Coverage: %v", err)
	}
	if cov.ProbedCount != 3 || cov.InventoryUnionCount != 4 {
		t.Fatalf("coverage is %d/%d, want 3/4", cov.ProbedCount, cov.InventoryUnionCount)
	}
	if cov.ConfirmedCount+cov.CandidateCount != cov.InventoryUnionCount {
		t.Fatalf("%d confirmed + %d candidate != %d union",
			cov.ConfirmedCount, cov.CandidateCount, cov.InventoryUnionCount)
	}
	if cov.ServerLineCoverage != nil {
		t.Fatalf("a full scan with no coverage agent carries %v, want nil",
			*cov.ServerLineCoverage)
	}
	if err := rec.ValidateDastCoverage(&cov); err != nil {
		t.Fatalf("internal/record's own validator refuses it: %v", err)
	}
	if err := s.AssertMixDecomposes(); err != nil {
		t.Fatalf("AssertMixDecomposes: %v", err)
	}
	if err := s.AssertDenominatorDecomposes(); err != nil {
		t.Fatalf("AssertDenominatorDecomposes: %v", err)
	}
	// Three tiers ran, one did not, and both facts are visible.
	ran := 0
	for _, c := range s.TierContributions() {
		if c.Ran {
			ran++
		}
	}
	if ran != 3 {
		t.Fatalf("%d tiers report Ran, want 3", ran)
	}

	// A partial scan must not derive clean.
	status, err := s.DeriveDastStatus(true, rec.HalfStatusSealed, 0)
	if err != nil {
		t.Fatalf("DeriveDastStatus: %v", err)
	}
	if status != rec.DastStatusCompletedPartial {
		t.Fatalf("a 3-of-4 scan derived %q, want %q", status, rec.DastStatusCompletedPartial)
	}
	if status.MeansDynamicallyScannedClean() {
		t.Fatalf("%q reports itself dynamically scanned clean", status)
	}

	// The report line carries the numerator and the denominator, never a
	// bare percentage.
	line := s.String()
	if !strings.Contains(line, "3/4 endpoints") {
		t.Fatalf("the report line does not carry both numbers: %q", line)
	}
	if !strings.Contains(line, "server_line_coverage=null") {
		t.Fatalf("the report line does not state the null: %q", line)
	}
}

// TestSummarizeIsDeterministic: map iteration is randomized and an unstable
// report makes an unchanged repository look changed.
func TestSummarizeIsDeterministic(t *testing.T) {
	build := func() Summary {
		u := merge(t, confirming(t, &prober{def: 404, byPath: map[string]int{"/b": 200}}, 20),
			[]inventory.Route{
				route(t, authz.MethodGet, "/a", "", rec.InventoryProvenanceRuntimeSpec),
				route(t, authz.MethodGet, "/b", "", rec.InventoryProvenanceRepoSpec),
				route(t, authz.MethodGet, "/a", "", rec.InventoryProvenanceStaticExtraction),
			})
		return mustSummarize(t, baseInputs(u))
	}
	first := rowTable(build())
	for i := 0; i < 8; i++ {
		if got := rowTable(build()); got != first {
			t.Fatalf("run %d produced a different table:\nfirst:\n%s\ngot:\n%s", i, first, got)
		}
	}
}

func rowTable(s Summary) string {
	rows := s.Rows()
	out := make([]string, 0, len(rows)+1)
	out = append(out, fmt.Sprintf("union=%d unrepresented=%d confirmed=%d ops=%d",
		s.MergedEndpointCount(), s.UnrepresentedCount(), s.ConfirmedCount(), s.OperationCount()))
	for _, r := range rows {
		out = append(out, fmt.Sprintf("%s confirmed=%v outcome=%s ops=%s",
			r.Key(), r.Confirmed, r.Outcome, strings.Join(r.Operations, ",")))
	}
	sort.Strings(out[1:])
	return strings.Join(out, "\n")
}

// ===========================================================================
// D.29 LOW 7 — the decomposition's arithmetic
// ===========================================================================

// TestDenominatorDecompositionRefusesANegativeUnrepresentedCount.
//
// AssertDenominatorDecomposes checked the IDENTITY Unrepresented ==
// Floor-Routes and never checked the SIGN. The identity holds perfectly well
// for (floor 2, routes 5, unrepresented -3): it constrains the three numbers
// to each other and says nothing about what any of them means. A negative
// unrepresented count then SHRINKS the denominator that every fraction in the
// summary is divided by — coverage inflation arriving through the arithmetic
// that exists to make coverage honest.
//
// It is not reachable from Summarize today, and that is exactly why it is
// asserted here rather than left implied. The tiers are the only producers of
// these numbers and the day one of them subtracts in the wrong order, the
// assertion whose entire job is "the denominator decomposes" would go on
// returning nil.
func TestDenominatorDecompositionRefusesANegativeUnrepresentedCount(t *testing.T) {
	// The generator: a hand-built Summary, because the production path
	// cannot produce this input and A GENERATOR THAT CANNOT PRODUCE THE
	// BREAKING INPUT IS THE DEFECT. Building it here is possible because
	// this test is in the package that owns the type.
	base := func(contribs []TierContribution, unrepresented, confirmed, merged int) Summary {
		return Summary{
			tiers:         contribs,
			unrepresented: unrepresented,
			confirmed:     confirmed,
			merged:        merged,
			sealed:        true,
		}
	}

	for _, tc := range []struct {
		name    string
		summary Summary
		wantErr bool
	}{
		{
			name: "an honest decomposition",
			summary: base([]TierContribution{
				{Tier: TierRepoSpec, Ran: true, Routes: 2, Floor: 3, Unrepresented: 1},
			}, 1, 0, 2),
			wantErr: false,
		},
		{
			name: "more routes than the floor they came from",
			summary: base([]TierContribution{
				{Tier: TierRepoSpec, Ran: true, Routes: 5, Floor: 2, Unrepresented: -3},
			}, -3, 0, 5),
			wantErr: true,
		},
		{
			name: "a negative floor",
			summary: base([]TierContribution{
				{Tier: TierRepoSpec, Ran: true, Routes: -4, Floor: -2, Unrepresented: 2},
			}, 2, 0, 0),
			wantErr: true,
		},
		{
			name: "one honest tier and one negative one, summing to something plausible",
			summary: base([]TierContribution{
				{Tier: TierRuntimeSpec, Ran: true, Routes: 1, Floor: 5, Unrepresented: 4},
				{Tier: TierRepoSpec, Ran: true, Routes: 5, Floor: 2, Unrepresented: -3},
			}, 1, 0, 6),
			wantErr: true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.summary.AssertDenominatorDecomposes()
			if gotErr := err != nil; gotErr != tc.wantErr {
				t.Fatalf("AssertDenominatorDecomposes = %v, want error=%v", err, tc.wantErr)
			}
			if tc.wantErr && !errors.Is(err, ErrRefused) {
				t.Errorf("error = %v, want ErrRefused", err)
			}
		})
	}

	// The last case is the one that matters most and it deserves its own
	// statement: 4 + -3 == 1, so the SUM check downstream is satisfied and
	// the tier-level sign check is the only thing standing between a
	// negative contribution and a shrunk denominator.
	sneaky := base([]TierContribution{
		{Tier: TierRuntimeSpec, Ran: true, Routes: 1, Floor: 5, Unrepresented: 4},
		{Tier: TierRepoSpec, Ran: true, Routes: 5, Floor: 2, Unrepresented: -3},
	}, 1, 0, 6)
	sum := 0
	for _, c := range sneaky.TierContributions() {
		sum += c.Unrepresented
	}
	if sum != sneaky.UnrepresentedCount() {
		t.Fatalf("the fixture's contributions sum to %d and it reports %d; it is not "+
			"exercising the case where only the SIGN check can fire",
			sum, sneaky.UnrepresentedCount())
	}
	if err := sneaky.AssertDenominatorDecomposes(); !errors.Is(err, ErrRefused) {
		t.Errorf("a tier reporting -3 unrepresented endpoints passed the decomposition "+
			"because another tier's +4 covered for it: %v", err)
	}
}
