// Tests for route confirmation (Tier 2): the step that turns a candidate into
// a confirmed endpoint, and therefore the packet that decides both halves of
// endpoint_coverage.
//
// The suite is organised around the two ways the fraction can be corrupted,
// because they are corrupted in OPPOSITE directions and only one of them is
// obvious:
//
//	THE NUMERATOR — every incentive points at inflating it, so it is the half
//	people watch. Tests here try to mint a confirmation without an observation:
//	from a prober that returns nothing, from a route that arrives already
//	claiming "confirmed", from a budget that ran out, from a kernel refusal,
//	from a templated path nobody could request.
//
//	THE DENOMINATOR — inflating it makes coverage look WORSE, so nobody
//	investigates and the number quietly stops meaning what it says. Tests here
//	feed one endpoint in from three tiers under three spellings and assert it
//	is ONE row with THREE provenances.
//
// Every kernel object below is built by the kernel's own constructors, reusing
// the harness tier0_runtime_test.go already established: initiateRun drives
// the real Phase 1 gates and authz.Adjudicate is the only mint for an
// authz.Authorization. THE ADMISSION RULING made the admission chain able to admit, so the
// confirmation path in this file is driven END TO END through the real kernel
// — authz.NewRequestIntent, authz.RequireAuthorization,
// authz.GateAudit.AuditedAdmit, authz.Governor.ObserveResponse — with the
// EndpointProber seam as the only double, because the build-time guard's gate 3 forbids this
// package from holding a socket.
package inventory

import (
	"context"
	"errors"
	"fmt"
	"go/ast"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/Susquehanna-Syntax/Anvil/internal/dast/authz"
	"github.com/Susquehanna-Syntax/Anvil/internal/record"
)

// ---------------------------------------------------------------------------
// Harness
// ---------------------------------------------------------------------------

// confirmRoute builds one inventory route on the fixture target.
func confirmRoute(t *testing.T, m authz.Method, path, op string,
	prov record.InventoryProvenance, conf Confirmation, params ...Param) Route {
	t.Helper()
	rt, err := NewRoute(RouteFacts{
		Method:       m,
		Path:         path,
		Target:       mustBareTarget(t),
		Operation:    op,
		Params:       params,
		Provenance:   prov,
		Confirmation: conf,
		Trust:        record.TrustUntrusted,
	})
	if err != nil {
		t.Fatalf("NewRoute(%s %s): %v", m, path, err)
	}
	return rt
}

// confirmCandidate is the common case: a candidate route from one tier.
func confirmCandidate(t *testing.T, m authz.Method, path string, prov record.InventoryProvenance) Route {
	t.Helper()
	return confirmRoute(t, m, path, "", prov, ConfirmationCandidate)
}

// confirmKernelOpts parameterises the governor so a test can put a REAL gate in
// the confirmation path rather than assert around it.
type confirmKernelOpts struct {
	robots    *authz.RobotsPolicy
	allowance authz.EndpointAllowance
	overrides *authz.CapOverrides
}

// confirmKernel builds a real Governor and GateAudit for the fixture target.
func confirmKernel(t *testing.T, opts confirmKernelOpts) (*authz.Governor, *authz.GateAudit, *countingSink) {
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
	sink := &countingSink{}
	audit, res := authz.NewGateAudit(sink, key, run)
	if !res.Passed() {
		t.Fatalf("authz.NewGateAudit: %v", res.Err())
	}
	caps := authz.CodedCaps()
	if opts.overrides != nil {
		caps, res = caps.Lower(*opts.overrides)
		if !res.Passed() {
			t.Fatalf("authz.Caps.Lower: %v", res.Err())
		}
	}
	robots := authz.RobotsNotFound(fixtureHost, 443)
	if opts.robots != nil {
		robots = *opts.robots
	}
	gov, res := authz.NewGovernor(authz.GovernorConfig{
		Target:      mustBareTarget(t),
		Scope:       scope,
		Attestation: att,
		Caps:        caps,
		Thresholds:  authz.CodedHealthThresholds(),
		Robots:      robots,
		Allowance:   opts.allowance,
		Start:       mustClock(t),
	})
	if !res.Passed() {
		t.Fatalf("authz.NewGovernor: %v", res.Err())
	}
	return gov, audit, sink
}

// confirmProber is the egress seam's double. It records every ConfirmRequest it
// was handed so a test can assert what actually left rather than what the
// implementation says it sends.
type confirmProber struct {
	byPath map[string]int
	def    int
	err    error
	seen   []ConfirmRequest
	calls  int
}

func (p *confirmProber) ProbeEndpoint(_ context.Context, req ConfirmRequest) (ConfirmResponse, error) {
	p.calls++
	p.seen = append(p.seen, req)
	if p.err != nil {
		return ConfirmResponse{}, p.err
	}
	if s, ok := p.byPath[req.Path()]; ok {
		return ConfirmResponse{Status: s, Latency: 3 * time.Millisecond}, nil
	}
	return ConfirmResponse{Status: p.def, Latency: 3 * time.Millisecond}, nil
}

func (p *confirmProber) paths() []string {
	out := make([]string, 0, len(p.seen))
	for _, r := range p.seen {
		out = append(out, string(r.Method())+" "+r.Path())
	}
	return out
}

func confirmAnswering(status int, byPath map[string]int) *confirmProber {
	return &confirmProber{def: status, byPath: byPath}
}

// confirmClock advances the instant between probes so gate 14's token bucket
// refills, which is what a real run's clock does.
type confirmClock struct {
	t    *testing.T
	at   time.Time
	step time.Duration
}

func confirmAdvancing(t *testing.T, step time.Duration) *confirmClock {
	t.Helper()
	return &confirmClock{t: t, at: mustClock(t).Instant(), step: step}
}

func (c *confirmClock) NextInstant() authz.Clock {
	c.at = c.at.Add(c.step)
	k, err := authz.NewClock(c.at)
	if err != nil {
		c.t.Fatalf("authz.NewClock(%v): %v", c.at, err)
	}
	return k
}

// confirmConcretizer is the PathConcretizer double.
type confirmConcretizer struct {
	fn    func(template string) (string, string, error)
	seen  []string
	calls int
}

func (c *confirmConcretizer) ConcretizePath(_ context.Context, _ authz.Method, template string) (string, string, error) {
	c.calls++
	c.seen = append(c.seen, template)
	return c.fn(template)
}

func confirmFixed(path, source string) *confirmConcretizer {
	return &confirmConcretizer{fn: func(string) (string, string, error) { return path, source, nil }}
}

// confirmConfirming is the standard confirming configuration.
func confirmConfirming(t *testing.T, prober EndpointProber, budget int) ConfirmConfig {
	t.Helper()
	gov, audit, _ := confirmKernel(t, confirmKernelOpts{})
	auth, _ := mintAuthorization(t)
	return ConfirmConfig{
		Governor:      gov,
		Audit:         audit,
		Authorization: auth,
		Target:        mustBareTarget(t),
		Confirm:       true,
		ProbeBudget:   budget,
		Technique:     authz.TechniqueContentDiscovery,
		Prober:        prober,
		Clock:         confirmAdvancing(t, time.Second),
	}
}

func confirmRun(t *testing.T, cfg ConfirmConfig, tiers ...[]Route) ConfirmResult {
	t.Helper()
	res, err := MergeAndConfirm(context.Background(), cfg, mustClock(t), tiers...)
	if err != nil {
		t.Fatalf("MergeAndConfirm: %v", err)
	}
	return res
}

func confirmEndpointTable(res ConfirmResult) []string {
	out := make([]string, 0, len(res.Endpoints()))
	for _, e := range res.Endpoints() {
		out = append(out, fmt.Sprintf("%s %s %s %s", e.Method(), e.Path(),
			e.Confirmation(), e.Outcome()))
	}
	return out
}

func confirmEndpoint(t *testing.T, res ConfirmResult, m authz.Method, path string) MergedEndpoint {
	t.Helper()
	for _, e := range res.Endpoints() {
		if e.Method() == m && e.Path() == path {
			return e
		}
	}
	t.Fatalf("no endpoint %s %s in the union; the union is %v", m, path, confirmEndpointTable(res))
	return MergedEndpoint{}
}

func confirmNoteCount(res ConfirmResult, reason MergeNoteReason) int {
	n := 0
	for _, note := range res.Notes() {
		if note.Reason == reason {
			n++
		}
	}
	return n
}

func confirmOutcomeCount(res ConfirmResult, o ConfirmOutcome) int {
	n := 0
	for _, e := range res.Endpoints() {
		if e.Outcome() == o {
			n++
		}
	}
	return n
}

// ===========================================================================
// THE END-TO-END PATH — new under THE ADMISSION RULING, and measured rather than assumed
// ===========================================================================

// TestAConfirmationIsARealObservationDrivenThroughTheKernel is the packet's
// central claim, and it is driven through the REAL admission chain, the REAL
// per-request gate chain and the REAL gate-21 audit writer. Only the socket is
// a double, because gate 3 forbids this package from holding one.
//
// It also pins the plan's Forbidden action: "Do not treat a non-404 as
// sufficient on its own without recording the actual status code observed — a
// 500 is 'route exists, handler errors,' not 'route works.'"
func TestAConfirmationIsARealObservationDrivenThroughTheKernel(t *testing.T) {
	gov, audit, sink := confirmKernel(t, confirmKernelOpts{})
	auth, _ := mintAuthorization(t)
	prober := confirmAnswering(200, map[string]int{
		"/health":  200,
		"/gone":    404,
		"/broken":  500,
		"/private": 403,
	})
	cfg := ConfirmConfig{
		Governor:      gov,
		Audit:         audit,
		Authorization: auth,
		Target:        mustBareTarget(t),
		Confirm:       true,
		ProbeBudget:   16,
		Technique:     authz.TechniqueContentDiscovery,
		Prober:        prober,
		Clock:         confirmAdvancing(t, time.Second),
	}
	res := confirmRun(t, cfg, []Route{
		confirmCandidate(t, authz.MethodGet, "/health", record.InventoryProvenanceRuntimeSpec),
		confirmCandidate(t, authz.MethodGet, "/gone", record.InventoryProvenanceRepoSpec),
		confirmCandidate(t, authz.MethodGet, "/broken", record.InventoryProvenanceStaticExtraction),
		confirmCandidate(t, authz.MethodGet, "/private", record.InventoryProvenanceCrawl),
	})

	want := []string{
		"GET /broken confirmed observed_non_404",
		"GET /gone candidate observed_404",
		"GET /health confirmed observed_non_404",
		"GET /private confirmed observed_non_404",
	}
	if got := confirmEndpointTable(res); !reflect.DeepEqual(got, want) {
		t.Fatalf("endpoint table =\n  %v\nwant\n  %v", got, want)
	}
	if res.ConfirmedCount() != 3 || res.CandidateCount() != 1 || res.EndpointCount() != 4 {
		t.Fatalf("confirmed=%d candidate=%d union=%d, want 3/1/4",
			res.ConfirmedCount(), res.CandidateCount(), res.EndpointCount())
	}
	if res.Issued() != 4 || res.Answered() != 4 || prober.calls != 4 {
		t.Fatalf("issued=%d answered=%d proberCalls=%d, want 4/4/4",
			res.Issued(), res.Answered(), prober.calls)
	}

	// THE STATUS CODE IS RECORDED, NOT FOLDED AWAY. A 500 and a 200 are both
	// confirmations and they are not the same fact.
	for _, tc := range []struct {
		path   string
		status int
	}{{"/health", 200}, {"/broken", 500}, {"/private", 403}, {"/gone", 404}} {
		e := confirmEndpoint(t, res, authz.MethodGet, tc.path)
		obs, ok := e.Observation()
		if !ok {
			t.Fatalf("%s carries no observation, so its outcome %q cannot be traced to "+
				"anything", tc.path, e.Outcome())
		}
		if obs.Status() != tc.status {
			t.Fatalf("%s recorded status %d, want %d", tc.path, obs.Status(), tc.status)
		}
		if obs.AuditSeq() == 0 {
			t.Fatalf("%s recorded audit sequence 0. Gate 21 makes the audit write part of "+
				"the decision, and a probe with no row cannot be joined back to who "+
				"authorized it", tc.path)
		}
		if obs.Technique() != authz.TechniqueContentDiscovery {
			t.Fatalf("%s recorded technique %q", tc.path, obs.Technique())
		}
		if obs.Path() != tc.path || obs.Method() != authz.MethodGet {
			t.Fatalf("%s recorded %s %s", tc.path, obs.Method(), obs.Path())
		}
	}

	if err := res.AssertEveryConfirmationHasEvidence(); err != nil {
		t.Fatalf("AssertEveryConfirmationHasEvidence: %v", err)
	}
	if err := res.AssertNoUnconfirmedEndpointClaimsConfirmation(); err != nil {
		t.Fatalf("AssertNoUnconfirmedEndpointClaimsConfirmation: %v", err)
	}
	if err := res.AssertBudgetSufficed(); err != nil {
		t.Fatalf("AssertBudgetSufficed: %v", err)
	}
	// Gate 21 wrote rows: one per gate consulted per admission, plus one per
	// observation. Four probes through a six-gate chain cannot be fewer than
	// four rows under any reading.
	if sink.n < 4 {
		t.Fatalf("the gate-21 sink recorded %d rows for 4 admitted probes and 4 "+
			"observations", sink.n)
	}
	if admitted, refused := gov.Counts(); admitted != 4 || refused != 0 {
		t.Fatalf("the governor admitted %d and refused %d, want 4 and 0", admitted, refused)
	}
}

// TestConfirmationRequiresAProberAndSaysSoLoudly is the tool-absent path. It
// does not fall back to a smaller numerator; it refuses.
func TestConfirmationRequiresAProberAndSaysSoLoudly(t *testing.T) {
	gov, audit, _ := confirmKernel(t, confirmKernelOpts{})
	auth, _ := mintAuthorization(t)
	cfg := ConfirmConfig{
		Governor: gov, Audit: audit, Authorization: auth, Target: mustBareTarget(t),
		Confirm: true, ProbeBudget: 4, Technique: authz.TechniqueContentDiscovery,
	}
	res, err := MergeAndConfirm(context.Background(), cfg, mustClock(t), []Route{
		confirmCandidate(t, authz.MethodGet, "/a", record.InventoryProvenanceRuntimeSpec),
		confirmCandidate(t, authz.MethodGet, "/b", record.InventoryProvenanceRuntimeSpec),
	})
	if !errors.Is(err, ErrNoEndpointProber) {
		t.Fatalf("MergeAndConfirm returned %v, want ErrNoEndpointProber", err)
	}
	if res.EndpointCount() != 2 {
		t.Fatalf("the union lost endpoints when the seam was absent: %d", res.EndpointCount())
	}
	if res.ConfirmedCount() != 0 {
		t.Fatalf("%d endpoints were confirmed with nothing wired to observe them",
			res.ConfirmedCount())
	}
	if n := confirmOutcomeCount(res, ConfirmOutcomeNoProberWired); n != 2 {
		t.Fatalf("%d endpoints carry no_prober_wired, want 2", n)
	}
	if res.Issued() != 0 {
		t.Fatalf("Issued()=%d with no prober", res.Issued())
	}
}

// TestAProberThatReturnsNoStatusCannotMintAConfirmation is the fail-closed
// guard the whole numerator rests on.
//
// The rule is "promote on a NON-404 response". Zero is non-404. So is -1, and
// so is 99999. A prober that lost the response, a stub, or a
// short-circuited implementation returns exactly those, and without the
// [100,599] bound each of them would be read as a confirmation.
func TestAProberThatReturnsNoStatusCannotMintAConfirmation(t *testing.T) {
	for _, status := range []int{0, -1, 1, 99, 600, 99999} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			prober := confirmAnswering(status, nil)
			res := confirmRun(t, confirmConfirming(t, prober, 4), []Route{
				confirmCandidate(t, authz.MethodGet, "/a", record.InventoryProvenanceRuntimeSpec),
			})
			e := confirmEndpoint(t, res, authz.MethodGet, "/a")
			if e.Confirmed() {
				t.Fatalf("status %d confirmed the endpoint. A value that is not an HTTP "+
					"status is not an answer, and reading it as a non-404 puts an "+
					"unobserved endpoint in endpoint_coverage's numerator", status)
			}
			if e.Outcome() != ConfirmOutcomeProbeFailed {
				t.Fatalf("outcome = %q, want probe_failed", e.Outcome())
			}
			if _, ok := e.Observation(); ok {
				t.Fatal("a probe that returned no status recorded an observation")
			}
			if res.Answered() != 0 {
				t.Fatalf("Answered()=%d; the target did not answer", res.Answered())
			}
			if res.Issued() != 1 {
				t.Fatalf("Issued()=%d; the request did leave", res.Issued())
			}
		})
	}
}

// TestAHostileProberCannotChooseWhatIsProbed pins what the seam can and cannot
// reach. ConfirmRequest is sealed and carries no setter, so the only thing a
// prober returns is a status.
func TestAHostileProberCannotChooseWhatIsProbed(t *testing.T) {
	prober := confirmAnswering(200, nil)
	res := confirmRun(t, confirmConfirming(t, prober, 4), []Route{
		confirmCandidate(t, authz.MethodGet, "/a", record.InventoryProvenanceRuntimeSpec),
	})
	if len(prober.seen) != 1 {
		t.Fatalf("the prober saw %d requests, want 1", len(prober.seen))
	}
	req := prober.seen[0]
	if !req.Constructed() {
		t.Fatal("the prober was handed a ConfirmRequest that reports itself unconstructed")
	}
	if req.Path() != "/a" || req.Method() != authz.MethodGet {
		t.Fatalf("the prober was handed %s %s", req.Method(), req.Path())
	}
	if !sameTarget(req.Target(), mustBareTarget(t)) {
		t.Fatalf("the prober was handed target %s", req.Target())
	}
	if err := authz.RequireAuthorization(req.Authorization(), req.Target()); err != nil {
		t.Fatalf("the request carries a token the kernel refuses for its own target: %v", err)
	}
	if req.AuditSeq() == 0 {
		t.Fatal("the request carries audit sequence 0")
	}
	// A composite literal elsewhere is not a request.
	if (ConfirmRequest{}).Constructed() {
		t.Fatal("the zero ConfirmRequest reports itself constructed")
	}
	// And the observation the loop recorded points at the same admission.
	e := confirmEndpoint(t, res, authz.MethodGet, "/a")
	obs, ok := e.Observation()
	if !ok || obs.AuditSeq() != req.AuditSeq() {
		t.Fatalf("the observation's audit sequence (%v) does not match the request's (%d)",
			obs.AuditSeq(), req.AuditSeq())
	}
}

// TestAProbeErrorIsNotAConfirmation.
func TestAProbeErrorIsNotAConfirmation(t *testing.T) {
	prober := &confirmProber{err: errors.New("dial refused by the fixture")}
	res := confirmRun(t, confirmConfirming(t, prober, 4), []Route{
		confirmCandidate(t, authz.MethodGet, "/a", record.InventoryProvenanceRuntimeSpec),
	})
	e := confirmEndpoint(t, res, authz.MethodGet, "/a")
	if e.Confirmed() || e.Outcome() != ConfirmOutcomeProbeFailed {
		t.Fatalf("a transport error produced %s/%s", e.Confirmation(), e.Outcome())
	}
	if res.Answered() != 0 {
		t.Fatalf("Answered()=%d", res.Answered())
	}
	if n := confirmRefusalCount(res, RefusalFetchFailed); n != 1 {
		t.Fatalf("%d fetch_failed refusals, want 1", n)
	}
	if err := res.AssertEveryConfirmationHasEvidence(); err != nil {
		t.Fatalf("AssertEveryConfirmationHasEvidence: %v", err)
	}
}

func confirmRefusalCount(res ConfirmResult, reason RefusalReason) int {
	n := 0
	for _, r := range res.Refusals() {
		if r.Reason == reason {
			n++
		}
	}
	return n
}

// ===========================================================================
// THE DENOMINATOR — three routes, one endpoint
// ===========================================================================

// TestTheSameEndpointFoundByThreeRoutesIsOneEndpointWithThreeProvenances is
// the denominator failure the brief names: the one nobody investigates,
// because counting it three times makes coverage look WORSE.
//
// The three routes arrive in THREE DIFFERENT SPELLINGS — the OpenAPI "{id}",
// gin's ":id", and gorilla's "{id:[0-9]+}" — so the test also proves that
// canonicalization happens BEFORE matching, and that it is Go route extraction's
// canonicalizePattern doing it rather than a second one here.
func TestTheSameEndpointFoundByThreeRoutesIsOneEndpointWithThreeProvenances(t *testing.T) {
	res := confirmRun(t, ConfirmConfig{Target: mustBareTarget(t)},
		[]Route{confirmRoute(t, authz.MethodGet, "/users/{id}", "getUser",
			record.InventoryProvenanceRuntimeSpec, ConfirmationCandidate)},
		[]Route{confirmCandidate(t, authz.MethodGet, "/users/:id",
			record.InventoryProvenanceRepoSpec)},
		[]Route{confirmCandidate(t, authz.MethodGet, "/users/{id:[0-9]+}",
			record.InventoryProvenanceStaticExtraction)},
	)

	if res.Offered() != 3 || res.Accepted() != 3 {
		t.Fatalf("offered=%d accepted=%d, want 3/3", res.Offered(), res.Accepted())
	}
	if res.EndpointCount() != 1 {
		t.Fatalf("the union has %d endpoints and the three routes name ONE: %v.\n"+
			"Counting one endpoint three times INFLATES the denominator of "+
			"endpoint_coverage, which makes coverage look worse -- so nobody "+
			"investigates it, and the number stops meaning what it says",
			res.EndpointCount(), confirmEndpointTable(res))
	}
	e := confirmEndpoint(t, res, authz.MethodGet, "/users/{id}")
	want := []record.InventoryProvenance{
		record.InventoryProvenanceRuntimeSpec,
		record.InventoryProvenanceRepoSpec,
		record.InventoryProvenanceStaticExtraction,
	}
	if got := e.Provenances(); !reflect.DeepEqual(got, want) {
		t.Fatalf("provenances = %v, want %v (strongest evidence first)", got, want)
	}
	if got := e.Operations(); !reflect.DeepEqual(got, []string{"getUser"}) {
		t.Fatalf("operations = %v, want [getUser]", got)
	}
	if n := len(e.Contributors()); n != 3 {
		t.Fatalf("%d contributors, want 3", n)
	}
	if n := confirmNoteCount(res, MergeNoteRoutesCollapsed); n != 2 {
		t.Fatalf("%d routes_collapsed notes, want 2 (the second and third arrivals)", n)
	}
	// Routes() is not the denominator, and this is the line that says so.
	if n := len(res.Routes()); n != 3 {
		t.Fatalf("Routes() returned %d, want 3 -- one per contributor", n)
	}
	if cov := res.Coverage(); cov.InventoryUnionCount != 1 {
		t.Fatalf("record.DastCoverage.InventoryUnionCount = %d, want 1",
			cov.InventoryUnionCount)
	}
}

// TestConfirmingOneEndpointConfirmsItOnceAndKeepsEveryProvenance is the
// packet's "two independent axes" requirement stated as arithmetic.
func TestConfirmingOneEndpointConfirmsItOnceAndKeepsEveryProvenance(t *testing.T) {
	prober := confirmAnswering(200, nil)
	res := confirmRun(t, confirmConfirming(t, prober, 8),
		[]Route{confirmCandidate(t, authz.MethodGet, "/users", record.InventoryProvenanceRuntimeSpec)},
		[]Route{confirmCandidate(t, authz.MethodGet, "/users", record.InventoryProvenanceStaticExtraction)},
	)
	if res.EndpointCount() != 1 || res.ConfirmedCount() != 1 {
		t.Fatalf("union=%d confirmed=%d, want 1/1", res.EndpointCount(), res.ConfirmedCount())
	}
	if prober.calls != 1 {
		t.Fatalf("the prober was called %d times for one endpoint. A duplicate that is "+
			"probed twice spends budget twice for one answer", prober.calls)
	}

	// The routes keep their own provenance and gain the endpoint's
	// confirmation. Confirming a static_extraction candidate does not make it
	// a runtime_spec endpoint.
	var got []string
	for _, rt := range res.Routes() {
		got = append(got, fmt.Sprintf("%s/%s", rt.Provenance(), rt.Confirmation()))
	}
	sort.Strings(got)
	want := []string{"runtime_spec/confirmed", "static_extraction/confirmed"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("routes = %v, want %v", got, want)
	}
	mix := res.InventoryProvenanceMix()
	if mix[record.InventoryProvenanceRuntimeSpec] != 1 ||
		mix[record.InventoryProvenanceStaticExtraction] != 1 {
		t.Fatalf("provenance mix = %v", mix)
	}
}

// TestARouteThatArrivesClaimingConfirmedIsNotLaundered.
//
// This is the repo spec reader's retag lesson applied to the merge. A caller feeding a
// previous result's Routes() back in, or a tier that stamped `confirmed` by
// mistake, must not reach the numerator without THIS run observing the
// endpoint. The fixture is asserted to really carry the confirmation first, so
// a green result cannot be the fixture having rotted.
func TestARouteThatArrivesClaimingConfirmedIsNotLaundered(t *testing.T) {
	laundered := confirmRoute(t, authz.MethodGet, "/admin", "", // deliberately confirmed
		record.InventoryProvenanceStaticExtraction, ConfirmationConfirmed)
	if laundered.Confirmation() != ConfirmationConfirmed {
		t.Fatalf("the fixture does not carry the value under test: %s",
			laundered.Confirmation())
	}

	t.Run("merge only", func(t *testing.T) {
		res := confirmRun(t, ConfirmConfig{Target: mustBareTarget(t)}, []Route{laundered})
		e := confirmEndpoint(t, res, authz.MethodGet, "/admin")
		if e.Confirmed() || e.Confirmation() != ConfirmationCandidate {
			t.Fatalf("an unprobed route carried its own confirmation through the merge: "+
				"%s/%s", e.Confirmation(), e.Outcome())
		}
		if e.Outcome() != ConfirmOutcomeNotRequested {
			t.Fatalf("outcome = %q", e.Outcome())
		}
		if n := confirmNoteCount(res, MergeNoteInboundConfirmationDiscarded); n != 1 {
			t.Fatalf("%d inbound_confirmation_discarded notes, want 1. A silent discard "+
				"and a silent acceptance look identical in the output", n)
		}
		if res.ConfirmedCount() != 0 {
			t.Fatalf("ConfirmedCount()=%d", res.ConfirmedCount())
		}
	})

	t.Run("probed and 404", func(t *testing.T) {
		res := confirmRun(t, confirmConfirming(t, confirmAnswering(404, nil), 4), []Route{laundered})
		e := confirmEndpoint(t, res, authz.MethodGet, "/admin")
		if e.Confirmed() {
			t.Fatal("the target said 404 and the endpoint is confirmed; the inbound claim " +
				"outranked the observation")
		}
		if e.Outcome() != ConfirmOutcomeObserved404 {
			t.Fatalf("outcome = %q", e.Outcome())
		}
	})

	t.Run("probed but budget exhausted", func(t *testing.T) {
		cfg := confirmConfirming(t, confirmAnswering(200, nil), 1)
		res := confirmRun(t, cfg,
			[]Route{confirmCandidate(t, authz.MethodGet, "/a", record.InventoryProvenanceRuntimeSpec)},
			[]Route{laundered},
		)
		// "/a" sorts before "/admin", so "/a" spends the single unit.
		e := confirmEndpoint(t, res, authz.MethodGet, "/admin")
		if e.Confirmed() || e.Outcome() != ConfirmOutcomeBudgetExhausted {
			t.Fatalf("a route that arrived confirmed and was never probed came out %s/%s",
				e.Confirmation(), e.Outcome())
		}
	})
}

// TestManyOperationsOnOneAddressAreOneEndpointAndTheSecondNumberIsReported.
//
// A GraphQL schema's root fields all live on POST /graphql. One probe reaches
// them, so they are ONE endpoint — and collapsing them is the DEFLATING
// direction, which is why OperationCount() exists and why the merge leaves a
// note.
func TestManyOperationsOnOneAddressAreOneEndpointAndTheSecondNumberIsReported(t *testing.T) {
	var tier []Route
	for _, op := range []string{"user", "posts", "search"} {
		tier = append(tier, confirmRoute(t, authz.MethodPost, "/graphql", op,
			record.InventoryProvenanceRuntimeSpec, ConfirmationCandidate))
	}
	tier = append(tier, confirmCandidate(t, authz.MethodGet, "/health",
		record.InventoryProvenanceRuntimeSpec))

	res := confirmRun(t, ConfirmConfig{Target: mustBareTarget(t)}, tier)
	if res.EndpointCount() != 2 {
		t.Fatalf("union = %d, want 2: %v", res.EndpointCount(), confirmEndpointTable(res))
	}
	if res.OperationCount() != 4 {
		t.Fatalf("OperationCount() = %d, want 4 (three root fields plus one REST "+
			"endpoint with no operation name)", res.OperationCount())
	}
	e := confirmEndpoint(t, res, authz.MethodPost, "/graphql")
	if got := e.Operations(); !reflect.DeepEqual(got, []string{"posts", "search", "user"}) {
		t.Fatalf("operations = %v", got)
	}
	if n := confirmNoteCount(res, MergeNoteOperationsOnOneAddress); n != 1 {
		t.Fatalf("%d multiple_operations_on_one_address notes, want 1. Collapsing "+
			"operations onto an address SHRINKS the denominator, and a number that "+
			"shrinks a denominator has to be visible", n)
	}
}

// TestPlaceholderNameDivergenceIsReportedRatherThanMerged, with its negative
// control.
//
// "/users/{id}" and "/users/{userId}" are almost certainly one endpoint. They
// are counted as two, which INFLATES the denominator — the pessimistic
// direction — because merging them needs an opinion Go route extraction's canonicalizer
// deliberately does not have. The note is what stops the inflation being
// silent.
func TestPlaceholderNameDivergenceIsReportedRatherThanMerged(t *testing.T) {
	res := confirmRun(t, ConfirmConfig{Target: mustBareTarget(t)}, []Route{
		confirmCandidate(t, authz.MethodGet, "/users/{id}", record.InventoryProvenanceRuntimeSpec),
		confirmCandidate(t, authz.MethodGet, "/users/{userId}", record.InventoryProvenanceStaticExtraction),
	})
	if res.EndpointCount() != 2 {
		t.Fatalf("union = %d, want 2 -- the merge must not invent a rename rule",
			res.EndpointCount())
	}
	if n := confirmNoteCount(res, MergeNotePlaceholderNamesDiverge); n != 1 {
		t.Fatalf("%d placeholder_names_diverge notes, want 1", n)
	}

	// NEGATIVE CONTROL: different literal segments are different endpoints and
	// must NOT be reported, or the note carries no information.
	res = confirmRun(t, ConfirmConfig{Target: mustBareTarget(t)}, []Route{
		confirmCandidate(t, authz.MethodGet, "/users/{id}", record.InventoryProvenanceRuntimeSpec),
		confirmCandidate(t, authz.MethodGet, "/orgs/{id}", record.InventoryProvenanceRuntimeSpec),
	})
	if n := confirmNoteCount(res, MergeNotePlaceholderNamesDiverge); n != 0 {
		t.Fatalf("%d placeholder_names_diverge notes for two different paths; a note that "+
			"fires on everything is not a note", n)
	}
	// And a literal segment still matches by IDENTITY, not by position.
	res = confirmRun(t, ConfirmConfig{Target: mustBareTarget(t)}, []Route{
		confirmCandidate(t, authz.MethodGet, "/users/me", record.InventoryProvenanceRuntimeSpec),
		confirmCandidate(t, authz.MethodGet, "/users/{id}", record.InventoryProvenanceRuntimeSpec),
	})
	if res.EndpointCount() != 2 {
		t.Fatalf("a literal segment merged with a placeholder: %v", confirmEndpointTable(res))
	}
}

// TestAMergeIsNotADuplicateRefusal.
//
// RefusalDuplicateRoute is PER-OPERATION, so it raises DenominatorFloor inside
// a tier. Recording a cross-tier merge as one would add back exactly the rows
// the merge collapsed — the denominator inflating itself through the refusal
// list instead of the endpoint list.
func TestAMergeIsNotADuplicateRefusal(t *testing.T) {
	res := confirmRun(t, ConfirmConfig{Target: mustBareTarget(t)},
		[]Route{confirmCandidate(t, authz.MethodGet, "/users", record.InventoryProvenanceRuntimeSpec)},
		[]Route{confirmCandidate(t, authz.MethodGet, "/users", record.InventoryProvenanceRepoSpec)},
		[]Route{confirmCandidate(t, authz.MethodGet, "/users", record.InventoryProvenanceCrawl)},
	)
	if n := confirmRefusalCount(res, RefusalDuplicateRoute); n != 0 {
		t.Fatalf("%d duplicate_route refusals. That reason is per-operation and raises the "+
			"denominator floor; a cross-tier merge is not an extra operation", n)
	}
	if len(res.Refusals()) != 0 {
		t.Fatalf("the merge recorded refusals for a clean union: %v", res.Refusals())
	}
	if n := confirmNoteCount(res, MergeNoteRoutesCollapsed); n != 2 {
		t.Fatalf("%d collapse notes, want 2", n)
	}
}

// ===========================================================================
// THE PROBE BUDGET — research/22 Risk #4, the phpBB regression
// ===========================================================================

// TestTheProbeBudgetIsRespectedAndUnprobedCandidatesAreMarkedNotDropped is the
// plan's required validation: "Test reproducing the phpBB-style regression
// scenario (candidate list larger than probe budget) and asserting the budget
// is respected rather than exceeded, with unconfirmed candidates explicitly
// marked, not dropped."
func TestTheProbeBudgetIsRespectedAndUnprobedCandidatesAreMarkedNotDropped(t *testing.T) {
	var tier []Route
	for i := 0; i < 10; i++ {
		tier = append(tier, confirmCandidate(t, authz.MethodGet,
			fmt.Sprintf("/e%02d", i), record.InventoryProvenanceStaticExtraction))
	}
	prober := confirmAnswering(200, nil)
	res := confirmRun(t, confirmConfirming(t, prober, 3), tier)

	if res.EndpointCount() != 10 {
		t.Fatalf("the union is %d and the inventory declared 10. A candidate the budget "+
			"could not reach must stay in the DENOMINATOR", res.EndpointCount())
	}
	if res.Issued() != 3 || prober.calls != 3 {
		t.Fatalf("issued=%d proberCalls=%d, want 3 and 3 -- the budget was exceeded",
			res.Issued(), prober.calls)
	}
	if res.ConfirmedCount() != 3 {
		t.Fatalf("confirmed=%d, want 3", res.ConfirmedCount())
	}
	if n := confirmOutcomeCount(res, ConfirmOutcomeBudgetExhausted); n != 7 {
		t.Fatalf("%d endpoints carry budget_exhausted, want 7", n)
	}
	for _, e := range res.Endpoints() {
		if e.Outcome() != ConfirmOutcomeBudgetExhausted {
			continue
		}
		if e.Confirmation() != ConfirmationCandidate {
			t.Fatalf("%s was never probed and is %s", e, e.Confirmation())
		}
		if _, ok := e.Observation(); ok {
			t.Fatalf("%s was never probed and carries an observation", e)
		}
	}
	// The endpoints that WERE probed are the first three in the deterministic
	// order, not three arbitrary ones.
	want := []string{"GET /e00", "GET /e01", "GET /e02"}
	if got := prober.paths(); !reflect.DeepEqual(got, want) {
		t.Fatalf("the budget was spent on %v, want %v. Which endpoints a short budget "+
			"reaches must be a property of the inventory, not of map iteration order",
			got, want)
	}

	err := res.AssertBudgetSufficed()
	if !errors.Is(err, ErrProbeBudgetExhausted) {
		t.Fatalf("AssertBudgetSufficed returned %v, want ErrProbeBudgetExhausted", err)
	}
	for _, frag := range []string{"7 of 10", "budget of 3"} {
		if !strings.Contains(err.Error(), frag) {
			t.Fatalf("the error does not say %q: %v", frag, err)
		}
	}
	if len(res.UnprobedEndpoints()) != 7 {
		t.Fatalf("UnprobedEndpoints() = %d, want 7", len(res.UnprobedEndpoints()))
	}
}

// TestMoreEndpointsCanMeanLessCoverage states research/22's Risk #4 as
// arithmetic, in one test, so the regression is visible rather than argued.
//
// The same target, the same budget, the same prober. A BIGGER inventory
// produces a SMALLER endpoint_coverage — and the only thing that tells a
// reader the second number is a floor rather than a measurement is
// AssertBudgetSufficed.
func TestMoreEndpointsCanMeanLessCoverage(t *testing.T) {
	small := []Route{
		confirmCandidate(t, authz.MethodGet, "/a", record.InventoryProvenanceRuntimeSpec),
		confirmCandidate(t, authz.MethodGet, "/b", record.InventoryProvenanceRuntimeSpec),
		confirmCandidate(t, authz.MethodGet, "/c", record.InventoryProvenanceRuntimeSpec),
	}
	big := append([]Route(nil), small...)
	for i := 0; i < 7; i++ {
		big = append(big, confirmCandidate(t, authz.MethodGet,
			fmt.Sprintf("/z%d", i), record.InventoryProvenanceStaticExtraction))
	}

	first := confirmRun(t, confirmConfirming(t, confirmAnswering(200, nil), 3), small)
	second := confirmRun(t, confirmConfirming(t, confirmAnswering(200, nil), 3), big)

	if first.Coverage().EndpointCoverage != 1.0 {
		t.Fatalf("the small run reported %v, want 1", first.Coverage().EndpointCoverage)
	}
	if got := second.Coverage().EndpointCoverage; got != 0.3 {
		t.Fatalf("the big run reported %v, want 0.3", got)
	}
	if second.Coverage().EndpointCoverage >= first.Coverage().EndpointCoverage {
		t.Fatal("the regression this test exists to reproduce did not happen")
	}
	if second.EndpointCount() <= first.EndpointCount() {
		t.Fatal("the second inventory is not larger")
	}
	if err := first.AssertBudgetSufficed(); err != nil {
		t.Fatalf("the small run's coverage is a measurement and the assertion refused it: %v",
			err)
	}
	if err := second.AssertBudgetSufficed(); err == nil {
		t.Fatal("the big run's coverage is a FLOOR -- 7 of its 10 endpoints were never " +
			"asked about -- and AssertBudgetSufficed reported it as a measurement. That " +
			"is research/22 Risk #4 published as a number")
	}
}

// TestABudgetThatIsNotConfiguredIsRefused. There is no default, and zero does
// not mean unlimited.
func TestABudgetThatIsNotConfiguredIsRefused(t *testing.T) {
	for _, budget := range []int{0, -1, maxProbeBudget + 1} {
		t.Run(fmt.Sprint(budget), func(t *testing.T) {
			cfg := confirmConfirming(t, confirmAnswering(200, nil), 4)
			cfg.ProbeBudget = budget
			_, err := MergeAndConfirm(context.Background(), cfg, mustClock(t), []Route{
				confirmCandidate(t, authz.MethodGet, "/a", record.InventoryProvenanceRuntimeSpec),
			})
			if !errors.Is(err, ErrRefused) {
				t.Fatalf("budget %d was accepted (%v)", budget, err)
			}
		})
	}
}

// TestAKernelRefusalCostsNoProbeBudget is the OTHER half of the starvation
// story, and it is why the budget counts requests that LEFT.
//
// A hundred state-changing endpoints gate 15 refuses would otherwise spend the
// whole budget on requests that never went anywhere, and the readable
// endpoints behind them would report budget_exhausted — a starvation Anvil
// caused, reported as a fact about the target.
func TestAKernelRefusalCostsNoProbeBudget(t *testing.T) {
	prober := confirmAnswering(200, nil)
	// "/a-delete" sorts first, so the refused endpoint is reached before the
	// probeable one and would spend the budget if refusals cost anything.
	res := confirmRun(t, confirmConfirming(t, prober, 1), []Route{
		confirmCandidate(t, authz.MethodDelete, "/a-delete", record.InventoryProvenanceRuntimeSpec),
		confirmCandidate(t, authz.MethodGet, "/b-get", record.InventoryProvenanceRuntimeSpec),
	})
	del := confirmEndpoint(t, res, authz.MethodDelete, "/a-delete")
	if del.Outcome() != ConfirmOutcomeKernelRefused {
		t.Fatalf("a DELETE with no operator allowance came out %q; gate 15 refuses "+
			"state-changing methods without a per-endpoint allow", del.Outcome())
	}
	if del.Confirmed() {
		t.Fatal("a kernel-refused endpoint is confirmed")
	}
	get := confirmEndpoint(t, res, authz.MethodGet, "/b-get")
	if !get.Confirmed() {
		t.Fatalf("the probeable endpoint came out %s/%s -- the refusal spent the budget",
			get.Confirmation(), get.Outcome())
	}
	if res.Issued() != 1 || prober.calls != 1 {
		t.Fatalf("issued=%d calls=%d, want 1/1", res.Issued(), prober.calls)
	}
	if res.EndpointCount() != 2 {
		t.Fatalf("the refused endpoint left the denominator: %v", confirmEndpointTable(res))
	}
	// The refusal names the gate, so an operator can see WHICH rule refused.
	found := false
	for _, r := range res.Refusals() {
		if r.Reason == RefusalKernelRefused && strings.Contains(r.Detail, "gate15") {
			found = true
		}
	}
	if !found {
		t.Fatalf("no refusal names gate15: %v", res.Refusals())
	}
}

// ===========================================================================
// THE KERNEL IS REALLY IN THE PATH
// ===========================================================================

// TestGate11RemovesAPathAndTheEndpointStaysInTheDenominator drives a real
// robots.txt through the real gate 11 in the Governor's per-request chain.
func TestGate11RemovesAPathAndTheEndpointStaysInTheDenominator(t *testing.T) {
	policy := authz.ParseRobotsTxt(fixtureHost, 443,
		[]byte("User-agent: *\nDisallow: /private\n"))
	if !policy.Determined() {
		t.Fatalf("the fixture robots.txt did not produce a determined policy")
	}
	if policy.PermitsPath("/private") {
		t.Fatal("the fixture robots.txt does not actually disallow /private, so this test " +
			"would prove nothing")
	}
	gov, audit, _ := confirmKernel(t, confirmKernelOpts{robots: &policy})
	auth, _ := mintAuthorization(t)
	prober := confirmAnswering(200, nil)
	res := confirmRun(t, ConfirmConfig{
		Governor: gov, Audit: audit, Authorization: auth, Target: mustBareTarget(t),
		Confirm: true, ProbeBudget: 8, Technique: authz.TechniqueContentDiscovery,
		Prober: prober, Clock: confirmAdvancing(t, time.Second),
	}, []Route{
		confirmCandidate(t, authz.MethodGet, "/private", record.InventoryProvenanceRepoSpec),
		confirmCandidate(t, authz.MethodGet, "/public", record.InventoryProvenanceRepoSpec),
	})

	priv := confirmEndpoint(t, res, authz.MethodGet, "/private")
	if priv.Outcome() != ConfirmOutcomeKernelRefused || priv.Confirmed() {
		t.Fatalf("/private came out %s/%s; gate 11 removes it", priv.Confirmation(),
			priv.Outcome())
	}
	if !confirmEndpoint(t, res, authz.MethodGet, "/public").Confirmed() {
		t.Fatal("/public was not confirmed")
	}
	if got := prober.paths(); !reflect.DeepEqual(got, []string{"GET /public"}) {
		t.Fatalf("the prober saw %v; a path robots.txt removes must never leave", got)
	}
	if res.EndpointCount() != 2 {
		t.Fatal("a path the kernel removed from SCOPE also left the coverage denominator; " +
			"it is still attack surface that exists")
	}
}

// TestGate14RefusesTheOverflowWhenTheClockDoesNotAdvance measures the
// consequence ClockSource exists for, rather than asserting it in a comment.
//
// The token bucket holds authz.CodedMaxRequestsPerSecondPerHost tokens and
// refills from the ELAPSED interval. With one frozen instant the eleventh
// probe is refused — correctly, by the kernel — and the endpoints behind it
// stay in the union carrying kernel_refused.
func TestGate14RefusesTheOverflowWhenTheClockDoesNotAdvance(t *testing.T) {
	var tier []Route
	const n = 12
	for i := 0; i < n; i++ {
		tier = append(tier, confirmCandidate(t, authz.MethodGet,
			fmt.Sprintf("/e%02d", i), record.InventoryProvenanceRuntimeSpec))
	}
	gov, audit, _ := confirmKernel(t, confirmKernelOpts{})
	auth, _ := mintAuthorization(t)
	frozen := ConfirmConfig{
		Governor: gov, Audit: audit, Authorization: auth, Target: mustBareTarget(t),
		Confirm: true, ProbeBudget: n, Technique: authz.TechniqueContentDiscovery,
		Prober: confirmAnswering(200, nil),
		// No Clock: the run instant is reused for every probe.
	}
	res := confirmRun(t, frozen, tier)
	if res.ConfirmedCount() != authz.CodedMaxRequestsPerSecondPerHost {
		t.Fatalf("confirmed=%d, want %d -- the bucket holds exactly that many tokens and "+
			"a frozen clock never refills it",
			res.ConfirmedCount(), authz.CodedMaxRequestsPerSecondPerHost)
	}
	if got := confirmOutcomeCount(res, ConfirmOutcomeKernelRefused); got != n-authz.CodedMaxRequestsPerSecondPerHost {
		t.Fatalf("%d endpoints kernel_refused, want %d", got,
			n-authz.CodedMaxRequestsPerSecondPerHost)
	}
	if res.EndpointCount() != n {
		t.Fatalf("the union is %d, want %d -- nothing may be dropped",
			res.EndpointCount(), n)
	}

	// The same inventory with an advancing clock confirms every endpoint. The
	// difference is Anvil's clock handling and nothing about the target, which
	// is exactly why the seam is not optional in a real run.
	advancing := confirmConfirming(t, confirmAnswering(200, nil), n)
	res2 := confirmRun(t, advancing, tier)
	if res2.ConfirmedCount() != n {
		t.Fatalf("with an advancing clock confirmed=%d, want %d: %v",
			res2.ConfirmedCount(), n, confirmEndpointTable(res2))
	}
}

// TestTheObservationIsFedBackToTheKernelAndCanStopTheRun.
//
// A confirmation loop that admits through the kernel and never TELLS the
// kernel what happened is a loop with no circuit breaker and no Retry-After:
// gate 16 and gate 17 both learn only from Governor.ObserveResponse. This
// drives one 429 and asserts the NEXT endpoint is refused at gate 17, which is
// the observable consequence of the feedback being wired.
//
// The 429 endpoint is itself CONFIRMED, and that is correct: a rate-limited
// route is a route that exists.
func TestTheObservationIsFedBackToTheKernelAndCanStopTheRun(t *testing.T) {
	prober := confirmAnswering(200, map[string]int{"/a": 429})
	res := confirmRun(t, confirmConfirming(t, prober, 8), []Route{
		confirmCandidate(t, authz.MethodGet, "/a", record.InventoryProvenanceRuntimeSpec),
		confirmCandidate(t, authz.MethodGet, "/b", record.InventoryProvenanceRuntimeSpec),
		confirmCandidate(t, authz.MethodGet, "/c", record.InventoryProvenanceRuntimeSpec),
	})
	a := confirmEndpoint(t, res, authz.MethodGet, "/a")
	if !a.Confirmed() {
		t.Fatalf("/a answered 429 and came out %s/%s; a rate-limited route exists",
			a.Confirmation(), a.Outcome())
	}
	for _, p := range []string{"/b", "/c"} {
		e := confirmEndpoint(t, res, authz.MethodGet, p)
		if e.Outcome() != ConfirmOutcomeKernelRefused {
			t.Fatalf("%s came out %q after the target said 429. Gate 17 learns about a "+
				"429 only through Governor.ObserveResponse, so a loop that does not feed "+
				"its observations back keeps probing a target that asked it to stop",
				p, e.Outcome())
		}
	}
	if got := prober.paths(); !reflect.DeepEqual(got, []string{"GET /a"}) {
		t.Fatalf("the prober saw %v after a 429", got)
	}
	if res.EndpointCount() != 3 {
		t.Fatal("the backed-off endpoints left the denominator")
	}
	if err := res.AssertBudgetSufficed(); err != nil {
		t.Fatalf("the run stopped for a kernel reason and not for a budget reason: %v", err)
	}
}

// TestTheKernelValidatesTheProbePathRatherThanASecondValidator.
func TestTheKernelValidatesTheProbePathRatherThanASecondValidator(t *testing.T) {
	// NewRoute accepts this path -- it is printable ASCII with no dot segment
	// -- and Go route extraction's canonicalizer refuses the placeholder name, because
	// sanitizing it would fold two distinct placeholders onto one row.
	bad := confirmCandidate(t, authz.MethodGet, "/a/{bad-name}", record.InventoryProvenanceRepoSpec)
	if !bad.Constructed() {
		t.Fatal("the fixture route was not built, so this test proves nothing")
	}
	res := confirmRun(t, ConfirmConfig{Target: mustBareTarget(t)}, []Route{
		bad,
		confirmCandidate(t, authz.MethodGet, "/ok", record.InventoryProvenanceRepoSpec),
	})
	if res.EndpointCount() != 1 {
		t.Fatalf("union = %d, want 1: %v", res.EndpointCount(), confirmEndpointTable(res))
	}
	if n := confirmRefusalCount(res, RefusalPathRejectedByKernel); n != 1 {
		t.Fatalf("%d path refusals, want 1: %v", n, res.Refusals())
	}
	if res.Accepted() != 1 || res.Offered() != 2 {
		t.Fatalf("offered=%d accepted=%d", res.Offered(), res.Accepted())
	}
}

// TestRoutesOnAnotherTargetAreRefusedNotCounted. One coverage fraction over
// two hosts is meaningless.
func TestRoutesOnAnotherTargetAreRefusedNotCounted(t *testing.T) {
	other, err := authz.NewTarget(authz.SchemeHTTPS, "other.example.com", "other.example.com",
		443, mustAddr(t, "198.51.100.8"))
	if err != nil {
		t.Fatalf("authz.NewTarget: %v", err)
	}
	foreign, err := NewRoute(RouteFacts{
		Method: authz.MethodGet, Path: "/x", Target: other,
		Provenance: record.InventoryProvenanceCrawl, Confirmation: ConfirmationCandidate,
		Trust: record.TrustUntrusted,
	})
	if err != nil {
		t.Fatalf("NewRoute: %v", err)
	}
	res := confirmRun(t, ConfirmConfig{Target: mustBareTarget(t)}, []Route{
		foreign,
		confirmCandidate(t, authz.MethodGet, "/ours", record.InventoryProvenanceRuntimeSpec),
	})
	if res.EndpointCount() != 1 {
		t.Fatalf("union = %d, want 1: %v", res.EndpointCount(), confirmEndpointTable(res))
	}
	if n := confirmRefusalCount(res, RefusalKernelRefused); n != 1 {
		t.Fatalf("%d refusals for the foreign route", n)
	}
	// sameTarget compares by identity, and a Target that was never built is
	// not the same as anything -- including another unbuilt one.
	if sameTarget(authz.Target{}, authz.Target{}) {
		t.Fatal("two unconstructed Targets compared equal")
	}
	if !sameTarget(mustBareTarget(t), mustBareTarget(t)) {
		t.Fatal("two identical Targets compared unequal")
	}
}

// TestAnUnconstructedRouteIsRefusedNotCounted.
func TestAnUnconstructedRouteIsRefusedNotCounted(t *testing.T) {
	res := confirmRun(t, ConfirmConfig{Target: mustBareTarget(t)}, []Route{
		{}, // a composite literal from another package looks exactly like this
		confirmCandidate(t, authz.MethodGet, "/ok", record.InventoryProvenanceRuntimeSpec),
	})
	if res.EndpointCount() != 1 || res.Accepted() != 1 || res.Offered() != 2 {
		t.Fatalf("union=%d accepted=%d offered=%d", res.EndpointCount(), res.Accepted(),
			res.Offered())
	}
	if n := confirmRefusalCount(res, RefusalRouteUnconstructible); n != 1 {
		t.Fatalf("%d unconstructible refusals", n)
	}
}

// ===========================================================================
// CONCRETIZATION — a template is not a request
// ===========================================================================

// TestATemplatedPathIsAnHonestCandidateWithoutAConcretizer.
func TestATemplatedPathIsAnHonestCandidateWithoutAConcretizer(t *testing.T) {
	prober := confirmAnswering(200, nil)
	res := confirmRun(t, confirmConfirming(t, prober, 8), []Route{
		confirmCandidate(t, authz.MethodGet, "/users/{id}", record.InventoryProvenanceRuntimeSpec),
		confirmCandidate(t, authz.MethodGet, "/health", record.InventoryProvenanceRuntimeSpec),
	})
	e := confirmEndpoint(t, res, authz.MethodGet, "/users/{id}")
	if e.Outcome() != ConfirmOutcomeTemplatedPathNotConcretized || e.Confirmed() {
		t.Fatalf("/users/{id} came out %s/%s", e.Confirmation(), e.Outcome())
	}
	if !e.Templated() {
		t.Fatal("Templated() is false for a path with a placeholder")
	}
	if got := prober.paths(); !reflect.DeepEqual(got, []string{"GET /health"}) {
		t.Fatalf("the prober saw %v; Anvil must not invent a value for {id}", got)
	}
	if res.EndpointCount() != 2 {
		t.Fatal("the templated endpoint left the denominator")
	}
	if res.Issued() != 1 {
		t.Fatalf("Issued()=%d; an unprobeable endpoint must not spend budget", res.Issued())
	}
}

// TestAConcretizerDrivesARealObservationAndItsSourceIsRecorded.
func TestAConcretizerDrivesARealObservationAndItsSourceIsRecorded(t *testing.T) {
	conc := confirmFixed("/users/42", "operator fixture dataset rev 7")
	cfg := confirmConfirming(t, confirmAnswering(200, map[string]int{"/users/42": 200}), 8)
	cfg.Concretizer = conc
	res := confirmRun(t, cfg, []Route{
		confirmCandidate(t, authz.MethodGet, "/users/{id}", record.InventoryProvenanceRuntimeSpec),
	})
	e := confirmEndpoint(t, res, authz.MethodGet, "/users/{id}")
	if !e.Confirmed() {
		t.Fatalf("the concretized endpoint came out %s/%s", e.Confirmation(), e.Outcome())
	}
	if e.Path() != "/users/{id}" {
		t.Fatalf("the endpoint's identity became %q; the union keys on the TEMPLATE",
			e.Path())
	}
	obs, _ := e.Observation()
	if obs.Path() != "/users/42" {
		t.Fatalf("the observation records %q; a reviewer needs the path that actually "+
			"went out in order to reproduce it", obs.Path())
	}
	if e.ConcretizedFrom() != "operator fixture dataset rev 7" {
		t.Fatalf("ConcretizedFrom() = %q", e.ConcretizedFrom())
	}
	if conc.calls != 1 || !reflect.DeepEqual(conc.seen, []string{"/users/{id}"}) {
		t.Fatalf("the concretizer saw %v across %d calls", conc.seen, conc.calls)
	}
}

// TestAHostileConcretizerCannotMoveTheProbe.
//
// A concretizer is outside Anvil. If it can change the path, it can choose
// which endpoint gets probed and which one the observation is attributed to.
func TestAHostileConcretizerCannotMoveTheProbe(t *testing.T) {
	cases := []struct {
		name          string
		path, source  string
		err           error
		wantRefusedBy string
	}{
		{name: "a different endpoint entirely", path: "/admin", source: "s"},
		{name: "an extra segment", path: "/users/42/secrets", source: "s"},
		{name: "a missing segment", path: "/users", source: "s"},
		{name: "a different literal segment", path: "/admins/42", source: "s"},
		{name: "still templated", path: "/users/{id}", source: "s"},
		{name: "an empty segment", path: "/users/", source: "s"},
		{name: "an absolute URL", path: "https://evil.example.com/users/42", source: "s"},
		{name: "a relative path", path: "users/42", source: "s"},
		{name: "no source named", path: "/users/42", source: ""},
		{name: "an error", path: "", source: "", err: errors.New("no value available")},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path, source, cerr := tc.path, tc.source, tc.err
			conc := &confirmConcretizer{fn: func(string) (string, string, error) {
				return path, source, cerr
			}}
			prober := confirmAnswering(200, nil)
			cfg := confirmConfirming(t, prober, 8)
			cfg.Concretizer = conc
			res := confirmRun(t, cfg, []Route{
				confirmCandidate(t, authz.MethodGet, "/users/{id}",
					record.InventoryProvenanceRuntimeSpec),
			})
			e := confirmEndpoint(t, res, authz.MethodGet, "/users/{id}")
			if e.Confirmed() {
				t.Fatalf("the concretizer returning %q confirmed the endpoint", tc.path)
			}
			if e.Outcome() != ConfirmOutcomeConcretizationRefused {
				t.Fatalf("outcome = %q, want concretization_refused", e.Outcome())
			}
			if prober.calls != 0 {
				t.Fatalf("the prober was called with %v", prober.paths())
			}
			if res.Issued() != 0 {
				t.Fatalf("Issued()=%d", res.Issued())
			}
			if res.EndpointCount() != 1 {
				t.Fatal("the endpoint left the denominator")
			}
		})
	}
	// POSITIVE CONTROL: the matcher accepts a genuine concretization, or the
	// table above would pass for the wrong reason.
	if !concretePathMatches("/users/{id}", "/users/42") {
		t.Fatal("concretePathMatches rejects a genuine concretization, so every case " +
			"above is vacuous")
	}
	if !concretePathMatches("/a/{x}/b/{y}", "/a/1/b/2") {
		t.Fatal("concretePathMatches rejects a two-placeholder concretization")
	}
}

// ===========================================================================
// THE ENUMS, THE INVARIANTS, THE COPIES
// ===========================================================================

// TestExactlyOneOutcomeConfirms, and the zero value is not it.
func TestExactlyOneOutcomeConfirms(t *testing.T) {
	confirming := 0
	for _, o := range ConfirmOutcomeValues() {
		if !o.Valid() {
			t.Fatalf("%q is in the value list and reports itself invalid", o)
		}
		if o.Confirms() {
			confirming++
			if o != ConfirmOutcomeObservedNon404 {
				t.Fatalf("%q confirms, and only observed_non_404 may", o)
			}
			if o.MeansAnvilCouldNotLook() {
				t.Fatalf("%q confirms and is classified as a limit of Anvil", o)
			}
		}
	}
	if confirming != 1 {
		t.Fatalf("%d outcomes confirm, want exactly 1", confirming)
	}
	if ConfirmOutcomeUnset.Confirms() {
		t.Fatal("the ZERO VALUE confirms. A Go zero value must never mean permitted, and " +
			"here permitted means counted in endpoint_coverage's numerator")
	}
	if ConfirmOutcomeUnset.Valid() {
		t.Fatal("the zero value is a legal outcome")
	}
	if !ConfirmOutcomeUnset.MeansAnvilCouldNotLook() {
		t.Fatal("an endpoint whose outcome nobody set is reported as looked at")
	}
	// Every outcome in which the target did NOT answer is a limit of Anvil.
	answered := map[ConfirmOutcome]bool{
		ConfirmOutcomeObservedNon404: true, ConfirmOutcomeObserved404: true,
	}
	for _, o := range ConfirmOutcomeValues() {
		if o.MeansAnvilCouldNotLook() == answered[o] {
			t.Fatalf("%q is classified as %v and the target answered = %v",
				o, o.MeansAnvilCouldNotLook(), answered[o])
		}
	}
	// Mutating the returned list must not move the classifier.
	vals := ConfirmOutcomeValues()
	for i := range vals {
		vals[i] = "tampered"
	}
	if !ConfirmOutcomeObservedNon404.Confirms() || ConfirmOutcome("tampered").Valid() {
		t.Fatal("the outcome vocabulary is reachable through the slice it returns")
	}
}

// TestEveryMergeNoteReasonIsRecognised.
func TestEveryMergeNoteReasonIsRecognised(t *testing.T) {
	if MergeNoteUnset.Recognised() {
		t.Fatal("the zero MergeNoteReason is recognised")
	}
	for _, r := range MergeNoteReasonValues() {
		if !r.Recognised() {
			t.Fatalf("%q is in the list and not recognised", r)
		}
		if !(MergeNote{Reason: r}).Valid() {
			t.Fatalf("a note carrying %q is invalid", r)
		}
	}
}

// TestAConfirmationCannotExistWithoutAnObservation exercises the two
// assertions in both directions, by building the corrupt state directly.
//
// The invariant is structural — confirmationFor is the only writer — but a
// structural claim nobody checks is a claim, and the assertions themselves
// need a red before they can be trusted.
func TestAConfirmationCannotExistWithoutAnObservation(t *testing.T) {
	good := confirmRun(t, confirmConfirming(t, confirmAnswering(200, nil), 4), []Route{
		confirmCandidate(t, authz.MethodGet, "/a", record.InventoryProvenanceRuntimeSpec),
	})
	if err := good.AssertEveryConfirmationHasEvidence(); err != nil {
		t.Fatalf("a real confirmation failed the assertion: %v", err)
	}

	// Strip the evidence and the assertion must fire.
	corrupt := good
	corrupt.endpoints = cloneEndpoints(good.endpoints)
	corrupt.endpoints[0].obs = Observation{}
	if err := corrupt.AssertEveryConfirmationHasEvidence(); !errors.Is(err, ErrConfirmationWithoutEvidence) {
		t.Fatalf("an outcome of %q with no observation passed the assertion (%v)",
			corrupt.endpoints[0].outcome, err)
	}
	if corrupt.endpoints[0].Confirmed() {
		t.Fatal("Confirmed() is true with no observation behind it")
	}
	if corrupt.ConfirmedCount() != 0 {
		t.Fatal("ConfirmedCount counted an endpoint with no observation")
	}

	// An observation whose audit row never landed is not evidence either.
	corrupt2 := good
	corrupt2.endpoints = cloneEndpoints(good.endpoints)
	corrupt2.endpoints[0].obs.auditSeq = 0
	if corrupt2.endpoints[0].Confirmed() {
		t.Fatal("an observation with audit sequence 0 confirmed an endpoint. Gate 21 " +
			"makes the audit write part of the decision")
	}
	if err := corrupt2.AssertEveryConfirmationHasEvidence(); err == nil {
		t.Fatal("the assertion accepted an observation with no gate-21 row")
	}

	// And a 404 recorded under a confirming outcome is a contradiction.
	corrupt3 := good
	corrupt3.endpoints = cloneEndpoints(good.endpoints)
	corrupt3.endpoints[0].obs.status = 404
	if err := corrupt3.AssertEveryConfirmationHasEvidence(); err == nil {
		t.Fatal("an outcome of observed_non_404 whose observation records 404 passed")
	}

	// The other direction: an outcome that does not confirm may not report
	// Confirmed().
	corrupt4 := good
	corrupt4.endpoints = cloneEndpoints(good.endpoints)
	corrupt4.endpoints[0].outcome = ConfirmOutcomeObserved404
	if err := corrupt4.AssertNoUnconfirmedEndpointClaimsConfirmation(); err != nil {
		t.Fatalf("a 404 outcome with a 200 observation reported Confirmed(): %v", err)
	}
}

// TestResultAccessorsReturnDeepCopies.
//
// The house has found three times that a test which mutates only the field
// where the copy is real proves nothing. Every mutation below goes through a
// NESTED reference — the provenance slice inside an endpoint, the operation
// slice inside an endpoint, the Params slice inside a contributor Route — and
// through both maps.
func TestConfirmResultAccessorsReturnDeepCopies(t *testing.T) {
	res := confirmRun(t, ConfirmConfig{Target: mustBareTarget(t)},
		[]Route{confirmRoute(t, authz.MethodGet, "/users/{id}", "getUser",
			record.InventoryProvenanceRuntimeSpec, ConfirmationCandidate,
			Param{Name: "id", In: ParamInPath, Type: "string", Required: true})},
		[]Route{confirmRoute(t, authz.MethodGet, "/users/{id}", "fetchUser",
			record.InventoryProvenanceRepoSpec, ConfirmationCandidate)},
	)

	eps := res.Endpoints()
	if len(eps) != 1 {
		t.Fatalf("union = %d", len(eps))
	}
	eps[0].provenances[0] = "tampered"
	eps[0].operations[0] = "tampered"
	eps[0].path = "/tampered"
	if got := res.Endpoints()[0]; got.path != "/users/{id}" ||
		got.provenances[0] != record.InventoryProvenanceRuntimeSpec ||
		got.operations[0] != "fetchUser" {
		t.Fatalf("mutating the returned endpoint reached the result: %+v", got)
	}

	// THE COPY INSIDE cloneEndpoints, EXERCISED WHERE IT IS REAL.
	//
	// The first version of this test mutated a contributor obtained through
	// Contributors(), which copies again — so breaking cloneEndpoints' own
	// deep copy left the suite GREEN. That is the shape the house has found
	// three times: a mutation aimed at a field where a SECOND copy is already
	// covering the first. The mutation below goes through the endpoint value
	// cloneEndpoints returned, and it goes through the Params slice NESTED
	// inside the contributor Route rather than through the Route struct
	// itself.
	eps2 := res.Endpoints()
	var withParams int
	for i := range eps2[0].contributor {
		if len(eps2[0].contributor[i].params) > 0 {
			withParams++
			eps2[0].contributor[i].params[0].Name = "tampered"
		}
		// The OUTER field. A shallow slice copy already protects this one, so
		// on its own it proves nothing — it is here to show which half of the
		// copy each mutation is actually testing.
		eps2[0].contributor[i].path = "/tampered"
	}
	if withParams == 0 {
		t.Fatal("no contributor carries a parameter, so the nested mutation is vacuous")
	}
	for _, c := range res.Endpoints()[0].contributor {
		if c.path == "/tampered" {
			t.Fatal("mutating the contributor Route's own field reached the result")
		}
		for _, p := range c.params {
			if p.Name == "tampered" {
				t.Fatal("mutating Params -- the slice NESTED inside a contributor Route -- " +
					"reached the result. cloneEndpoints must deep-copy through cloneRoutes")
			}
		}
	}
	// And the exported accessor is a copy on top of that copy.
	contribs := res.Endpoints()[0].Contributors()
	if len(contribs) != 2 {
		t.Fatalf("%d contributors", len(contribs))
	}
	for i := range contribs {
		for j := range contribs[i].params {
			contribs[i].params[j].Name = "tampered"
		}
	}
	for _, c := range res.Endpoints()[0].Contributors() {
		for _, p := range c.Params() {
			if p.Name == "tampered" {
				t.Fatal("Contributors() shares its Params with the result")
			}
		}
	}

	// THE ACCESSORS' OWN SLICES, CALLED TWICE ON ONE ENDPOINT.
	//
	// The first version re-read res.Endpoints() between the mutation and the
	// check, which hands back a fresh copy every time and so could not see
	// Provenances() aliasing. A caller holds ONE MergedEndpoint and calls the
	// accessor more than once; that is the shape that exposes it.
	one := res.Endpoints()[0]
	prov := one.Provenances()
	prov[0] = "tampered"
	if one.Provenances()[0] == "tampered" {
		t.Fatal("Provenances() hands out the endpoint's own slice; two calls on one " +
			"endpoint share a backing array")
	}
	ops := one.Operations()
	ops[0] = "tampered"
	if one.Operations()[0] == "tampered" {
		t.Fatal("Operations() hands out the endpoint's own slice")
	}
	contribOnce := one.Contributors()
	if len(contribOnce) > 0 {
		contribOnce[0].path = "/tampered"
		if one.Contributors()[0].Path() == "/tampered" {
			t.Fatal("Contributors() hands out the endpoint's own slice")
		}
	}

	notes := res.Notes()
	if len(notes) == 0 {
		t.Fatal("no notes, so the note mutation is vacuous")
	}
	notes[0].Detail = "tampered"
	if res.Notes()[0].Detail == "tampered" {
		t.Fatal("Notes() shares its slice with the result")
	}

	// Both maps, existing key and injected key.
	mix := res.InventoryProvenanceMix()
	mix[record.InventoryProvenanceRuntimeSpec] = 99
	mix[record.InventoryProvenanceCrawl] = 99
	if m := res.InventoryProvenanceMix(); m[record.InventoryProvenanceRuntimeSpec] != 1 ||
		m[record.InventoryProvenanceCrawl] != 0 {
		t.Fatalf("InventoryProvenanceMix shares its map: %v", m)
	}
	om := res.OutcomeMix()
	om[ConfirmOutcomeObservedNon404] = 99
	if res.OutcomeMix()[ConfirmOutcomeObservedNon404] != 0 {
		t.Fatal("OutcomeMix shares its map")
	}

	// UnprobedEndpoints is a copy too.
	up := res.UnprobedEndpoints()
	if len(up) != 1 {
		t.Fatalf("%d unprobed endpoints", len(up))
	}
	up[0].path = "/tampered"
	if res.UnprobedEndpoints()[0].path == "/tampered" {
		t.Fatal("UnprobedEndpoints shares its endpoints with the result")
	}
}

// TestOutputIsDeterministic.
func TestConfirmOutputIsDeterministic(t *testing.T) {
	build := func() []Route {
		return []Route{
			confirmCandidate(t, authz.MethodGet, "/z", record.InventoryProvenanceCrawl),
			confirmCandidate(t, authz.MethodGet, "/a", record.InventoryProvenanceRuntimeSpec),
			confirmRoute(t, authz.MethodPost, "/graphql", "b", record.InventoryProvenanceRuntimeSpec,
				ConfirmationCandidate),
			confirmRoute(t, authz.MethodPost, "/graphql", "a", record.InventoryProvenanceRepoSpec,
				ConfirmationCandidate),
			confirmCandidate(t, authz.MethodGet, "/m/{id}", record.InventoryProvenanceRepoSpec),
			confirmCandidate(t, authz.MethodGet, "/m/{key}", record.InventoryProvenanceCrawl),
			confirmCandidate(t, authz.MethodGet, "/a", record.InventoryProvenanceStaticExtraction),
		}
	}
	var firstTable, firstNotes, firstProbed []string
	for i := 0; i < 9; i++ {
		prober := confirmAnswering(200, nil)
		res := confirmRun(t, confirmConfirming(t, prober, 3), build())
		table := confirmEndpointTable(res)
		var notes []string
		for _, n := range res.Notes() {
			notes = append(notes, n.String())
		}
		probed := prober.paths()
		if i == 0 {
			firstTable, firstNotes, firstProbed = table, notes, probed
			continue
		}
		if !reflect.DeepEqual(table, firstTable) {
			t.Fatalf("run %d endpoints = %v, run 0 = %v", i, table, firstTable)
		}
		if !reflect.DeepEqual(notes, firstNotes) {
			t.Fatalf("run %d notes = %v, run 0 = %v", i, notes, firstNotes)
		}
		if !reflect.DeepEqual(probed, firstProbed) {
			t.Fatalf("run %d spent the budget on %v, run 0 on %v. An unstable answer to "+
				"\"which endpoints did we confirm\" is an unstable coverage number for an "+
				"unchanged target", i, probed, firstProbed)
		}
	}
}

// TestTheUnionDoesNotDependOnTheOrderTheTiersArriveIn.
//
// FOUND BY A BREAK THAT STAYED GREEN. Removing SortEndpoints left every test
// passing, because the accumulator preserves ARRIVAL order and every fixture
// happened to hand its routes over already sorted — so "deterministic" was
// being proved against repeated runs of one caller rather than against two
// callers who assembled the same inventory differently.
//
// It matters because the probe budget is spent in this order. Two runs over
// the same target that concatenated Tier 0, 1 and 2 in a different sequence
// would otherwise confirm DIFFERENT endpoints and report the same coverage
// fraction over a different set — which is a number that cannot be compared
// with itself between runs.
func TestTheUnionDoesNotDependOnTheOrderTheTiersArriveIn(t *testing.T) {
	a := func() []Route {
		return []Route{
			confirmCandidate(t, authz.MethodGet, "/alpha", record.InventoryProvenanceRuntimeSpec),
			confirmCandidate(t, authz.MethodGet, "/mike", record.InventoryProvenanceRuntimeSpec),
		}
	}
	b := func() []Route {
		return []Route{
			confirmCandidate(t, authz.MethodGet, "/zulu", record.InventoryProvenanceRepoSpec),
			confirmCandidate(t, authz.MethodGet, "/bravo", record.InventoryProvenanceRepoSpec),
		}
	}
	c := func() []Route {
		return []Route{
			confirmCandidate(t, authz.MethodGet, "/kilo", record.InventoryProvenanceStaticExtraction),
		}
	}

	forward := confirmAnswering(200, nil)
	fwd := confirmRun(t, confirmConfirming(t, forward, 2), a(), b(), c())
	reverse := confirmAnswering(200, nil)
	rev := confirmRun(t, confirmConfirming(t, reverse, 2), c(), b(), a())

	if !reflect.DeepEqual(confirmEndpointTable(fwd), confirmEndpointTable(rev)) {
		t.Fatalf("the union depends on tier order:\n  forward %v\n  reverse %v",
			confirmEndpointTable(fwd), confirmEndpointTable(rev))
	}
	want := []string{"GET /alpha", "GET /bravo"}
	if got := forward.paths(); !reflect.DeepEqual(got, want) {
		t.Fatalf("forward spent the budget on %v, want %v", got, want)
	}
	if got := reverse.paths(); !reflect.DeepEqual(got, want) {
		t.Fatalf("reverse spent the budget on %v, want %v. Which endpoints a short budget "+
			"reaches must be a property of the INVENTORY, not of the order the caller "+
			"concatenated the tiers in", got, want)
	}

	// The same, within one tier: the routes shuffled among themselves.
	shuffledProber := confirmAnswering(200, nil)
	shuffled := confirmRun(t, confirmConfirming(t, shuffledProber, 2), []Route{
		confirmCandidate(t, authz.MethodGet, "/kilo", record.InventoryProvenanceStaticExtraction),
		confirmCandidate(t, authz.MethodGet, "/zulu", record.InventoryProvenanceRepoSpec),
		confirmCandidate(t, authz.MethodGet, "/mike", record.InventoryProvenanceRuntimeSpec),
		confirmCandidate(t, authz.MethodGet, "/bravo", record.InventoryProvenanceRepoSpec),
		confirmCandidate(t, authz.MethodGet, "/alpha", record.InventoryProvenanceRuntimeSpec),
	})
	if !reflect.DeepEqual(confirmEndpointTable(shuffled), confirmEndpointTable(fwd)) {
		t.Fatalf("shuffling one tier's routes changed the union:\n  %v\n  %v",
			confirmEndpointTable(shuffled), confirmEndpointTable(fwd))
	}
	if got := shuffledProber.paths(); !reflect.DeepEqual(got, want) {
		t.Fatalf("the shuffled run spent the budget on %v, want %v", got, want)
	}
}

// TestCoverageComposesIntoRecordDastCoverage runs the result through the
// record's own validator rather than through a local re-statement of it.
func TestCoverageComposesIntoRecordDastCoverage(t *testing.T) {
	res := confirmRun(t, confirmConfirming(t, confirmAnswering(200, map[string]int{"/gone": 404}), 8),
		[]Route{
			confirmCandidate(t, authz.MethodGet, "/a", record.InventoryProvenanceRuntimeSpec),
			confirmCandidate(t, authz.MethodGet, "/b", record.InventoryProvenanceRepoSpec),
			confirmCandidate(t, authz.MethodGet, "/gone", record.InventoryProvenanceStaticExtraction),
			confirmCandidate(t, authz.MethodGet, "/a", record.InventoryProvenanceCrawl),
		})
	cov := res.Coverage()
	if err := record.ValidateDastCoverage(&cov); err != nil {
		t.Fatalf("record.ValidateDastCoverage: %v", err)
	}
	if cov.InventoryUnionCount != 3 {
		t.Fatalf("InventoryUnionCount = %d, want 3", cov.InventoryUnionCount)
	}
	if cov.ProbedCount != 2 || cov.ConfirmedCount != 2 || cov.CandidateCount != 1 {
		t.Fatalf("probed=%d confirmed=%d candidate=%d, want 2/2/1",
			cov.ProbedCount, cov.ConfirmedCount, cov.CandidateCount)
	}
	// ProbedCount is CONFIRMED ENDPOINTS and never a request count.
	if res.Issued() == cov.ProbedCount {
		t.Fatal("Issued() and ProbedCount coincide in this fixture, so the test cannot " +
			"tell an endpoint count from a request count")
	}
	if cov.ServerLineCoverage != nil {
		t.Fatal("ServerLineCoverage is zero rather than null; zero reads as \"we ran and " +
			"covered nothing\"")
	}
	want := map[record.InventoryProvenance]int{
		record.InventoryProvenanceRuntimeSpec:      1,
		record.InventoryProvenanceRepoSpec:         1,
		record.InventoryProvenanceStaticExtraction: 1,
		record.InventoryProvenanceCrawl:            1,
	}
	if !reflect.DeepEqual(cov.InventoryProvenanceMix, want) {
		t.Fatalf("mix = %v, want %v", cov.InventoryProvenanceMix, want)
	}
	// The mix SUMS TO MORE than the union, because /a has two provenances.
	sum := 0
	for _, n := range cov.InventoryProvenanceMix {
		sum += n
	}
	if sum <= cov.InventoryUnionCount {
		t.Fatalf("the mix sums to %d and the union is %d; this fixture is supposed to "+
			"exercise the case where they differ", sum, cov.InventoryUnionCount)
	}
}

// TestAnEmptyUnionIsAStatementAboutTheHandoffNotTheTarget.
func TestAnEmptyUnionIsAStatementAboutTheHandoffNotTheTarget(t *testing.T) {
	res := confirmRun(t, ConfirmConfig{Target: mustBareTarget(t)})
	if err := res.AssertNotSilentlyEmpty(); !errors.Is(err, ErrNothingMerged) {
		t.Fatalf("AssertNotSilentlyEmpty returned %v, want ErrNothingMerged", err)
	}
	if cov := res.Coverage(); cov.EndpointCoverage != 0 || cov.InventoryUnionCount != 0 {
		t.Fatalf("an empty union produced %v", cov)
	}
	// A denominator of zero must not be reported as full coverage.
	cov := res.Coverage()
	if err := record.ValidateDastCoverage(&cov); err != nil {
		t.Fatalf("record.ValidateDastCoverage on an empty union: %v", err)
	}
	// One route is enough to make it a statement about the target.
	res = confirmRun(t, ConfirmConfig{Target: mustBareTarget(t)}, []Route{
		confirmCandidate(t, authz.MethodGet, "/a", record.InventoryProvenanceRuntimeSpec),
	})
	if err := res.AssertNotSilentlyEmpty(); err != nil {
		t.Fatalf("AssertNotSilentlyEmpty on a real union: %v", err)
	}
	// And the unconstructed value is refused rather than reported clean.
	if err := (ConfirmResult{}).AssertNotSilentlyEmpty(); !errors.Is(err, ErrUnconstructed) {
		t.Fatalf("the zero ConfirmResult passed AssertNotSilentlyEmpty: %v", err)
	}
	if err := (ConfirmResult{}).AssertBudgetSufficed(); !errors.Is(err, ErrUnconstructed) {
		t.Fatal("the zero ConfirmResult passed AssertBudgetSufficed")
	}
	if err := (ConfirmResult{}).AssertEveryConfirmationHasEvidence(); !errors.Is(err, ErrUnconstructed) {
		t.Fatal("the zero ConfirmResult passed AssertEveryConfirmationHasEvidence")
	}
}

// TestACancelledRunDoesNotReportAPartialInventoryAsAMeasurement.
func TestACancelledRunDoesNotReportAPartialInventoryAsAMeasurement(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	prober := confirmAnswering(200, nil)
	cfg := confirmConfirming(t, prober, 8)
	res, err := MergeAndConfirm(ctx, cfg, mustClock(t), []Route{
		confirmCandidate(t, authz.MethodGet, "/a", record.InventoryProvenanceRuntimeSpec),
		confirmCandidate(t, authz.MethodGet, "/b", record.InventoryProvenanceRuntimeSpec),
	})
	if err != nil {
		t.Fatalf("MergeAndConfirm: %v", err)
	}
	if res.EndpointCount() != 2 {
		t.Fatalf("the union lost endpoints to cancellation: %d", res.EndpointCount())
	}
	if res.ConfirmedCount() != 0 || prober.calls != 0 {
		t.Fatalf("confirmed=%d proberCalls=%d after cancellation",
			res.ConfirmedCount(), prober.calls)
	}
	if n := confirmOutcomeCount(res, ConfirmOutcomeRunCancelled); n != 2 {
		t.Fatalf("%d endpoints carry run_cancelled, want 2", n)
	}
	for _, e := range res.Endpoints() {
		if !e.Outcome().MeansAnvilCouldNotLook() {
			t.Fatalf("%s is reported as a fact about the target", e)
		}
	}
}

// TestMergeOnlyIsALegitimateRequestAndSaysSo.
func TestMergeOnlyIsALegitimateRequestAndSaysSo(t *testing.T) {
	res := confirmRun(t, ConfirmConfig{Target: mustBareTarget(t)}, []Route{
		confirmCandidate(t, authz.MethodGet, "/a", record.InventoryProvenanceRuntimeSpec),
	})
	e := confirmEndpoint(t, res, authz.MethodGet, "/a")
	if e.Outcome() != ConfirmOutcomeNotRequested {
		t.Fatalf("outcome = %q, want confirmation_not_requested", e.Outcome())
	}
	if res.Budget() != 0 {
		t.Fatalf("Budget()=%d for a merge-only run", res.Budget())
	}
	if err := res.AssertBudgetSufficed(); err != nil {
		t.Fatalf("a merge-only run is not budget-starved: %v", err)
	}
	if res.ConfirmedCount() != 0 {
		t.Fatal("a merge-only run confirmed something")
	}
}

// TestConfirmationIsRefusedWhenTheKernelIsNotWired.
func TestConfirmationIsRefusedWhenTheKernelIsNotWired(t *testing.T) {
	auth, _ := mintAuthorization(t)
	gov, audit, _ := confirmKernel(t, confirmKernelOpts{})
	base := ConfirmConfig{
		Governor: gov, Audit: audit, Authorization: auth, Target: mustBareTarget(t),
		Confirm: true, ProbeBudget: 4, Technique: authz.TechniqueContentDiscovery,
		Prober: confirmAnswering(200, nil),
	}
	cases := []struct {
		name  string
		mutfn func(c *ConfirmConfig)
		want  error
	}{
		{"no governor", func(c *ConfirmConfig) { c.Governor = nil }, ErrUnconstructed},
		{"no audit", func(c *ConfirmConfig) { c.Audit = nil }, ErrUnconstructed},
		{"no authorization", func(c *ConfirmConfig) { c.Authorization = authz.Authorization{} }, ErrRefused},
		{"no technique", func(c *ConfirmConfig) { c.Technique = authz.TechniqueUnspecified }, ErrRefused},
		{"a destructive technique", func(c *ConfirmConfig) {
			c.Technique = authz.TechniqueDestructiveWrite
		}, ErrRefused},
		{"no target", func(c *ConfirmConfig) { c.Target = authz.Target{} }, ErrUnconstructed},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := base
			tc.mutfn(&cfg)
			if cfg.Constructed() {
				t.Fatalf("Constructed() is true for %q", tc.name)
			}
			_, err := MergeAndConfirm(context.Background(), cfg, mustClock(t), []Route{
				confirmCandidate(t, authz.MethodGet, "/a", record.InventoryProvenanceRuntimeSpec),
			})
			if !errors.Is(err, tc.want) {
				t.Fatalf("err = %v, want %v", err, tc.want)
			}
		})
	}
	if !base.Constructed() {
		t.Fatal("the base configuration is not Constructed, so every case above is vacuous")
	}
}

// ===========================================================================
// STRUCTURAL SCANNERS OVER THIS PACKET'S OWN SOURCE
// ===========================================================================

// TestConfirmationIsWrittenInExactlyOnePlace scans this file's own syntax tree.
//
// ConfirmationConfirmed is the identifier that moves an endpoint into
// endpoint_coverage's numerator. It may appear exactly once in tier2_confirm.go
// -- in MergedEndpoint.Confirmation, guarded by Confirmed() -- and in the
// laundering note's comparison. Anywhere else is a second writer.
func TestConfirmationIsWrittenInExactlyOnePlace(t *testing.T) {
	file, fset := parseOwnSource(t, "tier2_confirm.go")
	var lines []int
	idents := 0
	ast.Inspect(file, func(n ast.Node) bool {
		id, ok := n.(*ast.Ident)
		if !ok {
			return true
		}
		idents++
		if id.Name == "ConfirmationConfirmed" {
			lines = append(lines, fset.Position(id.Pos()).Line)
		}
		return true
	})
	if idents == 0 {
		t.Fatal("the scanner found no identifiers at all, so it could not have found a " +
			"violation either")
	}
	if len(lines) != 2 {
		t.Fatalf("ConfirmationConfirmed appears at lines %v. Exactly two uses are "+
			"legitimate: the return in MergedEndpoint.Confirmation, and the comparison "+
			"that records an inbound claim as discarded. Any other use is a second way "+
			"into the coverage numerator", lines)
	}
	// Positive control: the scanner can see an identifier that IS there many
	// times.
	seen := 0
	ast.Inspect(file, func(n ast.Node) bool {
		if id, ok := n.(*ast.Ident); ok && id.Name == "ConfirmationCandidate" {
			seen++
		}
		return true
	})
	if seen == 0 {
		t.Fatal("the scanner found zero uses of ConfirmationCandidate, which the file " +
			"certainly contains")
	}
}

// TestThisTierOpensNothing enforces an import allowlist on this file, with a
// positive control proving the scanner can see an import at all.
func TestThisTierOpensNothing(t *testing.T) {
	allowed := map[string]bool{
		`"context"`: true, `"errors"`: true, `"fmt"`: true, `"sort"`: true,
		`"strings"`: true, `"time"`: true,
		`"github.com/Susquehanna-Syntax/Anvil/internal/dast/authz"`: true,
		`"github.com/Susquehanna-Syntax/Anvil/internal/record"`:     true,
	}
	file, _ := parseOwnSource(t, "tier2_confirm.go")
	if len(file.Imports) == 0 {
		t.Fatal("the scanner found zero imports, so it could not have found a violation")
	}
	for _, imp := range file.Imports {
		if !allowed[imp.Path.Value] {
			t.Fatalf("tier2_confirm.go imports %s, which is not on the allowlist. This "+
				"package may not hold anything that can construct a socket; egress goes "+
				"through EndpointProber", imp.Path.Value)
		}
	}
	// And the scanner really would reject something: a fabricated entry.
	if allowed[`"net/http"`] {
		t.Fatal("net/http is on the allowlist")
	}
}

// TestNoRequestPathIsHardCodedInThisTier.
func TestNoRequestPathIsHardCodedInThisTier(t *testing.T) {
	file, fset := parseOwnSource(t, "tier2_confirm.go")
	found, hits := scanForPathLiterals(t, fset, file)
	if found == 0 {
		t.Fatal("the scanner found ZERO string literals in tier2_confirm.go, so it is " +
			"measuring nothing. A guard that reports clean because it could not see is " +
			"worse than no guard")
	}
	for _, h := range hits {
		t.Errorf("tier2_confirm.go contains the path literal %q at %s. The endpoints this "+
			"tier probes come from the inventory, never from a constant in the confirmer",
			h.value, h.where)
	}
}

// TestNoTestInThisPacketIsSkipped. A t.Skip is how an unprovable control
// reports itself green.
func TestNoTestInThisPacketIsSkipped(t *testing.T) {
	for _, name := range []string{"tier2_confirm.go", "tier2_confirm_test.go"} {
		file, _ := parseOwnSource(t, name)
		found := 0
		ast.Inspect(file, func(n ast.Node) bool {
			sel, ok := n.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			if sel.Sel.Name == "Skip" || sel.Sel.Name == "SkipNow" || sel.Sel.Name == "Skipf" {
				found++
			}
			return true
		})
		if found != 0 {
			t.Fatalf("%s contains %d t.Skip call(s)", name, found)
		}
	}
}
