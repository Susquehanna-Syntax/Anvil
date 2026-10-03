// Tests for Phase 3 of the Authorization Gate Sequence: gates 13–17.
//
// ===========================================================================
// WHAT THESE TESTS ARE FOR
// ===========================================================================
//
// A GUARD THAT HAS NEVER FAILED HAS NOT BEEN TESTED. Every gate in
// phase3_enforcement.go has at least one test here that drives it to REFUSE,
// and each of those refusals was verified to go RED against a build with the
// guard removed — the report for this packet names each guard, what was broken
// and what failed.
//
// A TEST WHOSE CORPUS COMES FROM THE IMPLEMENTATION IS NOT A TEST. Every
// number in this file is a hand-written literal taken from research/20 gate
// 14 and gate 16 or from plan/design/dynamic-tier.md's Authorization Gate Sequence table —
// 10 rps, 4 concurrent, 20,000 requests, 30 minutes, 1 MiB, 3 retries, 10%
// 5xx, 3× baseline, 30 seconds, 3 × 429. Nothing here asks the implementation
// what its own limits are and then asserts them.
//
// THE NAMED REPRODUCTION. Per-request enforcement's design requires "a reproduction test of
// the ZAP #2546 scenario (scope set to loopback, response 302s to an external
// host mid-scan) asserting the redirect is refused and logged, not followed".
// It is TestZAP2546RedirectToAnExternalHostIsRefusedNotFollowed, and it also
// asserts the thing that makes the reproduction interesting: the revalidation
// chain ALONE permits that hop, so gate 13's cross-host rule is the only thing
// standing between Anvil and the escape.
package authz

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"reflect"
	"strings"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// FIXTURES
// ---------------------------------------------------------------------------

const (
	// p3ExternalAddr is a routable address in none of the reserved ranges.
	p3ExternalAddr = "93.184.216.34"
	// p3SecondExternalAddr is a second routable address, used where a test
	// needs two different in-scope hosts.
	p3SecondExternalAddr = "93.184.216.35"
	// p3LoopbackAddr is the loopback address a lab-mode scope enumerates.
	p3LoopbackAddr = "127.0.0.1"
	// p3MetadataAddr is the cloud metadata endpoint gate 10 hard-refuses.
	p3MetadataAddr = "169.254.169.254"
)

func p3Addr(t *testing.T, s string) netip.Addr {
	t.Helper()
	a, err := netip.ParseAddr(s)
	if err != nil {
		t.Fatalf("ParseAddr(%q): %v", s, err)
	}
	return a
}

func p3Target(t *testing.T, scheme Scheme, host string, port uint16, addr string) Target {
	t.Helper()
	tgt, err := NewTarget(scheme, host, host, port, p3Addr(t, addr))
	if err != nil {
		t.Fatalf("NewTarget(%q,%q,%d,%q): %v", scheme, host, port, addr, err)
	}
	return tgt
}

func p3Scope(t *testing.T, mode Mode, allow, deny []ScopeEntry) Scope {
	t.Helper()
	decl, err := DeclareMode(mode)
	if err != nil {
		t.Fatalf("DeclareMode(%q): %v", mode, err)
	}
	s, err := NewScope(scopeFileJSON(mode, allow, deny), decl)
	if err != nil {
		t.Fatalf("NewScope: %v", err)
	}
	return s
}

// p3ExternalScope permits exactly target.example.com:443.
func p3ExternalScope(t *testing.T) Scope {
	t.Helper()
	return p3Scope(t, ModeExternal,
		[]ScopeEntry{{Host: "target.example.com", Ports: []uint16{443}}}, nil)
}

// p3LabScope is the ZAP #2546 fixture: a lab run scoped to loopback:8080 and
// to nothing else.
func p3LabScope(t *testing.T) Scope {
	t.Helper()
	return p3Scope(t, ModeLab,
		[]ScopeEntry{{Host: p3LoopbackAddr, Ports: []uint16{8080}}}, nil)
}

func p3Clock(t *testing.T, at time.Time) Clock {
	t.Helper()
	c, err := NewClock(at)
	if err != nil {
		t.Fatalf("NewClock(%s): %v", at, err)
	}
	return c
}

// p3At returns a clock d after the shared fixture instant.
func p3At(t *testing.T, d time.Duration) Clock {
	t.Helper()
	return p3Clock(t, fixtureNow.Add(d))
}

func p3Intent(t *testing.T, f RequestFacts) RequestIntent {
	t.Helper()
	i, err := NewRequestIntent(f)
	if err != nil {
		t.Fatalf("NewRequestIntent(%+v): %v", f.Origin, err)
	}
	return i
}

// p3AssertRefused is the shared shape of a Phase 3 refusal assertion.
func p3AssertRefused(t *testing.T, res GateResult, wantGate GateID, wantReason Reason) {
	t.Helper()
	if res.Passed() {
		t.Fatalf("the gate PASSED; it was required to refuse (%s / %s)", wantGate, wantReason)
	}
	if res.Gate() != wantGate {
		t.Fatalf("refusal attributed to %s; want %s (%s)", res.Gate(), wantGate, res.Err())
	}
	if got := res.Failure().Reason; got != wantReason {
		t.Fatalf("reason %q; want %q (%s)", string(got), string(wantReason), res.Err())
	}
	if !errors.Is(res.Err(), ErrRefused) {
		t.Fatalf("the failure does not unwrap to ErrRefused: %v", res.Err())
	}
}

func p3AssertPassed(t *testing.T, res GateResult, wantGate GateID) {
	t.Helper()
	if !res.Passed() {
		t.Fatalf("the gate REFUSED and was required to pass: %v", res.Err())
	}
	if res.Gate() != wantGate {
		t.Fatalf("pass attributed to %s; want %s", res.Gate(), wantGate)
	}
}

// ===========================================================================
// THE ONE RULE, FOR PHASE 3's OWN TYPES
// ===========================================================================

func TestPhase3ZeroValuesAuthorizeNothing(t *testing.T) {
	t.Run("RequestIntent", func(t *testing.T) {
		if (RequestIntent{}).Constructed() {
			t.Error("the zero RequestIntent reports Constructed() == true")
		}
		if !(RequestIntent{}).CrossHost() {
			t.Error("the zero RequestIntent reports CrossHost() == false, so a request " +
				"nobody built would be treated as staying on the admitted host")
		}
		p3AssertRefused(t, CheckGate13Revalidate(RequestIntent{}, p3ExternalScope(t),
			attestFor(t, p3ExternalScope(t)), mustClock(t)),
			Gate13RevalidateEveryRequest, ReasonRequestIntentUnbuilt)
	})

	t.Run("RequestOrigin and Method", func(t *testing.T) {
		if OriginUnset.Recognised() {
			t.Error("the zero RequestOrigin is recognised")
		}
		if MethodUnset.Recognised() {
			t.Error("the zero Method is recognised")
		}
		if !MethodUnset.ChangesState() {
			t.Error("the zero Method reports ChangesState() == false; an unknown verb must " +
				"fall on the state-changing side, which is the side that needs an allow")
		}
	})

	t.Run("Caps", func(t *testing.T) {
		var c Caps
		if c.Constructed() {
			t.Error("the zero Caps reports Constructed() == true")
		}
		if _, res := c.Lower(CapOverrides{}); res.Passed() {
			t.Error("lowering the zero Caps passed")
		}
		if _, err := c.RequestsPerSecondPerHost(); err == nil {
			t.Error("the zero Caps returned an rps cap with no error")
		}
		if c.rps.Allows(0) || c.rps.Allows(1) {
			t.Error("an undeclared Cap allowed a value")
		}
	})

	t.Run("HealthThresholds", func(t *testing.T) {
		var h HealthThresholds
		if h.Constructed() {
			t.Error("the zero HealthThresholds reports Constructed() == true")
		}
		if _, res := h.Lower(ThresholdOverrides{}); res.Passed() {
			t.Error("lowering the zero HealthThresholds passed")
		}
	})

	t.Run("EndpointAllowance", func(t *testing.T) {
		var a EndpointAllowance
		if a.Constructed() {
			t.Error("the zero EndpointAllowance reports Constructed() == true")
		}
		if a.Permits(MethodPost, "/anything") {
			t.Error("the zero EndpointAllowance permitted a POST")
		}
	})

	t.Run("Technique", func(t *testing.T) {
		if TechniqueUnspecified.Classified() {
			t.Error("the zero Technique is classified")
		}
		p3AssertRefused(t, CheckGate15DestructiveTechnique(TechniqueUnspecified, MethodGet,
			"/", EndpointAllowance{}),
			Gate15DestructiveTechniques, ReasonTechniqueUnclassified)
	})

	t.Run("nil limiter, breaker, ledger, governor and body", func(t *testing.T) {
		var l *RateLimiter
		if l.Constructed() {
			t.Error("a nil RateLimiter reports Constructed() == true")
		}
		p3AssertRefused(t, l.Acquire(0, mustClock(t)),
			Gate14HardCaps, ReasonLimiterUnconstructed)

		var m *HealthMonitor
		if m.Constructed() || m.Tripped() {
			t.Error("a nil HealthMonitor reports Constructed() or Tripped()")
		}
		p3AssertRefused(t, CheckGate16CircuitBreaker(m),
			Gate16CircuitBreaker, ReasonMonitorUnconstructed)

		var b *BackoffLedger
		if b.Constructed() || b.Aborted() {
			t.Error("a nil BackoffLedger reports Constructed() or Aborted()")
		}
		p3AssertRefused(t, CheckGate17RetryAfter(b, mustClock(t)),
			Gate17RetryAfter, ReasonLedgerUnconstructed)

		var g *Governor
		if g.Constructed() {
			t.Error("a nil Governor reports Constructed() == true")
		}
		if _, res := g.Admit(RequestIntent{}, TechniqueProofOfExistence, mustClock(t)); res.Passed() {
			t.Error("a nil Governor ADMITTED a request")
		}

		var body *BoundedBody
		if _, err := body.Read(make([]byte, 4)); err == nil {
			t.Error("a BoundedBody nobody built read without error")
		}
	})

	t.Run("an empty admission trace refuses", func(t *testing.T) {
		if LastResult(nil).Passed() {
			t.Error("LastResult(nil) passed. An empty trace means no gate was consulted, " +
				"and 'no gate objected' is the vacuous-truth bug a for-range over an " +
				"empty slice produces for free")
		}
	})
}

func TestPhase3ReasonTokensNameTheirOwnGate(t *testing.T) {
	byGate := map[GateID][]Reason{
		Gate11RobotsDeny: {ReasonRobotsRemovesNothing},
		Gate13RevalidateEveryRequest: {
			ReasonRequestIntentUnbuilt, ReasonRequestOriginUnrecognised,
			ReasonRevalidationRefused, ReasonHopOutsideScope, ReasonCrossHostRedirect,
			ReasonRedirectDowngradesScheme, ReasonRedirectFollowAttempted,
			ReasonRedirectHopBudget, ReasonHopMethodUnrecognised, ReasonHopPathMalformed,
			ReasonHopRevalidated, ReasonHopAttestationNotLive,
		},
		Gate14HardCaps: {
			ReasonCapsUnconstructed, ReasonCapRaiseAttempted, ReasonCapNotPositive,
			ReasonLimiterUnconstructed, ReasonRateExceeded, ReasonConcurrencyExceeded,
			ReasonVolumeExceeded, ReasonWallClockExceeded, ReasonRetryBudgetExceeded,
			ReasonBodyExceedsCap, ReasonCapClockWentBack, ReasonWithinEveryCap,
		},
		Gate15DestructiveTechniques: {
			ReasonTechniqueUnclassified, ReasonTechniqueDestructive,
			ReasonTechniqueMethodUnknown, ReasonStateChangingWithoutAll,
			ReasonTechniquePathMalformed, ReasonTechniqueNonDestructive,
		},
		Gate16CircuitBreaker: {
			ReasonMonitorUnconstructed, ReasonThresholdRaise, ReasonObservationMalformed,
			ReasonBreakerClockWentBack, ReasonBreakerServerErrors, ReasonBreakerConnErrors,
			ReasonBreakerLatency, ReasonTargetQuarantined, ReasonTargetHealthWithinAll,
		},
		Gate17RetryAfter: {
			ReasonLedgerUnconstructed, ReasonInsideRetryAfter, ReasonThreeTooManyRequests,
			ReasonRetryAfterUnparseable, ReasonRetryAfterAbsurd, ReasonServerSaid429,
			ReasonLedgerClockWentBack, ReasonBackoffElapsed,
		},
	}
	seen := map[Reason]bool{}
	for gate, reasons := range byGate {
		for _, r := range reasons {
			if err := r.Validate(); err != nil {
				t.Errorf("reason %q is not a legal token: %v", string(r), err)
				continue
			}
			named, err := r.Gate()
			if err != nil {
				t.Errorf("reason %q names no gate: %v", string(r), err)
				continue
			}
			if named != gate {
				t.Errorf("reason %q is declared under %s but names %s",
					string(r), gate, named)
			}
			if seen[r] {
				t.Errorf("reason %q is declared twice", string(r))
			}
			seen[r] = true
		}
	}
}

// TestNoPhase3GateIsInAnAdmissionChain is the NEGATIVE CONTROL the orchestrator
// required when it adopted this packet's reasoning about gates 13-17.
//
// The reasoning it adopted: a gateFunc cannot express "this request, this
// redirect hop, this rate budget", so none of the five belongs in an admission
// chain. The problem with stopping there: AN UNREGISTERED GATE AND A FORGOTTEN
// GATE ARE INDISTINGUISHABLE BY INSPECTION, and this project's method is that a
// control which can silently stop existing eventually does.
//
// So the separation is declared in the type system — per-request enforcement
// has its own chain type, requestChain, whose steps are not gateFuncs — and
// kernel.go's registerInto REFUSES a Phase 3 gate outright. This test asserts
// all three halves, so a future edit that "helpfully" registers one fails the
// build instead of silently changing WHEN enforcement happens.
func TestNoPhase3GateIsInAnAdmissionChain(t *testing.T) {
	for g := Gate13RevalidateEveryRequest; g <= Gate17RetryAfter; g++ {
		if _, ok := registry[g]; ok {
			t.Errorf("%s has a registered gateFunc. Phase 3 gates are per-REQUEST and are "+
				"not functions of the kernel's four inputs; registering one would mean "+
				"either a widened gateFunc or a gate reading ambient mutable state", g)
		}
		for name, list := range map[string][]GateID{
			"admission":    admissionChain,
			"revalidation": revalidationChain,
		} {
			for _, in := range list {
				if in == g {
					t.Errorf("%s appears in the %s chain. Moving a per-request gate into a "+
						"per-TARGET chain does not add a control; it changes when "+
						"enforcement happens, from every request to once", g, name)
				}
			}
		}

		// The structural half: registerInto refuses, so an init in a future file
		// cannot put one in even by accident.
		err := registerInto(map[GateID]gateFunc{}, g,
			func(Target, Scope, Attestation, Clock) Ruling { return Ruling{} })
		if err == nil {
			t.Errorf("registerInto ACCEPTED %s as an admission gateFunc", g)
			continue
		}
		if !errors.Is(err, ErrRefused) {
			t.Errorf("registerInto refused %s with an error that does not unwrap to "+
				"ErrRefused: %v", g, err)
		}
		if !strings.Contains(err.Error(), "requestChain") {
			t.Errorf("registerInto's refusal for %s does not name where the gate actually "+
				"lives, so a contributor who hits it learns only that they may not: %v",
				g, err)
		}
	}

	// And the per-request chain really is the one the interceptor runs. The
	// declared order is compared against governorGateOrder, which is written
	// down separately, so the chain is checked against an expectation rather
	// than against itself.
	if got := governorChain.gates(); !reflect.DeepEqual(got, governorGateOrder) {
		t.Fatalf("the per-request chain declares %v; governorGateOrder says %v", got,
			governorGateOrder)
	}
	for _, g := range governorChain.gates() {
		if g.Phase() != 3 && g != Gate11RobotsDeny {
			t.Errorf("%s is in the per-request chain and is neither a Phase 3 gate nor "+
				"gate 11, which is per-request because robots.txt is a property of an "+
				"origin AND A PATH", g)
		}
	}
}

// TestRequestChainRefusesWhenItIsEmptyOrMisattributed is the per-request chain
// runner's own fail-closed behaviour, which no production path reaches.
//
// It is tested rather than assumed for the reason kernel.go's chain runner
// handles an empty chain: "the list was empty so everything passed" is the
// vacuous-truth bug a for-range loop produces for free.
func TestRequestChainRefusesWhenItIsEmptyOrMisattributed(t *testing.T) {
	scope := p3ExternalScope(t)
	target := p3Target(t, SchemeHTTPS, "target.example.com", 443, p3ExternalAddr)
	g := p3Governor(t, scope, target)
	intent := p3Intent(t, RequestFacts{
		Origin: OriginInitial, Admitted: target, Next: target,
		Method: MethodGet, Path: "/",
	})

	// Each case asserts the TRACE, not LastResult(trace). LastResult already
	// refuses an empty slice, so a test written through it stays green when the
	// runner's own guard is deleted — which is exactly the subsumed-layer shape
	// this package deletes or tests. The contract here is that the runner
	// returns an ATTRIBUTED refusal, not that it returns nothing and lets a
	// later reducer invent one.
	t.Run("empty chain", func(t *testing.T) {
		trace := requestChain{}.run(g, intent, TechniqueProofOfExistence, p3At(t, 0))
		if len(trace) != 1 || trace[0].Passed() {
			t.Fatalf("an empty per-request chain returned %d result(s) instead of one "+
				"attributed refusal. Enforcing nothing is not admitting everything, and "+
				"a runner that returns an empty trace has left the refusal for somebody "+
				"else to remember", len(trace))
		}
		if trace[0].Gate() != Gate13RevalidateEveryRequest {
			t.Fatalf("the refusal is attributed to %s", trace[0].Gate())
		}
	})

	t.Run("nil step", func(t *testing.T) {
		trace := requestChain{{gate: Gate14HardCaps, run: nil}}.run(g, intent,
			TechniqueProofOfExistence, p3At(t, 0))
		if len(trace) != 1 || trace[0].Passed() {
			t.Fatalf("a chain step with no implementation produced %d result(s) instead "+
				"of one refusal", len(trace))
		}
		if trace[0].Gate() != Gate14HardCaps {
			t.Fatalf("the refusal is attributed to %s; the missing step was declared for %s",
				trace[0].Gate(), Gate14HardCaps)
		}
	})

	t.Run("a step that answers for another gate", func(t *testing.T) {
		trace := requestChain{{
			gate: Gate14HardCaps,
			run: func(*Governor, RequestIntent, Technique, Clock) GateResult {
				return gatePassed(Gate16CircuitBreaker)
			},
		}}.run(g, intent, TechniqueProofOfExistence, p3At(t, 0))
		if LastResult(trace).Passed() {
			t.Fatal("a step declared for gate 14 answered as gate 16 and the request was " +
				"admitted. The interceptor does not act on a result whose author is unclear")
		}
	})

	t.Run("positive control", func(t *testing.T) {
		trace := governorChain.run(g, intent, TechniqueProofOfExistence, p3At(t, 0))
		if !LastResult(trace).Passed() {
			t.Fatalf("the real per-request chain refused a well-formed request, so the "+
				"three cases above pass by refusing everything: %v", LastResult(trace).Err())
		}
	})
}

// ===========================================================================
// GATE 13 — the named reproduction, and the rest of the hop rules
// ===========================================================================

// TestZAP2546RedirectToAnExternalHostIsRefusedNotFollowed is the reproduction
// per-request enforcement's design names: "scope set to loopback, response 302s to an
// external host mid-scan".
//
// The second half of this test is the part that matters. GATES 8, 9 AND 10 ON
// THEIR OWN PERMIT the external destination: the host canonicalizes, the pinned
// address is routable unicast on no deny list, and a routable address is in no
// reserved range. If gate 13 were only "re-run gates 8-10", ZAP #2546 would
// reproduce here exactly as it did in ZAP.
//
// Two things stop it, and the test shows both. Gate 13 refuses a cross-host
// redirect before it consults anything else — that is the assertion above. And
// the revalidation chain refuses it anyway, because the orchestrator ruled that
// gate 4's scope allow-list match belongs in that chain; the second half shows
// gates 8-10 permitting it and gate 4 being what says no, so the reproduction
// stays a reproduction rather than becoming a tautology.
func TestZAP2546RedirectToAnExternalHostIsRefusedNotFollowed(t *testing.T) {
	scope := p3LabScope(t)
	att := attestFor(t, scope)
	clock := mustClock(t)

	admitted := p3Target(t, SchemeHTTP, p3LoopbackAddr, 8080, p3LoopbackAddr)
	escaped := p3Target(t, SchemeHTTP, "attacker.example.net", 80, p3ExternalAddr)

	hop := p3Intent(t, RequestFacts{
		Origin:   OriginRedirect,
		Admitted: admitted,
		Next:     escaped,
		Method:   MethodGet,
		Path:     "/collect",
		Hop:      1,
	})

	res := CheckGate13Revalidate(hop, scope, att, clock)
	p3AssertRefused(t, res, Gate13RevalidateEveryRequest, ReasonCrossHostRedirect)

	// "Refused and LOGGED, not followed": the refusal carries both origins as
	// evidence, so the audit row records where the branch was and where it was
	// asked to go.
	ev := strings.Join(res.Failure().Evidence, "\n")
	if !strings.Contains(ev, "127.0.0.1:8080") {
		t.Errorf("the refusal does not record the admitted origin:\n%s", ev)
	}
	if !strings.Contains(ev, "attacker.example.net:80") {
		t.Errorf("the refusal does not record the redirect destination:\n%s", ev)
	}

	// The half that makes this a reproduction rather than a tautology: gates
	// 8, 9 and 10 permit the external hop, exactly as they did in ZAP.
	only8to10 := chain{
		name:  "gates-8-10-only",
		gates: []GateID{Gate8Canonicalize, Gate9ResolveAndPin, Gate10ReservedRanges},
		impls: registry,
	}
	if r := only8to10.run(escaped, scope, att, clock); !r.Permits() {
		t.Fatalf("this test's premise no longer holds: gates 8-10 now refuse the external "+
			"destination on their own (%s). ZAP #2546 is a reproduction only while the "+
			"three gates a naive 're-run 8-10' reading would use let it through", r)
	}
	t.Log("premise confirmed: gates 8-10 PERMIT the external hop on their own")

	// And the full revalidation chain refuses it, at gate 4 — the scope
	// allow-list match the orchestrator ruled belongs there.
	r2 := Revalidate(escaped, scope, att, clock)
	if r2.Permits() {
		t.Fatal("the revalidation chain permitted a hop to a host the lab scope file " +
			"never names. research/20 gate 13: re-validate SCOPE on every single request")
	}
	if r2.Gate() != Gate4ScopeFile {
		t.Fatalf("the off-scope hop was refused by %s, not by the scope allow-list match: %s",
			r2.Gate(), r2)
	}
}

// TestCrossHostRedirectIsRefusedEvenWhenScopePermitsTheOtherHost is per-request enforcement's
// forbidden action in a test: "never follow a cross-host redirect, under any
// circumstance, including same-registrable-domain-but-different-host cases".
func TestCrossHostRedirectIsRefusedEvenWhenScopePermitsTheOtherHost(t *testing.T) {
	scope := p3Scope(t, ModeExternal, []ScopeEntry{
		{Host: "target.example.com", Ports: []uint16{443}},
		{Host: "www.target.example.com", Ports: []uint16{443}},
	}, nil)
	att := attestFor(t, scope)
	clock := mustClock(t)

	admitted := p3Target(t, SchemeHTTPS, "target.example.com", 443, p3ExternalAddr)
	sibling := p3Target(t, SchemeHTTPS, "www.target.example.com", 443, p3SecondExternalAddr)

	// Both hosts are in scope and both pass the revalidation chain. A "same
	// registrable domain" rule would follow this hop; there is no such rule.
	if r := Revalidate(sibling, scope, att, clock); !r.Permits() {
		t.Fatalf("premise: the sibling host does not pass revalidation: %s", r)
	}
	if !scope.Permits("www.target.example.com", 443) {
		t.Fatal("premise: the sibling host is not in scope")
	}

	hop := p3Intent(t, RequestFacts{
		Origin: OriginRedirect, Admitted: admitted, Next: sibling,
		Method: MethodGet, Path: "/", Hop: 1,
	})
	p3AssertRefused(t, CheckGate13Revalidate(hop, scope, att, clock),
		Gate13RevalidateEveryRequest, ReasonCrossHostRedirect)

	// A port change on the SAME host is a cross-origin hop too.
	otherPort := p3Target(t, SchemeHTTPS, "target.example.com", 8443, p3ExternalAddr)
	hop2 := p3Intent(t, RequestFacts{
		Origin: OriginRedirect, Admitted: admitted, Next: otherPort,
		Method: MethodGet, Path: "/", Hop: 1,
	})
	p3AssertRefused(t, CheckGate13Revalidate(hop2, scope, att, clock),
		Gate13RevalidateEveryRequest, ReasonCrossHostRedirect)
}

// TestSameHostRedirectIsRevalidatedAndPermitted proves gate 13 does not pass
// its refusal tests by refusing everything.
func TestSameHostRedirectIsRevalidatedAndPermitted(t *testing.T) {
	scope := p3ExternalScope(t)
	att := attestFor(t, scope)
	clock := mustClock(t)
	target := p3Target(t, SchemeHTTPS, "target.example.com", 443, p3ExternalAddr)

	hop := p3Intent(t, RequestFacts{
		Origin: OriginRedirect, Admitted: target, Next: target,
		Method: MethodGet, Path: "/moved", Hop: 1,
	})
	p3AssertPassed(t, CheckGate13Revalidate(hop, scope, att, clock),
		Gate13RevalidateEveryRequest)
}

// TestAnAttestationThatExpiresMidRunStopsTheNextRequest is kernel review finding HIGH 2,
// written as the measurement the critic made.
//
// WHAT WAS MEASURED. revalidationChain was {4, 8, 9, 10} and Gate5Attestation
// was absent, so nothing re-read the attestation's window once admission was
// past. The critic minted an attestation valid over [base-1h, base+29d], called
// Revalidate at base+365d, and got permits=true; CheckGate13Revalidate on an
// OriginInitial intent at the same instant PASSED.
//
// WHY IT MATTERS AT ALL. Gate 14 permits thirty minutes of wall clock PER
// TARGET, and a run has many targets, so an attestation can expire while a run
// is in progress. Gate 5's rule is "refuse to probe without a live
// attestation": per REQUEST, not per admission. Gate 5 is in revalidationChain
// now, and this test drives every arm of that.
//
// The instants are hand-written offsets from the shared fixture instant. The
// attestation window is 29 days, inside the coded 30-day ceiling, so nothing
// here is refused for the wrong reason.
func TestAnAttestationThatExpiresMidRunStopsTheNextRequest(t *testing.T) {
	scope := p3ExternalScope(t)
	issued := fixtureNow.Add(-time.Hour)
	expires := fixtureNow.Add(29 * 24 * time.Hour)

	att, err := NewAttestation(
		"attest-expires-mid-run",
		"Susquehanna Syntax, operator of target.example.com",
		AuthorityOperator,
		scope.Hash(),
		issued,
		expires,
		DefaultAttestationCeiling(),
	)
	if err != nil {
		t.Fatalf("NewAttestation: %v", err)
	}

	tgt := p3Target(t, SchemeHTTPS, "target.example.com", 443, p3ExternalAddr)
	intent := p3Intent(t, RequestFacts{
		Origin:   OriginInitial,
		Admitted: tgt,
		Next:     tgt,
		Method:   MethodGet,
		Path:     "/",
	})

	// Gate 5 is in the chain the per-request path runs. Without this, the
	// three assertions below could all be about gate 4.
	inChain := false
	for _, g := range revalidationChain {
		if g == Gate5Attestation {
			inChain = true
		}
	}
	if !inChain {
		t.Fatalf("revalidationChain is %v and Gate5Attestation is not in it, so nothing "+
			"re-reads the attestation's window once admission is past. An attestation "+
			"can expire DURING a run: gate 14 permits thirty minutes of wall clock per "+
			"target and a run has many targets", revalidationChain)
	}

	t.Run("inside the window the request proceeds", func(t *testing.T) {
		// One hour in: well past admission, well inside the attestation.
		clk := p3At(t, time.Hour)
		if r := Revalidate(tgt, scope, att, clk); !r.Permits() {
			t.Fatalf("Revalidate refused a live attestation an hour into the run: %s. "+
				"If this arm cannot pass, the refusals below prove nothing about "+
				"expiry", r)
		}
		p3AssertPassed(t, CheckGate13Revalidate(intent, scope, att, clk), Gate13RevalidateEveryRequest)
	})

	t.Run("one second after it expires the next request stops", func(t *testing.T) {
		clk := p3Clock(t, expires.Add(time.Second))
		r := Revalidate(tgt, scope, att, clk)
		if r.Permits() {
			t.Fatalf("Revalidate permitted one second after the attestation expired: %s. "+
				"Gate 5 is 'refuse to probe without a live attestation', and an "+
				"attestation that expired a second ago is not one. There is no grace "+
				"period", r)
		}
		if r.Gate() != Gate5Attestation {
			t.Fatalf("the expired attestation was refused by %s; gate 5 owns expiry, and "+
				"if some other gate is refusing then this fixture is not testing "+
				"expiry: %s", r.Gate(), r)
		}
		if r.Reason() != ReasonAttestationExpired {
			t.Fatalf("reason %q; want %q so the audit says the attestation ran out rather "+
				"than that revalidation said no", string(r.Reason()),
				string(ReasonAttestationExpired))
		}
		p3AssertRefused(t, CheckGate13Revalidate(intent, scope, att, clk),
			Gate13RevalidateEveryRequest, ReasonHopAttestationNotLive)
	})

	t.Run("the critic's own instant", func(t *testing.T) {
		// base+365d. This is the measurement verbatim: Revalidate returned
		// permits=true here, and CheckGate13Revalidate passed an
		// OriginInitial intent at the same instant.
		clk := p3At(t, 365*24*time.Hour)
		r := Revalidate(tgt, scope, att, clk)
		if r.Permits() {
			t.Fatalf("Revalidate permitted 365 days into a run under an attestation whose "+
				"window ended at day 29: %s", r)
		}
		p3AssertRefused(t, CheckGate13Revalidate(intent, scope, att, clk),
			Gate13RevalidateEveryRequest, ReasonHopAttestationNotLive)
	})

	t.Run("a redirect hop is judged at the same instant", func(t *testing.T) {
		// A same-host redirect, which gate 13 otherwise permits, at an
		// instant after expiry. The hop is the case research/20 cares most
		// about: it is the target choosing Anvil's next destination.
		hop := p3Intent(t, RequestFacts{
			Origin:   OriginRedirect,
			Admitted: tgt,
			Next:     tgt,
			Method:   MethodGet,
			Path:     "/moved",
			Hop:      1,
		})
		clk := p3Clock(t, expires.Add(time.Second))
		p3AssertRefused(t, CheckGate13Revalidate(hop, scope, att, clk),
			Gate13RevalidateEveryRequest, ReasonHopAttestationNotLive)
	})
}

// TestGate13RunsGates8Through10OnEveryOriginAndEveryHop is the assertion the gate-stack review
// is asked to trace: gate 13's re-validation actually calls gate 10's denylist
// and gate 9's pinning on every hop, not only on the first request.
//
// The destination is the cloud metadata address. In external mode gate 10
// hard-refuses it, and the refusal's evidence names gate10 — which is how this
// test proves the CHAIN ran rather than that some check somewhere said no.
func TestGate13RunsGates8Through10OnEveryOriginAndEveryHop(t *testing.T) {
	scope := p3Scope(t, ModeExternal, []ScopeEntry{
		{Host: "target.example.com", Ports: []uint16{443}},
		{Host: "metadata.example.com", Ports: []uint16{443}},
	}, nil)
	att := attestFor(t, scope)
	clock := mustClock(t)

	admitted := p3Target(t, SchemeHTTPS, "target.example.com", 443, p3ExternalAddr)
	// A host that IS in the scope file and resolves to the metadata address.
	// Gate 4 would have permitted it; gate 10 must not.
	metadata := p3Target(t, SchemeHTTPS, "metadata.example.com", 443, p3MetadataAddr)

	for _, origin := range requestOrigins() {
		t.Run(string(origin), func(t *testing.T) {
			hop := 0
			if origin == OriginRedirect {
				hop = 1
			}
			intent := p3Intent(t, RequestFacts{
				Origin: origin, Admitted: admitted, Next: metadata,
				Method: MethodGet, Path: "/latest/meta-data/", Hop: hop,
			})
			res := CheckGate13Revalidate(intent, scope, att, clock)
			if res.Passed() {
				t.Fatalf("origin %q reached the cloud metadata address", origin)
			}
			if origin == OriginRedirect {
				// A redirect is refused earlier, as a cross-host hop, and
				// never reaches the chain. That is stricter, not weaker.
				p3AssertRefused(t, res, Gate13RevalidateEveryRequest, ReasonCrossHostRedirect)
				return
			}
			p3AssertRefused(t, res, Gate13RevalidateEveryRequest, ReasonRevalidationRefused)
			ev := strings.Join(res.Failure().Evidence, "\n")
			if !strings.Contains(ev, Gate10ReservedRanges.String()) {
				t.Errorf("the refusal does not name gate 10 as the refusing gate, so this "+
					"test cannot show the revalidation chain ran:\n%s", ev)
			}
			if !strings.Contains(ev, string(ReasonReservedRangeExternal)) {
				t.Errorf("the refusal does not carry gate 10's own reason token:\n%s", ev)
			}
		})
	}
}

// TestGate13RefusesAHopOutsideScopeThatGates8Through10Permit is the second half
// of the same point: gates 8-10 do not perform the scope allow-list match, so
// something has to, and the orchestrator ruled that the something is gate 4 in
// revalidationChain rather than a duplicate check inside gate 13.
//
// The refusal still carries ReasonHopOutsideScope. A bare
// "gate13.revalidation_chain_refused_this_hop" would tell an operator that
// revalidation said no but not that the reason was scope, so gate 13 maps a
// gate-4 refusal onto its own scope token.
func TestGate13RefusesAHopOutsideScopeThatGates8Through10Permit(t *testing.T) {
	scope := p3ExternalScope(t)
	att := attestFor(t, scope)
	clock := mustClock(t)

	admitted := p3Target(t, SchemeHTTPS, "target.example.com", 443, p3ExternalAddr)
	offScope := p3Target(t, SchemeHTTPS, "cdn.example.net", 443, p3SecondExternalAddr)

	only8to10 := chain{
		name:  "gates-8-10-only",
		gates: []GateID{Gate8Canonicalize, Gate9ResolveAndPin, Gate10ReservedRanges},
		impls: registry,
	}
	if r := only8to10.run(offScope, scope, att, clock); !r.Permits() {
		t.Fatalf("premise: gates 8-10 already refuse the off-scope host (%s); this test "+
			"exists because they do not", r)
	}
	if scope.Permits("cdn.example.net", 443) {
		t.Fatal("premise: the off-scope host is in scope")
	}

	intent := p3Intent(t, RequestFacts{
		Origin: OriginBrowserFetch, Admitted: admitted, Next: offScope,
		Method: MethodGet, Path: "/lib.js",
	})
	res := CheckGate13Revalidate(intent, scope, att, clock)
	p3AssertRefused(t, res, Gate13RevalidateEveryRequest, ReasonHopOutsideScope)

	nl := string(byte(10))
	ev := strings.Join(res.Failure().Evidence, nl)
	if !strings.Contains(ev, Gate4ScopeFile.String()) {
		t.Errorf("the refusal does not name gate 4 as the refusing gate, so this test "+
			"cannot show the scope check ran in the chain: %s", ev)
	}
}

// TestGate13PermitsASecondInScopeHostForANonRedirectOrigin is the asymmetry
// stated as a test: a template-supplied URL or a browser fetch may reach a
// second host the scope file names; a redirect may not.
func TestGate13PermitsASecondInScopeHostForANonRedirectOrigin(t *testing.T) {
	scope := p3Scope(t, ModeExternal, []ScopeEntry{
		{Host: "target.example.com", Ports: []uint16{443}},
		{Host: "api.example.com", Ports: []uint16{443}},
	}, nil)
	att := attestFor(t, scope)
	clock := mustClock(t)

	admitted := p3Target(t, SchemeHTTPS, "target.example.com", 443, p3ExternalAddr)
	second := p3Target(t, SchemeHTTPS, "api.example.com", 443, p3SecondExternalAddr)

	for _, origin := range []RequestOrigin{OriginTemplateURL, OriginBrowserFetch,
		OriginWebSocketUpgrade, OriginOutOfBandCallback} {
		intent := p3Intent(t, RequestFacts{
			Origin: origin, Admitted: admitted, Next: second,
			Method: MethodGet, Path: "/v1/ping",
		})
		p3AssertPassed(t, CheckGate13Revalidate(intent, scope, att, clock),
			Gate13RevalidateEveryRequest)
	}

	redirect := p3Intent(t, RequestFacts{
		Origin: OriginRedirect, Admitted: admitted, Next: second,
		Method: MethodGet, Path: "/v1/ping", Hop: 1,
	})
	p3AssertRefused(t, CheckGate13Revalidate(redirect, scope, att, clock),
		Gate13RevalidateEveryRequest, ReasonCrossHostRedirect)
}

func TestGate13RefusesASchemeDowngradeOnARedirect(t *testing.T) {
	scope := p3Scope(t, ModeExternal, []ScopeEntry{
		{Host: "target.example.com", Ports: []uint16{443, 80}},
	}, nil)
	att := attestFor(t, scope)
	clock := mustClock(t)

	admitted := p3Target(t, SchemeHTTPS, "target.example.com", 443, p3ExternalAddr)
	plain := p3Target(t, SchemeHTTP, "target.example.com", 80, p3ExternalAddr)

	hop := p3Intent(t, RequestFacts{
		Origin: OriginRedirect, Admitted: admitted, Next: plain,
		Method: MethodGet, Path: "/", Hop: 1,
	})
	p3AssertRefused(t, CheckGate13Revalidate(hop, scope, att, clock),
		Gate13RevalidateEveryRequest, ReasonRedirectDowngradesScheme)
}

// TestServerChosenClassifiesTheOriginsTheTargetPicks records what
// RequestOrigin.ServerChosen answers. It is an audit label, not a control —
// every origin is re-validated identically, which
// TestGate13RunsGates8Through10OnEveryOriginAndEveryHop measures — so this
// test exists to keep the label honest rather than to hold a gate.
func TestServerChosenClassifiesTheOriginsTheTargetPicks(t *testing.T) {
	chosen := map[RequestOrigin]bool{
		OriginInitial:           false,
		OriginRedirect:          true,
		OriginTemplateURL:       true,
		OriginBrowserFetch:      true,
		OriginWebSocketUpgrade:  false,
		OriginOutOfBandCallback: false,
	}
	for _, o := range requestOrigins() {
		want, ok := chosen[o]
		if !ok {
			t.Fatalf("origin %q is enumerated but this test does not classify it", o)
		}
		if got := o.ServerChosen(); got != want {
			t.Errorf("%q.ServerChosen() = %v; want %v", o, got, want)
		}
	}
	if OriginUnset.ServerChosen() {
		t.Error("the zero origin claims a server chose it")
	}
}

func TestNewRequestIntentRefusesEveryMalformedShape(t *testing.T) {
	good := p3Target(t, SchemeHTTPS, "target.example.com", 443, p3ExternalAddr)

	cases := []struct {
		name  string
		facts RequestFacts
	}{
		{"no origin", RequestFacts{Admitted: good, Next: good, Method: MethodGet, Path: "/"}},
		{"origin nobody enumerated", RequestFacts{Origin: RequestOrigin("sitemap"),
			Admitted: good, Next: good, Method: MethodGet, Path: "/"}},
		{"no admitted target", RequestFacts{Origin: OriginInitial, Next: good,
			Method: MethodGet, Path: "/"}},
		{"no destination target", RequestFacts{Origin: OriginInitial, Admitted: good,
			Method: MethodGet, Path: "/"}},
		{"no method", RequestFacts{Origin: OriginInitial, Admitted: good, Next: good,
			Path: "/"}},
		{"method nobody enumerated", RequestFacts{Origin: OriginInitial, Admitted: good,
			Next: good, Method: Method("TRACE"), Path: "/"}},
		{"empty path", RequestFacts{Origin: OriginInitial, Admitted: good, Next: good,
			Method: MethodGet}},
		{"relative path", RequestFacts{Origin: OriginInitial, Admitted: good, Next: good,
			Method: MethodGet, Path: "index.html"}},
		{"path with a control byte", RequestFacts{Origin: OriginInitial, Admitted: good,
			Next: good, Method: MethodGet, Path: "/a\nb"}},
		{"negative hop", RequestFacts{Origin: OriginRedirect, Admitted: good, Next: good,
			Method: MethodGet, Path: "/", Hop: -1}},
		{"hop past the budget", RequestFacts{Origin: OriginRedirect, Admitted: good,
			Next: good, Method: MethodGet, Path: "/", Hop: maxRedirectHops + 1}},
		{"redirect at depth zero", RequestFacts{Origin: OriginRedirect, Admitted: good,
			Next: good, Method: MethodGet, Path: "/"}},
		{"non-redirect carrying a depth", RequestFacts{Origin: OriginInitial, Admitted: good,
			Next: good, Method: MethodGet, Path: "/", Hop: 2}},
		{"negative attempt", RequestFacts{Origin: OriginInitial, Admitted: good, Next: good,
			Method: MethodGet, Path: "/", Attempt: -1}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			i, err := NewRequestIntent(c.facts)
			if err == nil {
				t.Fatalf("NewRequestIntent accepted %s", c.name)
			}
			if !errors.Is(err, ErrRefused) {
				t.Fatalf("the refusal does not unwrap to ErrRefused: %v", err)
			}
			if i.Constructed() {
				t.Fatal("a refused NewRequestIntent still returned a constructed intent")
			}
		})
	}
}

// TestRefuseAllRedirectsRefusesEveryHopIncludingSameHost is the redirect
// policy. An http.Client with a nil CheckRedirect follows up to ten redirects
// with no gate consulted at all; this is the function that stops it, and it
// refuses a same-host hop too, because a same-host hop is legitimate only
// AFTER gate 13 has judged it and an automatic follow never gives gate 13 the
// chance.
func TestRefuseAllRedirectsRefusesEveryHopIncludingSameHost(t *testing.T) {
	req, err := http.NewRequest(http.MethodGet, "https://target.example.com/moved", nil)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	for _, hops := range []int{0, 1, 9, 100} {
		via := make([]*http.Request, hops)
		err := RefuseAllRedirects(req, via)
		if err == nil {
			t.Fatalf("the redirect policy permitted a hop at depth %d", hops)
		}
		if !errors.Is(err, ErrRedirectRefused) || !errors.Is(err, ErrRefused) {
			t.Fatalf("the refusal at depth %d does not unwrap to ErrRedirectRefused and "+
				"ErrRefused: %v", hops, err)
		}
	}
	if err := RefuseAllRedirects(nil, nil); err == nil {
		t.Fatal("the redirect policy permitted a hop carrying no request at all")
	}
}

// ===========================================================================
// GATE 14 — the floors, and that no combination of settings raises one
// ===========================================================================

func intPtr(v int) *int                     { return &v }
func int64Ptr(v int64) *int64               { return &v }
func durPtr(v time.Duration) *time.Duration { return &v }
func floatPtr(v float64) *float64           { return &v }

// TestCodedCapsAreTheFiguresTheGateSequenceNames checks the floors against the
// numbers written in plan/design/dynamic-tier.md's Authorization Gate Sequence table,
// which are hand-copied here rather than read from the implementation.
func TestCodedCapsAreTheFiguresTheGateSequenceNames(t *testing.T) {
	c := CodedCaps()
	if got, _ := c.RequestsPerSecondPerHost(); got != 10 {
		t.Errorf("rps floor is %d; the gate sequence says 10", got)
	}
	if got, _ := c.ConcurrentPerHost(); got != 4 {
		t.Errorf("concurrency floor is %d; the gate sequence says 4", got)
	}
	if got, _ := c.RequestsPerTargetRun(); got != 20000 {
		t.Errorf("volume floor is %d; the gate sequence says 20,000", got)
	}
	if got, _ := c.WallClockPerTarget(); got != 30*time.Minute {
		t.Errorf("wall-clock floor is %s; the gate sequence says 30 minutes", got)
	}
	if got, _ := c.BodyBytes(); got != 1<<20 {
		t.Errorf("body floor is %d; the gate sequence says 1 MiB", got)
	}
	if got, _ := c.Retries(); got != 3 {
		t.Errorf("retry floor is %d; the gate sequence says 3", got)
	}
}

// TestNoCombinationOfConfigValuesRaisesAnyCap is the test per-request enforcement's design
// requires: "a test asserting no combination of config values can push any of
// the five caps above its floor".
//
// It covers four separate ways a raise could be attempted, because they are
// four different mechanisms and closing three of them would still leave a
// hole:
//
//  1. one override above the floor, for each cap;
//  2. all six overrides above the floor at once;
//  3. a SEQUENCE of Lower calls walking a cap back up (lower to 5, then
//     "lower" to 9), which a comparison against the coded floor alone would
//     let through;
//  4. absurd values — MaxInt, a century, a terabyte.
//
// It also asserts the coded floor is unchanged after every refusal, so a
// partially-applied override cannot leave a raised cap behind.
func TestNoCombinationOfConfigValuesRaisesAnyCap(t *testing.T) {
	floors := CodedCaps()

	t.Run("one override above the floor, per cap", func(t *testing.T) {
		cases := []struct {
			name string
			over CapOverrides
		}{
			{"rps", CapOverrides{RequestsPerSecondPerHost: intPtr(11)}},
			{"rps, absurd", CapOverrides{RequestsPerSecondPerHost: intPtr(1 << 30)}},
			{"concurrency", CapOverrides{ConcurrentPerHost: intPtr(5)}},
			{"concurrency, absurd", CapOverrides{ConcurrentPerHost: intPtr(4096)}},
			{"volume", CapOverrides{RequestsPerTargetRun: intPtr(20001)}},
			{"volume, absurd", CapOverrides{RequestsPerTargetRun: intPtr(1 << 30)}},
			{"wall clock", CapOverrides{WallClockPerTarget: durPtr(30*time.Minute + time.Nanosecond)}},
			{"wall clock, absurd", CapOverrides{WallClockPerTarget: durPtr(100 * 365 * 24 * time.Hour)}},
			{"body", CapOverrides{BodyBytes: int64Ptr(1<<20 + 1)}},
			{"body, absurd", CapOverrides{BodyBytes: int64Ptr(1 << 40)}},
			{"retries", CapOverrides{Retries: intPtr(4)}},
			{"retries, absurd", CapOverrides{Retries: intPtr(1 << 20)}},
		}
		for _, c := range cases {
			t.Run(c.name, func(t *testing.T) {
				got, res := floors.Lower(c.over)
				p3AssertRefused(t, res, Gate14HardCaps, ReasonCapRaiseAttempted)
				if got.Constructed() {
					t.Fatal("a refused Lower still returned a constructed Caps, so a " +
						"caller that ignored the GateResult would run with it")
				}
			})
		}
	})

	t.Run("every cap raised at once", func(t *testing.T) {
		_, res := floors.Lower(CapOverrides{
			RequestsPerSecondPerHost: intPtr(1000),
			ConcurrentPerHost:        intPtr(1000),
			RequestsPerTargetRun:     intPtr(1 << 30),
			WallClockPerTarget:       durPtr(24 * time.Hour),
			BodyBytes:                int64Ptr(1 << 32),
			Retries:                  intPtr(1000),
		})
		p3AssertRefused(t, res, Gate14HardCaps, ReasonCapRaiseAttempted)
	})

	t.Run("a sequence of settings cannot walk a cap back up", func(t *testing.T) {
		lowered, res := floors.Lower(CapOverrides{RequestsPerSecondPerHost: intPtr(5)})
		p3AssertPassed(t, res, Gate14HardCaps)
		if got, _ := lowered.RequestsPerSecondPerHost(); got != 5 {
			t.Fatalf("effective rps is %d after lowering to 5", got)
		}
		// 9 is below the coded floor of 10 and ABOVE the current effective
		// value of 5. A comparison against the coded floor alone would accept
		// it, and the cap would have been walked from 5 back to 9.
		_, res = lowered.Lower(CapOverrides{RequestsPerSecondPerHost: intPtr(9)})
		p3AssertRefused(t, res, Gate14HardCaps, ReasonCapRaiseAttempted)

		// The same for every other cap, in one pass.
		layered, res := floors.Lower(CapOverrides{
			ConcurrentPerHost:    intPtr(2),
			RequestsPerTargetRun: intPtr(100),
			WallClockPerTarget:   durPtr(time.Minute),
			BodyBytes:            int64Ptr(4096),
			Retries:              intPtr(1),
		})
		p3AssertPassed(t, res, Gate14HardCaps)
		walkUps := []CapOverrides{
			{ConcurrentPerHost: intPtr(3)},
			{RequestsPerTargetRun: intPtr(200)},
			{WallClockPerTarget: durPtr(10 * time.Minute)},
			{BodyBytes: int64Ptr(8192)},
			{Retries: intPtr(2)},
		}
		for i, up := range walkUps {
			if _, res := layered.Lower(up); res.Passed() {
				t.Errorf("walk-up %d was accepted", i)
			}
		}
	})

	t.Run("the coded floor is unchanged after every refusal", func(t *testing.T) {
		_, _ = floors.Lower(CapOverrides{RequestsPerSecondPerHost: intPtr(1 << 30)})
		if got, _ := floors.rps.Coded(); got != CodedMaxRequestsPerSecondPerHost {
			t.Fatalf("the coded floor moved to %d", got)
		}
		if got, _ := floors.RequestsPerSecondPerHost(); got != 10 {
			t.Fatalf("the effective cap moved to %d", got)
		}
	})

	t.Run("lowering still works", func(t *testing.T) {
		got, res := floors.Lower(CapOverrides{
			RequestsPerSecondPerHost: intPtr(1),
			ConcurrentPerHost:        intPtr(1),
			RequestsPerTargetRun:     intPtr(10),
			WallClockPerTarget:       durPtr(time.Second),
			BodyBytes:                int64Ptr(1024),
			Retries:                  intPtr(1),
		})
		p3AssertPassed(t, res, Gate14HardCaps)
		if v, _ := got.BodyBytes(); v != 1024 {
			t.Errorf("body cap is %d after lowering to 1024", v)
		}
		if v, _ := got.WallClockPerTarget(); v != time.Second {
			t.Errorf("wall clock is %s after lowering to 1s", v)
		}
	})

	t.Run("a non-positive cap is refused rather than guessed at", func(t *testing.T) {
		for _, over := range []CapOverrides{
			{RequestsPerSecondPerHost: intPtr(0)},
			{ConcurrentPerHost: intPtr(-1)},
			{RequestsPerTargetRun: intPtr(0)},
			{WallClockPerTarget: durPtr(0)},
			{BodyBytes: int64Ptr(-4096)},
			{Retries: intPtr(0)},
		} {
			_, res := floors.Lower(over)
			p3AssertRefused(t, res, Gate14HardCaps, ReasonCapNotPositive)
		}
	})
}

// TestCapsCannotBeForgedFromOutsideThisPackage is the structural half of the
// floor rule, and it is here because the kernel-types review showed the other half
// failing: NewCap is exported and unvalidated, so a caller CAN mint a Cap with
// any floor it likes. Caps closes that by never accepting one.
func TestCapsCannotBeForgedFromOutsideThisPackage(t *testing.T) {
	ty := reflect.TypeOf(Caps{})
	for i := 0; i < ty.NumField(); i++ {
		if ty.Field(i).IsExported() {
			t.Errorf("Caps.%s is exported. An exported field is a composite literal in "+
				"another package, which is how a config-driven caller would hand this "+
				"package a floor of its own choosing — the exact hole the kernel-types review "+
				"demonstrated in NewAttestation's ceiling parameter", ty.Field(i).Name)
		}
	}
	th := reflect.TypeOf(HealthThresholds{})
	for i := 0; i < th.NumField(); i++ {
		if th.Field(i).IsExported() {
			t.Errorf("HealthThresholds.%s is exported", th.Field(i).Name)
		}
	}
	// And the only way in carries numbers, never Caps.
	over := reflect.TypeOf(CapOverrides{})
	capType := reflect.TypeOf(Cap[int]{})
	for i := 0; i < over.NumField(); i++ {
		f := over.Field(i)
		if f.Type == capType || (f.Type.Kind() == reflect.Pointer && f.Type.Elem() == capType) {
			t.Errorf("CapOverrides.%s carries a Cap. Configuration must supply numbers to "+
				"be compared against a floor, never a floor", f.Name)
		}
	}
}

// TestCapOverridesAreCopiedNotAliased closes the aliasing shape the kernel-types review
// found in Scope: a caller that keeps its pointers and writes through them
// after the fact must not be able to change a value that was already built.
func TestCapOverridesAreCopiedNotAliased(t *testing.T) {
	rps := 5
	over := CapOverrides{RequestsPerSecondPerHost: &rps}
	caps, res := CodedCaps().Lower(over)
	p3AssertPassed(t, res, Gate14HardCaps)

	rps = 10000
	if got, _ := caps.RequestsPerSecondPerHost(); got != 5 {
		t.Fatalf("writing through the caller's pointer changed the built cap to %d", got)
	}
}

// TestScalarRateCapDominatesConcurrency is nuclei's precedence discipline as a
// measurement: "one scalar rate cap dominates every concurrency knob, so no
// combination of settings can exceed it".
func TestScalarRateCapDominatesConcurrency(t *testing.T) {
	// Four concurrent connections permitted, one request per second.
	caps, res := CodedCaps().Lower(CapOverrides{
		RequestsPerSecondPerHost: intPtr(1),
		ConcurrentPerHost:        intPtr(4),
	})
	p3AssertPassed(t, res, Gate14HardCaps)

	lim, res := NewRateLimiter(caps, p3At(t, 0))
	p3AssertPassed(t, res, Gate14HardCaps)

	// At one instant, with four slots free, exactly one token exists.
	p3AssertPassed(t, lim.Acquire(0, p3At(t, 0)), Gate14HardCaps)
	for i := 0; i < 3; i++ {
		p3AssertRefused(t, lim.Acquire(0, p3At(t, 0)), Gate14HardCaps, ReasonRateExceeded)
	}
	if got := lim.InFlight(); got != 1 {
		t.Fatalf("%d connections in flight; the rate cap should have let exactly 1 through", got)
	}

	// Over ten seconds, ten requests and not forty.
	admitted := 1
	for s := 1; s <= 10; s++ {
		lim.Release()
		for i := 0; i < 4; i++ {
			if lim.Acquire(0, p3At(t, time.Duration(s)*time.Second)).Passed() {
				admitted++
			}
		}
	}
	if admitted != 11 {
		t.Fatalf("%d requests were admitted over 10 seconds at 1 rps with 4 concurrent "+
			"slots; the scalar cap allows 1 per second plus the initial full bucket, so "+
			"11 is the ceiling", admitted)
	}
}

func TestRateLimiterRefusesEveryCapItEnforces(t *testing.T) {
	t.Run("rate", func(t *testing.T) {
		lim, res := NewRateLimiter(CodedCaps(), p3At(t, 0))
		p3AssertPassed(t, res, Gate14HardCaps)
		for i := 0; i < 10; i++ {
			p3AssertPassed(t, lim.Acquire(0, p3At(t, 0)), Gate14HardCaps)
			lim.Release()
		}
		p3AssertRefused(t, lim.Acquire(0, p3At(t, 0)), Gate14HardCaps, ReasonRateExceeded)
	})

	t.Run("concurrency", func(t *testing.T) {
		lim, res := NewRateLimiter(CodedCaps(), p3At(t, 0))
		p3AssertPassed(t, res, Gate14HardCaps)
		for i := 0; i < 4; i++ {
			p3AssertPassed(t, lim.Acquire(0, p3At(t, 0)), Gate14HardCaps)
		}
		p3AssertRefused(t, lim.Acquire(0, p3At(t, 0)),
			Gate14HardCaps, ReasonConcurrencyExceeded)
		if got := lim.PeakInFlight(); got != 4 {
			t.Fatalf("peak in-flight was %d; the cap is 4", got)
		}
	})

	t.Run("volume", func(t *testing.T) {
		caps, res := CodedCaps().Lower(CapOverrides{RequestsPerTargetRun: intPtr(3)})
		p3AssertPassed(t, res, Gate14HardCaps)
		lim, res := NewRateLimiter(caps, p3At(t, 0))
		p3AssertPassed(t, res, Gate14HardCaps)
		for i := 0; i < 3; i++ {
			p3AssertPassed(t, lim.Acquire(0, p3At(t, time.Duration(i)*time.Second)),
				Gate14HardCaps)
			lim.Release()
		}
		p3AssertRefused(t, lim.Acquire(0, p3At(t, 10*time.Second)),
			Gate14HardCaps, ReasonVolumeExceeded)
	})

	t.Run("wall clock", func(t *testing.T) {
		lim, res := NewRateLimiter(CodedCaps(), p3At(t, 0))
		p3AssertPassed(t, res, Gate14HardCaps)
		p3AssertPassed(t, lim.Acquire(0, p3At(t, 29*time.Minute)), Gate14HardCaps)
		lim.Release()
		p3AssertRefused(t, lim.Acquire(0, p3At(t, 30*time.Minute+time.Second)),
			Gate14HardCaps, ReasonWallClockExceeded)
	})

	t.Run("retries", func(t *testing.T) {
		lim, res := NewRateLimiter(CodedCaps(), p3At(t, 0))
		p3AssertPassed(t, res, Gate14HardCaps)
		for attempt := 0; attempt <= 3; attempt++ {
			p3AssertPassed(t, lim.Acquire(attempt, p3At(t, time.Duration(attempt)*time.Second)),
				Gate14HardCaps)
			lim.Release()
		}
		p3AssertRefused(t, lim.Acquire(4, p3At(t, 10*time.Second)),
			Gate14HardCaps, ReasonRetryBudgetExceeded)
		p3AssertRefused(t, lim.Acquire(-1, p3At(t, 10*time.Second)),
			Gate14HardCaps, ReasonRetryBudgetExceeded)
	})

	t.Run("a clock that moves backwards", func(t *testing.T) {
		lim, res := NewRateLimiter(CodedCaps(), p3At(t, 0))
		p3AssertPassed(t, res, Gate14HardCaps)
		p3AssertPassed(t, lim.Acquire(0, p3At(t, time.Minute)), Gate14HardCaps)
		lim.Release()
		p3AssertRefused(t, lim.Acquire(0, p3At(t, 30*time.Second)),
			Gate14HardCaps, ReasonCapClockWentBack)
	})

	t.Run("a double release does not drive the semaphore negative", func(t *testing.T) {
		lim, res := NewRateLimiter(CodedCaps(), p3At(t, 0))
		p3AssertPassed(t, res, Gate14HardCaps)
		p3AssertPassed(t, lim.Acquire(0, p3At(t, 0)), Gate14HardCaps)
		p3AssertPassed(t, lim.Release(), Gate14HardCaps)
		p3AssertRefused(t, lim.Release(), Gate14HardCaps, ReasonConcurrencyExceeded)
		if got := lim.InFlight(); got != 0 {
			t.Fatalf("in-flight is %d after a double release; it must not go below zero", got)
		}
	})

	t.Run("an unconstructed clock or Caps", func(t *testing.T) {
		if _, res := NewRateLimiter(Caps{}, p3At(t, 0)); res.Passed() {
			t.Error("a limiter was built on a zero Caps")
		}
		if _, res := NewRateLimiter(CodedCaps(), Clock{}); res.Passed() {
			t.Error("a limiter was built on a zero Clock")
		}
	})
}

// ---------------------------------------------------------------------------
// The body cap, enforced WHILE READING
// ---------------------------------------------------------------------------

// countingReader serves an unbounded stream and counts how many bytes it was
// ASKED for. It is the instrument for "a 4 GiB response must not be buffered
// to discover it is too big": if the bound were checked after the read, this
// counter would reach four gigabytes.
type countingReader struct {
	served int64
	limit  int64
}

func (r *countingReader) Read(p []byte) (int, error) {
	if r.served >= r.limit {
		return 0, io.EOF
	}
	n := int64(len(p))
	if r.served+n > r.limit {
		n = r.limit - r.served
	}
	for i := range p[:n] {
		p[i] = 'A'
	}
	r.served += n
	return int(n), nil
}

func TestBoundedBodyNeverBuffersAFourGigabyteResponse(t *testing.T) {
	const fourGiB = int64(4) << 30
	src := &countingReader{limit: fourGiB}

	body, res := LimitBody(src, CodedCaps())
	p3AssertPassed(t, res, Gate14HardCaps)

	n, err := io.Copy(io.Discard, body)
	if !errors.Is(err, ErrBodyExceedsCap) {
		t.Fatalf("reading a 4 GiB body returned %v; want ErrBodyExceedsCap", err)
	}
	if !errors.Is(err, ErrRefused) {
		t.Fatalf("the body refusal does not unwrap to ErrRefused: %v", err)
	}
	if n > CodedMaxBodyBytes+1 {
		t.Fatalf("io.Copy moved %d bytes; the cap is %d", n, CodedMaxBodyBytes)
	}
	if src.served > CodedMaxBodyBytes+1 {
		t.Fatalf("the underlying reader was asked for %d bytes to discover the body was "+
			"too big. The cap is %d and the reader may be asked for at most one byte "+
			"past it — otherwise a hostile target sizes Anvil's heap", src.served,
			CodedMaxBodyBytes)
	}
	if src.served < CodedMaxBodyBytes {
		t.Fatalf("the reader was only asked for %d bytes, so the cap is being enforced "+
			"below its value", src.served)
	}
}

func TestBoundedBodyReadsABodyAtExactlyTheCap(t *testing.T) {
	src := &countingReader{limit: CodedMaxBodyBytes}
	body, res := LimitBody(src, CodedCaps())
	p3AssertPassed(t, res, Gate14HardCaps)

	n, err := io.Copy(io.Discard, body)
	if err != nil {
		t.Fatalf("a body of exactly the cap was refused: %v", err)
	}
	if n != CodedMaxBodyBytes {
		t.Fatalf("read %d bytes of a %d-byte body", n, CodedMaxBodyBytes)
	}
	if got := body.Consumed(); got != CodedMaxBodyBytes {
		t.Fatalf("the reader reports %d bytes consumed after reading %d", got, n)
	}
	if got := body.Limit(); got != CodedMaxBodyBytes {
		t.Fatalf("the reader reports a limit of %d", got)
	}
}

func TestBoundedBodyRefusesOneByteOverALoweredCap(t *testing.T) {
	caps, res := CodedCaps().Lower(CapOverrides{BodyBytes: int64Ptr(16)})
	p3AssertPassed(t, res, Gate14HardCaps)

	body, res := LimitBody(strings.NewReader(strings.Repeat("A", 17)), caps)
	p3AssertPassed(t, res, Gate14HardCaps)
	if _, err := io.Copy(io.Discard, body); !errors.Is(err, ErrBodyExceedsCap) {
		t.Fatalf("17 bytes against a 16-byte cap returned %v", err)
	}

	body, res = LimitBody(strings.NewReader(strings.Repeat("A", 16)), caps)
	p3AssertPassed(t, res, Gate14HardCaps)
	if _, err := io.Copy(io.Discard, body); err != nil {
		t.Fatalf("16 bytes against a 16-byte cap was refused: %v", err)
	}
}

// TestBoundedBodyRefusesOnTheReadThatCrossesTheCap is the difference between
// the two layers in BoundedBody.Read, and it exists because a mutation run
// found them indistinguishable without it.
//
// Removing the check at the END of Read left the suite green: the check at the
// TOP caught the overrun on the NEXT call, and io.Copy always makes one. But a
// caller that reads once and stops would have been handed bytes past the cap
// with a nil error and would never have learned. The refusal has to land on
// the read that crosses the cap.
func TestBoundedBodyRefusesOnTheReadThatCrossesTheCap(t *testing.T) {
	caps, res := CodedCaps().Lower(CapOverrides{BodyBytes: int64Ptr(4)})
	p3AssertPassed(t, res, Gate14HardCaps)

	body, res := LimitBody(strings.NewReader("AAAAA"), caps)
	p3AssertPassed(t, res, Gate14HardCaps)

	// ONE Read call, which crosses the 4-byte cap.
	n, err := body.Read(make([]byte, 8))
	if !errors.Is(err, ErrBodyExceedsCap) {
		t.Fatalf("the first Read past the cap returned (%d, %v); the refusal must land on "+
			"the read that crosses the cap, not on a later one that the caller may never "+
			"make", n, err)
	}
}

// TestBoundedBodyKeepsRefusingAfterItHasRefused is the other layer: a caller
// that ignores the error and reads again must be refused again, and must not
// index a negative-length slice on the way. Removing the check at the top of
// Read turns this test into a panic.
func TestBoundedBodyKeepsRefusingAfterItHasRefused(t *testing.T) {
	caps, res := CodedCaps().Lower(CapOverrides{BodyBytes: int64Ptr(4)})
	p3AssertPassed(t, res, Gate14HardCaps)

	body, res := LimitBody(strings.NewReader(strings.Repeat("A", 64)), caps)
	p3AssertPassed(t, res, Gate14HardCaps)

	if _, err := body.Read(make([]byte, 8)); !errors.Is(err, ErrBodyExceedsCap) {
		t.Fatalf("premise: the first over-cap read did not refuse: %v", err)
	}
	for i := 0; i < 3; i++ {
		n, err := body.Read(make([]byte, 8))
		if !errors.Is(err, ErrBodyExceedsCap) {
			t.Fatalf("read %d after the refusal returned (%d, %v)", i, n, err)
		}
		if n != 0 {
			t.Fatalf("read %d after the refusal still returned %d bytes", i, n)
		}
	}
}

// callCountingReader counts Read CALLS, not bytes.
type callCountingReader struct {
	calls int
	body  string
	pos   int
}

func (r *callCountingReader) Read(p []byte) (int, error) {
	r.calls++
	if r.pos >= len(r.body) {
		return 0, io.EOF
	}
	n := copy(p, r.body[r.pos:])
	r.pos += n
	return n, nil
}

// TestBoundedBodyDoesNotTouchTheReaderAfterItHasRefused is the property the
// early return in BoundedBody.Read actually holds.
//
// A mutation run showed that deleting that branch changes no refusal — the
// check at the bottom of Read fires on the next call anyway, because `room`
// can never go negative. What it does change is whether Anvil reads from the
// socket again after it has already decided the body is too big, and that is
// the difference this test measures.
func TestBoundedBodyDoesNotTouchTheReaderAfterItHasRefused(t *testing.T) {
	caps, res := CodedCaps().Lower(CapOverrides{BodyBytes: int64Ptr(4)})
	p3AssertPassed(t, res, Gate14HardCaps)

	src := &callCountingReader{body: strings.Repeat("A", 64)}
	body, res := LimitBody(src, caps)
	p3AssertPassed(t, res, Gate14HardCaps)

	if _, err := body.Read(make([]byte, 8)); !errors.Is(err, ErrBodyExceedsCap) {
		t.Fatalf("premise: the first over-cap read did not refuse: %v", err)
	}
	after := src.calls
	for i := 0; i < 5; i++ {
		if _, err := body.Read(make([]byte, 8)); !errors.Is(err, ErrBodyExceedsCap) {
			t.Fatalf("read %d after the refusal did not refuse: %v", i, err)
		}
	}
	if src.calls != after {
		t.Fatalf("the underlying reader was called %d more time(s) after the body was "+
			"refused. Once the cap is crossed there is nothing left to learn from the "+
			"socket, and a refused body must not keep reading from it",
			src.calls-after)
	}
}

func TestLimitBodyRefusesANilReaderAndAZeroCaps(t *testing.T) {
	if _, res := LimitBody(nil, CodedCaps()); res.Passed() {
		t.Error("LimitBody accepted a nil reader. A nil body is not an unbounded one")
	}
	if _, res := LimitBody(strings.NewReader("x"), Caps{}); res.Passed() {
		t.Error("LimitBody accepted a zero Caps")
	}
}

// ===========================================================================
// GATE 15 — the static denylist
// ===========================================================================

func TestGate15RefusesEveryDestructiveTechnique(t *testing.T) {
	// The list is hand-written from research/20 gate 15's prose, not read
	// back from DestructiveTechniques().
	wanted := []Technique{
		"resource_exhaustion",
		"denial_of_service",
		"credential_brute_force",
		"password_spraying",
		"authentication_lockout_sequence",
		"exploitation_past_proof_of_existence",
		"bulk_data_extraction",
		"persistence",
		"lateral_movement",
		"destructive_write",
	}
	for _, tech := range wanted {
		t.Run(string(tech), func(t *testing.T) {
			if !tech.Destructive() {
				t.Fatalf("%q is not on the compiled-in denylist", tech)
			}
			// GET is a safe method; the technique alone must refuse.
			p3AssertRefused(t,
				CheckGate15DestructiveTechnique(tech, MethodGet, "/", EndpointAllowance{}),
				Gate15DestructiveTechniques, ReasonTechniqueDestructive)
		})
	}
	if got := len(DestructiveTechniques()); got != len(wanted) {
		t.Errorf("the denylist has %d entries and this test enumerates %d. A technique "+
			"added to the implementation without a line here is a technique nobody "+
			"tested", got, len(wanted))
	}
}

// TestGate15RefusesATechniqueOnNeitherList is the allowlist half. A denylist
// alone would let a technique nobody thought to name arrive PERMITTED.
func TestGate15RefusesATechniqueOnNeitherList(t *testing.T) {
	for _, tech := range []Technique{
		"", "cache_poisoning", "RESOURCE_EXHAUSTION", "resource exhaustion",
		"proof_of_existence ", "dos", "fuzz",
	} {
		p3AssertRefused(t,
			CheckGate15DestructiveTechnique(tech, MethodGet, "/", EndpointAllowance{}),
			Gate15DestructiveTechniques, ReasonTechniqueUnclassified)
	}
}

func TestGate15PermitsTheNonDestructiveTechniques(t *testing.T) {
	for _, tech := range PermittedTechniques() {
		p3AssertPassed(t,
			CheckGate15DestructiveTechnique(tech, MethodGet, "/status", EndpointAllowance{}),
			Gate15DestructiveTechniques)
	}
}

// TestDestructiveDenylistCannotBeMutated is the same guard per-target admission wrote for the
// reserved ranges: an accessor that hands out a live backing array is a list
// anything holding it can edit.
func TestDestructiveDenylistCannotBeMutated(t *testing.T) {
	got := DestructiveTechniques()
	for i := range got {
		got[i] = "harmless"
	}
	got = append(got, TechniqueProofOfExistence)
	_ = got

	if !TechniqueDenialOfService.Destructive() {
		t.Fatal("mutating the slice DestructiveTechniques() returned removed an entry " +
			"from the compiled-in denylist")
	}
	p3AssertRefused(t,
		CheckGate15DestructiveTechnique(TechniqueDenialOfService, MethodGet, "/",
			EndpointAllowance{}),
		Gate15DestructiveTechniques, ReasonTechniqueDestructive)

	perm := PermittedTechniques()
	for i := range perm {
		perm[i] = TechniqueDenialOfService
	}
	if TechniqueDenialOfService.Classified() != true || !TechniqueProofOfExistence.Classified() {
		t.Fatal("mutating the slice PermittedTechniques() returned changed the allowlist")
	}
}

func TestGate15RefusesAStateChangingMethodWithoutAPerEndpointAllow(t *testing.T) {
	empty, err := NewEndpointAllowance()
	if err != nil {
		t.Fatalf("NewEndpointAllowance(): %v", err)
	}
	for _, m := range []Method{MethodPost, MethodPut, MethodPatch, MethodDelete} {
		t.Run(string(m), func(t *testing.T) {
			p3AssertRefused(t,
				CheckGate15DestructiveTechnique(TechniqueProofOfExistence, m, "/orders/1", empty),
				Gate15DestructiveTechniques, ReasonStateChangingWithoutAll)
			// The zero allowance refuses too.
			p3AssertRefused(t,
				CheckGate15DestructiveTechnique(TechniqueProofOfExistence, m, "/orders/1",
					EndpointAllowance{}),
				Gate15DestructiveTechniques, ReasonStateChangingWithoutAll)
		})
	}
}

func TestGate15AllowsExactlyTheEndpointTheOperatorNamed(t *testing.T) {
	allow, err := NewEndpointAllowance(EndpointRule{Method: MethodPost, Path: "/api/echo"})
	if err != nil {
		t.Fatalf("NewEndpointAllowance: %v", err)
	}
	p3AssertPassed(t,
		CheckGate15DestructiveTechnique(TechniqueProofOfExistence, MethodPost, "/api/echo", allow),
		Gate15DestructiveTechniques)

	// A different path, a different method, and a prefix are all refused: the
	// allow is per endpoint and there is no pattern language.
	for _, c := range []struct {
		m Method
		p string
	}{
		{MethodPost, "/api/echo/2"},
		{MethodPost, "/api/ech"},
		{MethodPut, "/api/echo"},
		{MethodDelete, "/api/echo"},
	} {
		p3AssertRefused(t,
			CheckGate15DestructiveTechnique(TechniqueProofOfExistence, c.m, c.p, allow),
			Gate15DestructiveTechniques, ReasonStateChangingWithoutAll)
	}
}

func TestNewEndpointAllowanceRefusesEveryMalformedRule(t *testing.T) {
	cases := []struct {
		name string
		rule EndpointRule
	}{
		{"no method", EndpointRule{Path: "/x"}},
		{"unknown method", EndpointRule{Method: Method("PURGE"), Path: "/x"}},
		{"a safe method needs no allowance", EndpointRule{Method: MethodGet, Path: "/x"}},
		{"empty path", EndpointRule{Method: MethodPost}},
		{"relative path", EndpointRule{Method: MethodPost, Path: "x"}},
		{"wildcard path", EndpointRule{Method: MethodPost, Path: "/api/*"}},
		{"control byte in path", EndpointRule{Method: MethodPost, Path: "/a\tb"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			a, err := NewEndpointAllowance(c.rule)
			if err == nil {
				t.Fatalf("NewEndpointAllowance accepted %s", c.name)
			}
			if !errors.Is(err, ErrRefused) {
				t.Fatalf("the refusal does not unwrap to ErrRefused: %v", err)
			}
			if a.Constructed() {
				t.Fatal("a refused allowance still reported Constructed()")
			}
		})
	}
}

func TestGate15RefusesAnUnknownMethodAndAMalformedPath(t *testing.T) {
	p3AssertRefused(t,
		CheckGate15DestructiveTechnique(TechniqueProofOfExistence, Method("TRACE"), "/",
			EndpointAllowance{}),
		Gate15DestructiveTechniques, ReasonTechniqueMethodUnknown)
	p3AssertRefused(t,
		CheckGate15DestructiveTechnique(TechniqueProofOfExistence, MethodGet, "no-leading-slash",
			EndpointAllowance{}),
		Gate15DestructiveTechniques, ReasonTechniquePathMalformed)
}

// ===========================================================================
// GATE 16 — the circuit breaker
// ===========================================================================

func p3Monitor(t *testing.T) *HealthMonitor {
	t.Helper()
	m, res := NewHealthMonitor(
		p3Target(t, SchemeHTTPS, "target.example.com", 443, p3ExternalAddr),
		CodedHealthThresholds(), p3At(t, 0))
	p3AssertPassed(t, res, Gate16CircuitBreaker)
	return m
}

// TestCircuitBreakerTripsOnTheServerErrorRateAndQuarantinesForTheRun is the
// 5xx half of per-request enforcement's required breaker test.
//
// The denominator rule is measured here rather than hidden: with fewer than
// minRateSamples observations the rate rule cannot fire, because one request
// answering 500 is a 100% error rate and is evidence of nothing. That is a
// deliberate permissiveness and it is asserted, so it cannot drift.
func TestCircuitBreakerTripsOnTheServerErrorRateAndQuarantinesForTheRun(t *testing.T) {
	t.Run("below the denominator the rule cannot fire", func(t *testing.T) {
		m := p3Monitor(t)
		for i := 0; i < minRateSamples-1; i++ {
			res := m.ObserveResponse(500, 50*time.Millisecond,
				p3At(t, time.Duration(i)*time.Second))
			if !res.Passed() {
				t.Fatalf("the breaker tripped on observation %d of %d, below the "+
					"denominator: %v", i+1, minRateSamples-1, res.Err())
			}
		}
		if m.Tripped() {
			t.Fatal("tripped below the minimum sample count")
		}
	})

	t.Run("15% of 5xx over the denominator trips", func(t *testing.T) {
		m := p3Monitor(t)
		// 20 requests, 3 of them 5xx: 15%, above the 10% threshold.
		statuses := []int{
			200, 200, 500, 200, 200, 200, 500, 200, 200, 200,
			200, 200, 500, 200, 200, 200, 200, 200, 200, 200,
		}
		var last GateResult
		for i, s := range statuses {
			last = m.ObserveResponse(s, 50*time.Millisecond,
				p3At(t, time.Duration(i)*time.Second))
		}
		p3AssertRefused(t, last, Gate16CircuitBreaker, ReasonBreakerServerErrors)
		if !m.Tripped() {
			t.Fatal("the breaker did not trip at 15% 5xx")
		}
	})

	t.Run("10% exactly does not trip; the threshold is 'above'", func(t *testing.T) {
		m := p3Monitor(t)
		for i := 0; i < 20; i++ {
			status := 200
			if i%10 == 0 {
				status = 503
			}
			res := m.ObserveResponse(status, 50*time.Millisecond,
				p3At(t, time.Duration(i)*time.Second))
			if !res.Passed() {
				t.Fatalf("the breaker tripped at exactly 10%%: %v", res.Err())
			}
		}
	})

	t.Run("once tripped, the target is quarantined for the rest of the run", func(t *testing.T) {
		m := p3Monitor(t)
		for i := 0; i < 20; i++ {
			m.ObserveResponse(500, 50*time.Millisecond, p3At(t, time.Duration(i)*time.Second))
		}
		if !m.Tripped() {
			t.Fatal("premise: the breaker did not trip on 20 consecutive 500s")
		}
		p3AssertRefused(t, CheckGate16CircuitBreaker(m),
			Gate16CircuitBreaker, ReasonTargetQuarantined)
		// A perfect run of 200s afterwards does not un-quarantine it.
		for i := 20; i < 200; i++ {
			res := m.ObserveResponse(200, time.Millisecond,
				p3At(t, time.Duration(i)*time.Second))
			p3AssertRefused(t, res, Gate16CircuitBreaker, ReasonTargetQuarantined)
		}
		p3AssertRefused(t, CheckGate16CircuitBreaker(m),
			Gate16CircuitBreaker, ReasonTargetQuarantined)

		// The incident is available for the audit record.
		reason, detail, at := m.Incident()
		if reason != ReasonBreakerServerErrors {
			t.Fatalf("incident reason is %q", string(reason))
		}
		if detail == "" || at.IsZero() {
			t.Fatal("the incident carries no detail or no instant")
		}
	})

	t.Run("there is no exported way back", func(t *testing.T) {
		ty := reflect.TypeOf(HealthMonitor{})
		for i := 0; i < ty.NumField(); i++ {
			if ty.Field(i).IsExported() {
				t.Errorf("HealthMonitor.%s is exported; a caller could clear the trip",
					ty.Field(i).Name)
			}
		}
		for _, name := range []string{"Reset", "Clear", "Close", "Reopen", "SetTripped"} {
			if _, ok := reflect.TypeOf(&HealthMonitor{}).MethodByName(name); ok {
				t.Errorf("HealthMonitor has a %s method. \"Quarantined for the rest of the "+
					"run\" is only true while there is no way back", name)
			}
		}
	})
}

func TestCircuitBreakerTripsOnTheConnectionErrorRate(t *testing.T) {
	m := p3Monitor(t)
	var last GateResult
	for i := 0; i < 20; i++ {
		if i%4 == 0 {
			last = m.ObserveConnectionError(p3At(t, time.Duration(i)*time.Second))
			continue
		}
		last = m.ObserveResponse(200, 20*time.Millisecond, p3At(t, time.Duration(i)*time.Second))
	}
	p3AssertRefused(t, last, Gate16CircuitBreaker, ReasonBreakerConnErrors)
	total, srv, conn := m.Observations()
	if total != 20 || srv != 0 || conn != 5 {
		t.Fatalf("observations are total=%d 5xx=%d conn=%d; want 20/0/5", total, srv, conn)
	}
}

// TestCircuitBreakerTripsOnSustainedLatencyAndNotOnASpike is the p95 half of
// per-request enforcement's required breaker test: "p95>3×baseline sustained 30s".
//
// Both halves are asserted. A spike shorter than the sustain window must NOT
// trip — otherwise the "sustained 30s" clause is decoration — and a sustained
// elevation must, and not before 30 seconds have passed.
func TestCircuitBreakerTripsOnSustainedLatencyAndNotOnASpike(t *testing.T) {
	const (
		baselineLatency = 100 * time.Millisecond
		elevated        = 400 * time.Millisecond // > 3 × 100ms
	)

	// A baseline of 25 samples inside the first 60 seconds.
	buildBaseline := func(t *testing.T) *HealthMonitor {
		t.Helper()
		m := p3Monitor(t)
		for i := 0; i < 25; i++ {
			res := m.ObserveResponse(200, baselineLatency,
				p3At(t, time.Duration(i)*time.Second))
			if !res.Passed() {
				t.Fatalf("the breaker tripped while establishing the baseline: %v", res.Err())
			}
		}
		return m
	}

	t.Run("a spike shorter than the sustain window does not trip", func(t *testing.T) {
		m := buildBaseline(t)
		// Ten seconds of elevation, then back to normal for a long while.
		for s := 60; s < 70; s++ {
			m.ObserveResponse(200, elevated, p3At(t, time.Duration(s)*time.Second))
		}
		for s := 70; s < 200; s++ {
			m.ObserveResponse(200, baselineLatency, p3At(t, time.Duration(s)*time.Second))
		}
		if m.Tripped() {
			t.Fatal("the breaker tripped on a 10-second spike; the sustain window is 30s")
		}
	})

	t.Run("sustained elevation trips, and not before 30 seconds", func(t *testing.T) {
		m := buildBaseline(t)
		if !m.BaselineEstablished() {
			// The baseline is frozen the first time an observation lands at
			// or after 60s, so this is expected to be false here.
			t.Log("baseline not yet frozen before the window closed, as expected")
		}
		trippedAtSecond := -1
		for s := 60; s <= 200 && trippedAtSecond < 0; s++ {
			res := m.ObserveResponse(200, elevated, p3At(t, time.Duration(s)*time.Second))
			if !res.Passed() {
				p3AssertRefused(t, res, Gate16CircuitBreaker, ReasonBreakerLatency)
				trippedAtSecond = s
			}
		}
		if trippedAtSecond < 0 {
			t.Fatal("the breaker never tripped on sustained elevated latency")
		}
		// Elevation cannot have started before t=60s, so a trip before t=90s
		// would mean the sustain window was not honoured.
		if trippedAtSecond < 90 {
			t.Fatalf("the breaker tripped at t=%ds. Elevation cannot begin before t=60s "+
				"and the sustain window is 30s, so the earliest honest trip is t=90s",
				trippedAtSecond)
		}
		if !m.BaselineEstablished() {
			t.Fatal("the breaker tripped on latency without an established baseline")
		}
		if got := m.BaselineP95(); got != baselineLatency {
			t.Fatalf("baseline p95 is %s; every baseline sample was %s", got, baselineLatency)
		}
		p3AssertRefused(t, CheckGate16CircuitBreaker(m),
			Gate16CircuitBreaker, ReasonTargetQuarantined)
	})

	t.Run("without a baseline the latency rule is inactive and says so", func(t *testing.T) {
		m := p3Monitor(t)
		// Three samples in the baseline window: below minBaselineSamples.
		for i := 0; i < 3; i++ {
			m.ObserveResponse(200, baselineLatency, p3At(t, time.Duration(i)*time.Second))
		}
		for s := 60; s <= 300; s++ {
			m.ObserveResponse(200, 5*time.Second, p3At(t, time.Duration(s)*time.Second))
		}
		if m.BaselineEstablished() {
			t.Fatal("a baseline of 3 samples was reported as established")
		}
		if m.Tripped() {
			t.Fatal("the latency rule fired without a baseline")
		}
		// The 5xx rule is still live, which is what makes the inactive
		// latency rule a stated limitation rather than a hole.
		for s := 301; s <= 400; s++ {
			m.ObserveResponse(500, time.Second, p3At(t, time.Duration(s)*time.Second))
		}
		if !m.Tripped() {
			t.Fatal("with no baseline the 5xx rule also stopped working")
		}
	})
}

// TestTwoShortSpikesFarApartDoNotTrip is the elevation-reset branch made
// falsifiable, and it exists because a mutation run found that branch
// indistinguishable without it.
//
// Deleting `m.elevated = false` left the suite green, because the sustain
// check sits inside `if current > ceiling` and is not reached while latency is
// normal. The difference shows up on the SECOND spike: without the reset,
// elevatedSince is still pointing at the first spike, so a one-second blip an
// hour later reads as "elevated for an hour" and trips instantly.
func TestTwoShortSpikesFarApartDoNotTrip(t *testing.T) {
	const (
		baselineLatency = 100 * time.Millisecond
		elevated        = 400 * time.Millisecond
	)
	m := p3Monitor(t)
	for i := 0; i < 25; i++ {
		m.ObserveResponse(200, baselineLatency, p3At(t, time.Duration(i)*time.Second))
	}
	observe := func(from, to int, d time.Duration) {
		t.Helper()
		for s := from; s <= to; s++ {
			res := m.ObserveResponse(200, d, p3At(t, time.Duration(s)*time.Second))
			if !res.Passed() {
				t.Fatalf("the breaker tripped at t=%ds: %v", s, res.Err())
			}
		}
	}
	observe(60, 69, elevated) // first spike, 10 seconds
	observe(70, 150, baselineLatency)
	observe(151, 160, elevated) // second spike, 10 seconds, 80 seconds later
	observe(161, 250, baselineLatency)

	if m.Tripped() {
		t.Fatal("two ten-second spikes eighty seconds apart tripped the breaker. Each is " +
			"far short of the 30-second sustain window; a breaker that adds them together " +
			"quarantines a target that was never continuously slow")
	}
}

func TestHealthMonitorRefusesMalformedObservationsAndABackwardsClock(t *testing.T) {
	t.Run("status codes outside 100..599", func(t *testing.T) {
		for _, s := range []int{0, -1, 99, 600, 1000} {
			m := p3Monitor(t)
			p3AssertRefused(t, m.ObserveResponse(s, time.Millisecond, p3At(t, time.Second)),
				Gate16CircuitBreaker, ReasonObservationMalformed)
		}
	})
	t.Run("implausible latencies", func(t *testing.T) {
		for _, d := range []time.Duration{-time.Second, maxPlausibleLatency + time.Second} {
			m := p3Monitor(t)
			p3AssertRefused(t, m.ObserveResponse(200, d, p3At(t, time.Second)),
				Gate16CircuitBreaker, ReasonObservationMalformed)
		}
	})
	t.Run("a clock that moves backwards", func(t *testing.T) {
		m := p3Monitor(t)
		p3AssertPassed(t, m.ObserveResponse(200, time.Millisecond, p3At(t, time.Minute)),
			Gate16CircuitBreaker)
		p3AssertRefused(t, m.ObserveResponse(200, time.Millisecond, p3At(t, 30*time.Second)),
			Gate16CircuitBreaker, ReasonBreakerClockWentBack)
	})
	t.Run("an unconstructed target, thresholds or clock", func(t *testing.T) {
		good := p3Target(t, SchemeHTTPS, "target.example.com", 443, p3ExternalAddr)
		if _, res := NewHealthMonitor(Target{}, CodedHealthThresholds(), p3At(t, 0)); res.Passed() {
			t.Error("a breaker was built on a zero Target")
		}
		if _, res := NewHealthMonitor(good, HealthThresholds{}, p3At(t, 0)); res.Passed() {
			t.Error("a breaker was built on zero HealthThresholds")
		}
		if _, res := NewHealthMonitor(good, CodedHealthThresholds(), Clock{}); res.Passed() {
			t.Error("a breaker was built on a zero Clock")
		}
	})
}

// TestHealthThresholdsMayBeTightenedAndNeverLoosened is gate 16's Configurable
// column: "Thresholds may be tightened; the floor is not configurable upward".
func TestHealthThresholdsMayBeTightenedAndNeverLoosened(t *testing.T) {
	floors := CodedHealthThresholds()

	loosen := []struct {
		name string
		over ThresholdOverrides
	}{
		{"5xx rate", ThresholdOverrides{ServerErrorRate: floatPtr(0.5)}},
		{"5xx rate, absurd", ThresholdOverrides{ServerErrorRate: floatPtr(1.0)}},
		{"connection error rate", ThresholdOverrides{ConnectionErrorRate: floatPtr(0.9)}},
		{"latency multiple", ThresholdOverrides{LatencyMultiple: floatPtr(10)}},
		{"sustain window", ThresholdOverrides{SustainWindow: durPtr(10 * time.Minute)}},
	}
	for _, c := range loosen {
		t.Run(c.name, func(t *testing.T) {
			got, res := floors.Lower(c.over)
			p3AssertRefused(t, res, Gate16CircuitBreaker, ReasonThresholdRaise)
			if got.Constructed() {
				t.Fatal("a refused Lower returned a constructed HealthThresholds")
			}
		})
	}

	tightened, res := floors.Lower(ThresholdOverrides{
		ServerErrorRate:     floatPtr(0.02),
		ConnectionErrorRate: floatPtr(0.02),
		LatencyMultiple:     floatPtr(1.5),
		SustainWindow:       durPtr(5 * time.Second),
	})
	p3AssertPassed(t, res, Gate16CircuitBreaker)
	if v, _ := tightened.ServerErrorRate(); v != 0.02 {
		t.Errorf("5xx threshold is %v after tightening to 0.02", v)
	}

	// A sequence cannot walk one back up.
	if _, res := tightened.Lower(ThresholdOverrides{ServerErrorRate: floatPtr(0.05)}); res.Passed() {
		t.Error("a threshold was walked back up from 0.02 to 0.05")
	}

	// And a tightened threshold really trips sooner: 5% of 5xx is under the
	// coded 10% and over the configured 2%.
	m, res := NewHealthMonitor(
		p3Target(t, SchemeHTTPS, "target.example.com", 443, p3ExternalAddr),
		tightened, p3At(t, 0))
	p3AssertPassed(t, res, Gate16CircuitBreaker)
	var last GateResult
	for i := 0; i < 20; i++ {
		status := 200
		if i == 7 {
			status = 500
		}
		last = m.ObserveResponse(status, 10*time.Millisecond,
			p3At(t, time.Duration(i)*time.Second))
	}
	p3AssertRefused(t, last, Gate16CircuitBreaker, ReasonBreakerServerErrors)
}

// ===========================================================================
// GATE 17 — 429 and Retry-After, absolute
// ===========================================================================

func p3Ledger(t *testing.T) *BackoffLedger {
	t.Helper()
	b, res := NewBackoffLedger(
		p3Target(t, SchemeHTTPS, "target.example.com", 443, p3ExternalAddr), p3At(t, 0))
	p3AssertPassed(t, res, Gate17RetryAfter)
	return b
}

func p3RetryAfter(v string) http.Header {
	h := http.Header{}
	h.Set("Retry-After", v)
	return h
}

func TestRetryAfterIsAbsoluteNotAdvisory(t *testing.T) {
	b := p3Ledger(t)

	p3AssertPassed(t, CheckGate17RetryAfter(b, p3At(t, 0)), Gate17RetryAfter)

	res := b.Observe429(p3RetryAfter("120"), p3At(t, time.Second))
	p3AssertRefused(t, res, Gate17RetryAfter, ReasonServerSaid429)

	until, open := b.BackoffUntil()
	if !open {
		t.Fatal("no backoff window is open after a 429")
	}
	if want := fixtureNow.Add(time.Second + 120*time.Second); !until.Equal(want) {
		t.Fatalf("the deadline is %s; 120 seconds after the 429 is %s", until, want)
	}

	// Every instant inside the window refuses. There is no partial backoff.
	for _, at := range []time.Duration{time.Second, 30 * time.Second, 60 * time.Second,
		120 * time.Second, 120*time.Second + 999*time.Millisecond} {
		p3AssertRefused(t, CheckGate17RetryAfter(b, p3At(t, at)),
			Gate17RetryAfter, ReasonInsideRetryAfter)
	}
	// And the instant it elapses, it stops refusing.
	p3AssertPassed(t, CheckGate17RetryAfter(b, p3At(t, 121*time.Second)), Gate17RetryAfter)
}

// TestGate17ClampsArePinnedToTheirValues is kernel review finding HIGH 4.
//
// # What was measured
//
// codedMinRetryAfter and codedDefaultRetryAfter were both set to 0 and THE
// ENTIRE REPOSITORY SUITE STAYED GREEN. With them at zero, "Retry-After: 0"
// yields a zero-second backoff and an unparseable Retry-After yields no backoff
// at all — which is gate 17 ("honoured as ABSOLUTE") not existing. The comment
// on the lower clamp calls it "a control, not tidiness"; writing that in a
// comment pins nothing.
//
// The numbers here are hand-written literals, not readings of the constants
// under some other name, so changing either constant turns this red. The
// behavioural half below is what says why each number matters: a value pin
// alone would still be green if the clamp were applied to the wrong thing.
func TestGate17ClampsArePinnedToTheirValues(t *testing.T) {
	if codedMinRetryAfter != 1*time.Second {
		t.Errorf("codedMinRetryAfter is %s; it is 1s. It is the floor under a PARSED "+
			"Retry-After, and a hostile or broken target answering \"Retry-After: 0\" is "+
			"not permission to retry immediately", codedMinRetryAfter)
	}
	if codedDefaultRetryAfter != 60*time.Second {
		t.Errorf("codedDefaultRetryAfter is %s; it is 60s. It is the backoff applied when "+
			"a 429 arrives with no Retry-After or with one that will not parse, and it "+
			"is deliberately longer than a typical server would ask for: an unreadable "+
			"instruction to slow down is not an absent one", codedDefaultRetryAfter)
	}
	if codedMaxRetryAfter != 24*time.Hour {
		t.Errorf("codedMaxRetryAfter is %s; it is 24h", codedMaxRetryAfter)
	}
	if CodedTooManyRequestsAbortCount != 3 {
		t.Errorf("CodedTooManyRequestsAbortCount is %d; research/20 gate 17 is \"three "+
			"429s abort the target\"", CodedTooManyRequestsAbortCount)
	}
	if codedMinRetryAfter <= 0 || codedDefaultRetryAfter <= 0 {
		t.Fatal("a clamp of zero is a clamp that does not exist: \"Retry-After: 0\" would " +
			"mean retry immediately, and an unreadable Retry-After would mean no backoff " +
			"at all")
	}
}

// TestGate17LowerClampTurnsRetryAfterZeroIntoAWait is the behavioural half of
// the 1s floor: the number is not merely declared, it is applied.
func TestGate17LowerClampTurnsRetryAfterZeroIntoAWait(t *testing.T) {
	now := p3At(t, 0)
	for _, header := range []string{"0", "  0  ", "1"} {
		got, err := ParseRetryAfter(header, now)
		if err != nil {
			t.Fatalf("ParseRetryAfter(%q): %v", header, err)
		}
		if got != 1*time.Second {
			t.Fatalf("ParseRetryAfter(%q) = %s; want 1s. A target under load answering "+
				"\"Retry-After: 0\" is asking Anvil to slow down, and the one instruction "+
				"a rate-limit response cannot be giving is \"retry immediately\"",
				header, got)
		}
	}
	// An HTTP-date already in the past is the same instruction wearing the
	// other of RFC 9110's two forms.
	past := fixtureNow.Add(-time.Hour).UTC().Format(http.TimeFormat)
	got, err := ParseRetryAfter(past, now)
	if err != nil {
		t.Fatalf("ParseRetryAfter(%q): %v", past, err)
	}
	if got != 1*time.Second {
		t.Fatalf("ParseRetryAfter(a date one hour in the past) = %s; want 1s", got)
	}

	// And the clamp reaches the ledger, which is where it stops a request.
	b := p3Ledger(t)
	p3AssertRefused(t, b.Observe429(p3RetryAfter("0"), p3At(t, 0)),
		Gate17RetryAfter, ReasonServerSaid429)
	p3AssertRefused(t, CheckGate17RetryAfter(b, p3At(t, 999*time.Millisecond)),
		Gate17RetryAfter, ReasonInsideRetryAfter)
	p3AssertPassed(t, CheckGate17RetryAfter(b, p3At(t, time.Second)), Gate17RetryAfter)
}

// TestGate17DefaultAppliesWhenRetryAfterCannotBeRead is the behavioural half of
// the 60s default: an unreadable instruction to slow down is not an absent one.
//
// The window is asserted at both ends. Asserting only that a request is refused
// one second in would stay green for any positive default, and asserting only
// that it passes at some late instant would stay green for a default of zero.
func TestGate17DefaultAppliesWhenRetryAfterCannotBeRead(t *testing.T) {
	for _, header := range []string{"", "soon", "-1", "3.5", "next tuesday"} {
		t.Run(fmt.Sprintf("%q", header), func(t *testing.T) {
			b := p3Ledger(t)
			var h http.Header
			if header != "" {
				h = p3RetryAfter(header)
			}
			p3AssertRefused(t, b.Observe429(h, p3At(t, 0)),
				Gate17RetryAfter, ReasonRetryAfterUnparseable)
			p3AssertRefused(t, CheckGate17RetryAfter(b, p3At(t, 59*time.Second)),
				Gate17RetryAfter, ReasonInsideRetryAfter)
			p3AssertPassed(t, CheckGate17RetryAfter(b, p3At(t, 60*time.Second)),
				Gate17RetryAfter)
		})
	}
}

// TestMaxRedirectHopsIsPinned is kernel review finding MEDIUM 5.
//
// # What was measured
//
// maxRedirectHops was raised from 5 to 50 and the suite stayed green: the only
// test that referred to it wrote "Hop: maxRedirectHops + 1", which is satisfied
// by any value at all. A same-host redirect loop was then walked ten times
// further than the budget allows. The const's own comment says "nothing may
// raise it and nothing may lower it either" — which was false, because nothing
// checked.
//
// The 5 below is a hand-written literal. The two behavioural assertions pin the
// boundary in both directions: hop 5 is the last hop inside the budget and hop
// 6 is refused, so raising the const turns the second red and lowering it turns
// the first red.
func TestMaxRedirectHopsIsPinned(t *testing.T) {
	if maxRedirectHops != 5 {
		t.Fatalf("maxRedirectHops is %d; it is 5. Gate 13 refuses to follow ANY redirect "+
			"automatically, so a hop exists only because the egress layer chose to "+
			"re-admit one through the full gate stack; this bounds how many times it may "+
			"do that, and a same-host redirect loop past the bound is a refusal rather "+
			"than a spin", maxRedirectHops)
	}

	scope := p3ExternalScope(t)
	att := attestFor(t, scope)
	clock := mustClock(t)
	target := p3Target(t, SchemeHTTPS, "target.example.com", 443, p3ExternalAddr)
	facts := func(n int) RequestFacts {
		return RequestFacts{
			Origin: OriginRedirect, Admitted: target, Next: target,
			Method: MethodGet, Path: "/loop", Hop: n,
		}
	}

	// The last hop inside the budget builds and is permitted. This is the
	// assertion that goes red if the budget is LOWERED.
	inside, err := NewRequestIntent(facts(5))
	if err != nil {
		t.Fatalf("NewRequestIntent at hop 5: %v. Five hops are inside the budget", err)
	}
	p3AssertPassed(t, CheckGate13Revalidate(inside, scope, att, clock),
		Gate13RevalidateEveryRequest)

	// The first hop past it does not build at all. This is the assertion that
	// goes red if the budget is RAISED.
	if _, err := NewRequestIntent(facts(6)); err == nil {
		t.Fatal("NewRequestIntent built a hop-6 intent. Six hops are past the coded " +
			"budget of five, and a same-host redirect loop past the budget is a refusal " +
			"rather than a spin")
	} else if !errors.Is(err, ErrRefused) {
		t.Fatalf("the hop-6 refusal does not unwrap to ErrRefused: %v", err)
	}

	// Gate 13 carries the same bound as its own second layer, for an intent
	// that reached it without passing through NewRequestIntent. It is minted
	// here through the unexported fields, which is the strongest form still
	// expressible, and it must still be refused — naming the budget.
	overBudget := RequestIntent{
		origin: OriginRedirect, admitted: target, next: target,
		method: MethodGet, path: "/loop", hop: maxRedirectHops + 1, sealed: true,
	}
	if !overBudget.Constructed() {
		t.Fatal("setup: the hand-built over-budget intent is not constructed, so the " +
			"assertion below would be about the wrong refusal")
	}
	p3AssertRefused(t, CheckGate13Revalidate(overBudget, scope, att, clock),
		Gate13RevalidateEveryRequest, ReasonRedirectHopBudget)
}

// TestNothingShortensARetryAfterWindow is "absolute, not advisory" as a
// structural assertion: there is no exported field and no method that could
// close the window early.
func TestNothingShortensARetryAfterWindow(t *testing.T) {
	ty := reflect.TypeOf(BackoffLedger{})
	for i := 0; i < ty.NumField(); i++ {
		if ty.Field(i).IsExported() {
			t.Errorf("BackoffLedger.%s is exported; a caller could move the deadline",
				ty.Field(i).Name)
		}
	}
	for _, name := range []string{"Reset", "Clear", "SetUntil", "Shorten", "Skip", "Force"} {
		if _, ok := reflect.TypeOf(&BackoffLedger{}).MethodByName(name); ok {
			t.Errorf("BackoffLedger has a %s method", name)
		}
	}
}

func TestThreeTooManyRequestsAbortTheTarget(t *testing.T) {
	b := p3Ledger(t)

	p3AssertRefused(t, b.Observe429(p3RetryAfter("1"), p3At(t, time.Second)),
		Gate17RetryAfter, ReasonServerSaid429)
	p3AssertRefused(t, b.Observe429(p3RetryAfter("1"), p3At(t, 10*time.Second)),
		Gate17RetryAfter, ReasonServerSaid429)
	if b.Aborted() {
		t.Fatal("the target was aborted after two 429s; the coded limit is three")
	}

	p3AssertRefused(t, b.Observe429(p3RetryAfter("1"), p3At(t, 20*time.Second)),
		Gate17RetryAfter, ReasonThreeTooManyRequests)
	if !b.Aborted() {
		t.Fatal("the target was not aborted after three 429s")
	}
	if got := b.TooManyRequests(); got != CodedTooManyRequestsAbortCount {
		t.Fatalf("the ledger counted %d 429s; want %d", got, CodedTooManyRequestsAbortCount)
	}

	// Aborted is for the rest of the run, whatever the clock says.
	for _, at := range []time.Duration{21 * time.Second, time.Hour, 24 * time.Hour} {
		p3AssertRefused(t, CheckGate17RetryAfter(b, p3At(t, at)),
			Gate17RetryAfter, ReasonThreeTooManyRequests)
	}
}

func TestParseRetryAfterAcceptsBothRFCFormsAndFailsClosedOtherwise(t *testing.T) {
	now := p3At(t, 0)

	t.Run("delta-seconds", func(t *testing.T) {
		got, err := ParseRetryAfter("300", now)
		if err != nil {
			t.Fatalf("ParseRetryAfter(\"300\"): %v", err)
		}
		if got != 300*time.Second {
			t.Fatalf("got %s; want 5m", got)
		}
	})

	t.Run("HTTP-date", func(t *testing.T) {
		when := fixtureNow.Add(90 * time.Second).UTC()
		got, err := ParseRetryAfter(when.Format(http.TimeFormat), now)
		if err != nil {
			t.Fatalf("ParseRetryAfter(HTTP-date): %v", err)
		}
		if got != 90*time.Second {
			t.Fatalf("got %s; want 1m30s", got)
		}
	})

	t.Run("zero and a past date are clamped, never 'retry now'", func(t *testing.T) {
		got, err := ParseRetryAfter("0", now)
		if err != nil {
			t.Fatalf("ParseRetryAfter(\"0\"): %v", err)
		}
		if got < codedMinRetryAfter {
			t.Fatalf("Retry-After: 0 produced %s; a rate-limit response cannot be asking "+
				"to be retried immediately, so the value is clamped at %s",
				got, codedMinRetryAfter)
		}
		past := fixtureNow.Add(-time.Hour).UTC().Format(http.TimeFormat)
		got, err = ParseRetryAfter(past, now)
		if err != nil {
			t.Fatalf("ParseRetryAfter(past date): %v", err)
		}
		if got < codedMinRetryAfter {
			t.Fatalf("a past HTTP-date produced %s", got)
		}
	})

	t.Run("unparseable values", func(t *testing.T) {
		for _, v := range []string{
			"", "   ", "soon", "-5", "1.5", "0x10", "300s",
			"Mon, 32 Jan 2027 00:00:00 GMT",
			strings.Repeat("9", 200),
		} {
			if _, err := ParseRetryAfter(v, now); err == nil {
				t.Errorf("ParseRetryAfter(%q) accepted it", v)
			} else if !errors.Is(err, ErrRefused) {
				t.Errorf("ParseRetryAfter(%q) refusal does not unwrap to ErrRefused: %v", v, err)
			}
		}
	})

	t.Run("absurdly long values", func(t *testing.T) {
		for _, v := range []string{"86401", "100000000"} {
			_, err := ParseRetryAfter(v, now)
			if !errors.Is(err, ErrRetryAfterTooLong) {
				t.Errorf("ParseRetryAfter(%q) returned %v; want ErrRetryAfterTooLong", v, err)
			}
		}
	})

	t.Run("no clock", func(t *testing.T) {
		if _, err := ParseRetryAfter("60", Clock{}); err == nil {
			t.Error("ParseRetryAfter accepted a zero Clock")
		}
	})
}

func TestA429WithNoReadableRetryAfterGetsTheCodedDefault(t *testing.T) {
	for _, h := range []http.Header{nil, {}, p3RetryAfter("later")} {
		b := p3Ledger(t)
		res := b.Observe429(h, p3At(t, time.Second))
		p3AssertRefused(t, res, Gate17RetryAfter, ReasonRetryAfterUnparseable)
		until, open := b.BackoffUntil()
		if !open {
			t.Fatal("no window opened for a 429 with no readable Retry-After")
		}
		if want := fixtureNow.Add(time.Second + codedDefaultRetryAfter); !until.Equal(want) {
			t.Fatalf("deadline %s; want the coded default %s after the 429",
				until, codedDefaultRetryAfter)
		}
	}
}

func TestAnAbsurdRetryAfterAbortsTheTargetRatherThanSittingOnATimer(t *testing.T) {
	b := p3Ledger(t)
	p3AssertRefused(t, b.Observe429(p3RetryAfter("604800"), p3At(t, time.Second)),
		Gate17RetryAfter, ReasonRetryAfterAbsurd)
	if !b.Aborted() {
		t.Fatal("a week-long Retry-After did not abort the target")
	}
	p3AssertRefused(t, CheckGate17RetryAfter(b, p3At(t, time.Hour)),
		Gate17RetryAfter, ReasonThreeTooManyRequests)
}

func TestBackoffWindowNeverShrinksWhenASecond429AsksForLess(t *testing.T) {
	b := p3Ledger(t)
	p3AssertRefused(t, b.Observe429(p3RetryAfter("600"), p3At(t, 0)),
		Gate17RetryAfter, ReasonServerSaid429)
	p3AssertRefused(t, b.Observe429(p3RetryAfter("1"), p3At(t, time.Second)),
		Gate17RetryAfter, ReasonServerSaid429)

	until, _ := b.BackoffUntil()
	if want := fixtureNow.Add(600 * time.Second); !until.Equal(want) {
		t.Fatalf("the deadline moved to %s after a shorter second Retry-After; the longer "+
			"window stands (want %s)", until, want)
	}
	p3AssertRefused(t, CheckGate17RetryAfter(b, p3At(t, 5*time.Second)),
		Gate17RetryAfter, ReasonInsideRetryAfter)
}

func TestBackoffLedgerRefusesABackwardsClockAndAnUnconstructedTarget(t *testing.T) {
	b := p3Ledger(t)
	p3AssertRefused(t, b.Observe429(p3RetryAfter("1"), p3At(t, time.Minute)),
		Gate17RetryAfter, ReasonServerSaid429)
	p3AssertRefused(t, b.Observe429(p3RetryAfter("1"), p3At(t, 30*time.Second)),
		Gate17RetryAfter, ReasonLedgerClockWentBack)

	if _, res := NewBackoffLedger(Target{}, p3At(t, 0)); res.Passed() {
		t.Error("a ledger was built on a zero Target")
	}
	if _, res := NewBackoffLedger(
		p3Target(t, SchemeHTTPS, "target.example.com", 443, p3ExternalAddr), Clock{}); res.Passed() {
		t.Error("a ledger was built on a zero Clock")
	}
}

// ===========================================================================
// THE INTERCEPTOR
// ===========================================================================

func p3Governor(t *testing.T, scope Scope, target Target) *Governor {
	t.Helper()
	allow, err := NewEndpointAllowance()
	if err != nil {
		t.Fatalf("NewEndpointAllowance: %v", err)
	}
	g, res := NewGovernor(GovernorConfig{
		Target:      target,
		Scope:       scope,
		Attestation: attestFor(t, scope),
		Caps:        CodedCaps(),
		Thresholds:  CodedHealthThresholds(),
		Robots:      RobotsNotFound(target.Canonical(), target.Port()),
		Allowance:   allow,
		Start:       p3At(t, 0),
	})
	p3AssertPassed(t, res, Gate13RevalidateEveryRequest)
	return g
}

// TestAdmitTraceNamesEveryGateInOrder is the guard against the interceptor
// silently losing a gate. It compares the trace against governorGateOrder,
// which is written down separately from the code that runs the gates.
func TestAdmitTraceNamesEveryGateInOrder(t *testing.T) {
	scope := p3ExternalScope(t)
	target := p3Target(t, SchemeHTTPS, "target.example.com", 443, p3ExternalAddr)
	g := p3Governor(t, scope, target)

	intent := p3Intent(t, RequestFacts{
		Origin: OriginInitial, Admitted: target, Next: target,
		Method: MethodGet, Path: "/",
	})
	lease, trace := g.AdmitTraced(intent, TechniqueProofOfExistence, p3At(t, 0))
	if !lease.Held() {
		t.Fatalf("the request was refused: %v", LastResult(trace).Err())
	}
	want := GovernorGateOrder()
	if len(trace) != len(want) {
		t.Fatalf("the trace has %d entries and the interceptor is supposed to consult %d "+
			"gates. A gate dropped out of Admit changes this number", len(trace), len(want))
	}
	for i, r := range trace {
		if r.Gate() != want[i] {
			t.Errorf("trace[%d] names %s; want %s", i, r.Gate(), want[i])
		}
		if !r.Passed() {
			t.Errorf("trace[%d] (%s) did not pass: %v", i, r.Gate(), r.Err())
		}
	}
	lease.Release()
}

// TestAdmitStopsAtTheFirstRefusalAndSpendsNoBudget is the ordering rationale
// as a test: gate 14 is last because it is the only gate that consumes
// something, and a refusal must not burn a token.
func TestAdmitStopsAtTheFirstRefusalAndSpendsNoBudget(t *testing.T) {
	scope := p3ExternalScope(t)
	target := p3Target(t, SchemeHTTPS, "target.example.com", 443, p3ExternalAddr)
	offScope := p3Target(t, SchemeHTTPS, "cdn.example.net", 443, p3SecondExternalAddr)
	g := p3Governor(t, scope, target)

	bad := p3Intent(t, RequestFacts{
		Origin: OriginBrowserFetch, Admitted: target, Next: offScope,
		Method: MethodGet, Path: "/lib.js",
	})
	for i := 0; i < 100; i++ {
		lease, trace := g.AdmitTraced(bad, TechniqueProofOfExistence, p3At(t, 0))
		if lease.Held() {
			t.Fatal("an off-scope destination was admitted")
		}
		p3AssertRefused(t, LastResult(trace), Gate13RevalidateEveryRequest, ReasonHopOutsideScope)
		if len(trace) != 3 {
			t.Fatalf("the trace has %d entries; the refusal is at the third gate (16, 17, "+
				"13) so it must stop there", len(trace))
		}
	}
	if got := g.Limiter().Issued(); got != 0 {
		t.Fatalf("%d requests were charged against the rate budget by 100 refusals. A "+
			"refusal that spends budget lets a caller drain a target's allowance with "+
			"requests that were never issued", got)
	}
	admitted, refused := g.Counts()
	if admitted != 0 || refused != 100 {
		t.Fatalf("counts are admitted=%d refused=%d; want 0/100", admitted, refused)
	}
}

// TestAdmitRefusesAtEachGateIndividually drives the interceptor to refuse at
// every one of its six gates, so that no gate can be dropped without a test
// going red.
func TestAdmitRefusesAtEachGateIndividually(t *testing.T) {
	scope := p3ExternalScope(t)
	target := p3Target(t, SchemeHTTPS, "target.example.com", 443, p3ExternalAddr)
	good := func(t *testing.T) RequestIntent {
		return p3Intent(t, RequestFacts{
			Origin: OriginInitial, Admitted: target, Next: target,
			Method: MethodGet, Path: "/",
		})
	}

	t.Run("gate16 quarantine", func(t *testing.T) {
		g := p3Governor(t, scope, target)
		for i := 0; i < 20; i++ {
			g.Health().ObserveResponse(500, time.Millisecond,
				p3At(t, time.Duration(i)*time.Second))
		}
		_, res := g.Admit(good(t), TechniqueProofOfExistence, p3At(t, time.Minute))
		p3AssertRefused(t, res, Gate16CircuitBreaker, ReasonTargetQuarantined)
	})

	t.Run("gate17 backoff", func(t *testing.T) {
		g := p3Governor(t, scope, target)
		g.Backoff().Observe429(p3RetryAfter("600"), p3At(t, 0))
		_, res := g.Admit(good(t), TechniqueProofOfExistence, p3At(t, time.Second))
		p3AssertRefused(t, res, Gate17RetryAfter, ReasonInsideRetryAfter)
	})

	t.Run("gate13 off-scope hop", func(t *testing.T) {
		g := p3Governor(t, scope, target)
		off := p3Target(t, SchemeHTTPS, "cdn.example.net", 443, p3SecondExternalAddr)
		intent := p3Intent(t, RequestFacts{
			Origin: OriginTemplateURL, Admitted: target, Next: off,
			Method: MethodGet, Path: "/x",
		})
		_, res := g.Admit(intent, TechniqueProofOfExistence, p3At(t, 0))
		p3AssertRefused(t, res, Gate13RevalidateEveryRequest, ReasonHopOutsideScope)
	})

	t.Run("gate11 robots", func(t *testing.T) {
		policy := ParseRobotsTxt("target.example.com", 443,
			[]byte("User-agent: *\nDisallow: /private\n"))
		allow, err := NewEndpointAllowance()
		if err != nil {
			t.Fatalf("NewEndpointAllowance: %v", err)
		}
		g, res := NewGovernor(GovernorConfig{
			Target: target, Scope: scope,
			Attestation: attestFor(t, scope),
			Caps:        CodedCaps(), Thresholds: CodedHealthThresholds(),
			Robots: policy, Allowance: allow, Start: p3At(t, 0),
		})
		p3AssertPassed(t, res, Gate13RevalidateEveryRequest)
		intent := p3Intent(t, RequestFacts{
			Origin: OriginInitial, Admitted: target, Next: target,
			Method: MethodGet, Path: "/private/keys",
		})
		_, out := g.Admit(intent, TechniqueProofOfExistence, p3At(t, 0))
		p3AssertRefused(t, out, Gate11RobotsDeny, ReasonRobotsDisallows)
	})

	t.Run("gate15 destructive technique", func(t *testing.T) {
		g := p3Governor(t, scope, target)
		_, res := g.Admit(good(t), TechniqueDenialOfService, p3At(t, 0))
		p3AssertRefused(t, res, Gate15DestructiveTechniques, ReasonTechniqueDestructive)
	})

	t.Run("gate14 rate", func(t *testing.T) {
		g := p3Governor(t, scope, target)
		for i := 0; i < 10; i++ {
			lease, res := g.Admit(good(t), TechniqueProofOfExistence, p3At(t, 0))
			p3AssertPassed(t, res, Gate14HardCaps)
			lease.Release()
		}
		_, res := g.Admit(good(t), TechniqueProofOfExistence, p3At(t, 0))
		p3AssertRefused(t, res, Gate14HardCaps, ReasonRateExceeded)
	})
}

// TestTheGovernorHasNoRobotsPolicyForASecondHostAndRefuses is a fail-closed
// interaction the individual gates cannot show.
//
// Gate 13 permits a template-supplied URL to a SECOND host the scope file
// names. The Governor holds one robots policy, for the target it was built
// for, so gate 11 then refuses that request as a policy for another origin.
// The consequence, stated rather than discovered later: reaching a second host
// requires a second Governor, built with that host's own robots policy. A run
// cannot reach a host whose robots.txt nobody fetched.
func TestTheGovernorHasNoRobotsPolicyForASecondHostAndRefuses(t *testing.T) {
	scope := p3Scope(t, ModeExternal, []ScopeEntry{
		{Host: "target.example.com", Ports: []uint16{443}},
		{Host: "api.example.com", Ports: []uint16{443}},
	}, nil)
	target := p3Target(t, SchemeHTTPS, "target.example.com", 443, p3ExternalAddr)
	second := p3Target(t, SchemeHTTPS, "api.example.com", 443, p3SecondExternalAddr)
	g := p3Governor(t, scope, target)

	intent := p3Intent(t, RequestFacts{
		Origin: OriginTemplateURL, Admitted: target, Next: second,
		Method: MethodGet, Path: "/v1/ping",
	})
	// Gate 13 permits it on its own...
	p3AssertPassed(t, CheckGate13Revalidate(intent, scope,
		attestFor(t, scope), p3At(t, 0)), Gate13RevalidateEveryRequest)
	// ...and the interceptor still refuses, at gate 11.
	_, res := g.Admit(intent, TechniqueProofOfExistence, p3At(t, 0))
	p3AssertRefused(t, res, Gate11RobotsDeny, ReasonRobotsWrongOrigin)
}

func TestNewGovernorRefusesEveryUnconstructedInput(t *testing.T) {
	target := p3Target(t, SchemeHTTPS, "target.example.com", 443, p3ExternalAddr)
	scope := p3ExternalScope(t)
	att := attestFor(t, scope)
	base := GovernorConfig{
		Target: target, Scope: scope, Attestation: att,
		Caps: CodedCaps(), Thresholds: CodedHealthThresholds(),
		Robots: RobotsNotFound("target.example.com", 443), Start: p3At(t, 0),
	}

	cases := []struct {
		name   string
		mutate func(c *GovernorConfig)
	}{
		{"no target", func(c *GovernorConfig) { c.Target = Target{} }},
		{"no scope", func(c *GovernorConfig) { c.Scope = Scope{} }},
		{"no attestation", func(c *GovernorConfig) { c.Attestation = Attestation{} }},
		{"no caps", func(c *GovernorConfig) { c.Caps = Caps{} }},
		{"no thresholds", func(c *GovernorConfig) { c.Thresholds = HealthThresholds{} }},
		{"no clock", func(c *GovernorConfig) { c.Start = Clock{} }},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			cfg := base
			c.mutate(&cfg)
			g, res := NewGovernor(cfg)
			if res.Passed() {
				t.Fatalf("NewGovernor accepted a config with %s", c.name)
			}
			if g.Constructed() {
				t.Fatal("a refused NewGovernor still returned a constructed Governor")
			}
		})
	}
}

func TestGovernorObservationsFeedGates16And17(t *testing.T) {
	scope := p3ExternalScope(t)
	target := p3Target(t, SchemeHTTPS, "target.example.com", 443, p3ExternalAddr)
	g := p3Governor(t, scope, target)
	intent := p3Intent(t, RequestFacts{
		Origin: OriginInitial, Admitted: target, Next: target,
		Method: MethodGet, Path: "/",
	})

	lease, res := g.Admit(intent, TechniqueProofOfExistence, p3At(t, 0))
	p3AssertPassed(t, res, Gate14HardCaps)
	if !lease.Held() {
		t.Fatal("an admitted request holds no lease")
	}

	// A 429 goes to the ledger, not to the breaker.
	p3AssertRefused(t, g.ObserveResponse(lease, http.StatusTooManyRequests, time.Millisecond,
		p3RetryAfter("30"), p3At(t, time.Second)),
		Gate17RetryAfter, ReasonServerSaid429)
	if lease.Held() {
		t.Fatal("the lease still holds a slot after the response was observed")
	}
	if got := g.Limiter().InFlight(); got != 0 {
		t.Fatalf("%d connections still in flight after the response", got)
	}
	if got := g.Backoff().TooManyRequests(); got != 1 {
		t.Fatalf("the ledger counted %d 429s", got)
	}
	total, _, _ := g.Health().Observations()
	if total != 0 {
		t.Fatalf("the breaker recorded %d observations for a 429; a 429 is a rate-limit "+
			"response and not a health signal", total)
	}

	// Release is idempotent: a second call must not drive the semaphore down.
	lease.Release()
	if got := g.Limiter().InFlight(); got != 0 {
		t.Fatalf("in-flight is %d after a second Release", got)
	}
}

func TestGovernorLimitBodyUsesTheGovernorsCaps(t *testing.T) {
	scope := p3ExternalScope(t)
	target := p3Target(t, SchemeHTTPS, "target.example.com", 443, p3ExternalAddr)
	g := p3Governor(t, scope, target)

	body, res := g.LimitBody(strings.NewReader(strings.Repeat("A", 32)))
	p3AssertPassed(t, res, Gate14HardCaps)
	if got := body.Limit(); got != CodedMaxBodyBytes {
		t.Fatalf("the governor's body cap is %d; want %d", got, CodedMaxBodyBytes)
	}
	n, err := io.Copy(io.Discard, body)
	if err != nil || n != 32 {
		t.Fatalf("copy returned (%d, %v)", n, err)
	}
}

// TestTheZeroEndpointAllowanceIsTheDefaultAndAllowsNothing is the one field of
// GovernorConfig whose zero value is legal: an unset Allowance means "no
// state-changing probe is permitted anywhere", which is the most restrictive
// value it can take. Every other field is refused when unset, which
// TestNewGovernorRefusesEveryUnconstructedInput asserts.
func TestTheZeroEndpointAllowanceIsTheDefaultAndAllowsNothing(t *testing.T) {
	ty := reflect.TypeOf(GovernorConfig{})
	if _, ok := ty.FieldByName("Allowance"); !ok {
		t.Fatal("GovernorConfig has no Allowance field")
	}
	g, res := NewGovernor(GovernorConfig{
		Target: p3Target(t, SchemeHTTPS, "target.example.com", 443, p3ExternalAddr),
		Scope:  p3ExternalScope(t), Attestation: attestFor(t, p3ExternalScope(t)),
		Caps: CodedCaps(), Thresholds: CodedHealthThresholds(),
		Robots: RobotsNotFound("target.example.com", 443), Start: p3At(t, 0),
	})
	p3AssertPassed(t, res, Gate13RevalidateEveryRequest)
	target := p3Target(t, SchemeHTTPS, "target.example.com", 443, p3ExternalAddr)
	intent := p3Intent(t, RequestFacts{
		Origin: OriginInitial, Admitted: target, Next: target,
		Method: MethodPost, Path: "/api/echo",
	})
	_, out := g.Admit(intent, TechniqueProofOfExistence, p3At(t, 0))
	p3AssertRefused(t, out, Gate15DestructiveTechniques, ReasonStateChangingWithoutAll)
}

// TestEveryGateInTheInterceptorHasAnAuditTokenOnBothOutcomes is gate 21's
// requirement applied to Phase 3: every row the audit writes must be
// attributable to a gate AND carry a grep-able token, on an allow as well as
// on a deny.
func TestEveryGateInTheInterceptorHasAnAuditTokenOnBothOutcomes(t *testing.T) {
	scope := p3ExternalScope(t)
	target := p3Target(t, SchemeHTTPS, "target.example.com", 443, p3ExternalAddr)
	g := p3Governor(t, scope, target)
	intent := p3Intent(t, RequestFacts{
		Origin: OriginInitial, Admitted: target, Next: target,
		Method: MethodGet, Path: "/",
	})

	lease, trace := g.AdmitTraced(intent, TechniqueProofOfExistence, p3At(t, 0))
	if !lease.Held() {
		t.Fatalf("the request was refused: %v", LastResult(trace).Err())
	}
	lease.Release()
	if len(trace) != len(GovernorGateOrder()) {
		t.Fatalf("the trace has %d entries; want %d", len(trace), len(GovernorGateOrder()))
	}
	for _, r := range trace {
		reason, err := AuditReason(r)
		if err != nil {
			t.Errorf("%s allowed with no audit token: %v", r.Gate(), err)
			continue
		}
		named, err := reason.Gate()
		if err != nil || named != r.Gate() {
			t.Errorf("%s's pass token is %q, which names %s", r.Gate(), string(reason), named)
		}
	}

	// A refusal carries its own token.
	off := p3Target(t, SchemeHTTPS, "cdn.example.net", 443, p3SecondExternalAddr)
	bad := p3Intent(t, RequestFacts{
		Origin: OriginTemplateURL, Admitted: target, Next: off,
		Method: MethodGet, Path: "/x",
	})
	_, badTrace := g.AdmitTraced(bad, TechniqueProofOfExistence, p3At(t, 0))
	reason, err := AuditReason(LastResult(badTrace))
	if err != nil {
		t.Fatalf("a refusal produced no audit token: %v", err)
	}
	if reason != ReasonHopOutsideScope {
		t.Fatalf("the refusal's audit token is %q", string(reason))
	}
}

func TestAuditReasonRefusesAnUnattributableResult(t *testing.T) {
	if _, err := AuditReason(GateResult{}); err == nil {
		t.Error("a zero GateResult produced an audit token. Gate 21 requires the row to " +
			"be attributable, and a token invented to fill the field attributes nothing")
	}
	// A gate the interceptor does not consult has no Phase 3 pass token.
	if _, err := AuditReason(gatePassed(Gate8Canonicalize)); err == nil {
		t.Error("gate 8 produced a Phase 3 pass token")
	}
	// A refusal whose reason token is invalid is not written either.
	broken := GateResult{gate: Gate14HardCaps, passed: false,
		failure: &GateFailure{Gate: Gate14HardCaps, Reason: Reason("nonsense"), Err: ErrRefused}}
	if _, err := AuditReason(broken); err == nil {
		t.Error("a refusal with an invalid reason token produced an audit token")
	}
}

// ---------------------------------------------------------------------------
// percentile, on hand-written sample sets
// ---------------------------------------------------------------------------

func TestPercentileOnHandWrittenSamples(t *testing.T) {
	ms := func(n int) time.Duration { return time.Duration(n) * time.Millisecond }
	cases := []struct {
		name    string
		samples []time.Duration
		p       float64
		want    time.Duration
	}{
		{"empty", nil, 0.95, 0},
		{"one sample", []time.Duration{ms(7)}, 0.95, ms(7)},
		{"twenty ascending, p95", []time.Duration{
			ms(1), ms(2), ms(3), ms(4), ms(5), ms(6), ms(7), ms(8), ms(9), ms(10),
			ms(11), ms(12), ms(13), ms(14), ms(15), ms(16), ms(17), ms(18), ms(19), ms(20),
		}, 0.95, ms(19)},
		{"unsorted input is sorted first", []time.Duration{
			ms(20), ms(1), ms(15), ms(3),
		}, 0.95, ms(20)},
		{"p50 of four", []time.Duration{ms(1), ms(2), ms(3), ms(4)}, 0.50, ms(2)},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := percentile(c.samples, c.p); got != c.want {
				t.Fatalf("percentile = %s; want %s", got, c.want)
			}
		})
	}
}

// TestPercentileDoesNotReorderItsInput is the aliasing guard: the breaker's
// ring must not be shuffled by asking it a question.
func TestPercentileDoesNotReorderItsInput(t *testing.T) {
	in := []time.Duration{5, 1, 4, 2, 3}
	before := fmt.Sprint(in)
	_ = percentile(in, 0.95)
	if after := fmt.Sprint(in); after != before {
		t.Fatalf("percentile reordered its input: %s -> %s", before, after)
	}
}
