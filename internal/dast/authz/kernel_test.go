package authz

import (
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"net/netip"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"
)

// ===========================================================================
// FIXTURES
// ===========================================================================
//
// Every value a refusal test feeds to the kernel is a HAND-WRITTEN LITERAL —
// a hostname, a hex string, a timestamp — and not something produced by the
// code under test. The constructors appear only where a test needs a
// well-formed value to prove that a LATER guard still refuses it, which is the
// one case where there is no alternative: the sealed types have no other way
// in, and that unforgeability is the property being tested.

const (
	// fixtureOtherHash is a hand-written 64-character lowercase hex string. It
	// is the sha256 of nothing, so no scope file hashes to it and every
	// attestation bound to it covers no scope this suite can build. That is
	// what it is for.
	fixtureOtherHash = "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210"
)

var (
	fixtureIssued  = time.Date(2026, time.August, 1, 12, 0, 0, 0, time.UTC)
	fixtureNow     = time.Date(2026, time.August, 10, 12, 0, 0, 0, time.UTC)
	fixtureExpires = time.Date(2026, time.August, 20, 12, 0, 0, 0, time.UTC)
)

// scopeFileJSON renders a scope file's wire form from a mode and two entry
// lists.
//
// The JSON is assembled here, byte by byte, rather than by marshalling the
// implementation's own scopeDocument: a fixture emitted by the parser it is
// fed to agrees with the parser by construction. The schema version is written
// as the literal 1 for the same reason, and TestScopeFileSchemaVersionIsOne
// asserts the implementation's const still is.
//
// It exists because NewScope no longer takes a caller-asserted hash. A Scope's
// hash is the sha256 of the bytes gate 4 parsed, so a test that wants a scope
// with particular entries has to supply a file that contains them — which is
// the property the constructor change bought.
func scopeFileJSON(mode Mode, allow, deny []ScopeEntry) []byte {
	entries := func(list []ScopeEntry) string {
		parts := make([]string, 0, len(list))
		for _, e := range list {
			ports := make([]string, 0, len(e.Ports))
			for _, p := range e.Ports {
				ports = append(ports, fmt.Sprintf("%d", p))
			}
			parts = append(parts, fmt.Sprintf(`{"host":%q,"ports":[%s]}`,
				e.Host, strings.Join(ports, ",")))
		}
		return "[" + strings.Join(parts, ",") + "]"
	}
	return []byte(fmt.Sprintf(`{"schema_version":1,"mode":%q,"allow":%s,"deny":%s}`,
		string(mode), entries(allow), entries(deny)))
}

// fixtureScopeRaw is the standard one-host external scope file this suite
// builds most of its scopes from, and fixtureScopeHash is what it hashes to.
//
// fixtureScopeHash is DERIVED rather than hand-written, because it is no longer
// a free-floating identifier: it is the sha256 of these exact bytes, and a
// hand-written value would simply not be the hash of anything.
// TestScopeHashIsOverTheExactBytes anchors ScopeHashOf against a digest
// computed outside this program.
var (
	fixtureScopeRaw = scopeFileJSON(ModeExternal,
		[]ScopeEntry{{Host: "target.example.com", Ports: []uint16{443}}}, nil)
	fixtureScopeHash = ScopeHashOf(fixtureScopeRaw)
)

// TestScopeFileSchemaVersionIsOne anchors the literal 1 that scopeFileJSON
// writes. If the schema version is ever bumped, every fixture in this suite is
// silently written against the old schema, and this is what says so.
func TestScopeFileSchemaVersionIsOne(t *testing.T) {
	if ScopeFileSchemaVersion != 1 {
		t.Fatalf("ScopeFileSchemaVersion is %d and scopeFileJSON writes 1, so every scope "+
			"fixture in this package is written against a schema the loader no longer "+
			"implements", ScopeFileSchemaVersion)
	}
}

func mustClock(t *testing.T) Clock {
	t.Helper()
	c, err := NewClock(fixtureNow)
	if err != nil {
		t.Fatalf("NewClock(%s): %v", fixtureNow, err)
	}
	return c
}

// mustScope builds the standard one-host scope for a mode.
func mustScope(t *testing.T, mode Mode) Scope {
	t.Helper()
	return mustScopeOf(t, mode,
		[]ScopeEntry{{Host: "target.example.com", Ports: []uint16{443}}}, nil)
}

// mustScopeOf builds a scope from a mode and two entry lists, by rendering the
// scope file they describe and loading it.
func mustScopeOf(t *testing.T, mode Mode, allow, deny []ScopeEntry) Scope {
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

// attestFor mints an attestation bound to the scope it is handed.
//
// It exists because a scope's hash is now a function of its bytes, so two
// scopes with different entries have different hashes and no single fixture
// constant binds to both.
func attestFor(t *testing.T, s Scope) Attestation {
	t.Helper()
	return mustAttestation(t, s.Hash())
}

// mustEnablement mints the gate-1 DastEnablement Adjudicate requires, for a
// scope and the attestation bound to it.
func mustEnablement(t *testing.T, s Scope, a Attestation) DastEnablement {
	t.Helper()
	mode, err := s.Mode()
	if err != nil {
		t.Fatalf("scope.Mode: %v", err)
	}
	decl, err := DeclareMode(mode)
	if err != nil {
		t.Fatalf("DeclareMode(%q): %v", mode, err)
	}
	e, err := EnableDAST(ArtifactDAST, decl, s, a, mustClock(t))
	if err != nil {
		t.Fatalf("EnableDAST: %v", err)
	}
	return e
}

func mustAttestation(t *testing.T, hash ScopeHash) Attestation {
	t.Helper()
	a, err := NewAttestation(
		"attest-2026-08-01-001",
		"Susquehanna Syntax, operator of target.example.com",
		AuthorityOperator,
		hash,
		fixtureIssued,
		fixtureExpires,
		DefaultAttestationCeiling(),
	)
	if err != nil {
		t.Fatalf("NewAttestation: %v", err)
	}
	return a
}

func mustTarget(t *testing.T, host string, port uint16, addr string) Target {
	t.Helper()
	ip, err := netip.ParseAddr(addr)
	if err != nil {
		t.Fatalf("ParseAddr(%q): %v", addr, err)
	}
	tgt, err := NewTarget(SchemeHTTPS, host, host, port, ip)
	if err != nil {
		t.Fatalf("NewTarget: %v", err)
	}
	return tgt
}

// recordingSink is an AuditSink that succeeds and remembers what it was asked
// to write.
type recordingSink struct {
	rows []GateRecord
	next AuditSeq
}

func (s *recordingSink) WriteGateDecision(r GateRecord) (AuditSeq, error) {
	s.rows = append(s.rows, r)
	s.next++
	return s.next, nil
}

// failingSink is an AuditSink whose write always fails. It is gate 21's
// negative control.
type failingSink struct{ err error }

func (s failingSink) WriteGateDecision(GateRecord) (AuditSeq, error) { return 0, s.err }

// silentSink returns success with sequence zero — the shape a stub, a mock
// left in by accident, or a short-circuited implementation returns.
type silentSink struct{}

func (silentSink) WriteGateDecision(GateRecord) (AuditSeq, error) { return 0, nil }

// permitAll builds a chain whose every gate permits, so the allow path can be
// exercised while gates 4–11 are unimplemented.
func permitAll(gates []GateID) chain {
	impls := map[GateID]gateFunc{}
	for _, g := range gates {
		g := g
		impls[g] = func(Target, Scope, Attestation, Clock) Ruling {
			return permit(g, Reason(fmt.Sprintf("%s.test_permit", g)), "test fixture")
		}
	}
	return chain{name: "test", gates: gates, impls: impls}
}

// ===========================================================================
// THE ONE RULE: THE ZERO VALUE REFUSES
// ===========================================================================

// TestEveryZeroValueRefuses is the package's single most important test.
//
// It is deliberately a duplicate of the check gate 1 runs at build time
// (zeroValuesThatWouldAuthorize), because the two catch different regressions:
// this one names the offending construct in a test failure, and gate 1's runs
// inside the shipped binary's own build gate where a test file cannot reach.
func TestEveryZeroValueRefuses(t *testing.T) {
	if bad := zeroValuesThatWouldAuthorize(); len(bad) > 0 {
		t.Fatalf("a zero value in the authorization kernel authorizes something:\n  %s\n\n"+
			"The whole design of internal/dast/authz rests on the zero value meaning "+
			"REFUSE. A struct that defaults to allowed when a field is unset is the bug "+
			"this package exists to prevent.", strings.Join(bad, "\n  "))
	}
}

// TestZeroValueAccessorsRefuseIndividually spells out the accessors one at a
// time, so that a regression names the exact method rather than a list.
func TestZeroValueAccessorsRefuseIndividually(t *testing.T) {
	cases := []struct {
		name string
		got  bool
	}{
		{"Decision{}.Allowed()", (Decision{}).Allowed()},
		{"Authorization{}.Valid()", (Authorization{}).Valid()},
		{"Ruling{}.Permits()", (Ruling{}).Permits()},
		{"Ruling{}.WellFormedDenial()", (Ruling{}).WellFormedDenial()},
		{"GateResult{}.Passed()", (GateResult{}).Passed()},
		{"Scope{}.Constructed()", (Scope{}).Constructed()},
		{"Scope{}.Permits(host,443)", (Scope{}).Permits("target.example.com", 443)},
		{"Attestation{}.Constructed()", (Attestation{}).Constructed()},
		{"Target{}.Constructed()", (Target{}).Constructed()},
		{"Clock{}.Valid()", (Clock{}).Valid()},
		{"ModeDeclaration{}.Declared()", (ModeDeclaration{}).Declared()},
		{"DastEnablement{}.Enabled()", (DastEnablement{}).Enabled()},
		{"ImportGraph{}.Walked()", (ImportGraph{}).Walked()},
		{"EgressScan{}.Ran()", (EgressScan{}).Ran()},
		{"Cap[int]{}.Allows(0)", (Cap[int]{}).Allows(0)},
		{"Cap[time.Duration]{}.Allows(0)", (Cap[time.Duration]{}).Allows(0)},
		{"GateUnspecified.Valid()", GateUnspecified.Valid()},
		{"ModeUnset.Valid()", ModeUnset.Valid()},
		{"OutcomeUnset.Allows()", OutcomeUnset.Allows()},
		{"ArtifactUnset.Valid()", ArtifactUnset.Valid()},
		{"SchemeUnset.Valid()", SchemeUnset.Valid()},
		{"AuthorityUnset.Valid()", AuthorityUnset.Valid()},
	}
	for _, c := range cases {
		if c.got {
			t.Errorf("%s returned true; every zero value in this package must refuse", c.name)
		}
	}
	if err := (Ruling{}).Err(); err == nil {
		t.Error("Ruling{}.Err() is nil, so a ruling nobody minted reads as a permit")
	}
	if err := (GateResult{}).Err(); err == nil {
		t.Error("GateResult{}.Err() is nil, so a gate nobody ran reads as a pass")
	}
	if err := (Decision{}).Err(); err == nil {
		t.Error("Decision{}.Err() is nil, so a decision nobody made reads as an allow")
	}
	if err := ReasonUnspecified.Validate(); err == nil {
		t.Error("the empty Reason validates")
	}
}

// ===========================================================================
// THE CHAIN — a missing gate is a refusal, never a skipped step
// ===========================================================================

// firstUnregisteredAdmissionGate reports the first gate in the admission chain
// with no implementation compiled in, or GateUnspecified if the stack is
// complete.
//
// Several tests below branch on it rather than hard-coding "D.2 is the only
// packet that has landed". A test that must be edited before the next packet
// can compile is a test that blocks the next packet, and D.4–D.7 cannot edit
// this file: it is outside their write scope.
func firstUnregisteredAdmissionGate() GateID {
	for _, g := range admissionChain {
		if fn, ok := registry[g]; !ok || fn == nil {
			return g
		}
	}
	return GateUnspecified
}

// TestDecideNeverPermitsThroughAnIncompleteChain is the live proof that the
// real kernel — the exported Decide, over the real registry — cannot permit
// anything while a gate is missing.
//
// It uses fully valid inputs on purpose: every precondition passes, so the
// only thing left to refuse is the incomplete stack. Today that is gates 4–11,
// all of them. As D.4–D.6 land the assertion narrows on its own rather than
// needing an edit.
func TestDecideNeverPermitsThroughAnIncompleteChain(t *testing.T) {
	scope := mustScope(t, ModeExternal)
	att := mustAttestation(t, fixtureScopeHash)
	tgt := mustTarget(t, "target.example.com", 443, "93.184.216.34")
	clk := mustClock(t)

	missing := firstUnregisteredAdmissionGate()
	r := Decide(tgt, scope, att, clk)

	if r.Permits() {
		if missing != GateUnspecified {
			t.Fatalf("Decide permitted although %s has no implementation compiled in: %s. "+
				"A gate with no implementation is a REFUSAL, never a skipped step", missing, r)
		}
		t.Logf("the admission stack is fully implemented and permitted the fixture at %s", r.Gate())
		return
	}
	if !errors.Is(r.Err(), ErrRefused) {
		t.Fatalf("Decide's error does not unwrap to ErrRefused: %v", r.Err())
	}
	if missing != GateUnspecified {
		// The token names THE MISSING GATE, not gate 21. GateRecord.Validate
		// refuses a row whose reason names a different gate from the row
		// itself, and Adjudicate validates every row before writing any, so a
		// gate21.* token here loses the entire audit trail of the denial. See
		// structuralRefusal.
		wantReason := Reason(missing.String() + "." + slugGateNotRegistered)
		if r.Reason() != wantReason {
			t.Fatalf("%s has no implementation and Decide refused with reason %q; expected "+
				"%q so that the refusal says the gate stack is incomplete rather than "+
				"blaming the input, AND names the gate it is attributed to so the audit "+
				"row for it validates", missing, string(r.Reason()), string(wantReason))
		}
		if r.Gate() != missing {
			t.Fatalf("the refusal names %s; the first unimplemented gate is %s", r.Gate(), missing)
		}
		t.Logf("the admission stack stops at %s, which has no implementation compiled in", missing)
	}
}

// TestEveryRegisteredGateIsLegal is the standing guard on the registry. It
// holds whether the registry is empty (today) or full (after D.4–D.6), so it
// never has to be edited to let a later packet land.
func TestEveryRegisteredGateIsLegal(t *testing.T) {
	inAChain := map[GateID]bool{}
	for _, g := range admissionChain {
		inAChain[g] = true
	}
	for _, g := range revalidationChain {
		inAChain[g] = true
	}
	for g, fn := range registry {
		if fn == nil {
			t.Errorf("%s is registered with a nil implementation", g)
		}
		if !g.Valid() {
			t.Errorf("%s is registered and is not one of the 21 gates", g)
		}
		if g == Gate12SecurityTxtReportingChannel {
			t.Errorf("gate 12 (security.txt) is registered as an admission gate. RFC 9116 " +
				"and plan/00-SPINE.md S7: it resolves a reporting channel and never " +
				"grants permission")
		}
		if p := g.Phase(); p == 0 || p == 4 {
			t.Errorf("%s is a Phase %d gate and does not take (target, scope, attestation, "+
				"clock)", g, p)
		}
		if !inAChain[g] {
			t.Errorf("%s is registered but appears in no chain, so it is never consulted. "+
				"A gate nobody runs is a gate nobody has", g)
		}
	}
	t.Logf("%d of %d admission gates implemented", len(registry), len(admissionChain))
}

// TestChainRefusesEveryMissingGateIndividually walks the admission chain and,
// for each gate, builds a chain in which only that one gate is missing. Every
// one must refuse, naming that gate.
func TestChainRefusesEveryMissingGateIndividually(t *testing.T) {
	scope := mustScope(t, ModeExternal)
	att := mustAttestation(t, fixtureScopeHash)
	tgt := mustTarget(t, "target.example.com", 443, "93.184.216.34")
	clk := mustClock(t)

	for _, missing := range admissionChain {
		t.Run(missing.String(), func(t *testing.T) {
			ch := permitAll(admissionChain)
			delete(ch.impls, missing)

			r := ch.run(tgt, scope, att, clk)
			if r.Permits() {
				t.Fatalf("the chain permitted with %s missing. A gate with no "+
					"implementation compiled in is a REFUSAL, never a skipped step: "+
					"internal/SKIPPED-CONTROLS.md records two incidents in this "+
					"repository where a control that could not run reported success",
					missing)
			}
			if r.Gate() != missing {
				t.Fatalf("refusal attributed to %s; the missing gate was %s", r.Gate(), missing)
			}
			wantReason := Reason(missing.String() + "." + slugGateNotRegistered)
			if r.Reason() != wantReason {
				t.Fatalf("reason %q; want %q. A refusal attributed to %s whose reason "+
					"names some other gate cannot be written as an audit row at all: "+
					"GateRecord.Validate rejects exactly that mismatch",
					string(r.Reason()), string(wantReason), missing)
			}
		})
	}
}

// TestChainRefusesAnEmptyChain covers the vacuous-truth case a for-range loop
// produces for free: no gates ran, so nothing objected.
func TestChainRefusesAnEmptyChain(t *testing.T) {
	scope := mustScope(t, ModeExternal)
	att := mustAttestation(t, fixtureScopeHash)
	tgt := mustTarget(t, "target.example.com", 443, "93.184.216.34")
	clk := mustClock(t)

	empty := chain{name: "empty-chain-fixture", gates: nil, impls: map[GateID]gateFunc{}}
	r := empty.run(tgt, scope, att, clk)
	if r.Permits() {
		t.Fatalf("an empty chain permitted: %s", r)
	}
	// The refusal must be ATTRIBUTED, not merely a zero Ruling that happens
	// to refuse. Without this assertion, deleting the explicit empty-chain
	// branch left the test green: `last` stays the zero Ruling and the
	// zero-value rule refuses it anyway. Two guards is fine; a test that
	// cannot tell which one fired is not.
	if r.Reason() != ReasonGateNotRegistered {
		t.Fatalf("an empty chain refused with reason %q; want %q so the audit says the "+
			"chain was empty rather than saying nothing at all", string(r.Reason()),
			string(ReasonGateNotRegistered))
	}
	if !strings.Contains(r.Detail(), "empty-chain-fixture") {
		t.Fatalf("the refusal does not name the empty chain: %q", r.Detail())
	}
}

// TestChainRefusesAGateThatSignsSomeoneElsesName covers the case where a gate
// implementation returns a ruling attributed to a different gate — a copied
// return statement, or a helper shared between two gates that forgot to change
// the ID.
func TestChainRefusesAGateThatSignsSomeoneElsesName(t *testing.T) {
	scope := mustScope(t, ModeExternal)
	att := mustAttestation(t, fixtureScopeHash)
	tgt := mustTarget(t, "target.example.com", 443, "93.184.216.34")
	clk := mustClock(t)

	ch := permitAll([]GateID{Gate10ReservedRanges})
	ch.impls[Gate10ReservedRanges] = func(Target, Scope, Attestation, Clock) Ruling {
		// Attributed to gate 4, returned by the implementation of gate 10.
		return permit(Gate4ScopeFile, "gate04.scope_permits", "copied from elsewhere")
	}
	r := ch.run(tgt, scope, att, clk)
	if r.Permits() {
		t.Fatalf("the chain accepted a ruling signed by a different gate: %s", r)
	}
	wantReason := Reason(Gate10ReservedRanges.String() + "." + slugGateIdentityMismatch)
	if r.Reason() != wantReason {
		t.Fatalf("reason %q; want %q", string(r.Reason()), string(wantReason))
	}
	if r.Gate() != Gate10ReservedRanges {
		t.Fatalf("the refusal is attributed to %s; gate 10 is the gate that signed "+
			"someone else's name", r.Gate())
	}
}

// TestChainRefusesAMalformedRuling covers a gate that returns a zero Ruling —
// the shape produced by `var r Ruling; return r`, or by a switch with no
// default arm.
func TestChainRefusesAMalformedRuling(t *testing.T) {
	scope := mustScope(t, ModeExternal)
	att := mustAttestation(t, fixtureScopeHash)
	tgt := mustTarget(t, "target.example.com", 443, "93.184.216.34")
	clk := mustClock(t)

	cases := map[string]Ruling{
		"zero ruling":             {},
		"allow with no reason":    {gate: Gate10ReservedRanges, outcome: OutcomeAllow},
		"allow with bad reason":   {gate: Gate10ReservedRanges, outcome: OutcomeAllow, reason: "looks fine"},
		"allow with wrong gate":   {gate: Gate10ReservedRanges, outcome: OutcomeAllow, reason: "gate04.x"},
		"outcome nobody set":      {gate: Gate10ReservedRanges, reason: "gate10.x"},
		"deny with bad reason":    {gate: Gate10ReservedRanges, outcome: OutcomeDeny, reason: "nope"},
		"outcome from thin air":   {gate: Gate10ReservedRanges, outcome: "maybe", reason: "gate10.x"},
		"gate outside the twenty": {gate: GateID(99), outcome: OutcomeAllow, reason: "gate10.x"},
	}
	for name, bad := range cases {
		t.Run(name, func(t *testing.T) {
			ch := chain{
				name:  "test",
				gates: []GateID{Gate10ReservedRanges},
				impls: map[GateID]gateFunc{
					Gate10ReservedRanges: func(Target, Scope, Attestation, Clock) Ruling { return bad },
				},
			}
			if r := ch.run(tgt, scope, att, clk); r.Permits() {
				t.Fatalf("the chain permitted on a malformed ruling %+v", bad)
			}
		})
	}
}

// TestChainPermitsOnlyWhenEveryGatePermits is the positive control. Without
// it, every test above would pass against a chain that refuses unconditionally,
// which would prove nothing.
func TestChainPermitsOnlyWhenEveryGatePermits(t *testing.T) {
	scope := mustScope(t, ModeExternal)
	att := mustAttestation(t, fixtureScopeHash)
	tgt := mustTarget(t, "target.example.com", 443, "93.184.216.34")
	clk := mustClock(t)

	ch := permitAll(admissionChain)
	r := ch.run(tgt, scope, att, clk)
	if !r.Permits() {
		t.Fatalf("a chain in which every gate permits refused: %s", r)
	}
	if want := admissionChain[len(admissionChain)-1]; r.Gate() != want {
		t.Fatalf("the chain's permit is attributed to %s; want the last gate, %s", r.Gate(), want)
	}

	// One refusing gate anywhere in the chain refuses the whole chain.
	for _, deny := range admissionChain {
		ch := permitAll(admissionChain)
		ch.impls[deny] = func(Target, Scope, Attestation, Clock) Ruling {
			return refuse(deny, Reason(fmt.Sprintf("%s.test_refusal", deny)), "test fixture")
		}
		got := ch.run(tgt, scope, att, clk)
		if got.Permits() {
			t.Errorf("the chain permitted although %s refused", deny)
		}
		if got.Gate() != deny {
			t.Errorf("refusal attributed to %s; %s is what refused", got.Gate(), deny)
		}
	}
}

// ===========================================================================
// GATE 12 — the structural exclusion
// ===========================================================================

// TestGate12IsInNoChain asserts the absence that IS the enforcement.
func TestGate12IsInNoChain(t *testing.T) {
	for _, ch := range map[string][]GateID{
		"admission":    admissionChain,
		"revalidation": revalidationChain,
	} {
		for _, g := range ch {
			if g == Gate12SecurityTxtReportingChannel {
				t.Fatalf("gate 12 (security.txt) is in a chain. RFC 9116 and "+
					"plan/00-SPINE.md S7 both say security.txt resolves a reporting "+
					"channel and NEVER grants permission; plan/50-dast.md gate 12 "+
					"requires it to be structurally excluded from the admission "+
					"decision's input type. Chain: %v", ch)
			}
		}
	}
}

// TestGate12CannotBeRegistered proves the refusal, not just the absence.
func TestGate12CannotBeRegistered(t *testing.T) {
	m := map[GateID]gateFunc{}
	err := registerInto(m, Gate12SecurityTxtReportingChannel,
		func(Target, Scope, Attestation, Clock) Ruling {
			return permit(Gate12SecurityTxtReportingChannel, "gate12.security_txt_says_yes", "")
		})
	if err == nil {
		t.Fatal("gate 12 was registered as an admission gate. security.txt resolves a " +
			"reporting channel and never grants permission (RFC 9116; plan/00-SPINE.md S7)")
	}
	if !errors.Is(err, ErrRefused) {
		t.Fatalf("registration refusal does not unwrap to ErrRefused: %v", err)
	}
	if len(m) != 0 {
		t.Fatalf("the registry was mutated despite the refusal: %v", m)
	}
}

// TestAdmissionInputClosureIsClosed is gate 12's type-level enforcement,
// checked mechanically.
//
// It walks the transitive field-type closure of Decide's four parameters and
// fails on anything that could be an extension point: an interface, a func, a
// channel, an unsafe.Pointer, or any type that embeds ReportingChannelOnly.
// A closed closure means there is no way to hand the admission decision a
// security.txt result without editing types.go — which is D.2's write scope and
// explicitly not D.5's.
//
// Types from outside this module are treated as opaque leaves. Their
// unexported fields cannot be set by Anvil code, so they cannot smuggle
// anything; but their KIND is still checked, so a stdlib interface used as a
// field type would still fail.
func TestAdmissionInputClosureIsClosed(t *testing.T) {
	decideType := reflect.TypeOf(Decide)
	if decideType.NumIn() != 4 {
		t.Fatalf("Decide takes %d parameters; plan/00-SPINE.md S7 fixes the kernel as a "+
			"pure function of exactly (target, scope, attestation, clock)", decideType.NumIn())
	}
	gateFuncType := reflect.TypeOf(gateFunc(nil))
	if gateFuncType.NumIn() != 4 {
		t.Fatalf("gateFunc takes %d parameters; a gate's world is the same four values "+
			"Decide gets and nothing else", gateFuncType.NumIn())
	}
	for i := 0; i < 4; i++ {
		if decideType.In(i) != gateFuncType.In(i) {
			t.Fatalf("parameter %d: Decide takes %s and gateFunc takes %s; they must be the "+
				"same four types or a gate can see something the kernel's contract does not "+
				"mention", i, decideType.In(i), gateFuncType.In(i))
		}
	}

	seen := map[reflect.Type]bool{}
	var walk func(path string, typ reflect.Type)
	walk = func(path string, typ reflect.Type) {
		if typ == nil || seen[typ] {
			return
		}
		seen[typ] = true

		switch typ.Kind() {
		case reflect.Interface:
			t.Errorf("%s is an interface (%s). An interface in the admission input closure "+
				"is an open extension point: any type satisfying it can be passed, "+
				"including one carrying a security.txt result, and a type assertion inside "+
				"a gate can read it back out. plan/50-dast.md gate 12 requires the "+
				"exclusion to be structural.", path, typ)
			return
		case reflect.Func, reflect.Chan, reflect.UnsafePointer:
			t.Errorf("%s is a %s (%s). It can carry arbitrary state into the admission "+
				"decision and is an extension point gate 12 forbids.", path, typ.Kind(), typ)
			return
		}

		if typ.Implements(reflect.TypeOf((*excludedFromAdmission)(nil)).Elem()) ||
			reflect.PointerTo(typ).Implements(reflect.TypeOf((*excludedFromAdmission)(nil)).Elem()) {
			t.Errorf("%s (%s) embeds ReportingChannelOnly and is therefore reachable from "+
				"the admission decision's input type. plan/00-SPINE.md S7: security.txt "+
				"resolves a reporting channel and never grants permission.", path, typ)
			return
		}

		// Types declared outside this module are opaque leaves: Anvil code
		// cannot set their unexported fields, so they cannot smuggle
		// anything into the closure.
		if pkg := typ.PkgPath(); pkg != "" && !strings.HasPrefix(pkg, modulePath) {
			return
		}

		switch typ.Kind() {
		case reflect.Struct:
			for i := 0; i < typ.NumField(); i++ {
				f := typ.Field(i)
				walk(path+"."+f.Name, f.Type)
			}
		case reflect.Slice, reflect.Array, reflect.Pointer:
			walk(path+"[]", typ.Elem())
		case reflect.Map:
			walk(path+"{key}", typ.Key())
			walk(path+"{val}", typ.Elem())
		}
	}
	for i := 0; i < decideType.NumIn(); i++ {
		in := decideType.In(i)
		walk(in.Name(), in)
	}

	// Positive control: the walk must actually be able to fail. A type that
	// embeds ReportingChannelOnly has to be detected as excluded, or the
	// check above is a no-op that passes because it looks at nothing.
	type fakeSecurityTxtResult struct {
		ReportingChannelOnly
		Contact string
	}
	iface := reflect.TypeOf((*excludedFromAdmission)(nil)).Elem()
	if !reflect.TypeOf(fakeSecurityTxtResult{}).Implements(iface) {
		t.Fatal("a type embedding ReportingChannelOnly does not satisfy " +
			"excludedFromAdmission, so the exclusion check above can never fire and " +
			"proves nothing")
	}
}

// ===========================================================================
// REGISTRATION
// ===========================================================================

func TestRegisterIntoRefusals(t *testing.T) {
	ok := func(Target, Scope, Attestation, Clock) Ruling {
		return permit(Gate4ScopeFile, "gate04.ok", "")
	}
	cases := []struct {
		name string
		gate GateID
		fn   gateFunc
		why  string
	}{
		{"nil implementation", Gate4ScopeFile, nil,
			"a nil implementation panics at decision time instead of refusing"},
		{"unspecified gate", GateUnspecified, ok, "the zero GateID is not a gate"},
		{"gate out of range", GateID(22), ok, "there are 21 gates"},
		{"phase 0 gate", Gate1DastShipsDisabled, ok,
			"Phase 0 gates take build facts, not a target"},
		{"phase 4 gate", Gate21ImmutableAudit, ok,
			"Phase 4 gates do not run per target"},
		{"security.txt", Gate12SecurityTxtReportingChannel, ok,
			"security.txt never grants permission"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			m := map[GateID]gateFunc{}
			if err := registerInto(m, c.gate, c.fn); err == nil {
				t.Fatalf("registerInto accepted %s (%s): %s", c.gate, c.name, c.why)
			}
			if len(m) != 0 {
				t.Fatalf("the registry was mutated despite the refusal")
			}
		})
	}

	t.Run("duplicate", func(t *testing.T) {
		m := map[GateID]gateFunc{}
		if err := registerInto(m, Gate4ScopeFile, ok); err != nil {
			t.Fatalf("the first registration of %s failed: %v", Gate4ScopeFile, err)
		}
		if err := registerInto(m, Gate4ScopeFile, ok); err == nil {
			t.Fatal("registerInto accepted a second implementation of gate 4. Two " +
				"implementations of one gate means one of them is not being consulted, " +
				"and which one is an accident of init order")
		}
	})

	t.Run("nil map", func(t *testing.T) {
		if err := registerInto(nil, Gate4ScopeFile, ok); err == nil {
			t.Fatal("registerInto accepted a nil registry")
		}
	})
}

// ===========================================================================
// KERNEL PRECONDITIONS
// ===========================================================================

func TestDecideRefusesUnconstructedInputs(t *testing.T) {
	goodScope := mustScope(t, ModeExternal)
	goodAtt := mustAttestation(t, fixtureScopeHash)
	goodTarget := mustTarget(t, "target.example.com", 443, "93.184.216.34")
	goodClock := mustClock(t)

	cases := []struct {
		name   string
		target Target
		scope  Scope
		att    Attestation
		clock  Clock
		gate   GateID
		reason Reason
	}{
		{"zero scope", goodTarget, Scope{}, goodAtt, goodClock,
			Gate4ScopeFile, ReasonScopeUnconstructed},
		{"zero attestation", goodTarget, goodScope, Attestation{}, goodClock,
			Gate5Attestation, ReasonAttestationUnconstructed},
		{"zero clock", goodTarget, goodScope, goodAtt, Clock{},
			Gate5Attestation, ReasonClockUnconstructed},
		{"zero target", Target{}, goodScope, goodAtt, goodClock,
			Gate8Canonicalize, ReasonTargetUnconstructed},
		{"everything zero", Target{}, Scope{}, Attestation{}, Clock{},
			Gate4ScopeFile, ReasonScopeUnconstructed},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := decideWith(permitAll(admissionChain), c.target, c.scope, c.att, c.clock)
			if r.Permits() {
				t.Fatalf("Decide permitted with %s, against a chain where every gate says "+
					"yes. The kernel's own preconditions are what stand between an "+
					"unconstructed value and a socket", c.name)
			}
			if r.Gate() != c.gate {
				t.Errorf("refusal attributed to %s; want %s so the audit names the starved "+
					"gate", r.Gate(), c.gate)
			}
			if r.Reason() != c.reason {
				t.Errorf("reason %q; want %q", string(r.Reason()), string(c.reason))
			}
		})
	}
}

// TestDecideRefusesAnAttestationForADifferentScope is gate 5's binding rule:
// editing the scope file invalidates the attestation.
func TestDecideRefusesAnAttestationForADifferentScope(t *testing.T) {
	scope := mustScope(t, ModeExternal)
	att := mustAttestation(t, fixtureOtherHash) // attests a DIFFERENT scope
	tgt := mustTarget(t, "target.example.com", 443, "93.184.216.34")
	clk := mustClock(t)

	r := decideWith(permitAll(admissionChain), tgt, scope, att, clk)
	if r.Permits() {
		t.Fatal("Decide permitted with an attestation bound to a different scope hash. " +
			"Gate 5 binds the attestation to the scope hash precisely so that editing the " +
			"scope file invalidates it")
	}
	if r.Reason() != ReasonScopeAttestationMismatch {
		t.Fatalf("reason %q; want %q", string(r.Reason()), string(ReasonScopeAttestationMismatch))
	}
}

// TestRevalidateRunsTheRedirectChain covers gate 13's dependency: the
// revalidation chain re-runs SCOPE MEMBERSHIP and THE LIVE ATTESTATION plus
// gates 8, 9 and 10, and refuses an unconstructed target, which is the shape a
// half-parsed Location header takes.
//
// GATE 5 IS IN THE CHAIN, and TestAnAttestationThatExpiresMidRunStopsTheNextRequest
// is what drives it. Gate 14 permits thirty minutes of wall clock per target,
// so an attestation can expire during a run, and gate 5 is "refuse to probe
// without a live attestation" per REQUEST rather than per admission.
//
// GATE 4 IS IN THE CHAIN, and that is the orchestrator's ruling. Gates 8-10
// canonicalize, pin and screen reserved ranges; not one of them asks whether
// the host is in scope, so a redirect to a routable, non-reserved host that
// nobody put in the scope file passed {8,9,10} cleanly. plan/50-dast.md's gate
// 13 row is "re-validate scope on every request including every redirect hop",
// and the scope allow-list match is gate 4.
func TestRevalidateRunsTheRedirectChain(t *testing.T) {
	want := []GateID{
		Gate4ScopeFile, Gate5Attestation,
		Gate8Canonicalize, Gate9ResolveAndPin, Gate10ReservedRanges,
	}
	if len(revalidationChain) != len(want) {
		t.Fatalf("the revalidation chain is %v; gate 13 re-runs scope membership, the "+
			"live attestation and gates 8-10 on every request and every redirect hop",
			revalidationChain)
	}
	for i, g := range want {
		if revalidationChain[i] != g {
			t.Fatalf("revalidation chain position %d is %s; want %s", i, revalidationChain[i], g)
		}
	}

	scope := mustScope(t, ModeExternal)
	att := attestFor(t, scope)
	clk := mustClock(t)

	// The gap gate 4's presence closes: a host that is routable, on no deny
	// list, in no reserved range — and in nobody's allow list.
	offScope := mustTarget(t, "cdn.example.net", 443, "93.184.216.35")
	r := Revalidate(offScope, scope, att, clk)
	if r.Permits() {
		t.Fatal("the revalidation chain permitted a hop to a host the scope file never " +
			"names. research/20 gate 13: re-validate SCOPE on every single request")
	}
	if r.Gate() != Gate4ScopeFile {
		t.Fatalf("the off-scope hop was refused by %s; the scope allow-list match is "+
			"gate 4, and if some other gate is refusing it then this fixture is not "+
			"testing scope membership: %s", r.Gate(), r)
	}
	if r := Revalidate(Target{}, scope, att, clk); r.Permits() {
		t.Fatal("Revalidate permitted an unconstructed target — the shape a half-parsed " +
			"Location header takes")
	}

	// A redirect hop to the cloud metadata endpoint, on a host the scope
	// never mentioned. This must be refused today (gates 8-10 are not
	// implemented, so the chain refuses at the first of them) and must go on
	// being refused once they are (gate 10's reserved-range denylist in
	// external mode, and the host is out of scope besides). The assertion
	// therefore survives D.5 landing without an edit, which matters because
	// D.5 cannot edit this file.
	metadata := mustTarget(t, "metadata.example.net", 80, "169.254.169.254")
	if r := Revalidate(metadata, scope, att, clk); r.Permits() {
		t.Fatalf("Revalidate permitted a redirect hop to %s, which is the cloud metadata "+
			"endpoint and is on no scope list: %s", metadata, r)
	}
}

// TestRevalidateDocNamesTheChainItRuns is D.9's LOW 8.
//
// Revalidate's doc comment said it "re-runs gates 8, 9 and 10 for gate 13"
// after Ruling 3 had put gate 4 in the chain. A reader of the EXPORTED API
// would have concluded that gate 13 does not re-check scope membership — the
// exact misreading Ruling 3 was issued to correct, and the one ZAP issue #2546
// is a record of. Gate 5 has since joined the chain too.
//
// A doc comment is not usually pinnable, but this one is: it makes a checkable
// claim about a list this file also declares. The expected sentence is built
// FROM revalidationChain, so changing the chain without changing the sentence
// turns this red, in either direction.
//
// Whitespace is normalised before the search, so reflowing the comment is not a
// failure; changing what it says is.
func TestRevalidateDocNamesTheChainItRuns(t *testing.T) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "kernel.go", nil, parser.ParseComments)
	if err != nil {
		t.Fatalf("parse kernel.go: %v", err)
	}
	var doc string
	for _, decl := range f.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if ok && fn.Recv == nil && fn.Name.Name == "Revalidate" && fn.Doc != nil {
			doc = fn.Doc.Text()
		}
	}
	if doc == "" {
		t.Fatal("Revalidate has no doc comment in kernel.go, so this guard measured " +
			"nothing. It is an exported function on the kernel's surface and a reader " +
			"of it decides what gate 13 re-checks")
	}
	doc = strings.Join(strings.Fields(doc), " ")

	want := "re-runs " + gateListPhrase(revalidationChain)
	if !strings.Contains(doc, want) {
		t.Fatalf("Revalidate's doc does not say %q.\n\nrevalidationChain is %v, and the "+
			"doc of the exported function is where a caller learns what gate 13 "+
			"re-checks. The older wording said \"re-runs gates 8, 9 and 10\" after gate "+
			"4 had been added, so the exported API described a gate 13 that does NOT "+
			"re-check scope membership — the misreading Ruling 3 was issued to correct.\n"+
			"\ndoc: %s", want, revalidationChain, doc)
	}
}

// gateListPhrase renders a gate list as "gates 4, 5, 8, 9 and 10".
func gateListPhrase(gates []GateID) string {
	nums := make([]string, 0, len(gates))
	for _, g := range gates {
		nums = append(nums, strconv.Itoa(int(g)))
	}
	switch len(nums) {
	case 0:
		return "no gates"
	case 1:
		return "gate " + nums[0]
	}
	return "gates " + strings.Join(nums[:len(nums)-1], ", ") + " and " + nums[len(nums)-1]
}

// ===========================================================================
// GATE 21 — the audit write is part of the decision
// ===========================================================================

// TestStructuralRefusalNamesTheGateItRefusesAt pins the kernel's structural
// refusal tokens.
//
// The kernel mints two refusals about the GATE STACK rather than about the
// inputs — "this chain position has no implementation compiled in" and "this
// implementation signed someone else's name" — and both must name the gate
// they are attributed to. A gateNN ruling carrying a gate21.* token is not a
// cosmetic mis-filing: GateRecord.Validate rejects exactly that mismatch and
// Adjudicate validates every row before writing any, so the whole audit of the
// denial is discarded. See TestAdjudicateWritesAuditRowsForARealChainDenial.
//
// It also pins the two slugs against the gate-21 constants they mirror, so the
// two spellings cannot drift apart, and drives the invalid-gate fallback.
func TestStructuralRefusalNamesTheGateItRefusesAt(t *testing.T) {
	// The slugs and the chain-level constants are the same words.
	if got := Reason("gate21." + slugGateNotRegistered); got != ReasonGateNotRegistered {
		t.Fatalf("gate21.%s is %q and ReasonGateNotRegistered is %q; the per-gate and "+
			"chain-level spellings of one refusal have drifted apart",
			slugGateNotRegistered, string(got), string(ReasonGateNotRegistered))
	}
	if got := Reason("gate21." + slugGateIdentityMismatch); got != ReasonGateIdentityMismatch {
		t.Fatalf("gate21.%s is %q and ReasonGateIdentityMismatch is %q",
			slugGateIdentityMismatch, string(got), string(ReasonGateIdentityMismatch))
	}

	// Every one of the 21 gates can name itself, and the ruling it produces
	// is one an audit row can be built from.
	for g := Gate1DastShipsDisabled; g.Valid(); g++ {
		for _, slug := range []string{slugGateNotRegistered, slugGateIdentityMismatch} {
			r := structuralRefusal(g, slug, "fixture")
			if r.Gate() != g {
				t.Fatalf("structuralRefusal(%s, %q) is attributed to %s", g, slug, r.Gate())
			}
			if !r.WellFormedDenial() {
				t.Fatalf("structuralRefusal(%s, %q) = %s is not a well-formed denial, so "+
					"the chain would convert it into a second refusal and the audit row "+
					"for it would not validate", g, slug, r)
			}
			named, err := r.Reason().Gate()
			if err != nil || named != g {
				t.Fatalf("structuralRefusal(%s, %q) minted reason %q, which names %s "+
					"(%v). GateRecord.Validate refuses a row whose reason names a "+
					"different gate from the row itself", g, slug, string(r.Reason()),
					named, err)
			}
			if want := Reason(g.String() + "." + slug); r.Reason() != want {
				t.Fatalf("structuralRefusal(%s, %q) minted %q; want %q",
					g, slug, string(r.Reason()), string(want))
			}
		}
	}

	// A gate that is not one of the 21 cannot name itself, so the refusal
	// falls back to gate 21 — the gate that has failed when the kernel cannot
	// say which gate failed. It must still be a well-formed denial.
	for _, bad := range []GateID{GateUnspecified, GateID(22), GateID(255)} {
		r := structuralRefusal(bad, slugGateNotRegistered, "fixture")
		if r.Gate() != Gate21ImmutableAudit {
			t.Fatalf("structuralRefusal(%s) is attributed to %s; an invalid gate cannot "+
				"name itself in a token, so the refusal belongs to gate 21", bad, r.Gate())
		}
		if r.Reason() != ReasonGateNotRegistered || !r.WellFormedDenial() {
			t.Fatalf("structuralRefusal(%s) = %s; want a well-formed gate-21 denial", bad, r)
		}
	}
}

// TestAdjudicateWritesAuditRowsForARealChainDenial is D.9's HIGH 1, written as
// the measurement the critic made.
//
// WHAT WAS MEASURED, AND WHY NOTHING SAW IT. chain.runTraced minted the
// missing-implementation refusal as refuse(Gate11RobotsDeny,
// ReasonGateNotRegistered, ...) — a gate21.* token attributed to gate 11.
// GateRecord.Validate rejects that mismatch, and Adjudicate validates every row
// before it writes any, so the whole write loop aborted: seven gates consulted,
// a denial issued, "audit rows written: 0", and the decision came back as
// gate21.audit_key_incomplete instead of as the gate-11 refusal it was. Gate 21
// says a decision is not "allowed" if its paired audit write fails; a DENIAL
// whose rows all vanish is the same control failing in the direction nobody
// looks at, and a run refused a thousand times then looks like a run nobody
// attempted.
//
// It was invisible because EVERY OTHER Adjudicate test substitutes
// permitAll(admissionChain) and never runs the real chain — they exercised a
// chain that cannot deny. THIS TEST CALLS THE EXPORTED Adjudicate, over the
// compiled-in registry, and drives it to a denial two different ways: a gate
// that refuses on the merits, and the structural refusal at the first
// unimplemented gate.
func TestAdjudicateWritesAuditRowsForARealChainDenial(t *testing.T) {
	scope := mustScope(t, ModeExternal)
	att := attestFor(t, scope)
	en := mustEnablement(t, scope, att)
	clk := mustClock(t)

	// assertAudited is the whole point: a denial is a decision, and gate 21
	// requires every decision to be recorded.
	assertAudited := func(t *testing.T, sink *recordingSink, d Decision, wantRows int) {
		t.Helper()
		if d.Allowed() {
			t.Fatalf("Adjudicate ALLOWED through the real admission chain: %v", d.Err())
		}
		if len(sink.rows) == 0 {
			t.Fatalf("audit rows written: 0, for a denial at %s (%s). Gate 21 is an "+
				"immutable audit of EVERY gate decision, allow and deny alike; a denial "+
				"that records nothing is the audit failing in the direction nobody "+
				"looks at", d.Gate(), string(d.Reason()))
		}
		if len(sink.rows) != wantRows {
			t.Fatalf("%d audit rows written; %d gates were consulted before the refusal",
				len(sink.rows), wantRows)
		}
		if d.Reason() == ReasonAuditKeyIncomplete {
			t.Fatalf("the decision came back as %q. That is the kernel saying it could "+
				"not build a keyable row for its own refusal — the D.9 HIGH 1 shape",
				string(ReasonAuditKeyIncomplete))
		}
		last := sink.rows[len(sink.rows)-1]
		if err := last.Validate(); err != nil {
			t.Fatalf("the last audit row does not validate: %v", err)
		}
		if last.Gate != d.Gate() || last.Reason != d.Reason() {
			t.Fatalf("the decision is %s/%s and the last row records %s/%s",
				d.Gate(), string(d.Reason()), last.Gate, string(last.Reason))
		}
		if last.Outcome != OutcomeDeny {
			t.Fatalf("the last row's outcome is %q for a refused decision", string(last.Outcome))
		}
		for i, row := range sink.rows {
			if err := row.Validate(); err != nil {
				t.Fatalf("audit row %d (%s) does not validate: %v", i, row.Gate, err)
			}
		}
	}

	t.Run("a gate refuses on the merits", func(t *testing.T) {
		// cdn.example.net is routable, on no deny list, in no reserved range
		// — and in nobody's allow list. Gate 4 is the first gate in the chain
		// and it refuses, so exactly one gate was consulted.
		offScope := mustTarget(t, "cdn.example.net", 443, "93.184.216.35")
		sink := &recordingSink{}
		d := Adjudicate(sink, en, offScope, scope, att, clk)
		assertAudited(t, sink, d, 1)
		if d.Gate() != Gate4ScopeFile {
			t.Fatalf("an off-scope target was refused by %s; the allow-list match is "+
				"gate 4, so this fixture is not testing what it claims", d.Gate())
		}
	})

	t.Run("the chain stops at an unimplemented gate", func(t *testing.T) {
		missing := firstUnregisteredAdmissionGate()
		inScope := mustTarget(t, "target.example.com", 443, "93.184.216.34")
		sink := &recordingSink{}
		d := Adjudicate(sink, en, inScope, scope, att, clk)

		if missing == GateUnspecified {
			// The stack is complete, so this fixture must be ALLOWED and every
			// gate must still have been recorded. The assertion narrows on its
			// own as later packets land rather than needing an edit.
			if !d.Allowed() {
				t.Fatalf("the admission stack is fully implemented and refused a fully "+
					"valid fixture: %v", d.Err())
			}
			if len(sink.rows) != len(admissionChain) {
				t.Fatalf("%d rows for %d gates", len(sink.rows), len(admissionChain))
			}
			return
		}

		// Every gate up to and including the missing one was consulted, so
		// every one of them must have a row.
		consulted := 0
		for _, g := range admissionChain {
			consulted++
			if g == missing {
				break
			}
		}
		assertAudited(t, sink, d, consulted)
		if d.Gate() != missing {
			t.Fatalf("the refusal names %s; the first unimplemented gate is %s",
				d.Gate(), missing)
		}
		if want := Reason(missing.String() + "." + slugGateNotRegistered); d.Reason() != want {
			t.Fatalf("reason %q; want %q", string(d.Reason()), string(want))
		}
		t.Logf("%d audit rows written for a denial at %s (%s)",
			len(sink.rows), d.Gate(), string(d.Reason()))
	})
}

// TestAdjudicateAllowsOnlyWhenTheAuditWriteSucceeds is gate 21 stated as a
// test: "a gate decision is not 'allowed' if its paired audit write fails."
//
// Every case here uses a chain in which EVERY GATE PERMITS. The pure ruling is
// an allow in all four; the only difference is the sink. Three of the four must
// still refuse.
func TestAdjudicateAllowsOnlyWhenTheAuditWriteSucceeds(t *testing.T) {
	scope := mustScope(t, ModeExternal)
	att := attestFor(t, scope)
	en := mustEnablement(t, scope, att)
	tgt := mustTarget(t, "target.example.com", 443, "93.184.216.34")
	clk := mustClock(t)
	ch := permitAll(admissionChain)

	t.Run("write succeeds", func(t *testing.T) {
		sink := &recordingSink{}
		d := adjudicateWith(sink, en, ch, tgt, scope, att, clk)
		if !d.Allowed() {
			t.Fatalf("a permitting chain with a working sink did not allow: %v", d.Err())
		}
		if len(sink.rows) != len(admissionChain) {
			t.Fatalf("%d audit rows written for %d gates consulted. Gate 21 is an "+
				"'immutable audit of EVERY GATE DECISION'; one row per adjudication "+
				"records one gate and loses the rest",
				len(sink.rows), len(admissionChain))
		}
		for i, row := range sink.rows {
			if row.Gate != admissionChain[i] {
				t.Fatalf("audit row %d is attributed to %s; the chain consulted %s at that "+
					"position", i, row.Gate, admissionChain[i])
			}
			if row.AttestationID != att.ID() || row.ScopeHash != scope.Hash() {
				t.Fatalf("audit row %d is keyed to (%q, %q); gate 21 requires "+
					"(attestation ID, scope hash) = (%q, %q)",
					i, row.AttestationID, row.ScopeHash, att.ID(), scope.Hash())
			}
			if row.Outcome != OutcomeAllow {
				t.Fatalf("audit row %d records outcome %q for an allowed decision",
					i, row.Outcome)
			}
		}
		if seq, err := d.AuditSeq(); err != nil || seq == 0 {
			t.Fatalf("an allowed decision has no audit sequence: seq=%d err=%v", seq, err)
		}
	})

	t.Run("write fails", func(t *testing.T) {
		boom := errors.New("disk full")
		d := adjudicateWith(failingSink{err: boom}, en, ch, tgt, scope, att, clk)
		if d.Allowed() {
			t.Fatal("the decision was allowed although the audit write failed. Gate 21: " +
				"'a gate decision is not \"allowed\" if its paired audit write fails'. " +
				"The write is part of the decision, not a side effect of it")
		}
		if !errors.Is(d.Err(), ErrAuditWriteFailed) {
			t.Fatalf("the refusal does not unwrap to ErrAuditWriteFailed: %v", d.Err())
		}
		if !errors.Is(d.Err(), boom) {
			t.Fatalf("the sink's own error was lost: %v", d.Err())
		}
		if _, err := d.Authorization(); err == nil {
			t.Fatal("an Authorization was minted from a decision whose audit write failed")
		}
	})

	t.Run("sink writes nothing and says so quietly", func(t *testing.T) {
		d := adjudicateWith(silentSink{}, en, ch, tgt, scope, att, clk)
		if d.Allowed() {
			t.Fatal("a sink returning (0, nil) produced an allowed decision. Sequence 0 " +
				"is what a stub or a short-circuited implementation returns, and a row " +
				"that was not written cannot make a decision allowed")
		}
		// Attributed, for the same reason as the empty chain above: two
		// guards catch this (Adjudicate's seq check and grant.ok's), and a
		// test that only looks at Allowed() cannot see one of them go.
		if d.Reason() != ReasonAuditWriteFailed {
			t.Fatalf("reason %q; want %q so the operator learns the sink wrote nothing "+
				"rather than reading the gate's own permit and wondering why it was "+
				"refused", string(d.Reason()), string(ReasonAuditWriteFailed))
		}
	})

	t.Run("no sink at all", func(t *testing.T) {
		d := adjudicateWith(nil, en, ch, tgt, scope, att, clk)
		if d.Allowed() {
			t.Fatal("a decision with no audit sink was allowed")
		}
		if d.Reason() != ReasonAuditSinkMissing {
			t.Fatalf("reason %q; want %q", string(d.Reason()), string(ReasonAuditSinkMissing))
		}
	})
}

// TestAdjudicateAuditsDenialsToo — gate 21 logs "every allow/deny/
// redirect-refusal/circuit-breaker-trip". A deny that vanishes makes a run
// that was refused a thousand times look like a run nobody attempted.
func TestAdjudicateAuditsDenialsToo(t *testing.T) {
	scope := mustScope(t, ModeExternal)
	att := attestFor(t, scope)
	en := mustEnablement(t, scope, att)
	tgt := mustTarget(t, "target.example.com", 443, "93.184.216.34")
	clk := mustClock(t)

	ch := permitAll(admissionChain)
	ch.impls[Gate10ReservedRanges] = func(Target, Scope, Attestation, Clock) Ruling {
		return refuse(Gate10ReservedRanges, "gate10.reserved_range", "169.254.169.254")
	}

	sink := &recordingSink{}
	d := adjudicateWith(sink, en, ch, tgt, scope, att, clk)
	if d.Allowed() {
		t.Fatal("a refusing chain produced an allowed decision")
	}

	// The gates that ran before the refusal, then the refusal. Everything
	// after it did not run and must not be recorded as having agreed.
	stopped := -1
	for i, g := range admissionChain {
		if g == Gate10ReservedRanges {
			stopped = i
			break
		}
	}
	if stopped < 0 {
		t.Fatalf("premise: %s is not in the admission chain", Gate10ReservedRanges)
	}
	if len(sink.rows) != stopped+1 {
		t.Fatalf("%d audit rows written; the chain consulted %d gates before refusing at "+
			"%s, and gate 21 logs every one of those decisions as well as the deny",
			len(sink.rows), stopped, Gate10ReservedRanges)
	}
	for i := 0; i < stopped; i++ {
		if sink.rows[i].Outcome != OutcomeAllow || sink.rows[i].Gate != admissionChain[i] {
			t.Fatalf("audit row %d is %s/%q; the chain permitted at %s",
				i, sink.rows[i].Gate, sink.rows[i].Outcome, admissionChain[i])
		}
	}
	last := sink.rows[stopped]
	if last.Outcome != OutcomeDeny {
		t.Fatalf("the deciding audit row records outcome %q for a denial", last.Outcome)
	}
	if last.Gate != Gate10ReservedRanges {
		t.Fatalf("the audit row attributes the denial to %s; %s refused",
			last.Gate, Gate10ReservedRanges)
	}
}

// TestGate21WritesOneRowPerGateDecision is D.3's critic's gate-21 finding as a
// test: "Eight gates consulted, one row."
//
// Adjudicate used to build ONE record from the chain's last permitting ruling.
// Every gate that agreed on the way there was invisible in the audit, which is
// not what "immutable audit of every gate decision" says. The assertion is on
// the SET of gates recorded, not on a count, so a chain that grows or shrinks
// does not silently satisfy it.
func TestGate21WritesOneRowPerGateDecision(t *testing.T) {
	scope := mustScope(t, ModeExternal)
	att := attestFor(t, scope)
	en := mustEnablement(t, scope, att)
	tgt := mustTarget(t, "target.example.com", 443, "93.184.216.34")
	sink := &recordingSink{}

	d := adjudicateWith(sink, en, permitAll(admissionChain), tgt, scope, att, mustClock(t))
	if !d.Allowed() {
		t.Fatalf("setup: a permitting chain did not allow: %v", d.Err())
	}

	var got []GateID
	for _, r := range sink.rows {
		got = append(got, r.Gate)
	}
	if !reflect.DeepEqual(got, admissionChain) {
		t.Fatalf("the audit recorded %v; the admission chain consulted %v. Gate 21 is an "+
			"immutable audit of EVERY GATE DECISION, and a gate whose ruling was never "+
			"written is a gate an auditor cannot tell ran", got, admissionChain)
	}
	if len(sink.rows) < 2 {
		t.Fatalf("premise: the admission chain has %d gates, so this test cannot "+
			"distinguish one row per gate from one row per adjudication", len(sink.rows))
	}
}

// TestAdjudicateRefusesAnUnkeyableDecision — gate 21 keys every row on the
// attestation ID and the scope hash. A decision that cannot be keyed cannot be
// joined back to who authorised what, so it is not allowed.
func TestAdjudicateRefusesAnUnkeyableDecision(t *testing.T) {
	scope := mustScope(t, ModeExternal)
	att := attestFor(t, scope)
	en := mustEnablement(t, scope, att)
	tgt := mustTarget(t, "target.example.com", 443, "93.184.216.34")

	// A Clock nobody minted. The kernel's preconditions refuse it at gate 5,
	// and the row built for that refusal carries the zero instant — so the
	// record validator, which is a SECOND line behind the preconditions,
	// refuses it too. Gate 21: a row with no instant is not an audit row.
	sink := &recordingSink{}
	d := adjudicateWith(sink, en, permitAll(admissionChain), tgt, scope, att, Clock{})
	if d.Allowed() {
		t.Fatal("a decision with an unkeyable audit row was allowed")
	}
	if d.Reason() != ReasonAuditKeyIncomplete {
		t.Fatalf("reason %q; want %q", string(d.Reason()), string(ReasonAuditKeyIncomplete))
	}
	if len(sink.rows) != 0 {
		t.Fatalf("an invalid row was handed to the sink anyway: %+v", sink.rows)
	}
}

// TestAdjudicateRefusesWithoutAnEnablement is gate 1 as a precondition rather
// than a decoration.
//
// D.3's critic reached Adjudicate without ever calling EnableDAST. The zero
// DastEnablement is what such a caller holds — and, because no reflective
// decoder can write an unexported field, it is also what a config file
// produces — so it must authorize nothing.
func TestAdjudicateRefusesWithoutAnEnablement(t *testing.T) {
	scope := mustScope(t, ModeExternal)
	att := attestFor(t, scope)
	tgt := mustTarget(t, "target.example.com", 443, "93.184.216.34")
	clk := mustClock(t)
	ch := permitAll(admissionChain)

	t.Run("no enablement at all", func(t *testing.T) {
		sink := &recordingSink{}
		d := adjudicateWith(sink, DastEnablement{}, ch, tgt, scope, att, clk)
		if d.Allowed() {
			t.Fatal("a caller who never called EnableDAST was allowed to probe. Gate 1's " +
				"'explicit, non-defaulted write' is a precondition of adjudication, not " +
				"a value nobody reads")
		}
		if d.Reason() != ReasonDastNotEnabled {
			t.Fatalf("reason %q; want %q", string(d.Reason()), string(ReasonDastNotEnabled))
		}
	})

	t.Run("enabled for another scope", func(t *testing.T) {
		// A second, genuinely enabled run against a DIFFERENT scope file. Its
		// enablement is real; it is simply not this scope's.
		other := mustScopeOf(t, ModeExternal,
			[]ScopeEntry{{Host: "other.example.com", Ports: []uint16{443}}}, nil)
		otherAtt := attestFor(t, other)
		otherEn := mustEnablement(t, other, otherAtt)

		d := adjudicateWith(&recordingSink{}, otherEn, ch, tgt, scope, att, clk)
		if d.Allowed() {
			t.Fatal("an enablement minted for one scope authorized a decision about " +
				"another. An operator's authorisation for one engagement is not " +
				"authorisation for the next one")
		}
		if d.Reason() != ReasonEnablementWrongScope {
			t.Fatalf("reason %q; want %q", string(d.Reason()),
				string(ReasonEnablementWrongScope))
		}
	})

	t.Run("positive control", func(t *testing.T) {
		d := adjudicateWith(&recordingSink{}, mustEnablement(t, scope, att), ch, tgt,
			scope, att, clk)
		if !d.Allowed() {
			t.Fatalf("the real enablement was refused, so the two cases above pass by "+
				"refusing everything: %v", d.Err())
		}
	})
}

// rewindingSink returns the SAME sequence number for every row: a sink that
// overwrote the previous one, or a counter that never advanced.
type rewindingSink struct{ n int }

func (s *rewindingSink) WriteGateDecision(GateRecord) (AuditSeq, error) {
	s.n++
	return 1, nil
}

// TestAdjudicateRefusesASinkThatDoesNotAdvance is gate 21's "IMMUTABLE audit"
// on the admission path.
//
// Now that one adjudication writes several rows, a sink that returns the same
// sequence for each of them has either overwritten a row or is not counting. It
// is consistent with D.7's GateAudit.Record, which makes the same check across
// a run; this one is within a single adjudication, which is the part Adjudicate
// can see.
func TestAdjudicateRefusesASinkThatDoesNotAdvance(t *testing.T) {
	scope := mustScope(t, ModeExternal)
	att := attestFor(t, scope)
	en := mustEnablement(t, scope, att)
	tgt := mustTarget(t, "target.example.com", 443, "93.184.216.34")

	sink := &rewindingSink{}
	d := adjudicateWith(sink, en, permitAll(admissionChain), tgt, scope, att, mustClock(t))
	if d.Allowed() {
		t.Fatal("a sink that returned the same sequence number for every row produced an " +
			"allowed decision. Gate 21 requires an immutable audit, and a log that can " +
			"go backwards is a log whose earlier rows cannot be trusted")
	}
	if d.Reason() != ReasonAuditNotAppendOnly {
		t.Fatalf("reason %q; want %q", string(d.Reason()), string(ReasonAuditNotAppendOnly))
	}
	if sink.n < 2 {
		t.Fatalf("the sink was called %d time(s); this test only distinguishes an "+
			"append-only check from a single-row write if more than one row is written",
			sink.n)
	}
}

// TestDecisionLayersEachRefuseOnTheirOwn is the LOW finding D.3's critic left
// on the denial path: two of the three layers were subsumed by the first, and
// mutating either left the suite green.
//
// They are kept rather than deleted because they are NOT subsumed for a
// Decision built any way other than the one Adjudicate takes — and this package
// is where Decisions are built. Each case below is refused by exactly one
// layer, so mutating that layer turns this test red.
func TestDecisionLayersEachRefuseOnTheirOwn(t *testing.T) {
	scope := mustScope(t, ModeExternal)
	att := attestFor(t, scope)
	tgt := mustTarget(t, "target.example.com", 443, "93.184.216.34")
	clk := mustClock(t)

	allowRec := GateRecord{
		Gate:          Gate10ReservedRanges,
		Outcome:       OutcomeAllow,
		Reason:        "gate10.test_permit",
		AttestationID: att.ID(),
		ScopeHash:     scope.Hash(),
		Mode:          ModeExternal,
		Target:        tgt.String(),
		At:            clk.Instant(),
	}
	if err := allowRec.Validate(); err != nil {
		t.Fatalf("premise: the fixture row is not a valid audit row: %v", err)
	}
	goodGrant := &grant{rec: allowRec, seq: 7, target: tgt, mode: ModeExternal}
	if !goodGrant.ok() {
		t.Fatal("premise: the fixture grant is not ok, so neither case below isolates a layer")
	}

	t.Run("a valid grant does not rescue a denying ruling", func(t *testing.T) {
		d := Decision{
			ruling: refuse(Gate10ReservedRanges, "gate10.reserved_range", "169.254.169.254"),
			grant:  goodGrant,
		}
		if d.Allowed() {
			t.Fatal("a Decision whose ruling DENIED was allowed because its grant was " +
				"well formed. Decision.Allowed's `d.ruling.Permits()` is the only thing " +
				"refusing this one")
		}
	})

	t.Run("a permitting ruling does not rescue a grant that records a deny", func(t *testing.T) {
		denyRec := allowRec
		denyRec.Outcome = OutcomeDeny
		denyRec.Reason = "gate10.reserved_range"
		d := Decision{
			ruling: permit(Gate10ReservedRanges, "gate10.test_permit", "test fixture"),
			grant:  &grant{rec: denyRec, seq: 7, target: tgt, mode: ModeExternal},
		}
		if d.Allowed() {
			t.Fatal("a Decision was allowed although the audit row behind it records a " +
				"DENY. grant.ok's `g.rec.Outcome == OutcomeAllow` is the only thing " +
				"refusing this one, and an authorization whose own audit row says it " +
				"was refused is not an authorization")
		}
	})

	t.Run("positive control", func(t *testing.T) {
		d := Decision{
			ruling: permit(Gate10ReservedRanges, "gate10.test_permit", "test fixture"),
			grant:  goodGrant,
		}
		if !d.Allowed() {
			t.Fatal("the well-formed Decision was refused, so the two cases above pass " +
				"by refusing everything")
		}
	})
}

func TestGateRecordValidateRefusals(t *testing.T) {
	good := GateRecord{
		Gate:          Gate10ReservedRanges,
		Outcome:       OutcomeDeny,
		Reason:        "gate10.reserved_range",
		AttestationID: "attest-1",
		ScopeHash:     fixtureScopeHash,
		Mode:          ModeExternal,
		Target:        "https://target.example.com:443 -> 93.184.216.34",
		At:            fixtureNow,
	}
	if err := good.Validate(); err != nil {
		t.Fatalf("a well-formed audit row was rejected: %v", err)
	}

	mutate := map[string]func(*GateRecord){
		"no gate":            func(r *GateRecord) { r.Gate = GateUnspecified },
		"no outcome":         func(r *GateRecord) { r.Outcome = OutcomeUnset },
		"invented outcome":   func(r *GateRecord) { r.Outcome = "maybe" },
		"no reason":          func(r *GateRecord) { r.Reason = ReasonUnspecified },
		"free-text reason":   func(r *GateRecord) { r.Reason = "it looked dangerous" },
		"reason wrong gate":  func(r *GateRecord) { r.Reason = "gate04.something" },
		"no attestation id":  func(r *GateRecord) { r.AttestationID = "" },
		"bad attestation id": func(r *GateRecord) { r.AttestationID = "attest 1; drop table" },
		"no scope hash":      func(r *GateRecord) { r.ScopeHash = "" },
		"short scope hash":   func(r *GateRecord) { r.ScopeHash = "abc123" },
		"uppercase hash":     func(r *GateRecord) { r.ScopeHash = ScopeHash(strings.ToUpper(string(fixtureScopeHash))) },
		"no mode":            func(r *GateRecord) { r.Mode = ModeUnset },
		"auto mode":          func(r *GateRecord) { r.Mode = "auto" },
		"no target":          func(r *GateRecord) { r.Target = "" },
		"no instant":         func(r *GateRecord) { r.At = time.Time{} },
	}
	for name, m := range mutate {
		t.Run(name, func(t *testing.T) {
			r := good
			m(&r)
			if err := r.Validate(); err == nil {
				t.Fatalf("an audit row with %s validated. Gate 21 keys every row on the "+
					"attestation ID and the scope hash, and a row that cannot be joined "+
					"back to who authorised what is not an audit row", name)
			}
		})
	}
}

// ===========================================================================
// AUTHORIZATION — gate 3's runtime half
// ===========================================================================

func TestAuthorizationCannotBeObtainedWithoutAnAuditedAllow(t *testing.T) {
	scope := mustScope(t, ModeExternal)
	att := attestFor(t, scope)
	en := mustEnablement(t, scope, att)
	tgt := mustTarget(t, "target.example.com", 443, "93.184.216.34")
	clk := mustClock(t)

	// The real kernel, through the real registry, against a target that no
	// complete gate stack may ever permit: a host on no scope list, pinned to
	// the cloud metadata endpoint, in external mode. Today it is refused
	// because the chain is unimplemented; after D.4-D.6 it is refused by
	// gates 4, 8 and 10. Either way there is no Authorization.
	metadata := mustTarget(t, "metadata.example.net", 80, "169.254.169.254")
	if _, err := Adjudicate(&recordingSink{}, en, metadata, scope, att, clk).Authorization(); err == nil {
		t.Fatalf("an Authorization was minted for %s, which is on no scope list and is the "+
			"cloud metadata endpoint", metadata)
	}

	// A permitting chain with a failing sink: still no authorization.
	if _, err := adjudicateWith(failingSink{err: errors.New("nope")}, en, permitAll(admissionChain),
		tgt, scope, att, clk).Authorization(); err == nil {
		t.Fatal("an Authorization was minted from a decision whose audit write failed")
	}

	// Positive control.
	auth, err := adjudicateWith(&recordingSink{}, en, permitAll(admissionChain),
		tgt, scope, att, clk).Authorization()
	if err != nil {
		t.Fatalf("no Authorization from an audited allow: %v", err)
	}
	if !auth.Valid() {
		t.Fatal("the Authorization minted from an audited allow reports Valid() == false")
	}

	// The accessors D.6's per-request enforcement and D.7's disclosure gates
	// read. Each must carry the token back to the exact decision it came
	// from, and each must refuse on the zero value.
	if got, err := auth.Target(); err != nil || got != tgt {
		t.Errorf("Authorization.Target() = (%s, %v); want the target it was minted for", got, err)
	}
	if got, err := auth.Mode(); err != nil || got != ModeExternal {
		t.Errorf("Authorization.Mode() = (%q, %v); want %q", got, err, ModeExternal)
	}
	if got, err := auth.AttestationID(); err != nil || got != att.ID() {
		t.Errorf("Authorization.AttestationID() = (%q, %v); want %q", got, err, att.ID())
	}
	if got, err := auth.ScopeHash(); err != nil || got != scope.Hash() {
		t.Errorf("Authorization.ScopeHash() = (%q, %v); want %q", got, err, scope.Hash())
	}
	if got, err := auth.AuditSeq(); err != nil || got == 0 {
		t.Errorf("Authorization.AuditSeq() = (%d, %v); an authorization always rests on a "+
			"written audit row", got, err)
	}

	var zero Authorization
	for name, err := range map[string]error{
		"Target":        secondErr(zero.Target()),
		"Mode":          secondErr(zero.Mode()),
		"AttestationID": secondErr(zero.AttestationID()),
		"ScopeHash":     secondErr(zero.ScopeHash()),
		"AuditSeq":      secondErr(zero.AuditSeq()),
	} {
		if err == nil {
			t.Errorf("Authorization{}.%s() answered without an error; a token nobody "+
				"minted knows nothing", name)
		}
	}
}

// secondErr discards a two-result accessor's value and keeps its error, so the
// zero-value sweep above can be written as a table.
func secondErr[T any](_ T, err error) error { return err }

func TestRequireAuthorizationRefusals(t *testing.T) {
	scope := mustScope(t, ModeExternal)
	att := attestFor(t, scope)
	en := mustEnablement(t, scope, att)
	clk := mustClock(t)
	tgt := mustTarget(t, "target.example.com", 443, "93.184.216.34")

	auth, err := adjudicateWith(&recordingSink{}, en, permitAll(admissionChain),
		tgt, scope, att, clk).Authorization()
	if err != nil {
		t.Fatalf("setup: %v", err)
	}

	if err := RequireAuthorization(auth, tgt); err != nil {
		t.Fatalf("the choke point refused the exact target the token was minted for: %v", err)
	}

	t.Run("zero authorization", func(t *testing.T) {
		if err := RequireAuthorization(Authorization{}, tgt); err == nil {
			t.Fatal("the egress choke point accepted a zero Authorization, so a socket " +
				"would be opened with no decision behind it")
		}
	})
	t.Run("zero target", func(t *testing.T) {
		if err := RequireAuthorization(auth, Target{}); err == nil {
			t.Fatal("the egress choke point accepted an unconstructed Target")
		}
	})
	t.Run("same host, different pinned address", func(t *testing.T) {
		// This is the DNS-rebinding shape: the hostname still matches and
		// the address has moved to the cloud metadata endpoint.
		rebound := mustTarget(t, "target.example.com", 443, "169.254.169.254")
		if err := RequireAuthorization(auth, rebound); err == nil {
			t.Fatal("a token minted for target.example.com pinned to 93.184.216.34 " +
				"authorized a connection to the same hostname pinned to " +
				"169.254.169.254. Gate 9 pins the resolved address precisely so that a " +
				"re-resolution between check and connect cannot move the connection")
		}
	})
	t.Run("different host", func(t *testing.T) {
		other := mustTarget(t, "evil.example.net", 443, "93.184.216.34")
		if err := RequireAuthorization(auth, other); err == nil {
			t.Fatal("a token minted for one host authorized another. Cross-target reuse " +
				"of a token is how a redirect escapes scope (gates 9 and 13)")
		}
	})
	t.Run("different port", func(t *testing.T) {
		other := mustTarget(t, "target.example.com", 8443, "93.184.216.34")
		if err := RequireAuthorization(auth, other); err == nil {
			t.Fatal("a token minted for :443 authorized :8443")
		}
	})
}

// TestGrantRequiresARealAuditRow tests the backstop directly.
//
// Adjudicate checks the sink's return value AND grant.ok re-checks it, which
// is deliberate redundancy — but it means neither guard can be seen to fail
// through Adjudicate alone. This test drives grant.ok itself so that each of
// its five conditions is a control that can be observed going red.
func TestGrantRequiresARealAuditRow(t *testing.T) {
	tgt := mustTarget(t, "target.example.com", 443, "93.184.216.34")
	goodRec := GateRecord{
		Gate:          Gate11RobotsDeny,
		Outcome:       OutcomeAllow,
		Reason:        "gate11.no_deny_signal",
		AttestationID: "attest-1",
		ScopeHash:     fixtureScopeHash,
		Mode:          ModeExternal,
		Target:        tgt.String(),
		At:            fixtureNow,
	}
	good := &grant{rec: goodRec, seq: 1, target: tgt, mode: ModeExternal}
	if !good.ok() {
		t.Fatalf("a well-formed grant is not ok; the positive control fails so nothing "+
			"below proves anything: rec.Validate()=%v", goodRec.Validate())
	}

	denyRec := goodRec
	denyRec.Outcome = OutcomeDeny
	unkeyedRec := goodRec
	unkeyedRec.AttestationID = ""

	bad := map[string]*grant{
		"nil":                       nil,
		"sequence zero":             {rec: goodRec, seq: 0, target: tgt, mode: ModeExternal},
		"records a denial":          {rec: denyRec, seq: 1, target: tgt, mode: ModeExternal},
		"unkeyable row":             {rec: unkeyedRec, seq: 1, target: tgt, mode: ModeExternal},
		"unconstructed target":      {rec: goodRec, seq: 1, target: Target{}, mode: ModeExternal},
		"no mode":                   {rec: goodRec, seq: 1, target: tgt, mode: ModeUnset},
		"auto mode":                 {rec: goodRec, seq: 1, target: tgt, mode: "auto"},
		"zero value":                {},
		"authorization around it":   {rec: goodRec, seq: 0, target: tgt, mode: ModeExternal},
		"decision wrapping it":      {rec: denyRec, seq: 0, target: Target{}, mode: ModeUnset},
		"row written by no sink at": nil,
	}
	for name, g := range bad {
		if g.ok() {
			t.Errorf("grant %q reports ok(). Sequence 0 is what a sink that wrote nothing "+
				"returns, and every other condition here means the row cannot be joined "+
				"back to a decision", name)
		}
		if (Authorization{grant: g}).Valid() {
			t.Errorf("an Authorization wrapping the %q grant reports Valid()", name)
		}
		if (Decision{grant: g}).Allowed() {
			t.Errorf("a Decision wrapping the %q grant reports Allowed()", name)
		}
	}
}

// TestTargetStaysComparable guards RequireAuthorization's single ==. If a
// future field makes Target incomparable the comparison stops compiling, which
// is correct; this test says so out loud so the fix is not "use reflect.DeepEqual".
func TestTargetStaysComparable(t *testing.T) {
	if !reflect.TypeOf(Target{}).Comparable() {
		t.Fatal("Target is no longer comparable. RequireAuthorization compares the " +
			"authorized target with the one being dialled using ==, and that comparison " +
			"IS the check. Keep Target comparable rather than replacing == with a " +
			"deep-equality helper that can be given a laxer definition later")
	}
}
