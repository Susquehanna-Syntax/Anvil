// The kernel proper: the pure decision function plan/00-SPINE.md S7 mandates,
// the gate chain it runs, and the audit-coupled adjudication that turns a pure
// ruling into something a socket may be opened on.
//
// ===========================================================================
// THE FOUR-STEP FLOW, AND WHY IT IS FOUR STEPS AND NOT ONE
// ===========================================================================
//
//	Decide(target, scope, attestation, clock) -> Ruling
//	    The pure function. S7: "The authorization kernel is a pure function of
//	    (target, scope, attestation, clock)". It reads no files, opens no
//	    sockets, consults no clock of its own, and writes nothing. A Ruling
//	    AUTHORIZES NOTHING — it is an opinion.
//
//	Adjudicate(sink, enablement, target, scope, attestation, clock) -> Decision
//	    The impure wrapper, and the only mint point for permission in Anvil.
//	    It checks gate 1's enablement, calls the chain, writes ONE AUDIT ROW
//	    PER GATE DECISION, and mints an allowing Decision ONLY if every one of
//	    those writes succeeded. This is gate 21 as a structure rather than as
//	    a rule people remember: "a gate decision is not 'allowed' if its paired
//	    audit write fails."
//
//	Decision.Authorization() -> Authorization
//	    The unforgeable token. It carries an unexported pointer to the grant
//	    minted above. No package outside internal/dast/authz can construct
//	    one, because a composite literal cannot set an unexported field — a
//	    compile error, not a lint.
//
//	RequireAuthorization(auth, target) -> error
//	    Gate 3's runtime half. The egress choke point calls this before it
//	    constructs a socket, and refuses if the token does not name exactly
//	    this target and exactly this pinned address.
//
// The split between step 1 and step 2 is the whole reason S7's "pure function"
// and gate 21's "the audit write is part of the decision" are not in conflict.
// A pure function cannot write to a log. So the pure function does not produce
// permission; it produces an opinion, and permission is produced by the thing
// that also wrote the log. Neither half can be used without the other.
//
// ===========================================================================
// WHY A MISSING GATE IS A REFUSAL
// ===========================================================================
//
// The admission chain is a compiled-in ordered list of GateIDs. Gate
// implementations install themselves into a registry from their own files
// (D.4–D.7). If a gate in the chain has NO implementation compiled in, the
// chain REFUSES at that gate. It does not skip it, log a warning, or treat the
// absence as a pass.
//
// That is not defensiveness for its own sake. internal/SKIPPED-CONTROLS.md
// records two separate incidents in this repository where a control that could
// not run reported success, and names the shape precisely: "a guard that
// vanishes silently when it cannot run is worse than no guard, because the
// green tick is read as an answer." A gate stack that is half-built must
// therefore deny everything, and today it does: gates 4, 5, 6, 8, 9 and 10 are
// compiled in and GATE 11 IS NOT, so Decide refuses every target at gate 11.
// TestGate11StopsTheAdmissionChain records where the chain actually stops, so
// that fact is measured rather than assumed.
//
// ===========================================================================
// GATE 12 IS NOT IN ANY CHAIN, AND CANNOT BE PUT IN ONE
// ===========================================================================
//
// security.txt resolves a reporting channel and never grants permission
// (RFC 9116; plan/00-SPINE.md S7; plan/50-dast.md gate 12). Three things
// enforce that here:
//
//   - Gate12SecurityTxtReportingChannel appears in no chain in this file.
//   - registerInto REFUSES to register it, with a message saying why. A
//     future contributor's "just add it to the chain" does not compile past
//     the first run of the test suite.
//   - gateFunc's parameters are the four admission inputs and nothing else,
//     so no gate implementation can even receive a security.txt result.
//
// See the ReportingChannelOnly block in types.go for the full accounting,
// including what this does not close.
//
// ===========================================================================
// WHICH GATES A gateFunc MAY EXPRESS, AND WHICH ARE STRUCTURALLY ELSEWHERE
// ===========================================================================
//
// A gateFunc is `func(Target, Scope, Attestation, Clock) Ruling`. Three
// families of gate cannot be written as one, and for each the impossibility is
// enforced by registerInto rather than remembered:
//
//	Phase 0 (1–3)   build and packaging facts, not a target.
//	Gate 7          run initiation. Evaluated ONCE PER RUN, before any target
//	                exists; a function of the trigger event, the actor and the
//	                repository. Its pass is a precondition of the Attestation
//	                the admission chain consumes.
//	Phase 3 (13–17) per REQUEST: this hop, this redirect, this rate budget.
//	                They have their own chain type — requestChain in
//	                phase3_enforcement.go — so the separation is in the type
//	                system and not in the absence of a line.
//	Phase 4 (18–21) output and disclosure. Gate 21 wraps the chain rather than
//	                sitting in it.
//
// An unregistered gate and a FORGOTTEN gate are indistinguishable by
// inspection, which is why registerInto refuses each of these with a message
// naming where the gate actually lives, and why
// TestNoPhase3GateIsInAnAdmissionChain fails the build if a future edit
// "helpfully" adds one to a chain here.

package authz

import (
	"fmt"
	"time"
)

// ---------------------------------------------------------------------------
// Ruling — the pure function's output. It authorizes nothing.
// ---------------------------------------------------------------------------

// Ruling is what one gate, or one chain of gates, concluded.
//
// It is deliberately NOT called a Decision. A Decision (below) has an audit row
// behind it and can be turned into an Authorization; a Ruling cannot be turned
// into anything. Keeping the two words apart is what stops "the gate said yes"
// from being mistaken for "we may connect".
//
// The zero Ruling has OutcomeUnset, GateUnspecified and ReasonUnspecified.
// Permits() is false for it, and for every Ruling that this package did not
// mint through permit or refuse.
type Ruling struct {
	gate    GateID
	outcome Outcome
	reason  Reason
	detail  string
}

// permit mints an allowing ruling. Unexported: only a gate implementation
// inside internal/dast/authz can say that a gate is satisfied.
func permit(g GateID, r Reason, detail string) Ruling {
	return Ruling{gate: g, outcome: OutcomeAllow, reason: r, detail: detail}
}

// refuse mints a denying ruling.
func refuse(g GateID, r Reason, detail string) Ruling {
	return Ruling{gate: g, outcome: OutcomeDeny, reason: r, detail: detail}
}

// Gate returns the gate that produced the ruling.
func (r Ruling) Gate() GateID { return r.gate }

// Outcome returns the ruling's outcome. OutcomeUnset for a zero Ruling.
func (r Ruling) Outcome() Outcome { return r.outcome }

// Reason returns the validated gateNN.slug token.
func (r Ruling) Reason() Reason { return r.reason }

// Detail returns the Anvil-authored operator-facing detail.
func (r Ruling) Detail() string { return r.detail }

// Permits reports whether the ruling is a well-formed permit.
//
// Every one of these conditions has to hold, and any of them failing means
// refuse:
//
//   - the outcome is OutcomeAllow (OutcomeUnset is not);
//   - the gate is one of the 21;
//   - the reason is a valid gateNN.slug token;
//   - the reason names THE SAME GATE as the ruling. A ruling reported under
//     gate 10 whose reason says gate 4 is a gate that copied someone else's
//     conclusion, and the kernel does not act on it.
func (r Ruling) Permits() bool {
	if r.outcome != OutcomeAllow || !r.gate.Valid() {
		return false
	}
	named, err := r.reason.Gate()
	return err == nil && named == r.gate
}

// WellFormedDenial reports whether the ruling is a properly attributed denial.
// A ruling that is neither a well-formed permit nor a well-formed denial is a
// bug in a gate, and the chain converts it into an attributed refusal rather
// than passing it along.
func (r Ruling) WellFormedDenial() bool {
	if r.outcome != OutcomeDeny || !r.gate.Valid() {
		return false
	}
	named, err := r.reason.Gate()
	return err == nil && named == r.gate
}

// Err renders the ruling as an error, or nil if it permits.
func (r Ruling) Err() error {
	if r.Permits() {
		return nil
	}
	if r.outcome == OutcomeUnset {
		return fmt.Errorf("%w: %s produced a Ruling that neither permit nor refuse minted",
			ErrUnconstructed, r.gate)
	}
	return &GateFailure{Gate: r.gate, Reason: r.reason, Detail: r.detail, Err: ErrRefused}
}

// String renders the ruling for a log line.
func (r Ruling) String() string {
	out := r.outcome
	if out == OutcomeUnset {
		out = "unset"
	}
	return fmt.Sprintf("%s %s (%s): %s", r.gate, out, string(r.reason), r.detail)
}

// ---------------------------------------------------------------------------
// The gate registry and the chains
// ---------------------------------------------------------------------------

// gateFunc is the signature of every gate implementation in phases 1–3.
//
// THESE FOUR PARAMETERS ARE THE WHOLE OF A GATE'S WORLD. There is no context,
// no options struct, no io.Reader, no logger, and above all no security.txt
// result. plan/00-SPINE.md S7 requires the kernel to be a pure function of
// exactly (target, scope, attestation, clock), and gate 12 requires that the
// admission decision be structurally unable to see a security.txt result.
// Widening this signature is how both requirements would be lost, so it is
// declared here, in D.2's write scope, and nowhere else.
type gateFunc func(target Target, scope Scope, attestation Attestation, clock Clock) Ruling

// registry holds the compiled-in gate implementations. It is package-level and
// unexported: no package outside internal/dast/authz can install a gate, and
// nothing at all can install one at runtime from a config file.
var registry = map[GateID]gateFunc{}

// registerInto installs one gate implementation into a registry map, refusing
// every registration that would weaken the contract.
//
// It is separate from register so that the refusal paths are testable without
// mutating the package-level registry that D.4–D.7 populate from init.
func registerInto(m map[GateID]gateFunc, g GateID, fn gateFunc) error {
	if m == nil {
		return fmt.Errorf("authz: %w: nil registry", ErrRefused)
	}
	if !g.Valid() {
		return fmt.Errorf("authz: %w: %s is not one of the 21 gates", ErrRefused, g)
	}
	if fn == nil {
		return fmt.Errorf("authz: %w: %s was registered with a nil implementation, which "+
			"would panic at decision time instead of refusing", ErrRefused, g)
	}
	if g == Gate12SecurityTxtReportingChannel {
		return fmt.Errorf("authz: %w: %s (security.txt) cannot be registered as a gate "+
			"implementation. RFC 9116, plan/00-SPINE.md S7 and plan/50-dast.md gate 12 all "+
			"say the same thing: security.txt resolves a reporting channel and NEVER grants "+
			"permission. Its result is recorded in the audit log and is structurally "+
			"excluded from the admission decision's input type. Fetch it with D.5's "+
			"FetchSecurityTxt and write the result to the audit; do not put it in a chain",
			ErrRefused, g)
	}
	if g.Phase() == 0 {
		return fmt.Errorf("authz: %w: %s is a Phase 0 build-and-packaging gate. It is a "+
			"named function in phase0_build.go called from a build-time test, not a "+
			"per-decision gate, and it takes build facts rather than a target",
			ErrRefused, g)
	}
	if g.Phase() == 4 {
		return fmt.Errorf("authz: %w: %s is a Phase 4 output-and-disclosure gate. It does "+
			"not run per target and does not take (target, scope, attestation, clock)",
			ErrRefused, g)
	}
	if g == Gate7TriggerProvenance {
		return fmt.Errorf("authz: %w: %s is a Phase 1 RUN-INITIATION gate and cannot be "+
			"registered as a per-target gate implementation. plan/50-dast.md's gate table "+
			"puts it in Phase 1: it is evaluated ONCE PER RUN, before any target exists, and "+
			"it is a function of the trigger event, the actor and the repository — none of "+
			"which is a target, a scope, an attestation or a clock. Widening gateFunc to "+
			"carry them would break plan/00-SPINE.md S7's \"pure function of (target, scope, "+
			"attestation, clock)\", which is the property that makes the admission decision "+
			"auditable. Call CheckGate7TriggerProvenance from InitiateRun; its pass is a "+
			"precondition of the Attestation the admission chain consumes",
			ErrRefused, g)
	}
	if g.Phase() == 3 {
		return fmt.Errorf("authz: %w: %s is a Phase 3 PER-REQUEST enforcement gate and has "+
			"its own chain type. A gateFunc's world is one target; gates 13–17 are about "+
			"THIS request, THIS redirect hop and THIS rate budget, and a gateFunc cannot "+
			"express any of the three. Registering one here would not add a control, it "+
			"would silently move enforcement from per-request to per-target. Add it to "+
			"phase3_enforcement.go's requestChain, which the Governor runs on every "+
			"request", ErrRefused, g)
	}
	if _, dup := m[g]; dup {
		return fmt.Errorf("authz: %w: %s already has an implementation. Two implementations "+
			"of one gate means one of them is not being consulted, and which one is an "+
			"accident of init order", ErrRefused, g)
	}
	m[g] = fn
	return nil
}

// register is how phase1_run.go, phase2_admission.go and phase3_enforcement.go
// install their gates, from an init function in their own file.
//
// It PANICS on a bad registration rather than returning an error, because
// there is no correct way to continue: a process whose gate stack did not
// assemble must not run, and a returned error at init time has nowhere to go.
// The panic fires at process start, in every test binary that links the
// package, which is the earliest possible moment.
func register(g GateID, fn gateFunc) {
	if err := registerInto(registry, g, fn); err != nil {
		panic(err)
	}
}

// admissionChain is the ordered per-target admission decision.
//
// # What is absent, and why each absence is structural rather than remembered
//
// GATE 7 IS A PHASE 1 RUN-INITIATION GATE. plan/50-dast.md:1032's own table
// puts it there, and it is evaluated ONCE PER RUN, before any target exists.
// Trigger provenance is not a function of (target, scope, attestation, clock),
// so a gateFunc cannot express it, and widening gateFunc to carry it would
// break plan/00-SPINE.md S7's "pure function of (target, scope, attestation,
// clock)" — the property that makes the admission decision auditable at all.
// Gate 7 runs at run initiation (CheckGate7TriggerProvenance, called by
// InitiateRun), and its pass is a PRECONDITION of obtaining the Attestation
// this chain consumes: by the time admission runs, provenance has been checked
// or there is no run. registerInto refuses to register it, so the separation is
// enforced rather than described.
//
// GATE 12 IS ABSENT BY CONSTRUCTION and its absence is the enforcement, not a
// comment about it. security.txt resolves a reporting channel and never grants
// permission; registerInto refuses it too.
//
// GATES 13–17 ARE PER-REQUEST, not per-target. They have their own chain type
// (requestChain, phase3_enforcement.go), their own runner and their own
// registration rule: registerInto refuses a Phase 3 gate, so the separation is
// declared in the type system rather than implied by absence.
// TestNoPhase3GateIsInAnAdmissionChain is the negative control.
//
// Gates 18–21 are about output and disclosure, and gate 21 wraps this whole
// chain rather than sitting inside it.
//
// GATE 11 IS STILL HERE AND STILL HAS NO IMPLEMENTATION, and that is stated
// rather than hidden. robots.txt is a property of an ORIGIN AND A PATH, and a
// gateFunc receives no path, so D.5 implemented it as CheckGate11RobotsDeny and
// the Governor calls it per request. Its presence in this list with nothing
// registered means THE ADMISSION CHAIN REFUSES EVERY TARGET AT GATE 11 — a
// missing gate is a REFUSAL, never a skipped step.
// TestGate11StopsTheAdmissionChain records where the chain actually stops, so
// the fact is measured rather than assumed, and the orchestrator rules on where
// the robots policy should enter the kernel.
var admissionChain = []GateID{
	Gate4ScopeFile,
	Gate5Attestation,
	Gate6ModeDeclaration,
	Gate8Canonicalize,
	Gate9ResolveAndPin,
	Gate10ReservedRanges,
	Gate11RobotsDeny,
}

// revalidationChain is what gate 13 re-runs on EVERY request and EVERY redirect
// hop: SCOPE MEMBERSHIP, canonicalize, resolve-and-pin, reserved ranges.
//
// # Gate 4 is in this chain because gate 13 is a scope re-check
//
// plan/50-dast.md:1032's gate 13 row is "Re-validate scope on every request
// including every redirect hop", and research/20 says "re-validate SCOPE on
// every single request". Gates 8, 9 and 10 canonicalize, pin and screen
// reserved ranges; NOT ONE OF THEM ASKS WHETHER THE HOST IS IN SCOPE. A
// redirect to a host that is routable, non-reserved, on no deny list and in
// nobody's allow list passed {8,9,10} cleanly. Gate 4 is the allow-list match,
// so gate 4 is what "re-validate scope" means, and it belongs here.
//
// research/20 names the failure this exists to prevent — ZAP issue #2546, where
// scope was a job-level property rather than a per-request one — and calls it
// "the single most likely way Anvil escapes scope". D.6 calls Revalidate; it
// does not re-implement these four gates.
var revalidationChain = []GateID{
	Gate4ScopeFile,
	Gate8Canonicalize,
	Gate9ResolveAndPin,
	Gate10ReservedRanges,
}

// chain is an ordered list of gates plus the implementations to run them with.
type chain struct {
	name  string
	gates []GateID
	impls map[GateID]gateFunc
}

// runTraced executes the chain and returns ONE RULING PER GATE CONSULTED, in
// the order they were consulted, stopping at the first refusal.
//
// It returns the trace rather than a single ruling because gate 21 requires "an
// immutable audit of EVERY GATE DECISION". An earlier draft returned only the
// last permitting ruling, and Adjudicate wrote one row from it: seven gates
// consulted, one row recorded. D.3's critic named that, and the fix is here
// rather than in the audit writer, because a writer cannot record decisions the
// chain runner did not hand it.
//
// An EMPTY chain refuses, and the refusal is the trace's only element. "The
// list was empty so everything passed" is the vacuous-truth bug that a
// for-range loop produces for free.
func (c chain) runTraced(target Target, scope Scope, attestation Attestation, clock Clock) []Ruling {
	if len(c.gates) == 0 {
		return []Ruling{refuse(Gate21ImmutableAudit, ReasonGateNotRegistered,
			fmt.Sprintf("the %s chain is empty, and an empty chain permits nothing", c.name))}
	}
	trace := make([]Ruling, 0, len(c.gates))
	for _, g := range c.gates {
		fn, ok := c.impls[g]
		if !ok || fn == nil {
			return append(trace, refuse(g, ReasonGateNotRegistered, fmt.Sprintf(
				"%s has no implementation compiled in, so the %s chain cannot complete. "+
					"A gate with no implementation is a REFUSAL, never a skipped step",
				g, c.name)))
		}
		r := fn(target, scope, attestation, clock)
		if r.Gate() != g {
			return append(trace, refuse(g, ReasonGateIdentityMismatch, fmt.Sprintf(
				"the implementation registered for %s returned a ruling attributed to %s; "+
					"the kernel does not act on a ruling whose author is unclear",
				g, r.Gate())))
		}
		if r.Permits() {
			trace = append(trace, r)
			continue
		}
		if r.WellFormedDenial() {
			return append(trace, r)
		}
		return append(trace, refuse(g, ReasonGateIdentityMismatch, fmt.Sprintf(
			"%s returned a ruling that is neither a well-formed permit nor a well-formed "+
				"denial (outcome=%q reason=%q); a malformed ruling refuses",
			g, string(r.Outcome()), string(r.Reason()))))
	}
	return trace
}

// run executes the chain and reduces the trace to one ruling: the refusal if
// there is one, otherwise the last gate's permit.
func (c chain) run(target Target, scope Scope, attestation Attestation, clock Clock) Ruling {
	return lastRuling(c.runTraced(target, scope, attestation, clock))
}

// lastRuling reduces a trace to the ruling that decides it.
//
// An EMPTY trace is a REFUSAL. A caller holding no rulings consulted no gates,
// and "no gate objected" is not "every gate agreed".
func lastRuling(trace []Ruling) Ruling {
	if len(trace) == 0 {
		return refuse(Gate21ImmutableAudit, ReasonGateNotRegistered,
			"the decision trace is empty, so no gate was consulted. An empty trace is a "+
				"refusal, never a silent pass")
	}
	for _, r := range trace {
		if !r.Permits() {
			return r
		}
	}
	return trace[len(trace)-1]
}

// ---------------------------------------------------------------------------
// Decide — plan/00-SPINE.md S7's pure function
// ---------------------------------------------------------------------------

// Decide is the authorization kernel's pure decision function.
//
// plan/50-dast.md D.2 writes this contract as
// `Decision(target, scope, attestation, clock) (Allow|Deny, Reason)`. The
// function is named Decide here because Decision is the name of the AUDITED
// result type below, and having a function and a type with the same name in
// one package is not expressible in Go. D.5's constraint — "Gate 12's
// SecurityTxtResult type must not appear anywhere in the `Decision(...)`
// function signature or any type it transitively references" — applies to this
// function, to gateFunc, and to Adjudicate.
//
// It reads nothing, writes nothing, and does not consult the wall clock. Given
// the same four values it returns the same Ruling forever, which is what makes
// the audit row a reproducible record of a decision rather than a note about
// one.
//
// A permitting Ruling from this function is NOT permission to open a socket.
// Only Adjudicate can produce that, and only after the audit write lands.
func Decide(target Target, scope Scope, attestation Attestation, clock Clock) Ruling {
	return decideWith(admissionRunner(), target, scope, attestation, clock)
}

// admissionRunner binds the compiled-in admission chain to the compiled-in
// registry. It is a function rather than a package-level value so that a gate
// registered from an init in another file is visible however the init order
// falls out.
func admissionRunner() chain {
	return chain{name: "admission", gates: admissionChain, impls: registry}
}

// revalidationRunner binds gate 13's three-gate chain to the same registry.
func revalidationRunner() chain {
	return chain{name: "revalidation", gates: revalidationChain, impls: registry}
}

// decideWith is Decide with the chain supplied.
//
// The seam is unexported and exists so that this package's own tests can drive
// a fully-populated chain while gates 4–11 are still unimplemented. No package
// outside internal/dast/authz can reach it, so no caller can substitute a
// shorter chain for the real one; and D.4–D.7 install gates through register
// rather than by calling this.
func decideWith(ch chain, target Target, scope Scope, attestation Attestation, clock Clock) Ruling {
	return lastRuling(decideTracedWith(ch, target, scope, attestation, clock))
}

// decideTracedWith is decideWith returning one ruling per gate consulted.
//
// A precondition refusal is a one-element trace: the kernel's structural floor
// is itself a decision, it is attributed to the gate whose input was malformed,
// and gate 21 records it like any other.
func decideTracedWith(ch chain, target Target, scope Scope, attestation Attestation, clock Clock) []Ruling {
	if r, ok := checkKernelPreconditions(target, scope, attestation, clock); !ok {
		return []Ruling{r}
	}
	return ch.runTraced(target, scope, attestation, clock)
}

// Revalidate re-runs gates 8, 9 and 10 for gate 13, which must do so on every
// request and every redirect hop.
//
// It performs the same preconditions as Decide, so a redirect hop that
// produced an unconstructed Target — the shape a hand-parsed Location header
// takes when parsing half-failed — is refused rather than probed.
func Revalidate(target Target, scope Scope, attestation Attestation, clock Clock) Ruling {
	return decideWith(revalidationRunner(), target, scope, attestation, clock)
}

// checkKernelPreconditions is the kernel's own structural floor, run before
// any gate implementation sees the inputs.
//
// It answers only questions the KERNEL owns: did each of the four inputs come
// from a constructor in this package, and is the attestation bound to this
// exact scope. It deliberately does NOT check expiry, authority, trigger
// provenance or scope membership — those are gates 4–7, they belong to D.4,
// and a second implementation of them here would be a second implementation
// that can disagree.
//
// The scope/attestation binding is checked here anyway, and the duplication is
// deliberate: it is the invariant that makes gate 21's audit key coherent (the
// row is keyed to an attestation ID and a scope hash, and a row keyed to an
// attestation that does not cover that scope is a row that records nothing
// true), and it is cheap.
//
// Each refusal is attributed to the gate whose input was malformed, so an
// operator reading the audit sees "gate 8 got a target nobody canonicalized"
// rather than "the kernel said no".
func checkKernelPreconditions(target Target, scope Scope, attestation Attestation, clock Clock) (Ruling, bool) {
	if !scope.Constructed() {
		return refuse(Gate4ScopeFile, ReasonScopeUnconstructed,
			"the Scope was not built by NewScope. A zero Scope, or one built as a composite "+
				"literal in another package, has no entries and no hash and permits nothing"), false
	}
	if !attestation.Constructed() {
		return refuse(Gate5Attestation, ReasonAttestationUnconstructed,
			"the Attestation was not built by NewAttestation. Gate 5 refuses to probe "+
				"without a live attestation, and a value nobody minted is not one"), false
	}
	if !clock.Valid() {
		return refuse(Gate5Attestation, ReasonClockUnconstructed,
			"the Clock was not built by NewClock. Every expiry check in the gate stack is "+
				"measured against it, so an unset clock would silently make attestations "+
				"look eternal or expired depending on the comparison's direction"), false
	}
	if !target.Constructed() {
		return refuse(Gate8Canonicalize, ReasonTargetUnconstructed,
			"the Target was not built by NewTarget, so it carries no canonical form and no "+
				"pinned address, and gates 8 and 9 have nothing to match on"), false
	}
	if !attestation.CoversScope(scope) {
		return refuse(Gate5Attestation, ReasonScopeAttestationMismatch, fmt.Sprintf(
			"the attestation is bound to scope hash %s and this scope hashes to %s. "+
				"Gate 5 binds the attestation to the scope hash precisely so that editing "+
				"the scope file invalidates it",
			string(attestation.ScopeHash()), string(scope.Hash()))), false
	}
	return Ruling{}, true
}

// ---------------------------------------------------------------------------
// Gate 21 — the audit row IS the decision
// ---------------------------------------------------------------------------

// AuditSeq is the append-only sequence number a sink returns for a row it
// durably wrote.
//
// ZERO IS NOT A SEQUENCE NUMBER. A sink that returns (0, nil) did not write
// anything — that is what a stub, a mock left in by accident, or a
// short-circuited implementation returns — and Adjudicate treats it as a
// failed write. Real sinks number from 1.
type AuditSeq uint64

// GateRecord is one row of gate 21's immutable audit log.
//
// Gate 21: "Every allow/deny/redirect-refusal/circuit-breaker-trip logged,
// keyed to attestation ID + scope hash". Both keys are required fields here,
// and Validate refuses a record missing either, because a row that cannot be
// joined back to who authorised what is not an audit row.
type GateRecord struct {
	// Gate is the gate that ruled.
	Gate GateID
	// Outcome is allow or deny. OutcomeUnset is refused.
	Outcome Outcome
	// Reason is the validated gateNN.slug token, naming the same gate.
	Reason Reason
	// Detail is Anvil-authored text. It is never assembled from bytes that
	// originated outside Anvil.
	Detail string
	// AttestationID is the first half of gate 21's key.
	AttestationID AttestationID
	// ScopeHash is the second half.
	ScopeHash ScopeHash
	// Mode is the run's irreversible mode (gate 6).
	Mode Mode
	// Target is the human-readable target the ruling was about, rendered by
	// Target.String, including the pinned address.
	Target string
	// At is the instant from the Clock the decision was made against — not
	// wall-clock time read inside the sink, which would make the row
	// disagree with the decision it records.
	At time.Time
}

// Validate reports whether the record can be written as an audit row.
func (r GateRecord) Validate() error {
	if !r.Gate.Valid() {
		return fmt.Errorf("audit: %w: record names %s", ErrRefused, r.Gate)
	}
	if !r.Outcome.Valid() {
		return fmt.Errorf("audit: %w: record for %s has outcome %q, which is neither %q nor %q",
			ErrRefused, r.Gate, string(r.Outcome), OutcomeAllow, OutcomeDeny)
	}
	named, err := r.Reason.Gate()
	if err != nil {
		return fmt.Errorf("audit: %s: %w", r.Gate, err)
	}
	if named != r.Gate {
		return fmt.Errorf("audit: %w: record is attributed to %s but its reason names %s",
			ErrRefused, r.Gate, named)
	}
	if err := r.AttestationID.Validate(); err != nil {
		return fmt.Errorf("audit: %s: %w", r.Gate, err)
	}
	if err := r.ScopeHash.Validate(); err != nil {
		return fmt.Errorf("audit: %s: %w", r.Gate, err)
	}
	if !r.Mode.Valid() {
		return fmt.Errorf("audit: %w: record for %s has mode %q; gate 6 has no default and "+
			"no `auto`", ErrRefused, r.Gate, string(r.Mode))
	}
	if r.Target == "" {
		return fmt.Errorf("audit: %w: record for %s names no target", ErrRefused, r.Gate)
	}
	if r.At.IsZero() {
		return fmt.Errorf("audit: %w: record for %s has no instant", ErrRefused, r.Gate)
	}
	return nil
}

// AuditSink is the append-only writer gate 21 requires. D.7 implements it over
// the SQLite record store.
//
// It returns the sequence number of the row it wrote. Returning (0, nil) is
// treated as a failed write; see AuditSeq.
//
// This interface is a parameter of Adjudicate and is NOT a field of any type
// in Decide's input closure. That is not an accident of layout: an interface
// reachable from the admission input would be exactly the extension point
// gate 12 forbids.
type AuditSink interface {
	WriteGateDecision(GateRecord) (AuditSeq, error)
}

// grant is the unexported proof that a decision was both made and durably
// audited. It is the same idiom as internal/record/sealing.go's seal
// provenance: an unexported pointer that only this package can set, so a
// composite literal in any other package cannot forge one.
type grant struct {
	rec    GateRecord
	seq    AuditSeq
	target Target
	mode   Mode
}

// ok reports whether the grant is a real one. It is nil-safe, because every
// caller reaches it through a possibly-nil pointer on a zero-value Decision or
// Authorization.
func (g *grant) ok() bool {
	return g != nil &&
		g.seq > 0 &&
		g.rec.Outcome == OutcomeAllow &&
		g.rec.Validate() == nil &&
		g.target.Constructed() &&
		g.mode.Valid()
}

// ---------------------------------------------------------------------------
// Decision and Adjudicate
// ---------------------------------------------------------------------------

// Decision is a Ruling that has been durably audited.
//
// The zero Decision is a refusal: grant is nil, so Allowed() is false. So is a
// Decision built as a composite literal in any other package, for the same
// reason.
type Decision struct {
	ruling   Ruling
	grant    *grant
	auditErr error
}

// Allowed reports whether the decision permits the target.
//
// It is true only when the pure ruling permitted AND the audit row was
// durably written AND the grant it produced is internally consistent. There is
// no path to true that skips any of the three.
//
// # Three layers, and why none of them is deleted as subsumed
//
// On the path Adjudicate takes, a denial returns a Decision with a nil grant,
// so grant.ok() alone already refuses; `d.ruling.Permits()` here and
// `g.rec.Outcome == OutcomeAllow` inside grant.ok() add nothing to THAT path.
// The package's standard is that a layer which cannot be the only thing
// refusing is deleted rather than commented — Cap.Lower and
// CheckGate4ScopeFile both lost a branch to it.
//
// These two are kept because they are NOT subsumed for a Decision this package
// builds any other way, and this package is where Decisions are built:
// TestDecisionLayersEachRefuseOnTheirOwn constructs a Decision with a valid
// grant and a DENYING ruling (only this line refuses it) and one with a
// permitting ruling and a grant whose recorded outcome is deny (only the check
// inside grant.ok refuses it), and asserts each is not allowed. Mutating either
// layer turns that test red.
func (d Decision) Allowed() bool { return d.grant.ok() && d.ruling.Permits() }

// Ruling returns the underlying pure ruling.
func (d Decision) Ruling() Ruling { return d.ruling }

// Reason returns the ruling's reason token.
func (d Decision) Reason() Reason { return d.ruling.Reason() }

// Gate returns the gate the decision is attributed to.
func (d Decision) Gate() GateID { return d.ruling.Gate() }

// AuditSeq returns the sequence number of the row that made this decision
// real, or an error if there is none.
func (d Decision) AuditSeq() (AuditSeq, error) {
	if !d.grant.ok() {
		return 0, fmt.Errorf("authz: %w: this decision has no audit row behind it", ErrRefused)
	}
	return d.grant.seq, nil
}

// Err returns why the decision refused, or nil if it allowed.
func (d Decision) Err() error {
	if d.Allowed() {
		return nil
	}
	if d.auditErr != nil {
		return d.auditErr
	}
	return d.ruling.Err()
}

// Authorization returns the token the egress choke point demands, or an error
// if the decision did not allow.
func (d Decision) Authorization() (Authorization, error) {
	if !d.Allowed() {
		return Authorization{}, fmt.Errorf("authz: %w", d.Err())
	}
	return Authorization{grant: d.grant}, nil
}

// Adjudicate is the ONLY mint point for permission anywhere in Anvil.
//
// It runs the pure decision, writes ONE AUDIT ROW PER GATE DECISION — allow or
// deny, gate 21 requires both — and mints an allowing Decision only if every
// one of those writes returned a real sequence number and no error.
//
// # Gate 1 is a precondition, not a decoration
//
// enablement is the DastEnablement EnableDAST minted. Gate 1 requires an
// explicit, non-defaulted write before DAST is on; D.3's critic reached
// Adjudicate without ever calling EnableDAST, which made that write decorative.
// It is now the first thing checked, and the zero DastEnablement — the value a
// caller who never called EnableDAST holds — refuses. The enablement must also
// cover THIS scope and THIS attestation: an enablement minted against another
// scope is not permission to probe this one.
//
// # Gate 21 gets a row per gate, not a row per adjudication
//
// plan/50-dast.md gate 21 is "immutable audit of every gate decision". An
// earlier draft wrote one row, built from the chain's last permitting ruling:
// seven gates consulted, one gate recorded, and the six that agreed were
// invisible. The chain now returns a trace and every ruling in it becomes a
// row. If ANY row fails to validate or fails to write, the whole decision
// refuses — a partially recorded decision is not a recorded decision.
//
// # The order of operations is load-bearing
//
//  1. Refuse a nil sink before anything else. No sink means no audit, and no
//     audit means no allow. This is checked first so that the refusal is
//     honest about what happened rather than reporting a gate refusal that
//     never ran.
//  2. Check gate 1's enablement. Nothing below matters if DAST is not on.
//  3. Run the chain, traced. Pure, and its result does not depend on anything
//     below.
//  4. Build and validate a record for EVERY ruling. An unkeyable record
//     refuses: gate 21 keys on attestation ID plus scope hash, and a row that
//     cannot be keyed cannot be joined back to who authorised what.
//  5. Write them all. THE WRITES HAPPEN FOR DENIALS TOO. Gate 21 says every
//     allow and every deny is logged, and a deny that vanishes is how a run
//     that was refused a thousand times looks like a run that was never
//     attempted.
//  6. Only now branch on the deciding ruling. A permitting ruling whose write
//     failed returns a REFUSING Decision carrying the write error.
//
// There is no (Decision, error) return, on purpose. `d, _ := Adjudicate(...)`
// is a line someone writes, and it must not be able to discard the half that
// says no. The error is inside the Decision, and Allowed() is false whenever
// it is set.
func Adjudicate(sink AuditSink, enablement DastEnablement, target Target, scope Scope, attestation Attestation, clock Clock) Decision {
	return adjudicateWith(sink, enablement, admissionRunner(), target, scope, attestation, clock)
}

// adjudicateWith is Adjudicate with the chain supplied. See decideWith for why
// the seam exists and why it is unexported.
func adjudicateWith(sink AuditSink, enablement DastEnablement, ch chain, target Target, scope Scope, attestation Attestation, clock Clock) Decision {
	if sink == nil {
		return Decision{
			ruling: refuse(Gate21ImmutableAudit, ReasonAuditSinkMissing,
				"no audit sink was supplied. Gate 21 makes the audit write part of the "+
					"decision, so a decision with nowhere to be recorded is a refusal"),
			auditErr: ErrAuditWriteFailed,
		}
	}
	if r, ok := checkEnablement(enablement, scope, attestation); !ok {
		return Decision{ruling: r}
	}

	trace := decideTracedWith(ch, target, scope, attestation, clock)
	ruling := lastRuling(trace)

	// Scope.Mode returns ModeUnset alongside its error, and GateRecord.Validate
	// refuses a row whose mode is unset, so the error needs no branch of its
	// own here — one would be a second statement of what the value already is.
	mode, _ := scope.Mode()
	targetStr := target.String()

	rows := make([]GateRecord, 0, len(trace))
	for _, r := range trace {
		rec := GateRecord{
			Gate:          r.Gate(),
			Outcome:       r.Outcome(),
			Reason:        r.Reason(),
			Detail:        r.Detail(),
			AttestationID: attestation.ID(),
			ScopeHash:     scope.Hash(),
			Mode:          mode,
			Target:        targetStr,
			At:            clock.Instant(),
		}
		if err := rec.Validate(); err != nil {
			return Decision{
				ruling: refuse(Gate21ImmutableAudit, ReasonAuditKeyIncomplete, fmt.Sprintf(
					"%s's decision could not be recorded: %v. Gate 21 keys every row on "+
						"the attestation ID and the scope hash; a decision that cannot "+
						"be keyed is not allowed", r.Gate(), err)),
				auditErr: fmt.Errorf("%w: %w", ErrAuditWriteFailed, err),
			}
		}
		rows = append(rows, rec)
	}
	// There is no `if len(rows) == 0` branch. decideTracedWith returns either a
	// one-element precondition refusal or chain.runTraced, which returns a
	// refusal for an empty chain and at least one ruling otherwise — so the
	// trace is never empty, and if it somehow were, lastRuling REFUSES an empty
	// trace and the decision below carries no grant. A branch that can never be
	// the only thing refusing anything is not kept here.
	//
	// The rows are written in chain order and their sequences must strictly
	// advance. D.7's GateAudit.Record makes the same check across a run; this
	// one is within a single adjudication, which is the part Adjudicate can
	// see. A sink that rewound or overwrote a row is a sink whose earlier rows
	// cannot be trusted, and gate 21 asks for an IMMUTABLE audit.
	var lastSeq AuditSeq
	var lastRec GateRecord
	for _, rec := range rows {
		seq, err := sink.WriteGateDecision(rec)
		switch {
		case err == nil && seq > 0 && seq <= lastSeq:
			return Decision{
				ruling: refuse(Gate21ImmutableAudit, ReasonAuditNotAppendOnly, fmt.Sprintf(
					"the audit sequence did not advance: %s was written at %d and the "+
						"previous row was at %d. Gate 21 requires an immutable audit, "+
						"and a log that can go backwards is a log whose earlier rows "+
						"cannot be trusted", rec.Gate, seq, lastSeq)),
				auditErr: ErrAuditWriteFailed,
			}
		case err != nil:
			return Decision{
				ruling: refuse(Gate21ImmutableAudit, ReasonAuditWriteFailed, fmt.Sprintf(
					"%s's audit write failed (%v), so this decision is not allowed "+
						"regardless of what %s ruled", rec.Gate, err, ruling.Gate())),
				auditErr: fmt.Errorf("%w: %w", ErrAuditWriteFailed, err),
			}
		case seq == 0:
			return Decision{
				ruling: refuse(Gate21ImmutableAudit, ReasonAuditWriteFailed, fmt.Sprintf(
					"the audit sink returned sequence 0 with no error for %s, which is "+
						"what a stub or a short-circuited implementation returns; a row "+
						"that was not written cannot make a decision allowed", rec.Gate)),
				auditErr: ErrAuditWriteFailed,
			}
		}
		lastSeq, lastRec = seq, rec
	}

	if !ruling.Permits() {
		// Audited denial: every row is written and the decision carries no
		// grant.
		return Decision{ruling: ruling}
	}
	return Decision{
		ruling: ruling,
		grant:  &grant{rec: lastRec, seq: lastSeq, target: target, mode: lastRec.Mode},
	}
}

// checkEnablement is gate 1 at adjudication time.
//
// D.3's critic reached Adjudicate without ever calling EnableDAST, so gate 1's
// "explicit non-defaulted write" authorised nothing and prevented nothing. It
// is a precondition now, and the zero DastEnablement — which is what a caller
// who never called EnableDAST holds, and what encoding/json produces, because
// no decoder can write an unexported field — refuses.
//
// The binding checks matter as much as the enabled bit. An enablement is minted
// against one scope hash and one attestation ID; carrying it over to a
// different scope would make gate 1 a one-time formality rather than a
// statement about this run.
func checkEnablement(e DastEnablement, scope Scope, attestation Attestation) (Ruling, bool) {
	if !e.Enabled() {
		return refuse(Gate1DastShipsDisabled, ReasonDastNotEnabled,
			"DAST is not enabled. Gate 1 requires an explicit, non-defaulted write, and the "+
				"only thing that produces one is EnableDAST — which checks the artifact, "+
				"the mode declaration, the scope and the attestation before it will mint "+
				"one. A zero DastEnablement is the value a caller who never called it "+
				"holds, and it authorizes nothing"), false
	}
	// There is deliberately no separate `if !scope.Constructed()` branch. An
	// enabled DastEnablement carries a scopeHash that passed Validate, and an
	// unconstructed Scope hashes to the empty string, so the comparison below
	// always fires first. A mutation run confirmed the branch could never be
	// the only thing refusing anything; it is gone rather than commented, the
	// same way Cap.Lower and CheckGate4ScopeFile lost theirs.
	if e.scopeHash != scope.Hash() {
		return refuse(Gate1DastShipsDisabled, ReasonEnablementWrongScope, fmt.Sprintf(
			"DAST was enabled for scope hash %s and this decision is about scope hash %s. "+
				"An enablement is minted for one scope; reusing it against another is how "+
				"an operator's authorisation for one engagement becomes authorisation for "+
				"the next one", string(e.scopeHash), string(scope.Hash()))), false
	}
	if e.attestID != attestation.ID() {
		return refuse(Gate1DastShipsDisabled, ReasonEnablementWrongScope, fmt.Sprintf(
			"DAST was enabled under attestation %s and this decision is being made under "+
				"attestation %s", string(e.attestID), string(attestation.ID()))), false
	}
	return Ruling{}, true
}

// ---------------------------------------------------------------------------
// Authorization — gate 3's runtime half
// ---------------------------------------------------------------------------

// Authorization is the token the egress choke point requires before it will
// construct a socket.
//
// It carries an unexported pointer to the grant Adjudicate minted. A composite
// literal in any other package cannot set that field — a compile error, not a
// lint — so the only Authorization that exists anywhere in Anvil is one that
// came from a Decision that came from an audited allow. The zero value carries
// nil and authorizes nothing.
//
// It is a value type and is safe to copy. Copying it copies the pointer, which
// is the intent: two copies of one authorization are the same authorization,
// keyed to the same audit row.
type Authorization struct {
	grant *grant
}

// Valid reports whether the token is real.
func (a Authorization) Valid() bool { return a.grant.ok() }

// Target returns the exact target this authorization covers, pinned address
// and all.
func (a Authorization) Target() (Target, error) {
	if !a.Valid() {
		return Target{}, fmt.Errorf("authz: %w: authorization token was not minted by "+
			"Adjudicate", ErrUnconstructed)
	}
	return a.grant.target, nil
}

// Mode returns the run mode the authorization was granted under.
func (a Authorization) Mode() (Mode, error) {
	if !a.Valid() {
		return ModeUnset, fmt.Errorf("authz: %w", ErrUnconstructed)
	}
	return a.grant.mode, nil
}

// AttestationID returns the first half of the audit key this authorization
// hangs from.
func (a Authorization) AttestationID() (AttestationID, error) {
	if !a.Valid() {
		return "", fmt.Errorf("authz: %w", ErrUnconstructed)
	}
	return a.grant.rec.AttestationID, nil
}

// ScopeHash returns the second half of the audit key.
func (a Authorization) ScopeHash() (ScopeHash, error) {
	if !a.Valid() {
		return "", fmt.Errorf("authz: %w", ErrUnconstructed)
	}
	return a.grant.rec.ScopeHash, nil
}

// AuditSeq returns the audit row this authorization rests on.
func (a Authorization) AuditSeq() (AuditSeq, error) {
	if !a.Valid() {
		return 0, fmt.Errorf("authz: %w", ErrUnconstructed)
	}
	return a.grant.seq, nil
}

// RequireAuthorization is gate 3's runtime half: the check the egress choke
// point makes immediately before constructing a socket.
//
// It refuses unless the token is real AND names EXACTLY this target — same
// scheme, same canonical host, same port, and the same PINNED ADDRESS. The
// pinned-address comparison is what makes gate 9's "never re-resolve between
// check and connect" enforceable rather than aspirational: an authorization
// for example.com pinned to 93.0.2.1 does not authorize a connection to
// example.com pinned to 169.254.169.254, even though the hostname matches.
//
// Target is comparable (strings, a uint16, a netip.Addr and a bool), so the
// comparison is a single ==. If a future field makes Target incomparable this
// stops compiling, which is the correct outcome: the comparison is the check.
func RequireAuthorization(auth Authorization, target Target) error {
	if !target.Constructed() {
		return fmt.Errorf("authz: %w: the egress choke point was handed a Target that "+
			"NewTarget never built", ErrUnconstructed)
	}
	if !auth.Valid() {
		return fmt.Errorf("authz: %w: no valid authorization for %s. Every socket in Anvil "+
			"is constructed by the kernel and only against an Authorization that "+
			"Adjudicate minted; construct one with Adjudicate rather than dialling "+
			"directly (gate 3)", ErrRefused, target)
	}
	if auth.grant.target != target {
		return fmt.Errorf("authz: %w: the authorization covers %s and the connection is to "+
			"%s. A cross-target reuse of a token is how a redirect escapes scope, which is "+
			"exactly the failure gates 9 and 13 exist to prevent",
			ErrRefused, auth.grant.target, target)
	}
	return nil
}
