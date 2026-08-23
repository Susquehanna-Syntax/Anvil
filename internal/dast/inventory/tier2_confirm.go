// D.22 — Tier 2 confirmation: merge the Tier 0-2 inventories into ONE union of
// endpoints, and promote a candidate to `confirmed` only on a real observation
// Anvil made through the kernel.
//
// # Both sides of endpoint_coverage are decided here
//
// plan/50-dast.md:1152 defines endpoint_coverage as confirmed-probed endpoints
// over the union of the Tier 0-2 inventory, and says in bold "Never a raw
// request count." This file computes both halves, and both halves can be
// corrupted in opposite directions:
//
//	THE NUMERATOR inflates when a candidate is promoted on weak evidence. Every
//	incentive in a metric points here, so it is the half people watch. The
//	answer is that exactly one thing in this file writes
//	ConfirmationConfirmed — confirmationFor — and it reads a single enumerated
//	outcome that only observeEndpoint can produce, from a status code the
//	target actually returned to a kernel-admitted request. The inbound
//	Confirmation on a merged route is DISCARDED and never read: a caller
//	handing back a route that already says "confirmed" is exactly how an
//	unprobed endpoint reaches the numerator.
//
//	THE DENOMINATOR inflates when one endpoint found by three routes becomes
//	three rows. Nobody investigates that, because it makes coverage look WORSE
//	— and the number quietly stops meaning what it says. The answer is that the
//	union is keyed on the address a probe reaches, method plus canonical path,
//	and the path is canonicalized by D.20's canonicalizePattern — the ONE
//	canonicalizer this package has — rather than by a second one here that
//	could disagree with it. A merge is recorded as a MergeNote and never as a
//	RefusalDuplicateRoute, because that reason is per-operation and would raise
//	the denominator floor for an endpoint that was already counted.
//
// # Why the unit of the union is (method, path) and not (method, path, operation)
//
// Route.Key() includes the operation, which is right WITHIN a tier: an OpenAPI
// operationId and a GraphQL root field name distinguish two things a document
// declared at one path. It is wrong for THIS union, for a reason that is about
// confirmation rather than taste: a probe addresses an ADDRESS. There is no
// request that confirms "the listUsers operation" separately from "GET /users",
// and a GraphQL server exposing forty root fields on POST /graphql answers one
// address. The numerator counts endpoints Anvil observed, so the denominator
// must count things that could have been observed, or the fraction is over two
// different units. The operations are not lost — MergedEndpoint.Operations()
// carries every one, and ConfirmResult.OperationCount() reports the second
// number beside the first.
//
// # Provenance and confirmation are independent axes
//
// Confirming a static_extraction candidate does not make it a runtime_spec
// endpoint. A MergedEndpoint carries a SET of provenances, one per route that
// contributed it, and confirmation is a property of the endpoint rather than
// of any contributor. ConfirmResult.Routes() re-stamps each contributing route
// with the endpoint's confirmation THROUGH NewRoute while carrying that
// route's own provenance, trust, operation, params and servedAt across
// unchanged. D.26 aggregates both axes.
//
// # A confirmation that cannot be traced to a specific observation is not one
//
// Every confirmed endpoint carries an Observation: the status code, the gate-21
// audit sequence the probe was admitted under, the instant, the technique, and
// the CONCRETE path that was actually requested. Observation has no exported
// fields and one unexported constructor in this file, so no caller can mint
// one. AssertEveryConfirmationHasEvidence sweeps the result and fails if a
// confirmation exists without one.
//
// Sources: plan/50-dast.md D.22 (lines 709-737) and the Coverage Reporting
// Contract (lines 1142-1160); research/22-attack-surface-discovery.md line 339
// ("promote to confirmed only on a non-404 response") and Risk #4 ("more
// endpoints can mean less coverage" — the phpBB regression from timeout
// exhaustion), which is what ProbeBudget and AssertBudgetSufficed exist for.
package inventory

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/Susquehanna-Syntax/Anvil/internal/dast/authz"
	"github.com/Susquehanna-Syntax/Anvil/internal/record"
)

// ---------------------------------------------------------------------------
// Sentinel errors
// ---------------------------------------------------------------------------

var (
	// ErrNoEndpointProber is returned when confirmation was asked for and no
	// egress seam is wired. It is an error and not an empty numerator: a run
	// that confirmed nothing because nothing could leave the process must not
	// be reportable as a run that found nothing to confirm.
	ErrNoEndpointProber = errors.New("inventory: no EndpointProber is wired, so no candidate " +
		"can be confirmed and endpoint_coverage's numerator would describe Anvil rather " +
		"than the target")

	// ErrProbeBudgetExhausted is what AssertBudgetSufficed returns when the
	// configured per-target probe budget ran out before every probeable
	// endpoint had been attempted. It names research/22's Risk #4 directly:
	// a larger candidate list producing a smaller confirmed count is a
	// coverage REGRESSION that looks like a coverage measurement.
	ErrProbeBudgetExhausted = errors.New("inventory: the per-target probe budget was exhausted " +
		"before every probeable endpoint was attempted, so endpoint_coverage computed over " +
		"this result is a FLOOR and not a measurement")

	// ErrNothingMerged is what AssertNotSilentlyEmpty returns when no tier
	// contributed a single route. An empty union is a denominator of zero,
	// and a denominator of zero is the shape every "100% covered" report is
	// made of.
	ErrNothingMerged = errors.New("inventory: the merge received no routes from any tier; " +
		"an empty Tier 0-2 union describes the handoff, not the target's surface")

	// ErrConfirmationWithoutEvidence is what AssertEveryConfirmationHasEvidence
	// returns. It exists so the claim "a confirmation is traceable to one
	// observation" is checked rather than asserted.
	ErrConfirmationWithoutEvidence = errors.New("inventory: an endpoint is marked confirmed " +
		"and carries no observation")
)

// ---------------------------------------------------------------------------
// Coded bounds
// ---------------------------------------------------------------------------

const (
	// maxEndpointsPerMerge bounds the union. Every input tier already has its
	// own coded bound; this one is the backstop for a caller that concatenates
	// several of them.
	maxEndpointsPerMerge = 20000

	// maxProbeBudget bounds ConfirmConfig.ProbeBudget. The budget is operator
	// configuration and the plan requires it to be config rather than
	// hard-coded, so this is a sanity ceiling and not the budget itself. The
	// kernel's own gate 14 volume cap applies independently and may bite
	// first; whichever refuses first is the one that refuses.
	maxProbeBudget = 100000

	// maxOperationsPerEndpoint bounds how many operation names one merged
	// endpoint records. A GraphQL schema with a hundred thousand root fields
	// is a resource-exhaustion probe pointed back at Anvil.
	maxOperationsPerEndpoint = 4096

	// maxContributorsPerEndpoint bounds how many source routes one endpoint
	// records.
	maxContributorsPerEndpoint = 4096

	// maxStatusCode and minStatusCode bound what counts as an HTTP status. A
	// prober that returns 0 is a prober that returned nothing, and 0 is
	// non-404 — so this bound is the difference between "no answer" and a
	// confirmation.
	minStatusCode = 100
	maxStatusCode = 599
)

// ---------------------------------------------------------------------------
// ConfirmOutcome — what happened to one endpoint, with no default
// ---------------------------------------------------------------------------

// ConfirmOutcome is why an endpoint ended up confirmed or still a candidate.
//
// It is an enum and not a bool because "Anvil asked and the target said 404"
// and "Anvil never asked" are the same bool and completely different facts.
// The first is a statement about the target; the second is a statement about
// Anvil, and only the second means the coverage number is a floor.
type ConfirmOutcome string

const (
	// ConfirmOutcomeUnset is the zero value and names nothing. It does not
	// confirm — FAIL CLOSED: a Go zero value must never mean "permitted", and
	// here "permitted" means "counted in the numerator".
	ConfirmOutcomeUnset ConfirmOutcome = ""

	// ConfirmOutcomeObservedNon404: Anvil issued a kernel-admitted request to
	// this endpoint and the target answered with something other than 404.
	// THE ONLY OUTCOME THAT CONFIRMS.
	//
	// The status code itself is recorded on the Observation and is not folded
	// away, because plan/50-dast.md D.22's Forbidden actions require it: a 500
	// is "route exists, handler errors" and a 200 is "route works", and both
	// are more informative than 404 without being the same thing.
	ConfirmOutcomeObservedNon404 ConfirmOutcome = "observed_non_404"

	// ConfirmOutcomeObserved404: Anvil asked and the target answered 404. A
	// FACT ABOUT THE TARGET. The endpoint stays a candidate and stays in the
	// denominator: something declared it, and a stale declaration is a real
	// finding about the inventory rather than a reason to shrink it.
	ConfirmOutcomeObserved404 ConfirmOutcome = "observed_404"

	// ConfirmOutcomeKernelRefused: the per-request gate chain refused before
	// anything could leave. A state-changing method with no operator
	// allowance (gate 15), a quarantined target (gate 16), an open
	// Retry-After window (gate 17), a path robots.txt removes (gate 11), or
	// an exhausted rate budget (gate 14).
	ConfirmOutcomeKernelRefused ConfirmOutcome = "kernel_refused"

	// ConfirmOutcomeIntentRejected: the endpoint could not be expressed as an
	// authz.RequestIntent at all.
	ConfirmOutcomeIntentRejected ConfirmOutcome = "not_a_valid_request_intent"

	// ConfirmOutcomeProbeFailed: the seam returned an error, or returned
	// something that is not an HTTP status. A FACT ABOUT ANVIL'S REACH.
	ConfirmOutcomeProbeFailed ConfirmOutcome = "probe_failed"

	// ConfirmOutcomeBudgetExhausted: the per-target probe budget ran out
	// before this endpoint was reached. research/22 Risk #4 is exactly this:
	// a candidate list larger than the budget makes a LARGER inventory report
	// LOWER coverage, and the endpoint must stay visible as unprobed rather
	// than be dropped or defaulted.
	ConfirmOutcomeBudgetExhausted ConfirmOutcome = "budget_exhausted"

	// ConfirmOutcomeNoProberWired: confirmation was requested and there is no
	// egress seam. Loud, counted, never silent.
	ConfirmOutcomeNoProberWired ConfirmOutcome = "no_prober_wired"

	// ConfirmOutcomeTemplatedPathNotConcretized: the endpoint's path carries a
	// {placeholder} and no PathConcretizer supplied a value for it.
	//
	// A templated path is not a request. Anvil could invent "/users/1", but
	// then a 404 is unattributable — the route may be absent or the id may be
	// — and a non-404 is a fact about an input Anvil chose. Inventing the
	// value would also spend probe budget on requests that cannot settle the
	// question, which is the starvation half of Risk #4. So it stays a
	// candidate, in the denominator, with the reason named.
	ConfirmOutcomeTemplatedPathNotConcretized ConfirmOutcome = "templated_path_not_concretized"

	// ConfirmOutcomeConcretizationRefused: a PathConcretizer was wired and
	// returned something that is not a concretization of this endpoint's
	// template — a different shape, a different literal segment, or a path
	// the kernel refuses. Refused rather than used: a concretizer that can
	// change the path is a concretizer that can move the probe.
	ConfirmOutcomeConcretizationRefused ConfirmOutcome = "concretization_refused"

	// ConfirmOutcomeRunCancelled: the context was cancelled before this
	// endpoint was reached.
	ConfirmOutcomeRunCancelled ConfirmOutcome = "run_cancelled"

	// ConfirmOutcomeNotRequested: MergeAndConfirm was asked to merge only.
	// The union is still a union; nothing in it was probed.
	ConfirmOutcomeNotRequested ConfirmOutcome = "confirmation_not_requested"
)

// ConfirmOutcomeValues returns every legal outcome, in a stable order.
func ConfirmOutcomeValues() []ConfirmOutcome {
	return []ConfirmOutcome{
		ConfirmOutcomeObservedNon404,
		ConfirmOutcomeObserved404,
		ConfirmOutcomeKernelRefused,
		ConfirmOutcomeIntentRejected,
		ConfirmOutcomeProbeFailed,
		ConfirmOutcomeBudgetExhausted,
		ConfirmOutcomeNoProberWired,
		ConfirmOutcomeTemplatedPathNotConcretized,
		ConfirmOutcomeConcretizationRefused,
		ConfirmOutcomeRunCancelled,
		ConfirmOutcomeNotRequested,
	}
}

// Valid reports whether o is one of the enumerated outcomes.
func (o ConfirmOutcome) Valid() bool {
	for _, k := range ConfirmOutcomeValues() {
		if k == o {
			return true
		}
	}
	return false
}

// confirmingOutcomes is the ALLOWLIST of outcomes that promote a candidate.
//
// It is an allowlist with exactly one member, built from a const rather than
// stored in a package-level var, so there is no variable to reassign and no
// backing array to write through. A new outcome added to the enum does not
// confirm anything until somebody adds it here, and forgetting UNDERSTATES the
// numerator — the safe direction.
func confirmingOutcomes() map[ConfirmOutcome]bool {
	return map[ConfirmOutcome]bool{ConfirmOutcomeObservedNon404: true}
}

// Confirms reports whether this outcome promotes a candidate to confirmed.
func (o ConfirmOutcome) Confirms() bool { return confirmingOutcomes()[o] }

// answeredOutcomes is the set of outcomes in which the TARGET answered. It is
// what separates a fact about the target from a fact about Anvil's reach.
func answeredOutcomes() map[ConfirmOutcome]bool {
	return map[ConfirmOutcome]bool{
		ConfirmOutcomeObservedNon404: true,
		ConfirmOutcomeObserved404:    true,
	}
}

// MeansAnvilCouldNotLook reports whether this outcome describes ANVIL rather
// than the target.
//
// D.26 needs the distinction to decide whether a coverage number is a
// measurement or a floor. Every outcome in which the target never answered is
// one of these, including the zero value: an endpoint whose outcome nobody set
// was not looked at.
func (o ConfirmOutcome) MeansAnvilCouldNotLook() bool { return !answeredOutcomes()[o] }

// ---------------------------------------------------------------------------
// Observation — the evidence behind one confirmation
// ---------------------------------------------------------------------------

// Observation is one thing Anvil saw: a status code the target returned to a
// request the kernel admitted.
//
// Every field is unexported and the only constructor is unexported and lives
// in this file, so nothing outside package inventory can mint one — for the
// same reason SpecRequest and Route are shaped that way. A caller who could
// build an Observation could make the coverage numerator say anything.
type Observation struct {
	status    int
	auditSeq  authz.AuditSeq
	at        time.Time
	technique authz.Technique
	method    authz.Method
	// path is the CONCRETE path that was requested. For a literal endpoint it
	// equals the endpoint path; for a concretized one it is what actually
	// went out, which is the string a reviewer needs in order to reproduce
	// the observation.
	path   string
	sealed bool
}

// Recorded reports whether obs came from an actual probe.
//
// An audit sequence of zero is refused: gate 21 makes the audit write part of
// the decision, and a probe with no audit row is a probe whose admission
// cannot be joined back to who authorized it.
func (o Observation) Recorded() bool {
	return o.sealed && o.status >= minStatusCode && o.status <= maxStatusCode && o.auditSeq > 0
}

// Status is the HTTP status code the target returned.
func (o Observation) Status() int { return o.status }

// AuditSeq is the gate-21 row this probe was admitted under.
func (o Observation) AuditSeq() authz.AuditSeq { return o.auditSeq }

// At is the run-clock instant of the probe.
func (o Observation) At() time.Time { return o.at }

// Technique is the declared technique the kernel judged at gate 15.
func (o Observation) Technique() authz.Technique { return o.technique }

// Method is the method actually requested.
func (o Observation) Method() authz.Method { return o.method }

// Path is the CONCRETE path actually requested.
func (o Observation) Path() string { return o.path }

// String renders the observation for a log line.
func (o Observation) String() string {
	if !o.Recorded() {
		return "observation(none)"
	}
	return fmt.Sprintf("%s %s -> %d (audit seq %d, %s, at %s)",
		o.method, redact(o.path), o.status, o.auditSeq, o.technique,
		o.at.UTC().Format(time.RFC3339))
}

// ---------------------------------------------------------------------------
// The egress seam
// ---------------------------------------------------------------------------

// ConfirmRequest is a probe the kernel has already admitted.
//
// A composite literal in another package produces the zero value, whose
// Constructed() is false — the same property SpecRequest and
// engines.AdmittedRequest hold, for the same reason: argument construction is
// a security boundary when the argument is a destination.
type ConfirmRequest struct {
	auth      authz.Authorization
	target    authz.Target
	method    authz.Method
	path      string
	technique authz.Technique
	seq       authz.AuditSeq
	sealed    bool
}

// Constructed reports whether r was built by the confirmation loop.
func (r ConfirmRequest) Constructed() bool { return r.sealed && r.target.Constructed() }

// Authorization returns the kernel token this probe rests on. An implementor
// MUST pass it to authz.RequireAuthorization (or authz.PinnedDialAddress,
// which calls it) immediately before constructing a socket.
func (r ConfirmRequest) Authorization() authz.Authorization { return r.auth }

// Target returns the authorized destination, pinned address and all.
func (r ConfirmRequest) Target() authz.Target { return r.target }

// Method returns the method to issue.
func (r ConfirmRequest) Method() authz.Method { return r.method }

// Path returns the CONCRETE request path.
func (r ConfirmRequest) Path() string { return r.path }

// Technique returns the technique gate 15 judged.
func (r ConfirmRequest) Technique() authz.Technique { return r.technique }

// AuditSeq returns the gate-21 row this probe was admitted under.
func (r ConfirmRequest) AuditSeq() authz.AuditSeq { return r.seq }

// ConfirmResponse is what the seam got back.
//
// There is no body. Confirmation asks whether an address exists, and a body is
// neither necessary nor free: reading one costs gate 14 budget and puts
// attacker-controlled bytes in this package for no gain in what the status
// code already settles.
type ConfirmResponse struct {
	// Status is the HTTP status code. A value outside [100,599] is treated as
	// "the prober returned nothing", NOT as a non-404 — see
	// ConfirmOutcomeProbeFailed.
	Status int
	// Latency is how long the request took. It is fed to gate 16's circuit
	// breaker, which is what stops a large candidate list from being driven
	// into a target that is already degrading.
	Latency time.Duration
}

// EndpointProber is the egress seam.
//
// # Why this is an interface and not a function that dials
//
// D.9's gate 3 tier 1: a socket constructed inside internal/dast outside
// internal/dast/authz fails the build, with no allowlist. This package cannot
// dial, cannot hold an http.Client, and cannot import a package that could.
// The implementation lives on the far side of that boundary — in the kernel,
// or in cmd/anvil-dast — and is handed in. Nothing in this module implements
// it today, and its absence is a loud, counted refusal rather than a silently
// empty numerator.
type EndpointProber interface {
	ProbeEndpoint(ctx context.Context, req ConfirmRequest) (ConfirmResponse, error)
}

// ClockSource hands the confirmation loop the instant of the NEXT probe.
//
// # Why one instant is not enough here, and is enough for D.18
//
// D.18's Probe takes a single authz.Clock because it issues at most
// maxEndpointsPerProbe requests from a configured list. Confirmation issues one
// request per endpoint in the union, which is a number the target's own
// inventory chooses. Gate 14's token bucket refills from the ELAPSED interval
// between the instants it is handed (phase3_enforcement.go's RateLimiter.
// Acquire), so a frozen clock spends the initial bucket and then refuses every
// remaining probe at ReasonRateExceeded — which is the kernel behaving
// correctly, and would silently cap endpoint_coverage's numerator at
// authz.CodedMaxRequestsPerSecondPerHost for a reason that is about Anvil's
// clock rather than about the target.
//
// So the seam exists, and its absence is honest rather than hidden: with no
// ClockSource the run instant is reused for every probe, the kernel refuses the
// overflow at gate 14, and those endpoints stay in the union carrying
// ConfirmOutcomeKernelRefused. They are never dropped and never defaulted.
type ClockSource interface {
	// NextInstant returns the clock for the next probe. It must not go
	// backwards; the kernel's limiter refuses a clock that does.
	NextInstant() authz.Clock
}

// PathConcretizer turns a templated path into a concrete one.
//
// # Why this is a seam and not a default
//
// "/users/{id}" is not a request. Something has to choose a value, and the
// choice is a fact about the run rather than about the inventory: a fixture
// dataset, a seeded record, an operator's configuration. Anvil inventing one
// would make a 404 unattributable and a non-404 a statement about Anvil's
// guess. So the value comes from outside, WITH a stated source, and its
// absence leaves the endpoint an honest candidate.
//
// The returned path is not trusted. concretePathMatches checks it against the
// template segment by segment and the kernel re-validates it, so a concretizer
// cannot move a probe to a different path, a different shape or a different
// host.
type PathConcretizer interface {
	// ConcretizePath returns a concrete path for template, and a short
	// non-empty string naming WHERE the values came from. Returning an error
	// leaves the endpoint a candidate with the reason recorded.
	ConcretizePath(ctx context.Context, method authz.Method, template string) (path string, source string, err error)
}

// ---------------------------------------------------------------------------
// MergeNote — what the merge did, so the denominator can be audited
// ---------------------------------------------------------------------------

// MergeNoteReason names something the merge did to the union.
//
// These are NOT Refusals. RefusalDuplicateRoute is per-operation and raises
// DenominatorFloor, which is correct within a tier — a document that declares
// the same operation twice declared two operations — and WRONG here, where a
// duplicate is the same endpoint arriving from a second tier. Recording a
// merge as a refusal would inflate the union by exactly the number of
// endpoints the merge was supposed to collapse.
type MergeNoteReason string

const (
	// MergeNoteUnset is the zero value and names nothing.
	MergeNoteUnset MergeNoteReason = ""

	// MergeNoteRoutesCollapsed: two or more routes named one endpoint and
	// became one row. THE NOTE THE DENOMINATOR DEPENDS ON.
	MergeNoteRoutesCollapsed MergeNoteReason = "routes_collapsed_to_one_endpoint"

	// MergeNoteOperationsOnOneAddress: one endpoint carries more than one
	// operation name — a GraphQL schema's root fields, or two operationIds a
	// document put on one method and path.
	MergeNoteOperationsOnOneAddress MergeNoteReason = "multiple_operations_on_one_address"

	// MergeNoteInboundConfirmationDiscarded: a route arrived already claiming
	// `confirmed`. The claim was DISCARDED — only this run's observations
	// confirm anything — and the discard is recorded rather than silent,
	// because a silent discard and a silent acceptance look identical in the
	// output and only one of them is safe.
	MergeNoteInboundConfirmationDiscarded MergeNoteReason = "inbound_confirmation_discarded"

	// MergeNotePlaceholderNamesDiverge: two endpoints have identical path
	// templates up to placeholder NAMES — "/users/{id}" and "/users/{userId}".
	// They are almost certainly one endpoint and they are counted as two,
	// which INFLATES the denominator. Reported rather than merged: merging
	// would need a second canonicalizer with an opinion D.20's does not have.
	MergeNotePlaceholderNamesDiverge MergeNoteReason = "placeholder_names_diverge"
)

// MergeNoteReasonValues returns every legal note reason.
func MergeNoteReasonValues() []MergeNoteReason {
	return []MergeNoteReason{
		MergeNoteRoutesCollapsed, MergeNoteOperationsOnOneAddress,
		MergeNoteInboundConfirmationDiscarded, MergeNotePlaceholderNamesDiverge,
	}
}

// Recognised reports whether r is one of the enumerated reasons.
func (r MergeNoteReason) Recognised() bool {
	for _, k := range MergeNoteReasonValues() {
		if k == r {
			return true
		}
	}
	return false
}

// MergeNote is one thing the merge did.
type MergeNote struct {
	// Reason is the enumerated cause.
	Reason MergeNoteReason
	// Method is the endpoint's method.
	Method string
	// Path is the endpoint's canonical path, redacted.
	Path string
	// Count is how many things the note is about — routes collapsed,
	// operations on the address, endpoints in the divergent group.
	Count int
	// Detail is a short redacted explanation.
	Detail string
}

// Valid reports whether the note names a recognised reason.
func (n MergeNote) Valid() bool { return n.Reason.Recognised() }

// String renders the note for a log line.
func (n MergeNote) String() string {
	return fmt.Sprintf("%s %s: %s x%d (%s)", n.Method, n.Path, n.Reason, n.Count, n.Detail)
}

func cloneMergeNotes(in []MergeNote) []MergeNote {
	if in == nil {
		return nil
	}
	out := make([]MergeNote, len(in))
	copy(out, in)
	return out
}

// SortMergeNotes orders notes deterministically. Map iteration is randomized
// and an unstable report makes an unchanged target look changed.
func SortMergeNotes(ns []MergeNote) {
	sort.SliceStable(ns, func(i, j int) bool {
		if ns[i].Path != ns[j].Path {
			return ns[i].Path < ns[j].Path
		}
		if ns[i].Method != ns[j].Method {
			return ns[i].Method < ns[j].Method
		}
		if ns[i].Reason != ns[j].Reason {
			return ns[i].Reason < ns[j].Reason
		}
		return ns[i].Detail < ns[j].Detail
	})
}

// ---------------------------------------------------------------------------
// MergedEndpoint — one row of the union
// ---------------------------------------------------------------------------

// MergedEndpoint is ONE address in the Tier 0-2 union.
//
// It is the unit of BOTH halves of endpoint_coverage: the denominator counts
// these, and the numerator counts the ones whose Confirmed() is true. Nothing
// else in this file is allowed to be a unit of either half, because a fraction
// over two different units is not a fraction.
type MergedEndpoint struct {
	method      authz.Method
	path        string
	target      authz.Target
	provenances []record.InventoryProvenance
	operations  []string
	contributor []Route
	outcome     ConfirmOutcome
	obs         Observation
	// concretizedFrom names where a concrete path's values came from, or "".
	concretizedFrom string
	sealed          bool
}

// Constructed reports whether e came from the merge.
func (e MergedEndpoint) Constructed() bool {
	return e.sealed && e.method.Recognised() && e.path != "" && e.target.Constructed()
}

// Method is the endpoint's HTTP method.
func (e MergedEndpoint) Method() authz.Method { return e.method }

// Path is the endpoint's canonical path template.
func (e MergedEndpoint) Path() string { return e.path }

// Target is the kernel Target this endpoint lives on.
func (e MergedEndpoint) Target() authz.Target { return e.target }

// Key is the endpoint's identity in the union: method and canonical path.
//
// It is deliberately NOT Route.Key(), which includes the operation. See this
// file's header: the operation is a name for something on an address, and the
// unit of confirmation is the address.
func (e MergedEndpoint) Key() string { return endpointKey(e.method, e.path) }

// Provenances returns a COPY of the sorted, deduplicated set of provenances
// that named this endpoint.
//
// It is a SET and not one value because the same endpoint found by three
// routes is one endpoint with three provenances. Confirming it changes none of
// them.
func (e MergedEndpoint) Provenances() []record.InventoryProvenance {
	if len(e.provenances) == 0 {
		return nil
	}
	out := make([]record.InventoryProvenance, len(e.provenances))
	copy(out, e.provenances)
	return out
}

// Operations returns a COPY of the sorted operation names living on this
// address — OpenAPI operationIds, GraphQL root fields. Empty for an ordinary
// REST endpoint.
func (e MergedEndpoint) Operations() []string {
	if len(e.operations) == 0 {
		return nil
	}
	out := make([]string, len(e.operations))
	copy(out, e.operations)
	return out
}

// Contributors returns a deep COPY of the routes that named this endpoint,
// each carrying its own provenance and its own confirmation as it arrived.
func (e MergedEndpoint) Contributors() []Route { return cloneRoutes(e.contributor) }

// Outcome is why this endpoint is or is not confirmed.
func (e MergedEndpoint) Outcome() ConfirmOutcome { return e.outcome }

// Observation returns the evidence behind a confirmation, and whether there is
// any.
func (e MergedEndpoint) Observation() (Observation, bool) {
	return e.obs, e.obs.Recorded()
}

// ConcretizedFrom names where a concretized path's values came from, or "".
func (e MergedEndpoint) ConcretizedFrom() string { return e.concretizedFrom }

// Confirmed reports whether this endpoint is in endpoint_coverage's numerator.
//
// THREE things must hold, and the conjunction is the point: the outcome must
// be on the one-member allowlist, an observation must be recorded, and that
// observation must carry a gate-21 audit sequence. A confirmation that cannot
// be traced to a specific admitted request is not a confirmation.
func (e MergedEndpoint) Confirmed() bool {
	return e.outcome.Confirms() && e.obs.Recorded()
}

// Confirmation renders the endpoint's confirmation on D.18's axis.
func (e MergedEndpoint) Confirmation() Confirmation {
	if e.Confirmed() {
		return ConfirmationConfirmed
	}
	return ConfirmationCandidate
}

// Templated reports whether the path carries a {placeholder} and therefore
// cannot be requested without a concretizer.
func (e MergedEndpoint) Templated() bool { return pathIsTemplated(e.path) }

// String renders the endpoint for a log line.
func (e MergedEndpoint) String() string {
	if !e.Constructed() {
		return "endpoint(unconstructed)"
	}
	return fmt.Sprintf("%s %s [%v/%s/%s]", e.method, e.path, e.provenances,
		e.Confirmation(), e.outcome)
}

func cloneEndpoints(in []MergedEndpoint) []MergedEndpoint {
	if in == nil {
		return nil
	}
	out := make([]MergedEndpoint, len(in))
	for i, e := range in {
		out[i] = e
		if e.provenances != nil {
			out[i].provenances = make([]record.InventoryProvenance, len(e.provenances))
			copy(out[i].provenances, e.provenances)
		}
		if e.operations != nil {
			out[i].operations = make([]string, len(e.operations))
			copy(out[i].operations, e.operations)
		}
		out[i].contributor = cloneRoutes(e.contributor)
	}
	return out
}

// SortEndpoints orders the union deterministically by path then method, the
// same order SortRoutes uses, so the two listings read alike.
func SortEndpoints(es []MergedEndpoint) {
	sort.SliceStable(es, func(i, j int) bool {
		if es[i].path != es[j].path {
			return es[i].path < es[j].path
		}
		return es[i].method < es[j].method
	})
}

// endpointKey is the union's identity function. The separator is a NUL byte,
// which cannot appear in either component: the method comes from the kernel's
// closed allowlist and the path passed the kernel's printable-ASCII rule.
func endpointKey(m authz.Method, path string) string {
	return string(m) + "\x00" + path
}

// ---------------------------------------------------------------------------
// ConfirmConfig
// ---------------------------------------------------------------------------

// ConfirmConfig is everything MergeAndConfirm needs. Nothing in it has a
// default that means "permitted", and nothing in it has a default that means
// "unlimited".
type ConfirmConfig struct {
	// Governor is the kernel's per-request interceptor for this target.
	// Required when Confirm is true.
	Governor *authz.Governor

	// Audit is gate 21's writer, coupled to the interceptor by AuditedAdmit:
	// an admission whose audit row did not land is not an admission. Required
	// when Confirm is true.
	Audit *authz.GateAudit

	// Authorization is the kernel token for Target. Required when Confirm is
	// true; authz.Adjudicate is the only mint.
	Authorization authz.Authorization

	// Target is the target every route in the union must live on. Required
	// always: it is what the merge validates each route against, and an
	// inventory spanning two hosts is two inventories.
	Target authz.Target

	// Confirm says whether to probe at all. It is explicit rather than
	// inferred from a nil Prober, because "merge only" is a legitimate
	// request and "confirm, but nothing is wired" is a defect, and inferring
	// would turn the second into the first.
	Confirm bool

	// ProbeBudget is the maximum number of requests this run may ISSUE
	// against this target for confirmation. plan/50-dast.md D.22 requires it
	// to be config rather than hard-coded. There is no default: zero with
	// Confirm true is refused, because a zero budget that meant "unlimited"
	// would be the exact shape research/22's Risk #4 describes.
	//
	// It counts requests that reached the seam. A kernel refusal costs no
	// budget — the loop is bounded by the endpoint count regardless — because
	// spending budget on requests that never left would let a hundred
	// state-changing endpoints gate 15 refuses starve the readable ones.
	ProbeBudget int

	// Technique is the declared technique for a confirmation probe. Required
	// when Confirm is true; gate 15 judges it and there is no default,
	// because a default here would be a gate running against a value nobody
	// chose. TechniqueContentDiscovery is the accurate one — confirming which
	// paths a site publishes is exactly what it names.
	Technique authz.Technique

	// Prober is the egress seam. A nil Prober with Confirm true produces a
	// counted outcome on every endpoint and a loud error — never a silent
	// numerator of zero.
	Prober EndpointProber

	// Concretizer supplies values for templated paths. Optional: absent, a
	// templated endpoint stays an honest candidate.
	Concretizer PathConcretizer

	// Clock advances the instant between probes. Optional: absent, the run
	// instant handed to MergeAndConfirm is reused for every probe and gate
	// 14's token bucket refuses the overflow. See ClockSource.
	Clock ClockSource
}

// Constructed reports whether cfg carries what MergeAndConfirm needs.
func (c ConfirmConfig) Constructed() bool {
	if !c.Target.Constructed() {
		return false
	}
	if !c.Confirm {
		return true
	}
	// Every clause below is one validateConfirmConfig also checks, so a
	// caller that asks Constructed() first and a caller that just calls
	// MergeAndConfirm cannot disagree about whether a configuration is
	// usable. The authorization check in particular is the kernel's own
	// RequireAuthorization rather than a local comparison of hosts.
	return c.Governor.Constructed() && c.Audit.Constructed() &&
		authz.RequireAuthorization(c.Authorization, c.Target) == nil &&
		c.Technique.Classified() && !c.Technique.Destructive() &&
		c.ProbeBudget > 0 && c.ProbeBudget <= maxProbeBudget
}

// ---------------------------------------------------------------------------
// ConfirmResult
// ---------------------------------------------------------------------------

// ConfirmResult is one merge-and-confirm over one target.
type ConfirmResult struct {
	endpoints []MergedEndpoint
	refusals  []Refusal
	notes     []MergeNote
	offered   int
	accepted  int
	attempted int
	issued    int
	answered  int
	budget    int
	confirm   bool
	truncated bool
	sealed    bool
}

// Constructed reports whether r came from MergeAndConfirm.
func (r ConfirmResult) Constructed() bool { return r.sealed }

// Endpoints returns a deep COPY of the union, sorted deterministically.
//
// THIS IS THE DENOMINATOR. len(Endpoints()) is InventoryUnionCount.
func (r ConfirmResult) Endpoints() []MergedEndpoint { return cloneEndpoints(r.endpoints) }

// Refusals returns a COPY of every route that did not enter the union.
func (r ConfirmResult) Refusals() []Refusal { return cloneRefusals(r.refusals) }

// Notes returns a COPY of what the merge did to the union.
func (r ConfirmResult) Notes() []MergeNote { return cloneMergeNotes(r.notes) }

// Offered is how many routes the caller handed in, across every tier.
func (r ConfirmResult) Offered() int { return r.offered }

// Accepted is how many of those became a contributor to some endpoint.
func (r ConfirmResult) Accepted() int { return r.accepted }

// Attempted is how many endpoints the confirmation loop reached.
func (r ConfirmResult) Attempted() int { return r.attempted }

// Issued is how many requests actually reached the seam. It is what
// ProbeBudget bounds, and it can never exceed it.
func (r ConfirmResult) Issued() int { return r.issued }

// Answered is how many probes the TARGET answered, whatever the status. It is
// the number that separates "these endpoints do not exist" from "Anvil never
// reached this application".
func (r ConfirmResult) Answered() int { return r.answered }

// Budget returns the configured per-target probe budget, or 0 when
// confirmation was not requested.
func (r ConfirmResult) Budget() int { return r.budget }

// Truncated reports that the union hit the coded endpoint bound.
func (r ConfirmResult) Truncated() bool { return r.truncated }

// Routes returns one Route per CONTRIBUTOR, re-stamped with its endpoint's
// confirmation and carrying its own provenance across unchanged.
//
// It is deliberately NOT the denominator, and callers must not count it:
// several routes can name one endpoint, which is the whole point of the merge.
// It exists so D.26 can aggregate the provenance axis per route while counting
// endpoints on the other axis.
//
// A route that cannot be rebuilt is DROPPED FROM THIS LISTING ONLY and never
// from Endpoints(), so a rebuild failure can never shrink the denominator.
func (r ConfirmResult) Routes() []Route {
	out := make([]Route, 0, r.accepted)
	for _, e := range r.endpoints {
		conf := e.Confirmation()
		for _, c := range e.contributor {
			rebuilt, err := NewRoute(RouteFacts{
				Method:       c.Method(),
				Path:         c.Path(),
				Target:       c.Target(),
				Operation:    c.Operation(),
				Params:       c.Params(),
				Provenance:   c.Provenance(),
				Confirmation: conf,
				Trust:        c.Trust(),
				ServedAt:     c.ServedAt(),
			})
			if err != nil {
				continue
			}
			out = append(out, rebuilt)
		}
	}
	SortRoutes(out)
	return out
}

// ConfirmedCount is endpoint_coverage's NUMERATOR: endpoints Anvil observed.
func (r ConfirmResult) ConfirmedCount() int {
	n := 0
	for _, e := range r.endpoints {
		if e.Confirmed() {
			n++
		}
	}
	return n
}

// CandidateCount is the rest of the union.
func (r ConfirmResult) CandidateCount() int { return len(r.endpoints) - r.ConfirmedCount() }

// EndpointCount is endpoint_coverage's DENOMINATOR: the size of the union.
func (r ConfirmResult) EndpointCount() int { return len(r.endpoints) }

// OperationCount is the number of distinct (endpoint, operation) pairs.
//
// It is reported BESIDE EndpointCount rather than instead of it, because
// collapsing forty GraphQL root fields onto one address is the DEFLATING
// direction and a number that deflates a denominator has to be visible. An
// endpoint with no operation names counts once.
func (r ConfirmResult) OperationCount() int {
	n := 0
	for _, e := range r.endpoints {
		if len(e.operations) == 0 {
			n++
			continue
		}
		n += len(e.operations)
	}
	return n
}

// OutcomeMix returns the endpoint count per outcome, as a fresh map.
func (r ConfirmResult) OutcomeMix() map[ConfirmOutcome]int {
	out := make(map[ConfirmOutcome]int, len(ConfirmOutcomeValues()))
	for _, e := range r.endpoints {
		out[e.outcome]++
	}
	return out
}

// InventoryProvenanceMix is record.DastCoverage's mix: endpoint count per
// provenance literal.
//
// IT IS A MIX AND NOT A PARTITION. An endpoint named by three tiers counts
// once under each of its three provenances, so the values sum to more than
// EndpointCount. That is the honest shape — the alternative is picking one
// tier's provenance and discarding the fact that two others found it — and it
// is why endpoint_coverage's denominator is EndpointCount rather than the sum
// of this map.
func (r ConfirmResult) InventoryProvenanceMix() map[record.InventoryProvenance]int {
	out := make(map[record.InventoryProvenance]int, len(record.InventoryProvenanceValues()))
	for _, e := range r.endpoints {
		for _, p := range e.provenances {
			out[p]++
		}
	}
	return out
}

// UnprobedEndpoints returns a COPY of every endpoint whose outcome is a fact
// about ANVIL rather than about the target, sorted.
//
// These are the endpoints that make a coverage number a floor.
func (r ConfirmResult) UnprobedEndpoints() []MergedEndpoint {
	var out []MergedEndpoint
	for _, e := range r.endpoints {
		if e.outcome.MeansAnvilCouldNotLook() {
			out = append(out, e)
		}
	}
	return cloneEndpoints(out)
}

// Coverage renders the result as record.DastCoverage.
//
// ProbedCount is CONFIRMED ENDPOINTS, never a request count — plan/50-dast.md
// :1152 in bold. r.issued, the request count, is deliberately not used here;
// it is available separately as Issued() so that a reader comparing the two
// can see how many requests bought how many confirmations.
func (r ConfirmResult) Coverage() record.DastCoverage {
	confirmed := r.ConfirmedCount()
	union := len(r.endpoints)
	var frac float64
	if union > 0 {
		frac = float64(confirmed) / float64(union)
	}
	return record.DastCoverage{
		ProbedCount:            confirmed,
		InventoryUnionCount:    union,
		EndpointCoverage:       frac,
		ServerLineCoverage:     nil,
		InventoryProvenanceMix: r.InventoryProvenanceMix(),
		ConfirmedCount:         confirmed,
		CandidateCount:         union - confirmed,
	}
}

// AssertNotSilentlyEmpty decides whether an empty union is a statement about
// the TARGET or a statement about ANVIL.
//
// "No tier found anything" and "the handoff was never wired" produce
// byte-identical endpoint lists, and the empty list flows straight into the
// denominator of endpoint_coverage.
func (r ConfirmResult) AssertNotSilentlyEmpty() error {
	if !r.sealed {
		return fmt.Errorf("inventory: %w: AssertNotSilentlyEmpty was called on a "+
			"ConfirmResult MergeAndConfirm never built", ErrUnconstructed)
	}
	if len(r.endpoints) > 0 {
		return nil
	}
	return fmt.Errorf("%w: %d routes were offered across every tier and %d were accepted, "+
		"with %d refusals", ErrNothingMerged, r.offered, r.accepted, len(r.refusals))
}

// AssertBudgetSufficed reports whether endpoint_coverage over this result is a
// MEASUREMENT or a FLOOR.
//
// research/22's Risk #4 is the phpBB regression: a bigger candidate list
// exhausted the time budget and produced LOWER coverage than a smaller one.
// The failure mode is not the budget — a budget is correct — it is publishing
// the resulting fraction as though every candidate had been asked. This method
// is what makes D.26 write a line of code to do that.
func (r ConfirmResult) AssertBudgetSufficed() error {
	if !r.sealed {
		return fmt.Errorf("inventory: %w: AssertBudgetSufficed was called on a ConfirmResult "+
			"MergeAndConfirm never built", ErrUnconstructed)
	}
	starved := 0
	for _, e := range r.endpoints {
		if e.outcome == ConfirmOutcomeBudgetExhausted {
			starved++
		}
	}
	if starved == 0 {
		return nil
	}
	return fmt.Errorf("%w: %d of %d endpoints in the union were never attempted because the "+
		"configured budget of %d request(s) was spent (%d issued). A LARGER inventory "+
		"reporting LOWER coverage is research/22 Risk #4, not a measurement",
		ErrProbeBudgetExhausted, starved, len(r.endpoints), r.budget, r.issued)
}

// AssertEveryConfirmationHasEvidence sweeps the union and fails if anything is
// marked confirmed without a recorded observation behind it.
//
// The invariant is already structural — confirmationFor is the only writer and
// it reads only an outcome observeEndpoint produced — but a structural claim
// nobody checks is a claim, and this build's standing rule is that a guard
// which has never failed has not been tested.
func (r ConfirmResult) AssertEveryConfirmationHasEvidence() error {
	if !r.sealed {
		return fmt.Errorf("inventory: %w: AssertEveryConfirmationHasEvidence was called on a "+
			"ConfirmResult MergeAndConfirm never built", ErrUnconstructed)
	}
	for _, e := range r.endpoints {
		if !e.outcome.Confirms() {
			continue
		}
		if !e.obs.Recorded() {
			return fmt.Errorf("%w: %s %s carries outcome %q and no observation. A "+
				"confirmation that cannot be traced to a specific kernel-admitted request "+
				"is not a confirmation, and it is one row of endpoint_coverage's numerator",
				ErrConfirmationWithoutEvidence, e.method, redact(e.path), e.outcome)
		}
		if e.obs.status == 404 {
			return fmt.Errorf("%w: %s %s claims %q and its observation records status 404",
				ErrConfirmationWithoutEvidence, e.method, redact(e.path), e.outcome)
		}
	}
	return nil
}

// AssertNoUnconfirmedEndpointClaimsConfirmation is the other direction: no
// endpoint whose outcome does not confirm may report Confirmed().
func (r ConfirmResult) AssertNoUnconfirmedEndpointClaimsConfirmation() error {
	if !r.sealed {
		return fmt.Errorf("inventory: %w: this assertion was called on a ConfirmResult "+
			"MergeAndConfirm never built", ErrUnconstructed)
	}
	for _, e := range r.endpoints {
		if !e.outcome.Confirms() && e.Confirmed() {
			return fmt.Errorf("inventory: %w: %s %s reports Confirmed() with outcome %q",
				ErrRefused, e.method, redact(e.path), e.outcome)
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// MergeAndConfirm
// ---------------------------------------------------------------------------

// MergeAndConfirm is plan/50-dast.md D.22's named entry point.
//
// DEVIATION, stated: the plan's expected schema is
// `MergeAndConfirm(tiers ...[]Route) ([]Route, error)`. Three things about it
// could not survive contact with the kernel and with what the plan's own
// Forbidden actions require, and each is a refusal the plan signature makes
// impossible:
//
//   - Confirmation is a REQUEST. It needs a Governor, a GateAudit, an
//     Authorization, a Technique and a clock, because every request in Anvil
//     goes through the kernel; and it needs an egress seam, because D.9's gate
//     3 forbids this package from holding one.
//   - The plan itself requires "a bounded per-target probe budget (config, not
//     hard-coded)". There is nowhere in the plan signature to put it.
//   - A bare []Route cannot carry the union. Several routes are one endpoint,
//     and the number the plan's own Validation clause asks about — how many
//     candidates were never probed — is not expressible in a route list.
//
// The steps, and what each is for:
//
//	1  merge every tier into one union keyed on (method, canonical path),
//	   discarding every inbound Confirmation and recording the discard
//	2  for each endpoint in a deterministic order, while budget remains:
//	   2a concretize a templated path through the seam, or leave it a candidate
//	   2b build an authz.RequestIntent, so the kernel's own path rule applies
//	   2c authz.RequireAuthorization, immediately before anything can leave
//	   2d GateAudit.AuditedAdmit — the per-request chain plus a gate-21 row per
//	      gate. A refusal ends this endpoint as a counted candidate.
//	   2e only now does anything leave, and it leaves through EndpointProber
//	   2f Governor.ObserveResponse feeds gates 16 and 17 and releases the
//	      lease; GateAudit.AuditedObservation records the ruling
//	3  promote on a non-404 status, recording the status that was seen
//
// Every failure at every step produces an outcome on the endpoint. None
// produces a shorter union, and none produces a silent candidate.
func MergeAndConfirm(ctx context.Context, cfg ConfirmConfig, now authz.Clock, tiers ...[]Route) (ConfirmResult, error) {
	if !cfg.Target.Constructed() {
		return ConfirmResult{}, fmt.Errorf("inventory: %w: MergeAndConfirm was handed a "+
			"Target authz.NewTarget never built. Every route in the union is validated "+
			"against it, and an inventory that spans two hosts is two inventories",
			ErrUnconstructed)
	}
	if cfg.Confirm {
		if err := validateConfirmConfig(cfg); err != nil {
			return ConfirmResult{}, err
		}
	}

	out := ConfirmResult{sealed: true, confirm: cfg.Confirm, budget: 0}
	if cfg.Confirm {
		out.budget = cfg.ProbeBudget
	}

	merged := newMergeAccumulator(cfg.Target)
	for _, tier := range tiers {
		for _, rt := range tier {
			out.offered++
			if merged.add(&out, rt) {
				out.accepted++
			}
		}
	}
	out.endpoints = merged.endpoints(&out)
	out.truncated = merged.truncated
	noteMultiOperationAddresses(&out)
	notePlaceholderNameDivergence(&out)

	if !cfg.Confirm {
		for i := range out.endpoints {
			out.endpoints[i].outcome = ConfirmOutcomeNotRequested
		}
		SortMergeNotes(out.notes)
		return out, nil
	}

	confirmEndpoints(ctx, cfg, now, &out)
	SortMergeNotes(out.notes)

	if cfg.Prober == nil {
		return out, fmt.Errorf("%w: %d endpoint(s) in the union stayed candidates because "+
			"nothing could leave the process", ErrNoEndpointProber, len(out.endpoints))
	}
	return out, nil
}

func validateConfirmConfig(cfg ConfirmConfig) error {
	if !cfg.Governor.Constructed() {
		return fmt.Errorf("inventory: %w: confirmation was requested and the Governor is one "+
			"authz.NewGovernor never built. A nil governor enforces nothing, and enforcing "+
			"nothing is not admitting everything", ErrUnconstructed)
	}
	if !cfg.Audit.Constructed() {
		return fmt.Errorf("inventory: %w: confirmation was requested and the GateAudit is "+
			"one authz.NewGateAudit never built. Gate 21 makes the audit write part of the "+
			"decision, and a probe with no audit row cannot be joined back to who "+
			"authorized it", ErrUnconstructed)
	}
	if err := authz.RequireAuthorization(cfg.Authorization, cfg.Target); err != nil {
		return fmt.Errorf("inventory: %w: %w", ErrRefused, err)
	}
	if !cfg.Technique.Classified() {
		return fmt.Errorf("inventory: %w: the confirmation technique is %q, which is on "+
			"neither of gate 15's compiled-in lists. There is no default: a default here "+
			"would be a gate running against a value nobody chose",
			ErrRefused, redact(string(cfg.Technique)))
	}
	if cfg.Technique.Destructive() {
		return fmt.Errorf("inventory: %w: the confirmation technique is %q, which is on gate "+
			"15's destructive denylist. Confirming that an endpoint exists is content "+
			"discovery; declaring it as something destructive would be refused per request "+
			"and would leave the whole numerator at zero for the wrong reason",
			ErrRefused, redact(string(cfg.Technique)))
	}
	if cfg.ProbeBudget <= 0 {
		return fmt.Errorf("inventory: %w: the per-target probe budget is %d. "+
			"plan/50-dast.md D.22 requires a bounded budget that is configuration rather "+
			"than a constant, and there is no default — a zero that meant \"unlimited\" is "+
			"exactly the shape research/22's Risk #4 describes", ErrRefused, cfg.ProbeBudget)
	}
	if cfg.ProbeBudget > maxProbeBudget {
		return fmt.Errorf("inventory: %w: the per-target probe budget is %d and the coded "+
			"ceiling is %d", ErrRefused, cfg.ProbeBudget, maxProbeBudget)
	}
	return nil
}

// ---------------------------------------------------------------------------
// The merge
// ---------------------------------------------------------------------------

type mergeAccumulator struct {
	target    authz.Target
	byKey     map[string]*MergedEndpoint
	order     []string
	truncated bool
}

func newMergeAccumulator(target authz.Target) *mergeAccumulator {
	return &mergeAccumulator{target: target, byKey: map[string]*MergedEndpoint{}}
}

// add folds one route into the union. It returns whether the route became a
// contributor.
//
// NOTHING HERE READS rt.Confirmation() except to record that it was discarded.
// That is the single most important line in this file: a caller feeding a
// previous ConfirmResult's Routes() back in, or a tier that mistakenly stamped
// `confirmed`, must not be able to reach the numerator without this run
// observing the endpoint.
func (a *mergeAccumulator) add(out *ConfirmResult, rt Route) bool {
	if !rt.Constructed() {
		out.refusals = append(out.refusals, Refusal{
			Reason: RefusalRouteUnconstructible,
			Detail: "a route that NewRoute never built was offered to the merge. It names " +
				"no provenance and no confirmation, so it can be neither counted nor " +
				"attributed",
		})
		return false
	}
	if !sameTarget(a.target, rt.Target()) {
		out.refusals = append(out.refusals, Refusal{
			Path:   redact(rt.Path()),
			Method: string(rt.Method()),
			Reason: RefusalKernelRefused,
			Detail: fmt.Sprintf("the route lives on %s and this merge is for %s. An "+
				"inventory spanning two hosts is two inventories, and one coverage "+
				"fraction over both is meaningless",
				redact(rt.Target().String()), redact(a.target.String())),
		})
		return false
	}

	// ONE canonicalizer. D.20's canonicalizePattern is the package's only
	// path-template normalizer and D.21 already reuses it; a second one here
	// could disagree with it, and the disagreement would be silent — two
	// spellings of one endpoint sitting in the denominator forever.
	canon, _, err := canonicalizePattern(rt.Path())
	if err != nil {
		out.refusals = append(out.refusals, Refusal{
			Path:   redact(rt.Path()),
			Method: string(rt.Method()),
			Reason: RefusalPathRejectedByKernel,
			Detail: redact(err.Error()),
		})
		return false
	}
	if err := kernelAcceptsPath(a.target, rt.Method(), canon); err != nil {
		out.refusals = append(out.refusals, Refusal{
			Path:   redact(rt.Path()),
			Method: string(rt.Method()),
			Reason: RefusalPathRejectedByKernel,
			Detail: redact(err.Error()),
		})
		return false
	}

	if rt.Confirmation() == ConfirmationConfirmed {
		out.notes = append(out.notes, MergeNote{
			Reason: MergeNoteInboundConfirmationDiscarded,
			Method: string(rt.Method()),
			Path:   redact(canon),
			Count:  1,
			Detail: "a route arrived claiming \"confirmed\"; only an observation this run " +
				"made through the kernel confirms anything",
		})
	}

	key := endpointKey(rt.Method(), canon)
	e, ok := a.byKey[key]
	if !ok {
		if len(a.byKey) >= maxEndpointsPerMerge {
			a.truncated = true
			out.refusals = append(out.refusals, Refusal{
				Path:   redact(canon),
				Method: string(rt.Method()),
				Reason: RefusalSpecTruncated,
				Detail: fmt.Sprintf("the union reached the coded bound of %d endpoints",
					maxEndpointsPerMerge),
			})
			return false
		}
		e = &MergedEndpoint{
			method: rt.Method(),
			path:   canon,
			target: a.target,
			sealed: true,
		}
		a.byKey[key] = e
		a.order = append(a.order, key)
	} else {
		out.notes = append(out.notes, MergeNote{
			Reason: MergeNoteRoutesCollapsed,
			Method: string(rt.Method()),
			Path:   redact(canon),
			Count:  len(e.contributor) + 1,
			Detail: fmt.Sprintf("a %s route named an endpoint already in the union; it is "+
				"ONE endpoint with more than one provenance, and counting it twice would "+
				"inflate the denominator of endpoint_coverage", rt.Provenance()),
		})
	}

	if !containsProvenance(e.provenances, rt.Provenance()) {
		e.provenances = append(e.provenances, rt.Provenance())
	}
	if op := rt.Operation(); op != "" && len(e.operations) < maxOperationsPerEndpoint &&
		!containsString(e.operations, op) {
		e.operations = append(e.operations, op)
	}
	if len(e.contributor) < maxContributorsPerEndpoint {
		e.contributor = append(e.contributor, rt)
	}
	return true
}

// endpoints materializes the union in a deterministic order.
func (a *mergeAccumulator) endpoints(_ *ConfirmResult) []MergedEndpoint {
	out := make([]MergedEndpoint, 0, len(a.order))
	for _, k := range a.order {
		e := a.byKey[k]
		sortProvenances(e.provenances)
		sort.Strings(e.operations)
		SortRoutes(e.contributor)
		out = append(out, *e)
	}
	SortEndpoints(out)
	return out
}

// sortProvenances orders a provenance set by record's own declared order —
// strongest evidence first — rather than alphabetically, so a reader sees the
// strongest claim about an endpoint at the front of the list.
func sortProvenances(ps []record.InventoryProvenance) {
	rank := map[record.InventoryProvenance]int{}
	for i, p := range record.InventoryProvenanceValues() {
		rank[p] = i
	}
	sort.SliceStable(ps, func(i, j int) bool { return rank[ps[i]] < rank[ps[j]] })
}

func containsProvenance(ps []record.InventoryProvenance, p record.InventoryProvenance) bool {
	for _, q := range ps {
		if q == p {
			return true
		}
	}
	return false
}

func containsString(ss []string, s string) bool {
	for _, q := range ss {
		if q == s {
			return true
		}
	}
	return false
}

// sameTarget compares two kernel Targets by IDENTITY — scheme, canonical host,
// port and pinned address — rather than by position in a list or by their
// rendered String(), which is a display form.
func sameTarget(a, b authz.Target) bool {
	if !a.Constructed() || !b.Constructed() {
		return false
	}
	return a.Scheme() == b.Scheme() &&
		a.Canonical() == b.Canonical() &&
		a.Port() == b.Port() &&
		a.Pinned() == b.Pinned()
}

// noteMultiOperationAddresses records every address carrying more than one
// operation name.
//
// This is the DEFLATING direction made visible. The union counts addresses; an
// address with forty root fields on it is one row and forty operations, and a
// reader who is not told that will read the denominator as forty smaller than
// the operation count without knowing why.
func noteMultiOperationAddresses(out *ConfirmResult) {
	for _, e := range out.endpoints {
		if len(e.operations) < 2 {
			continue
		}
		out.notes = append(out.notes, MergeNote{
			Reason: MergeNoteOperationsOnOneAddress,
			Method: string(e.method),
			Path:   redact(e.path),
			Count:  len(e.operations),
			Detail: "one address, several operations. endpoint_coverage counts addresses, " +
				"because an address is what a probe can confirm; OperationCount() is the " +
				"other number",
		})
	}
}

// notePlaceholderNameDivergence reports groups of endpoints whose path
// templates are identical up to placeholder NAMES.
//
// It REPORTS and does not merge. Merging "/users/{id}" with "/users/{userId}"
// needs an opinion D.20's canonicalizePattern deliberately does not have —
// placeholderName refuses to sanitize a name precisely because collapsing two
// names onto one would merge two rows into one, and over-merging is the
// direction that makes coverage look BETTER. Under-merging inflates the
// denominator instead, which is pessimistic, and this note is what stops it
// being silent.
func notePlaceholderNameDivergence(out *ConfirmResult) {
	groups := map[string][]int{}
	for i, e := range out.endpoints {
		if !pathIsTemplated(e.path) {
			continue
		}
		shape := endpointKey(e.method, placeholderShape(e.path))
		groups[shape] = append(groups[shape], i)
	}
	shapes := make([]string, 0, len(groups))
	for s := range groups {
		if len(groups[s]) > 1 {
			shapes = append(shapes, s)
		}
	}
	sort.Strings(shapes)
	for _, s := range shapes {
		idx := groups[s]
		paths := make([]string, 0, len(idx))
		for _, i := range idx {
			paths = append(paths, out.endpoints[i].path)
		}
		sort.Strings(paths)
		out.notes = append(out.notes, MergeNote{
			Reason: MergeNotePlaceholderNamesDiverge,
			Method: string(out.endpoints[idx[0]].method),
			Path:   redact(paths[0]),
			Count:  len(idx),
			Detail: fmt.Sprintf("%s differ only in placeholder names and are counted as %d "+
				"endpoints. They are probably one, and counting them separately INFLATES "+
				"the denominator", redact(strings.Join(paths, " ")), len(idx)),
		})
	}
}

// placeholderShape replaces every placeholder segment with "{}" and leaves
// every literal segment alone.
//
// It is a REPORTING form and never a matcher for the union — nothing keys on
// it — so it cannot become a second canonicalization that disagrees with
// D.20's. Literal segments still compare by identity; only the fact that a
// segment IS a placeholder is positional.
func placeholderShape(path string) string {
	segs := strings.Split(path, "/")
	for i, s := range segs {
		if segmentIsPlaceholder(s) {
			segs[i] = "{}"
		}
	}
	return strings.Join(segs, "/")
}

func segmentIsPlaceholder(seg string) bool {
	return len(seg) >= 2 && strings.HasPrefix(seg, "{") && strings.HasSuffix(seg, "}")
}

// pathIsTemplated reports whether the path carries a {placeholder} segment,
// and therefore whether it can be requested as it stands.
func pathIsTemplated(path string) bool {
	for _, seg := range strings.Split(path, "/") {
		if segmentIsPlaceholder(seg) {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// The confirmation loop
// ---------------------------------------------------------------------------

// confirmEndpoints walks the union in its sorted order and probes what it can.
//
// The order is deterministic and written down: SortEndpoints has already
// ordered by path then method, so which endpoints a short budget reaches is a
// property of the inventory rather than of Go's map iteration. An unstable
// answer to "which endpoints did we confirm" is an unstable coverage number
// for an unchanged target.
func confirmEndpoints(ctx context.Context, cfg ConfirmConfig, now authz.Clock, out *ConfirmResult) {
	for i := range out.endpoints {
		e := &out.endpoints[i]

		if err := ctx.Err(); err != nil {
			e.outcome = ConfirmOutcomeRunCancelled
			continue
		}
		if cfg.Prober == nil {
			e.outcome = ConfirmOutcomeNoProberWired
			out.refusals = append(out.refusals, Refusal{
				Path:   redact(e.path),
				Method: string(e.method),
				Reason: RefusalNoFetcherWired,
				Detail: "confirmation was requested and there is no EndpointProber to " +
					"issue the probe through",
			})
			continue
		}
		if out.issued >= cfg.ProbeBudget {
			// NOT dropped, NOT defaulted to confirmed, NOT removed from the
			// union. plan/50-dast.md D.22's Forbidden actions name this case
			// by itself: a candidate that never gets probed must remain a
			// candidate.
			e.outcome = ConfirmOutcomeBudgetExhausted
			continue
		}

		concrete := e.path
		if pathIsTemplated(e.path) {
			if cfg.Concretizer == nil {
				e.outcome = ConfirmOutcomeTemplatedPathNotConcretized
				continue
			}
			got, source, cerr := cfg.Concretizer.ConcretizePath(ctx, e.method, e.path)
			if cerr != nil || source == "" || !concretePathMatches(e.path, got) {
				e.outcome = ConfirmOutcomeConcretizationRefused
				out.refusals = append(out.refusals, Refusal{
					Path:   redact(e.path),
					Method: string(e.method),
					Reason: RefusalPathRejectedByKernel,
					Detail: concretizationDetail(got, source, cerr),
				})
				continue
			}
			concrete = got
			e.concretizedFrom = redact(source)
		}

		out.attempted++
		// The per-probe instant. An invalid one from the seam is NOT
		// second-guessed here: gate 14's Acquire refuses a Clock NewClock
		// never built, and a check in this file would be a second copy of a
		// kernel rule that could drift from it.
		at := now
		if cfg.Clock != nil {
			at = cfg.Clock.NextInstant()
		}
		probeOne(ctx, cfg, at, out, e, concrete)
	}
}

func concretizationDetail(got, source string, err error) string {
	switch {
	case err != nil:
		return "the concretizer refused: " + redact(err.Error())
	case source == "":
		return "the concretizer named no source for its values; a concretization whose " +
			"origin is unknown makes the observation untraceable"
	default:
		return "the concretizer returned " + redact(got) + ", which is not a concretization " +
			"of this endpoint's template. A concretizer that can change the path is a " +
			"concretizer that can move the probe"
	}
}

// probeOne drives ONE endpoint through the kernel and the seam.
func probeOne(ctx context.Context, cfg ConfirmConfig, now authz.Clock, out *ConfirmResult,
	e *MergedEndpoint, concrete string) {

	intent, err := authz.NewRequestIntent(authz.RequestFacts{
		Origin:   authz.OriginInitial,
		Admitted: cfg.Target,
		Next:     cfg.Target,
		Method:   e.method,
		Path:     concrete,
	})
	if err != nil {
		e.outcome = ConfirmOutcomeIntentRejected
		out.refusals = append(out.refusals, Refusal{
			Path:   redact(concrete),
			Method: string(e.method),
			Reason: RefusalIntentRejected,
			Detail: redact(err.Error()),
		})
		return
	}

	// Gate 3's runtime half, done again even though validateConfirmConfig
	// already did it, because it costs a comparison and because the token and
	// the target are both still in scope at the moment a socket could be
	// constructed.
	if err := authz.RequireAuthorization(cfg.Authorization, cfg.Target); err != nil {
		e.outcome = ConfirmOutcomeKernelRefused
		out.refusals = append(out.refusals, Refusal{
			Path:   redact(concrete),
			Method: string(e.method),
			Reason: RefusalKernelRefused,
			Detail: redact(err.Error()),
		})
		return
	}

	lease, res := cfg.Audit.AuditedAdmit(cfg.Governor, intent, cfg.Technique, now)
	if !res.Passed() {
		e.outcome = ConfirmOutcomeKernelRefused
		out.refusals = append(out.refusals, Refusal{
			Path:   redact(concrete),
			Method: string(e.method),
			Reason: RefusalKernelRefused,
			Detail: fmt.Sprintf("the kernel refused at %s: %s",
				res.Gate(), redact(errText(res.Err()))),
		})
		return
	}

	seq := cfg.Audit.LastSeq()
	req := ConfirmRequest{
		auth:      cfg.Authorization,
		target:    cfg.Target,
		method:    e.method,
		path:      concrete,
		technique: cfg.Technique,
		seq:       seq,
		sealed:    true,
	}

	out.issued++
	resp, perr := cfg.Prober.ProbeEndpoint(ctx, req)
	if perr != nil {
		obsRes := cfg.Governor.ObserveConnectionError(lease, now)
		cfg.Audit.AuditedObservation(obsRes, cfg.Target, now)
		e.outcome = ConfirmOutcomeProbeFailed
		out.refusals = append(out.refusals, Refusal{
			Path:   redact(concrete),
			Method: string(e.method),
			Reason: RefusalFetchFailed,
			Detail: redact(perr.Error()),
		})
		return
	}

	// A status outside [100,599] is NOT an answer. It is what a stub, a
	// short-circuited implementation, or a prober that lost the response
	// returns — and 0 is non-404, so without this check "the prober returned
	// nothing" would promote the endpoint into the coverage numerator.
	if resp.Status < minStatusCode || resp.Status > maxStatusCode {
		obsRes := cfg.Governor.ObserveConnectionError(lease, now)
		cfg.Audit.AuditedObservation(obsRes, cfg.Target, now)
		e.outcome = ConfirmOutcomeProbeFailed
		out.refusals = append(out.refusals, Refusal{
			Path:   redact(concrete),
			Method: string(e.method),
			Reason: RefusalFetchFailed,
			Detail: fmt.Sprintf("the prober returned status %d, which is not an HTTP "+
				"status. A value that is not an answer must not be read as a non-404",
				resp.Status),
		})
		return
	}

	// ObserveResponse releases the lease itself and feeds gates 16 and 17, so
	// a target that starts degrading under a large candidate list trips the
	// breaker rather than being driven through the whole budget. The ruling
	// gets a gate-21 row whether it passed or tripped.
	obsRes := cfg.Governor.ObserveResponse(lease, resp.Status, resp.Latency, nil, now)
	cfg.Audit.AuditedObservation(obsRes, cfg.Target, now)

	out.answered++
	e.obs = Observation{
		status:    resp.Status,
		auditSeq:  seq,
		at:        now.Instant(),
		technique: cfg.Technique,
		method:    e.method,
		path:      concrete,
		sealed:    true,
	}
	e.outcome = outcomeForStatus(resp.Status)

	if e.outcome == ConfirmOutcomeObserved404 {
		out.refusals = append(out.refusals, Refusal{
			Path:   redact(concrete),
			Method: string(e.method),
			Reason: RefusalStatusNotOK,
			Detail: "the target answered 404; the endpoint stays a candidate and stays in " +
				"the denominator, because something declared it and a stale declaration " +
				"is a finding about the inventory rather than a reason to shrink it",
		})
	}
}

// outcomeForStatus is research/22 line 339, and it is the ONLY function that
// can produce a confirming outcome.
//
// "Promote to confirmed only on a non-404 response." The status itself is
// recorded on the Observation rather than folded away, because a 500 is "route
// exists, handler errors" and a 200 is "route works" — plan/50-dast.md D.22's
// Forbidden actions require both to be distinguishable after the fact.
func outcomeForStatus(status int) ConfirmOutcome {
	if status == 404 {
		return ConfirmOutcomeObserved404
	}
	return ConfirmOutcomeObservedNon404
}

// concretePathMatches checks that got is this template with its placeholder
// segments filled in, and nothing else.
//
// Segment count must match, every LITERAL segment must match by identity, and
// every placeholder segment must be filled with a non-empty segment that is
// not itself a placeholder and carries no slash. A concretizer is outside
// Anvil; this is what stops it choosing a different endpoint.
func concretePathMatches(template, got string) bool {
	if got == "" || !strings.HasPrefix(got, "/") {
		return false
	}
	if pathIsTemplated(got) {
		return false
	}
	ts := strings.Split(template, "/")
	gs := strings.Split(got, "/")
	if len(ts) != len(gs) {
		return false
	}
	for i := range ts {
		if segmentIsPlaceholder(ts[i]) {
			if gs[i] == "" {
				return false
			}
			continue
		}
		if ts[i] != gs[i] {
			return false
		}
	}
	return true
}
