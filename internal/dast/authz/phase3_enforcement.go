// Phase 3 of the Authorization Gate Sequence: PER-REQUEST ENFORCEMENT, gates
// 13–17.
//
// Phase 1 asked whether this RUN may start. Phase 2 asked whether THIS TARGET
// may be connected to. Phase 3 asks the question those two cannot: may THIS
// REQUEST, right now, at this rate, using this technique, against a target
// that is still healthy and is not being told to back off, be issued.
//
// ===========================================================================
// THE ONE SENTENCE THAT ORGANISES THIS FILE
// ===========================================================================
//
// SCOPE IS A PROPERTY OF A REQUEST, NOT OF A JOB. research/20 names the
// failure verbatim — ZAP issue #2546, where scope was a job-level property so
// a 302 walked the scanner off-scope — and calls it "the single most likely
// way Anvil escapes scope". Everything in gate 13 below exists because a
// decision taken once, at the top of a scan, is not a decision that holds for
// the eight hundredth request of that scan.
//
// ===========================================================================
// WHY NONE OF THESE FIVE GATES IS AN ADMISSION GATE
// ===========================================================================
//
// A gateFunc is `func(Target, Scope, Attestation, Clock) Ruling`. Those four
// values are the spine's whole world for the ADMISSION decision, and
// widening them is the change gate 12 exists to prevent. Not one of gates
// 13–17 is a function of them:
//
//	gate 13  needs the target Phase 2 admitted AND the destination this
//	         particular request would reach, which are two Targets, plus the
//	         request's origin (redirect? template URL? browser fetch?).
//	gate 14  needs mutable per-target state — a token bucket, an in-flight
//	         count, a request tally, a start instant. A gateFunc reading
//	         package-level mutable state would make Decide a function of
//	         ambient state, which is a safety-section violation wearing a hat.
//	gate 15  needs the technique being attempted, the HTTP method and the
//	         path. None of the three is in a Target.
//	gate 16  needs the target's observed health history.
//	gate 17  needs the 429 ledger and the Retry-After deadline.
//
// So each is an exported Check function that really refuses, called per
// request by the egress layer, and the Governor at the bottom of this file is
// the interceptor that calls all five in one place and in one order. Gate 11
// (per-target admission's CheckGate11RobotsDeny) is absent from the admission chain for the same
// class of reason and is called the same way; the Governor calls it too, so a
// run does not have to remember to.
//
// THE SEPARATION IS DECLARED IN THE TYPE SYSTEM, NOT IMPLIED BY ABSENCE. An
// unregistered gate and a forgotten gate look identical from the outside, so
// per-request enforcement has its own chain type — requestChain, at the bottom
// of this file — and kernel.go's registerInto REFUSES a Phase 3 gate outright.
// A future edit that "helpfully" registers one into the admission chain fails
// the build rather than silently moving enforcement from per-request to
// per-target; TestNoPhase3GateIsInAnAdmissionChain is that negative control.
//
// ===========================================================================
// CAPS, FLOORS AND THE DIRECTION CONFIGURATION MAY MOVE
// ===========================================================================
//
// The kernel-types review demonstrated a real hole in the kernel core's Cap:
// NewCap was exported and unvalidated, so `authz.NewCap(10*365*24*time.Hour)`
// minted a "coded floor" of ten years, and gate 5's ceiling was a
// caller-supplied parameter. types.go now unexports the constructor and
// NewAttestation re-checks against the const; gate 5's own gateFunc re-checks
// it a third time, in the chain.
//
// Gate 14 and gate 16 close it structurally instead. Caps and HealthThresholds
// have UNEXPORTED FIELDS and exactly one constructor each — CodedCaps and
// CodedHealthThresholds — which read compiled-in consts and take no argument.
// There is no way to hand this file a Cap. Configuration enters through
// CapOverrides / ThresholdOverrides, which carry plain numbers, and the only
// operation on them is Lower. A config value therefore cannot BE a floor; it
// can only be compared against one.

package authz

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"
)

// ---------------------------------------------------------------------------
// REASONS — the gate-numbered tokens Phase 3 refuses with
// ---------------------------------------------------------------------------

// Gate 13 reasons.
const (
	ReasonRequestIntentUnbuilt      Reason = "gate13.request_intent_not_constructed"
	ReasonRequestOriginUnrecognised Reason = "gate13.request_origin_not_on_the_allowlist"
	ReasonRevalidationRefused       Reason = "gate13.revalidation_chain_refused_this_hop"
	ReasonHopOutsideScope           Reason = "gate13.hop_host_and_port_are_not_in_scope"
	ReasonCrossHostRedirect         Reason = "gate13.cross_host_redirect"
	ReasonRedirectDowngradesScheme  Reason = "gate13.redirect_downgrades_https_to_http"
	ReasonRedirectFollowAttempted   Reason = "gate13.http_client_tried_to_follow_a_redirect"
	ReasonRedirectHopBudget         Reason = "gate13.redirect_hop_budget_exhausted"
	ReasonHopMethodUnrecognised     Reason = "gate13.method_not_on_the_allowlist"
	ReasonHopPathMalformed          Reason = "gate13.request_path_is_malformed"
	ReasonHopRevalidated            Reason = "gate13.hop_revalidated_against_scope"
	ReasonHopAttestationNotLive     Reason = "gate13.attestation_is_not_live_for_this_request"
)

// Gate 14 reasons.
const (
	ReasonCapsUnconstructed    Reason = "gate14.caps_not_constructed"
	ReasonCapRaiseAttempted    Reason = "gate14.configuration_tried_to_raise_a_coded_cap"
	ReasonCapNotPositive       Reason = "gate14.configured_cap_is_not_positive"
	ReasonLimiterUnconstructed Reason = "gate14.limiter_not_constructed"
	ReasonRateExceeded         Reason = "gate14.requests_per_second_per_host_exceeded"
	ReasonConcurrencyExceeded  Reason = "gate14.concurrent_connections_per_host_exceeded"
	ReasonVolumeExceeded       Reason = "gate14.requests_per_target_per_run_exceeded"
	ReasonWallClockExceeded    Reason = "gate14.wall_clock_per_target_exceeded"
	ReasonRetryBudgetExceeded  Reason = "gate14.retry_budget_exceeded"
	ReasonBodyExceedsCap       Reason = "gate14.body_exceeds_the_coded_cap"
	ReasonCapClockWentBack     Reason = "gate14.clock_went_backwards"
	ReasonWithinEveryCap       Reason = "gate14.within_every_cap"
)

// Gate 15 reasons.
const (
	ReasonTechniqueUnclassified   Reason = "gate15.technique_is_not_on_the_static_list"
	ReasonTechniqueDestructive    Reason = "gate15.technique_is_on_the_destructive_denylist"
	ReasonTechniqueMethodUnknown  Reason = "gate15.method_not_on_the_allowlist"
	ReasonStateChangingWithoutAll Reason = "gate15.state_changing_method_without_endpoint_allow"
	ReasonTechniquePathMalformed  Reason = "gate15.request_path_is_malformed"
	ReasonTechniqueNonDestructive Reason = "gate15.technique_is_non_destructive"
)

// Gate 16 reasons.
const (
	ReasonMonitorUnconstructed  Reason = "gate16.health_monitor_not_constructed"
	ReasonThresholdRaise        Reason = "gate16.configuration_tried_to_loosen_a_threshold"
	ReasonObservationMalformed  Reason = "gate16.observation_is_malformed"
	ReasonBreakerClockWentBack  Reason = "gate16.clock_went_backwards"
	ReasonBreakerServerErrors   Reason = "gate16.server_error_rate_above_threshold"
	ReasonBreakerConnErrors     Reason = "gate16.connection_error_rate_above_threshold"
	ReasonBreakerLatency        Reason = "gate16.p95_latency_above_the_baseline_multiple"
	ReasonTargetQuarantined     Reason = "gate16.target_is_quarantined_for_the_rest_of_the_run"
	ReasonTargetHealthWithinAll Reason = "gate16.target_health_within_every_threshold"
)

// Gate 17 reasons.
const (
	ReasonLedgerUnconstructed   Reason = "gate17.backoff_ledger_not_constructed"
	ReasonInsideRetryAfter      Reason = "gate17.inside_the_retry_after_window"
	ReasonThreeTooManyRequests  Reason = "gate17.three_429s_aborted_this_target"
	ReasonRetryAfterUnparseable Reason = "gate17.retry_after_header_is_unparseable"
	ReasonRetryAfterAbsurd      Reason = "gate17.retry_after_exceeds_the_coded_bound"
	ReasonServerSaid429         Reason = "gate17.server_answered_429"
	ReasonLedgerClockWentBack   Reason = "gate17.clock_went_backwards"
	ReasonBackoffElapsed        Reason = "gate17.no_backoff_window_is_open"
)

// ===========================================================================
// GATE 13 — re-validate scope on EVERY request and EVERY redirect hop
// ===========================================================================

// RequestOrigin says what caused this request to be about to happen.
//
// research/20 gate 13 enumerates the five ways a destination arrives that a
// job-level scope check never sees: "each `Location` header, each
// template-supplied absolute URL, each WebSocket upgrade, each `fetch`/XHR
// issued by a headless browser component, and each out-of-band callback
// target". Each has a constant here, and the type is an ALLOWLIST: the zero
// value is not an origin, and a value nobody enumerated is not a weaker origin,
// it is no origin, and gate 13 refuses it.
type RequestOrigin string

// The recognised origins. OriginUnset is the zero value and is not one.
const (
	// OriginUnset is the zero value. It names no origin and refuses.
	OriginUnset RequestOrigin = ""
	// OriginInitial is the first request to a target Phase 2 admitted.
	OriginInitial RequestOrigin = "initial"
	// OriginRedirect is a hop the SERVER chose, through a Location header.
	// This is the one origin for which a different host is refused outright
	// rather than checked against scope — see CheckGate13Revalidate.
	OriginRedirect RequestOrigin = "redirect"
	// OriginTemplateURL is an absolute URL supplied by a probe template.
	OriginTemplateURL RequestOrigin = "template_absolute_url"
	// OriginWebSocketUpgrade is a WebSocket upgrade request.
	OriginWebSocketUpgrade RequestOrigin = "websocket_upgrade"
	// OriginBrowserFetch is a fetch or XHR issued by a headless browser
	// component while rendering a response.
	OriginBrowserFetch RequestOrigin = "browser_fetch"
	// OriginOutOfBandCallback is an out-of-band callback target.
	OriginOutOfBandCallback RequestOrigin = "out_of_band_callback"
)

// requestOrigins is the allowlist, returned as a FRESH SLICE on every call so
// that no caller can retain and mutate it. The same shape per-target admission used for the
// reserved ranges, for the same reason.
func requestOrigins() []RequestOrigin {
	return []RequestOrigin{
		OriginInitial,
		OriginRedirect,
		OriginTemplateURL,
		OriginWebSocketUpgrade,
		OriginBrowserFetch,
		OriginOutOfBandCallback,
	}
}

// Recognised reports whether o is one of the enumerated origins.
func (o RequestOrigin) Recognised() bool {
	for _, k := range requestOrigins() {
		if k == o {
			return true
		}
	}
	return false
}

// ServerChosen reports whether the DESTINATION of this request was chosen by
// the target rather than by Anvil's scope file.
//
// It is documentation with a return value rather than a control: every origin
// is re-validated identically. It exists so that an audit row can say which
// requests had their destination picked by the thing being probed.
func (o RequestOrigin) ServerChosen() bool {
	switch o {
	case OriginRedirect, OriginTemplateURL, OriginBrowserFetch:
		return true
	default:
		return false
	}
}

// Method is an HTTP method, as an ALLOWLIST.
//
// The zero value is not a method. An unrecognised method is refused rather
// than classified: gate 15 has to know whether a method changes state, and
// "we have never heard of this verb" is not evidence that it is safe.
type Method string

// The recognised methods.
const (
	// MethodUnset is the zero value and is not a method.
	MethodUnset   Method = ""
	MethodGet     Method = "GET"
	MethodHead    Method = "HEAD"
	MethodOptions Method = "OPTIONS"
	MethodPost    Method = "POST"
	MethodPut     Method = "PUT"
	MethodPatch   Method = "PATCH"
	MethodDelete  Method = "DELETE"
)

// safeMethods is the allowlist of methods that do not change server state.
// RFC 9110 section 9.2.1 calls these "safe". TRACE and CONNECT are absent on
// purpose: neither is a probe Anvil issues, and adding one is an edit here.
func safeMethods() []Method {
	return []Method{MethodGet, MethodHead, MethodOptions}
}

// stateChangingMethods is the allowlist of methods that DO change state and
// therefore need a per-endpoint explicit allow (gate 15).
func stateChangingMethods() []Method {
	return []Method{MethodPost, MethodPut, MethodPatch, MethodDelete}
}

// Recognised reports whether m is on either allowlist.
func (m Method) Recognised() bool {
	return slices.Contains(safeMethods(), m) || slices.Contains(stateChangingMethods(), m)
}

// ChangesState reports whether m is a state-changing method.
//
// It returns TRUE for an unrecognised method, including MethodUnset. That is
// the fail-closed direction: an unknown verb is treated as state-changing, so
// it needs an explicit per-endpoint allow, and gate 15 refuses it outright at
// the recognition check before this is ever consulted.
func (m Method) ChangesState() bool {
	return !slices.Contains(safeMethods(), m)
}

// RequestFacts is what the egress layer knows about one request it is about to
// issue. NewRequestIntent turns it into a sealed RequestIntent.
//
// It is a plain struct with exported fields for the same reason
// phase1_run.go's TriggerFacts is: a caller has to be able to write the facts
// down. Nothing is authorized because a RequestFacts exists — only
// NewRequestIntent produces the value the gate reads, and it validates every
// field.
type RequestFacts struct {
	// Origin is what caused this request. Required.
	Origin RequestOrigin
	// Admitted is the Target Phase 2 admitted for this branch of the scan.
	Admitted Target
	// Next is the target this request would ACTUALLY reach. For an initial
	// request it equals Admitted; for a redirect hop it is the Location
	// header's destination, canonicalized and pinned by per-target admission's PinTarget.
	Next Target
	// Method is the HTTP method. Required.
	Method Method
	// Path is the request path, beginning with "/". Required.
	Path string
	// Hop is the redirect depth: 0 for a request that is not a redirect
	// hop, 1 for the first hop, and so on.
	Hop int
	// Attempt is the retry number: 0 for the first attempt.
	Attempt int
}

// maxRedirectHops is the coded redirect-depth bound.
//
// Gate 13 refuses to follow ANY redirect automatically (RefuseAllRedirects),
// so a hop only ever exists because the egress layer chose to re-admit one
// through the full gate stack. This bounds how many times it may do that, so
// that a same-host redirect loop is a refusal rather than a spin. It is a
// const, not a Cap: nothing may raise it and nothing may lower it either.
const maxRedirectHops = 5

// RequestIntent is a sealed, validated request. The zero value is not one.
type RequestIntent struct {
	origin   RequestOrigin
	admitted Target
	next     Target
	method   Method
	path     string
	hop      int
	attempt  int
	sealed   bool
}

// NewRequestIntent validates the facts and seals them.
//
// Everything it refuses, it refuses because the resulting RequestIntent would
// otherwise reach a gate carrying a field nobody set. A zero Target, an empty
// path, an origin nobody enumerated and a negative hop count are all shapes a
// partially-failed parse of a Location header takes.
func NewRequestIntent(f RequestFacts) (RequestIntent, error) {
	if !f.Origin.Recognised() {
		return RequestIntent{}, fmt.Errorf("request intent: %w: %q is not one of the "+
			"enumerated request origins. Gate 13 re-validates every request, and a "+
			"request whose provenance nobody recorded is not a weaker request, it is an "+
			"unattributable one", ErrRefused, redactUntrusted(string(f.Origin)))
	}
	if !f.Admitted.Constructed() {
		return RequestIntent{}, fmt.Errorf("request intent: %w: the admitted Target was "+
			"not built by NewTarget, so there is nothing for gate 13 to compare this "+
			"request's destination against", ErrUnconstructed)
	}
	if !f.Next.Constructed() {
		return RequestIntent{}, fmt.Errorf("request intent: %w: the destination Target was "+
			"not built by NewTarget. A Location header that half-parsed produces exactly "+
			"this value, and it is refused rather than probed", ErrUnconstructed)
	}
	if !f.Method.Recognised() {
		return RequestIntent{}, fmt.Errorf("request intent: %w: %q is not on the method "+
			"allowlist", ErrRefused, redactUntrusted(string(f.Method)))
	}
	if !validRequestPath(f.Path) {
		return RequestIntent{}, fmt.Errorf("request intent: %w: the request path is empty, "+
			"does not begin with \"/\", exceeds the coded bound, or contains a byte "+
			"outside printable ASCII", ErrRefused)
	}
	if f.Hop < 0 || f.Hop > maxRedirectHops {
		return RequestIntent{}, fmt.Errorf("request intent: %w: redirect depth %d is "+
			"outside 0..%d", ErrRefused, f.Hop, maxRedirectHops)
	}
	if f.Attempt < 0 {
		return RequestIntent{}, fmt.Errorf("request intent: %w: attempt number %d is "+
			"negative", ErrRefused, f.Attempt)
	}
	if f.Origin != OriginRedirect && f.Hop != 0 {
		return RequestIntent{}, fmt.Errorf("request intent: %w: origin %q carries redirect "+
			"depth %d. Only a redirect hop has a depth, and a request that claims one "+
			"under another origin has had two different things written into one field",
			ErrRefused, string(f.Origin), f.Hop)
	}
	if f.Origin == OriginRedirect && f.Hop == 0 {
		return RequestIntent{}, fmt.Errorf("request intent: %w: a redirect hop at depth 0 "+
			"is not a hop. The first hop is depth 1", ErrRefused)
	}
	return RequestIntent{
		origin:   f.Origin,
		admitted: f.Admitted,
		next:     f.Next,
		method:   f.Method,
		path:     f.Path,
		hop:      f.Hop,
		attempt:  f.Attempt,
		sealed:   true,
	}, nil
}

// Constructed reports whether this intent came from NewRequestIntent.
func (i RequestIntent) Constructed() bool {
	return i.sealed && i.origin.Recognised() && i.next.Constructed() && i.admitted.Constructed()
}

// Origin returns the request's origin.
func (i RequestIntent) Origin() RequestOrigin { return i.origin }

// Admitted returns the Target Phase 2 admitted.
func (i RequestIntent) Admitted() Target { return i.admitted }

// Next returns the Target this request would actually reach.
func (i RequestIntent) Next() Target { return i.next }

// Method returns the HTTP method.
func (i RequestIntent) Method() Method { return i.method }

// Path returns the request path.
func (i RequestIntent) Path() string { return i.path }

// Hop returns the redirect depth.
func (i RequestIntent) Hop() int { return i.hop }

// Attempt returns the retry number, 0 for a first attempt.
func (i RequestIntent) Attempt() int { return i.attempt }

// CrossHost reports whether this request's destination is a different host or
// port from the target Phase 2 admitted.
//
// The comparison is on the CANONICAL form and the port, and it is exact. There
// is deliberately no registrable-domain, eTLD+1 or "same site" comparison
// anywhere in this file: per-request enforcement's forbidden actions say "never
// follow a cross-host redirect, under any circumstance, including
// same-registrable-domain-but-different-host cases", and the only way to be
// sure a same-site rule is not implemented is for there to be no public-suffix
// list in the kernel to implement it with.
func (i RequestIntent) CrossHost() bool {
	if !i.Constructed() {
		return true
	}
	return i.next.Canonical() != i.admitted.Canonical() || i.next.Port() != i.admitted.Port()
}

// CheckGate13Revalidate is gate 13: scope re-validated for THIS request.
//
// # What it re-runs, and why that is not all of it
//
// It calls kernel.go's Revalidate, which runs gates 4, 5, 8, 9 and 10 against
// the destination — SCOPE MEMBERSHIP, A LIVE ATTESTATION, canonicalize, judge
// the pinned address, reserved-range denylist.
//
// GATE 5 IS IN THAT CHAIN BECAUSE AN ATTESTATION EXPIRES AT AN INSTANT. Gate 14
// permits thirty minutes of wall clock per target and a run has many targets,
// so an attestation can expire mid-run; the build-time guard's review measured a Revalidate at
// base+365d permitting an attestation whose window ended at base+29d, and this
// function passing an OriginInitial intent at the same instant. Gate 5 is
// "refuse to probe without a live attestation" per REQUEST, and it is gate 5's
// own gateFunc that makes the comparison — not a private expiry check written
// here, which would be a second implementation that can disagree with the
// first.
//
// Per-request enforcement's design specifies "re-runs gates 8–10", and gates 8–10 are not
// enough. None of the three asks whether the host is in the allow list, so a
// redirect to a host that is routable, non-reserved and on no deny list passed
// them cleanly — a host nobody put in the scope file. research/20 gate 13's own
// words are "re-validate SCOPE on every single request", and the scope
// allow-list match is gate 4. This packet implemented the check locally and
// escalated the disagreement; the orchestrator ruled that revalidationChain was
// wrong, so gate 4 is in the chain now and the local duplicate is gone rather
// than kept as a layer that can no longer be the only thing refusing anything.
//
// What survives of the local check is its ATTRIBUTION. A chain refusal arrives
// as ReasonRevalidationRefused, which tells an operator that revalidation said
// no but not that the reason was scope; so when the chain refuses AT GATE 4,
// this function reports ReasonHopOutsideScope and names the destination. The
// token is the one per-request enforcement wrote and the check is the one the kernel owns.
//
// # The redirect rule
//
// For OriginRedirect a cross-host destination is refused OUTRIGHT — before
// scope is consulted, and whether or not scope would have permitted it. Every
// other origin's destination is checked against scope in the ordinary way, so
// a probe template or a browser fetch may reach a second host that the scope
// file names. The asymmetry is the point: a redirect is the TARGET choosing
// Anvil's next destination, and "the server asked us to" is precisely the
// argument ZAP #2546 accepted.
func CheckGate13Revalidate(intent RequestIntent, scope Scope, att Attestation, clock Clock) GateResult {
	const g = Gate13RevalidateEveryRequest

	if !intent.Constructed() {
		return gateFailed(g, ReasonRequestIntentUnbuilt,
			"gate 13 was handed a RequestIntent that NewRequestIntent never built. A zero "+
				"intent names no origin and carries no destination, and a request whose "+
				"destination nobody recorded is refused rather than issued.")
	}
	if !intent.Origin().Recognised() {
		return gateFailed(g, ReasonRequestOriginUnrecognised,
			"the request's origin is not on gate 13's allowlist. research/20 enumerates "+
				"the ways a destination arrives — Location header, template-supplied "+
				"absolute URL, WebSocket upgrade, headless-browser fetch/XHR, "+
				"out-of-band callback — and a sixth way nobody enumerated is refused.")
	}
	if !intent.Method().Recognised() {
		return gateFailed(g, ReasonHopMethodUnrecognised,
			"the request names a method that is not on the allowlist.")
	}
	if !validRequestPath(intent.Path()) {
		return gateFailed(g, ReasonHopPathMalformed,
			"the request path is empty, does not begin with \"/\", exceeds the coded bound, "+
				"or contains a byte outside printable ASCII.")
	}
	if intent.Hop() > maxRedirectHops {
		return gateFailed(g, ReasonRedirectHopBudget, fmt.Sprintf(
			"this is redirect hop %d and the coded budget is %d. A redirect chain longer "+
				"than the budget is refused rather than walked; the budget is a const in "+
				"the kernel and no configuration reaches it.", intent.Hop(), maxRedirectHops))
	}

	if intent.Origin() == OriginRedirect {
		if intent.Next().Scheme() == SchemeHTTP && intent.Admitted().Scheme() == SchemeHTTPS {
			return gateFailed(g, ReasonRedirectDowngradesScheme,
				"the redirect moves this branch from https to http. A downgrade is refused "+
					"on a hop the server chose, because a target that can rewrite the "+
					"scheme can move the whole exchange onto a channel it can read.")
		}
		if intent.CrossHost() {
			return gateFailed(g, ReasonCrossHostRedirect,
				"the Location header points at a different host or port from the one Phase "+
					"2 admitted. Per-request enforcement's design: never follow a cross-host redirect, "+
					"under any circumstance, INCLUDING same-registrable-domain-but-"+
					"different-host cases. The hop is recorded and this branch stops; it "+
					"is not followed, and no scope entry makes it followable.",
				"admitted:    "+redactedOrigin(intent.Admitted()),
				"redirect to: "+redactedOrigin(intent.Next()))
		}
	}

	// The revalidation chain: gates 4, 5, 8, 9 and 10, against the destination
	// this request would actually reach. This is the call the whole gate
	// exists to make, and it is made for every origin, on every hop, not only
	// on the first request.
	if r := Revalidate(intent.Next(), scope, att, clock); !r.Permits() {
		if r.Gate() == Gate5Attestation {
			return gateFailed(g, ReasonHopAttestationNotLive,
				"the attestation covering this run is not live for this request. It is "+
					"checked per request and not once per run: gate 14 permits thirty "+
					"minutes of wall clock per target, a run has many targets, and an "+
					"attestation that was live at admission can have expired by the time "+
					"this hop is issued. There is no grace period.",
				"refused at:  "+r.Gate().String(),
				"reason:      "+string(r.Reason()),
				"destination: "+redactedOrigin(intent.Next()))
		}
		if r.Gate() == Gate4ScopeFile {
			return gateFailed(g, ReasonHopOutsideScope,
				"the scope layer does not permit this request's destination host and port. "+
					"Either no allow entry covers it, or a deny entry does. Scope is "+
					"re-checked per request because scope is a property of a request and "+
					"not of a job — that is the exact reading ZAP issue #2546 got wrong.",
				"refused at:  "+r.Gate().String(),
				"reason:      "+string(r.Reason()),
				"destination: "+redactedOrigin(intent.Next()))
		}
		return gateFailed(g, ReasonRevalidationRefused,
			"the destination this request would reach does not pass the kernel's "+
				"revalidation chain. Gates 4, 5, 8, 9 and 10 are re-run for every "+
				"request and every redirect hop; a target that passed them once at "+
				"admission does not pass them forever.",
			"refused at:  "+r.Gate().String(),
			"reason:      "+string(r.Reason()),
			"destination: "+redactedOrigin(intent.Next()))
	}

	return gatePassed(g)
}

// redactedOrigin renders a target as "host:port" for an evidence line.
//
// The HOST goes through redactUntrusted and the port is rendered as a decimal
// separately, because redactUntrusted's charset allowlist does not contain
// ':' — redacting the whole "host:port" string would turn the separator into
// '?' and make every evidence line unreadable. The port is a uint16 and
// carries no bytes that did not come from a number.
func redactedOrigin(t Target) string {
	if !t.Constructed() {
		return "<unconstructed>"
	}
	return redactUntrusted(t.Canonical()) + ":" + strconv.Itoa(int(t.Port()))
}

// ErrRedirectRefused is what RefuseAllRedirects returns. It wraps ErrRefused,
// so an egress layer that only checks errors.Is(err, ErrRefused) still sees a
// refusal rather than a transport error.
var ErrRedirectRefused = fmt.Errorf("%w: %s: this client never follows a redirect "+
	"automatically; every hop is re-admitted through the gate stack or the branch stops",
	ErrRefused, string(ReasonRedirectFollowAttempted))

// RefuseAllRedirects is the redirect policy the kernel owns.
//
// # Why this function exists at all
//
// An http.Client with a nil CheckRedirect FOLLOWS UP TO TEN REDIRECTS
// automatically. The caller sees one Response and never learns that eight
// other hosts were contacted on the way to it. That is ZAP #2546's mechanism
// in one sentence, and it is the default behaviour of the standard library, so
// the failure mode here is not "somebody wrote bad code" — it is "somebody
// wrote no code".
//
// Assign this to http.Client.CheckRedirect. It refuses EVERY redirect,
// including a same-host one, and that is stricter than gate 13 requires on
// purpose: a same-host hop is legitimate, but it is legitimate only after
// CheckGate13Revalidate has judged it, and a client that follows it
// automatically never gives gate 13 a chance to run. So the client stops, the
// egress layer records the hop, and a same-host hop is re-issued as a fresh
// request with OriginRedirect and Hop+1.
//
// # Why an error rather than http.ErrUseLastResponse
//
// Returning http.ErrUseLastResponse makes Client.Do return the 3xx as an
// ordinary successful response. A caller that is not paying attention treats
// that as a result and may follow the Location itself. Returning an error
// makes Do return an error, which fails closed for a caller that is not paying
// attention. The previous response is still handed back with its body closed,
// so the hop can be recorded for the audit.
func RefuseAllRedirects(req *http.Request, via []*http.Request) error {
	// A nil request is not a reason to permit. This branch is reachable only
	// from a caller invoking the policy directly; net/http never passes nil.
	if req == nil {
		return fmt.Errorf("%w (the redirect carried no request at all)", ErrRedirectRefused)
	}
	return fmt.Errorf("%w (hop %d, refused before any connection to it)",
		ErrRedirectRefused, len(via))
}

// Compile-time proof that RefuseAllRedirects has exactly the signature
// http.Client.CheckRedirect requires. It asserts the signature and nothing
// more: no test can make a client that forgot to set the field call this.
var _ func(*http.Request, []*http.Request) error = RefuseAllRedirects

// ===========================================================================
// GATE 14 — the hard caps, as coded floors configuration may only LOWER
// ===========================================================================

// The six coded floors. plan/design/dynamic-tier.md gate 14 and research/20 gate 14 name
// each of them, for `external` mode, as a value "no config may raise".
//
// They are exported CONSTS so that a caller can see what it is lowering from
// and a test can assert against the same number the implementation uses
// without either of them being able to change it. A const cannot be
// reassigned, cannot be addressed, and cannot be reached by a config loader.
const (
	// CodedMaxRequestsPerSecondPerHost is the ≤10 rps/host floor.
	CodedMaxRequestsPerSecondPerHost = 10
	// CodedMaxConcurrentPerHost is the ≤4 concurrent connections/host floor.
	CodedMaxConcurrentPerHost = 4
	// CodedMaxRequestsPerTargetRun is the ≤20,000 requests/target/run floor.
	CodedMaxRequestsPerTargetRun = 20000
	// CodedMaxWallClockPerTarget is the ≤30 minutes/target floor.
	CodedMaxWallClockPerTarget = 30 * time.Minute
	// CodedMaxBodyBytes is the ≤1 MiB body floor.
	CodedMaxBodyBytes int64 = 1 << 20
	// CodedMaxRetries is the ≤3 retries floor.
	CodedMaxRetries = 3
)

// Caps is gate 14's six caps as one value.
//
// EVERY FIELD IS UNEXPORTED AND THERE IS EXACTLY ONE CONSTRUCTOR. CodedCaps
// takes no argument and reads the consts above, so there is no way to hand
// this package a cap — which is the structural answer to the hole the kernel-types review
// found in the kernel core's Cap (NewCap was exported and unvalidated, so a caller could
// mint a "coded floor" of any size). Configuration reaches Caps only through
// Lower, which takes plain numbers and compares them against the floors.
//
// The zero Caps permits nothing: every Cap inside it is undeclared, and an
// undeclared Cap's Allows is false for every value including zero.
type Caps struct {
	rps        Cap[int]
	concurrent Cap[int]
	volume     Cap[int]
	wallClock  Cap[time.Duration]
	bodyBytes  Cap[int64]
	retries    Cap[int]
	sealed     bool
}

// CodedCaps returns the six compiled-in floors.
func CodedCaps() Caps {
	return Caps{
		rps:        newCap(CodedMaxRequestsPerSecondPerHost),
		concurrent: newCap(CodedMaxConcurrentPerHost),
		volume:     newCap(CodedMaxRequestsPerTargetRun),
		wallClock:  newCap(CodedMaxWallClockPerTarget),
		bodyBytes:  newCap(CodedMaxBodyBytes),
		retries:    newCap(CodedMaxRetries),
		sealed:     true,
	}
}

// Constructed reports whether c came from CodedCaps (possibly via Lower).
func (c Caps) Constructed() bool { return c.sealed }

// CapOverrides is configuration's only way in.
//
// A nil field means "not configured", which leaves the coded floor in place —
// so the ZERO CapOverrides changes nothing, which is the safe direction for a
// struct somebody forgot to fill in. A pointer is used rather than a
// zero-means-unset int because 0 is a meaningful (and maximally restrictive)
// configured value and conflating it with "absent" would make the two
// indistinguishable in the audit.
//
// The values are read and copied at the moment Lower runs. A caller that keeps
// its pointers and writes through them afterwards cannot change a Caps that
// was already built — TestCapOverridesAreCopiedNotAliased proves it, because
// the same class of aliasing bug is what the kernel-types review demonstrated in Scope.
type CapOverrides struct {
	RequestsPerSecondPerHost *int
	ConcurrentPerHost        *int
	RequestsPerTargetRun     *int
	WallClockPerTarget       *time.Duration
	BodyBytes                *int64
	Retries                  *int
}

// Lower applies configuration to the caps. It can only tighten.
//
// Each field goes through Cap.Lower, which refuses anything above the CURRENT
// EFFECTIVE value — so a single override above the floor is refused, and so is
// a SEQUENCE of Lower calls walking a cap back up (lower to 4, then "lower" to
// 9). That second property is what makes "no combination of config values can
// raise a cap" true rather than hoped for, and it is the kernel core's Cap that provides
// it; this function's job is to make sure every path into a Caps goes through
// it.
//
// A non-positive value is refused outright. A cap of zero would block every
// request, which is safe, but it is far more likely to be an unset config key
// that decoded to zero than a deliberate instruction, and a gate that cannot
// tell those apart should refuse rather than guess.
func (c Caps) Lower(o CapOverrides) (Caps, GateResult) {
	const g = Gate14HardCaps

	if !c.Constructed() {
		return Caps{}, gateFailed(g, ReasonCapsUnconstructed,
			"these Caps did not come from CodedCaps, so there is no coded floor to lower "+
				"from. A zero Caps permits nothing, and lowering nothing is not an "+
				"operation.")
	}

	var res GateResult
	c.rps, res = lowerInt(c.rps, o.RequestsPerSecondPerHost, "requests per second per host")
	if !res.Passed() {
		return Caps{}, res
	}
	c.concurrent, res = lowerInt(c.concurrent, o.ConcurrentPerHost, "concurrent connections per host")
	if !res.Passed() {
		return Caps{}, res
	}
	c.volume, res = lowerInt(c.volume, o.RequestsPerTargetRun, "requests per target per run")
	if !res.Passed() {
		return Caps{}, res
	}
	c.retries, res = lowerInt(c.retries, o.Retries, "retries")
	if !res.Passed() {
		return Caps{}, res
	}
	if o.WallClockPerTarget != nil {
		v := *o.WallClockPerTarget
		if v <= 0 {
			return Caps{}, capNotPositive("wall clock per target", v.String())
		}
		lowered, err := c.wallClock.Lower(v)
		if err != nil {
			return Caps{}, capRaised("wall clock per target", err)
		}
		c.wallClock = lowered
	}
	if o.BodyBytes != nil {
		v := *o.BodyBytes
		if v <= 0 {
			return Caps{}, capNotPositive("body bytes", strconv.FormatInt(v, 10))
		}
		lowered, err := c.bodyBytes.Lower(v)
		if err != nil {
			return Caps{}, capRaised("body bytes", err)
		}
		c.bodyBytes = lowered
	}
	return c, gatePassed(g)
}

// lowerInt is the shared int arm of Lower.
func lowerInt(c Cap[int], v *int, what string) (Cap[int], GateResult) {
	if v == nil {
		return c, gatePassed(Gate14HardCaps)
	}
	if *v <= 0 {
		return Cap[int]{}, capNotPositive(what, strconv.Itoa(*v))
	}
	lowered, err := c.Lower(*v)
	if err != nil {
		return Cap[int]{}, capRaised(what, err)
	}
	return lowered, gatePassed(Gate14HardCaps)
}

func capRaised(what string, err error) GateResult {
	return gateFailed(Gate14HardCaps, ReasonCapRaiseAttempted,
		"configuration tried to set a gate 14 cap above its coded floor, or to walk one "+
			"back up through a sequence of settings. plan/design/dynamic-tier.md gate 14: caps may "+
			"only be LOWERED; no combination of settings raises any cap above its coded "+
			"floor. The kernel refuses the configuration rather than clamping it, so the "+
			"operator learns that what they wrote is not what would run.",
		"cap:      "+what,
		"refusal:  "+err.Error())
}

func capNotPositive(what, value string) GateResult {
	return gateFailed(Gate14HardCaps, ReasonCapNotPositive,
		"a configured gate 14 cap is zero or negative. Zero would block every request, "+
			"which is safe, but it is far likelier to be a config key that decoded to "+
			"its zero value than a deliberate instruction — and a gate that cannot tell "+
			"those apart refuses rather than guessing.",
		"cap:   "+what,
		"value: "+redactUntrusted(value))
}

// RequestsPerSecondPerHost returns the effective rps cap.
func (c Caps) RequestsPerSecondPerHost() (int, error) { return c.rps.Effective() }

// ConcurrentPerHost returns the effective concurrency cap.
func (c Caps) ConcurrentPerHost() (int, error) { return c.concurrent.Effective() }

// RequestsPerTargetRun returns the effective per-run volume cap.
func (c Caps) RequestsPerTargetRun() (int, error) { return c.volume.Effective() }

// WallClockPerTarget returns the effective per-target wall-clock cap.
func (c Caps) WallClockPerTarget() (time.Duration, error) { return c.wallClock.Effective() }

// BodyBytes returns the effective body-size cap.
func (c Caps) BodyBytes() (int64, error) { return c.bodyBytes.Effective() }

// Retries returns the effective retry cap.
func (c Caps) Retries() (int, error) { return c.retries.Effective() }

// RateLimiter is gate 14's per-target token bucket, concurrency semaphore,
// volume tally and wall clock, in one value.
//
// # The precedence discipline
//
// research/20 gate 14: "Adopt nuclei's precedence discipline — one scalar rate
// cap dominates every concurrency knob, so no combination of settings can
// exceed it." Acquire takes a bucket token BEFORE it takes a concurrency slot,
// and refuses on the token. So a configuration of 4 concurrent connections and
// 1 request per second issues one request per second and not four:
// TestScalarRateCapDominatesConcurrency measures exactly that.
//
// # The clock
//
// Every method takes a Clock. Nothing in here reads the wall clock, which is
// what makes the bucket's behaviour reproducible in a test rather than
// approximately observable. A Clock that moves BACKWARDS is refused: a bucket
// that refills on a negative elapsed time is a bucket that can be refilled by
// lying about the time.
type RateLimiter struct {
	mu         sync.Mutex
	caps       Caps
	start      time.Time
	last       time.Time
	tokens     float64
	inFlight   int
	issued     int
	highWater  int
	capacity   float64
	refillRate float64
	sealed     bool
}

// NewRateLimiter builds a limiter for one target.
//
// The bucket starts FULL, at capacity == the effective rps cap. A full bucket
// permits an initial burst of at most one second's worth of requests, which is
// what "≤10 requests per second" means; it does not permit a burst larger than
// the cap, because capacity never exceeds it.
func NewRateLimiter(caps Caps, start Clock) (*RateLimiter, GateResult) {
	const g = Gate14HardCaps

	if !caps.Constructed() {
		return nil, gateFailed(g, ReasonCapsUnconstructed,
			"the limiter was handed Caps that CodedCaps never built. A zero Caps has six "+
				"undeclared limits, and an undeclared Cap allows nothing — but a limiter "+
				"built on one would refuse for the wrong reason, so it is refused here "+
				"where the message can say which.")
	}
	if !start.Valid() {
		return nil, gateFailed(g, ReasonCapClockWentBack,
			"the limiter was handed a Clock that NewClock never built. The per-target wall "+
				"clock is measured from this instant, and an unset one would make every "+
				"target look either brand new or long expired.")
	}
	rps, err := caps.RequestsPerSecondPerHost()
	if err != nil {
		return nil, gateFailed(g, ReasonCapsUnconstructed,
			"the rate cap inside these Caps was never declared.")
	}
	return &RateLimiter{
		caps:       caps,
		start:      start.Instant(),
		last:       start.Instant(),
		tokens:     float64(rps),
		capacity:   float64(rps),
		refillRate: float64(rps),
		sealed:     true,
	}, gatePassed(g)
}

// Constructed reports whether l came from NewRateLimiter.
func (l *RateLimiter) Constructed() bool { return l != nil && l.sealed }

// Acquire is gate 14 for one request. On a pass the caller holds one
// concurrency slot and must call Release exactly once.
//
// The order is: wall clock, volume, retry budget, RATE, concurrency. The rate
// check is second-to-last and the concurrency check is last, so that the
// scalar cap is what refuses when both would.
func (l *RateLimiter) Acquire(attempt int, now Clock) GateResult {
	const g = Gate14HardCaps

	if !l.Constructed() {
		return gateFailed(g, ReasonLimiterUnconstructed,
			"the rate limiter was never constructed by NewRateLimiter, so it has no bucket, "+
				"no tally and no start instant. A nil limiter does not mean unlimited.")
	}
	if !now.Valid() {
		return gateFailed(g, ReasonCapClockWentBack,
			"Acquire was handed a Clock that NewClock never built.")
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	at := now.Instant()
	if at.Before(l.last) {
		return gateFailed(g, ReasonCapClockWentBack,
			"the clock handed to the limiter is earlier than the last instant it saw. A "+
				"token bucket that refills over a negative interval is a bucket that can "+
				"be refilled by lying about the time, so this refuses rather than "+
				"clamping the interval to zero.")
	}

	elapsed := at.Sub(l.start)
	if !l.caps.wallClock.Allows(elapsed) {
		coded, _ := l.caps.WallClockPerTarget()
		return gateFailed(g, ReasonWallClockExceeded, fmt.Sprintf(
			"this target has been under test for %s and the cap is %s. The wall-clock cap "+
				"is a coded floor; configuration may lower it and nothing raises it.",
			elapsed, coded))
	}
	if !l.caps.volume.Allows(l.issued + 1) {
		coded, _ := l.caps.RequestsPerTargetRun()
		return gateFailed(g, ReasonVolumeExceeded, fmt.Sprintf(
			"this would be request %d against this target in this run and the cap is %d.",
			l.issued+1, coded))
	}
	if attempt < 0 {
		return gateFailed(g, ReasonRetryBudgetExceeded,
			"the attempt number is negative, which is not a retry count.")
	}
	if !l.caps.retries.Allows(attempt) {
		coded, _ := l.caps.Retries()
		return gateFailed(g, ReasonRetryBudgetExceeded, fmt.Sprintf(
			"this is retry %d and the budget is %d retries after the first attempt.",
			attempt, coded))
	}

	// Refill, then spend. The refill is computed from the elapsed interval
	// rather than accumulated per call, so a caller that calls Acquire a
	// million times in one instant gets one instant's worth of tokens.
	l.tokens += at.Sub(l.last).Seconds() * l.refillRate
	if l.tokens > l.capacity {
		l.tokens = l.capacity
	}
	l.last = at

	if l.tokens < 1 {
		coded, _ := l.caps.RequestsPerSecondPerHost()
		return gateFailed(g, ReasonRateExceeded, fmt.Sprintf(
			"the token bucket for this host is empty. The scalar rate cap is %d requests "+
				"per second and it DOMINATES every concurrency setting: a run configured "+
				"for more concurrent connections than the rate cap allows per second "+
				"still issues no more than the rate cap.", coded))
	}

	if !l.caps.concurrent.Allows(l.inFlight + 1) {
		coded, _ := l.caps.ConcurrentPerHost()
		return gateFailed(g, ReasonConcurrencyExceeded, fmt.Sprintf(
			"%d connections to this host are already in flight and the cap is %d.",
			l.inFlight, coded))
	}

	l.tokens--
	l.inFlight++
	l.issued++
	if l.inFlight > l.highWater {
		l.highWater = l.inFlight
	}
	return gatePassed(g)
}

// Release returns one concurrency slot. Releasing more slots than were
// acquired is refused rather than allowed to drive the counter negative — a
// negative in-flight count is how a semaphore silently stops limiting.
func (l *RateLimiter) Release() GateResult {
	const g = Gate14HardCaps

	if !l.Constructed() {
		return gateFailed(g, ReasonLimiterUnconstructed,
			"Release was called on a limiter NewRateLimiter never built.")
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.inFlight <= 0 {
		return gateFailed(g, ReasonConcurrencyExceeded,
			"Release was called with no connection in flight. Driving the in-flight count "+
				"below zero is how a semaphore stops limiting without anything looking "+
				"wrong, so the double release is refused and the count stays at zero.")
	}
	l.inFlight--
	return gatePassed(g)
}

// Issued returns how many requests this limiter has admitted.
func (l *RateLimiter) Issued() int {
	if !l.Constructed() {
		return 0
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.issued
}

// InFlight returns how many connections are currently held.
func (l *RateLimiter) InFlight() int {
	if !l.Constructed() {
		return 0
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.inFlight
}

// PeakInFlight returns the highest in-flight count ever reached. It is the
// measurement a concurrency-cap test asserts against.
func (l *RateLimiter) PeakInFlight() int {
	if !l.Constructed() {
		return 0
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.highWater
}

// Caps returns the caps this limiter enforces.
func (l *RateLimiter) Caps() Caps {
	if !l.Constructed() {
		return Caps{}
	}
	return l.caps
}

// ---------------------------------------------------------------------------
// Gate 14's body cap, enforced WHILE READING
// ---------------------------------------------------------------------------

// ErrBodyExceedsCap is what a BoundedBody's Read returns once the response has
// produced more bytes than gate 14's cap allows.
var ErrBodyExceedsCap = fmt.Errorf("%w: gate14: the body exceeded the coded size cap and "+
	"the read was refused at the byte that crossed it", ErrRefused)

// BoundedBody enforces gate 14's body cap AT READ TIME.
//
// # Why this is not io.ReadAll followed by a length check
//
// Because a 4 GiB response would then be four gigabytes in this process's heap
// before anyone noticed it was too big — and the response body is
// attacker-controlled (the spine's safety section names it "the highest-risk field").
// A resource-exhaustion probe pointed at Anvil is still a
// resource-exhaustion probe.
//
// This reader never asks the underlying reader for more than (cap - consumed +
// 1) bytes. The +1 is what lets it distinguish "exactly at the cap" from "over
// the cap" without reading a second buffer's worth, so at most cap+1 bytes are
// ever pulled from the network no matter how large the response claims to be.
// TestBoundedBodyNeverBuffersAFourGigabyteResponse measures the bytes the
// underlying reader was asked for and asserts that bound.
type BoundedBody struct {
	r        io.Reader
	limit    int64
	consumed int64
	sealed   bool
}

// LimitBody wraps r so that reading past the caps' body limit refuses.
func LimitBody(r io.Reader, caps Caps) (*BoundedBody, GateResult) {
	const g = Gate14HardCaps

	if r == nil {
		return nil, gateFailed(g, ReasonBodyExceedsCap,
			"there is no reader to bound. A nil body is not an unbounded one.")
	}
	if !caps.Constructed() {
		return nil, gateFailed(g, ReasonCapsUnconstructed,
			"LimitBody was handed Caps that CodedCaps never built, so there is no body cap "+
				"to enforce.")
	}
	limit, err := caps.BodyBytes()
	if err != nil || limit <= 0 {
		return nil, gateFailed(g, ReasonCapsUnconstructed,
			"the body cap inside these Caps was never declared, or is not positive.")
	}
	return &BoundedBody{r: r, limit: limit, sealed: true}, gatePassed(g)
}

// Read implements io.Reader. It refuses at the byte that crosses the cap.
func (b *BoundedBody) Read(p []byte) (int, error) {
	if b == nil || !b.sealed {
		return 0, fmt.Errorf("%w: a BoundedBody that LimitBody never built reads nothing",
			ErrUnconstructed)
	}
	// Once the cap has been crossed this reader is finished, and it says so
	// WITHOUT touching the underlying reader again. That is the property this
	// branch holds and it is the only one it holds: a mutation run showed that
	// deleting it does not change any refusal, because `room` can never go
	// negative (consumed rises by at most room per read, so consumed never
	// exceeds limit+1) and the check at the bottom of this function therefore
	// fires on every subsequent call anyway. What it does change is that the
	// underlying reader — a socket, in the shape this file exists for — would
	// be read from again after Anvil had already decided to stop.
	// TestBoundedBodyDoesNotTouchTheReaderAfterItHasRefused is the guard.
	if b.consumed > b.limit {
		return 0, ErrBodyExceedsCap
	}
	// Never ask for more than one byte past the cap. That single extra byte
	// is the whole difference between "we noticed" and "we buffered 4 GiB to
	// find out".
	room := b.limit - b.consumed + 1
	if int64(len(p)) > room {
		p = p[:room]
	}
	n, err := b.r.Read(p)
	b.consumed += int64(n)
	if b.consumed > b.limit {
		return n, ErrBodyExceedsCap
	}
	return n, err
}

// Consumed returns how many bytes have been read so far.
func (b *BoundedBody) Consumed() int64 {
	if b == nil {
		return 0
	}
	return b.consumed
}

// Limit returns the cap being enforced.
func (b *BoundedBody) Limit() int64 {
	if b == nil {
		return 0
	}
	return b.limit
}

// ===========================================================================
// GATE 15 — the destructive-technique denylist, compiled in and static
// ===========================================================================

// Technique names what a probe is trying to do.
//
// # This is a denylist AND an allowlist, and both are load-bearing
//
// plan/design/dynamic-tier.md gate 15 and per-request enforcement's forbidden
// actions both specify a STATIC COMPILED-IN DENYLIST, "never a model
// judgement". That denylist is destructiveTechniques below, and it is what
// produces the specific refusal an operator reads.
//
// This project's standing rule is that a denylist loses, and it is right here
// too: a technique nobody thought to name would arrive PERMITTED under a
// denylist alone. So there is also permittedTechniques, and a Technique on
// NEITHER list is refused. The denylist gives the message; the allowlist is
// what actually holds. Both are package-level functions returning fresh
// slices, so no caller can retain and mutate either.
//
// # The residual risk, stated rather than papered over
//
// Gate 15 judges the DECLARED technique. A caller that labels a table dump
// "proof_of_existence" is not caught by this list, and no static list can
// catch it — that is the price of "never a model judgement", and the
// alternative (an inference layer classifying its own probes) is the thing the
// gate exists to forbid. Two independent things reduce it: the method and
// endpoint checks below do not consult the label at all, and gate 14's caps
// bound what any mislabelled probe can do. Neither closes it.
type Technique string

// The techniques. The zero value names none and is refused.
const (
	// TechniqueUnspecified is the zero value and is not a technique.
	TechniqueUnspecified Technique = ""

	// --- the compiled-in denylist ---

	// TechniqueResourceExhaustion is any probe whose mechanism is to
	// consume the target's resources.
	TechniqueResourceExhaustion Technique = "resource_exhaustion"
	// TechniqueDenialOfService is any availability attack.
	TechniqueDenialOfService Technique = "denial_of_service"
	// TechniqueCredentialBruteForce is password or token guessing.
	TechniqueCredentialBruteForce Technique = "credential_brute_force"
	// TechniquePasswordSpraying is one password against many accounts.
	TechniquePasswordSpraying Technique = "password_spraying"
	// TechniqueAccountLockout is any sequence whose effect is to lock a
	// real account out.
	TechniqueAccountLockout Technique = "authentication_lockout_sequence"
	// TechniqueExploitPastProof is exploitation carried past the point that
	// proves the finding exists — dumping a table rather than reading a
	// canary, opening a shell rather than echoing a benign string.
	TechniqueExploitPastProof Technique = "exploitation_past_proof_of_existence"
	// TechniqueBulkDataExtraction is mass retrieval of real data.
	TechniqueBulkDataExtraction Technique = "bulk_data_extraction"
	// TechniquePersistence is leaving anything behind.
	TechniquePersistence Technique = "persistence"
	// TechniqueLateralMovement is using one host to reach another.
	TechniqueLateralMovement Technique = "lateral_movement"
	// TechniqueDestructiveWrite is any probe whose success destroys or
	// corrupts target state.
	TechniqueDestructiveWrite Technique = "destructive_write"

	// --- the allowlist ---

	// TechniquePassiveObservation reads what the target volunteers.
	TechniquePassiveObservation Technique = "passive_observation"
	// TechniqueVersionFingerprint identifies software and versions.
	TechniqueVersionFingerprint Technique = "version_fingerprint"
	// TechniqueContentDiscovery enumerates paths a site publishes.
	TechniqueContentDiscovery Technique = "content_discovery"
	// TechniqueConfigurationCheck inspects headers, TLS and settings.
	TechniqueConfigurationCheck Technique = "configuration_check"
	// TechniqueProofOfExistence demonstrates a finding and stops: read the
	// canary, echo the benign string, and go no further.
	TechniqueProofOfExistence Technique = "proof_of_existence"
	// TechniqueAuthenticatedRead is a read performed with credentials the
	// operator supplied for the purpose.
	TechniqueAuthenticatedRead Technique = "authenticated_read"
)

// DestructiveTechniques returns the compiled-in denylist, as a FRESH SLICE.
//
// The list is built here from consts rather than stored in a package-level
// var, so there is no variable for anything to reassign and no backing array
// for a caller to write through. TestDestructiveDenylistCannotBeMutated
// mutates the returned slice and asserts the classifier is unmoved.
func DestructiveTechniques() []Technique {
	return []Technique{
		TechniqueResourceExhaustion,
		TechniqueDenialOfService,
		TechniqueCredentialBruteForce,
		TechniquePasswordSpraying,
		TechniqueAccountLockout,
		TechniqueExploitPastProof,
		TechniqueBulkDataExtraction,
		TechniquePersistence,
		TechniqueLateralMovement,
		TechniqueDestructiveWrite,
	}
}

// PermittedTechniques returns the compiled-in allowlist, as a fresh slice.
func PermittedTechniques() []Technique {
	return []Technique{
		TechniquePassiveObservation,
		TechniqueVersionFingerprint,
		TechniqueContentDiscovery,
		TechniqueConfigurationCheck,
		TechniqueProofOfExistence,
		TechniqueAuthenticatedRead,
	}
}

// Destructive reports whether t is on the compiled-in denylist.
func (t Technique) Destructive() bool { return slices.Contains(DestructiveTechniques(), t) }

// Classified reports whether t appears on either compiled-in list. An
// unclassified technique is refused; it is not assumed benign.
func (t Technique) Classified() bool {
	return t.Destructive() || slices.Contains(PermittedTechniques(), t)
}

// EndpointRule names one method-and-path pair an operator explicitly allowed a
// state-changing probe against.
type EndpointRule struct {
	// Method is the state-changing method being allowed.
	Method Method
	// Path is the exact request path. There is no wildcard, no prefix match
	// and no pattern language: gate 15's allow is PER ENDPOINT, and a
	// pattern is how "one endpoint" becomes "a family of endpoints the
	// operator did not enumerate".
	Path string
}

// EndpointAllowance is the set of state-changing endpoints an operator
// explicitly allowed. The zero value allows nothing.
type EndpointAllowance struct {
	rules  map[string]struct{}
	sealed bool
}

// NewEndpointAllowance seals a set of rules.
//
// An EMPTY allowance is legal and is the normal case: it means no
// state-changing probe is permitted anywhere, which is what a run that never
// configured one should get. It is sealed so that Permits can tell "the
// operator allowed nothing" from "nobody built this value" — the same
// distinction per-target admission's RobotsDetermination exists for.
func NewEndpointAllowance(rules ...EndpointRule) (EndpointAllowance, error) {
	set := make(map[string]struct{}, len(rules))
	for i, r := range rules {
		if !r.Method.Recognised() {
			return EndpointAllowance{}, fmt.Errorf("endpoint allowance: %w: rule %d names "+
				"method %q, which is not on the allowlist", ErrRefused, i,
				redactUntrusted(string(r.Method)))
		}
		if !r.Method.ChangesState() {
			return EndpointAllowance{}, fmt.Errorf("endpoint allowance: %w: rule %d allows "+
				"%s, which is a safe method and needs no allowance. A rule that grants "+
				"nothing is a rule somebody wrote by mistake", ErrRefused, i, r.Method)
		}
		if !validRequestPath(r.Path) {
			return EndpointAllowance{}, fmt.Errorf("endpoint allowance: %w: rule %d has a "+
				"path that is empty, does not begin with \"/\", exceeds the coded bound, "+
				"or contains a byte outside printable ASCII", ErrRefused, i)
		}
		if strings.Contains(r.Path, "*") {
			return EndpointAllowance{}, fmt.Errorf("endpoint allowance: %w: rule %d's path "+
				"contains a wildcard. Gate 15's allow is per ENDPOINT; a pattern is how "+
				"one endpoint becomes a family of endpoints nobody enumerated",
				ErrRefused, i)
		}
		set[endpointKey(r.Method, r.Path)] = struct{}{}
	}
	return EndpointAllowance{rules: set, sealed: true}, nil
}

// Constructed reports whether a came from NewEndpointAllowance.
func (a EndpointAllowance) Constructed() bool { return a.sealed && a.rules != nil }

// Permits reports whether this exact method and path were explicitly allowed.
func (a EndpointAllowance) Permits(m Method, path string) bool {
	if !a.Constructed() {
		return false
	}
	_, ok := a.rules[endpointKey(m, path)]
	return ok
}

// Count returns how many endpoints were explicitly allowed.
func (a EndpointAllowance) Count() int {
	if !a.Constructed() {
		return 0
	}
	return len(a.rules)
}

func endpointKey(m Method, path string) string { return string(m) + " " + path }

// CheckGate15DestructiveTechnique is gate 15.
//
// Order matters and is deliberate: the technique is judged before the method,
// so a DoS probe issued with GET is still refused as a DoS probe rather than
// passing because GET is safe.
func CheckGate15DestructiveTechnique(t Technique, m Method, path string, allow EndpointAllowance) GateResult {
	const g = Gate15DestructiveTechniques

	if !t.Classified() {
		return gateFailed(g, ReasonTechniqueUnclassified,
			"this probe's technique appears on neither of gate 15's two compiled-in lists. "+
				"The denylist names what is destructive and the allowlist names what is "+
				"permitted; a technique on neither is refused, because a static list that "+
				"treated everything it had not heard of as safe would be defeated by "+
				"naming a technique something new.",
			"technique: "+redactUntrusted(string(t)))
	}
	if t.Destructive() {
		return gateFailed(g, ReasonTechniqueDestructive,
			"this probe's technique is on gate 15's compiled-in destructive denylist. The "+
				"list is a set of Go constants in the kernel: no environment variable, "+
				"CLI flag, config key or model-authored value reaches it, and nothing "+
				"infers membership — plan/design/dynamic-tier.md gate 15 requires a static list, "+
				"never a model judgement.",
			"technique: "+redactUntrusted(string(t)))
	}
	if !m.Recognised() {
		return gateFailed(g, ReasonTechniqueMethodUnknown,
			"the request names a method that is on neither method allowlist. An unknown "+
				"verb is not a safe verb.",
			"method: "+redactUntrusted(string(m)))
	}
	if !validRequestPath(path) {
		return gateFailed(g, ReasonTechniquePathMalformed,
			"the request path is empty, does not begin with \"/\", exceeds the coded bound, "+
				"or contains a byte outside printable ASCII. Gate 15's endpoint allowance "+
				"is matched on the exact path, and a path it cannot compare is refused "+
				"rather than compared loosely.")
	}
	if m.ChangesState() && !allow.Permits(m, path) {
		return gateFailed(g, ReasonStateChangingWithoutAll,
			"this is a state-changing method against an endpoint no operator explicitly "+
				"allowed. research/20 gate 15: no probes on state-changing endpoints "+
				"(DELETE, PUT, and POST to non-idempotent paths) without a per-endpoint "+
				"explicit allow. An empty allowance is the default and it permits none.",
			"method:   "+redactUntrusted(string(m)),
			"path:     "+redactUntrusted(path),
			"allowed:  "+strconv.Itoa(allow.Count())+" endpoint(s)")
	}
	return gatePassed(g)
}

// ===========================================================================
// GATE 16 — the target-health circuit breaker
// ===========================================================================

// The coded thresholds and windows. plan/design/dynamic-tier.md gate 16: "Trip at 5xx>10%
// or p95>3× baseline sustained 30s; quarantine target for rest of run"; the
// Configurable column says "Thresholds may be tightened; the floor is not
// configurable upward".
const (
	// CodedMaxServerErrorRate is the 5xx-rate ceiling: 10%.
	CodedMaxServerErrorRate = 0.10
	// CodedMaxConnectionErrorRate is the connection-error-rate ceiling.
	// research/20 names connection-error rate as a monitored signal without
	// giving a figure; 10% is the same ceiling as 5xx, chosen because a
	// target refusing one connection in ten is in the same trouble as one
	// answering 500 to one request in ten.
	CodedMaxConnectionErrorRate = 0.10
	// CodedMaxLatencyMultiple is the p95 ceiling as a multiple of the
	// first-60-seconds baseline: 3×.
	CodedMaxLatencyMultiple = 3.0
	// CodedLatencySustainWindow is how long p95 must stay above the
	// multiple before the breaker trips: 30 seconds.
	CodedLatencySustainWindow = 30 * time.Second

	// baselineWindow is the first-60-seconds baseline period.
	baselineWindow = 60 * time.Second
	// minBaselineSamples is how many latency samples the baseline needs
	// before a p95 computed from it means anything. Below this the latency
	// rule is INACTIVE and BaselineEstablished reports false, so an audit
	// row records which rules were live rather than implying all three were.
	minBaselineSamples = 20
	// minRateSamples is the denominator a rate rule needs. One request that
	// answers 500 is a 100% error rate and is not evidence of anything.
	minRateSamples = 20
	// recentLatencyWindow is how far back the "current" p95 looks.
	//
	// It is a TIME window rather than a fixed number of samples, and it is
	// SHORTER than the sustain window, and both of those are load-bearing.
	// p95 over a trailing window of length W stays elevated for roughly W
	// after a spike ends, because the spike's samples are still in the
	// window. If W were 60 seconds, a ten-second spike would hold p95 up for
	// about a minute and the breaker would trip on it — which would make
	// gate 16's "sustained 30 seconds" clause decoration rather than a rule.
	// With W = 10s a ten-second spike keeps p95 up for under 20 seconds and
	// does not trip, while a genuinely sustained elevation trips at 30.
	// TestCircuitBreakerTripsOnSustainedLatencyAndNotOnASpike asserts both
	// halves.
	recentLatencyWindow = 10 * time.Second
	// minRecentSamples is how many samples the current window needs before
	// its p95 is compared against anything. Two samples do not have a 95th
	// percentile.
	minRecentSamples = 5
	// latencyRingCap is a hard bound on the sample set regardless of the
	// time window, so that a very high request rate cannot make it grow
	// without limit. The oldest samples are dropped first.
	latencyRingCap = 4096
	// maxPlausibleLatency bounds one latency sample. A negative or absurd
	// duration is a measurement error, and a breaker fed measurement errors
	// trips on the wrong thing.
	maxPlausibleLatency = 10 * time.Minute
)

// HealthThresholds is gate 16's four thresholds. Same construction rule as
// Caps: unexported fields, one argument-free constructor reading consts, and
// Lower as the only way configuration gets in.
type HealthThresholds struct {
	serverErrorRate     Cap[float64]
	connectionErrorRate Cap[float64]
	latencyMultiple     Cap[float64]
	sustainWindow       Cap[time.Duration]
	sealed              bool
}

// CodedHealthThresholds returns the compiled-in thresholds.
func CodedHealthThresholds() HealthThresholds {
	return HealthThresholds{
		serverErrorRate:     newCap(CodedMaxServerErrorRate),
		connectionErrorRate: newCap(CodedMaxConnectionErrorRate),
		latencyMultiple:     newCap(CodedMaxLatencyMultiple),
		sustainWindow:       newCap(CodedLatencySustainWindow),
		sealed:              true,
	}
}

// Constructed reports whether h came from CodedHealthThresholds.
func (h HealthThresholds) Constructed() bool { return h.sealed }

// ThresholdOverrides is configuration's only way into HealthThresholds. A nil
// field leaves the coded threshold in place.
//
// Every one of the four tightens by getting SMALLER, which is why Cap.Lower is
// the right primitive for all four: a lower 5xx ceiling trips sooner, a lower
// latency multiple trips sooner, and a shorter sustain window trips sooner.
type ThresholdOverrides struct {
	ServerErrorRate     *float64
	ConnectionErrorRate *float64
	LatencyMultiple     *float64
	SustainWindow       *time.Duration
}

// Lower tightens the thresholds. It refuses any attempt to loosen one.
func (h HealthThresholds) Lower(o ThresholdOverrides) (HealthThresholds, GateResult) {
	const g = Gate16CircuitBreaker

	if !h.Constructed() {
		return HealthThresholds{}, gateFailed(g, ReasonMonitorUnconstructed,
			"these thresholds did not come from CodedHealthThresholds, so there is no coded "+
				"floor to tighten from.")
	}
	var err error
	if o.ServerErrorRate != nil {
		if h.serverErrorRate, err = h.serverErrorRate.Lower(*o.ServerErrorRate); err != nil {
			return HealthThresholds{}, thresholdRaised("server error rate", err)
		}
	}
	if o.ConnectionErrorRate != nil {
		if h.connectionErrorRate, err = h.connectionErrorRate.Lower(*o.ConnectionErrorRate); err != nil {
			return HealthThresholds{}, thresholdRaised("connection error rate", err)
		}
	}
	if o.LatencyMultiple != nil {
		if h.latencyMultiple, err = h.latencyMultiple.Lower(*o.LatencyMultiple); err != nil {
			return HealthThresholds{}, thresholdRaised("p95 latency multiple", err)
		}
	}
	if o.SustainWindow != nil {
		if h.sustainWindow, err = h.sustainWindow.Lower(*o.SustainWindow); err != nil {
			return HealthThresholds{}, thresholdRaised("latency sustain window", err)
		}
	}
	return h, gatePassed(g)
}

func thresholdRaised(what string, err error) GateResult {
	return gateFailed(Gate16CircuitBreaker, ReasonThresholdRaise,
		"configuration tried to loosen a gate 16 threshold. plan/design/dynamic-tier.md gate 16: "+
			"thresholds may be tightened; the floor is not configurable upward. A run "+
			"that wants to keep probing a target answering 500 to a third of its "+
			"requests is asking for the breaker to be removed, not adjusted.",
		"threshold: "+what,
		"refusal:   "+err.Error())
}

// ServerErrorRate returns the effective 5xx-rate ceiling.
func (h HealthThresholds) ServerErrorRate() (float64, error) { return h.serverErrorRate.Effective() }

// ConnectionErrorRate returns the effective connection-error-rate ceiling.
func (h HealthThresholds) ConnectionErrorRate() (float64, error) {
	return h.connectionErrorRate.Effective()
}

// LatencyMultiple returns the effective p95 multiple.
func (h HealthThresholds) LatencyMultiple() (float64, error) { return h.latencyMultiple.Effective() }

// SustainWindow returns the effective sustain window.
func (h HealthThresholds) SustainWindow() (time.Duration, error) { return h.sustainWindow.Effective() }

// HealthMonitor is gate 16's per-target circuit breaker.
//
// Once it trips, the target is QUARANTINED FOR THE REST OF THE RUN. There is
// no reset method, no half-open state and no exported field to clear: a
// breaker that can be re-closed by the code that tripped it is a breaker whose
// job is done by whoever calls it last.
type HealthMonitor struct {
	mu         sync.Mutex
	target     Target
	thresholds HealthThresholds
	start      time.Time
	last       time.Time

	baseline      []time.Duration
	baselineP95   time.Duration
	baselineFixed bool

	recent []latencySample

	total       int
	serverError int
	connError   int

	elevatedSince time.Time
	elevated      bool

	tripped    bool
	tripReason Reason
	tripDetail string
	trippedAt  time.Time

	sealed bool
}

// NewHealthMonitor starts a breaker for one target.
func NewHealthMonitor(target Target, thresholds HealthThresholds, start Clock) (*HealthMonitor, GateResult) {
	const g = Gate16CircuitBreaker

	if !target.Constructed() {
		return nil, gateFailed(g, ReasonMonitorUnconstructed,
			"the breaker was handed a Target that NewTarget never built, so the incident it "+
				"would eventually write could not name what it quarantined.")
	}
	if !thresholds.Constructed() {
		return nil, gateFailed(g, ReasonMonitorUnconstructed,
			"the breaker was handed HealthThresholds that CodedHealthThresholds never "+
				"built. A zero HealthThresholds has four undeclared Caps, and an "+
				"undeclared Cap's Allows is false for every value — so the breaker would "+
				"trip on the first observation, for the wrong reason.")
	}
	if !start.Valid() {
		return nil, gateFailed(g, ReasonMonitorUnconstructed,
			"the breaker was handed a Clock that NewClock never built. The 60-second "+
				"baseline window is measured from this instant.")
	}
	return &HealthMonitor{
		target:     target,
		thresholds: thresholds,
		start:      start.Instant(),
		last:       start.Instant(),
		recent:     make([]latencySample, 0, minRecentSamples),
		sealed:     true,
	}, gatePassed(g)
}

// Constructed reports whether m came from NewHealthMonitor.
func (m *HealthMonitor) Constructed() bool { return m != nil && m.sealed }

// ObserveResponse records one completed response and re-evaluates the breaker.
//
// It returns the gate's verdict AFTER the observation: a refusal means the
// breaker has tripped and the target is quarantined from here on.
func (m *HealthMonitor) ObserveResponse(status int, latency time.Duration, now Clock) GateResult {
	const g = Gate16CircuitBreaker

	if !m.Constructed() {
		return gateFailed(g, ReasonMonitorUnconstructed,
			"ObserveResponse was called on a breaker NewHealthMonitor never built. A nil "+
				"breaker is not a healthy target.")
	}
	if status < 100 || status > 599 {
		return gateFailed(g, ReasonObservationMalformed, fmt.Sprintf(
			"status %d is not an HTTP status code. A breaker fed measurements it cannot "+
				"interpret trips on the wrong thing, so the observation is refused rather "+
				"than counted as a success.", status))
	}
	if latency < 0 || latency > maxPlausibleLatency {
		return gateFailed(g, ReasonObservationMalformed, fmt.Sprintf(
			"a latency of %s is a measurement error, not a measurement. The plausible "+
				"range is 0..%s.", latency, maxPlausibleLatency))
	}
	return m.observe(status, latency, true, now)
}

// ObserveConnectionError records one failed connection attempt.
func (m *HealthMonitor) ObserveConnectionError(now Clock) GateResult {
	const g = Gate16CircuitBreaker

	if !m.Constructed() {
		return gateFailed(g, ReasonMonitorUnconstructed,
			"ObserveConnectionError was called on a breaker NewHealthMonitor never built.")
	}
	return m.observe(0, 0, false, now)
}

// observe is the shared body. hasResponse distinguishes a response (whose
// status and latency count) from a connection error (which has neither).
func (m *HealthMonitor) observe(status int, latency time.Duration, hasResponse bool, now Clock) GateResult {
	const g = Gate16CircuitBreaker

	if !now.Valid() {
		return gateFailed(g, ReasonBreakerClockWentBack,
			"the breaker was handed a Clock that NewClock never built.")
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	if m.tripped {
		return m.quarantinedLocked()
	}

	at := now.Instant()
	if at.Before(m.last) {
		return gateFailed(g, ReasonBreakerClockWentBack,
			"the clock handed to the breaker is earlier than the last instant it saw. A "+
				"sustained-elevation window measured over a clock that moves backwards "+
				"can be kept open forever, so this refuses rather than reordering.")
	}
	m.last = at

	m.total++
	switch {
	case !hasResponse:
		m.connError++
	case status >= 500:
		m.serverError++
	}

	if hasResponse {
		if at.Sub(m.start) < baselineWindow && !m.baselineFixed {
			m.baseline = append(m.baseline, latency)
		} else {
			m.fixBaselineLocked()
		}
		m.pushRecentLocked(at, latency)
	} else if at.Sub(m.start) >= baselineWindow {
		m.fixBaselineLocked()
	}

	// Rate rules. Both need a denominator: one request that answers 500 is a
	// 100% error rate and is evidence of nothing.
	if m.total >= minRateSamples {
		ceiling, err := m.thresholds.ServerErrorRate()
		if err == nil {
			if rate := float64(m.serverError) / float64(m.total); rate > ceiling {
				return m.tripLocked(ReasonBreakerServerErrors, fmt.Sprintf(
					"%d of %d requests to this target answered 5xx (%.1f%%) and the "+
						"threshold is %.1f%%. plan/design/dynamic-tier.md gate 16 trips here and "+
						"quarantines the target for the rest of the run; research/20 "+
						"calls the breaker \"the mechanical evidence that Anvil operates "+
						"in a manner designed to avoid any harm\".",
					m.serverError, m.total, rate*100, ceiling*100), at)
			}
		}
		ceiling, err = m.thresholds.ConnectionErrorRate()
		if err == nil {
			if rate := float64(m.connError) / float64(m.total); rate > ceiling {
				return m.tripLocked(ReasonBreakerConnErrors, fmt.Sprintf(
					"%d of %d attempts against this target failed to connect (%.1f%%) and "+
						"the threshold is %.1f%%. A target that has stopped accepting "+
						"connections is a target Anvil is harming or has already harmed.",
					m.connError, m.total, rate*100, ceiling*100), at)
			}
		}
	}

	// The latency rule, which is INACTIVE until a baseline exists. See
	// minBaselineSamples: a p95 over three samples is not a p95, and a
	// breaker that trips on one is a breaker that quarantines healthy
	// targets. BaselineEstablished reports which state the monitor is in so
	// that an audit row can say which rules were live.
	if m.baselineFixed && m.baselineP95 > 0 {
		multiple, err := m.thresholds.LatencyMultiple()
		window, werr := m.thresholds.SustainWindow()
		if err == nil && werr == nil {
			current := m.currentP95Locked()
			ceiling := time.Duration(float64(m.baselineP95) * multiple)
			if current > ceiling {
				if !m.elevated {
					m.elevated = true
					m.elevatedSince = at
				}
				if at.Sub(m.elevatedSince) >= window {
					return m.tripLocked(ReasonBreakerLatency, fmt.Sprintf(
						"this target's p95 latency has been %s — more than %.1f× the "+
							"first-60-seconds baseline of %s — continuously for %s, and "+
							"the sustain window is %s.",
						current, multiple, m.baselineP95, at.Sub(m.elevatedSince), window), at)
				}
			} else {
				m.elevated = false
				m.elevatedSince = time.Time{}
			}
		}
	}

	return gatePassed(g)
}

// fixBaselineLocked freezes the baseline p95 the first time the 60-second
// window closes. If too few samples were taken the baseline stays UNSET and
// the latency rule never fires — which BaselineEstablished reports.
func (m *HealthMonitor) fixBaselineLocked() {
	if m.baselineFixed {
		return
	}
	m.baselineFixed = true
	if len(m.baseline) < minBaselineSamples {
		m.baselineP95 = 0
		return
	}
	m.baselineP95 = percentile(m.baseline, 0.95)
}

// latencySample is one observed latency and when it was observed.
type latencySample struct {
	at time.Time
	d  time.Duration
}

// pushRecentLocked adds one latency and evicts everything outside the current
// window, by time first and by count second.
func (m *HealthMonitor) pushRecentLocked(at time.Time, d time.Duration) {
	m.recent = append(m.recent, latencySample{at: at, d: d})
	cutoff := at.Add(-recentLatencyWindow)
	drop := 0
	for drop < len(m.recent) && m.recent[drop].at.Before(cutoff) {
		drop++
	}
	if over := len(m.recent) - drop - latencyRingCap; over > 0 {
		drop += over
	}
	if drop > 0 {
		m.recent = append(m.recent[:0], m.recent[drop:]...)
	}
}

// currentP95Locked is the p95 of the current window, or zero when the window
// holds too few samples for a 95th percentile to mean anything. Zero never
// exceeds a positive ceiling, so too-few-samples reads as "not elevated"
// rather than as "elevated" — which is the direction that does not quarantine
// a healthy target on the strength of two measurements.
func (m *HealthMonitor) currentP95Locked() time.Duration {
	if len(m.recent) < minRecentSamples {
		return 0
	}
	ds := make([]time.Duration, len(m.recent))
	for i, s := range m.recent {
		ds[i] = s.d
	}
	return percentile(ds, 0.95)
}

// tripLocked trips the breaker and records the incident.
func (m *HealthMonitor) tripLocked(r Reason, detail string, at time.Time) GateResult {
	m.tripped = true
	m.tripReason = r
	m.tripDetail = detail
	m.trippedAt = at
	return gateFailed(Gate16CircuitBreaker, r, detail,
		"target: "+redactedOrigin(m.target),
		"tripped at: "+at.UTC().Format(time.RFC3339))
}

func (m *HealthMonitor) quarantinedLocked() GateResult {
	return gateFailed(Gate16CircuitBreaker, ReasonTargetQuarantined,
		"this target is quarantined for the rest of the run. The circuit breaker tripped "+
			"and there is no path back: no reset method, no half-open state, no exported "+
			"field to clear. A breaker the caller can re-close is a breaker whose job is "+
			"done by whoever calls it last.",
		"target:      "+redactedOrigin(m.target),
		"tripped for: "+string(m.tripReason),
		"incident:    "+m.tripDetail)
}

// CheckGate16CircuitBreaker is gate 16 asked as a question rather than fed an
// observation: may this target still be probed.
func CheckGate16CircuitBreaker(m *HealthMonitor) GateResult {
	const g = Gate16CircuitBreaker

	if !m.Constructed() {
		return gateFailed(g, ReasonMonitorUnconstructed,
			"there is no health monitor for this target. A target nobody is monitoring is "+
				"not a target known to be healthy — docs/controls.md records "+
				"two incidents in this repository where \"we did not look\" was read as "+
				"\"we looked and it was fine\".")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.tripped {
		return m.quarantinedLocked()
	}
	return gatePassed(g)
}

// Tripped reports whether the breaker has tripped.
func (m *HealthMonitor) Tripped() bool {
	if !m.Constructed() {
		return false
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.tripped
}

// Incident returns the trip reason and detail for the audit record, or
// ReasonUnspecified if the breaker has not tripped.
func (m *HealthMonitor) Incident() (Reason, string, time.Time) {
	if !m.Constructed() {
		return ReasonUnspecified, "", time.Time{}
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.tripped {
		return ReasonUnspecified, "", time.Time{}
	}
	return m.tripReason, m.tripDetail, m.trippedAt
}

// BaselineEstablished reports whether the first-60-seconds baseline collected
// enough samples for the p95 rule to be live. When it is false the 5xx and
// connection-error rules are the only ones running, and an audit row should
// say so rather than implying all three were.
func (m *HealthMonitor) BaselineEstablished() bool {
	if !m.Constructed() {
		return false
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.baselineFixed && m.baselineP95 > 0
}

// BaselineP95 returns the frozen baseline p95, or zero if none was
// established.
func (m *HealthMonitor) BaselineP95() time.Duration {
	if !m.Constructed() {
		return 0
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.baselineP95
}

// Observations returns the total, 5xx and connection-error counts.
func (m *HealthMonitor) Observations() (total, serverErrors, connErrors int) {
	if !m.Constructed() {
		return 0, 0, 0
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.total, m.serverError, m.connError
}

// percentile returns the p-th percentile of a sample set, by the
// nearest-rank method on a sorted COPY. It returns zero for an empty set,
// which every caller checks before comparing.
func percentile(samples []time.Duration, p float64) time.Duration {
	if len(samples) == 0 {
		return 0
	}
	sorted := append([]time.Duration(nil), samples...)
	slices.Sort(sorted)
	rank := int(float64(len(sorted))*p + 0.999999)
	if rank < 1 {
		rank = 1
	}
	if rank > len(sorted) {
		rank = len(sorted)
	}
	return sorted[rank-1]
}

// ===========================================================================
// GATE 17 — 429 and Retry-After, honoured as ABSOLUTE
// ===========================================================================

const (
	// CodedTooManyRequestsAbortCount is how many 429s abort a target.
	// research/20 gate 17: "three 429s abort the target".
	CodedTooManyRequestsAbortCount = 3
	// codedDefaultRetryAfter is the backoff applied when a 429 arrives with
	// no Retry-After, or with one that will not parse. It is deliberately
	// LONGER than a typical server would ask for: an unreadable instruction
	// to slow down is not an absent one.
	codedDefaultRetryAfter = 60 * time.Second
	// codedMinRetryAfter is the floor applied to a parsed Retry-After. A
	// hostile or broken target answering "Retry-After: 0" is not permission
	// to retry immediately.
	codedMinRetryAfter = 1 * time.Second
	// codedMaxRetryAfter bounds a parsed Retry-After. Anything longer is
	// treated as an instruction to stop for the run, which is the
	// fail-closed direction: honouring it literally and honouring it by
	// abandoning the target differ only in how long Anvil waits to do
	// nothing.
	codedMaxRetryAfter = 24 * time.Hour
)

// ErrRetryAfterUnparseable is returned by ParseRetryAfter for a header value
// that is absent, malformed, or outside the coded bound.
var ErrRetryAfterUnparseable = fmt.Errorf("%w: gate17: the Retry-After header could not be "+
	"read as a delta-seconds value or an HTTP-date", ErrRefused)

// ErrRetryAfterTooLong is returned for a Retry-After beyond codedMaxRetryAfter.
var ErrRetryAfterTooLong = fmt.Errorf("%w: gate17: the Retry-After value is longer than the "+
	"coded bound and is treated as an instruction to stop for the run", ErrRefused)

// ParseRetryAfter turns a Retry-After header value into a duration.
//
// RFC 9110 section 10.2.3 gives two forms and this accepts both: delta-seconds
// (a non-negative integer) and an HTTP-date. The header comes FROM THE TARGET
// and is therefore `anvil/trust: untrusted` — so the parse is strict, the
// value is bounded at both ends, and nothing from it is interpolated into a
// Detail string.
//
// The lower clamp is a control, not tidiness. "Retry-After: 0" from a target
// under load, or an HTTP-date already in the past, would otherwise mean "retry
// immediately", which is the one instruction a rate-limit response cannot be
// asking for. The result is never below codedMinRetryAfter.
func ParseRetryAfter(value string, now Clock) (time.Duration, error) {
	if !now.Valid() {
		return 0, fmt.Errorf("%w: gate17: no clock", ErrUnconstructed)
	}
	v := strings.TrimSpace(value)
	if v == "" {
		return 0, ErrRetryAfterUnparseable
	}
	if len(v) > 128 {
		return 0, ErrRetryAfterUnparseable
	}

	if secs, err := strconv.ParseInt(v, 10, 64); err == nil {
		if secs < 0 {
			return 0, ErrRetryAfterUnparseable
		}
		if secs > int64(codedMaxRetryAfter/time.Second) {
			return 0, ErrRetryAfterTooLong
		}
		return clampRetryAfter(time.Duration(secs) * time.Second), nil
	}

	when, err := http.ParseTime(v)
	if err != nil {
		return 0, ErrRetryAfterUnparseable
	}
	d := when.Sub(now.Instant())
	if d > codedMaxRetryAfter {
		return 0, ErrRetryAfterTooLong
	}
	return clampRetryAfter(d), nil
}

func clampRetryAfter(d time.Duration) time.Duration {
	if d < codedMinRetryAfter {
		return codedMinRetryAfter
	}
	return d
}

// BackoffLedger is gate 17's per-target 429 record.
//
// # "Absolute, not advisory" is a structure here, not an adjective
//
// There is no exported field, no Clear, no Reset and no "force" argument
// anywhere on this type. The only way the window closes is for the Clock the
// caller passes to CheckGate17RetryAfter to reach the deadline. A caller that
// wants to retry early has nothing to call.
type BackoffLedger struct {
	mu       sync.Mutex
	target   Target
	count429 int
	until    time.Time
	open     bool
	aborted  bool
	last     time.Time
	sealed   bool
}

// NewBackoffLedger starts a ledger for one target.
func NewBackoffLedger(target Target, start Clock) (*BackoffLedger, GateResult) {
	const g = Gate17RetryAfter

	if !target.Constructed() {
		return nil, gateFailed(g, ReasonLedgerUnconstructed,
			"the ledger was handed a Target that NewTarget never built, so a 429 recorded "+
				"in it would not name what had asked Anvil to slow down.")
	}
	if !start.Valid() {
		return nil, gateFailed(g, ReasonLedgerUnconstructed,
			"the ledger was handed a Clock that NewClock never built.")
	}
	return &BackoffLedger{target: target, last: start.Instant(), sealed: true}, gatePassed(g)
}

// Constructed reports whether b came from NewBackoffLedger.
func (b *BackoffLedger) Constructed() bool { return b != nil && b.sealed }

// Observe429 records a 429 and opens the backoff window.
//
// It ALWAYS returns a refusal: a 429 is the target saying not now, and there
// is no shape of Retry-After header that turns one into permission. The third
// 429 aborts the target for the rest of the run.
//
// header may be nil; a 429 with no Retry-After gets codedDefaultRetryAfter.
func (b *BackoffLedger) Observe429(header http.Header, now Clock) GateResult {
	const g = Gate17RetryAfter

	if !b.Constructed() {
		return gateFailed(g, ReasonLedgerUnconstructed,
			"Observe429 was called on a ledger NewBackoffLedger never built. A 429 nobody "+
				"recorded is a 429 nobody will count towards the three that abort.")
	}
	if !now.Valid() {
		return gateFailed(g, ReasonLedgerClockWentBack,
			"Observe429 was handed a Clock that NewClock never built.")
	}

	b.mu.Lock()
	defer b.mu.Unlock()

	at := now.Instant()
	if at.Before(b.last) {
		return gateFailed(g, ReasonLedgerClockWentBack,
			"the clock handed to the ledger is earlier than the last instant it saw. A "+
				"Retry-After deadline measured against a clock that moves backwards is a "+
				"deadline that can be stepped over.")
	}
	b.last = at

	raw := ""
	if header != nil {
		raw = header.Get("Retry-After")
	}

	wait, err := ParseRetryAfter(raw, now)
	reason := ReasonServerSaid429
	note := ""
	switch {
	case errors.Is(err, ErrRetryAfterTooLong):
		b.aborted = true
		b.count429++
		return gateFailed(g, ReasonRetryAfterAbsurd, fmt.Sprintf(
			"the target answered 429 with a Retry-After longer than the coded bound of %s. "+
				"Anvil treats that as an instruction to stop probing this target for the "+
				"rest of the run rather than as a timer to sit on: waiting a day and "+
				"abandoning the target differ only in how long Anvil waits to do nothing.",
			codedMaxRetryAfter),
			"target: "+redactedOrigin(b.target))
	case err != nil:
		wait = codedDefaultRetryAfter
		reason = ReasonRetryAfterUnparseable
		note = fmt.Sprintf("no readable Retry-After was supplied, so the coded default of "+
			"%s applies. An unreadable instruction to slow down is not an absent one.",
			codedDefaultRetryAfter)
	}

	b.count429++
	deadline := at.Add(wait)
	if !b.open || deadline.After(b.until) {
		b.until = deadline
		b.open = true
	}

	if b.count429 >= CodedTooManyRequestsAbortCount {
		b.aborted = true
		return gateFailed(g, ReasonThreeTooManyRequests, fmt.Sprintf(
			"this target has answered 429 %d times and the coded limit is %d. research/20 "+
				"gate 17: three 429s abort the target. The count is a const in the "+
				"kernel; no configuration reaches it, and there is no method on this "+
				"ledger that lowers it back.",
			b.count429, CodedTooManyRequestsAbortCount),
			"target: "+redactedOrigin(b.target))
	}

	detail := fmt.Sprintf("the target answered 429 and asked for %s. Gate 17 honours "+
		"Retry-After as ABSOLUTE, not advisory: no request is issued to this target "+
		"before the deadline, and there is no method on this ledger that shortens it. "+
		"This is 429 number %d of %d before the target is aborted.",
		wait, b.count429, CodedTooManyRequestsAbortCount)
	if note != "" {
		detail = detail + " " + note
	}
	return gateFailed(g, reason, detail,
		"target:   "+redactedOrigin(b.target),
		"until:    "+b.until.UTC().Format(time.RFC3339))
}

// CheckGate17RetryAfter is gate 17: may a request be issued to this target now.
func CheckGate17RetryAfter(b *BackoffLedger, now Clock) GateResult {
	const g = Gate17RetryAfter

	if !b.Constructed() {
		return gateFailed(g, ReasonLedgerUnconstructed,
			"there is no 429 ledger for this target. A target nobody is counting 429s for "+
				"is not a target known to be accepting requests.")
	}
	if !now.Valid() {
		return gateFailed(g, ReasonLedgerClockWentBack,
			"CheckGate17RetryAfter was handed a Clock that NewClock never built.")
	}

	b.mu.Lock()
	defer b.mu.Unlock()

	if b.aborted {
		return gateFailed(g, ReasonThreeTooManyRequests, fmt.Sprintf(
			"this target was aborted after %d 429 response(s) and is not probed again in "+
				"this run.", b.count429),
			"target: "+redactedOrigin(b.target))
	}
	at := now.Instant()
	if at.Before(b.last) {
		return gateFailed(g, ReasonLedgerClockWentBack,
			"the clock handed to the ledger is earlier than the last instant it saw.")
	}
	if b.open && at.Before(b.until) {
		return gateFailed(g, ReasonInsideRetryAfter, fmt.Sprintf(
			"the target asked Anvil to wait until %s and it is %s. Retry-After is honoured "+
				"for the FULL duration; there is no partial backoff, no jitter that "+
				"shortens it and no method that clears it.",
			b.until.UTC().Format(time.RFC3339), at.UTC().Format(time.RFC3339)))
	}
	if b.open && !at.Before(b.until) {
		b.open = false
	}
	return gatePassed(g)
}

// TooManyRequests returns how many 429s this target has answered.
func (b *BackoffLedger) TooManyRequests() int {
	if !b.Constructed() {
		return 0
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.count429
}

// Aborted reports whether the target has been aborted for the run.
func (b *BackoffLedger) Aborted() bool {
	if !b.Constructed() {
		return false
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.aborted
}

// BackoffUntil returns the open deadline, and whether one is open.
func (b *BackoffLedger) BackoffUntil() (time.Time, bool) {
	if !b.Constructed() {
		return time.Time{}, false
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.until, b.open
}

// ===========================================================================
// THE PER-REQUEST INTERCEPTOR
// ===========================================================================

// Governor is Phase 3 for one target: gates 13, 14, 15, 16 and 17, plus per-target admission's
// gate 11, in one value with one order.
//
// Per-request enforcement's expected output schema asks for "a per-request interceptor". This is
// it. The point of having one is that a request layer cannot enforce four of
// the five gates and forget the fifth: there is a single Admit call, and every
// gate is inside it.
type Governor struct {
	mu       sync.Mutex
	target   Target
	limiter  *RateLimiter
	health   *HealthMonitor
	backoff  *BackoffLedger
	robots   RobotsPolicy
	scope    Scope
	att      Attestation
	allow    EndpointAllowance
	admitted int
	refused  int
	sealed   bool
}

// GovernorConfig is everything a Governor needs to exist. Every field is
// required; there is no default for any of them, because a default here would
// be a gate that ran against a value nobody chose.
type GovernorConfig struct {
	// Target is the target Phase 2 admitted.
	Target Target
	// Scope and Attestation are the run's, re-checked per request by gate 13.
	Scope       Scope
	Attestation Attestation
	// Caps and Thresholds are gate 14's and gate 16's, already lowered by
	// configuration if it lowered them.
	Caps       Caps
	Thresholds HealthThresholds
	// Robots is per-target admission's determined policy for this origin, consulted per
	// request by gate 11. A RobotsUnset policy refuses every path, which is
	// gate 11's fail-closed behaviour and not this type's business to
	// soften.
	Robots RobotsPolicy
	// Allowance is gate 15's per-endpoint allow set. The zero value is
	// legal: it allows no state-changing probe anywhere.
	Allowance EndpointAllowance
	// Start is the instant the target's clocks begin.
	Start Clock
}

// NewGovernor assembles the per-target enforcement state.
func NewGovernor(cfg GovernorConfig) (*Governor, GateResult) {
	limiter, res := NewRateLimiter(cfg.Caps, cfg.Start)
	if !res.Passed() {
		return nil, res
	}
	health, res := NewHealthMonitor(cfg.Target, cfg.Thresholds, cfg.Start)
	if !res.Passed() {
		return nil, res
	}
	backoff, res := NewBackoffLedger(cfg.Target, cfg.Start)
	if !res.Passed() {
		return nil, res
	}
	if !cfg.Scope.Constructed() {
		return nil, gateFailed(Gate13RevalidateEveryRequest, ReasonScopeUnconstructed,
			"the governor was handed a Scope that NewScope never built, so gate 13 would "+
				"have nothing to re-validate each request against.")
	}
	if !cfg.Attestation.Constructed() {
		return nil, gateFailed(Gate13RevalidateEveryRequest, ReasonAttestationUnconstructed,
			"the governor was handed an Attestation that NewAttestation never built.")
	}
	return &Governor{
		target:  cfg.Target,
		limiter: limiter,
		health:  health,
		backoff: backoff,
		robots:  cfg.Robots,
		scope:   cfg.Scope,
		att:     cfg.Attestation,
		allow:   cfg.Allowance,
		sealed:  true,
	}, gatePassed(Gate13RevalidateEveryRequest)
}

// Constructed reports whether g came from NewGovernor.
func (g *Governor) Constructed() bool { return g != nil && g.sealed }

// Lease is one admitted request's hold on a concurrency slot.
//
// A Lease that was never granted holds nothing, and Release on it is a no-op
// rather than a decrement — releasing a slot nobody took is how a semaphore's
// count drifts until it stops limiting.
type Lease struct {
	gov     *Governor
	granted bool
	done    bool
}

// Held reports whether this lease holds a concurrency slot.
func (l *Lease) Held() bool { return l != nil && l.granted && !l.done }

// Release returns the concurrency slot. It is idempotent.
func (l *Lease) Release() {
	if l == nil || !l.granted || l.done {
		return
	}
	l.done = true
	l.gov.limiter.Release()
}

// Admit is the per-request interceptor.
//
// # The order, and why it is this order
//
//	gate 16  is the target quarantined? Nothing else matters if it is.
//	gate 17  is a Retry-After window open, or was the target aborted?
//	gate 13  is this request's actual destination still in scope, on this
//	         hop, after this redirect?
//	gate 11  does the site's own robots.txt remove this path?
//	gate 15  is this technique and this method permitted here?
//	gate 14  is there budget — and, only here, SPEND it.
//
// Gate 14 is last because it is the only gate that consumes something. A
// request that gate 13 was going to refuse should not first burn a token out
// of the target's rate budget, and a refusal that spent budget would let a
// caller drain a target's allowance with requests that were never issued.
func (g *Governor) Admit(intent RequestIntent, t Technique, now Clock) (*Lease, GateResult) {
	lease, trace := g.AdmitTraced(intent, t, now)
	return lease, LastResult(trace)
}

// AdmitTraced is Admit with the whole trace.
//
// It returns ONE GateResult PER GATE CONSULTED, in the order they ran, and
// stops at the first refusal. The kernel-types review made this point against
// Adjudicate's audit writer — gate 21 asks for "an immutable audit of every
// gate decision" and a single row naming the last gate records one gate in
// eight. The audit path for Phase 3 therefore gets the whole trace and can
// write a row for each, and TestAdmitTraceNamesEveryGateInOrder is the guard
// that fails if a future edit drops a gate out of the interceptor: it asserts
// the exact ordered gate list, so removing a call changes the trace rather
// than passing silently.
//
// governorGateOrder is the same list, declared separately, so the test
// compares the interceptor against a written-down expectation rather than
// against itself.
func (g *Governor) AdmitTraced(intent RequestIntent, t Technique, now Clock) (*Lease, []GateResult) {
	if !g.Constructed() {
		return &Lease{}, []GateResult{
			gateFailed(Gate13RevalidateEveryRequest, ReasonRequestIntentUnbuilt,
				"Admit was called on a Governor NewGovernor never built. A nil governor "+
					"enforces nothing, and enforcing nothing is not admitting everything."),
		}
	}

	g.mu.Lock()
	defer g.mu.Unlock()

	trace := governorChain.run(g, intent, t, now)
	if len(trace) > 0 && !trace[len(trace)-1].Passed() {
		g.refused++
		return &Lease{}, trace
	}
	if len(trace) != len(governorGateOrder) {
		// The chain returned short without a refusal at the end. That cannot
		// happen through requestChain.run, which either runs every step or
		// terminates on a failing one, and it is handled anyway because a
		// truncated trace is a set of gates that were not consulted.
		g.refused++
		return &Lease{}, append(trace, gateFailed(Gate13RevalidateEveryRequest,
			ReasonRequestIntentUnbuilt,
			"the per-request chain returned fewer results than it has gates and none of "+
				"them was a refusal. A request that skipped a gate is refused."))
	}

	g.admitted++
	return &Lease{gov: g, granted: true}, trace
}

// ---------------------------------------------------------------------------
// requestChain — the per-request chain type, distinct from gateFunc
// ---------------------------------------------------------------------------

// requestGateFunc is the signature of a PER-REQUEST enforcement step.
//
// # Why this type exists at all
//
// Gates 13–17 are not in kernel.go's admissionChain, and the reason is
// structural: a gateFunc's world is `(Target, Scope, Attestation, Clock)` and
// not one of the five is a function of those four values. Gate 13 needs THIS
// hop and the request's origin; gate 14 needs a mutable token bucket; gate 15
// needs the technique and the method; gate 16 needs observed health; gate 17
// needs the 429 ledger.
//
// Declining to register them was correct, but AN UNREGISTERED GATE AND A
// FORGOTTEN GATE ARE INDISTINGUISHABLE BY INSPECTION, and this project's method
// is that a control which can silently stop existing eventually does. So
// per-request enforcement gets its OWN CHAIN TYPE. The separation now lives in
// the type system: a requestGateFunc is not assignable to a gateFunc and cannot
// be handed to register, kernel.go's registerInto refuses a Phase 3 gate
// outright with a message naming this file, and
// TestNoPhase3GateIsInAnAdmissionChain fails the build if one is added to a
// chain over there.
//
// The Governor is the first argument rather than a captured variable so that
// the chain is a package-level value a test can enumerate, rather than a slice
// of closures rebuilt inside Admit where only Admit can see it.
type requestGateFunc func(g *Governor, intent RequestIntent, t Technique, now Clock) GateResult

// requestGate is one declared step of the per-request chain: the gate it is,
// and the function that runs it.
type requestGate struct {
	gate GateID
	run  requestGateFunc
}

// requestChain is the ordered per-request enforcement chain.
type requestChain []requestGate

// run executes the chain, returning ONE GateResult PER GATE CONSULTED in the
// order they ran and stopping at the first refusal.
//
// It mirrors kernel.go's chain.run in the two ways that matter and differs in
// the one that matters most: an EMPTY chain refuses, a result attributed to a
// gate other than the one that was called refuses, and the four admission
// inputs are nowhere in the signature.
func (c requestChain) run(g *Governor, intent RequestIntent, t Technique, now Clock) []GateResult {
	if len(c) == 0 {
		return []GateResult{gateFailed(Gate13RevalidateEveryRequest, ReasonRequestIntentUnbuilt,
			"the per-request enforcement chain is empty, and an empty chain enforces "+
				"nothing. Enforcing nothing is not admitting everything.")}
	}
	trace := make([]GateResult, 0, len(c))
	for _, step := range c {
		if step.run == nil {
			return append(trace, gateFailed(step.gate, ReasonRequestIntentUnbuilt, fmt.Sprintf(
				"%s is declared in the per-request chain with no implementation. A gate "+
					"with nothing behind it is a REFUSAL, never a skipped step.", step.gate)))
		}
		res := step.run(g, intent, t, now)
		if res.Gate() != step.gate {
			return append(trace, gateFailed(step.gate, ReasonRequestIntentUnbuilt, fmt.Sprintf(
				"the step declared for %s returned a result attributed to %s; the "+
					"interceptor does not act on a result whose author is unclear.",
				step.gate, res.Gate())))
		}
		trace = append(trace, res)
		if !res.Passed() {
			return trace
		}
	}
	return trace
}

// gates returns the chain's declared gate order as a fresh slice.
func (c requestChain) gates() []GateID {
	out := make([]GateID, len(c))
	for i, step := range c {
		out[i] = step.gate
	}
	return out
}

// governorChain is the per-request chain Admit runs.
//
// Gate 16 first because a quarantined target makes every later question moot;
// gate 14 LAST because it is the only gate that consumes something, and a
// request another gate was going to refuse must not first burn a token out of
// the target's rate budget.
var governorChain = requestChain{
	{Gate16CircuitBreaker, func(g *Governor, _ RequestIntent, _ Technique, _ Clock) GateResult {
		return CheckGate16CircuitBreaker(g.health)
	}},
	{Gate17RetryAfter, func(g *Governor, _ RequestIntent, _ Technique, now Clock) GateResult {
		return CheckGate17RetryAfter(g.backoff, now)
	}},
	{Gate13RevalidateEveryRequest, func(g *Governor, intent RequestIntent, _ Technique, now Clock) GateResult {
		return CheckGate13Revalidate(intent, g.scope, g.att, now)
	}},
	{Gate11RobotsDeny, func(g *Governor, intent RequestIntent, _ Technique, _ Clock) GateResult {
		return CheckGate11RobotsDeny(g.robots, intent.Next(), intent.Path())
	}},
	{Gate15DestructiveTechniques, func(g *Governor, intent RequestIntent, t Technique, _ Clock) GateResult {
		return CheckGate15DestructiveTechnique(t, intent.Method(), intent.Path(), g.allow)
	}},
	{Gate14HardCaps, func(g *Governor, intent RequestIntent, _ Technique, now Clock) GateResult {
		return g.limiter.Acquire(intent.Attempt(), now)
	}},
}

// governorGateOrder is the order Admit consults the gates in, written down
// separately from the chain that runs them so that a test can compare the two.
//
// Gate 16 first because a quarantined target makes every later question moot;
// gate 14 LAST because it is the only gate that consumes something, and a
// request another gate was going to refuse must not first burn a token out of
// the target's rate budget.
var governorGateOrder = []GateID{
	Gate16CircuitBreaker,
	Gate17RetryAfter,
	Gate13RevalidateEveryRequest,
	Gate11RobotsDeny,
	Gate15DestructiveTechniques,
	Gate14HardCaps,
}

// GovernorGateOrder returns the order Admit consults the gates in, as a fresh
// slice.
func GovernorGateOrder() []GateID { return append([]GateID(nil), governorGateOrder...) }

// ReasonRobotsRemovesNothing is gate 11's PASS token.
//
// It is declared here rather than in phase2_admission.go because per-target admission's file is
// outside this packet's write scope and because the need for it is Phase 3's:
// gate 11 is consulted per request, by the Governor, and gate 21 wants a token
// on the allow row as well as on the deny row. Per-target admission declares gate 11's refusal
// tokens and this adds the one shape it had no caller for.
const ReasonRobotsRemovesNothing Reason = "gate11.robots_txt_removes_nothing"

// phase3PassReasons is the audit token each gate in the interceptor carries on
// an ALLOW. gatePassed does not take a Reason — the kernel core's GateResult has no field
// for one — so without this map a Phase 3 allow row would reach gate 21's
// audit with an empty reason, and an audit row that records "gate 14 allowed"
// with no token is a row an operator cannot grep for.
var phase3PassReasons = map[GateID]Reason{
	Gate11RobotsDeny:             ReasonRobotsRemovesNothing,
	Gate13RevalidateEveryRequest: ReasonHopRevalidated,
	Gate14HardCaps:               ReasonWithinEveryCap,
	Gate15DestructiveTechniques:  ReasonTechniqueNonDestructive,
	Gate16CircuitBreaker:         ReasonTargetHealthWithinAll,
	Gate17RetryAfter:             ReasonBackoffElapsed,
}

// AuditReason returns the gate-numbered token that belongs on this result's
// audit row.
//
// A refusal carries its own token. An allow gets the gate's pass token. A
// GateResult no gate in this package minted, or one naming a gate the
// interceptor does not consult, returns an ERROR rather than a token: gate 21
// requires the row to be attributable, and a row whose reason was invented to
// fill the field is not.
func AuditReason(r GateResult) (Reason, error) {
	// There is deliberately no separate `if !r.Gate().Valid()` branch. A
	// GateResult naming no gate cannot report Passed() — GateResult.Passed
	// requires a valid gate — so it always lands in the arm below, where
	// Failure() is nil for a value nobody minted and the refusal already
	// fires. A mutation run confirmed the branch could never be the only
	// thing refusing anything, so it is gone rather than commented, the same
	// way the kernel core removed a subsumed branch in Cap.Lower.
	if !r.Passed() {
		f := r.Failure()
		if f == nil || f.Reason.Validate() != nil {
			return ReasonUnspecified, fmt.Errorf("audit: %w: %s produced no valid reason "+
				"token, so there is no attributable row to write", ErrUnconstructed, r.Gate())
		}
		return f.Reason, nil
	}
	reason, ok := phase3PassReasons[r.Gate()]
	if !ok {
		return ReasonUnspecified, fmt.Errorf("audit: %w: %s has no Phase 3 pass token; "+
			"this result did not come from the per-request interceptor", ErrRefused, r.Gate())
	}
	return reason, nil
}

// LastResult reduces a trace to one GateResult: the refusal if there is one,
// otherwise the final pass.
//
// An EMPTY trace is a refusal. A caller that got no results at all consulted
// no gates, and "no gate objected" is the vacuous-truth bug that a for-range
// over an empty slice produces for free — the same case kernel.go's chain
// runner handles for an empty chain.
func LastResult(trace []GateResult) GateResult {
	if len(trace) == 0 {
		return gateFailed(Gate13RevalidateEveryRequest, ReasonRequestIntentUnbuilt,
			"the admission trace is empty, so no gate was consulted. An empty trace is a "+
				"refusal, never a silent pass.")
	}
	for _, r := range trace {
		if !r.Passed() {
			return r
		}
	}
	return trace[len(trace)-1]
}

// ObserveResponse feeds one completed response to gates 16 and 17.
//
// It releases the lease first, so that a slot is returned even when the
// breaker trips on this very observation.
func (g *Governor) ObserveResponse(l *Lease, status int, latency time.Duration, header http.Header, now Clock) GateResult {
	if !g.Constructed() {
		return gateFailed(Gate16CircuitBreaker, ReasonMonitorUnconstructed,
			"ObserveResponse was called on a Governor NewGovernor never built.")
	}
	l.Release()
	if status == http.StatusTooManyRequests {
		return g.backoff.Observe429(header, now)
	}
	return g.health.ObserveResponse(status, latency, now)
}

// ObserveConnectionError feeds one failed connection to gate 16.
func (g *Governor) ObserveConnectionError(l *Lease, now Clock) GateResult {
	if !g.Constructed() {
		return gateFailed(Gate16CircuitBreaker, ReasonMonitorUnconstructed,
			"ObserveConnectionError was called on a Governor NewGovernor never built.")
	}
	l.Release()
	return g.health.ObserveConnectionError(now)
}

// LimitBody bounds a response body at gate 14's cap.
func (g *Governor) LimitBody(r io.Reader) (*BoundedBody, GateResult) {
	if !g.Constructed() {
		return nil, gateFailed(Gate14HardCaps, ReasonLimiterUnconstructed,
			"LimitBody was called on a Governor NewGovernor never built.")
	}
	return LimitBody(r, g.limiter.Caps())
}

// Counts returns how many requests this governor admitted and refused.
func (g *Governor) Counts() (admitted, refused int) {
	if !g.Constructed() {
		return 0, 0
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.admitted, g.refused
}

// Health returns the target's circuit breaker, for the audit path.
func (g *Governor) Health() *HealthMonitor {
	if !g.Constructed() {
		return nil
	}
	return g.health
}

// Backoff returns the target's 429 ledger, for the audit path.
func (g *Governor) Backoff() *BackoffLedger {
	if !g.Constructed() {
		return nil
	}
	return g.backoff
}

// Limiter returns the target's rate limiter, for the audit path.
func (g *Governor) Limiter() *RateLimiter {
	if !g.Constructed() {
		return nil
	}
	return g.limiter
}
