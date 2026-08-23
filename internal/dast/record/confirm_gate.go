// confirm_gate.go is plan/50-dast.md D.27: the finding confirmation gate.
//
// It is the packet that decides WHAT ANVIL CLAIMS TO HAVE FOUND. Everything
// below exists because one of three things is true, and each is stated here
// rather than in a commit message because a reader who does not know them
// will "simplify" this file back into a false-positive machine.
//
// ===========================================================================
// 1. UNCONFIRMED IS A THIRD OUTCOME, NOT A LOW SCORE
// ===========================================================================
//
// The Coverage Reporting Contract (plan/50-dast.md:1156) says of `confidence`:
// "oracle-less classes (authorization, IDOR, business logic) are tagged
// `unconfirmed` rather than asserted or dropped."
//
// There is nothing that mechanically decides whether a 200 on /admin/users is
// a broken access control or the intended behaviour for the identity we
// authenticated as. Asserting it produces false positives at the 18-45% rate
// research/23-dast-signal-sources.md Risk #2 measured. Dropping it hides real
// findings. So the gate has THREE terminal outcomes and they are separate
// values of a named enum, not three regions of a float:
//
//	OutcomeConfirmed    Anvil re-probed and the oracle reproduced, every time
//	OutcomeUnconfirmed  Anvil re-probed and nothing here can decide it
//	OutcomeRejected     Anvil re-probed and the oracle did not reproduce
//
// A low `confidence` would not have been enough. A consumer that sorts by
// confidence puts an undecidable authorization finding next to a disproved
// SQL injection, and 0.0 is what Go hands you for a field nobody filled in.
// Hence also: Confidence() returns (float64, bool). An oracle-less class has
// NO reproduction ratio, so it reports no number at all — the same shape, and
// for the same reason, as this package's server_line_coverage, which is NULL
// on an incremental scan and never 0 (coverage.go, ScanMode).
//
// ===========================================================================
// 2. EVIDENCE IS EXTRACTED, NOT CARRIED
// ===========================================================================
//
// plan/00-SPINE.md S7: "The DAST response body is the highest-risk injection
// channel... Hash-and-reference by default; inline only a regex-extracted
// evidence span." A raw response body that reaches a record is a raw response
// body that reaches a coding agent's prompt.
//
// The enforcement is structural, in the sense the kernel's gate-12 exclusion
// is structural (internal/dast/authz/kernel_test.go,
// TestAdmissionInputClosureIsClosed): not "we are careful not to assign the
// body", but "there is nowhere to assign it".
//
//   - Finding has NO exported fields. A consumer cannot construct one and
//     cannot write to one. The only constructor is Gate.ConfirmFinding.
//   - Finding's transitive field-type closure contains no []byte, no pointer,
//     no slice, no map, no interface, no func and no channel. It is strings,
//     named string enums, ints, a float and bools. There is no field a body
//     could be assigned to and no reference through which one could be
//     reached. TestFindingTypeClosureHasNoRawBodyPath proves this by walking
//     the closure.
//   - Every string Finding can hold is bounded at MaxSpanBytes, and the bound
//     is enforced by REFUSAL, not truncation — truncating an identity (a
//     target, a path) produces a finding that names the wrong endpoint.
//     TestNoFindingReachableStringExceedsTheSpanLimit drives a 512 KiB
//     hostile body through the gate and walks the result.
//
// The body itself exists only as Observation.Body, which is what the Reprober
// seam returns, is a local in ConfirmFinding, and is reachable from no value
// this gate emits.
//
// ===========================================================================
// 3. A FINDING'S detection_method IS PART OF ITS TRUTH
// ===========================================================================
//
// A template match and a model inference are different epistemic acts. A
// consumer must be able to tell them apart without reading the finding text,
// so DetectionMethod is a named enum whose zero value is DetectionMethodUnset
// and whose Unset value is REFUSED. Nothing defaults it.
//
// And the method constrains the outcome: DetectionMethodModelInference can
// never reach OutcomeConfirmed here. The standing ruling is that only an
// observation Anvil made through the kernel confirms anything; a regex
// reproducing on re-probe validates the SIGNATURE, not the model's inference
// about what the signature means. A model-flagged candidate is therefore
// unconfirmed at best, which is exactly research 23's mitigation.
//
// ===========================================================================
// THE ONE REGEX, AND ITS TWO JOBS
// ===========================================================================
//
// A candidate carries exactly one Signature. It is used for two things and
// the split is the whole design:
//
//	EXTRACTION  always. Its match against the re-probe body IS the evidence
//	            span. This is why evidence exists exactly when something
//	            matched, and why there is no second "evidence regex" that
//	            could disagree with the oracle.
//	ORACLE      only when the class has one. For an oracle-bearing class,
//	            "the signature matched on every attempt" is reproduction. For
//	            an oracle-less class the same match is evidence for a human
//	            and decides nothing.
//
// The regexes are RE2 (Go's regexp), so there is no catastrophic
// backtracking: matching a hostile 512 KiB body is linear in its length. That
// is a property of the engine, not a claim about the patterns.
//
// ===========================================================================
// WHAT THIS GATE DOES NOT DO
// ===========================================================================
//
// IT DOES NOT CANONICALIZE. engines.Finding.Target is documented as "the
// kernel's rendering of the target, pinned address included" — it is already
// canonical, having been through authz.Canonicalize at gate 8. Re-normalizing
// here would be the second canonicalization the house forbids, and two
// canonicalizers that disagree is how an allowlist gets bypassed. This gate
// VALIDATES (charset, bound, shape) and refuses; it never rewrites.
//
// IT DOES NOT DIAL. Gate 3 tier 1 forbids a socket constructed inside
// internal/dast outside internal/dast/authz. The re-probe therefore arrives
// through the Reprober interface, whose implementation lives on the far side
// of that boundary. A nil Reprober is legal to construct and produces
// ErrNotReprobed at ConfirmFinding — a REFUSAL, never a clean sheet. That is
// the same shape engines.Driver gives a nil Issuer, and for the same reason.
//
// IT DOES NOT DECIDE dast_status. record.DeriveDastStatus owns that mapping
// and Summary.DeriveDastStatus (coverage.go, D.26) is the only caller area D
// gets. What this file supplies is the one number that mapping needs and the
// one assertion that stops it lying: Ledger.FindingCountForStatus() counts
// CONFIRMED findings only — "no finding reaches dast_status: findings without
// having passed a re-probe confirmation step" — and
// Ledger.AssertNotSilentlyClean() refuses to let a caller read a zero
// confirmed count as "scanned clean" while unconfirmed or refused candidates
// are sitting in the ledger.
//
// Sources: plan/50-dast.md D.27 (lines 870-911) and the Coverage Reporting
// Contract (lines 1142-1160); plan/00-SPINE.md S7; research/15-dast-tooling-
// landscape.md (ZAP's 88 phantom SQL-injection findings);
// research/23-dast-signal-sources.md Risk #2.
package record

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// ---------------------------------------------------------------------------
// Sentinel errors
// ---------------------------------------------------------------------------
//
// ErrRefused and ErrUnconstructed are declared in coverage.go and reused here
// on purpose: one refusal sentinel per package, so errors.Is(err, ErrRefused)
// means the same thing everywhere in it.

var (
	// ErrNotReprobed is returned when a candidate could not be re-probed at
	// all: no Reprober was wired, the Reprober errored, or it reported that
	// nothing was issued.
	//
	// It is an ERROR and not an unconfirmed Finding. An unconfirmed Finding
	// is a claim that Anvil looked and could not decide; this is the claim
	// that Anvil did not look. Collapsing them would make a scan with no
	// egress indistinguishable from a scan that found undecidable things,
	// which is the plan/00-SPINE.md S6 failure mode one level down.
	ErrNotReprobed = errors.New("dastrecord: the candidate was not re-probed, so it was not confirmed")

	// ErrSignatureMatchesEverything is returned by NewSignature for a
	// pattern that matches the empty string.
	//
	// Such a pattern reproduces against ANY body, including an empty one, so
	// it is an oracle that always says yes. That is worse than no oracle: it
	// converts the confirmation gate into a pass-through while continuing to
	// report `confirmed`.
	ErrSignatureMatchesEverything = errors.New("dastrecord: the signature matches the empty string and would confirm anything")

	// ErrSilentlyClean is what AssertNotSilentlyClean returns when a ledger
	// with zero confirmed findings also holds unconfirmed findings or
	// refused candidates.
	ErrSilentlyClean = errors.New("dastrecord: zero confirmed findings is not the same fact as a clean scan")
)

// ---------------------------------------------------------------------------
// Bounds
// ---------------------------------------------------------------------------

// MaxSpanBytes is the length limit on the regex-extracted evidence span, and
// it is simultaneously the length limit on EVERY string a Finding can hold.
//
// The two are deliberately one constant. plan/50-dast.md D.27's validation
// requirement is "a reflection-based test confirming no Finding-reachable
// field can hold a value longer than the regex-extracted-span length limit
// (proving raw-body inlining is structurally impossible, not just avoided by
// convention)". That test can only be written against a single bound, so
// there is a single bound.
//
// The consequence is a real limit, stated rather than hidden: a target
// rendering, path or template identity longer than this is REFUSED, not
// truncated. See MaxFieldBytes.
const MaxSpanBytes = 512

// MaxFieldBytes is the bound on every other string. It is MaxSpanBytes by
// definition; see there.
const MaxFieldBytes = MaxSpanBytes

// MaxPatternBytes bounds a Signature's source pattern. A pattern is
// Anvil-authored or template-derived, but it arrives alongside untrusted
// bytes and Pattern() is quotable in a refusal, so it is bounded here rather
// than assumed.
const MaxPatternBytes = 1024

// DefaultAttempts is how many times ConfirmFinding re-fires the probe when
// GateConfig.Attempts is left at zero.
//
// It is three and not one because the scenario this gate exists to catch is
// not only "the engine was wrong", it is "the engine was right once". The
// ZAP phantom-SQLi cluster in research/15-dast-tooling-landscape.md is a
// cluster of results that do not survive being asked again. One re-probe
// cannot tell a stable finding from a flaky one; three can report the ratio.
const DefaultAttempts = 3

// MaxAttempts bounds GateConfig.Attempts. A confirmation pass is egress
// against a live target and the kernel's rate caps are per request, so an
// unbounded attempt count is an amplification channel.
const MaxAttempts = 16

// ---------------------------------------------------------------------------
// DetectionMethod — the enum nothing may default
// ---------------------------------------------------------------------------

// DetectionMethod is the `detection_method` field of the Coverage Reporting
// Contract: which epistemic act produced this candidate.
//
// FAIL CLOSED: the zero value is DetectionMethodUnset and every constructor
// refuses it. A defaulted detection method would silently label a model's
// inference as a template match, which is precisely the distinction research
// 23's mitigation depends on.
type DetectionMethod string

const (
	// DetectionMethodUnset is the zero value and names nothing.
	DetectionMethodUnset DetectionMethod = ""

	// DetectionMethodTemplate: a template's declared matcher fired. The
	// evidence is a pattern the template author wrote down in advance.
	DetectionMethodTemplate DetectionMethod = "template"

	// DetectionMethodDifferential: two requests that differ in one
	// controlled way produced responses that differ in a way the probe
	// predicted. The evidence is the difference.
	DetectionMethodDifferential DetectionMethod = "differential"

	// DetectionMethodModelInference: a model read something and inferred a
	// vulnerability. There is no mechanical oracle behind it, and this gate
	// will not promote it to confirmed no matter how the re-probe goes.
	DetectionMethodModelInference DetectionMethod = "model_inference"
)

// DetectionMethodValues returns every legal literal, excluding the zero
// value. The order is the contract's order.
func DetectionMethodValues() []DetectionMethod {
	return []DetectionMethod{
		DetectionMethodTemplate, DetectionMethodDifferential, DetectionMethodModelInference,
	}
}

// Valid reports whether m is one of the three legal literals. The zero value
// is not one of them.
func (m DetectionMethod) Valid() bool {
	for _, k := range DetectionMethodValues() {
		if k == m {
			return true
		}
	}
	return false
}

// CanConfirm reports whether a candidate detected this way is eligible for
// OutcomeConfirmed at all.
//
// Model inference is not. A re-probe reproduces a SIGNATURE; it does not
// reproduce an inference about what that signature means, and the standing
// ruling is that only an observation Anvil made through the kernel confirms
// anything.
func (m DetectionMethod) CanConfirm() bool {
	return m == DetectionMethodTemplate || m == DetectionMethodDifferential
}

// ---------------------------------------------------------------------------
// Class — which vulnerability classes have an oracle
// ---------------------------------------------------------------------------

// Class is the vulnerability class of a candidate. It exists for exactly one
// decision: whether anything mechanical can settle this candidate.
//
// FAIL CLOSED in two directions. The zero value is ClassUnset and is refused;
// and an unrecognised class is refused rather than assumed to have an oracle,
// because "we do not know what this is" must never take the route that ends
// in `confirmed`.
type Class string

const (
	// ClassUnset is the zero value and names nothing.
	ClassUnset Class = ""

	// --- classes with a mechanical oracle -------------------------------

	// ClassInjection covers SQL, command, template and similar injection:
	// the probe can make the target emit a string it would not otherwise
	// emit, and that string is the oracle.
	ClassInjection Class = "injection"
	// ClassXSS: a reflected or stored payload appears in a response in an
	// executable position. The reflection is the oracle.
	ClassXSS Class = "xss"
	// ClassPathTraversal: a file the application does not serve appears in
	// a response. The file's content is the oracle.
	ClassPathTraversal Class = "path_traversal"
	// ClassSSRF: the target fetched a URL the probe chose. The interaction
	// is the oracle.
	ClassSSRF Class = "ssrf"
	// ClassMisconfiguration: a header, method or endpoint is present or
	// absent. Presence is the oracle.
	ClassMisconfiguration Class = "misconfiguration"
	// ClassExposedSecret: a credential-shaped string is served. The string
	// is the oracle.
	ClassExposedSecret Class = "exposed_secret"
	// ClassOutdatedComponent: a version banner. The banner is the oracle.
	ClassOutdatedComponent Class = "outdated_component"

	// --- oracle-less classes --------------------------------------------
	//
	// The contract names these three by name. Nothing mechanical decides
	// them, because the question is not "what did the server do" but "was
	// the server allowed to do that for this identity" — and the answer
	// lives in an intent no response body contains.

	// ClassAuthorization: broken access control.
	ClassAuthorization Class = "authorization"
	// ClassIDOR: insecure direct object reference.
	ClassIDOR Class = "idor"
	// ClassBusinessLogic: a workflow used in an order the designer did not
	// intend.
	ClassBusinessLogic Class = "business_logic"
)

// classOracles maps every recognised class to whether a mechanical oracle
// exists for it.
//
// It is a map keyed BY IDENTITY and not two slices compared by position. A
// positional allowlist is the failure this house has already watched happen:
// insert one literal at the top of the wrong list and every class after it
// silently changes meaning, and nothing goes red.
func classOracles() map[Class]bool {
	return map[Class]bool{
		ClassInjection:         true,
		ClassXSS:               true,
		ClassPathTraversal:     true,
		ClassSSRF:              true,
		ClassMisconfiguration:  true,
		ClassExposedSecret:     true,
		ClassOutdatedComponent: true,

		ClassAuthorization: false,
		ClassIDOR:          false,
		ClassBusinessLogic: false,
	}
}

// ClassValues returns every recognised class, excluding the zero value, in a
// deterministic order.
func ClassValues() []Class {
	out := make([]Class, 0, len(classOracles()))
	for c := range classOracles() {
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// Recognised reports whether c is a class this gate knows how to route.
func (c Class) Recognised() bool {
	_, ok := classOracles()[c]
	return ok
}

// OracleLess reports whether nothing mechanical can settle a candidate of
// this class.
//
// An UNRECOGNISED class reports true. That is the fail-closed direction: an
// unknown class cannot reach `confirmed` through this predicate. It is
// belt-and-braces — RawFinding validation refuses an unrecognised class
// before this is consulted — but a predicate whose default answer is "yes,
// assert it" is one refactor away from being the bug.
func (c Class) OracleLess() bool {
	hasOracle, ok := classOracles()[c]
	return !ok || !hasOracle
}

// ---------------------------------------------------------------------------
// Outcome — the third state
// ---------------------------------------------------------------------------

// Outcome is what the gate decided about a candidate. Three terminal values;
// see this file's header for why unconfirmed is one of them and not a number.
type Outcome string

const (
	// OutcomeUnset is the zero value and names nothing. A Finding never
	// carries it: ConfirmFinding assigns one of the three below or returns
	// an error.
	OutcomeUnset Outcome = ""

	// OutcomeConfirmed: Anvil re-probed through the kernel and the oracle
	// reproduced on every attempt. This is the ONLY outcome that counts
	// toward dast_status: findings.
	OutcomeConfirmed Outcome = "confirmed"

	// OutcomeUnconfirmed: Anvil re-probed and nothing available can decide
	// it. Reached three ways — an oracle-less class, a model inference, or
	// intermittent reproduction — and Reason() says which.
	OutcomeUnconfirmed Outcome = "unconfirmed"

	// OutcomeRejected: Anvil re-probed and the oracle did not reproduce
	// once. This is the ZAP phantom-SQLi case.
	//
	// A rejected candidate still becomes a Finding rather than vanishing.
	// A drop nobody can see is indistinguishable from a candidate that was
	// never there, and the count of them is how an operator learns the
	// engine is noisy.
	OutcomeRejected Outcome = "rejected"
)

// OutcomeValues returns every terminal outcome, excluding the zero value.
func OutcomeValues() []Outcome {
	return []Outcome{OutcomeConfirmed, OutcomeUnconfirmed, OutcomeRejected}
}

// Valid reports whether o is a terminal outcome.
func (o Outcome) Valid() bool {
	for _, k := range OutcomeValues() {
		if k == o {
			return true
		}
	}
	return false
}

// CountsAsFinding reports whether a finding with this outcome may drive
// record.DastStatusCompletedFindings.
//
// Only OutcomeConfirmed does. plan/50-dast.md D.27: "No finding reaches
// dast_status: findings without having passed a re-probe confirmation step."
func (o Outcome) CountsAsFinding() bool { return o == OutcomeConfirmed }

// ---------------------------------------------------------------------------
// Reason — why the outcome is what it is
// ---------------------------------------------------------------------------

// Reason is the logged reason attached to every Finding. "Demotes/drops with
// a logged reason" is D.27's wording; this is the log, on the value itself,
// where it cannot be separated from the decision it explains.
type Reason string

const (
	// ReasonUnset is the zero value and names nothing.
	ReasonUnset Reason = ""

	// ReasonReproduced: the oracle matched on every attempt.
	ReasonReproduced Reason = "reproduced_on_every_attempt"

	// ReasonNoOracleForClass: the class is one of the three the contract
	// names as oracle-less. Tagged unconfirmed rather than asserted or
	// dropped.
	ReasonNoOracleForClass Reason = "class_has_no_mechanical_oracle"

	// ReasonModelInferenceIsNotObservation: the signature reproduced, but
	// the candidate came from a model's inference and a reproduced
	// signature does not validate an inference.
	ReasonModelInferenceIsNotObservation Reason = "model_inference_is_not_an_observation"

	// ReasonReproducedIntermittently: the oracle matched on some attempts
	// and not others. A flaky oracle is not a confirmed finding and is not
	// a disproved one.
	ReasonReproducedIntermittently Reason = "reproduced_intermittently"

	// ReasonDidNotReproduce: the oracle matched on no attempt. This is what
	// the 88 phantom findings get.
	ReasonDidNotReproduce Reason = "did_not_reproduce_on_any_attempt"
)

// ReasonValues returns every legal reason, excluding the zero value.
func ReasonValues() []Reason {
	return []Reason{
		ReasonReproduced, ReasonNoOracleForClass,
		ReasonModelInferenceIsNotObservation, ReasonReproducedIntermittently,
		ReasonDidNotReproduce,
	}
}

// Valid reports whether r is one of the legal reasons.
func (r Reason) Valid() bool {
	for _, k := range ReasonValues() {
		if k == r {
			return true
		}
	}
	return false
}

// outcomeForReason is the single mapping from reason to outcome.
//
// It exists so that the outcome and the reason cannot disagree: ConfirmFinding
// decides a Reason and this function decides the Outcome from it, so there is
// no code path that can label a ReasonDidNotReproduce finding `confirmed`.
func outcomeForReason(r Reason) (Outcome, error) {
	switch r {
	case ReasonReproduced:
		return OutcomeConfirmed, nil
	case ReasonNoOracleForClass, ReasonModelInferenceIsNotObservation, ReasonReproducedIntermittently:
		return OutcomeUnconfirmed, nil
	case ReasonDidNotReproduce:
		return OutcomeRejected, nil
	}
	return OutcomeUnset, fmt.Errorf("%w: %q is not a reason this gate mints", ErrRefused, string(r))
}

// ---------------------------------------------------------------------------
// RefuseReason — why a candidate never became a Finding at all
// ---------------------------------------------------------------------------

// RefuseReason is why ConfirmAll could not produce a Finding for a candidate.
// It is distinct from Reason: a Reason explains a decision about a finding, a
// RefuseReason explains that no decision was possible.
type RefuseReason string

const (
	// RefuseUnrecognisedClass: ClassUnset, or a class not in classOracles.
	RefuseUnrecognisedClass RefuseReason = "unrecognised_class"
	// RefuseUnrecognisedDetectionMethod: DetectionMethodUnset, or a literal
	// outside the contract's three.
	RefuseUnrecognisedDetectionMethod RefuseReason = "unrecognised_detection_method"
	// RefuseMissingSignature: no Signature, so nothing to extract evidence
	// with and nothing to reproduce.
	RefuseMissingSignature RefuseReason = "missing_signature"
	// RefuseOversizedField: a string longer than MaxFieldBytes. Refused
	// rather than truncated; truncating an identity renames an endpoint.
	RefuseOversizedField RefuseReason = "oversized_field"
	// RefuseMalformedField: an empty, mis-shaped or non-printable field.
	RefuseMalformedField RefuseReason = "malformed_field"
	// RefuseNotReprobed: the re-probe did not happen. See ErrNotReprobed.
	RefuseNotReprobed RefuseReason = "not_reprobed"
)

// ---------------------------------------------------------------------------
// Signature — the one regex
// ---------------------------------------------------------------------------

// Signature is the compiled pattern a candidate carries. See this file's
// header for its two jobs.
//
// The zero value compiles nothing and matches nothing; Constructed() reports
// false and RawFinding validation refuses it.
type Signature struct {
	re     *regexp.Regexp
	src    string
	sealed bool
}

// NewSignature compiles pattern.
//
// It refuses three things, each because the alternative is an oracle that
// lies:
//
//	an empty pattern          nothing to match, nothing to extract
//	an over-long pattern      MaxPatternBytes; the source is quotable
//	a pattern matching ""     it reproduces against any body, including an
//	                          empty one, so it confirms everything
//
// The engine is RE2, so a compiled Signature cannot backtrack catastrophically
// however hostile the body it is later run against.
func NewSignature(pattern string) (Signature, error) {
	if pattern == "" {
		return Signature{}, fmt.Errorf("%w: an empty signature pattern extracts no evidence "+
			"and reproduces nothing", ErrRefused)
	}
	if len(pattern) > MaxPatternBytes {
		return Signature{}, fmt.Errorf("%w: the signature pattern is %d bytes and the bound is %d",
			ErrRefused, len(pattern), MaxPatternBytes)
	}
	re, err := regexp.Compile(pattern)
	if err != nil {
		return Signature{}, fmt.Errorf("%w: compiling the signature pattern: %w", ErrRefused, err)
	}
	if re.MatchString("") {
		return Signature{}, fmt.Errorf("%w: %q", ErrSignatureMatchesEverything, printable(pattern, MaxFieldBytes))
	}
	return Signature{re: re, src: pattern, sealed: true}, nil
}

// Constructed reports whether s came from NewSignature.
func (s Signature) Constructed() bool { return s.sealed && s.re != nil && s.src != "" }

// Pattern returns the source pattern.
func (s Signature) Pattern() string { return s.src }

// ---------------------------------------------------------------------------
// EvidenceRef — {body_hash, extracted_span} and nothing else
// ---------------------------------------------------------------------------

// EvidenceRef is the contract's `evidence` struct: "{body_hash string,
// extracted_span string}. Never the raw response body."
//
// Both fields are unexported. That is not decoration: an exported
// ExtractedSpan is a field a consumer — or a future maintainer with a body in
// hand and a deadline — can assign a body to. With no exported field and no
// exported constructor outside this file, the only EvidenceRef that exists is
// one newEvidenceRef built, and newEvidenceRef bounds its span.
type EvidenceRef struct {
	bodyHash string
	span     string

	// spanDroppedBytes is how many bytes the extraction removed because
	// they were outside printable ASCII. Non-zero means the response body
	// carried control, bidirectional or invisible characters inside the
	// matched region — worth surfacing, since this string is prompt-bound.
	spanDroppedBytes int
	// spanTruncatedFrom is the byte length of the regex match when it
	// exceeded the budget, 0 otherwise.
	spanTruncatedFrom int

	sealed bool
}

// BodyHash returns the hex SHA-256 of the response body the span came from.
// This is the "hash-and-reference by default" half of spine S7.
func (e EvidenceRef) BodyHash() string { return e.bodyHash }

// ExtractedSpan returns the bounded, printable-ASCII regex match. Empty when
// the signature matched no attempt.
func (e EvidenceRef) ExtractedSpan() string { return e.span }

// SpanDroppedBytes returns how many bytes extraction removed as
// non-printable.
func (e EvidenceRef) SpanDroppedBytes() int { return e.spanDroppedBytes }

// SpanTruncatedFrom returns the original match length when the match exceeded
// the span budget, 0 otherwise.
func (e EvidenceRef) SpanTruncatedFrom() int { return e.spanTruncatedFrom }

// Constructed reports whether e came from newEvidenceRef. The zero value has
// no hash, and a Finding with no body hash is a Finding nothing was observed
// for.
func (e EvidenceRef) Constructed() bool { return e.sealed && e.bodyHash != "" }

// ---------------------------------------------------------------------------
// Observation — the ONLY type in this file that carries a body
// ---------------------------------------------------------------------------

// Observation is what one re-probe saw. It is the boundary: the body enters
// here, is hashed and extracted from inside ConfirmFinding, and is reachable
// from nothing the gate emits.
//
// Body is []byte rather than string on purpose. It makes the one type that
// holds a body structurally unlike every type that does not, so
// TestFindingTypeClosureHasNoRawBodyPath can say "no []byte anywhere in
// Finding's closure" and have that mean something.
type Observation struct {
	// Issued reports whether the request actually left the process. FALSE is
	// the zero value and the fail-closed direction: an Observation nobody
	// filled in describes a probe nobody ran, and ConfirmFinding treats it
	// as ErrNotReprobed rather than as a non-reproduction.
	Issued bool
	// Status is the HTTP status observed, 0 if none was.
	Status int
	// Body is the response body, already bounded by the kernel's gate-14
	// cap on the far side of the Reprober interface.
	Body []byte
}

// Reprober is the re-probe seam.
//
// Gate 3 tier 1 forbids this package from constructing a socket, so the
// implementation lives on the far side of that boundary — in the kernel, or
// in cmd/anvil-dast, which is where engines.Issuer is wired too. An
// implementation MUST route the request through the kernel: an observation
// Anvil did not make through the admission chain confirms nothing, and a
// Reprober that dialled directly would be confirming findings with an
// unauthorized request.
//
// attempt is 1-based and is passed so an implementation can vary a nonce per
// attempt. It must not be used to short-circuit: returning attempt 1's cached
// response for attempts 2 and 3 turns the reproduction ratio into a constant
// and defeats the flake detection this gate is for.
type Reprober interface {
	Reprobe(ctx context.Context, candidate RawFinding, attempt int) (Observation, error)
}

// ---------------------------------------------------------------------------
// RawFinding — the untrusted candidate
// ---------------------------------------------------------------------------

// RawFinding is one candidate finding as an engine reported it. Everything in
// it originated outside Anvil except the Signature.
//
// IT CARRIES NO BODY, and that is a design decision rather than an omission.
// The engine's first-seen body is the engine's account of a request Anvil did
// not make. Evidence on a Finding comes from Anvil's own kernel-routed
// re-probe, so the engine's body is never needed here and therefore never
// offered a field to sit in.
//
// The fields are exported because a caller must be able to build one from an
// engines.Finding (D.14) or a ZAP alert (D.15) without this package importing
// either. Nothing here is trusted for being exported: NewGate's ConfirmFinding
// validates every field before the first probe leaves.
type RawFinding struct {
	// Engine is which engine produced the candidate ("nuclei", "zap").
	Engine string
	// Target is the kernel's rendering of the target, pinned address
	// included, exactly as engines.Finding.Target carries it. It is already
	// canonical and this gate does not re-canonicalize it.
	Target string
	// Method is the HTTP method, uppercase. It is not upper-cased here: see
	// this file's header on canonicalization.
	Method string
	// Path is the request path. Must begin with '/'.
	Path string
	// Class decides whether anything mechanical can settle this candidate.
	Class Class
	// DetectionMethod is which epistemic act produced it. There is no
	// default and DetectionMethodUnset is refused.
	DetectionMethod DetectionMethod
	// TemplateID and TemplateDigest identify the template BY IDENTITY. Both
	// may be empty for an engine that has no templates.
	TemplateID     string
	TemplateDigest string
	// Signature is the one regex. See this file's header.
	Signature Signature
}

// Validate refuses a candidate the gate will not probe.
//
// It runs BEFORE any egress. A candidate that cannot produce an interpretable
// Finding must not spend requests against a live target first.
func (c RawFinding) Validate() (RefuseReason, error) {
	fields := []struct {
		name     string
		value    string
		required bool
	}{
		{"engine", c.Engine, true},
		{"target", c.Target, true},
		{"method", c.Method, true},
		{"path", c.Path, true},
		{"template_id", c.TemplateID, false},
		{"template_digest", c.TemplateDigest, false},
	}
	for _, f := range fields {
		if len(f.value) > MaxFieldBytes {
			return RefuseOversizedField, fmt.Errorf("%w: %s is %d bytes and the bound is %d. "+
				"It is refused and not truncated: a truncated target or path names a "+
				"different endpoint than the one that was probed",
				ErrRefused, f.name, len(f.value), MaxFieldBytes)
		}
		if f.required && f.value == "" {
			return RefuseMalformedField, fmt.Errorf("%w: %s is empty", ErrRefused, f.name)
		}
		if !isPrintableASCII(f.value) {
			return RefuseMalformedField, fmt.Errorf("%w: %s carries bytes outside printable "+
				"ASCII; every string a Finding holds is prompt-bound", ErrRefused, f.name)
		}
	}
	if c.Method != strings.ToUpper(c.Method) {
		return RefuseMalformedField, fmt.Errorf("%w: method %q is not upper-case. HTTP methods "+
			"are case-sensitive and this gate validates rather than rewrites",
			ErrRefused, printable(c.Method, 32))
	}
	if c.Path[0] != '/' {
		return RefuseMalformedField, fmt.Errorf("%w: path %q does not begin with '/'",
			ErrRefused, printable(c.Path, 64))
	}
	if !c.Class.Recognised() {
		return RefuseUnrecognisedClass, fmt.Errorf("%w: %q is not a class this gate routes. An "+
			"unrecognised class is refused rather than assumed to have an oracle",
			ErrRefused, printable(string(c.Class), 64))
	}
	if !c.DetectionMethod.Valid() {
		return RefuseUnrecognisedDetectionMethod, fmt.Errorf("%w: detection_method %q is not one "+
			"of %v. The Coverage Reporting Contract requires it per finding and nothing "+
			"defaults it", ErrRefused, printable(string(c.DetectionMethod), 64),
			DetectionMethodValues())
	}
	if !c.Signature.Constructed() {
		return RefuseMissingSignature, fmt.Errorf("%w: the candidate carries no Signature, so "+
			"there is nothing to extract evidence with and nothing to reproduce",
			ErrRefused)
	}
	return "", nil
}

// ---------------------------------------------------------------------------
// Finding — the type a consumer holds
// ---------------------------------------------------------------------------

// Finding is a candidate the gate has decided about.
//
// EVERY FIELD IS UNEXPORTED AND EVERY FIELD IS A VALUE. There is no exported
// field to assign a body to, no pointer or slice through which one could be
// reached, and consequently no way for a consumer to hold a Finding that
// carries a raw response body. That is D.27's "this gate's output type must
// make 'the model reads the raw body' a type error, not a discipline
// problem", and it is checked mechanically by
// TestFindingTypeClosureHasNoRawBodyPath.
//
// Because there are no reference-typed fields, a Finding value IS a complete
// copy. Findings() can hand out a shallow clone and it is a deep one; there
// is no aliasing hazard hiding behind an unexported slice header.
//
// The plan's expected schema for this type is `{ Evidence EvidenceRef;
// DetectionMethod string; Confidence float64 }` with exported fields. The
// vocabulary is preserved on the accessors; the export is not, because an
// exported field is exactly the hole this packet exists to close. Confidence()
// additionally returns (float64, bool) rather than a bare float — see this
// file's header.
type Finding struct {
	engine         string
	target         string
	method         string
	path           string
	templateID     string
	templateDigest string

	class     Class
	detection DetectionMethod
	outcome   Outcome
	reason    Reason

	evidence EvidenceRef

	// status is the HTTP status of the attempt the evidence came from.
	status int
	// attempts is how many re-probes were issued; matches is how many of
	// them the signature matched.
	attempts int
	matches  int

	// confidence is the reproduction ratio, matches/attempts. It is
	// meaningful ONLY when confidenceKnown is true, which happens only for
	// a class that has an oracle. A caller reading confidence without
	// consulting confidenceKnown reads 0.0 for "no oracle exists", which is
	// the Go-zero-value-means-permitted trap; the accessor is what stops
	// them, since the field is unexported.
	confidence      float64
	confidenceKnown bool

	sealed bool
}

// Constructed reports whether f came from ConfirmFinding. The zero value
// carries OutcomeUnset and asserts nothing.
func (f Finding) Constructed() bool { return f.sealed }

// Engine returns which engine produced the candidate.
func (f Finding) Engine() string { return f.engine }

// Target returns the kernel's rendering of the target.
func (f Finding) Target() string { return f.target }

// Method returns the HTTP method.
func (f Finding) Method() string { return f.method }

// Path returns the request path.
func (f Finding) Path() string { return f.path }

// TemplateIdentity returns the template id and digest, by identity.
func (f Finding) TemplateIdentity() (id, digest string) { return f.templateID, f.templateDigest }

// Class returns the vulnerability class.
func (f Finding) Class() Class { return f.class }

// DetectionMethod returns the contract's `detection_method`. It is never
// DetectionMethodUnset on a constructed Finding.
func (f Finding) DetectionMethod() DetectionMethod { return f.detection }

// Outcome returns the terminal outcome. Never OutcomeUnset on a constructed
// Finding.
func (f Finding) Outcome() Outcome { return f.outcome }

// Reason returns the logged reason for the outcome.
func (f Finding) Reason() Reason { return f.reason }

// Evidence returns the contract's `evidence` struct. It has a body hash and a
// bounded span, and no route to the body.
func (f Finding) Evidence() EvidenceRef { return f.evidence }

// Status returns the HTTP status of the attempt the evidence came from.
func (f Finding) Status() int { return f.status }

// Attempts returns how many re-probes were issued.
func (f Finding) Attempts() int { return f.attempts }

// SignatureMatches returns how many of those attempts the signature matched.
//
// This is a raw measurement and is reported for every finding, including
// oracle-less ones. It is deliberately NOT called confidence: for an
// authorization finding, "the signature matched 3 times out of 3" says the
// response was stable, not that the access control is broken.
func (f Finding) SignatureMatches() int { return f.matches }

// Confidence returns the contract's `confidence` in [0,1], and whether there
// is one at all.
//
// ok is false for an oracle-less class. Confidence here is defined as the
// reproduction ratio of the oracle; a class with no oracle has no ratio, so
// there is no number to report — and 0.0 would read as "certainly not a
// vulnerability", which is the opposite of what an unconfirmed authorization
// finding means.
//
// This is the same shape, for the same reason, as server_line_coverage in
// coverage.go: NULL where nothing was measured, never 0.
func (f Finding) Confidence() (float64, bool) { return f.confidence, f.confidenceKnown }

// CountsAsFinding reports whether this finding may drive
// record.DastStatusCompletedFindings. Only a confirmed one does.
func (f Finding) CountsAsFinding() bool { return f.outcome.CountsAsFinding() }

// String renders the finding for a log. It quotes no body and no span: the
// span is prompt-bound prose from outside Anvil and a log line is a prompt
// often enough. What it prints is the decision and the arithmetic behind it.
func (f Finding) String() string {
	if !f.sealed {
		return "finding(unconstructed)"
	}
	conf := "n/a"
	if f.confidenceKnown {
		conf = fmt.Sprintf("%.3f", f.confidence)
	}
	return fmt.Sprintf("%s %s %s class=%s detection=%s outcome=%s reason=%s "+
		"matches=%d/%d confidence=%s body_hash=%s span_bytes=%d",
		f.engine, f.method, f.path, f.class, f.detection, f.outcome, f.reason,
		f.matches, f.attempts, conf, f.evidence.bodyHash, len(f.evidence.span))
}

// ---------------------------------------------------------------------------
// Refusal — a candidate that never became a Finding
// ---------------------------------------------------------------------------

// Refusal is a candidate ConfirmAll could not decide about at all.
//
// Refusals are carried rather than discarded for the same reason rejected
// findings are: a batch that produced no findings because every candidate was
// malformed is not a clean scan, and only a count can tell the two apart.
type Refusal struct {
	// Index is the candidate's position in the slice handed to ConfirmAll.
	Index int
	// Reason is why no decision was possible.
	Reason RefuseReason
	// Detail is a bounded, printable-ASCII rendering of the offending
	// candidate — enough to find it, not enough to be a channel.
	Detail string
	// Err is the error this package minted. It wraps ErrRefused or
	// ErrNotReprobed.
	Err error
}

// ---------------------------------------------------------------------------
// The gate
// ---------------------------------------------------------------------------

// GateConfig is everything the gate needs.
type GateConfig struct {
	// Reprober is the re-probe seam. A nil Reprober is legal to construct
	// and produces ErrNotReprobed at ConfirmFinding — a refusal, never a
	// clean sheet. Gate 3 forbids this package from dialling, so an unwired
	// Reprober means THE RE-PROBE DID NOT RUN, and a candidate that was not
	// re-probed is not confirmed.
	Reprober Reprober
	// Attempts is how many times to re-fire each probe. Zero means
	// DefaultAttempts. Negative, or above MaxAttempts, is refused.
	Attempts int
}

// Gate is D.27: the finding confirmation gate.
type Gate struct {
	reprober Reprober
	attempts int
	sealed   bool
}

// NewGate assembles the gate.
func NewGate(cfg GateConfig) (*Gate, error) {
	attempts := cfg.Attempts
	if attempts == 0 {
		attempts = DefaultAttempts
	}
	if attempts < 0 || attempts > MaxAttempts {
		return nil, fmt.Errorf("%w: %d re-probe attempts is outside [1,%d]",
			ErrRefused, cfg.Attempts, MaxAttempts)
	}
	return &Gate{reprober: cfg.Reprober, attempts: attempts, sealed: true}, nil
}

// Constructed reports whether g came from NewGate.
func (g *Gate) Constructed() bool { return g != nil && g.sealed }

// Attempts returns how many re-probes the gate issues per candidate.
func (g *Gate) Attempts() int {
	if !g.Constructed() {
		return 0
	}
	return g.attempts
}

// ReproberWired reports whether there is anything to re-probe with. False
// means every ConfirmFinding call will return ErrNotReprobed, which is the
// tool-absent path refusing loudly rather than reporting a clean target.
func (g *Gate) ReproberWired() bool { return g.Constructed() && g.reprober != nil }

// ConfirmFinding re-probes one candidate and decides about it.
//
// # The order, and what each step is for
//
//	1  the gate is constructed and the candidate validates. Validation runs
//	   BEFORE egress: a candidate that cannot produce an interpretable
//	   Finding must not spend requests against a live target first.
//	2  the re-probe seam is wired. If it is not, this is ErrNotReprobed and
//	   not a non-reproduction — Anvil did not look.
//	3  Attempts re-probes are issued through the Reprober, each of which
//	   MUST route through the kernel. Any error, or any attempt that reports
//	   Issued == false, aborts the whole candidate: a partial re-probe is not
//	   a re-probe, and confirming on two of three attempts because the third
//	   errored is exactly the arithmetic this gate exists to prevent.
//	4  evidence is taken from the FIRST attempt whose signature matched, or
//	   from attempt 1 if none did. The body is hashed, the match is extracted
//	   and bounded, and the body goes out of scope here.
//	5  the reason is decided, and outcomeForReason decides the outcome from
//	   it, so the two cannot disagree.
//
// It returns a *Finding for all three outcomes including OutcomeRejected. A
// rejected candidate is a fact about the engine and is not thrown away.
func (g *Gate) ConfirmFinding(ctx context.Context, candidate RawFinding) (*Finding, error) {
	if !g.Constructed() {
		return nil, fmt.Errorf("%w: ConfirmFinding was called on a Gate NewGate never built",
			ErrUnconstructed)
	}
	if _, err := candidate.Validate(); err != nil {
		return nil, err
	}
	if g.reprober == nil {
		return nil, fmt.Errorf("%w: no Reprober is wired, so the candidate for %s %s was not "+
			"re-probed. Gate 3 forbids this package from issuing the request itself, so an "+
			"unwired seam means the confirmation DID NOT RUN — it does not mean the "+
			"candidate failed to reproduce", ErrNotReprobed, candidate.Method, candidate.Path)
	}

	var (
		matches      int
		evidenceSeen bool
		ev           EvidenceRef
		evStatus     int
	)
	for attempt := 1; attempt <= g.attempts; attempt++ {
		obs, err := g.reprober.Reprobe(ctx, candidate, attempt)
		if err != nil {
			return nil, fmt.Errorf("%w: re-probe attempt %d of %d for %s %s failed: %w",
				ErrNotReprobed, attempt, g.attempts, candidate.Method, candidate.Path, err)
		}
		if !obs.Issued {
			return nil, fmt.Errorf("%w: re-probe attempt %d of %d for %s %s reported that "+
				"nothing was issued. A probe that did not leave the process observed "+
				"nothing, and observing nothing is not observing an absence",
				ErrNotReprobed, attempt, g.attempts, candidate.Method, candidate.Path)
		}

		span, dropped, truncatedFrom, matched := extractSpan(obs.Body, candidate.Signature.re)
		if matched {
			matches++
		}
		// Evidence comes from the FIRST attempt whose signature matched;
		// failing that, from attempt 1. Deterministic, and it means a
		// confirmed finding's span is always a span that reproduced —
		// never the empty span of some later attempt that happened to miss.
		if attempt == 1 || (matched && !evidenceSeen) {
			ev = EvidenceRef{
				bodyHash:          hashBody(obs.Body),
				span:              span,
				spanDroppedBytes:  dropped,
				spanTruncatedFrom: truncatedFrom,
				sealed:            true,
			}
			evStatus = obs.Status
		}
		if matched {
			evidenceSeen = true
		}
	}

	reason := decide(candidate, matches, g.attempts)
	outcome, err := outcomeForReason(reason)
	if err != nil {
		return nil, err
	}

	f := Finding{
		engine:         candidate.Engine,
		target:         candidate.Target,
		method:         candidate.Method,
		path:           candidate.Path,
		templateID:     candidate.TemplateID,
		templateDigest: candidate.TemplateDigest,
		class:          candidate.Class,
		detection:      candidate.DetectionMethod,
		outcome:        outcome,
		reason:         reason,
		evidence:       ev,
		status:         evStatus,
		attempts:       g.attempts,
		matches:        matches,
		sealed:         true,
	}
	if !candidate.Class.OracleLess() {
		f.confidence = float64(matches) / float64(g.attempts)
		f.confidenceKnown = true
	}

	// The bound is asserted on the assembled value rather than trusted from
	// Validate. Validate ran against the candidate; this runs against the
	// thing a consumer will hold, which is the object the claim is about.
	if err := assertFindingStringsBounded(f); err != nil {
		return nil, err
	}
	return &f, nil
}

// decide is the reason table. It is a separate function so the precedence is
// readable in one screen and testable value by value.
//
// PRECEDENCE, and why each rule outranks the next:
//
//  1. ORACLE-LESS CLASS. Outranks everything, including "matched zero times".
//     The contract says these are "tagged unconfirmed rather than asserted or
//     dropped" — a signature that did not match an authorization finding
//     disproves nothing, so this class can never reach OutcomeRejected.
//  2. MATCHED NOTHING. The oracle exists and never fired. This is the 88
//     phantom findings.
//  3. MODEL INFERENCE. The signature reproduced but the candidate came from a
//     model. Outranks the confirmed rule, so no model-detected candidate can
//     be confirmed here regardless of how clean the reproduction was.
//  4. INTERMITTENT. Matched sometimes. Not confirmed, not disproved.
//  5. REPRODUCED EVERY TIME, with an oracle and a mechanical detection
//     method. The only route to OutcomeConfirmed.
func decide(c RawFinding, matches, attempts int) Reason {
	switch {
	case c.Class.OracleLess():
		return ReasonNoOracleForClass
	case matches == 0:
		return ReasonDidNotReproduce
	case !c.DetectionMethod.CanConfirm():
		return ReasonModelInferenceIsNotObservation
	case matches < attempts:
		return ReasonReproducedIntermittently
	default:
		return ReasonReproduced
	}
}

// ConfirmAll runs ConfirmFinding over a batch and collects the results.
//
// It does not stop at the first refusal. A batch of 88 candidates in which
// one is malformed must still produce the verdict on the other 87, and the
// malformed one must still be counted — see Refusal.
func (g *Gate) ConfirmAll(ctx context.Context, candidates []RawFinding) (Ledger, error) {
	if !g.Constructed() {
		return Ledger{}, fmt.Errorf("%w: ConfirmAll was called on a Gate NewGate never built",
			ErrUnconstructed)
	}
	l := Ledger{sealed: true}
	for i, c := range candidates {
		if err := ctx.Err(); err != nil {
			return Ledger{}, fmt.Errorf("%w: the confirmation pass was cancelled after %d of "+
				"%d candidates, so the remainder were not re-probed: %w",
				ErrNotReprobed, i, len(candidates), err)
		}
		f, err := g.ConfirmFinding(ctx, c)
		if err != nil {
			l.refusals = append(l.refusals, Refusal{
				Index:  i,
				Reason: refuseReasonOf(c, err),
				Detail: printable(c.Method+" "+c.Path+" @"+c.Target, MaxFieldBytes),
				Err:    err,
			})
			continue
		}
		l.findings = append(l.findings, *f)
	}
	return l, nil
}

// refuseReasonOf recovers the RefuseReason for a ConfirmFinding error.
//
// It asks Validate again rather than parsing the error text: the reason is
// derived from the candidate, which is the thing that is actually wrong, and
// a string match on an error message is a guard that breaks the next time
// someone improves the wording.
func refuseReasonOf(c RawFinding, err error) RefuseReason {
	if r, verr := c.Validate(); verr != nil {
		return r
	}
	if errors.Is(err, ErrNotReprobed) {
		return RefuseNotReprobed
	}
	return RefuseMalformedField
}

// ---------------------------------------------------------------------------
// Ledger
// ---------------------------------------------------------------------------

// Ledger is one confirmation pass. It is the value that answers "what does
// Anvil claim to have found", and the answer is four numbers, not one.
type Ledger struct {
	findings []Finding
	refusals []Refusal
	sealed   bool
}

// Constructed reports whether l came from ConfirmAll. The zero value
// describes a pass that did not happen.
func (l Ledger) Constructed() bool { return l.sealed }

// Findings returns every decided candidate, all three outcomes included, as a
// copy.
//
// The copy is total. Finding has no reference-typed field — no pointer, no
// slice, no map, no interface — so copying the slice header copies the
// values, and there is no aliased buffer a caller could reach back through.
// TestFindingTypeClosureHasNoRawBodyPath is what keeps that true.
func (l Ledger) Findings() []Finding {
	out := make([]Finding, len(l.findings))
	copy(out, l.findings)
	return out
}

// Refusals returns every candidate no decision was possible for, as a copy.
func (l Ledger) Refusals() []Refusal {
	out := make([]Refusal, len(l.refusals))
	copy(out, l.refusals)
	return out
}

// count returns how many findings carry outcome o.
func (l Ledger) count(o Outcome) int {
	n := 0
	for _, f := range l.findings {
		if f.outcome == o {
			n++
		}
	}
	return n
}

// ConfirmedCount returns how many findings Anvil re-probed and reproduced.
func (l Ledger) ConfirmedCount() int { return l.count(OutcomeConfirmed) }

// UnconfirmedCount returns how many findings nothing available can decide.
func (l Ledger) UnconfirmedCount() int { return l.count(OutcomeUnconfirmed) }

// RejectedCount returns how many candidates the re-probe disproved.
func (l Ledger) RejectedCount() int { return l.count(OutcomeRejected) }

// RefusedCount returns how many candidates no decision was possible for.
func (l Ledger) RefusedCount() int { return len(l.refusals) }

// CandidateCount returns how many candidates went in: decided plus refused.
func (l Ledger) CandidateCount() int { return len(l.findings) + len(l.refusals) }

// FindingCountForStatus is the number Summary.DeriveDastStatus takes, and it
// counts CONFIRMED findings only.
//
// plan/50-dast.md D.27: "No finding reaches dast_status: findings without
// having passed a re-probe confirmation step — a first-seen finding from an
// engine is provisional until confirmed." An unconfirmed finding is by
// definition one that did not pass that step, and a rejected one failed it.
//
// This is the whole reason the gate exists, expressed as one integer: with
// the 88 phantom ZAP results in the ledger and nothing else, this returns 0
// and the record says the scan was clean, because it was.
func (l Ledger) FindingCountForStatus() int { return l.ConfirmedCount() }

// AssertNotSilentlyClean refuses to let a caller read a zero confirmed count
// as "scanned clean".
//
// FindingCountForStatus() == 0 routes to record.DastStatusCompletedClean,
// whose MeansDynamicallyScannedClean() a downstream consumer reads as "we
// looked and there is nothing here". That is true only when the ledger is
// also empty of unconfirmed findings and of refusals. An authorization
// finding nothing could decide, or 88 candidates that were never re-probed
// because no Reprober was wired, both produce a zero confirmed count and
// neither is a clean scan.
//
// It is an error rather than a different status because choosing the status
// is not this packet's call: record.DeriveDastStatus owns the mapping and
// Summary.DeriveDastStatus (D.26) is area D's only door to it. What this can
// do is make the caller handle the case explicitly, which is the same shape
// coverage.go's ErrCoverageNotComputable uses and for the same reason.
//
// It mirrors engines.ScanResult.AssertNotSilentlyEmpty one layer up: that one
// separates "no findings" from "nothing probed"; this one separates "no
// confirmed findings" from "nothing confirmable".
func (l Ledger) AssertNotSilentlyClean() error {
	if !l.sealed {
		return fmt.Errorf("%w: AssertNotSilentlyClean was called on a Ledger ConfirmAll never "+
			"built", ErrUnconstructed)
	}
	if l.ConfirmedCount() > 0 {
		return nil
	}
	unconfirmed, refused := l.UnconfirmedCount(), l.RefusedCount()
	if unconfirmed == 0 && refused == 0 {
		return nil
	}
	return fmt.Errorf("%w: 0 confirmed, %d unconfirmed, %d rejected, %d refused. Reporting "+
		"dast_status completed_clean from this ledger would tell a coding agent that "+
		"Anvil looked and found nothing, which is not what happened",
		ErrSilentlyClean, unconfirmed, l.RejectedCount(), refused)
}

// String renders the ledger's arithmetic for a log.
func (l Ledger) String() string {
	if !l.sealed {
		return "ledger(unconstructed)"
	}
	return fmt.Sprintf("candidates=%d confirmed=%d unconfirmed=%d rejected=%d refused=%d",
		l.CandidateCount(), l.ConfirmedCount(), l.UnconfirmedCount(),
		l.RejectedCount(), l.RefusedCount())
}

// ---------------------------------------------------------------------------
// Extraction — the only code that touches a body
// ---------------------------------------------------------------------------

// hashBody is the "hash-and-reference by default" half of spine S7. A nil
// body hashes to the SHA-256 of the empty string rather than to "", so a
// Finding always carries a hash and EvidenceRef.Constructed() stays a
// meaningful predicate.
func hashBody(body []byte) string {
	sum := sha256.Sum256(body)
	return hex.EncodeToString(sum[:])
}

// extractSpan is the "inline only a regex-extracted evidence span" half.
//
// It returns the bounded, printable-ASCII rendering of re's first match
// against body, how many bytes it dropped as non-printable, the original
// match length if the budget ran out, and whether there was a match at all.
//
// THREE PROPERTIES, each of which a test breaks and restores:
//
//  1. THE OUTPUT IS AT MOST MaxSpanBytes. The budget is spent on OUTPUT
//     bytes, and the loop stops the moment it is full. A 512 KiB match
//     produces a 512-byte span and does not first build a 512 KiB
//     intermediate.
//  2. THE OUTPUT IS PRINTABLE ASCII. Everything outside 0x20-0x7e is dropped
//     and counted. That removes, without needing to enumerate them, every
//     C0 and C1 control, every bidirectional override and isolate, every
//     zero-width and word-joiner character, every Unicode tag character, and
//     every malformed UTF-8 byte — the classes engines.scrub removes one at a
//     time. This string is prompt-bound, so the charset is an allowlist and
//     not a denylist.
//  3. IT DROPS RATHER THAN SUBSTITUTES. A replacement character would be a
//     byte Anvil invented appearing inside prose attributed to the target.
//     The dropped count is how a reader learns something was removed.
func extractSpan(body []byte, re *regexp.Regexp) (span string, dropped, truncatedFrom int, matched bool) {
	if re == nil {
		return "", 0, 0, false
	}
	loc := re.FindIndex(body)
	if loc == nil {
		return "", 0, 0, false
	}
	match := body[loc[0]:loc[1]]

	var b strings.Builder
	budget := MaxSpanBytes
	if len(match) < budget {
		b.Grow(len(match))
	} else {
		b.Grow(budget)
	}
	consumed := 0
	for _, c := range match {
		if b.Len() == budget {
			break
		}
		consumed++
		if c < 0x20 || c > 0x7e {
			dropped++
			continue
		}
		b.WriteByte(c)
	}
	if consumed < len(match) {
		truncatedFrom = len(match)
	}
	return b.String(), dropped, truncatedFrom, true
}

// isPrintableASCII reports whether every byte of s is in 0x20-0x7e.
func isPrintableASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < 0x20 || s[i] > 0x7e {
			return false
		}
	}
	return true
}

// printable bounds s at n bytes and drops everything outside printable ASCII.
//
// It is the one channel from an untrusted identifier into a refusal message,
// and it is deliberately the same shape as engines.redactIdentifier: a bound
// and an allowlisted charset, because a refusal message is read by a human
// and increasingly by an agent.
func printable(s string, n int) string {
	var b strings.Builder
	for i := 0; i < len(s) && b.Len() < n; i++ {
		if c := s[i]; c >= 0x20 && c <= 0x7e {
			b.WriteByte(c)
		}
	}
	return b.String()
}

// assertFindingStringsBounded is the runtime half of D.27's "no
// Finding-reachable field can hold a value longer than the
// regex-extracted-span length limit".
//
// The reflection test proves the TYPE has nowhere to put a body. This proves
// the VALUE this call is about to return does not, and it runs on every
// Finding rather than only in tests — a check that runs in zero production
// paths is a check that is one refactor from being wrong without anyone
// noticing.
//
// It is written out field by field rather than by reflection on purpose: a
// reflective version would silently keep passing if a new field were added
// with a type it did not handle, whereas this fails to compile the day
// someone adds a string field and does not add it here... which is not true
// of Go, so the reflection test in confirm_gate_test.go is what catches THAT.
// The two checks cover each other's gap and neither is redundant.
func assertFindingStringsBounded(f Finding) error {
	for _, s := range []struct {
		name  string
		value string
	}{
		{"engine", f.engine},
		{"target", f.target},
		{"method", f.method},
		{"path", f.path},
		{"template_id", f.templateID},
		{"template_digest", f.templateDigest},
		{"class", string(f.class)},
		{"detection_method", string(f.detection)},
		{"outcome", string(f.outcome)},
		{"reason", string(f.reason)},
		{"evidence.body_hash", f.evidence.bodyHash},
		{"evidence.extracted_span", f.evidence.span},
	} {
		if len(s.value) > MaxSpanBytes {
			return fmt.Errorf("%w: the assembled Finding's %s is %d bytes and the bound is "+
				"%d. plan/00-SPINE.md S7 forbids inlining a response body; a field over "+
				"the span limit is how one would arrive",
				ErrRefused, s.name, len(s.value), MaxSpanBytes)
		}
	}
	return nil
}
