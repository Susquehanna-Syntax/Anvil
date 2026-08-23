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
// AND OutcomeRejected IS THE NARROWEST OF THE THREE, deliberately. It means
// the oracle RAN and did not fire, and the ONLY way to establish that it ran
// is that the target answered AS THE APPLICATION. Every other re-probe — any
// status outside applicationResponseStatuses, a body the configured defence
// signature matched, an observation that cannot say what it saw — is
// unconfirmed (ReasonReprobeIndecisive), never rejected: nothing was
// disproved, because nothing was asked. That distinction was absent from the
// first version of this file and its absence was measured — a vulnerable
// target whose limiter tripped came out `rejected` at confidence 0.000,
// indistinguishable from a phantom, and the ledger then derived
// completed_clean over a live finding. It was measured AGAIN one layer down
// when the distinction was implemented as a four-entry list of defensive
// statuses and a target answering 403 reproduced the whole defect; see
// applicationResponseStatuses for why the question is now asked the other way
// round.
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
// THE ERROR CHANNEL IS PART OF THE OUTPUT AND IS CLOSED THE SAME WAY. The
// guarantee above was once true of Finding and false of the type beside it:
// Refusal.Err was a bare `error` that ConfirmFinding filled with `%w` of the
// Reprober's error, UNBOUNDED, and a Reprober quoting an unparseable response
// put 4301 verbatim body bytes onto Ledger.Refusals()[0].Err. So:
//
//   - Refusal.Err is a RefusalError VALUE with no interface, no pointer and
//     no Unwrap. errors.Is still classifies it; errors.Unwrap hands back
//     nothing to print. See RefusalError.
//   - The Reprober's error text never enters a message. quarantine renders
//     its Go type, its length and its SHA-256 and quotes not one byte of it —
//     "hash-and-reference by default" applied to the error channel.
//   - The evidence span is withheld ENTIRELY when the regex match runs past
//     MaxSpanBytes, rather than truncated to it. A 512-byte prefix of an
//     arbitrary response body is a raw body arriving through the one channel
//     S7 sanctions, so an over-long match yields NO span rather than a
//     shorter one. See EvidenceRef.spanOverBroadBytes and extractSpan, which
//     also states what that rule does NOT claim.
//   - NewSignature refuses a pattern that fires against benignCorpus, a
//     GENERATED corpus of ordinary responses, which is where the over-broad
//     patterns come from in the first place.
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
//
// ===========================================================================
// GATE 3: regexp/syntax IS NOT ON inertImports, AND THIS FILE IMPORTS IT
// ===========================================================================
//
// refuseOverBroadPattern decides over-broadness on the PARSED pattern, which
// needs regexp/syntax. That path is not on gate 3's inert allowlist in
// internal/dast/authz/egress_chokepoint_test.go, so
// TestGate3NoSocketIsConstructedOutsideTheKernel FAILS on this file and on its
// test — by design, because gate 3 is an allowlist and the failure mode of a
// new import is a red build rather than a silent widening:
//
//	gate03 refused (gate03.socket_constructed_inside_dast_outside_kernel):
//	2 socket construction(s) inside the DAST tree but outside .../dast/authz.
//	  internal/dast/record/confirm_gate.go import "regexp/syntax"
//	  internal/dast/record/confirm_gate_test.go import "regexp/syntax"
//
// (Line numbers are omitted on purpose: they move with every edit above, and a
// citation that rots is worse than one a reader has to grep for.)
//
// THE EDIT IS ONE LINE AND IS NOT MADE HERE. Widening that allowlist is the
// review gate 3 exists to force, and a packet that widens it in the same diff
// that needs it has reviewed itself. It is reported to the orchestrator, the
// same way encoding/base64 was in internal/dast/inventory/auth_helper.go.
//
// The justification a reviewer needs, stated so the decision can be made
// without re-deriving it: regexp/syntax is the PARSER AND COMPILER behind
// `regexp`, which is already on inertImports. It has no dialer, no listener,
// no transport and no I/O of any kind — it turns a string into a tree and a
// tree into a program. Every package in this repository that imports `regexp`
// already links it transitively; gate 3 attributes by import line rather than
// transitively, which is why the line is needed at all.
package record

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"regexp/syntax"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"
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
	// pattern that fires against a body carrying no vulnerability.
	//
	// Such a pattern reproduces against ANY body, so it is an oracle that
	// always says yes. That is worse than no oracle: it converts the
	// confirmation gate into a pass-through while continuing to report
	// `confirmed`.
	//
	// FOUND BY MEASUREMENT THREE TIMES, not by design. The predicate used to
	// be re.MatchString("") alone, and against a benign homepage that
	// predicate accepted ".", "(?s).{1,512}", `[\s\S]`, ".*." and "(?s)^" —
	// five oracles that confirm a benign page at confidence 1.000. It then
	// became seventeen hand-written probes, and `(?s)[\s\S]{721}` — one byte
	// past their combined length — walked over those. It then became a
	// seeded generator over five vocabulary slices, and
	// `(?s)<h1[\s\S]{0,400}` walked over THAT, because `h1` was not one of
	// the tag names the generator was given.
	//
	// EACH OF THOSE PREDICATES WAS A SAMPLE OF BODIES, and the sentinel is
	// now raised by two checks that are not the same kind of thing: a
	// STRUCTURAL one that decides on the parsed pattern and samples nothing
	// (refuseOverBroadPattern — the control), and the generated corpus
	// (the backstop). An earlier version of this comment said the corpus
	// section explained "why not a cleverer regex analysis either"; no such
	// paragraph ever existed, and the analysis it was waving away is now the
	// control. Both sections say which is which.
	ErrSignatureMatchesEverything = errors.New("dastrecord: the signature fires against a body with no vulnerability in it and would confirm anything")

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

// MinAttempts is the floor on GateConfig.Attempts, and it exists because the
// bound used to have a ceiling and no floor.
//
// Attempts=1 was legal, and a gate configured that way still stamped
// reason="reproduced_on_every_attempt" — from ONE observation. That is not a
// weaker version of the flake detection DefaultAttempts=3 exists for, it is
// the flake detection removed while the reason string goes on claiming it
// ran. A caller under a time budget (D.31 wiring is exactly that caller) is
// the one most likely to set it, and it is the one place where the saving is
// invisible in the output.
//
// Two is the floor and not three because two is the smallest count at which
// the ratio has a middle: a flake shows up as 1/2 and lands on
// ReasonReproducedIntermittently. At one attempt there is no ratio at all.
// Three remains the default for the reason DefaultAttempts states. A caller
// that must spend less should re-probe FEWER CANDIDATES, not ask each
// candidate a question it cannot answer.
const MinAttempts = 2

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

	// ReasonReprobeIndecisive: the re-probe did not establish that the
	// target answered AS THE APPLICATION, so the oracle never got to run.
	//
	// THIS IS THE FAILURE THIS PROJECT EXISTS TO AVOID, and it was
	// unmitigated until it was measured. Observation.Status was captured,
	// stamped onto the Finding and READ BY NOTHING. A genuinely vulnerable
	// target whose rate limiter trips during the confirmation pass returns
	// 429 on all three attempts; the signature matches none of them because
	// there is no application response to match against; and the candidate
	// came out outcome=rejected, reason=did_not_reproduce_on_any_attempt,
	// confidence 0.000 — byte-for-byte indistinguishable from a phantom.
	// A real vulnerability, reported clean.
	//
	// The first fix named the condition "defended" and enumerated four
	// statuses that meant it. THAT WAS THE SAME DEFECT IN A SMALLER ROOM:
	// a target answering 403 with a block page walked straight past it. The
	// condition is now the NEGATION of a positive test — see
	// applicationResponseStatuses — so every status, body and transport
	// outcome nobody enumerated lands here instead of in `rejected`.
	//
	// It is UNCONFIRMED and never REJECTED: nothing was disproved, because
	// nothing was asked. It is also not a refusal — the request did leave
	// the process and Anvil did observe something, which is more than
	// ErrNotReprobed describes.
	ReasonReprobeIndecisive Reason = "reprobe_did_not_reach_the_application"
)

// ReasonValues returns every legal reason, excluding the zero value.
func ReasonValues() []Reason {
	return []Reason{
		ReasonReproduced, ReasonNoOracleForClass,
		ReasonModelInferenceIsNotObservation, ReasonReproducedIntermittently,
		ReasonDidNotReproduce, ReasonReprobeIndecisive,
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
	case ReasonNoOracleForClass, ReasonModelInferenceIsNotObservation,
		ReasonReproducedIntermittently, ReasonReprobeIndecisive:
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
	re  *regexp.Regexp
	src string

	// spelled is minLiteral from refuseOverBroadPattern: a LOWER BOUND, in
	// bytes, on the literal content every match path of this pattern
	// requires. It is carried on the Signature rather than recomputed
	// because extractSpan needs it on every re-probe, and parsing the
	// pattern per attempt would make the composition rule something a
	// caller works around.
	//
	// It is ZERO on any Signature NewSignature did not build, and zero is
	// the fail-closed value: a match with no spelled bytes has no budget for
	// unspelled ones, so extractSpan produces no span at all. Validate
	// refuses an unconstructed Signature before that can matter in
	// production; the zero is what makes an in-package test fixture fail
	// closed too.
	spelled int

	sealed bool
}

// ---------------------------------------------------------------------------
// The syntactic over-broadness check — THIS IS THE CONTROL
// ---------------------------------------------------------------------------
//
// ===========================================================================
// FOUR ROUNDS OF ENUMERATION, AND WHY DECIDING ON THE PATTERN ENDS IT
// ===========================================================================
//
// "Is this regex an oracle, or does it say yes to anything?" was asked three
// times by RUNNING the regex against bodies, and each answer was a set of
// bodies: the empty string; then seventeen hand-written probes; then a seeded
// generator over five hand-written vocabulary slices. Every one of those is a
// CORPUS — a generator with a fixed seed and a written-down alphabet is a
// corpus assembled by a loop — and a corpus is a sample. The attacker needs
// one input outside the sample, and each round produced one:
//
//	re.MatchString("") alone     `.` walked over it
//	seventeen probes, 720 bytes  `(?s)[\s\S]{721}` walked over it
//	a generated corpus, 1 MiB    `(?s)<h1[\s\S]{0,400}` walks over it,
//	                             because <h1 is not one of the thirteen tag
//	                             names the generator was given
//
// The third is MEASURED: 17 of 20 bounded-prefix HTML anchors pass, and the
// h1 spelling also INLINES 403 verbatim body bytes into ExtractedSpan, which
// MaxSpanBytes cannot see because that bound only refuses matches LONGER than
// 512.
//
// So the question is asked a different way, and it is asked OF THE PATTERN. A
// parsed regex is a finite object. "What must every match path of this pattern
// require, and what can every match path swallow?" is answered by walking it,
// and the answer depends on no body, no vocabulary, no seed and no list. THERE
// IS NOTHING HERE FOR AN ATTACKER TO STEP OUTSIDE, because nothing is sampled.
//
// ===========================================================================
// THE THREE RULES, AND WHAT EACH ONE CLOSES
// ===========================================================================
//
// A rune position in a match is one of three things: the pattern SPELLS it (a
// literal, or a class naming exactly one rune), the pattern DECLARES it (a
// class the pattern narrowed), or the pattern leaves it OPEN. The rules are
// stated over that partition.
//
//	R1  FOOTING. Every match path must require at least one byte of literal
//	    content. A pattern that can match while spelling nothing describes a
//	    body's SHAPE, and a shape is not an oracle. This closes the whole
//	    length-threshold family — `[\s\S]{721}`, eighty-five concatenated
//	    `.{1000}`, `(?s)^`, `a?`, `x{0,3}` — BY CONSTRUCTION rather than by
//	    owning a body longer than the pattern demands. There is no number in
//	    it.
//
//	R2  NO OPEN POSITION. Every rune a match can consume must be spelled by
//	    the pattern or drawn from a class confined to printable ASCII,
//	    0x20-0x7e.
//
//	    THE CHARSET IS NOT CHOSEN HERE. It is extractSpan's own: the span
//	    extractor DROPS every byte outside 0x20-0x7e and counts them into
//	    SpanDroppedBytes. So R2 says only this — a signature may not match
//	    through bytes its own evidence extractor throws away. A pattern that
//	    does is one whose span is not what it matched, and it is, every
//	    time, a pattern that declared nothing about what it would quote.
//	    `[\s\S]`, `.`, `[^\n]`, `\s` and `[^\x00]` are all open, so this is
//	    the rule that kills the bounded-prefix family — `(?s)<h1[\s\S]{0,400}`
//	    and `(?s)<div[\s\S]{0,500}` alike — WITHOUT knowing what a div is.
//	    There is no number in it either.
//
//	R3  QUOTATION. A class that admits an ASCII LETTER and also an ASCII
//	    rune that is neither letter nor digit can run from one token into
//	    the next, which is what it takes to carry the response's prose,
//	    markup or structure. Positions drawn from such a class are the
//	    pattern QUOTING THE BODY, and a match path may not quote more
//	    positions than it spells bytes.
//
//	    This is the only rule with a relation in it, and the relation has no
//	    knob: it is 1:1 against the pattern's own literal footing, not a
//	    ceiling somebody picked. It closes the R2 evasion — rewrite
//	    `(?s)<h1[\s\S]{0,400}` as `<h1[[:print:]]{0,400}` and the class is no
//	    longer open, but 400 quoted positions against 3 spelled bytes is
//	    refused all the same.
//
//	    "SUCH A CLASS" IS THE UNION OF WHAT THE POSITION CAN CONSUME, not
//	    the classes taken one at a time, and getting that wrong was a
//	    measured evasion of this rule. `[0-9A-Za-z]` is not content-bearing;
//	    `[[:punct:]]` carries no letter and is not content-bearing either;
//	    their UNION is both, and a match at a position that can take either
//	    runs across token boundaries exactly as `[[:print:]]` does.
//	    regexp/syntax merges `[0-9A-Za-z]|[[:punct:]]` into one class and
//	    the old per-branch reading caught it by accident — but capture
//	    groups block that merge, and
//	    `ZZZZZZZZ(?:([0-9A-Za-z])|([[:punct:]])|( ))*` was ACCEPTED with a
//	    quotation count of zero and then matched ALL 634 BYTES of an
//	    ordinary single-line HTML document — 626 of them past its eight
//	    bytes of literal footing, through spaces, semicolons, angle brackets
//	    and quotes. So the union is taken AT THE STEP WHERE THE AMBIGUITY IS:
//	    at an alternation, whose branches are readings of one position, and
//	    at a repeat, whose unit's alphabet is the alphabet of the contiguous
//	    region the repeat produces. See quotationOverUnion.
//
// ===========================================================================
// WHAT R3 BUYS THE SPAN, AS ARITHMETIC
// ===========================================================================
//
// Let L be the length of a match extractSpan actually inlines, so
// L <= MaxSpanBytes = 512. Write q for the quoted (content-bearing, unspelled)
// bytes in it and s for its literal bytes. R3 gives q <= minLiteral, and
// minLiteral <= s because minLiteral is a lower bound on the literal every
// path requires, so q <= s = L - q and therefore
//
//	q <= L/2 <= 256.
//
// AT MOST HALF OF ANY INLINED SPAN IS BODY THE PATTERN DID NOT SPELL, AND
// NEVER MORE THAN 256 BYTES OF IT. The measured 403-byte h1 inlining is not
// made smaller by this; it stops compiling.
// TestTheQuotationRuleBoundsWhatAnInlinedSpanCanCarry drives the inequality
// over real matches rather than restating it.
//
// THE SAME INEQUALITY IS ENFORCED A SECOND TIME, ON THE ACTUAL MATCH, and
// that is not redundancy. R3 reasons about CONTENT-BEARING positions and says
// nothing about a class like `[0-9A-Za-z]`; rerunning this round's own attack
// one class to the left found `<h1[0-9A-Za-z]{0,400}` accepted and inlining
// 403 bytes. extractSpan's property 1b re-applies L - s <= s to the match
// itself, where no class definition is involved at all, and that is what
// makes the arithmetic above true of EVERY accepted signature rather than
// only of the ones R3 looked at.
//
// ===========================================================================
// WHAT THIS DOES NOT DECIDE, STATED BECAUSE IT IS THE WHOLE RESIDUAL
// ===========================================================================
//
// THE RULES DECIDE STRUCTURE. THEY DO NOT DECIDE WHETHER A LITERAL IS
// TARGET-SPECIFIC, and nothing structural can. That is ONE residual, wearing
// three faces, all the same defect. (It is not the only thing the rules leave
// open — the class carve-out at the end of this section is the other, and it
// is a different question: not "is this literal a marker" but "how much of the
// response may a token-shaped class run through".)
//
//	(?i)(error|warning|expired)   spells five to seven bytes on every path,
//	                              quotes nothing, passes R1, R2 and R3 — and
//	                              confirms a SQL-injection candidate at
//	                              confidence 1.000 against an ordinary page
//	                              carrying the word "expired". MEASURED.
//	<h1[[:print:]]{0,3}           three spelled bytes, three quoted, R3
//	                              satisfied 1:1. Confirms any page with an h1.
//	<h1[0-9A-Za-z]{0,400}         an alnum class is not content-bearing, so
//	                              R3 does not count it — see the note below.
//	                              Confirms any page with an h1, and its
//	                              403-byte INLINING is closed at extraction
//	                              (extractSpan property 1b) rather than here.
//
// In every case the literal is real, required, and ordinary. THE RULES CANNOT
// TELL AN ORDINARY LITERAL FROM A MARKER, because both are spelled bytes.
//
// THAT IS WHAT THE BENIGN CORPUS IS FOR, and it is why the corpus survives
// this round as a BACKSTOP and not as the control. It answers the question the
// pattern cannot: does this literal appear in an ordinary document? Its answer
// is only as wide as its generated vocabulary. That IS a budget, it is named
// in its own section header, and it is a backstop's budget rather than a
// control's.
//
// R3'S CLASS CARVE-OUT IS THE OTHER THING TO KNOW, and it is deliberate rather
// than an oversight. `[0-9A-Z]`, `[0-9]`, `[a-zA-Z]` are not content-bearing,
// so a pattern may repeat them without a ceiling and R3 stays silent — which
// is what lets `AKIA[0-9A-Z]{16}` and `Server: nginx/1\.[0-9]+\.[0-9]+` exist
// at all. The price is that such a class can match a long token-shaped run of
// the response. NOTHING IS QUOTED FROM IT: extractSpan's composition rule
// bounds the actual match by the same inequality with no class involved, so
// the residual is a confirmation residual and not an inlining one.
//
// THE CARVE-OUT IS OVER THE UNION, and stating it any other way is what the
// previous round got wrong. It is not "each class is token-shaped", it is
// "everything the position can consume is token-shaped together" — because a
// position that can take a letter on one reading and a semicolon on another
// crosses the boundary those two classes were supposed to respect. So
// `[0-9A-Z]` repeated is silent, and `(?:[0-9A-Z]|[[:punct:]])` repeated is
// not, even when capture groups stop the parser folding the two into one
// class. R3 aggregates over the union at an ALTERNATION and at a REPEAT'S
// UNIT; those are the two nodes where one region of the response has more than
// one alphabet.
//
// THE UNION IS OVER LITERALS AND CLASSES ALIKE, and reading it as "classes
// only" is how the same evasion came back a round later. `consumes` used to
// hold classes because "a literal is not a class" — so the punctuation was
// respelled as captured single-rune literals and the whole thing was accepted
// again with quoted=0, matching 252 of the 321 bytes of an ordinary document.
// The non-capturing spelling was refused ONLY because regexp/syntax merges
// alternated single runes into a class, which made the guard's real dependency
// a parser optimisation rather than the rule it states. Two things close it,
// and each is load-bearing on its own:
//
//	A SPELLED RUNE IS IN THE UNION. `(?:([a-z])|( ))*` is a class and a
//	space, and the space is what turns a lowercase-token alphabet into
//	prose. See spelledRunes.
//	AN ALTERNATION IS AN UNDECIDED POSITION. Putting the literals in the
//	union is not enough by itself, because quotation is promoted from
//	DECLARED positions and an alternation whose every branch is a spelled
//	rune declares none. Twenty-nine captured single-rune literals spelling
//	the alphabet of English prose contain no class at all. So an alternation
//	over an alphabet of more than one rune counts as at least one declared
//	position. See the OpAlternate arm of shapeOf.
//
// The price is stated rather than hidden: a repeat of an alternation whose
// union crosses letters into punctuation is now refused EVEN WHEN EVERY BRANCH
// IS SPELLED, so `Z(?:err|, )*` no longer compiles. Its bytes are all spelled,
// but a two-hundred-byte alphabet declaration is not evidence about a
// response, and R3's remedy — give the repeat a ceiling — still applies.
//
// WHAT R3 STILL DOES NOT DECIDE, SO IT IS SAID RATHER THAN IMPLIED: a
// CONCATENATION of differing narrow classes. A concatenation is a sequence of
// positions, each with one alphabet, so its union is not any position's
// alphabet and R3 does not promote it. `Z[ab][,;][ab][,;]...` therefore quotes
// positions R3 counts as zero. THE BOUND ON THAT IS ARITHMETIC, NOT A LIST:
// every such position must be SPELLED OUT in the pattern, the cheapest
// spelling of a two-rune class is four bytes, and MaxPatternBytes is 1024.
// MEASURED at the ceiling: `Z` followed by 127 copies of `[ab][,;]` is 1017
// bytes, is accepted, and matches 255 bytes of a body it spells one byte of;
// 128 copies is 1025 bytes and does not compile at all. The consequence is
// closed downstream and measured there too: extractSpan inlines ZERO bytes of
// that 255-byte match and reports all 255 as SpanOverBroadBytes, because
// property 1b re-applies L - s <= s to the match with no class definition
// involved. TestTheQuotationRuleIsTakenOverTheUnionOfWhatAPositionConsumes
// drives both halves.

// printableASCIILo and printableASCIIHi are extractSpan's charset. R2 is about
// exactly that set, and a second spelling of 0x20 and 0x7e would be a second
// thing to keep current.
// TestTheOpenPositionRuleUsesTheSpanExtractorsOwnCharset asserts the two agree
// by RUNNING the extractor over every byte rather than by reading it.
const (
	printableASCIILo = 0x20
	printableASCIIHi = 0x7e
)

// patternShape is what one walk of a parsed pattern learned about it.
//
// Both numbers are worst-case over match paths, and they are taken
// INDEPENDENTLY: minLiteral is the minimum over paths and quoted is the
// maximum over paths, so a pattern whose thinnest path and whose greediest
// path are different paths is judged against both at once. That is
// conservative — it can only refuse a pattern a per-path analysis would
// accept, never accept one a per-path analysis would refuse — and
// conservative is the direction this gate fails in.
type patternShape struct {
	// minLiteral is a LOWER BOUND, in bytes, on the literal content every
	// match path requires. R1 refuses zero.
	minLiteral int
	// quoted is an UPPER BOUND on the number of rune positions a match can
	// draw from a content-bearing class. shapeUnbounded means a repeat with
	// no ceiling. R3 compares it with minLiteral.
	quoted int
	// declared is an UPPER BOUND on the number of rune positions a match can
	// draw from ANY multi-rune class, content-bearing or not. It is what
	// quoted becomes when the UNION of those classes turns out to be
	// content-bearing even though no single one of them was: see
	// quotationOverUnion.
	declared int
	// consumes is the UNION, as a rune-pair list in the shape
	// regexp/syntax uses, of every rune a position in this sub-expression
	// can draw from — FROM CLASSES AND FROM SPELLED LITERALS ALIKE. See
	// spelledRunes for why the literals are in it: a literal at an
	// alternation position is an alphabet of one, and a union that leaves
	// it out is a union over a REPRESENTATION rather than over the subject.
	//
	// IT IS WHY THIS STRUCT EXISTS RATHER THAN TWO INTS. quoted alone is a
	// MAX over alternation branches, and a max over branches is not the
	// alphabet of the position: `(?:([0-9A-Za-z])|([[:punct:]]))` has a
	// non-content-bearing class on every branch and a content-bearing
	// UNION, and the capture groups stop the parser merging the classes
	// into one. The union is taken where the ambiguity is — at the
	// alternation, and at a repeat's unit — not at the end.
	//
	// PUTTING LITERALS IN IT DOES NOT MAKE EVERY LETTERED PATTERN
	// CONTENT-BEARING, which was the old comment's fear and the reason they
	// were left out. contentBearingClass is what decides, it partitions
	// printable ASCII into letter / digit / other, and a union of letters
	// is not content-bearing. `(?i)(error|warning|expired)` still compiles;
	// so does `(?:[0-9]{1,3}\.){3}` with its spelled dot. What changes is
	// that a union crossing letters INTO punctuation is seen however it was
	// spelled.
	consumes []rune
	// open reports that some path can consume a rune the pattern neither
	// spells nor confines to printable ASCII. R2 refuses it outright, so
	// this is a bool and not a count: one open position is enough.
	open bool
}

// shapeUnbounded marks a count that no repeat ceiling bounds. It is negative
// so that arithmetic on it cannot be mistaken for a large number.
const shapeUnbounded = -1

// shapeCeiling is where saturating arithmetic gives up and says unbounded.
//
// It is not a limit on what patterns may do: it is far above anything
// MaxPatternBytes can express (Go caps a repeat's total expansion at 1000, so
// a 1024-byte pattern cannot demand more than 1,024,000 of anything), and
// saturating lands on shapeUnbounded, which R3 refuses. The only thing it
// prevents is signed overflow turning a huge count negative and passing.
const shapeCeiling = 1 << 30

func addShape(a, b int) int {
	if a == shapeUnbounded || b == shapeUnbounded {
		return shapeUnbounded
	}
	if a > shapeCeiling-b {
		return shapeUnbounded
	}
	return a + b
}

func mulShape(a, n int) int {
	if n <= 0 {
		return 0
	}
	if a == shapeUnbounded {
		return shapeUnbounded
	}
	if a == 0 {
		return 0
	}
	if a > shapeCeiling/n {
		return shapeUnbounded
	}
	return a * n
}

// maxShape is the larger of two counts with shapeUnbounded ordered above every
// finite one. shapeUnbounded is negative, so the ordinary comparison would
// pick the finite number and lose the refusal.
func maxShape(a, b int) int {
	if a == shapeUnbounded || b == shapeUnbounded {
		return shapeUnbounded
	}
	if a > b {
		return a
	}
	return b
}

// unionRunes merges two rune-pair class lists into one normalised list.
//
// The result is sorted by low bound with overlapping and ADJACENT ranges
// merged, so `[0-9]` unioned with `[a-z]` and `[A-Z]` is three pairs rather
// than a list that grows with every class the walk meets. That bound matters:
// a normalised union over printable ASCII can hold at most 48 pairs whatever
// the pattern does, so this cannot be made expensive by a hostile pattern.
//
// It always allocates. The inputs are the parser's own slices, shared between
// sub-expressions, and appending into one of them would rewrite a class the
// walk has not finished with.
func unionRunes(a, b []rune) []rune {
	if len(a) == 0 && len(b) == 0 {
		return nil
	}
	pairs := make([][2]rune, 0, (len(a)+len(b))/2)
	for _, src := range [][]rune{a, b} {
		for i := 0; i+1 < len(src); i += 2 {
			if src[i] > src[i+1] {
				continue
			}
			pairs = append(pairs, [2]rune{src[i], src[i+1]})
		}
	}
	if len(pairs) == 0 {
		return nil
	}
	sort.Slice(pairs, func(i, j int) bool {
		if pairs[i][0] != pairs[j][0] {
			return pairs[i][0] < pairs[j][0]
		}
		return pairs[i][1] < pairs[j][1]
	})
	out := make([]rune, 0, len(pairs)*2)
	lo, hi := pairs[0][0], pairs[0][1]
	for _, p := range pairs[1:] {
		if p[0] <= hi+1 {
			if p[1] > hi {
				hi = p[1]
			}
			continue
		}
		out = append(out, lo, hi)
		lo, hi = p[0], p[1]
	}
	return append(out, lo, hi)
}

// spelledRunes is a SPELLED literal's contribution to a position's alphabet,
// as a rune-pair list in the shape unionRunes and contentBearingClass consume.
//
// RULING 12, AND THE REASON THIS FUNCTION EXISTS AT ALL: a literal at an
// alternation position is AN ALPHABET OF ONE, and a union that leaves it out
// is not the alphabet of the position. `consumes` used to hold classes only,
// on the reading that "a literal is not a class" — so spelling the punctuation
// as captured single-rune literals restored the whole evasion:
//
//	MEASURED, and it is why this function exists:
//	`anvil-probe-4f2a(?:([0-9A-Za-z])|( )|(<)|(>)|(/)|(")|(=)|(-)|(:)|(;)|(,)|(\.)|(!)|(@))*`
//	was ACCEPTED with quoted=0 and then matched 252 of the 321 bytes of an
//	ordinary HTML document. Its non-capturing spelling was refused only
//	because regexp/syntax MERGES the branches into one class — so the
//	guard's real dependency was a parser optimisation rather than the
//	stated rule.
//
// ONLY PRINTABLE ASCII IS CARRIED, and that is a bound rather than a
// convenience. contentBearingClass partitions printable ASCII and ignores
// everything else, so a rune outside 0x20-0x7e could not change any verdict;
// dropping it here is what keeps a normalised union at no more than 48 pairs
// however many distinct runes a 1024-byte pattern spells.
//
// UNDER (?i) THE WHOLE FOLD ORBIT IS CARRIED, for the same reason
// literalRuneBytes takes the orbit's shortest member: `(?i)K` can consume 'k',
// and a position's alphabet must hold everything the position can consume.
func spelledRunes(rs []rune, fold bool) []rune {
	pairs := make([]rune, 0, len(rs)*2)
	add := func(r rune) {
		if r >= printableASCIILo && r <= printableASCIIHi {
			pairs = append(pairs, r, r)
		}
	}
	for _, r := range rs {
		add(r)
		if !fold {
			continue
		}
		for f := unicode.SimpleFold(r); f != r; f = unicode.SimpleFold(f) {
			add(f)
		}
	}
	return unionRunes(pairs, nil)
}

// alphabetIsAmbiguous reports whether a rune-pair list names more than one
// rune — that is, whether a position drawing from it is a position the pattern
// did not decide.
//
// It counts rather than measures length because unionRunes emits RANGES: one
// pair can name ninety-five runes, and `len(runes) > 2` would miss it.
func alphabetIsAmbiguous(runes []rune) bool {
	n := 0
	for i := 0; i+1 < len(runes); i += 2 {
		if runes[i] > runes[i+1] {
			continue
		}
		n += int(runes[i+1]-runes[i]) + 1
		if n >= 2 {
			return true
		}
	}
	return false
}

// quotationOverUnion is R3's aggregation, and it is the whole of ruling 11
// applied to a regex walk: THE UNION IS TAKEN WHERE THE AMBIGUITY IS.
//
// A sub-expression's `quoted` is a max over the branches it was built from,
// and a max over branches answers "which single branch quotes most". That is
// the wrong question at a position a match can enter by any branch: the
// alphabet of such a position is the UNION of the branches' alphabets, and a
// union of token-shaped classes need not be token-shaped.
//
//	MEASURED, and it is why this function exists:
//	`ZZZZZZZZ(?:([0-9A-Za-z])|([[:punct:]])|( ))*` was ACCEPTED with
//	quoted=0 and then matched all 634 bytes of an ordinary 634-byte
//	single-line HTML document, running through spaces, semicolons and tags.
//	Each branch is a class R3 is silent about — alnum is not
//	content-bearing, punct carries no letter, and a single space is a
//	spelled literal — and the capture groups stop regexp/syntax merging the
//	three into the one class that would have been content-bearing.
//
// So where a union is formed, the count of DECLARED positions is promoted to
// quotation if the union is content-bearing. declared >= quoted always, so
// this can only ever raise the number, which is the direction this gate fails
// in.
func quotationOverUnion(s patternShape) int {
	if contentBearingClass(s.consumes) {
		return maxShape(s.quoted, s.declared)
	}
	return s.quoted
}

// literalRuneBytes is how many bytes of the response a spelled rune requires.
//
// UNDER (?i) IT IS THE SHORTEST MEMBER OF THE FOLD ORBIT, not the length of
// the rune as written. `(?i)K` matches the Kelvin sign, three bytes, but it
// also matches 'k', one byte — and minLiteral must be a LOWER bound or the
// arithmetic in this section's header is not sound.
func literalRuneBytes(r rune, fold bool) int {
	n := utf8.RuneLen(r)
	if n < 0 {
		n = 1
	}
	if !fold {
		return n
	}
	for f := unicode.SimpleFold(r); f != r; f = unicode.SimpleFold(f) {
		if m := utf8.RuneLen(f); m > 0 && m < n {
			n = m
		}
	}
	return n
}

// runeInClass reports whether r is in a parsed class's rune-pair list.
func runeInClass(runes []rune, r rune) bool {
	for i := 0; i+1 < len(runes); i += 2 {
		if r >= runes[i] && r <= runes[i+1] {
			return true
		}
	}
	return false
}

// openClass reports whether a class can match a rune outside printable ASCII.
//
// IT ALLOWS EXACTLY ONE KIND OF NON-ASCII MEMBER: a SINGLE rune that is the
// case fold of a printable-ASCII rune the same class already admits. That is
// not an exception carved for convenience, it is what the parser does to a
// class under (?i): `(?i)[a-z]` becomes [A-Za-z] plus the two isolated runes
// U+017F and U+212A, which fold to 's' and 'k'. Without this, every
// case-insensitive class in existence would be refused as open, and the rule
// would be one nobody could satisfy rather than one nobody can evade.
//
// A range wider than one rune above 0x7e is open, whatever it contains. Fold
// artifacts are isolated single runes; a range is a request for a region of
// Unicode.
func openClass(runes []rune) bool {
	for i := 0; i+1 < len(runes); i += 2 {
		lo, hi := runes[i], runes[i+1]
		if lo < printableASCIILo {
			return true
		}
		if hi <= printableASCIIHi {
			continue
		}
		if lo <= printableASCIIHi {
			return true // straddles the top of printable ASCII
		}
		if lo != hi {
			return true
		}
		folded := false
		for f := unicode.SimpleFold(lo); f != lo; f = unicode.SimpleFold(f) {
			if f >= printableASCIILo && f <= printableASCIIHi && runeInClass(runes, f) {
				folded = true
				break
			}
		}
		if !folded {
			return true
		}
	}
	return false
}

// contentBearingClass reports whether a class can carry the response's own
// text. See R3 in this section's header for the argument.
//
// THE TEST IS A PARTITION OF PRINTABLE ASCII, NOT A LIST OF CHARACTERS. Every
// printable-ASCII rune is a letter, a digit, or neither. A class admitting a
// letter AND something that is neither can run from one token into the next,
// so a repeat of it swallows prose, markup and JSON alike. A class that cannot
// — `[0-9A-Z]`, `[0-9]`, `[A-F]` — is confined to a single token shape THE
// PATTERN DECLARED, and repeating it quotes that shape rather than the
// document.
//
// `\w` is content-bearing, because `_` is neither letter nor digit. That is
// the conservative direction and it is deliberate: an author who wants an
// identifier bounds the repeat, and a bounded repeat is what R3 asks for.
func contentBearingClass(runes []rune) bool {
	letter, other := false, false
	for i := 0; i+1 < len(runes); i += 2 {
		lo, hi := runes[i], runes[i+1]
		if lo < printableASCIILo {
			lo = printableASCIILo
		}
		if hi > printableASCIIHi {
			hi = printableASCIIHi
		}
		for r := lo; r <= hi; r++ {
			switch {
			case (r >= 'A' && r <= 'Z') || (r >= 'a' && r <= 'z'):
				letter = true
			case r >= '0' && r <= '9':
			default:
				other = true
			}
			if letter && other {
				return true
			}
		}
	}
	return false
}

// classShape is the per-class verdict: spelled, declared, or open.
//
// A class that is not content-bearing still reports declared=1 and its own
// rune list, because R3's aggregation over a union has to know what the
// position can consume even when this class alone decides nothing. See
// quotationOverUnion.
func classShape(runes []rune) patternShape {
	// A class naming exactly one rune is a literal with brackets round it,
	// and reading it as anything else would let `[<][h][1]` evade R1.
	if len(runes) == 2 && runes[0] == runes[1] {
		return patternShape{
			minLiteral: literalRuneBytes(runes[0], false),
			consumes:   spelledRunes(runes[:1], false),
		}
	}
	if openClass(runes) {
		return patternShape{open: true}
	}
	if contentBearingClass(runes) {
		return patternShape{quoted: 1, declared: 1, consumes: unionRunes(runes, nil)}
	}
	return patternShape{declared: 1, consumes: unionRunes(runes, nil)}
}

// shapeOf walks a parsed pattern.
//
// THE DEFAULT ARM IS THE POINT. An operator this function has never heard of —
// a future Go release's, or one added to regexp/syntax after this was written
// — lands on `open`, which R2 refuses. The failure mode of not knowing is a
// REFUSED SIGNATURE, never an accepted one, which is the same shape as
// applicationResponseStatuses: an allowlist with no deny side to keep current.
func shapeOf(re *syntax.Regexp) patternShape {
	if re == nil {
		return patternShape{open: true}
	}
	// The single-child operators below index Sub[0]. syntax.Parse never
	// produces one without a child, so this guard is unreachable from
	// NewSignature — but a panic inside a production admission check is a
	// crash, and "unreachable" is a claim about today's parser.
	switch re.Op {
	case syntax.OpCapture, syntax.OpQuest, syntax.OpStar, syntax.OpPlus, syntax.OpRepeat:
		if len(re.Sub) == 0 {
			return patternShape{open: true}
		}
	}
	switch re.Op {
	case syntax.OpEmptyMatch, syntax.OpBeginLine, syntax.OpEndLine,
		syntax.OpBeginText, syntax.OpEndText, syntax.OpWordBoundary,
		syntax.OpNoWordBoundary:
		// Zero width. It consumes nothing, so it spells nothing and
		// quotes nothing, and R1 is what refuses a pattern made only of
		// these.
		return patternShape{}

	case syntax.OpLiteral:
		fold := re.Flags&syntax.FoldCase != 0
		n := 0
		for _, r := range re.Rune {
			n = addShape(n, literalRuneBytes(r, fold))
		}
		// consumes carries the spelled runes too. See spelledRunes: a
		// literal at an alternation position is an alphabet of one, and a
		// union that omits it is not the alphabet of the position.
		return patternShape{minLiteral: n, consumes: spelledRunes(re.Rune, fold)}

	case syntax.OpCharClass:
		return classShape(re.Rune)

	case syntax.OpAnyChar, syntax.OpAnyCharNotNL:
		return patternShape{open: true}

	case syntax.OpCapture:
		return shapeOf(re.Sub[0])

	case syntax.OpConcat:
		var out patternShape
		for _, sub := range re.Sub {
			s := shapeOf(sub)
			out.minLiteral = addShape(out.minLiteral, s.minLiteral)
			out.quoted = addShape(out.quoted, s.quoted)
			out.declared = addShape(out.declared, s.declared)
			out.consumes = unionRunes(out.consumes, s.consumes)
			out.open = out.open || s.open
		}
		// NO UNION PROMOTION HERE, and that is deliberate. A concatenation
		// is a SEQUENCE of positions, each declared by its own class; it is
		// not one position with several readings, so the union is not this
		// node's alphabet. What a concatenation of narrow-but-differing
		// classes can do is bounded by how many of them the pattern spells
		// out, and MaxPatternBytes bounds that. A repeat is where the same
		// unit's alphabet becomes a stream region's alphabet, and that is
		// where the promotion happens. See the residual note in this
		// section's header.
		return out

	case syntax.OpAlternate:
		if len(re.Sub) == 0 {
			return patternShape{open: true}
		}
		out := shapeOf(re.Sub[0])
		out.consumes = unionRunes(out.consumes, nil)
		for _, sub := range re.Sub[1:] {
			s := shapeOf(sub)
			// The THINNEST branch decides the footing: a candidate can
			// take whichever branch it likes.
			if s.minLiteral < out.minLiteral {
				out.minLiteral = s.minLiteral
			}
			// The GREEDIEST branch decides the quotation...
			out.quoted = maxShape(out.quoted, s.quoted)
			out.declared = maxShape(out.declared, s.declared)
			// ...and the UNION of the branches decides the alphabet. A
			// match entering here can take any branch, so this position
			// consumes from all of them.
			out.consumes = unionRunes(out.consumes, s.consumes)
			out.open = out.open || s.open
		}
		// AN ALTERNATION IS A POSITION THE PATTERN DID NOT DECIDE, and
		// that is true whether its branches are classes or spelled runes.
		// declared is a max over branches, so an alternation every branch
		// of which is a single spelled rune reports declared=0 — and then
		// quotationOverUnion, which promotes DECLARED positions, has
		// nothing to promote even when the union it just computed runs
		// letters into punctuation. MEASURED before this line existed:
		// `anvil-probe-4f2a(?:(a)|(b)|...|(z)|( )|(,)|(\.))*`, thirty-two
		// captured single-rune literals and not one class, was ACCEPTED
		// with quoted=0.
		//
		// One is a LOWER count than the number of positions some branches
		// consume, and that is deliberate rather than an oversight: it is
		// the number this node can justify from its own structure without
		// a second traversal, and R3's arithmetic stays sound because
		// minLiteral takes the MINIMUM over branches — a branch drawing
		// from a class contributes zero footing, so a repeat of a mixed
		// alternation is judged against the footing of its thinnest
		// branch. What one buys is the whole of ruling 12 here: a repeat
		// of an ambiguous position is a repeat of an ambiguous position,
		// so `unboundedIfDeclaring` refuses it however it was spelled.
		if len(re.Sub) > 1 && alphabetIsAmbiguous(out.consumes) {
			out.declared = maxShape(out.declared, 1)
		}
		out.quoted = quotationOverUnion(out)
		return out

	case syntax.OpQuest:
		s := shapeOf(re.Sub[0])
		return patternShape{minLiteral: 0, quoted: s.quoted, declared: s.declared,
			consumes: s.consumes, open: s.open}

	case syntax.OpStar:
		s := shapeOf(re.Sub[0])
		return patternShape{minLiteral: 0, quoted: unboundedIfQuoting(s),
			declared: unboundedIfDeclaring(s), consumes: s.consumes, open: s.open}

	case syntax.OpPlus:
		s := shapeOf(re.Sub[0])
		return patternShape{minLiteral: s.minLiteral, quoted: unboundedIfQuoting(s),
			declared: unboundedIfDeclaring(s), consumes: s.consumes, open: s.open}

	case syntax.OpRepeat:
		s := shapeOf(re.Sub[0])
		out := patternShape{consumes: s.consumes, open: s.open}
		out.minLiteral = mulShape(s.minLiteral, re.Min)
		if re.Max < 0 {
			out.quoted = unboundedIfQuoting(s)
			out.declared = unboundedIfDeclaring(s)
		} else {
			out.quoted = mulShape(quotationOverUnion(s), re.Max)
			out.declared = mulShape(s.declared, re.Max)
		}
		return out

	default:
		return patternShape{open: true}
	}
}

// unboundedIfQuoting is the repeat rule for a ceiling-less repeat.
//
// Repeating something that quotes nothing quotes nothing however many times it
// runs: `(abc)+` can be arbitrarily long and every byte of it is spelled.
// Repeating something that quotes even one position quotes without limit.
//
// THE UNIT'S QUOTATION IS TAKEN OVER ITS UNION, not over its per-branch max.
// A repeat makes one contiguous region of the response out of many traversals
// of the unit, so the region's alphabet is the union of everything the unit
// can consume — which is how `(?:[a-z][[:punct:]])*` quotes without limit
// while neither of its two classes is content-bearing on its own.
func unboundedIfQuoting(s patternShape) int {
	if quotationOverUnion(s) == 0 {
		return 0
	}
	return shapeUnbounded
}

// unboundedIfDeclaring is unboundedIfQuoting for the declared count: a
// ceiling-less repeat of a unit that draws even one position from a class
// draws unboundedly many.
//
// declared has to be carried through repeats separately from quoted, because
// it is what quoted BECOMES when an enclosing alternation's union turns out to
// be content-bearing. Collapsing it into quoted here would be the same defect
// this fix exists to close, one node higher.
func unboundedIfDeclaring(s patternShape) int {
	if s.declared == 0 {
		return 0
	}
	return shapeUnbounded
}

// refuseOverBroadPattern is the control. See this section's header.
//
// It runs BEFORE the benign corpus in NewSignature, and the order is not only
// about which check is the control. It is also what makes the corpus scan
// affordable: the pathological patterns that cost seconds to run against a
// megabyte — eighty-five concatenated `[\s\S]{1000}` is the worst expressible
// under MaxPatternBytes — are open under R2 and are refused here, in
// microseconds, without the corpus ever being touched.
// It returns the pattern's minLiteral on success, which is what the accepted
// Signature carries into extractSpan as its span budget. Returning it here
// rather than recomputing it later is what keeps the two numbers the same
// number.
func refuseOverBroadPattern(pattern string) (spelled int, err error) {
	parsed, err := syntax.Parse(pattern, syntax.Perl)
	if err != nil {
		// regexp.Compile parses with these same flags and has already
		// succeeded by the time this runs, so this arm is unreachable
		// today. It refuses rather than returning nil anyway: an
		// unanalysable pattern is one this control cannot vouch for.
		return 0, fmt.Errorf("%w: %q could not be parsed for structural analysis: %s",
			ErrSignatureMatchesEverything, printable(pattern, MaxFieldBytes),
			printable(err.Error(), MaxFieldBytes))
	}
	shape := shapeOf(parsed)

	if shape.minLiteral == 0 {
		return 0, fmt.Errorf("%w: %q has a match path that requires no literal content at "+
			"all (rule R1). A pattern that can match while spelling nothing describes "+
			"the SHAPE of a response rather than anything wrong with one, so it fires "+
			"on every response of that shape. This is decided on the pattern, not by "+
			"running it against any body",
			ErrSignatureMatchesEverything, printable(pattern, MaxFieldBytes))
	}
	if shape.open {
		return 0, fmt.Errorf("%w: %q can match a rune it neither spells nor confines to "+
			"printable ASCII 0x%02x-0x%02x (rule R2). That is the charset extractSpan "+
			"drops bytes outside of, so such a pattern matches through bytes its own "+
			"evidence extractor throws away — and a class that open declares nothing "+
			"about what the span will quote. Narrow the class, or spell the rune",
			ErrSignatureMatchesEverything, printable(pattern, MaxFieldBytes),
			printableASCIILo, printableASCIIHi)
	}
	if shape.quoted == shapeUnbounded {
		return 0, fmt.Errorf("%w: %q can quote unboundedly many positions from a class that "+
			"carries ordinary text, against %d byte(s) of literal footing (rule R3). "+
			"Give the repeat a ceiling",
			ErrSignatureMatchesEverything, printable(pattern, MaxFieldBytes),
			shape.minLiteral)
	}
	if shape.quoted > shape.minLiteral {
		return 0, fmt.Errorf("%w: %q quotes up to %d position(s) of ordinary text against %d "+
			"byte(s) of literal footing (rule R3). A signature may not quote more of "+
			"the response than it spells: past that point the span is the response "+
			"rather than evidence about it",
			ErrSignatureMatchesEverything, printable(pattern, MaxFieldBytes),
			shape.quoted, shape.minLiteral)
	}
	return shape.minLiteral, nil
}

// ---------------------------------------------------------------------------
// The benign corpus — THE BACKSTOP, generated and never enumerated
// ---------------------------------------------------------------------------
//
// ===========================================================================
// THIS IS THE BACKSTOP. refuseOverBroadPattern IS THE CONTROL.
// ===========================================================================
//
// SAYING WHICH IS WHICH IS THE POINT OF THIS PARAGRAPH. For three rounds this
// corpus was described as the check that decides whether a signature is an
// oracle, and it was never able to be that: every corpus is a sample, a
// generator over a written-down alphabet is a corpus, and a sample has a
// budget — one input outside it. The fourth round moved the decision onto the
// PATTERN, where it is structural and samples nothing. See the section above.
//
// What survives here is the half a structural rule cannot do. R1, R2 and R3
// decide what a pattern REQUIRES and what it can SWALLOW; they cannot decide
// whether `<title>` is a marker or furniture, because both are seven spelled
// bytes. This corpus decides that one question — does the literal appear in an
// ordinary document? — by generating ordinary documents and looking.
//
// ITS ANSWER IS ONLY AS WIDE AS ITS VOCABULARY, AND THAT IS A BUDGET. The tag
// list below has thirteen entries and `h1` is not one of them, which is the
// measured miss: 17 of 20 bounded-prefix HTML anchors passed this check.
// Those all fail R2 now, on the pattern, whatever tag they name.
//
// THE BUDGET IS EVERY WRITTEN-DOWN LIST IN THESE GENERATORS, AND THERE ARE
// NINE OF THEM. It was disclosed as one, then as five, and five was still
// narrower than what a probe finds. A signature spelling anything outside ANY
// of the lists is a signature this corpus cannot see. MEASURED, probes per
// list, every "accepted" one below waved through by NewSignature with nothing
// wrong with it:
//
//	the SHAPE list, 4 entries     THE WIDEST ONE, and it was never named.
//	                              buildBenignCorpus crosses lengths with
//	                              exactly four generators — prose, HTML,
//	                              JSON, structural — so no XML document, no
//	                              PEM block and no multipart part is ever
//	                              generated. `<\?xml `, `-----BEGIN ` and
//	                              `Content-Disposition: ` are all accepted.
//	                              Every ordinary response in a format this
//	                              list does not name is invisible to the
//	                              backstop entirely, not merely at the token
//	                              level.
//	benignWords, 33 entries       `(?i)(error|warning|expired)` — the
//	                              originally-disclosed face. It confirms a
//	                              SQL-injection candidate at confidence
//	                              1.000 against an ordinary page carrying
//	                              the word "expired".
//	benignProse enders, 6 pairs   prose ends a sentence with one of six
//	                              fixed pairs, so `!` is only ever followed
//	                              by a newline and `?` only by a space:
//	                              `! ` is accepted while `\. ` and `; ` are
//	                              refused.
//	benignHTML tags, 13 entries   `<h1>`, `<table`, `<button`, `<form ` are
//	                              accepted; `<div` and `<h2` are refused.
//	                              The difference between those two groups is
//	                              nothing but the list.
//	benignHTML classes, 9         reachable the same way, through
//	                              `class="..."` values the generator never
//	                              emits.
//	benignHTML's fixed head       the document skeleton is six literal
//	                              lines, so the only attributes that ever
//	                              appear are lang, charset, rel, href, src
//	                              and class, and the only paths are
//	                              /static/site.css and /static/app.js.
//	                              `id="`, `data-testid="`, `href="https`,
//	                              `/assets/` and `&amp;` are accepted —
//	                              NO HTML ENTITY IS EVER EMITTED — while
//	                              `class="`, `href="/static` and `<title>`
//	                              are refused.
//	benignJSON keys, 14 entries   `"error_code":` and `"user_id":` are
//	                              accepted; `"status":` is refused.
//	benignJSON value kinds, 6     the switch has six arms and every number
//	                              is printed with %d, so NO DECIMAL POINT
//	                              EVER FOLLOWS A DIGIT and an array only
//	                              ever holds integers: `1\.0`, `0\.0` and
//	                              `\[\{` are accepted; `:null` and `\[\]`
//	                              are refused.
//	benignStructural toks,        `X-Powered-By: `, `Set-Cookie: `,
//	  45 entries                  `text/html` and `HTTP/1\.1 404` are
//	                              accepted. The list carries ONE status
//	                              line and ONE content type, and every other
//	                              header and media type ever sent is outside
//	                              it.
//
// TestTheCorpusResidualIsAsWideAsItsVocabularies drives all of these, so the
// disclosure fails when it stops being true rather than aging quietly.
//
// A BACKSTOP IS ALLOWED A BUDGET. A control is not, which is why the control
// is somewhere else now — and why the honest statement of this one is "nine
// vocabularies, the widest of which is the list of formats it can generate at
// all" rather than "a word list".
//
// A Signature must fire on NONE of these bodies. What they are is "responses
// with nothing wrong with them", and an oracle that cannot tell one of those
// from a vulnerable response is an oracle that says yes.
//
// This used to be seventeen hand-written probes totalling 720 bytes. MEASURED:
// NewSignature accepted `(?s)[\s\S]{721}` — one byte past the longest probe —
// and that pattern confirms an ordinary 3 KiB product page at confidence
// 1.000. The five originally-enumerated over-broad patterns were correctly
// refused; the CORPUS was the ceiling, and the ceiling was the whole defence.
//
// A FIXED CORPUS IS A DENYLIST OF EXAMPLES AND ITS SIZE IS THE ATTACKER'S
// BUDGET: they need one input outside it, and here the input is just "a bit
// longer". Enlarging the list moves the ceiling; it does not remove one. So
// the corpus is SAMPLED FROM A SPACE instead — four structural shapes crossed
// with lengths from 0 bytes upward, from a SEEDED deterministic generator, so
// a failure reproduces byte-for-byte on the next run and in CI.
//
// THE LENGTH RACE IS CLOSED TWICE OVER NOW, and the two closures are
// independent. R1 refuses `(?s)[\s\S]{721}` on the pattern — it spells nothing
// — so the family never reaches this corpus at all. What follows is the older
// argument, kept because it is what makes the corpus's own ceiling honest
// rather than merely large, and because a backstop that rests on an unstated
// ceiling is a backstop nobody can check. It is closed by arithmetic rather
// than by sampling harder; sampling more lengths would still leave a longest
// sample. Two bounds remove the ceiling instead:
//
//	WHAT A PATTERN CAN DEMAND IS BOUNDED. Go's regexp caps the total
//	expansion of a repeat at 1000 — `{1001}` does not compile and neither
//	does `(X{1000}){2}`, because the PRODUCT is checked. A repeat construct
//	costs at least one byte of pattern and a pattern is bounded at
//	MaxPatternBytes, so no signature this gate can compile demands more than
//	MaxPatternBytes*1000 = 1,024,000 bytes. The corpus ceiling is larger.
//
//	WHAT A BODY CAN CARRY IS BOUNDED. Gate 14's coded floor caps a response
//	body at 1 MiB (internal/dast/authz, CodedMaxBodyBytes) and the plan
//	permits that cap to be lowered and never raised, so an Observation
//	longer than the ceiling cannot exist either.
//
// So the corpus carries ONE body at exactly that cap, and every length
// threshold that can be written down meets a generated body at least that
// long. TestTheLengthThresholdFamilyIsClosedAndNotMerelyOutrun asserts all
// three facts, and TestTheBenignCorpusIsGeneratedAndReachesTheKernelsCodedBodyCap
// asserts the ceiling against authz's own constant, so neither paragraph can
// quietly become false.
//
// THE COST, MEASURED RATHER THAN ASSERTED. Two costs exist and they are
// different things:
//
//	BUILDING IT, once, at package initialisation: 3.3 ms, allocating the
//	1 MiB ceiling body and about 200 KiB of shorter ones.
//
//	SCANNING IT, once per NewSignature call: 27 us for an ordinary oracle —
//	one that matches nothing, so it pays for the whole corpus rather than
//	stopping early. The structural control that runs before it costs 2.3 us
//	of that, so the corpus is 91% of what a signature costs to compile.
//
// THE CONTROL GOT 1.3 us MORE EXPENSIVE WHEN RULING 12 LANDED, and the number
// is moved rather than left: putting spelled runes into `consumes` means every
// OpLiteral allocates a rune-pair list and unions it, so a pattern that is
// mostly literal now pays per rune. It was 972 ns. It buys the closure of an
// evasion that a capture group and a re-spelling walked straight through, and
// 2.3 us against a 27 us compile is not a cost anyone will notice — but a
// benchmark block that still said 972 would be a measurement of a tree that no
// longer exists.
//
// MEASURED ON THIS TREE, NOT ESTIMATED, by BenchmarkBenignCorpusBuild,
// BenchmarkNewSignature and BenchmarkRefuseOverBroadPattern in
// confirm_gate_test.go — go1.26.5, AMD Ryzen 5 9600X, windows/amd64:
//
//	go test -run XXX -bench 'BenignCorpus|NewSignature|RefuseOverBroad' -benchtime 200x ./internal/dast/record/
//	BenchmarkBenignCorpusBuild-12          200    3394635 ns/op
//	BenchmarkNewSignature-12               200      26681 ns/op
//	BenchmarkRefuseOverBroadPattern-12     200       2292 ns/op
//
// THE FIGURE THAT USED TO BE HERE WAS NOT A MEASUREMENT OF THIS PACKAGE. It
// cited a cmd/anvil test run as evidence that the init cost was harmless, and
// `go list -deps ./cmd/...` contains this package NOWHERE — no shipped binary
// imports it yet, so that number described a program that does not run this
// code. It is deleted rather than qualified. The consequence is worth stating
// plainly rather than burying: the 3.3 ms is paid today by `go test` and by
// whatever wires this gate next, and the day cmd/anvil-dast imports it, the
// figure to re-measure is the one above and not a test run's total.
//
// THE PATHOLOGICAL CASE IS NO LONGER PAID FOR. The old note here claimed the
// worst pattern expressible under MaxPatternBytes — eighty-five concatenated
// `[\s\S]{1000}` — costs about fifteen seconds against this corpus. It no
// longer costs anything: `[\s\S]` is open under R2, so the control refuses it
// before the corpus is consulted. The claim is deleted rather than qualified.
//
// THE COST TO AN AUTHOR IS STATED TOO. A signature that fires on ordinary
// prose, ordinary markup or an ordinary JSON document is refused and its
// author must make it more specific. `(?s)A.*B` is the case a reader will
// remember: it used to pass, and it is now refused twice over — by R2, because
// `.` is open, and by this corpus, because generated prose capitalises
// sentence openings so a body with an 'A' before a 'B' is an ordinary body.
// TestTheBackstopRefusesWhatTheControlAccepts is where the corpus is shown
// refusing something the control passes, so "backstop" is a demonstrated word
// and not a hopeful one.

// benignCorpusSeed is the generator's seed. It is fixed and written down so
// that "a signature was refused" is a reproducible fact rather than a report
// about one run. Changing it changes which bodies exist and is a deliberate
// act, not a tuning knob.
const benignCorpusSeed uint64 = 0x416e76696c2d4432 // "Anvil-D2"

// maxBenignBodyBytes is the longest generated body, and it is not a taste
// decision: it is gate 14's coded body cap, internal/dast/authz's
// CodedMaxBodyBytes. See the section header for why the corpus needs exactly
// this number to close the length race rather than merely postpone it.
const maxBenignBodyBytes = 1 << 20

// benignRNG is splitmix64: a deterministic, seekable, dependency-free
// generator.
//
// It is written out rather than taken from math/rand/v2 because this runs in
// PRODUCTION — NewSignature calls it — and a corpus whose contents depend on a
// stdlib generator's algorithm is a corpus that can change under a toolchain
// upgrade. The refusals this decides must be reproducible across Go versions,
// not merely across runs.
type benignRNG struct{ state uint64 }

func newBenignRNG(seed uint64) *benignRNG { return &benignRNG{state: seed} }

func (r *benignRNG) next() uint64 {
	r.state += 0x9e3779b97f4a7c15
	z := r.state
	z ^= z >> 30
	z *= 0xbf58476d1ce4e5b9
	z ^= z >> 27
	z *= 0x94d049bb133111eb
	z ^= z >> 31
	return z
}

// intn returns a value in [0,n). It returns 0 for a non-positive n rather than
// panicking: this runs on every NewSignature call, and a corpus generator that
// can take the process down is worse than one that repeats a token.
func (r *benignRNG) intn(n int) int {
	if n <= 0 {
		return 0
	}
	return int(r.next() % uint64(n))
}

func (r *benignRNG) pick(xs []string) string { return xs[r.intn(len(xs))] }

// benignWords is the generator's alphabet at the word level.
//
// Every word is unremarkable catalogue and documentation vocabulary. None of
// them, in any order, spells a credential, a stack trace, a version banner, a
// SQL error or any other thing a real oracle looks for — which is what makes a
// signature that fires on this text over-broad BY CONSTRUCTION rather than by
// coincidence.
func benignWords() []string {
	return []string{
		"account", "basket", "catalogue", "dashboard", "delivery", "estimate",
		"feature", "gallery", "history", "invoice", "journal", "listing",
		"member", "notice", "option", "package", "quantity", "receipt",
		"schedule", "template", "update", "vendor", "warehouse", "yield",
		"the", "and", "for", "with", "from", "into", "over", "under", "between",
	}
}

// benignPhrase returns n words separated by single spaces, with no punctuation
// and no newlines. It is what goes inside a JSON string or an HTML attribute,
// where a newline would be a lie about the document's shape.
func benignPhrase(r *benignRNG, words int) string {
	var b strings.Builder
	for i := 0; i < words; i++ {
		if i > 0 {
			b.WriteByte(' ')
		}
		b.WriteString(r.pick(benignWords()))
	}
	return b.String()
}

// benignProse generates at least n bytes of ordinary sentences.
//
// Sentence openings are CAPITALISED on purpose. A corpus of lower-case filler
// cannot refuse a pattern anchored on a capital letter, and "an upper-case
// letter appears in a response" is not an oracle.
func benignProse(r *benignRNG, n int) string {
	// enders is a WRITTEN-DOWN VOCABULARY like every other list in these
	// generators, and it is named rather than inlined so the disclosure can
	// count it. It is six pairs, so `!` is only ever followed by a newline
	// and `?` only by a space: MEASURED, `! ` is accepted by NewSignature.
	enders := []string{". ", ".\n", "? ", "!\n", ", ", "; "}
	var b strings.Builder
	b.Grow(n + 64)
	for b.Len() < n {
		words := 3 + r.intn(12)
		for i := 0; i < words; i++ {
			w := r.pick(benignWords())
			if i == 0 {
				w = strings.ToUpper(w[:1]) + w[1:]
			}
			b.WriteString(w)
			if i < words-1 {
				b.WriteByte(' ')
			}
		}
		b.WriteString(r.pick(enders))
	}
	return b.String()
}

// benignHTML generates at least n bytes of an ordinary HTML document.
//
// It carries a doctype, a head, a stylesheet link, an ordinary script tag and
// a body of nested elements WITH class attributes. Every one of those is a
// thing a template author might anchor a signature on, and every one of them
// appears on pages with nothing wrong with them — which is exactly why the
// corpus has to contain them. `(?s)<div[\s\S]{0,500}` passed the seventeen
// hand-written probes for no better reason than that none of them contained a
// div.
func benignHTML(r *benignRNG, n int) string {
	tags := []string{"div", "section", "article", "p", "span", "li", "td",
		"h2", "h3", "aside", "nav", "header", "footer"}
	classes := []string{"row", "card", "panel", "list", "item", "grid",
		"content", "summary", "meta"}
	var b strings.Builder
	b.Grow(n + 512)
	b.WriteString("<!doctype html>\n<html lang=\"en\">\n<head>\n")
	b.WriteString("<meta charset=\"utf-8\">\n")
	b.WriteString("<title>" + benignPhrase(r, 3) + "</title>\n")
	b.WriteString("<link rel=\"stylesheet\" href=\"/static/site.css\">\n")
	b.WriteString("<script src=\"/static/app.js\"></script>\n")
	b.WriteString("</head>\n<body>\n")
	for b.Len() < n {
		t := r.pick(tags)
		b.WriteString("<" + t + " class=\"" + r.pick(classes) + "\">")
		b.WriteString(benignProse(r, 8+r.intn(120)))
		b.WriteString("</" + t + ">\n")
	}
	b.WriteString("</body>\n</html>\n")
	return b.String()
}

// benignJSON generates at least n bytes of an ordinary JSON document: nested
// objects and arrays, every scalar kind, and the empty containers a pattern
// like a bare brace class fires on.
func benignJSON(r *benignRNG, n int) string {
	keys := []string{"id", "name", "status", "count", "items", "total", "page",
		"created_at", "updated_at", "tags", "links", "meta", "next", "ok"}
	var b strings.Builder
	b.Grow(n + 64)
	b.WriteByte('{')
	for first := true; b.Len() < n; first = false {
		if !first {
			b.WriteByte(',')
		}
		b.WriteString("\"" + r.pick(keys) + "\":")
		switch r.intn(6) {
		case 0:
			b.WriteString("null")
		case 1:
			b.WriteString(r.pick([]string{"true", "false"}))
		case 2:
			b.WriteString(fmt.Sprintf("%d", r.intn(100000)))
		case 3:
			b.WriteString("\"" + benignPhrase(r, 1+r.intn(8)) + "\"")
		case 4:
			b.WriteString("[")
			for i, m := 0, r.intn(5); i < m; i++ {
				if i > 0 {
					b.WriteByte(',')
				}
				b.WriteString(fmt.Sprintf("%d", r.intn(1000)))
			}
			b.WriteString("]")
		default:
			b.WriteString("{\"" + r.pick(keys) + "\":{}}")
		}
	}
	b.WriteByte('}')
	return b.String()
}

// benignStructural generates at least n bytes of the punctuation, whitespace
// and protocol furniture that appears in every response ever served.
//
// This is the shape that catches the family whose defect is that it fires on a
// document's SKELETON — whitespace classes, brace classes, comment markers. At
// small lengths it is also where the single-character and empty-document cases
// come from: they are SAMPLED, not listed.
func benignStructural(r *benignRNG, n int) string {
	toks := []string{
		"{}", "[]", "null", "true", "false", "0", "1", "-1", "\"\"", "{ }", "[ ]",
		" ", "\n", "\t", "\r\n", "  ", "\n\n",
		"HTTP/1.1 200 OK\r\n", "Content-Type: application/json\r\n",
		"Content-Length: 0\r\n", "Cache-Control: no-store\r\n",
		"---", "===", "...", "<!-- -->", "/* */", "//", "#", "|", "::", ";", ",",
		"<>", "()", "$", "%", "&", "*", "+", "@", "^", "~", "`", "'", "\\",
	}
	var b strings.Builder
	b.Grow(n + 32)
	for b.Len() < n {
		b.WriteString(r.pick(toks))
	}
	return b.String()
}

// benignBodyLengths is the length axis the shapes are crossed with.
//
// It is dense at the bottom — 0, 1, 2, 3 bytes are where the empty body and
// the single-character cases live — and then spreads, straddling MaxSpanBytes
// (511/512/513) and THE OLD CORPUS'S TOTAL SIZE (719/720/721), which is the
// exact ceiling `(?s)[\s\S]{721}` was measured stepping over. The top of the
// axis is not here: see maxBenignBodyBytes.
func benignBodyLengths() []int {
	return []int{
		0, 1, 2, 3, 5, 8, 13, 21, 34, 55, 89, 144, 233, 377,
		511, 512, 513, 719, 720, 721, 1024, 1536, 2047, 4096, 8192, 12289, 16384,
	}
}

// benignCorpus is built once, at package initialisation, from the seed.
//
// It is a package-level value rather than a function call because NewSignature
// consults it on every call and regenerating a megabyte per signature would
// make the check something a caller works around. It is unexported and never
// handed out, so there is nothing to copy defensively.
var benignCorpus = buildBenignCorpus()

// buildBenignCorpus crosses every shape with every length, then appends the
// one body at the kernel's cap.
//
// THE ORDER IS SHORTEST FIRST, and that is not cosmetic: NewSignature stops at
// the first match, so a pattern that fires on everything dies against the
// zero-byte body and never touches the megabyte. Only a signature that is
// genuinely specific pays the full scan.
func buildBenignCorpus() []string {
	r := newBenignRNG(benignCorpusSeed)
	shapes := []func(*benignRNG, int) string{
		benignStructural, benignJSON, benignHTML, benignProse,
	}
	out := make([]string, 0, len(benignBodyLengths())*len(shapes)+1)
	for _, n := range benignBodyLengths() {
		for _, shape := range shapes {
			body := shape(r, n)
			if len(body) > n {
				body = body[:n]
			}
			out = append(out, body)
		}
	}

	// The ceiling body. It is a MIXTURE of all four shapes rather than a
	// megabyte of one of them: a length-threshold pattern is caught by any
	// filler, but a pattern that needs markup, or braces at some depth, is
	// only caught if the long body actually contains them.
	var b strings.Builder
	b.Grow(maxBenignBodyBytes + 8192)
	for i := 0; b.Len() < maxBenignBodyBytes; i++ {
		b.WriteString(shapes[i%len(shapes)](r, 4096))
	}
	out = append(out, b.String()[:maxBenignBodyBytes])
	return out
}

// NewSignature compiles pattern.
//
// It refuses five things, each because the alternative is an oracle that
// lies:
//
//	an empty pattern          nothing to match, nothing to extract
//	an over-long pattern      MaxPatternBytes; the source is quotable
//	a pattern that does not   it cannot be analysed and cannot be run
//	  compile
//	an OVER-BROAD PATTERN     decided on the pattern's own structure by
//	                          refuseOverBroadPattern: R1 footing, R2 open
//	                          positions, R3 quotation. THIS IS THE CONTROL
//	a pattern matching a      it reproduces against a body with nothing
//	  benign body             wrong with it. THIS IS THE BACKSTOP
//
// THE ORDER IS THE ARGUMENT. The structural check decides first, because it
// decides on the pattern and therefore samples nothing; the corpus runs after
// it, catches the one family structure cannot see (a literal that is ordinary
// document furniture), and is described as a backstop everywhere it is
// mentioned. Three rounds of this file described the corpus as the control and
// three attackers stepped outside it.
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
		return Signature{}, fmt.Errorf("%w: compiling the signature pattern: %s",
			ErrRefused, printable(err.Error(), MaxFieldBytes))
	}
	// THE CONTROL. It decides on the pattern; nothing is sampled. Its
	// minLiteral becomes the Signature's span budget: see Signature.spelled
	// and extractSpan's composition rule.
	spelled, err := refuseOverBroadPattern(pattern)
	if err != nil {
		return Signature{}, err
	}
	// THE BACKSTOP.
	for i, body := range benignCorpus {
		if !re.MatchString(body) {
			continue
		}
		return Signature{}, fmt.Errorf("%w: %q fires against generated benign body %d of %d "+
			"(%d bytes, %q...). An oracle that cannot tell a vulnerable response from an "+
			"ordinary one confirms ordinary ones. The corpus is generated from seed "+
			"%#x, so this is reproducible",
			ErrSignatureMatchesEverything, printable(pattern, MaxFieldBytes), i,
			len(benignCorpus), len(body), printable(body, 32), benignCorpusSeed)
	}
	return Signature{re: re, src: pattern, spelled: spelled, sealed: true}, nil
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
	// spanOverBroadBytes is the byte length of the regex match when the
	// match could not be inlined AT ALL, 0 otherwise. Non-zero means
	// THERE IS NO SPAN even though the signature matched.
	//
	// TWO RULES SET IT, and extractSpan documents both: the match was
	// longer than MaxSpanBytes, or it carried more bytes the pattern did
	// not spell than bytes it did. They are recorded the same way on
	// purpose — the fact a reader needs is "the oracle fired and its match
	// is not shown, and it was this long", and which bound withheld it is
	// a property of the signature rather than of the finding.
	//
	// This field replaced one called spanTruncatedFrom, and the rename is
	// the fix rather than a tidy-up. Truncating an over-broad match to
	// MaxSpanBytes still inlines a raw body prefix — 512 verbatim bytes of
	// whatever the target sent, through the one channel spine S7 sanctions.
	// A signature whose match runs past the span budget is not extracting
	// evidence, it is quoting the response, so the answer is to produce no
	// span at all and record how long the match was. The match still
	// counts: the ORACLE fired, and that is a separate fact from whether
	// its match is safe to show.
	spanOverBroadBytes int

	sealed bool
}

// BodyHash returns the hex SHA-256 of the response body the span came from.
// This is the "hash-and-reference by default" half of spine S7.
func (e EvidenceRef) BodyHash() string { return e.bodyHash }

// ExtractedSpan returns the bounded, printable-ASCII regex match.
//
// It is empty in TWO different situations and SpanOverBroadBytes is what
// tells them apart: the signature matched nothing (0), or the signature
// matched something extraction would not inline (non-zero) — because the
// match was over MaxSpanBytes, or because more of it was body than the
// pattern spelled.
func (e EvidenceRef) ExtractedSpan() string { return e.span }

// SpanDroppedBytes returns how many bytes extraction removed as
// non-printable.
func (e EvidenceRef) SpanDroppedBytes() int { return e.spanDroppedBytes }

// SpanOverBroadBytes returns the match length when the match could not be
// inlined at all, 0 otherwise. Non-zero always accompanies an empty span.
func (e EvidenceRef) SpanOverBroadBytes() int { return e.spanOverBroadBytes }

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
	//
	// IT IS READ, AND IT IS READ AGAINST AN ALLOWLIST. It used to be
	// captured, stamped onto the Finding and consulted by nothing, which is
	// how a 429 on every attempt became "did_not_reproduce_on_any_attempt".
	// It was then read against a list of four statuses that meant "defence",
	// which is how a 403 did the same thing. See
	// applicationResponseStatuses and ReasonReprobeIndecisive.
	Status int
	// Body is the response body, already bounded by the kernel's gate-14
	// cap on the far side of the Reprober interface.
	Body []byte
}

// applicationResponseStatuses is the ALLOWLIST of HTTP statuses that
// establish the target answered the confirmation pass AS THE APPLICATION.
//
// ===========================================================================
// THIS IS AN INVERSION, AND THE INVERSION IS THE CONTROL
// ===========================================================================
//
// It used to be defensiveStatuses: {429, 502, 503, 504}, four ways a target
// can defend itself, with EVERYTHING ELSE falling through to "the application
// answered, so the oracle's silence disproves the candidate". MEASURED: a
// Reprober answering 403 with a WAF page on all three attempts reproduced the
// original defect exactly — 12 vulnerable candidates, outcome=rejected,
// reason=did_not_reproduce_on_any_attempt, and the ledger reads
// completed_clean over live findings.
//
// The set of ways a target can decline to run the application is UNBOUNDED
// and vendor-specific: 403, 401, 407, 451, 418, a captive portal's 302, a
// connection reset, a TLS alert, and a status nobody has shipped yet.
// Enumerating that set is a denylist, and a denylist's SIZE IS THE ATTACKER'S
// BUDGET — one input outside it wins, and here "the attacker" is any appliance
// vendor who picked a different number.
//
// So the question is asked the other way round. A re-probe is evidence of
// ABSENCE only when the response is an ORDINARY APPLICATION RESPONSE: one the
// target produced by dispatching the request to its own handling and returning
// that handling's outcome. Anything else — any status not named below, any
// body the caller's defence signature recognises, any observation that cannot
// say what it saw — is INDECISIVE. Not disproved. Indecisive.
//
// THE MEMBERSHIP TEST, STATED BEFORE THE LIST, so the list can be checked
// against it rather than read as a set of independent opinions:
//
//	A STATUS IS ON THIS ALLOWLIST WHEN THE STATUS ITSELF ESTABLISHES THAT
//	THE BODY IS A REPRESENTATION THE ORIGIN APPLICATION PRODUCED.
//
// Not "the application probably answered". Not "an intermediary rarely emits
// this". The question is whether the NUMBER settles it, because the number is
// all this function has.
//
// THE RULE HAS THREE CONJUNCTS, and they are written out because the last
// round's list satisfied only the first and nobody noticed. "The body is a
// representation the origin application produced" requires ALL of:
//
//	(a) THERE IS A BODY. A status that forbids one cannot establish anything
//	    about one. RFC 9110 §6.4.1 and §15.3.5: a 1xx, a 204 and a 304 are
//	    terminated by the first empty line after the header fields and
//	    CANNOT contain a message body at all; a 205 must have a zero-length
//	    one.
//	(b) THE BODY IS THE WHOLE REPRESENTATION. A 206 body is a byte range
//	    SOMEONE ELSE CHOSE. A signature that failed to match a fragment has
//	    not shown the marker is absent from the representation, only from
//	    the part that came back.
//	(c) ONLY THE ORIGIN CAN HAVE PRODUCED IT. A success status reports that
//	    the request was carried out, and carrying it out is the
//	    application's own act. A CDN serving a cached 200 is serving a COPY
//	    of the application's own bytes, which is still the application's
//	    output. Every error status, by contrast, is something a CDN, a
//	    proxy, a gateway or a WAF manufactures without reaching the origin.
//
// EACH MEMBER, DERIVED FROM THE RULE RATHER THAN ASSERTED:
//
//	200 ok          (a) a 200 carries the representation of the target
//	                resource. (b) it is the whole of it. (c) only the origin
//	                can report that a request was carried out. ON.
//	201 created     (a) RFC 9110 §15.3.2: the response contains a
//	                representation describing the request's status and the
//	                new resource. (b) whole. (c) creating the resource is
//	                the origin's act. ON.
//
// WHAT THE RULE THREW OFF THIS ROUND, and this is the entry a reader should
// check hardest, because it was on the list under the rule above and DID NOT
// SATISFY IT:
//
//	202 accepted    FAILS (c), and it failed it while carrying a derivation
//	                that read as if it passed. The old entry said "accepting
//	                the request into processing is the origin's act" — which
//	                is true, and is not conjunct (c). CONJUNCT (c) IS THAT
//	                THE REQUEST WAS CARRIED OUT, and RFC 9110 §15.3.3 says
//	                the opposite of a 202 in its own words: "the request has
//	                been accepted for processing, but the processing has not
//	                been completed", and the response is "intentionally
//	                noncommittal". Its body describes a STATUS MONITOR, not
//	                the outcome. A signature's silence over a queue receipt
//	                is silence about work that has not happened yet, so a
//	                rejection built on it disproves nothing. It survived a
//	                round because the test's conjunct (c) was still
//	                literally `2xx`, which admits every success status and
//	                distinguishes none of them.
//
// WHAT THE RULE THREW OFF THE ROUND BEFORE, kept because re-adding either is
// still a deliberate act against a written argument:
//
//	204 no content  FAILS (a). §15.3.5: a 204 cannot contain a message body.
//	                MEASURED, and the measurement is the argument: a 204
//	                re-probe over a vulnerable candidate yielded
//	                outcome=rejected at confidence 0.000 MARKED KNOWN — a
//	                finding disproven by bytes that could not have existed.
//	                The list also disagreed with itself: 205, the other
//	                mandated-empty status, was never a member, so two
//	                statuses with the same body semantics were decided two
//	                different ways. A signature's silence over a body the
//	                protocol forbids is not the application declining to
//	                emit a marker; it is nothing at all.
//	206 partial     FAILS (b). The body is a range, and the range boundaries
//	    content     were chosen by whoever answered — which need not be the
//	                origin: a range-capable cache assembles a 206 from what
//	                it already holds. A marker two bytes past the end of the
//	                returned range is a marker the signature cannot see, so
//	                a non-match disproves nothing. This gate never sends a
//	                Range header, so a 206 to its re-probe is additionally a
//	                report about a request it did not make.
//
// THE COST OF THOSE TWO IS SMALLER THAN THE OTHER REMOVALS AND IS STILL
// STATED: an endpoint that answers 204 or 206 on every attempt is now
// UNCONFIRMED rather than REJECTED. For 204 that costs nothing real — there
// were never any bytes to run the oracle over — and for 206 it costs the case
// where a marker happens to fall inside the returned range. Both land in front
// of a human with the body hash, which is where an undecided thing belongs.
//
// WHAT IS DELIBERATELY ABSENT. Nothing below is "denied" — the allowlist still
// has no deny side, and a status not named simply falls to indecisive by
// control flow. These are listed because a reader will ask, and the first
// three are listed because they USED TO BE ON THE LIST and a round of review
// asked for each to be decided explicitly:
//
//	404              REMOVED. The old entry said "the application DISPATCHED
//	                 the request and its own routing answered". That is one
//	                 of the things a 404 can mean. It is also what a CDN
//	                 edge node answers for a path not in its origin rules,
//	                 what nginx `try_files` answers without ever proxying,
//	                 and what an object store answers for a missing key —
//	                 none of which consulted the application at all.
//	                 MEASURED: a CDN answering 404 on all three attempts
//	                 yields outcome=rejected, which is a finding disproven
//	                 by an edge node. The number cannot tell the two apart,
//	                 so the honest answer is indecisive.
//	405 410          REMOVED, for the same reason and by the same test.
//	                 nginx answers 405 from `limit_except` and a CDN answers
//	                 410 from a purge rule; both are the intermediary's own
//	                 output. They are removed rather than left because a
//	                 membership rule that does not cover its own list is the
//	                 defect this file has now watched four times.
//	422              REMOVED. "The application parsed the request" is the
//	                 strongest case of the three, and it is still not
//	                 settled by the number: an API gateway with request
//	                 validation, and any WAF whose block status is
//	                 configurable — which is all of them — can emit 422
//	                 without an origin round trip.
//	500              REMOVED, and this is the entry that costs something.
//	                 The old text argued a 500 "is frequently what an
//	                 injection probe is TRYING to cause, and treating it as
//	                 indecisive would make that class's own success
//	                 condition undecidable". THAT IS AN ARGUMENT FROM
//	                 CONSEQUENCE, NOT FROM EVIDENCE, and it is the same
//	                 shape of argument that kept 403 on the list for a
//	                 round. A reverse proxy emits 500 for its own internal
//	                 failures, and a WAF can be configured to. The number
//	                 does not establish an origin answered.
//	401 403 407 451  authentication, authorization, proxy-auth and legal
//	                 blocks. Each is the exact shape a WAF, an API gateway
//	                 and an identity proxy all emit. 403 is the measured
//	                 case from the previous round.
//	400              a reverse proxy or WAF answers 400 for anything it
//	                 dislikes about the request line or headers, before the
//	                 application is consulted at all.
//	3xx              a redirect to a login page or an interstitial is the
//	                 standard "you may not have this" shape. A redirect body
//	                 is also usually empty, and a signature that failed to
//	                 match an empty body has disproved nothing whatever
//	                 produced it.
//	406 415          configurable WAF block statuses (ModSecurity ships
//	                 both), indistinguishable from content negotiation.
//	429 502 503 504  the original four. They are not special any more. They
//	                 are simply not on the allowlist, together with every
//	                 status nobody thought of.
//
// THE COST, STATED RATHER THAN HIDDEN, AND IT IS BIGGER THIS ROUND. Two
// separate prices:
//
//	A candidate whose target answers 403 — or now 404 — on every attempt is
//	UNCONFIRMED where it used to be REJECTED, and an operator sees one more
//	undecided row. That is the correct direction to fail: Anvil did not
//	observe the application, so Anvil did not disprove anything.
//
//	AN ERROR-BASED INJECTION WHOSE ONLY REPRODUCTION IS A 500 CAN NO LONGER
//	BE CONFIRMED BY THIS GATE. The re-probe is counted indecisive before the
//	signature is run, so a stack trace in a 500 body is not read. That is a
//	loss of true positives and it is not a small one. It is accepted because
//	the alternative is a WAF's or a proxy's 500 counting as the application,
//	and because the finding is not dropped — it lands unconfirmed, with the
//	body hash, in front of a human. The route back is not re-adding the
//	number: it is GateConfig.DefenceSignature's mirror image, a
//	caller-supplied pattern that recognises the caller's OWN application
//	error page. That does not exist yet and is not invented here.
//
// The comment this replaced claimed the opposite cost — that calling 403 a
// non-answer "would make the oracle-less classes undecidable for a second,
// wrong reason". THAT CLAIM WAS FALSE and is deleted rather than qualified:
// decide()'s rule 1 routes an oracle-less class to ReasonNoOracleForClass
// before indecisiveness is ever consulted, so an authorization candidate's 403
// reaches exactly the outcome and reason it always did.
// TestAnOracleLessClassIsUnaffectedByTheInversion drives that.
//
// THE RESIDUAL CASE NO STATUS CHECK CAN SETTLE is a WAF serving its block page
// with 200. That response IS on this allowlist and no number distinguishes it
// from the application's own 200. GateConfig.DefenceSignature is the only
// thing that can, it is caller-supplied because nothing in this package can
// recognise an arbitrary vendor's block page, and WITH NO DefenceSignature
// WIRED A 200 BLOCK PAGE IS INDISTINGUISHABLE FROM AN APPLICATION RESPONSE.
//
// It is a map keyed by the status itself, for the reason classOracles is: a
// positional list silently changes meaning when someone inserts a value.
//
// TestTheApplicationAllowlistMatchesTheRuleItsCommentStates runs the three
// conjuncts above over every member and over the whole status space. It used
// to encode "2xx", which is conjunct (c) alone — and (c) alone is what let 204
// and 206 sit here under a comment that did not cover either.
func applicationResponseStatuses() map[int]string {
	return map[int]string{
		200: "ok",
		201: "created",
	}
}

// IsApplicationResponseStatus reports whether status is one this gate accepts
// as the target answering as the application.
//
// FALSE IS THE ANSWER FOR EVERY STATUS NOT NAMED, 0 included, and that is the
// fail-closed direction: a status this gate does not recognise has not
// established that the oracle ran.
func IsApplicationResponseStatus(status int) bool {
	_, ok := applicationResponseStatuses()[status]
	return ok
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
	// indecisive is how many of those attempts failed to establish that the
	// target answered as the application. Non-zero means the oracle did not
	// get to run that many times, which is a different fact from the oracle
	// running and not firing.
	indecisive int

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

// IndecisiveAttempts returns how many re-probes failed to establish that the
// target answered as the application — a status outside
// applicationResponseStatuses, a body the configured DefenceSignature
// matched, or an observation that could not say what it saw.
//
// It is reported separately from SignatureMatches because the two are
// different facts. matches=0, indecisive=0 is an oracle that ran and did not
// fire. matches=0, indecisive=3 is an oracle that never ran. The first is a
// phantom; the second could be anything, including a real vulnerability the
// target's rate limiter, WAF or identity proxy hid.
func (f Finding) IndecisiveAttempts() int { return f.indecisive }

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
		"matches=%d/%d indecisive=%d status=%d confidence=%s body_hash=%s span_bytes=%d "+
		"span_over_broad_bytes=%d",
		f.engine, f.method, f.path, f.class, f.detection, f.outcome, f.reason,
		f.matches, f.attempts, f.indecisive, f.status, conf, f.evidence.bodyHash,
		len(f.evidence.span), f.evidence.spanOverBroadBytes)
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
	// Err is why. It is a RefusalError VALUE and not an `error` interface;
	// see RefusalError for what that closes.
	Err RefusalError
}

// ---------------------------------------------------------------------------
// RefusalError — the error channel, closed the same way Finding is
// ---------------------------------------------------------------------------

// refusalSentinel names which package sentinel a RefusalError stands for. It
// is a named string so that RefusalError's field-type closure stays free of
// pointers and interfaces; see RefusalError.
type refusalSentinel string

const (
	sentinelNone          refusalSentinel = ""
	sentinelRefused       refusalSentinel = "refused"
	sentinelNotReprobed   refusalSentinel = "not_reprobed"
	sentinelUnconstructed refusalSentinel = "unconstructed"
)

// RefusalError is the error a Refusal carries.
//
// ===========================================================================
// WHY THIS TYPE EXISTS AT ALL: THE RAW BODY ESCAPED THROUGH THE ERROR RETURN
// ===========================================================================
//
// Finding's type-closure guarantee is real and TestFindingTypeClosureHasNoRawBodyPath
// proves it against a violating fixture. It was also pointed at the wrong set
// of types. Refusal.Err used to be a bare `error`, and ConfirmFinding wrapped
// the Reprober's error into it with %w, UNBOUNDED.
//
// The Reprober is implemented on the FAR SIDE of the gate-3 boundary — it has
// to be, because this package may not construct a socket — so its error text
// is written by code this packet does not own and cannot review. The ordinary
// thing for an implementation to do with an unparseable response is to quote
// it. Measured: that put 4301 verbatim body bytes, non-printable ASCII
// included, onto Ledger.Refusals()[0].Err, straight past a type whose entire
// design is "there is nowhere to put a body". A structural guarantee with an
// interface-shaped hole beside it is a guarantee about one field.
//
// So this type is closed the way Finding is closed:
//
//   - every field is unexported and every field is a VALUE — a named string,
//     a string, an int, a bool. No pointer, no slice, no map, no interface.
//     closureViolations(RefusalError{}) is clean, and a Refusal is therefore
//     a complete copy exactly as a Finding is.
//   - THERE IS NO Unwrap. A wrapped foreign error would be reachable through
//     errors.Unwrap and its Error() would print the body again, so the chain
//     stops here on purpose. Identity with this package's sentinels is
//     preserved by the Is method instead, which compares a named string —
//     so errors.Is(refusal.Err, ErrRefused) keeps working and errors.Unwrap
//     hands back nothing to print.
//   - the message is Anvil-authored. Foreign text reaches it only through
//     quarantine, which hashes rather than quotes.
type RefusalError struct {
	sentinel refusalSentinel
	msg      string
	sealed   bool
}

// newRefusalError renders err into a closed value.
//
// The sentinel is recovered by identity BEFORE the message is taken, so the
// classification never depends on the text. The text is then bounded and
// charset-filtered — belt and braces over quarantine, because this is the
// last point at which anything can be done about a message that grew a body
// somewhere upstream.
func newRefusalError(err error) RefusalError {
	if err == nil {
		return RefusalError{}
	}
	s := sentinelNone
	switch {
	case errors.Is(err, ErrNotReprobed):
		s = sentinelNotReprobed
	case errors.Is(err, ErrUnconstructed):
		s = sentinelUnconstructed
	case errors.Is(err, ErrRefused):
		s = sentinelRefused
	}
	return RefusalError{sentinel: s, msg: printable(err.Error(), MaxRefusalMessageBytes), sealed: true}
}

// Error implements error.
func (e RefusalError) Error() string {
	if !e.sealed {
		return "dastrecord: no refusal"
	}
	return e.msg
}

// Is preserves identity with this package's sentinels without an Unwrap
// chain a caller could print. errors.Is(refusal.Err, ErrRefused) works;
// errors.Unwrap(refusal.Err) returns nil.
func (e RefusalError) Is(target error) bool {
	switch e.sentinel {
	case sentinelRefused:
		return target == ErrRefused
	case sentinelNotReprobed:
		return target == ErrNotReprobed
	case sentinelUnconstructed:
		return target == ErrUnconstructed
	}
	return false
}

// Constructed reports whether e describes an actual refusal. The zero value
// does not.
func (e RefusalError) Constructed() bool { return e.sealed }

// MaxRefusalMessageBytes bounds a RefusalError's rendered message.
//
// It is larger than MaxFieldBytes because a refusal message is Anvil-authored
// prose that names the bound it is explaining, and squeezing it to 512 would
// truncate the explanation rather than any untrusted part of it. It is
// bounded at all because "the message is ours" is a claim about today's code
// and the bound is what makes it a claim about tomorrow's.
const MaxRefusalMessageBytes = 2048

// quarantine renders a foreign error WITHOUT QUOTING IT.
//
// This is spine S7's "hash-and-reference by default" applied to the error
// channel, and for the identical reason: the Reprober's error text is written
// on the far side of gate 3, an unparseable-response error routinely contains
// the response, and a refusal message is read by a human and increasingly by
// an agent.
//
// What survives is the Go type name (declared in the implementer's source,
// not in the response), the length, and the SHA-256 — which is enough to
// correlate two refusals as the same failure, to look the text up in the
// implementation's own logs, and to tell a hash apart from a message. What
// does not survive is one byte of the text.
//
// Cancellation and deadline are named explicitly because they are stdlib
// values with fixed text, they are the two causes an operator most needs to
// see by name, and neither can carry a payload.
func quarantine(err error) string {
	if err == nil {
		return "no error"
	}
	switch {
	case errors.Is(err, context.Canceled):
		return "the context was cancelled"
	case errors.Is(err, context.DeadlineExceeded):
		return "the context deadline was exceeded"
	}
	msg := err.Error()
	sum := sha256.Sum256([]byte(msg))
	return fmt.Sprintf("the Reprober returned an error of Go type %s, whose %d-byte text is "+
		"NOT quoted here (sha256:%s). It is written on the far side of the gate-3 "+
		"boundary and an unparseable-response error routinely quotes the response body",
		printable(fmt.Sprintf("%T", err), 64), len(msg), hex.EncodeToString(sum[:]))
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
	// DefaultAttempts. Anything outside [MinAttempts, MaxAttempts] is
	// refused; see MinAttempts for why there is a floor.
	Attempts int

	// DefenceSignature is an OPTIONAL pattern that identifies the target's
	// block page. When it matches a re-probe body, that attempt counts as
	// indecisive whatever its status was.
	//
	// It exists because the status code is not the whole story. A WAF that
	// returns its block page with 200 is the RESIDUAL CASE no status check
	// can settle: 200 is on applicationResponseStatuses and must be, the
	// signature did not match because the application never ran, and the
	// candidate would come out REJECTED — the same silent false negative as
	// the 429, wearing a number that is genuinely indistinguishable.
	//
	// It is caller-supplied because nothing in this package can recognise
	// an arbitrary vendor's block page, and a built-in guess would be a
	// denylist of block-page markers, which is the shape this house has
	// already watched lose. WITH NO DefenceSignature WIRED, A 200 BLOCK PAGE
	// IS INDISTINGUISHABLE FROM AN APPLICATION RESPONSE — stated here rather
	// than left for a reader to discover.
	//
	// The zero Signature means "no defence page is recognised" and is legal.
	DefenceSignature Signature
}

// Gate is D.27: the finding confirmation gate.
type Gate struct {
	reprober Reprober
	attempts int
	defence  Signature
	sealed   bool
}

// NewGate assembles the gate.
func NewGate(cfg GateConfig) (*Gate, error) {
	attempts := cfg.Attempts
	if attempts == 0 {
		attempts = DefaultAttempts
	}
	if attempts < MinAttempts || attempts > MaxAttempts {
		return nil, fmt.Errorf("%w: %d re-probe attempts is outside [%d,%d]. A single "+
			"attempt is not a cheaper confirmation, it is the flake detection removed "+
			"while the finding goes on saying %q",
			ErrRefused, cfg.Attempts, MinAttempts, MaxAttempts, string(ReasonReproduced))
	}
	return &Gate{
		reprober: cfg.Reprober,
		attempts: attempts,
		defence:  cfg.DefenceSignature,
		sealed:   true,
	}, nil
}

// attemptAnsweredAsApplication reports whether one observation establishes
// that the target answered as the application, and names why not when it does
// not.
//
// EVERY RETURN PATH BUT ONE IS false. That is the shape the inversion buys:
// the function has to find positive evidence, and the absence of evidence is
// never mistaken for evidence of absence. A status nobody enumerated, a
// transport that returned nothing legible, a Go zero value — all of them exit
// here as "no", which is why FAIL CLOSED is a property of the control flow and
// not of a list somebody has to keep current.
//
// See applicationResponseStatuses for what the one true path requires.
func (g *Gate) attemptAnsweredAsApplication(obs Observation) (bool, string) {
	if !obs.Issued {
		return false, "the re-probe did not leave the process"
	}
	what, ok := applicationResponseStatuses()[obs.Status]
	if !ok {
		if obs.Status == 0 {
			return false, "the re-probe reported no HTTP status, so it cannot say what it saw"
		}
		return false, fmt.Sprintf("status %d is not one this gate accepts as the "+
			"application answering", obs.Status)
	}
	// The defence signature runs LAST and can only take an answer away. It is
	// the residual case: a 200 that is a block page is on the allowlist by
	// status and only the caller's own pattern can see it.
	if g.defence.Constructed() && g.defence.re.Match(obs.Body) {
		return false, "the configured defence signature matched the body"
	}
	return true, what
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
		indecisive   int
		evidenceSeen bool // evidence came from an attempt the signature matched
		evAnySeen    bool // evidence came from anything at all
		evCleanSeen  bool // evidence came from an attempt that WAS the application
		ev           EvidenceRef
		evStatus     int
	)
	for attempt := 1; attempt <= g.attempts; attempt++ {
		obs, err := g.reprober.Reprobe(ctx, candidate, attempt)
		if err != nil {
			// The foreign error's TEXT IS NOT WRAPPED. See quarantine.
			return nil, fmt.Errorf("%w: re-probe attempt %d of %d for %s %s failed: %s",
				ErrNotReprobed, attempt, g.attempts, candidate.Method, candidate.Path,
				quarantine(err))
		}
		if !obs.Issued {
			return nil, fmt.Errorf("%w: re-probe attempt %d of %d for %s %s reported that "+
				"nothing was issued. A probe that did not leave the process observed "+
				"nothing, and observing nothing is not observing an absence",
				ErrNotReprobed, attempt, g.attempts, candidate.Method, candidate.Path)
		}

		// The application-answered test runs BEFORE the oracle. A body the
		// target sent instead of running the application must not be handed
		// to the signature at all: a block page that happens to contain the
		// marker string would otherwise count as a reproduction, and a
		// block page that does not would count as a disproof. Neither is
		// an observation of the application.
		if answered, _ := g.attemptAnsweredAsApplication(obs); !answered {
			indecisive++
			// An indecisive attempt supplies the body hash only if nothing
			// better has been seen yet, and it carries NO SPAN: the
			// signature was never run against this body, so there is no
			// match to extract and inventing one would attribute a block
			// page to the application.
			if !evAnySeen {
				ev = EvidenceRef{bodyHash: hashBody(obs.Body), sealed: true}
				evStatus = obs.Status
				evAnySeen = true
			}
			continue
		}

		span, dropped, overBroad, matched := extractSpan(obs.Body, candidate.Signature)
		if matched {
			matches++
		}
		// Evidence comes from the FIRST attempt whose signature matched;
		// failing that, from the first attempt the application answered.
		// Deterministic, and it means a confirmed finding's span is always
		// a span that reproduced — never the empty span of some later
		// attempt that happened to miss, and never a defence page.
		if !evCleanSeen || (matched && !evidenceSeen) {
			ev = EvidenceRef{
				bodyHash:           hashBody(obs.Body),
				span:               span,
				spanDroppedBytes:   dropped,
				spanOverBroadBytes: overBroad,
				sealed:             true,
			}
			evStatus = obs.Status
			evAnySeen = true
			evCleanSeen = true
		}
		if matched {
			evidenceSeen = true
		}
	}

	reason := decide(candidate, matches, indecisive, g.attempts)
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
		indecisive:     indecisive,
		sealed:         true,
	}
	// WHETHER THERE IS A CONFIDENCE AT ALL is three questions, not one, and
	// keying on the class alone was a measured defect.
	//
	//  1. the class must have an oracle — confidence here is DEFINED as the
	//     oracle's reproduction ratio, and a class with no oracle has no
	//     ratio;
	//  2. the detection method must be one that can confirm. A
	//     model_inference candidate matching 3/3 used to land unconfirmed
	//     with reason "model_inference_is_not_an_observation" AND
	//     confidence 1.000 — two statements contradicting each other inside
	//     one record. The 3/3 is not lost: SignatureMatches() and
	//     Attempts() still report it. What is withheld is the CLAIM, and
	//     the claim is exactly what a reproduced signature does not license
	//     for an inference;
	//  3. every attempt must have been answered by the application.
	//     matches/attempts over a run the target did not answer is a ratio
	//     whose denominator counts questions that were never asked, and
	//     0.000 reads as "certainly not a vulnerability", which is the
	//     opposite of what ReasonReprobeIndecisive means.
	if !candidate.Class.OracleLess() && candidate.DetectionMethod.CanConfirm() && indecisive == 0 {
		f.confidence = float64(matches) / float64(g.attempts)
		f.confidenceKnown = true
	}

	// The bound is asserted on the assembled value rather than trusted from
	// Validate. Validate ran against the candidate; this runs against the
	// thing a consumer will hold, which is the object the claim is about.
	if err := assertFindingStringsBounded(f); err != nil {
		return nil, err
	}
	if err := assertRejectionIsDecisive(f); err != nil {
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
//  2. INDECISIVE WITH NOTHING TO SHOW FOR IT. At least one attempt failed
//     to establish that the target answered as the application, and the
//     oracle fired on none of the rest.
//     THIS RULE OUTRANKS "MATCHED NOTHING" AND THAT ORDERING IS THE WHOLE
//     FIX. Without it, a vulnerable target whose rate limiter trips returns
//     429 three times, matches zero, and comes out `rejected` —
//     indistinguishable from a phantom, and Ledger.FindingCountForStatus()
//     then derives completed_clean over a live vulnerability. Nothing was
//     disproved here because nothing was asked, so it is unconfirmed. Which
//     inputs reach this rule is decided by an ALLOWLIST of application
//     responses and not by a list of defences; see
//     applicationResponseStatuses for why that difference is the fix and not
//     a spelling.
//  3. MATCHED NOTHING. The oracle exists, it RAN, and it never fired. This
//     is the 88 phantom findings, and after rule 2 it is only ever reached
//     by a run in which EVERY attempt was an ordinary application response.
//     assertRejectionIsDecisive re-states that as a refusal on the assembled
//     value, because this ordering is the only thing holding it up.
//  4. MODEL INFERENCE. The signature reproduced but the candidate came from a
//     model. Outranks the confirmed rule, so no model-detected candidate can
//     be confirmed here regardless of how clean the reproduction was.
//  5. INTERMITTENT. Matched sometimes. Not confirmed, not disproved. A run
//     with any indecisive attempt and at least one match lands here by
//     arithmetic — matches can be at most attempts-indecisive, which is
//     strictly less than attempts — and that is the right answer: a mixed
//     run is exactly "sometimes".
//  6. REPRODUCED EVERY TIME, with an oracle, a mechanical detection method,
//     and the application answering on every single attempt. The only route
//     to OutcomeConfirmed.
func decide(c RawFinding, matches, indecisive, attempts int) Reason {
	switch {
	case c.Class.OracleLess():
		return ReasonNoOracleForClass
	case indecisive > 0 && matches == 0:
		return ReasonReprobeIndecisive
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
				Err:    newRefusalError(err),
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
//
// REJECTIONS ARE NOT COUNTED HERE, and that is the whole point of the gate: a
// ledger of nothing but rejections IS an earned clean, which is what
// TestEightyEightPhantomsAloneProduceCompletedCleanAndThatIsHonest asserts. What makes that safe is
// not a second count of "rejections that were not decisive" — that count
// existed, could not fire from any production path, and has been deleted along
// with the claim that it was a second line of defence. What makes it safe is
// that a rejection cannot be ASSEMBLED unless every attempt was an ordinary
// application response; see assertRejectionIsDecisive, which turns a violation
// into a refusal, and a refusal IS counted here.
func (l Ledger) AssertNotSilentlyClean() error {
	if !l.sealed {
		return fmt.Errorf("%w: AssertNotSilentlyClean was called on a Ledger ConfirmAll never "+
			"built", ErrUnconstructed)
	}
	if l.ConfirmedCount() > 0 {
		return nil
	}
	unconfirmed, refused, rejected := l.UnconfirmedCount(), l.RefusedCount(), l.RejectedCount()
	if unconfirmed == 0 && refused == 0 {
		return nil
	}
	return fmt.Errorf("%w: 0 confirmed, %d unconfirmed, %d rejected, %d refused. Reporting "+
		"dast_status completed_clean from this ledger would tell a coding agent that Anvil "+
		"looked and found nothing, which is not what happened",
		ErrSilentlyClean, unconfirmed, rejected, refused)
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
// It returns the printable-ASCII rendering of re's first match against body,
// how many bytes it dropped as non-printable, the match length if the match
// was too long to inline at all, and whether there was a match.
//
// THREE PROPERTIES, each of which a test breaks and restores:
//
//  1. A MATCH LONGER THAN MaxSpanBytes PRODUCES NO SPAN. Not a truncated
//     one — none.
//
//     This used to truncate, and truncating was the bug. A regex like
//     "(?s).{1,512}" or "[\s\S]" matches the response body itself; cutting
//     that match down to the budget hands back a VERBATIM 512-BYTE PREFIX OF
//     THE RESPONSE, which is raw-body inlining arriving through the one
//     channel plan/00-SPINE.md S7 sanctions. So the answer is not a shorter
//     prefix, it is no prefix. matched stays TRUE — the oracle fired, and
//     whether the oracle fired is a different question from whether its match
//     is safe to show. NewSignature refuses most such patterns up front; this
//     is the second line, because a pattern can be narrow against the
//     generated benign corpus and still swallow a hostile body.
//
//     WHAT THIS BOUND DOES NOT CLAIM, stated because the comment here once
//     claimed it: NOT that "there is no length at which a prefix of an
//     arbitrary body becomes evidence". This bound only refuses matches
//     LONGER than 512, so a 403-byte match walks straight through it. That
//     was measured: `(?s)<h1[\s\S]{0,400}` inlined 403 verbatim body bytes,
//     and the corpus could not see it either, because `h1` is not one of the
//     thirteen tag names the generator was given.
//
//     WHAT ANSWERS THAT FAMILY IS refuseOverBroadPattern, ON THE PATTERN.
//     `[\s\S]` is an open position under R2, so every spelling of the
//     bounded-prefix shape is refused at compile time whatever tag it names
//     — and rewriting the class as `[[:print:]]` to get past R2 meets R3,
//     which refuses 400 quoted positions against three spelled bytes.
//     TestTheBoundedPrefixFamilyIsRefusedByTheControlOnItsStructure drives
//     both spellings.
//
//     WHAT IS LEFT FOR THIS BOUND, and it is why the bound is still here:
//     a pattern can satisfy all three rules and still swallow a hostile body
//     whole. `ANVIL-SPAN-BEGIN[0-9A-Za-z]*ANVIL-SPAN-END` declares a
//     token-shaped class, which is not content-bearing, so R3 lets it repeat
//     without a ceiling — and a target that answers with a megabyte of
//     alphanumerics between the two markers produces a megabyte-long match.
//     That match yields NO SPAN here.
//
//     1b. A MATCH WITH MORE UNSPELLED BYTES THAN SPELLED ONES PRODUCES NO SPAN
//     EITHER, and this is a SECOND bound rather than a restatement of the
//     first. It was added because rerunning the round's own attack one class
//     to the left found the defect alive:
//
//     `(?s)<h1[\s\S]{0,400}`   refused by R2 — an open class
//     `<h1[[:print:]]{0,400}`  refused by R3 — 400 quoted against 3 spelled
//     `<h1[0-9A-Za-z]{0,400}`  ACCEPTED, and it inlined a 403-byte span
//
//     The third one is accepted for a real reason: an alphanumeric class
//     carries no separator, so R3 does not count it as quotation, and the
//     same reasoning is what lets `AKIA[0-9A-Z]{16}` and
//     `Server: nginx/1\.[0-9]+\.[0-9]+` compile at all. It is nevertheless
//     400 bytes of the response — a bearer token, a JWT, a hash — reached
//     from three spelled bytes.
//
//     So the inequality R3 argues for at COMPILE time is enforced again here
//     at EXTRACTION time, over the actual match, for every class: with s the
//     pattern's minLiteral and L the match length, a span exists only when
//     L - s <= s. Nothing is exempt, there is no class list, and the
//     arithmetic gives the same q <= L/2 <= 256 for a pattern R3 never
//     looked at. The cost is stated rather than hidden: a 20-byte
//     `AKIA[0-9A-Z]{16}` match against four spelled bytes now yields NO
//     SPAN, so the key id itself is not inlined. The finding is still
//     CONFIRMED and still carries the body hash — and a 16-character AWS key
//     id is a credential, so declining to quote it into a prompt-bound field
//     is the right answer arrived at by the right rule.
//     TestASpanMayNotCarryMoreOfTheBodyThanThePatternSpells is the sweep.
//
//  2. THE OUTPUT IS PRINTABLE ASCII. Everything outside 0x20-0x7e is dropped
//     and counted. That removes, without needing to enumerate them, every
//     C0 and C1 control, every bidirectional override and isolate, every
//     zero-width and word-joiner character, every Unicode tag character, and
//     every malformed UTF-8 byte — the classes engines.scrub removes one at a
//     time. This string is prompt-bound, so the charset is an allowlist and
//     not a denylist.
//
//  3. IT DROPS RATHER THAN SUBSTITUTES. A replacement character would be a
//     byte Anvil invented appearing inside prose attributed to the target.
//     The dropped count is how a reader learns something was removed.
func extractSpan(body []byte, sig Signature) (span string, dropped, overBroad int, matched bool) {
	if sig.re == nil {
		return "", 0, 0, false
	}
	loc := sig.re.FindIndex(body)
	if loc == nil {
		return "", 0, 0, false
	}
	match := body[loc[0]:loc[1]]
	if len(match) > MaxSpanBytes {
		// Matched, and there is no span. See property 1.
		return "", 0, len(match), true
	}
	// PROPERTY 1b, THE COMPOSITION RULE. len(match)-spelled is an upper
	// bound on how many bytes of this match the pattern did not spell, and a
	// span may not carry more of those than of the ones it did. See the
	// rule's own paragraph in this function's doc.
	if len(match)-sig.spelled > sig.spelled {
		return "", 0, len(match), true
	}

	var b strings.Builder
	b.Grow(len(match))
	for _, c := range match {
		if c < 0x20 || c > 0x7e {
			dropped++
			continue
		}
		b.WriteByte(c)
	}
	return b.String(), dropped, 0, true
}

// assertRejectionIsDecisive refuses to emit a REJECTED finding that could not
// have disproved anything.
//
// ===========================================================================
// WHY THIS IS AN ASSERTION AND NOT A COUNT
// ===========================================================================
//
// It replaces Ledger.IndecisiveRejectionCount, which counted this same
// condition and WAS UNREACHABLE FROM PRODUCTION. Measured by sweeping
// ConfirmAll over 26 statuses x {the signature matches, the signature does not
// match} = 52 runs, that method returned non-zero zero times — decide()'s
// rule 2 routes every indecisive run to ReasonReprobeIndecisive before
// ReasonDidNotReproduce can be reached, so no ConfirmFinding call can produce
// the value it was counting. A control that cannot fire is not a second line,
// it is a sentence; the count and the claim that it was "the second line of
// AssertNotSilentlyClean" are both deleted rather than qualified.
//
// What survives is the invariant they were about, stated at the one place it
// can actually fail. OutcomeRejected means THE ORACLE RAN AND DID NOT FIRE, so
// a rejected finding must carry zero indecisive attempts and a status this
// gate accepts as the application answering. This runs on every Finding
// ConfirmFinding assembles, in production, on every path.
//
// It is reachable: it is one edit to decide()'s switch away, which is exactly
// the edit it exists to survive.
// TestARejectionThatCouldNotHaveDisprovedAnythingIsRefused makes that edit and
// watches this fire.
//
// FAIL CLOSED. The failure mode is a candidate reported as REFUSED — which
// AssertNotSilentlyClean counts, and which therefore cannot become a silent
// clean — never a candidate reported as disproved.
func assertRejectionIsDecisive(f Finding) error {
	if f.outcome != OutcomeRejected {
		return nil
	}
	if f.indecisive > 0 {
		return fmt.Errorf("%w: a finding was assembled with outcome=%s over a run with %d "+
			"of %d attempt(s) that never established the application answered. A "+
			"rejection is the claim that the oracle RAN and did not fire, and this run "+
			"cannot support it",
			ErrRefused, OutcomeRejected, f.indecisive, f.attempts)
	}
	if !IsApplicationResponseStatus(f.status) {
		return fmt.Errorf("%w: a finding was assembled with outcome=%s from an attempt "+
			"whose status was %d, which this gate does not accept as the application "+
			"answering. Nothing was disproved, because nothing was asked",
			ErrRefused, OutcomeRejected, f.status)
	}
	return nil
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
