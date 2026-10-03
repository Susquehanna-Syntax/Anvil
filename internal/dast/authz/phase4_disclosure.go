// Phase 4 of the Authorization Gate Sequence: OUTPUT AND DISCLOSURE, gates
// 18–21.
//
// Phases 1–3 decide whether Anvil may TOUCH something. This phase decides what
// Anvil may SAY, WRITE and SEND once it has, and it is the phase whose failures
// are not recoverable: a finding published early cannot be unpublished, a patch
// pushed to a stranger's repository cannot be unpushed, and a gate decision
// that was never written down cannot be reconstructed after a complaint.
//
// ===========================================================================
// WHY NONE OF THESE FOUR IS A gateFunc, AND WHY THAT IS ENFORCED ELSEWHERE
// ===========================================================================
//
// kernel.go's registerInto REFUSES to register any Phase 4 gate, by number,
// with a message saying they "do not run per target and do not take (target,
// scope, attestation, clock)". That refusal is the kernel core's, not this file's, and
// TestPhase4GatesCannotBeRegisteredIntoAChain exercises all four so that a later
// contributor who adds `register(Gate18Embargo, ...)` to this file gets a
// panic in every test binary that links the package rather than a gate that
// silently never runs.
//
// The four are exported Check-style functions instead, each returning a real
// GateResult, and gate 21's GateAudit is the thing that couples them to the
// audit log.
//
// ===========================================================================
// GATE 19 IS A DATA-LOCATION RULE, AND IT IS THE ONE PEOPLE GET WRONG
// ===========================================================================
//
// The spine's corrected-requirements table row 5 collapsed the "8-hour buffer file, then deleted"
// design into "one SQLite store of record + a `handoff` table + a regenerable
// tmpfs packet", and says plainly that "8 hours" is A CLAIM TIMEOUT, NOT A
// DELETION POLICY. That is what makes a 45-day embargo representable at all:
// a 45-day clock cannot live in a buffer that a reboot empties.
//
// AN EMBARGO THAT FORGETS ITSELF IS AN EMBARGO THAT PUBLISHES. If the
// disclosure state for a third-party finding lives only in the tmpfs handoff
// packet, then after a reboot the next run sees no embargo, and "no embargo
// recorded" reads as "nothing is embargoed". So gate 19 refuses to persist
// disclosure state anywhere but the record store, and gate 18 refuses to
// publish anything whose disclosure state was not durably persisted — the two
// gates are wired to each other rather than each hoping the other ran.
//
// The structural half of the same rule: DisclosureRecord has NO EXPORTED
// FIELDS. `json.Marshal` of a fully populated one produces `{}`, so a handoff
// packet builder that embeds a DisclosureRecord serialises nothing, and
// TestDisclosureRecordSerialisesToNothing is the guard. What that does not
// close, stated plainly: a determined caller can read the accessors and copy
// the values into a packet by hand. Nothing in Go prevents that. What the
// design buys is that the accident does not happen, and the deliberate act
// looks deliberate in review.
//
// ===========================================================================
// WHAT IS NOT CONFIGURABLE HERE, AND HOW THAT IS ENFORCED
// ===========================================================================
//
// plan/design/dynamic-tier.md's gate table marks gates 19, 20 and 21 "Configurable? No",
// and gate 18 configurable only through "acceleration (active exploitation) /
// extension (core-OS changes)... disabling the embargo outright is not
// configurable".
//
// So there is NO FUNCTION IN THIS FILE THAT TAKES AN EMBARGO DURATION.
// OpenEmbargo takes no duration; DefaultEmbargo is a const; and the only two
// operations that move a deadline are Accelerate and Extend, each of which
// requires a reason drawn from a compiled-in ALLOWLIST of documented cases,
// requires evidence, and is bounded — acceleration cannot go below
// MinAcceleratedEmbargo and extension cannot go past MaxEmbargo.
//
// THAT SENTENCE IS TRUE AND, ON ITS OWN, BESIDE THE POINT — AND IT USED TO BE
// THE WHOLE DEFENCE. A duration parameter is one way to shorten an embargo.
// THE ORIGIN OF THE CLOCK IS THE OTHER, and it was open: the deadline is first
// contact plus 45 days, first contact is whatever Clock the caller handed
// RecordVendorContact, and nothing compared that instant to the clock the
// decision is made against.
//
// The first repair bounded the contact instant against a SECOND caller-
// supplied instant. That caught the lie told with ONE clock and missed the lie
// told with TWO, and the miss was measured end to end:
//
//	RecordVendorContact(channel, at=2026-01-03, now=2026-01-03)  PASSES
//	  — the back-date is zero, so MaxVendorContactBackdate never engages
//	OpenEmbargo(..., now=2026-01-03)                             PASSES
//	  — the deadline, 2026-02-17, is comfortably in that clock's future
//	AuditedPublication(..., Now=2026-08-22)                      PASSES
//	  — 45 days elapsed, zero days of vendor notice, one audit row
//
// A third comparison between two values the same caller controls fails the
// same way. So the repair is structural instead:
//
//	A RUN HAS EXACTLY ONE CLOCK. THE CALLER STILL CHOOSES IT — ONCE, AT
//	INITIATION — AND CANNOT RE-SUPPLY IT, OR A DIFFERENT ONE, PER DECISION.
//
// The earlier wording here was "AND IT IS NOT A PARAMETER", which is not true
// and is corrected rather than qualified: RunRequest.Clock is an exported,
// settable field and InitiateRun copies it verbatim into the seal, so the
// run's instant is exactly as caller-chosen as it ever was. What the seal
// buys is the OTHER half, and it is the half the January lie needed: a
// RunClock cannot be minted outside this package, and no Phase 4 decision
// accepts a "now", so the one instant the caller chose is the one every
// comparison in the run is made against. A lie is still spellable; it is no
// longer spellable INCONSISTENTLY, and the cost of telling it consistently is
// in this file's closing section and in docs/controls.md G18-2.
//
// types.go's RunClock is sealed at run initiation by an unexported
// constructor, exactly as Scope and Attestation are, and
// RunInitiation.RunClock is the only exported route to one. Every Phase 4
// decision READS it rather than accepting a "now":
//
//   - RecordVendorContact takes the contact instant — a recorded fact about
//     the past — and bounds it against the RUN'S clock. A contact in the
//     future is refused; a contact back-dated further than
//     MaxVendorContactBackdate is refused, because back-dating shortens the
//     embargo by exactly the amount it back-dates and so is Accelerate with
//     the allowlist and the evidence deleted.
//   - OpenEmbargo refuses an embargo whose deadline has already passed at the
//     run's clock. An embargo that was over before anybody opened it is not
//     an embargo.
//   - Accelerate accelerates TO the run's clock. Extend still chooses a new
//     deadline, which is a future instant an operator picks, but the instant
//     the adjustment is RECORDED at is the run's.
//   - PublicationRequest and PushRequest have NO CLOCK FIELD. GateAudit is
//     bound to the run's clock and gates 18 and 20 read it from there.
//
// So within one run the three instants above are one instant, and the sequence
// cannot be spelled: at a January run clock the publication is refused with
// the embargo still running, and at an August run clock the January contact is
// refused as back-dated past the bound.
// TestGate18TheConsistentClockLieIsRefusedInBothDirections is the guard and it
// runs both halves.
//
// WHAT THIS DOES NOT CLOSE, STATED RATHER THAN PAPERED OVER. This package has
// no ambient time source — the spine's safety section makes the kernel a pure
// function of (target, scope, attestation, clock) — so a run's clock is still
// the instant the harness handed InitiateRun. Telling the January/August lie
// now costs TWO run initiations: two scope loads, two gate-7 trigger checks,
// and two attestations live at instants seven months apart, which gate 5's
// 30-day ceiling means cannot be one attestation. The audit rows for the two
// runs are keyed to different attestation IDs. That is a materially larger and
// more visible act than passing a different time.Time to the next call, and it
// is as far as a kernel with no trusted clock can go. Recorded in
// docs/controls.md as G18-2.

package authz

import (
	"fmt"
	"strings"
	"sync"
	"time"
)

// ---------------------------------------------------------------------------
// REASONS — the gate-numbered tokens Phase 4 refuses and permits with
// ---------------------------------------------------------------------------

// Gate 18 reasons.
const (
	ReasonFindingUnidentified            Reason = "gate18.finding_has_no_valid_identifier"
	ReasonOwnershipUnclassified          Reason = "gate18.finding_ownership_was_never_classified"
	ReasonOwnershipRepositoryMalformed   Reason = "gate18.repository_name_is_malformed"
	ReasonEmbargoUnconstructed           Reason = "gate18.embargo_state_not_constructed"
	ReasonEmbargoOperatorOwned           Reason = "gate18.operator_owned_finding_is_not_embargoed"
	ReasonEmbargoNoVendorContact         Reason = "gate18.no_vendor_contact_was_recorded"
	ReasonEmbargoNoReportingChannel      Reason = "gate18.gate12_resolved_no_reporting_channel"
	ReasonEmbargoClockUnconstructed      Reason = "gate18.clock_not_constructed"
	ReasonEmbargoClockWentBack           Reason = "gate18.clock_went_backwards"
	ReasonEmbargoContactInTheFuture      Reason = "gate18.vendor_contact_is_in_the_future"
	ReasonEmbargoContactBackdated        Reason = "gate18.vendor_contact_is_back_dated_past_the_bound"
	ReasonEmbargoElapsedBeforeItOpened   Reason = "gate18.embargo_deadline_had_already_passed_at_open"
	ReasonEmbargoFindingMismatch         Reason = "gate18.embargo_is_for_another_finding"
	ReasonEmbargoRunning                 Reason = "gate18.embargo_clock_is_still_running"
	ReasonEmbargoAccelerationUnsupported Reason = "gate18.acceleration_reason_not_on_the_allowlist"
	ReasonEmbargoAccelerationUnevidenced Reason = "gate18.acceleration_reason_carries_no_evidence"
	ReasonEmbargoAccelerationNoEffect    Reason = "gate18.acceleration_does_not_move_the_deadline"
	ReasonEmbargoExtensionUnsupported    Reason = "gate18.extension_reason_not_on_the_allowlist"
	ReasonEmbargoExtensionUnevidenced    Reason = "gate18.extension_reason_carries_no_evidence"
	ReasonEmbargoExtensionNotLonger      Reason = "gate18.extension_does_not_lengthen_the_embargo"
	ReasonEmbargoExtensionExceedsBound   Reason = "gate18.extension_exceeds_the_coded_bound"
	ReasonPublicationStateNotPersisted   Reason = "gate18.disclosure_state_was_never_persisted"
	ReasonPublicationFindingWithheld     Reason = "gate18.finding_is_withheld"
	ReasonPublicationStoreMissing        Reason = "gate18.no_disclosure_store_to_read_the_state_from"
	ReasonPublicationStoreWrongMedium    Reason = "gate18.disclosure_store_is_not_the_sqlite_record_store"
	ReasonPublicationStoreUnreadable     Reason = "gate18.disclosure_store_could_not_be_read"
	ReasonPublicationPermitted           Reason = "gate18.publication_permitted"
)

// Gate 19 reasons.
const (
	ReasonDisclosureRecordUnconstructed  Reason = "gate19.disclosure_record_not_constructed"
	ReasonDisclosureStateUnknown         Reason = "gate19.disclosure_state_is_not_on_the_allowlist"
	ReasonDisclosureStoreMissing         Reason = "gate19.no_disclosure_store_was_supplied"
	ReasonDisclosureStoreWrongMedium     Reason = "gate19.store_is_not_the_sqlite_record_store"
	ReasonDisclosureWriteFailed          Reason = "gate19.disclosure_state_write_failed"
	ReasonDisclosureReadFailed           Reason = "gate19.disclosure_state_read_failed"
	ReasonDisclosureKeyIncomplete        Reason = "gate19.disclosure_row_cannot_be_keyed"
	ReasonDisclosureWithholdingHeld      Reason = "gate19.transition_out_of_withheld_carries_no_release"
	ReasonDisclosureReleaseUnsupported   Reason = "gate19.release_reason_not_on_the_allowlist"
	ReasonDisclosureReleaseUnevidenced   Reason = "gate19.release_reason_carries_no_evidence"
	ReasonDisclosureReleaseNotApplicable Reason = "gate19.release_offered_where_nothing_is_being_released"
	ReasonDisclosureStateMovedUnderWrite Reason = "gate19.recorded_state_moved_between_the_check_and_the_write"
	ReasonDisclosurePersisted            Reason = "gate19.disclosure_state_persisted_in_the_record_store"
)

// Gate 20 reasons.
const (
	ReasonPushPatchUnidentified       Reason = "gate20.patch_was_never_identified"
	ReasonPushOwnershipUnclassified   Reason = "gate20.destination_ownership_was_never_classified"
	ReasonPushClockUnconstructed      Reason = "gate20.clock_not_constructed"
	ReasonPushScopeUnconstructed      Reason = "gate20.scope_not_constructed"
	ReasonPushWithoutAttestation      Reason = "gate20.no_attestation_for_this_patch_delivery"
	ReasonPushAttestationScopeUnbound Reason = "gate20.attestation_is_not_bound_to_this_scope"
	ReasonPushAttestationNotLive      Reason = "gate20.attestation_is_expired_or_not_yet_valid"
	ReasonPushAttestationLifetime     Reason = "gate20.attestation_lifetime_exceeds_the_coded_ceiling"
	ReasonPushNoEmbargoOpened         Reason = "gate20.no_embargo_and_therefore_no_vendor_contact"
	ReasonPushFindingMismatch         Reason = "gate20.embargo_is_for_another_finding"
	ReasonPushPermitted               Reason = "gate20.patch_delivery_permitted"
)

// Gate 21 reasons.
//
// ReasonAuditWriteFailed, ReasonAuditKeyIncomplete and ReasonAuditSinkMissing
// are the kernel core's and are reused rather than re-spelled: a second token for one
// condition is a second thing an operator has to grep for.
const (
	ReasonAuditClockUnconstructed Reason = "gate21.clock_not_constructed"
	ReasonAuditRowUnattributable  Reason = "gate21.gate_result_carries_no_reason_token"
	ReasonAuditNotAppendOnly      Reason = "gate21.audit_sequence_did_not_advance"
	ReasonAuditTraceEmpty         Reason = "gate21.no_gate_decision_to_record"
	ReasonAuditRowWritten         Reason = "gate21.decision_recorded"
)

// ReasonTriggerProvenanceVerified is gate 7's PASS token.
//
// It is declared here rather than in phase1_run.go for the reason per-request enforcement gave for
// declaring gate 11's pass token in phase3_enforcement.go: run initiation's file is
// outside this packet's write scope, and the need for the token is gate 21's.
// CheckGate7TriggerProvenance returns gatePassed, which carries no Reason —
// the kernel core's GateResult has no field for one — so without this the audit row for a
// gate 7 allow would have an empty reason and GateRecord.Validate would refuse
// it.
const ReasonTriggerProvenanceVerified Reason = "gate07.trigger_provenance_verified"

// ===========================================================================
// GATE 18 — no auto-publication of third-party findings
// ===========================================================================

// maxFindingIDLen bounds a finding identifier. It reaches the audit log and
// the record store, so it is bounded where it is constructed rather than
// wherever it is eventually rendered.
const maxFindingIDLen = 128

// FindingID is the stable identifier of one finding.
//
// The charset is an ALLOWLIST, for the same reason AttestationID's is: this
// value lands in an audit row and in a SQLite column, both of which are read
// by humans and by tooling, and the spine's safety section makes anything derived
// from a scanned target `anvil/trust: untrusted`.
type FindingID string

// Validate reports whether id is a non-empty, bounded, allowlisted token.
func (id FindingID) Validate() error {
	if id == "" {
		return fmt.Errorf("%w: finding ID is empty, so no disclosure state can be keyed to "+
			"it and no embargo can be about it", ErrRefused)
	}
	if len(id) > maxFindingIDLen {
		return fmt.Errorf("%w: finding ID is %d bytes; the cap is %d",
			ErrRefused, len(id), maxFindingIDLen)
	}
	for i := 0; i < len(id); i++ {
		c := id[i]
		ok := (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
			(c >= '0' && c <= '9') || c == '-' || c == '_' || c == '.'
		if !ok {
			return fmt.Errorf("%w: finding ID has byte %q at offset %d, which is not in the "+
				"allowed set [A-Za-z0-9._-]", ErrRefused, string(c), i)
		}
	}
	return nil
}

// FindingOwnership says whether a finding is against code the operator owns.
//
// research/20 gate 18: "Findings against code Anvil's operator does not own
// enter an embargoed state." The zero value is not a classification, and the
// accessors below treat it as third-party, which is the fail-closed direction.
type FindingOwnership string

// The ownership classifications. FindingOwnershipUnset is not one.
const (
	// FindingOwnershipUnset is the zero value: nobody classified this.
	FindingOwnershipUnset FindingOwnership = ""
	// FindingOwnershipOperatorOwned means the repository is on the
	// operator's own declared list.
	FindingOwnershipOperatorOwned FindingOwnership = "operator_owned"
	// FindingOwnershipThirdParty means it is not, which includes every
	// repository nobody listed.
	FindingOwnershipThirdParty FindingOwnership = "third_party"
)

// Valid reports whether o is one of the two classifications.
func (o FindingOwnership) Valid() bool {
	return o == FindingOwnershipOperatorOwned || o == FindingOwnershipThirdParty
}

// OwnedRepositories is the operator's declaration of what they own.
//
// # Why this is an allowlist and not a "is it third party" denylist
//
// The question gate 18 asks is "may this be published without an embargo",
// and the only safe default answer is no. A denylist of third-party
// repositories would have to enumerate every repository in the world that is
// not the operator's; an allowlist has to enumerate the handful that are. A
// repository nobody listed is therefore third-party, and the ZERO VALUE OWNS
// NOTHING, so a caller that forgot to declare ownership embargoes everything.
type OwnedRepositories struct {
	repos  map[string]struct{}
	sealed bool
}

// NewOwnedRepositories declares the repositories the operator owns.
//
// An EMPTY declaration is legal and owns nothing. That is not the same as the
// zero value — which also owns nothing — but it is the same answer, on
// purpose: there is no shape of this type that owns everything.
func NewOwnedRepositories(repos ...string) (OwnedRepositories, error) {
	set := make(map[string]struct{}, len(repos))
	for i, r := range repos {
		if err := validateRepositoryName(r, "owned repository"); err != nil {
			return OwnedRepositories{}, fmt.Errorf("owned repositories: entry %d: %w", i, err)
		}
		set[r] = struct{}{}
	}
	return OwnedRepositories{repos: set, sealed: true}, nil
}

// Constructed reports whether this came from NewOwnedRepositories.
func (o OwnedRepositories) Constructed() bool { return o.sealed }

// Owns reports whether repo is on the operator's declared list. It is false
// for the zero value, for every repo.
func (o OwnedRepositories) Owns(repo string) bool {
	if !o.sealed || o.repos == nil || repo == "" {
		return false
	}
	_, ok := o.repos[repo]
	return ok
}

// Count returns how many repositories were declared.
func (o OwnedRepositories) Count() int { return len(o.repos) }

// Ownership is one repository's CLASSIFIED ownership.
//
// It is sealed rather than being a bare FindingOwnership field on a request
// struct, because a bare enum field is a place for a caller to write
// "operator_owned" and skip the embargo. The only way to get one is
// ClassifyOwnership, which compares against the operator's own declaration.
//
// The zero value is not a classification: Classified() is false, ThirdParty()
// is TRUE and OperatorOwned() is false, so a forgotten field embargoes rather
// than publishes.
type Ownership struct {
	repo   string
	owner  FindingOwnership
	sealed bool
}

// ClassifyOwnership classifies one repository against the operator's
// declaration.
func ClassifyOwnership(repo string, owned OwnedRepositories) (Ownership, GateResult) {
	const g = Gate18Embargo
	if err := validateRepositoryName(repo, "finding repository"); err != nil {
		return Ownership{}, gateFailed(g, ReasonOwnershipRepositoryMalformed,
			"the repository a finding is against must be a well-formed \"owner/name\" "+
				"before gate 18 can say whether the operator owns it. A name that does "+
				"not parse is not matched against the operator's list and is not "+
				"quietly treated as third-party either: it is refused, because a "+
				"classification nobody could make is not a classification.",
			"repository: "+redactUntrusted(repo))
	}
	own := FindingOwnershipThirdParty
	if owned.Owns(repo) {
		own = FindingOwnershipOperatorOwned
	}
	return Ownership{repo: repo, owner: own, sealed: true}, gatePassed(g)
}

// Classified reports whether this Ownership came from ClassifyOwnership.
func (o Ownership) Classified() bool { return o.sealed && o.owner.Valid() && o.repo != "" }

// OperatorOwned reports whether the operator owns this repository. It is
// false for the zero value.
func (o Ownership) OperatorOwned() bool {
	return o.Classified() && o.owner == FindingOwnershipOperatorOwned
}

// ThirdParty reports whether the repository must be treated as somebody
// else's. It is TRUE for the zero value: an unclassified repository is not a
// repository known to be ours.
func (o Ownership) ThirdParty() bool { return !o.OperatorOwned() }

// Repository returns the classified repository name.
func (o Ownership) Repository() string { return o.repo }

// Owner returns the classification for the audit row and the record store.
// It is FindingOwnershipUnset for the zero value.
func (o Ownership) Owner() FindingOwnership {
	if !o.Classified() {
		return FindingOwnershipUnset
	}
	return o.owner
}

// VendorContact is the recorded fact that the vendor was contacted, through
// the channel gate 12 resolved.
//
// research/20 gate 18 starts the clock at "45 days from first vendor contact",
// so the embargo cannot be opened without one: a 45-day clock started before
// anybody was told is 45 days of nobody being told.
//
// # Gate 12 appears here and cannot leak into an admission decision
//
// SecurityTxtResult embeds ReportingChannelOnly, so it satisfies the
// unexported excludedFromAdmission interface and kernel_test.go's closure walk
// refuses it anywhere in Decide's input types. This is Phase 4: the reporting
// channel is being used for REPORTING, which is the only thing RFC 9116 and
// the spine's safety section permit it to be used for. Nothing in this file returns a
// Ruling, so nothing here can put a security.txt result into an admission
// decision even by accident.
type VendorContact struct {
	channel SecurityTxtResult
	at      time.Time
	sealed  bool
}

// RecordVendorContact records first contact through gate 12's resolved
// channel.
//
// # Why it takes a contact instant and THE RUN'S clock
//
// `at` is when the vendor was contacted and is what the 45-day deadline is
// measured from. It is a recorded fact about the past, so it is a parameter.
//
// `run` is not. It is the clock established once at run initiation, sealed by
// sealRunClock, and there is no exported constructor for one — see types.go's
// RunClock. An earlier shape took a second Clock here and called it `now`, and
// that shape bounded one caller-supplied instant against another: a caller who
// dated the contact 3 January and ALSO passed a 3 January "now" produced a
// back-date of zero, so MaxVendorContactBackdate never engaged, and the same
// caller then published against the real August present. Every gate green,
// forty-five days elapsed, nobody contacted.
//
// Two refusals, both measured against THE RUN'S clock:
//
//   - A contact in the FUTURE. The embargo would not start until then, and a
//     deadline measured from an instant that has not happened records a
//     conversation nobody has had.
//   - A contact back-dated further than MaxVendorContactBackdate. Back-dating
//     shortens the embargo by exactly the amount back-dated, with no
//     allowlisted reason, no evidence and no EmbargoAdjustment in the audit
//     trail — which is every property Accelerate has, removed.
func RecordVendorContact(channel SecurityTxtResult, at Clock, run RunClock) (VendorContact, GateResult) {
	const g = Gate18Embargo
	if !at.Valid() {
		return VendorContact{}, gateFailed(g, ReasonEmbargoClockUnconstructed,
			"vendor contact was recorded against a Clock that NewClock never built. The "+
				"embargo deadline is measured from this instant, so an unset one would "+
				"put the deadline in 1970 and the embargo would read as already elapsed.")
	}
	if !run.Valid() {
		return VendorContact{}, gateFailed(g, ReasonEmbargoClockUnconstructed,
			"there is no RUN CLOCK to bound this contact against. A RunClock is sealed at "+
				"run initiation and cannot be minted by a caller; the zero value means "+
				"this contact is being recorded outside any initiated run, and the "+
				"instant the 45-day deadline is measured from would be a free "+
				"parameter again.")
	}
	if at.Instant().After(run.Instant()) {
		return VendorContact{}, gateFailed(g, ReasonEmbargoContactInTheFuture,
			"the vendor contact is dated after the run recording it. A contact that has "+
				"not happened yet starts no clock, and a deadline measured from it is "+
				"measured from nothing.",
			"contact:   "+at.Instant().UTC().Format(time.RFC3339),
			"run clock: "+run.Instant().UTC().Format(time.RFC3339))
	}
	if back := run.Instant().Sub(at.Instant()); back > MaxVendorContactBackdate {
		return VendorContact{}, gateFailed(g, ReasonEmbargoContactBackdated,
			"the vendor contact is back-dated further than the coded bound. Back-dating "+
				"first contact shortens the embargo by exactly that much and leaves no "+
				"EmbargoAdjustment behind, so an unbounded back-date is acceleration "+
				"with the allowlist and the evidence requirement deleted. Acceleration "+
				"is the documented way to shorten an embargo; it takes a reason and "+
				"evidence, and it is recorded.",
			"contact:     "+at.Instant().UTC().Format(time.RFC3339),
			"run clock:   "+run.Instant().UTC().Format(time.RFC3339),
			"coded bound: "+MaxVendorContactBackdate.String(),
			"back-dated:  "+back.String())
	}
	if channel.Status() != SecurityTxtStatusResolved || len(channel.Contacts()) == 0 {
		return VendorContact{}, gateFailed(g, ReasonEmbargoNoReportingChannel,
			"gate 12 resolved no reporting channel for this vendor, so there is nobody to "+
				"have contacted. An embargo whose clock starts without a contact is a "+
				"countdown to publishing a finding the vendor was never told about, "+
				"which is the exact outcome gate 18 exists to prevent.",
			"security.txt status: "+string(channel.Status()))
	}
	return VendorContact{channel: channel, at: at.Instant(), sealed: true}, gatePassed(g)
}

// Recorded reports whether contact was actually recorded.
func (v VendorContact) Recorded() bool {
	return v.sealed && !v.at.IsZero() && v.channel.Status() == SecurityTxtStatusResolved
}

// At returns the instant of first contact, which is when the embargo clock
// starts.
func (v VendorContact) At() time.Time { return v.at }

// Channel returns gate 12's resolved reporting channel.
func (v VendorContact) Channel() SecurityTxtResult { return v.channel }

// DefaultEmbargo is the CERT/CC 45-day clock research/20 gate 18 names:
// "Default clock: 45 days from first vendor contact, per CERT/CC".
//
// It is a const and there is no function in this package that accepts an
// embargo duration, which is how "disabling the embargo outright is not
// configurable" (plan/design/dynamic-tier.md gate 18) is enforced rather than promised.
const DefaultEmbargo = 45 * 24 * time.Hour

// MinAcceleratedEmbargo is the floor an ACCELERATED embargo cannot go below,
// measured from first contact.
//
// THIS NUMBER IS ANVIL'S, NOT CERT/CC'S. CERT/CC documents acceleration for
// observed active exploitation; it does not publish a floor, and this file
// does not pretend it does. The floor exists for a structural reason: without
// one, "accelerate to now" is how an embargo gets disabled while still being
// called an embargo, and the gate table says disabling is not configurable.
// One day is the shortest window in which a vendor who has just been told
// about active exploitation can act at all.
//
// # THE FLOOR IS MEASURED FROM FIRST CONTACT, AND FIRST CONTACT CAN BE MOVED
//
// So this constant on its own guarantees nothing. Back-dating the contact by B
// moves the floor B earlier, and the window a vendor actually gets, measured
// forward from the run that accelerates, is
//
//	MinAcceleratedEmbargo - MaxVendorContactBackdate
//
// not MinAcceleratedEmbargo. While both constants were 24h that difference was
// ZERO, and the floor was cancelled exactly: contact back-dated to the
// permitted bound, accelerated, and published IN THE SAME RUN, with 0s of
// embargo served. Neither constant was wrong on its own; the RELATION between
// them was never asserted. It is asserted now, both in
// TestPhase4EmbargoConstantsPinTheRelationsNotOnlyTheValues and behaviourally
// in TestGate18BackdatingToTheBoundCannotCancelTheAccelerationFloor.
const MinAcceleratedEmbargo = 24 * time.Hour

// MaxEmbargo is the ceiling an EXTENDED embargo cannot go past, measured from
// first contact.
//
// Also Anvil's number, for the mirror-image reason: an unbounded extension is
// how a finding gets buried while still being called embargoed. research/20
// permits extension for "standards/core-OS-level fixes", which are slow; a
// year is long enough for one and short enough to be a bound.
const MaxEmbargo = 365 * 24 * time.Hour

// MaxVendorContactBackdate is how far in the past a vendor contact may be
// dated relative to the run that records it.
//
// ALSO ANVIL'S NUMBER. No source publishes a back-dating bound, because no
// source anticipated a kernel with no trusted time source, whose every instant
// therefore arrives from the caller. The structural
// reason is the one MinAcceleratedEmbargo has: without a bound, dating first
// contact 45 days ago produces a zero-length embargo, and it does so with no
// allowlisted reason, no evidence and no EmbargoAdjustment — strictly weaker
// preconditions than Accelerate, for a strictly larger effect. With the bound,
// the shortest embargo reachable without an Accelerate call is DefaultEmbargo
// minus this, and the only way below that is the allowlist.
//
// # WHY THIS IS AN HOUR AND NOT THE DAY IT WAS
//
// It was 24h, and MinAcceleratedEmbargo is 24h, and the two cancelled: a
// contact back-dated to exactly the permitted bound put the acceleration floor
// at the run's own instant, so one allowlisted acceleration published a
// third-party finding in the run that recorded first contact. 0s of embargo
// served. Measured, not reasoned about.
//
// THE CONSTANT THAT MOVED IS THIS ONE, AND NOT THE FLOOR, because of what each
// number is for. MinAcceleratedEmbargo is a substantive claim about the world
// — the shortest window in which a vendor told about active exploitation can
// act at all — and lowering the risk by raising it would silently make every
// honest acceleration two days instead of one, changing a control nobody asked
// to change. This number is not a claim about the world; it is OPERATIONAL
// SLACK, and its own text already said what for: "clock skew and ... a contact
// made earlier in the same operational window, not a window in which to
// relocate the deadline". A day was never needed for either. An NTP-
// synchronised host agrees to within milliseconds; an unsynchronised one is
// wrong by minutes; the largest plausible SYSTEMATIC error is a whole-hour
// timezone or DST mistake. An hour covers all three. The day bought nothing
// except the entire acceleration floor.
//
// What this leaves, stated as a number rather than as "a day": the shortest
// embargo any sequence in this file can produce, measured forward from the run
// that accelerates, is MinAcceleratedEmbargo - MaxVendorContactBackdate = 23h.
// It is strictly positive because the two constants are asserted to be
// ordered, not because they happen to differ today.
const MaxVendorContactBackdate = 1 * time.Hour

// maxEmbargoEvidenceLen bounds the evidence string an adjustment carries.
const maxEmbargoEvidenceLen = 512

// EmbargoAccelerationReason is the compiled-in allowlist of reasons an embargo
// may be shortened.
//
// There is exactly ONE, and it is the one research/20 gate 18 documents:
// "documented acceleration for observed active exploitation". A reason nobody
// enumerated is not a weaker reason; it is no reason.
type EmbargoAccelerationReason string

// The acceleration reasons. The zero value is not one.
const (
	// EmbargoAccelerationUnset is the zero value and accelerates nothing.
	EmbargoAccelerationUnset EmbargoAccelerationReason = ""
	// EmbargoAccelerationActiveExploitation is CERT/CC's documented case.
	EmbargoAccelerationActiveExploitation EmbargoAccelerationReason = "active_exploitation_observed"
)

// Valid reports whether r is the one documented acceleration reason.
func (r EmbargoAccelerationReason) Valid() bool {
	return r == EmbargoAccelerationActiveExploitation
}

// EmbargoExtensionReason is the compiled-in allowlist of reasons an embargo
// may be lengthened: research/20 gate 18's "extension for standards/core-OS-
// level fixes".
type EmbargoExtensionReason string

// The extension reasons. The zero value is not one.
const (
	// EmbargoExtensionUnset is the zero value and extends nothing.
	EmbargoExtensionUnset EmbargoExtensionReason = ""
	// EmbargoExtensionStandardsProcess is a fix that requires a standards
	// change before it can ship.
	EmbargoExtensionStandardsProcess EmbargoExtensionReason = "standards_process"
	// EmbargoExtensionCoreOSChange is a fix that requires a core operating
	// system change.
	EmbargoExtensionCoreOSChange EmbargoExtensionReason = "core_os_change"
)

// Valid reports whether r is one of the two documented extension reasons.
func (r EmbargoExtensionReason) Valid() bool {
	return r == EmbargoExtensionStandardsProcess || r == EmbargoExtensionCoreOSChange
}

// EmbargoAdjustmentKind says which direction an adjustment moved the deadline.
type EmbargoAdjustmentKind string

// The adjustment kinds. The zero value is not one.
const (
	EmbargoAdjustmentUnset      EmbargoAdjustmentKind = ""
	EmbargoAdjustmentAccelerate EmbargoAdjustmentKind = "accelerated"
	EmbargoAdjustmentExtend     EmbargoAdjustmentKind = "extended"
)

// EmbargoAdjustment is one recorded move of the deadline.
//
// It carries the before and after deadlines, not just the new one, so that the
// audit trail answers "how did a 45-day embargo become a 6-day one" without
// anybody having to reconstruct it. Every field is unexported and every field
// is a value type — no slices, no maps, no pointers — so a returned copy
// cannot be written through.
type EmbargoAdjustment struct {
	kind     EmbargoAdjustmentKind
	reason   string
	evidence string
	at       time.Time
	from     time.Time
	to       time.Time
}

// Kind returns whether this adjustment accelerated or extended.
func (a EmbargoAdjustment) Kind() EmbargoAdjustmentKind { return a.kind }

// Reason returns the allowlisted reason literal.
func (a EmbargoAdjustment) Reason() string { return a.reason }

// Evidence returns the bounded evidence the operator attached.
func (a EmbargoAdjustment) Evidence() string { return a.evidence }

// At returns when the adjustment was made.
func (a EmbargoAdjustment) At() time.Time { return a.at }

// From returns the deadline before the adjustment.
func (a EmbargoAdjustment) From() time.Time { return a.from }

// To returns the deadline after it.
func (a EmbargoAdjustment) To() time.Time { return a.to }

// EmbargoState is one third-party finding's disclosure clock.
//
// The zero value is not an embargo — Constructed() is false and
// CheckGate18Publication refuses it — and there is no method that sets the
// deadline directly. Accelerate and Extend return a NEW EmbargoState rather
// than mutating the receiver, the same shape Cap.Lower uses, so a caller
// holding an old copy holds an old deadline rather than a surprising one.
type EmbargoState struct {
	finding      FindingID
	ownership    Ownership
	contact      VendorContact
	firstContact time.Time
	deadline     time.Time
	adjustments  []EmbargoAdjustment
	sealed       bool
}

// OpenEmbargo starts the 45-day clock for a third-party finding.
//
// It refuses an OPERATOR-OWNED finding on purpose. Gate 18 is about findings
// "against code Anvil's operator does not own"; opening an embargo on your own
// finding would put a meaningless clock in the record store and, worse, would
// make the presence of an EmbargoState stop being evidence that the finding is
// somebody else's.
//
// `run` is THE RUN'S clock, not a per-call one, and it is here for one check:
// an embargo whose deadline has already passed at open time is not an embargo,
// it is a publication with a countdown drawn on it afterwards. Within one run
// this is the same instant RecordVendorContact bounded the contact against and
// the same instant checkGate18Publication measures the deadline against — that
// is the point, and it is what makes the consistently-told January lie a
// refusal instead of a green chain.
func OpenEmbargo(own Ownership, finding FindingID, contact VendorContact, run RunClock) (EmbargoState, GateResult) {
	const g = Gate18Embargo
	if err := finding.Validate(); err != nil {
		return EmbargoState{}, gateFailed(g, ReasonFindingUnidentified,
			"an embargo is keyed to a finding, and this one has no valid identifier.",
			"finding: "+redactUntrusted(string(finding)))
	}
	if !own.Classified() {
		return EmbargoState{}, gateFailed(g, ReasonOwnershipUnclassified,
			"the finding's repository was never classified against the operator's declared "+
				"list, so gate 18 cannot say whether this finding needs an embargo. An "+
				"unclassified finding is not published and is not embargoed either: it "+
				"is refused until somebody classifies it.")
	}
	if own.OperatorOwned() {
		return EmbargoState{}, gateFailed(g, ReasonEmbargoOperatorOwned,
			"this finding is against a repository the operator declared they own, and gate "+
				"18 embargoes third-party findings. Publish it through the "+
				"operator-owned path rather than opening an embargo that means nothing.",
			"repository: "+redactUntrusted(own.Repository()))
	}
	if !contact.Recorded() {
		return EmbargoState{}, gateFailed(g, ReasonEmbargoNoVendorContact,
			"no vendor contact was recorded, and the 45-day clock runs FROM first contact. "+
				"Starting it without one would count down 45 days of the vendor not "+
				"knowing, and then publish.")
	}
	if !run.Valid() {
		return EmbargoState{}, gateFailed(g, ReasonEmbargoClockUnconstructed,
			"the embargo was opened outside any initiated run: the RunClock is the zero "+
				"value, which sealRunClock never produces from a valid Clock. There is "+
				"nothing to check the new deadline against and an already-elapsed "+
				"embargo would open silently.")
	}
	deadline := contact.At().Add(DefaultEmbargo)
	if !deadline.After(run.Instant()) {
		return EmbargoState{}, gateFailed(g, ReasonEmbargoElapsedBeforeItOpened,
			"the 45-day deadline computed from this contact has ALREADY PASSED at the "+
				"instant the embargo is being opened. That is not an embargo; it is a "+
				"publication with a countdown drawn on it afterwards. The clock runs "+
				"from first contact, so an embargo is opened when contact is made, not "+
				"reconstructed later from a date that makes it elapsed.",
			"first contact: "+contact.At().UTC().Format(time.RFC3339),
			"deadline:      "+deadline.UTC().Format(time.RFC3339),
			"run clock:     "+run.Instant().UTC().Format(time.RFC3339))
	}
	return EmbargoState{
		finding:      finding,
		ownership:    own,
		contact:      contact,
		firstContact: contact.At(),
		deadline:     deadline,
		sealed:       true,
	}, gatePassed(g)
}

// Constructed reports whether this came from OpenEmbargo.
func (e EmbargoState) Constructed() bool {
	return e.sealed && e.finding.Validate() == nil && !e.firstContact.IsZero() &&
		!e.deadline.IsZero() && e.ownership.Classified() && e.contact.Recorded()
}

// Finding returns the finding this embargo is about.
func (e EmbargoState) Finding() FindingID { return e.finding }

// Ownership returns the finding's classified ownership.
func (e EmbargoState) Ownership() Ownership { return e.ownership }

// Contact returns the recorded vendor contact.
func (e EmbargoState) Contact() VendorContact { return e.contact }

// FirstContact returns the instant the clock started.
func (e EmbargoState) FirstContact() time.Time { return e.firstContact }

// Deadline returns the instant publication becomes permissible.
func (e EmbargoState) Deadline() time.Time { return e.deadline }

// Adjustments returns a copy of the recorded adjustments.
//
// The copy is enough here and would not be enough for a Scope: the kernel-types review
// showed that copying a []ScopeEntry copies the structs but not their []uint16
// backing arrays. EmbargoAdjustment has no slice, map or pointer field — only
// strings and time.Times — so a copied element shares nothing with the
// original. TestEmbargoAdjustmentsCannotBeWrittenThrough is the guard, and
// TestEmbargoAdjustmentHasNoReferenceFields is the guard that fails if
// somebody adds one.
func (e EmbargoState) Adjustments() []EmbargoAdjustment {
	return append([]EmbargoAdjustment(nil), e.adjustments...)
}

// Elapsed reports whether the embargo deadline has passed at now. It is false
// for an unconstructed embargo and for an invalid clock: an embargo nobody
// opened has not elapsed, it does not exist, and neither state publishes.
func (e EmbargoState) Elapsed(now Clock) bool {
	if !e.Constructed() || !now.Valid() {
		return false
	}
	return !now.Instant().Before(e.deadline)
}

// Accelerate shortens the embargo for one of the documented reasons.
//
// # The three things that make this not a disable switch
//
//  1. The reason must be on the compiled-in allowlist. There is one entry.
//  2. Evidence is required and bounded. "Active exploitation observed" with
//     nothing attached is an assertion, and an assertion that shortens an
//     embargo is the config key the gate table says does not exist.
//  3. The new deadline is FLOORED at MinAcceleratedEmbargo from FIRST
//     CONTACT. Accelerating to "now" does not produce a zero-length embargo:
//     with an honest contact instant it produces a one-day one, and with a
//     contact back-dated to the permitted bound it produces
//     MinAcceleratedEmbargo - MaxVendorContactBackdate = 23h. The second
//     number is the guarantee, because the second case is the one an attacker
//     picks; see MaxVendorContactBackdate for what it cost while the two
//     constants were equal.
//
// The instant it accelerates TO is the run's, not a parameter. Acceleration is
// "publish now because it is already being exploited", and "now" is the run's
// clock; a caller-supplied instant here would be a fourth place to relocate
// the deadline, reachable with one allowlisted reason instead of the bound.
func (e EmbargoState) Accelerate(reason EmbargoAccelerationReason, evidence string, run RunClock) (EmbargoState, GateResult) {
	const g = Gate18Embargo
	if !e.Constructed() {
		return EmbargoState{}, gateFailed(g, ReasonEmbargoUnconstructed,
			"Accelerate was called on an EmbargoState that OpenEmbargo never built. There "+
				"is no deadline to move, and returning a constructed one here would "+
				"mint an embargo out of a zero value.")
	}
	if !reason.Valid() {
		return EmbargoState{}, gateFailed(g, ReasonEmbargoAccelerationUnsupported,
			"the only documented acceleration case is observed active exploitation "+
				"(research/20 gate 18, CERT/CC). The reason supplied is not that one, "+
				"and an undocumented reason does not shorten an embargo — including "+
				"the empty reason a caller that forgot the argument supplies.",
			"reason: "+redactUntrusted(string(reason)),
			"the allowlist: "+string(EmbargoAccelerationActiveExploitation))
	}
	ev, err := boundedEvidence(evidence)
	if err != nil {
		return EmbargoState{}, gateFailed(g, ReasonEmbargoAccelerationUnevidenced,
			"acceleration requires evidence, and this one carries none the audit can hold. "+
				"plan/design/dynamic-tier.md calls acceleration a DOCUMENTED exception; an "+
				"exception with no document is a config key.",
			"evidence: "+err.Error())
	}
	if !run.Valid() {
		return EmbargoState{}, gateFailed(g, ReasonEmbargoClockUnconstructed,
			"Accelerate was called outside any initiated run, so the new deadline would be "+
				"computed against an instant nobody set.")
	}
	if run.Instant().Before(e.firstContact) {
		return EmbargoState{}, gateFailed(g, ReasonEmbargoClockWentBack,
			"the run accelerating this embargo is clocked BEFORE the first contact the "+
				"embargo runs from. A clock that went backwards is a clock, not a "+
				"shorter embargo.",
			"first contact: "+e.firstContact.UTC().Format(time.RFC3339),
			"run clock:     "+run.Instant().UTC().Format(time.RFC3339))
	}
	candidate := run.Instant()
	if floor := e.firstContact.Add(MinAcceleratedEmbargo); candidate.Before(floor) {
		candidate = floor
	}
	if !candidate.Before(e.deadline) {
		return EmbargoState{}, gateFailed(g, ReasonEmbargoAccelerationNoEffect,
			"this acceleration would not move the deadline earlier, so nothing was "+
				"changed. Refusing rather than silently doing nothing: a caller that "+
				"asked to accelerate and got a success it did not get is a caller that "+
				"will publish on a date it thinks it moved.",
			"current deadline: "+e.deadline.UTC().Format(time.RFC3339),
			"requested:        "+candidate.UTC().Format(time.RFC3339))
	}
	next := e
	next.adjustments = append(append([]EmbargoAdjustment(nil), e.adjustments...), EmbargoAdjustment{
		kind:     EmbargoAdjustmentAccelerate,
		reason:   string(reason),
		evidence: ev,
		at:       run.Instant(),
		from:     e.deadline,
		to:       candidate,
	})
	next.deadline = candidate
	return next, gatePassed(g)
}

// Extend lengthens the embargo for one of the documented reasons.
//
// It is bounded at MaxEmbargo from first contact for the same reason
// Accelerate is floored: an adjustment with no bound in one direction is an
// adjustment that can be used to defeat the gate in that direction.
//
// `until` is the NEW DEADLINE — a future instant the operator is choosing, so
// it is legitimately a parameter, and it is bounded in both directions. `run`
// is the run's clock and supplies the one thing the caller must not choose:
// WHEN THE ADJUSTMENT WAS MADE. An earlier shape recorded the adjustment's
// instant as `until`, so the audit row for a six-month extension claimed the
// extension was made six months from now.
func (e EmbargoState) Extend(reason EmbargoExtensionReason, evidence string, until Clock, run RunClock) (EmbargoState, GateResult) {
	const g = Gate18Embargo
	if !e.Constructed() {
		return EmbargoState{}, gateFailed(g, ReasonEmbargoUnconstructed,
			"Extend was called on an EmbargoState that OpenEmbargo never built.")
	}
	if !reason.Valid() {
		return EmbargoState{}, gateFailed(g, ReasonEmbargoExtensionUnsupported,
			"the documented extension cases are a standards process and a core-OS-level "+
				"change (research/20 gate 18). The reason supplied is neither.",
			"reason: "+redactUntrusted(string(reason)),
			"the allowlist: "+string(EmbargoExtensionStandardsProcess)+", "+
				string(EmbargoExtensionCoreOSChange))
	}
	ev, err := boundedEvidence(evidence)
	if err != nil {
		return EmbargoState{}, gateFailed(g, ReasonEmbargoExtensionUnevidenced,
			"extension requires evidence, and this one carries none the audit can hold.",
			"evidence: "+err.Error())
	}
	if !until.Valid() {
		return EmbargoState{}, gateFailed(g, ReasonEmbargoClockUnconstructed,
			"Extend was called with a Clock that NewClock never built.")
	}
	if !run.Valid() {
		return EmbargoState{}, gateFailed(g, ReasonEmbargoClockUnconstructed,
			"Extend was called outside any initiated run, so the audit trail could not say "+
				"when the deadline was moved. An adjustment nobody can date is an "+
				"adjustment nobody can review.")
	}
	if !until.Instant().After(e.deadline) {
		return EmbargoState{}, gateFailed(g, ReasonEmbargoExtensionNotLonger,
			"an extension must move the deadline LATER. This one does not, and a "+
				"\"extension\" that shortens an embargo is an acceleration that skipped "+
				"the acceleration allowlist.",
			"current deadline: "+e.deadline.UTC().Format(time.RFC3339),
			"requested:        "+until.Instant().UTC().Format(time.RFC3339))
	}
	if bound := e.firstContact.Add(MaxEmbargo); until.Instant().After(bound) {
		return EmbargoState{}, gateFailed(g, ReasonEmbargoExtensionExceedsBound,
			"this extension runs past the coded bound measured from first contact. An "+
				"unbounded extension is how a finding is buried while still being "+
				"called embargoed.",
			"coded bound: "+bound.UTC().Format(time.RFC3339),
			"requested:   "+until.Instant().UTC().Format(time.RFC3339))
	}
	next := e
	next.adjustments = append(append([]EmbargoAdjustment(nil), e.adjustments...), EmbargoAdjustment{
		kind:     EmbargoAdjustmentExtend,
		reason:   string(reason),
		evidence: ev,
		at:       run.Instant(),
		from:     e.deadline,
		to:       until.Instant(),
	})
	next.deadline = until.Instant()
	return next, gatePassed(g)
}

// PublicationRequest is everything gate 18 needs to decide whether a finding
// may be published EXCEPT the record store, which is a parameter of
// AuditedPublication rather than a field here — an interface field on a Phase
// 4 decision input is an extension point, and
// TestPhase4DecisionInputsCarryNoResponseBytes refuses one.
//
// Every field that could be forged is a SEALED type: Ownership comes only from
// ClassifyOwnership, EmbargoState only from OpenEmbargo, PersistedDisclosure
// only from a successful gate 19 write. The one plain field, a FindingID, is
// validated, and its zero value refuses.
//
// THERE IS NO CLOCK FIELD, and that is the fix for the consistently-told
// January lie. "Now" is the run's, read from the GateAudit the request is
// submitted through, so a caller cannot date the publication differently from
// the run that recorded the vendor contact. See types.go's RunClock.
type PublicationRequest struct {
	// Finding is the finding proposed for publication.
	Finding FindingID
	// Ownership is the classified ownership of the repository the finding is
	// against.
	Ownership Ownership
	// Embargo is the finding's clock. It is not consulted for an
	// operator-owned finding, which has none.
	Embargo EmbargoState
	// Persisted is gate 19's proof that this finding's disclosure state was
	// durably written to the record store. It is required of EVERY
	// publication, including the operator's own — see checkGate18Publication.
	Persisted PersistedDisclosure
}

// checkGate18Publication is gate 18: "No auto-publication of third-party
// findings, ever."
//
// # Why this is unexported and AuditedPublication is not
//
// Gate 21 says a decision is not "allowed" if its paired audit write fails.
// While this function was exported it returned an allow having written
// nothing, and the coupling was a wrapper a caller could choose — the probe
// output was literally "bare CheckGate18Publication passed=true". A rule that
// holds only when the caller opts in is not a rule.
//
// So the admission path's idiom is used here: kernel.go mints a grant only
// after the audit write lands, and no other package can construct one. Phase
// 4's equivalent is that gates 18, 19 and 20 have NO EXPORTED ENTRY POINT AT
// ALL. The only way to reach them from outside this package is
// GateAudit.AuditedPublication, AuditedPersistDisclosure and AuditedPush, each
// of which runs the gate and then requires the row to land before returning
// the allow. TestPhase4HasNoUnauditedExportedDecisionPath is the guard that
// fails if any of them is exported again.
//
// # The order, and why gate 19's proof is required before the deadline check
//
// Because the deadline check is only meaningful if the deadline is durable.
// An EmbargoState is a value in memory; it can be reconstructed by any caller
// that has the pieces. What makes it a real embargo is that the same state was
// written to the SQLite record store, where the next run — and the run after
// the reboot — will find it. So gate 18 refuses to publish anything whose
// disclosure state gate 19 did not persist, BEFORE it looks at the clock.
//
// # WHAT THE OWNERSHIP CLAIM MAY DELETE, AND WHAT IT MAY NOT
//
// This is gate 20's rule, applied here, and it was applied here LATE. Gate 20
// was fixed by hoisting its scope, attestation and liveness checks above its
// OperatorOwned() branch; gate 18 kept the bypass in its original position for
// a further round, and it was reachable through the only exported route:
//
//	NewOwnedRepositories("victim/product") -> ClassifyOwnership
//	  -> GateAudit.AuditedPublication{zero Embargo, zero Persisted}
//	  -> passed=true, rows=1
//
// Ownership is a SELF-ASSERTION. ClassifyOwnership compares the repository
// against a list of "owner/name" strings the caller supplied, and nothing in
// this package can check that list against a forge. AN UNVERIFIED CALLER
// ASSERTION MAY DELETE ONLY THE PART OF A CONTROL THAT THE ASSERTION IS ABOUT.
// "This repository is mine" bears on whether the finding needs an EMBARGO —
// research/20 gate 18 is about "findings against code Anvil's operator does
// not own", and an embargo on your own finding means nothing. It does not bear
// on whether the disclosure state was persisted, on whether somebody recorded
// a decision to WITHHOLD, or on what time it is.
//
// So the branch sits below every check it is not about. Everything above it
// holds for the operator's own findings too, and gate 19 has
// NewOwnFindingDisclosureRecord precisely so that an operator-owned
// publication can satisfy the persistence requirement rather than being
// exempted from it.
//
// # WHY IT TAKES THE STORE AND WHY THE STORE IS NOT A FIELD OF THE REQUEST
//
// It takes the store because a decision to WITHHOLD is a fact about a finding,
// not about a request, and while this function read only req.Persisted a
// second write overturned the first — see DisclosureStore's header for the
// measured sequence. Reading the caller's proof and calling that "the
// disclosure state" is reading the answer the caller chose to hand over.
//
// It is a parameter and not a field of PublicationRequest because
// TestPhase4DecisionInputsCarryNoResponseBytes refuses any INTERFACE field on
// the Phase 4 input structs: an interface reachable from a decision input is
// an extension point a scanned response body could arrive through. That guard
// is right and it decided this signature.
func checkGate18Publication(req PublicationRequest, run RunClock, store DisclosureStore) GateResult {
	const g = Gate18Embargo

	if err := req.Finding.Validate(); err != nil {
		return gateFailed(g, ReasonFindingUnidentified,
			"publication was requested for a finding with no valid identifier. An audit "+
				"row that cannot name what was published records nothing.",
			"finding: "+redactUntrusted(string(req.Finding)))
	}
	if !run.Valid() {
		return gateFailed(g, ReasonEmbargoClockUnconstructed,
			"publication was requested outside any initiated run: the RunClock is the zero "+
				"value. Every embargo comparison is measured against the run's clock, "+
				"and an unset one reads as 1970, which is after no deadline and before "+
				"every one depending on the comparison's direction.")
	}
	if !req.Ownership.Classified() {
		return gateFailed(g, ReasonOwnershipUnclassified,
			"the finding's repository was never classified, so gate 18 cannot say whether "+
				"this is the operator's own code or somebody else's. Unclassified is "+
				"refused rather than assumed either way.")
	}

	// ---- Everything the ownership claim is NOT about, above the branch ----
	if !req.Persisted.Valid() {
		return gateFailed(g, ReasonPublicationStateNotPersisted,
			"this finding's disclosure state was never durably persisted, so gate 19's "+
				"proof is missing. An embargo held only in memory or in the tmpfs "+
				"handoff packet does not survive a reboot, and an embargo that forgets "+
				"itself is an embargo that publishes. Claiming to own the repository "+
				"does not remove this: whether the state reached the record store is "+
				"not a question about who owns the code.",
			"repository: "+redactUntrusted(req.Ownership.Repository()))
	}
	if req.Persisted.Finding() != req.Finding {
		return gateFailed(g, ReasonPublicationStateNotPersisted,
			"the persisted disclosure state is for a different finding, so nothing durable "+
				"records the state of THIS one.",
			"requested finding: "+redactUntrusted(string(req.Finding)),
			"persisted finding: "+redactUntrusted(string(req.Persisted.Finding())))
	}
	if req.Persisted.State() == DisclosureStateWithheld {
		return gateFailed(g, ReasonPublicationFindingWithheld,
			"the persisted disclosure state for this finding is `withheld`, which is a "+
				"decision somebody made and recorded. An elapsed clock does not "+
				"overturn it, and neither does a claim to own the repository.")
	}

	// ---- What the STORE says, which is not what the caller handed us ----
	//
	// Everything above this point is a property of the proof the caller chose
	// to present. A caller who holds two proofs presents the convenient one,
	// which is exactly how a recorded `withheld` was overturned by writing a
	// second row. So the authority is asked directly.
	if store == nil {
		return gateFailed(g, ReasonPublicationStoreMissing,
			"no disclosure store was supplied, so gate 18 cannot ask what this finding's "+
				"recorded state actually is and would be deciding from the proof the "+
				"caller chose to hand over. A caller holding two proofs presents the "+
				"convenient one.")
	}
	if medium := store.Medium(); medium != MediumRecordStoreSQLite {
		return gateFailed(g, ReasonPublicationStoreWrongMedium,
			"the store gate 18 was asked to read the disclosure state from is not the "+
				"SQLite store of record. Reading \"nothing is withheld\" out of the "+
				"tmpfs handoff buffer proves nothing: the buffer does not survive a "+
				"reboot, so it cannot be the place a withholding decision is kept.",
			"declared medium: "+redactUntrusted(string(medium)),
			"the allowlist:   "+string(MediumRecordStoreSQLite))
	}
	stored, rerr := store.DisclosureStateFor(req.Finding)
	switch {
	case rerr != nil:
		return gateFailed(g, ReasonPublicationStoreUnreadable,
			"the disclosure state for this finding could not be read from the record "+
				"store. An unreadable state is not an absent one: it is refused rather "+
				"than assumed to be publishable, because the row that could not be read "+
				"is the row that says `withheld`.",
			"store error: "+rerr.Error())
	case stored == DisclosureStateWithheld:
		return gateFailed(g, ReasonPublicationFindingWithheld,
			"the RECORD STORE says this finding's disclosure state is `withheld`, whatever "+
				"the proof presented with this request says. A decision to withhold is "+
				"reversed by a row that carries an allowlisted release reason and "+
				"evidence, which gate 19 requires and which is what makes `withheld` "+
				"mean withheld rather than withheld-until-somebody-writes-another-row.")
	case !stored.Valid():
		return gateFailed(g, ReasonPublicationStateNotPersisted,
			"the record store holds no disclosure state for this finding, so nothing "+
				"durable records what was decided about it — whatever proof was "+
				"presented with this request, the store is the authority and the store "+
				"has forgotten. An embargo that forgets itself is an embargo that "+
				"publishes.",
			"state in the store: "+redactUntrusted(string(stored)))
	}

	if req.Ownership.OperatorOwned() {
		// The operator publishing a finding against their own code is not
		// what gate 18 restricts: research/20 gate 18 is about "findings
		// against code Anvil's operator does not own". The claim removes the
		// EMBARGO and nothing else — see this function's header for the
		// bypass that existed while it removed everything below it.
		return gatePassed(g)
	}

	if !req.Embargo.Constructed() {
		return gateFailed(g, ReasonEmbargoUnconstructed,
			"this is a THIRD-PARTY finding and no embargo was ever opened for it. The "+
				"absence of an embargo is not permission to publish — it is the state a "+
				"finding is in before anybody told the vendor.",
			"repository: "+redactUntrusted(req.Ownership.Repository()))
	}
	if req.Embargo.Finding() != req.Finding {
		return gateFailed(g, ReasonEmbargoFindingMismatch,
			"the embargo supplied is for a different finding. One finding's elapsed "+
				"embargo does not publish another finding, which is exactly how a "+
				"batch publisher would leak the newest report in a set.",
			"requested finding: "+redactUntrusted(string(req.Finding)),
			"embargo finding:   "+redactUntrusted(string(req.Embargo.Finding())))
	}
	if !req.Embargo.Elapsed(run.Now()) {
		return gateFailed(g, ReasonEmbargoRunning,
			"the embargo clock is still running. A third-party finding is not published "+
				"before its deadline, and the only two ways the deadline moves are "+
				"Accelerate (observed active exploitation) and Extend (standards or "+
				"core-OS change), each of which requires an allowlisted reason and "+
				"evidence.",
			"first contact: "+req.Embargo.FirstContact().UTC().Format(time.RFC3339),
			"deadline:      "+req.Embargo.Deadline().UTC().Format(time.RFC3339),
			"run clock:     "+run.Instant().UTC().Format(time.RFC3339),
			fmt.Sprintf("adjustments so far: %d", len(req.Embargo.adjustments)))
	}
	return gatePassed(g)
}

// ===========================================================================
// GATE 19 — disclosure state lives in the record store, not the buffer
// ===========================================================================

// StorageMedium names where a store keeps its bytes.
//
// The check gate 19 makes is an ALLOWLIST OF ONE: only
// MediumRecordStoreSQLite may hold disclosure state. The other two constants
// exist so that the refusal message can name what the caller actually offered
// — a refusal that says "not the record store" is less useful than one that
// says "you offered the tmpfs handoff buffer, which a reboot empties".
//
// The zero value is not a medium, so a store that declares nothing is refused.
type StorageMedium string

// The media. MediumUnset is not one, and only one of the others is permitted.
const (
	// MediumUnset is the zero value: the store did not say.
	MediumUnset StorageMedium = ""
	// MediumRecordStoreSQLite is the SQLite store of record
	// (the spine's corrected-requirements table). It is the only medium gate 19 permits.
	MediumRecordStoreSQLite StorageMedium = "record_store_sqlite"
	// MediumTmpfsHandoffBuffer is the regenerable tmpfs handoff packet. It
	// does not survive a reboot and holds no disclosure state.
	MediumTmpfsHandoffBuffer StorageMedium = "tmpfs_handoff_buffer"
	// MediumProcessMemory is anything that lives only for this process.
	MediumProcessMemory StorageMedium = "process_memory"
)

// DisclosureState is where a finding is in the disclosure process.
//
// # A note for whoever adds this to the record
//
// the first plan's shared-vocabulary review rules that the record area (internal/record)
// owns every shared enum and that no other area may declare one. This enum is
// declared HERE because internal/record has no disclosure column today and
// this packet's write scope is two files in internal/dast/authz. If and when
// `disclosure_state` becomes a column on the record, these literals should
// move to internal/record and this type should alias them. That is a note for
// the orchestrator, not a licence taken.
type DisclosureState string

// The disclosure states. The zero value is not one.
const (
	// DisclosureStateUnset is the zero value: nobody recorded a state.
	DisclosureStateUnset DisclosureState = ""
	// DisclosureStateEmbargoed: the vendor has been contacted and the clock
	// is running.
	DisclosureStateEmbargoed DisclosureState = "embargoed"
	// DisclosureStateEmbargoElapsed: the clock has run out and publication
	// is permissible but has not happened.
	DisclosureStateEmbargoElapsed DisclosureState = "embargo_elapsed"
	// DisclosureStatePublished: the finding has been published.
	DisclosureStatePublished DisclosureState = "published"
	// DisclosureStateWithheld: somebody decided not to publish. An elapsed
	// clock does not overturn this.
	DisclosureStateWithheld DisclosureState = "withheld"
)

// WithholdingReleaseReason is the compiled-in allowlist of reasons a recorded
// `withheld` decision may be REVERSED.
//
// # Why leaving `withheld` needs an allowlist at all
//
// Because until this existed it needed nothing. `withheld` is a decision a
// person made and recorded, and DisclosureStateWithheld's own doc says "an
// elapsed clock does not overturn this" — but a SECOND ROW did, silently.
// Gate 18 read only the PersistedDisclosure the caller handed it, so persisting
// `withheld` and then persisting `embargoed` for the same finding produced a
// second, perfectly valid proof, and publication proceeded. The word "withheld"
// meant "withheld until somebody writes another row", which is advisory.
//
// So the transition out of `withheld` now costs what shortening an embargo
// costs: a reason from a compiled-in list, and evidence. Accelerate and Extend
// established that shape; this is the same shape applied to the other decision
// in this file that a later write could quietly undo.
//
// THESE TWO REASONS ARE ANVIL'S. No external source enumerates them, and this
// file does not pretend otherwise — research/20 gate 18 covers acceleration
// and extension and says nothing about withholding. They are the two cases in
// which continuing to withhold protects nobody: the decision-maker rescinded
// it, or the vendor published first and there is no longer anything to
// withhold. A case nobody enumerated is not a weaker case; it is no case.
type WithholdingReleaseReason string

// The withholding-release reasons. The zero value is not one.
const (
	// WithholdingReleaseUnset is the zero value and releases nothing.
	WithholdingReleaseUnset WithholdingReleaseReason = ""
	// WithholdingReleaseRescinded: whoever recorded the withholding recorded
	// its reversal.
	WithholdingReleaseRescinded WithholdingReleaseReason = "withholding_decision_rescinded"
	// WithholdingReleaseVendorPublished: the vendor published the advisory
	// themselves, so withholding protects nobody.
	WithholdingReleaseVendorPublished WithholdingReleaseReason = "vendor_published_advisory"
)

// Valid reports whether r is one of the two documented release reasons.
func (r WithholdingReleaseReason) Valid() bool {
	return r == WithholdingReleaseRescinded || r == WithholdingReleaseVendorPublished
}

// Valid reports whether s is one of the four recorded states.
func (s DisclosureState) Valid() bool {
	switch s {
	case DisclosureStateEmbargoed, DisclosureStateEmbargoElapsed,
		DisclosureStatePublished, DisclosureStateWithheld:
		return true
	}
	return false
}

// DisclosureRecord is one row of disclosure state, on its way to the SQLite
// record store.
//
// EVERY FIELD IS UNEXPORTED, AND THAT IS THE POINT. `json.Marshal` of a fully
// populated DisclosureRecord produces `{}` — encoding/json cannot read an
// unexported field any more than a composite literal in another package can
// write one — so a handoff-packet builder that embeds one carries no
// disclosure state into tmpfs. See this file's header for what that does and
// does not close.
type DisclosureRecord struct {
	finding      FindingID
	state        DisclosureState
	ownership    FindingOwnership
	repository   string
	firstContact time.Time
	deadline     time.Time
	adjustments  int
	key          AuditKey
	// releaseReason and releaseEvidence are set only by ReleaseWithholding,
	// and gate 19 requires them of a row that moves a finding OUT of
	// `withheld`. They live on the ROW rather than being a parameter of the
	// write so that the record store keeps the reason and the evidence next to
	// the transition they permitted — an audit trail that says a withholding
	// was reversed but not why is the trail that made this defect invisible.
	releaseReason   WithholdingReleaseReason
	releaseEvidence string
	sealed          bool
}

// NewDisclosureRecord builds the row for one finding's disclosure state.
//
// It derives everything it can from the EmbargoState rather than taking it
// again as a parameter, so the row cannot disagree with the embargo it
// describes: a row saying "deadline 2026-09-01" for an embargo whose deadline
// is 2026-10-15 is a row that will be believed and is wrong.
func NewDisclosureRecord(emb EmbargoState, state DisclosureState, key AuditKey) (DisclosureRecord, GateResult) {
	const g = Gate19DisclosureStateInDB
	if !emb.Constructed() {
		return DisclosureRecord{}, gateFailed(g, ReasonEmbargoUnconstructed,
			"there is no embargo to record the state of. A disclosure row minted from a "+
				"zero EmbargoState would carry a 1970 deadline, which reads as elapsed.")
	}
	if !state.Valid() {
		return DisclosureRecord{}, gateFailed(g, ReasonDisclosureStateUnknown,
			"the disclosure state is not one of the four recorded states. The empty "+
				"string in particular is what a struct nobody filled in carries, and "+
				"an empty disclosure state in a database column is indistinguishable "+
				"from a finding nobody has looked at.",
			"state: "+redactUntrusted(string(state)))
	}
	if !key.Valid() {
		return DisclosureRecord{}, gateFailed(g, ReasonDisclosureKeyIncomplete,
			"the disclosure row has no audit key. Gate 21 keys every decision on the "+
				"attestation ID and the scope hash, and a disclosure row that cannot be "+
				"joined back to who authorised the scan is a row nobody can act on.")
	}
	return DisclosureRecord{
		finding:      emb.Finding(),
		state:        state,
		ownership:    emb.Ownership().Owner(),
		repository:   emb.Ownership().Repository(),
		firstContact: emb.FirstContact(),
		deadline:     emb.Deadline(),
		adjustments:  len(emb.adjustments),
		key:          key,
		sealed:       true,
	}, gatePassed(g)
}

// NewOwnFindingDisclosureRecord builds the disclosure row for a finding
// against the OPERATOR'S OWN code, which has no embargo and therefore no
// deadline.
//
// # Why this exists, and why it is not "the same thing without the checks"
//
// Gate 18 requires gate 19's proof before it will publish ANYTHING. That
// requirement used to be reachable only for third-party findings, because the
// only way to a DisclosureRecord was NewDisclosureRecord and the only way to
// an EmbargoState is OpenEmbargo, which refuses an operator-owned finding. The
// consequence was not that operator-owned publications were blocked — it was
// that gate 18 returned a bare allow on the ownership claim before it ever
// looked at persistence, which is the bypass this file's gate-18 header
// records.
//
// So the persistence requirement is universal and this is how the operator's
// own findings meet it. What it does NOT do is take the caller's word for the
// ownership: it requires a classified Ownership that reports OperatorOwned,
// which only ClassifyOwnership against the operator's own declaration
// produces. A third-party finding routed through here is refused, so this is
// not a second door into the record for a finding that owes an embargo.
//
// The row carries a ZERO first contact and a ZERO deadline, which is the
// truth: nobody was contacted because there is nobody to contact.
func NewOwnFindingDisclosureRecord(own Ownership, finding FindingID, state DisclosureState, key AuditKey) (DisclosureRecord, GateResult) {
	const g = Gate19DisclosureStateInDB
	if err := finding.Validate(); err != nil {
		return DisclosureRecord{}, gateFailed(g, ReasonFindingUnidentified,
			"a disclosure row is keyed to a finding, and this one has no valid identifier.",
			"finding: "+redactUntrusted(string(finding)))
	}
	if !own.Classified() {
		return DisclosureRecord{}, gateFailed(g, ReasonOwnershipUnclassified,
			"the finding's repository was never classified against the operator's declared "+
				"list, so nothing here says this is the operator's own code.")
	}
	if !own.OperatorOwned() {
		return DisclosureRecord{}, gateFailed(g, ReasonEmbargoUnconstructed,
			"this row is for a finding against the OPERATOR'S OWN code, and the ownership "+
				"supplied classifies the repository as third-party. A third-party "+
				"finding's disclosure row is built from its EmbargoState by "+
				"NewDisclosureRecord, so that the row cannot record a deadline the "+
				"embargo does not have. Routing one through here would mint a durable "+
				"row with no first contact and no deadline, and gate 18 would then "+
				"have gate 19's proof for a finding nobody told the vendor about.",
			"repository: "+redactUntrusted(own.Repository()))
	}
	if !state.Valid() {
		return DisclosureRecord{}, gateFailed(g, ReasonDisclosureStateUnknown,
			"the disclosure state is not one of the four recorded states.",
			"state: "+redactUntrusted(string(state)))
	}
	if !key.Valid() {
		return DisclosureRecord{}, gateFailed(g, ReasonDisclosureKeyIncomplete,
			"the disclosure row has no audit key. Gate 21 keys every decision on the "+
				"attestation ID and the scope hash.")
	}
	return DisclosureRecord{
		finding:    finding,
		state:      state,
		ownership:  own.Owner(),
		repository: own.Repository(),
		key:        key,
		sealed:     true,
	}, gatePassed(g)
}

// Constructed reports whether this came from NewDisclosureRecord.
func (r DisclosureRecord) Constructed() bool {
	return r.sealed && r.finding.Validate() == nil && r.state.Valid() && r.key.Valid()
}

// Finding returns the finding this row is about.
func (r DisclosureRecord) Finding() FindingID { return r.finding }

// State returns the recorded disclosure state.
func (r DisclosureRecord) State() DisclosureState { return r.state }

// Ownership returns the finding's ownership classification.
func (r DisclosureRecord) Ownership() FindingOwnership { return r.ownership }

// Repository returns the repository the finding is against.
func (r DisclosureRecord) Repository() string { return r.repository }

// FirstContact returns when the embargo clock started.
func (r DisclosureRecord) FirstContact() time.Time { return r.firstContact }

// Deadline returns when publication becomes permissible.
func (r DisclosureRecord) Deadline() time.Time { return r.deadline }

// Adjustments returns how many times the deadline was moved.
func (r DisclosureRecord) Adjustments() int { return r.adjustments }

// ReleaseReason returns the allowlisted reason this row carries for moving a
// finding out of `withheld`, or WithholdingReleaseUnset if it carries none.
func (r DisclosureRecord) ReleaseReason() WithholdingReleaseReason { return r.releaseReason }

// ReleaseEvidence returns the bounded evidence attached to that release.
func (r DisclosureRecord) ReleaseEvidence() string { return r.releaseEvidence }

// ReleaseWithholding attaches the allowlisted reason and the evidence that
// permit this row to move a finding OUT of a recorded `withheld` state.
//
// It returns a NEW DisclosureRecord rather than mutating the receiver, the
// same shape Accelerate and Extend use, so a caller holding the old row holds
// a row that still cannot overturn a withholding.
//
// It refuses a release attached to a row that is not leaving `withheld` — a
// row whose own state IS `withheld` is entering the state, not leaving it, and
// a reason token recorded next to a transition that did not happen is a lie
// the record store will be believed about.
//
// gate 19's persist path is what enforces the requirement; this only mints the
// permission. Nothing here writes anything.
func (r DisclosureRecord) ReleaseWithholding(reason WithholdingReleaseReason, evidence string) (DisclosureRecord, GateResult) {
	const g = Gate19DisclosureStateInDB
	if !r.Constructed() {
		return DisclosureRecord{}, gateFailed(g, ReasonDisclosureRecordUnconstructed,
			"ReleaseWithholding was called on a DisclosureRecord that neither "+
				"NewDisclosureRecord nor NewOwnFindingDisclosureRecord built. There is no "+
				"row to attach a release to, and returning a constructed one here would "+
				"mint a disclosure row out of a zero value.")
	}
	if r.state == DisclosureStateWithheld {
		return DisclosureRecord{}, gateFailed(g, ReasonDisclosureReleaseNotApplicable,
			"this row records the state `withheld`, so it ENTERS the withholding rather "+
				"than leaving it, and there is nothing for a release to permit. A "+
				"release recorded against a transition that did not happen is a reason "+
				"token the record store will be believed about.",
			"row state: "+string(r.state))
	}
	if !reason.Valid() {
		return DisclosureRecord{}, gateFailed(g, ReasonDisclosureReleaseUnsupported,
			"the reason supplied is not one of the two documented cases in which "+
				"continuing to withhold protects nobody. An undocumented reason does not "+
				"reverse a recorded decision — including the empty reason a caller that "+
				"forgot the argument supplies.",
			"reason: "+redactUntrusted(string(reason)),
			"the allowlist: "+string(WithholdingReleaseRescinded)+", "+
				string(WithholdingReleaseVendorPublished))
	}
	ev, err := boundedEvidence(evidence)
	if err != nil {
		return DisclosureRecord{}, gateFailed(g, ReasonDisclosureReleaseUnevidenced,
			"releasing a withholding requires evidence, and this one carries none the "+
				"record store can hold. Reversing a decision somebody made and recorded, "+
				"with nothing attached, is the config key gate 18 does not have.",
			"evidence: "+err.Error())
	}
	next := r
	next.releaseReason = reason
	next.releaseEvidence = ev
	return next, gatePassed(g)
}

// Key returns the audit key this row is joined on.
func (r DisclosureRecord) Key() AuditKey { return r.key }

// AttestationID returns the first half of the audit key.
func (r DisclosureRecord) AttestationID() AttestationID { return r.key.AttestationID() }

// ScopeHash returns the second half.
func (r DisclosureRecord) ScopeHash() ScopeHash { return r.key.ScopeHash() }

// DisclosureStore is the durable writer gate 19 requires.
//
// # NOTHING IMPLEMENTS THIS INTERFACE
//
// This comment used to say "The kernel's build-time guard and target
// provisioning implement it over the SQLite record store". That was false.
// plan/design/dynamic-tier.md:317-348 makes the kernel's build-time guard the
// build-invariant packet (a dependency-graph test and an egress lint) and
// :349-378 makes target provisioning run containers under gVisor. Neither
// writes a disclosure row, and no other plan step schedules one. A
// repository-wide grep for PutDisclosureState finds this interface, its one
// call site below, and a test fake — no production implementation.
//
// So gate 19 is a rule with nothing standing behind it today: it says
// disclosure state lives in the SQLite store of record rather than the tmpfs
// handoff buffer, and in this tree disclosure state lives NOWHERE. Every
// refusal in this section is real and tested; the ALLOW has never been taken
// by a caller that actually persisted anything. Recorded in
// docs/controls.md as G19-1, with what would settle it.
//
// # The residual the declaration leaves even once one exists
//
// Medium is a declaration, and this package cannot verify it: a kernel that
// imports no store cannot inspect a store's files. The residual risk is
// therefore real and is stated rather than papered over — a store that
// declares MediumRecordStoreSQLite while writing to tmpfs defeats gate 19.
// What the declaration buys is that the honest implementation is the easy one,
// that the dishonest one is a visible lie in a diff, and that the ACCIDENT —
// somebody passing the handoff buffer because it was the store in scope — is
// refused.
// # WHY THERE IS A READ METHOD HERE AND WHAT IT COST TO NOT HAVE ONE
//
// This interface used to be write-only, and a write-only store cannot back a
// state machine. Gate 18's `withheld` check read only the PersistedDisclosure
// its CALLER handed it, and persistDisclosureState imposed no ordering on the
// rows it wrote, so the following sequence published a finding somebody had
// recorded a decision not to publish — measured against the shipped tree with
// one store shared by both writes:
//
//	AuditedPersistDisclosure(store, rec{state: withheld})   passed=true
//	AuditedPersistDisclosure(store, rec{state: embargoed})  passed=true
//	AuditedPublication(store, req{Persisted: the second proof})  passed=true
//
// Nothing lied. Every value was sealed, every gate was audited, and the second
// row simply out-voted the first because no gate could see the first. A GATE
// THAT CAN ONLY SEE WHAT THE CALLER HANDS IT CANNOT ENFORCE A STATE MACHINE.
//
// So the store answers one question about what it already holds, gate 18 asks
// it before publishing, and gate 19 asks it before writing. This is still an
// INTERFACE and this package still cannot verify the answer — the residual is
// the same one Medium() has and is stated in the same place — but the accident
// is now refused and the deliberate act is a store that lies about its own
// rows, which is a visible thing in a diff rather than an absent check.
type DisclosureStore interface {
	// Medium says where this store keeps bytes.
	Medium() StorageMedium
	// PutDisclosureState durably writes one row and returns its sequence
	// number. Returning (0, nil) is treated as a failed write, for the
	// reason AuditSeq gives.
	PutDisclosureState(DisclosureRecord) (AuditSeq, error)
	// DisclosureStateFor returns the state the store ALREADY HOLDS for this
	// finding — the most recent row written for it — or
	// DisclosureStateUnset if it holds no row at all.
	//
	// DisclosureStateUnset is not an error and an error is not
	// DisclosureStateUnset: "this finding has no disclosure row" and "I could
	// not tell you whether it has one" are different facts and both gates
	// refuse on both, but for different stated reasons. A store that cannot
	// distinguish them should return the error.
	DisclosureStateFor(FindingID) (DisclosureState, error)
}

// checkGate19DisclosureStore is gate 19's location check: is this store the
// record store.
func checkGate19DisclosureStore(store DisclosureStore) GateResult {
	const g = Gate19DisclosureStateInDB
	if store == nil {
		return gateFailed(g, ReasonDisclosureStoreMissing,
			"no disclosure store was supplied. Disclosure state that is not written "+
				"anywhere is disclosure state that will not be found by the run after "+
				"the reboot, and a finding whose embargo cannot be found is a finding "+
				"nothing is stopping.")
	}
	return checkDisclosureMedium(store.Medium())
}

// checkDisclosureMedium is gate 19's allowlist-of-one, taking the medium as a
// VALUE rather than the store it came from.
//
// The split exists so that persistDisclosureState can read Medium() EXACTLY
// ONCE. It used to read it twice — once through the location check and once to
// stamp the proof — and a store that answered `record_store_sqlite` and then
// `tmpfs_handoff_buffer` returned a PASSING gate result paired with a
// PersistedDisclosure whose Valid() is false. A gate that says yes while
// handing back a proof that says no is worse than either answer on its own,
// because the caller checks one of them.
// TestGate19ReadsTheStoresMediumExactlyOnce is the guard.
func checkDisclosureMedium(medium StorageMedium) GateResult {
	const g = Gate19DisclosureStateInDB
	if medium == MediumRecordStoreSQLite {
		return gatePassed(g)
	}
	detail := "disclosure state may live only in the SQLite store of record " +
		"(the spine's corrected-requirements table, gate 19). "
	switch medium {
	case MediumTmpfsHandoffBuffer:
		detail += "The store offered is the tmpfs handoff buffer. The spine's corrected-requirements table is explicit that " +
			"the buffer's \"8 hours\" is a CLAIM TIMEOUT, not a deletion policy and " +
			"not a confidentiality control, and tmpfs does not survive a reboot at " +
			"all. A 45-day embargo cannot be held in an 8-hour buffer."
	case MediumProcessMemory:
		detail += "The store offered keeps state only for this process, so the embargo " +
			"ends when the process does."
	case MediumUnset:
		detail += "The store declared no medium. A store that will not say where it " +
			"writes is not a store gate 19 will write an embargo to."
	default:
		detail += "The store declared a medium that is not on the allowlist. The " +
			"allowlist has one entry on purpose."
	}
	return gateFailed(g, ReasonDisclosureStoreWrongMedium, detail,
		"declared medium: "+redactUntrusted(string(medium)),
		"the allowlist:   "+string(MediumRecordStoreSQLite))
}

// PersistedDisclosure is the unforgeable proof that a finding's disclosure
// state reached the record store.
//
// It is the same idiom as kernel.go's grant: unexported fields, minted in
// exactly one place, and a zero value that proves nothing. Gate 18 requires
// one before it will permit publication, so "the embargo was only ever in
// memory" is a refusal rather than an oversight.
type PersistedDisclosure struct {
	finding FindingID
	state   DisclosureState
	medium  StorageMedium
	seq     AuditSeq
	key     AuditKey
	sealed  bool
}

// Valid reports whether this proof is real. False for the zero value.
func (p PersistedDisclosure) Valid() bool {
	return p.sealed && p.seq > 0 && p.medium == MediumRecordStoreSQLite &&
		p.state.Valid() && p.finding.Validate() == nil && p.key.Valid()
}

// Finding returns the finding whose state was persisted.
func (p PersistedDisclosure) Finding() FindingID { return p.finding }

// State returns the state that was persisted.
func (p PersistedDisclosure) State() DisclosureState { return p.state }

// Medium returns the medium it was persisted to.
func (p PersistedDisclosure) Medium() StorageMedium { return p.medium }

// Seq returns the store's row sequence number.
func (p PersistedDisclosure) Seq() AuditSeq { return p.seq }

// Key returns the audit key the row is joined on.
func (p PersistedDisclosure) Key() AuditKey { return p.key }

// disclosureDecision is what gate 19 concluded about a row BEFORE anything
// durable happened — the two facts the apply half needs and must not re-derive
// by asking the store a second question.
//
// medium is read once, for the reason checkDisclosureMedium's header gives.
// prior is the state the store held at the moment the decision was made, and
// the apply half checks that it has not moved since.
type disclosureDecision struct {
	medium StorageMedium
	prior  DisclosureState
}

// decideDisclosurePersist is gate 19's DECISION half: every check, and no
// durable write.
//
// # WHY THE DECISION AND THE WRITE ARE TWO FUNCTIONS
//
// Because AuditedPersistDisclosure has to put gate 21's audit row BETWEEN
// them. It used to run the whole of persistDisclosureState and audit
// afterwards, and an audit sink that failed — a full disk, a locked table, no
// malice required — then left the disclosure state transition PERMANENTLY
// APPLIED with zero audit rows behind it. Applied to a withholding release
// that consumed the withheld-survives-a-second-row control outright: the store
// stopped saying `withheld`, so the next persist carrying no release reason
// and no evidence was permitted, and publication cleared. See
// AuditedPersistDisclosure's header for the measured sequence.
func decideDisclosurePersist(store DisclosureStore, rec DisclosureRecord) (disclosureDecision, GateResult) {
	const g = Gate19DisclosureStateInDB
	if !rec.Constructed() {
		return disclosureDecision{}, gateFailed(g, ReasonDisclosureRecordUnconstructed,
			"the disclosure row was not built by NewDisclosureRecord, so it carries no "+
				"finding, no state and no audit key. Writing it would put a row in the "+
				"record store that says nothing and reads as \"looked at, nothing "+
				"embargoed\".")
	}
	if store == nil {
		return disclosureDecision{}, checkGate19DisclosureStore(nil)
	}
	// READ THE MEDIUM ONCE. The value checked here and the value stamped into
	// the proof by the apply half must be the same value, not two answers to one
	// question. It is carried in disclosureDecision rather than re-read for
	// exactly that reason.
	medium := store.Medium()
	if res := checkDisclosureMedium(medium); !res.Passed() {
		return disclosureDecision{}, res
	}

	// ---- THE STATE MACHINE, which gate 19 used not to have ----
	//
	// Without it, "persist withheld, then persist embargoed" was two
	// successful writes and the second one won. Every value was sealed and
	// every write was audited; the rule "an elapsed clock does not overturn a
	// withholding" simply had no enforcement point, because nothing read the
	// row that was already there.
	prior, rerr := store.DisclosureStateFor(rec.Finding())
	switch {
	case rerr != nil:
		return disclosureDecision{}, gateFailed(g, ReasonDisclosureReadFailed,
			"the state this finding is already in could not be read, so this write cannot "+
				"be checked against it. A write that cannot see the row it is replacing "+
				"is how a recorded `withheld` becomes advisory.",
			"store error: "+rerr.Error())
	case prior == DisclosureStateWithheld && rec.State() != DisclosureStateWithheld &&
		rec.releaseReason == WithholdingReleaseUnset:
		return disclosureDecision{}, gateFailed(g, ReasonDisclosureWithholdingHeld,
			"this finding's recorded state is `withheld` and this row moves it out of "+
				"that state, carrying no allowlisted release reason and no evidence. "+
				"Shortening an embargo takes both; reversing a decision not to publish "+
				"at all takes no less. Attach one with "+
				"DisclosureRecord.ReleaseWithholding.",
			"recorded state: "+string(prior),
			"row would write: "+string(rec.State()))
	case prior != DisclosureStateWithheld && rec.releaseReason != WithholdingReleaseUnset:
		return disclosureDecision{}, gateFailed(g, ReasonDisclosureReleaseNotApplicable,
			"this row carries a withholding release, and the state it would replace is not "+
				"`withheld`, so there is nothing to release. The release is refused "+
				"rather than ignored: an unused reason token written next to a "+
				"transition that did not happen is a row a reviewer will believe.",
			"recorded state: "+redactUntrusted(string(prior)),
			"release reason: "+string(rec.releaseReason))
	}

	return disclosureDecision{medium: medium, prior: prior}, gatePassed(g)
}

// applyDisclosureState is gate 19's APPLY half: the durable write, and the
// minting of the proof, against a decision that has already been made and —
// on the audited route — already recorded.
//
// # THE RE-READ IS NOT BELT AND BRACES
//
// Splitting the decision from the write puts gate 21's audit row between them,
// and that widens the window between "the store said `withheld`" and "the
// store is written". So the apply half asks once more and REFUSES if the
// answer moved. This NARROWS the window; it does not close it, and saying
// otherwise would be a claim this package cannot demonstrate — DisclosureStore
// offers no compare-and-set, so two writers can still interleave between this
// read and the PutDisclosureState below. What it does buy is that the ordinary
// case — the audit write taking time while another writer lands a row — is
// refused rather than silently overwriting a decision that was made against a
// state that no longer exists. Closing it takes a conditional write —
// PutDisclosureState taking the state it expects to replace — on an interface
// that G19-1 already records as having no implementation in this tree.
// TestApplyRefusesAWriteWhoseStateMovedUnderIt is the guard on the half that
// does exist.
func applyDisclosureState(store DisclosureStore, rec DisclosureRecord, d disclosureDecision) (PersistedDisclosure, GateResult) {
	const g = Gate19DisclosureStateInDB
	switch now, rerr := store.DisclosureStateFor(rec.Finding()); {
	case rerr != nil:
		return PersistedDisclosure{}, gateFailed(g, ReasonDisclosureReadFailed,
			"the state this finding is in could not be re-read immediately before the "+
				"write, so the decision that authorised this write cannot be confirmed "+
				"to still apply.",
			"store error: "+rerr.Error())
	case now != d.prior:
		return PersistedDisclosure{}, gateFailed(g, ReasonDisclosureStateMovedUnderWrite,
			"this finding's recorded state changed between the check and the write, so "+
				"the decision that authorised this write was made against a state the "+
				"store no longer holds. The write is refused rather than applied: "+
				"re-read the state and decide again.",
			"state at the check: "+redactUntrusted(string(d.prior)),
			"state now:          "+redactUntrusted(string(now)))
	}

	seq, err := store.PutDisclosureState(rec)
	switch {
	case err != nil:
		return PersistedDisclosure{}, gateFailed(g, ReasonDisclosureWriteFailed,
			"the disclosure state write failed, so nothing durable records this finding's "+
				"embargo. The failure is returned rather than logged: a caller that "+
				"believes the state was written will publish on the deadline it thinks "+
				"is stored.",
			"store error: "+err.Error())
	case seq == 0:
		return PersistedDisclosure{}, gateFailed(g, ReasonDisclosureWriteFailed,
			"the disclosure store returned sequence 0 with no error, which is what a stub "+
				"or a short-circuited implementation returns. A row that was not "+
				"written cannot make an embargo durable.")
	}
	return PersistedDisclosure{
		finding: rec.Finding(),
		state:   rec.State(),
		medium:  d.medium,
		seq:     seq,
		key:     rec.Key(),
		sealed:  true,
	}, gatePassed(g)
}

// persistDisclosureState is the two halves run back to back, with nothing
// between them.
//
// It is what an UNAUDITED caller gets, and in this tree that is tests only:
// AuditedPersistDisclosure is the sole production route and it deliberately
// does NOT call this, because the whole point of the split is what it puts
// between the halves.
func persistDisclosureState(store DisclosureStore, rec DisclosureRecord) (PersistedDisclosure, GateResult) {
	d, res := decideDisclosurePersist(store, rec)
	if !res.Passed() {
		return PersistedDisclosure{}, res
	}
	return applyDisclosureState(store, rec, d)
}

// ===========================================================================
// GATE 20 — no unsolicited fixes pushed to third parties
// ===========================================================================

// PatchProposal identifies a patch WITHOUT containing it.
//
// # The content is not an input to the decision
//
// research/20 gate 20: "The coding agent may generate a patch, but delivering
// it to a repository Anvil's operator does not control requires the same
// affirmative attestation as probing, plus vendor contact through the channel
// discovered in gate 12." Nothing in that sentence is about what the patch
// says. So gate 20 never reads patch content, and this type carries only a
// digest and a size — enough for the audit row to name what was almost
// delivered, and not enough for a "but the patch is harmless" argument to
// exist in the code.
//
// A benign patch with no attestation is refused, and
// TestPushGateRefusesABenignPatchWithoutAnAttestation is the guard.
type PatchProposal struct {
	digest string
	bytes  int
	sealed bool
}

// NewPatchProposal identifies a patch by its SHA-256 and its size.
//
// It does not hash anything: hashing the patch is the caller's job, and a
// kernel that took patch bytes would be a kernel that could be asked to look
// at them.
func NewPatchProposal(sha256Hex string, sizeBytes int) (PatchProposal, error) {
	if err := validateSHA256Hex(sha256Hex, "patch digest"); err != nil {
		return PatchProposal{}, err
	}
	if sizeBytes <= 0 {
		return PatchProposal{}, fmt.Errorf("patch: %w: a patch of %d bytes is not a patch; "+
			"gate 20's audit row names what was almost delivered and cannot name nothing",
			ErrRefused, sizeBytes)
	}
	return PatchProposal{digest: sha256Hex, bytes: sizeBytes, sealed: true}, nil
}

// Constructed reports whether this came from NewPatchProposal.
func (p PatchProposal) Constructed() bool {
	return p.sealed && validateSHA256Hex(p.digest, "patch digest") == nil && p.bytes > 0
}

// Digest returns the patch's SHA-256, lowercase hex.
func (p PatchProposal) Digest() string { return p.digest }

// Bytes returns the patch's size.
func (p PatchProposal) Bytes() int { return p.bytes }

// PushRequest is everything gate 20 needs to decide whether a patch may be
// delivered.
//
// Destination is the DESTINATION repository's classified ownership, which is
// not necessarily the finding's: a patch for a finding in our own code might
// still be pushed somewhere else, and it is the destination that decides
// whether this is a fix to a stranger.
type PushRequest struct {
	// Finding is the finding the patch addresses.
	Finding FindingID
	// Destination is the classified ownership of the repository the patch
	// would be pushed to.
	Destination Ownership
	// Attestation is the run's attestation — gate 20 requires "the same
	// affirmative attestation as probing".
	Attestation Attestation
	// Scope is the run's scope, which the attestation must be bound to.
	Scope Scope
	// Embargo carries the vendor contact recorded through gate 12's
	// reporting channel. There is no separate contact field: OpenEmbargo
	// cannot produce an EmbargoState without a resolved channel, so holding
	// one IS holding the contact.
	Embargo EmbargoState
	// Patch identifies the patch. Its content is never read.
	Patch PatchProposal
}

// pushGate is gate 20: no unsolicited fixes pushed to third parties.
//
// It is unexported for the reason checkGate18Publication is: gate 21 makes the
// audit write part of the decision, and an exported function that returns an
// allow having written no row makes that optional. AuditedPush is the entry
// point.
//
// # What it requires of EVERY delivery, and what only a third-party one adds
//
// Of every delivery, in order: an identified patch, a classified destination,
// a valid clock, a constructed scope, and an attestation that is constructed,
// bound to that scope and LIVE at this instant.
//
// A THIRD-PARTY destination adds an embargo for THIS finding — which is how
// the gate-12 reporting channel and the recorded vendor contact become
// preconditions, since OpenEmbargo refuses without both.
//
// The split is deliberate and it is the answer to a real bypass. See the
// operator-owned branch below.
//
// It does NOT require the embargo to have ELAPSED. Delivering a patch to the
// vendor is the coordinated part of coordinated disclosure; requiring the
// embargo to run out first would forbid the exact thing the embargo exists to
// make room for. Gate 18 is what stands between a finding and the public;
// gate 20 stands between a patch and a stranger's repository, and they are not
// the same question.
//
// It also does not restrict WHICH of gate 5's four authorities is acceptable.
// The requirement is parity with probing — "the same affirmative attestation"
// — and a stricter rule here would be this file inventing disclosure policy
// that no source in the plan states.
func pushGate(req PushRequest, run RunClock) GateResult {
	const g = Gate20NoUnsolicitedFixes

	if !req.Patch.Constructed() {
		return gateFailed(g, ReasonPushPatchUnidentified,
			"the patch was not identified by NewPatchProposal, so gate 20's audit row could "+
				"not name what was delivered. A delivery nobody can identify afterwards "+
				"is refused before it happens.")
	}
	if !req.Destination.Classified() {
		return gateFailed(g, ReasonPushOwnershipUnclassified,
			"the destination repository was never classified against the operator's "+
				"declared list, so gate 20 cannot say whether this is our own repo or "+
				"somebody else's. Unclassified is refused, not assumed to be ours.")
	}
	if !run.Valid() {
		return gateFailed(g, ReasonPushClockUnconstructed,
			"the push was proposed outside any initiated run: the RunClock is the zero "+
				"value, so the attestation's liveness could not be measured against "+
				"anything.")
	}

	if !req.Scope.Constructed() {
		return gateFailed(g, ReasonPushScopeUnconstructed,
			"there is no constructed Scope, so there is nothing for the attestation to be "+
				"bound to and no way to tell whether the operator's authorisation "+
				"covers this engagement at all.",
			"destination: "+redactUntrusted(req.Destination.Repository()))
	}
	if !req.Attestation.Constructed() {
		return gateFailed(g, ReasonPushWithoutAttestation,
			"delivering a patch requires THE SAME affirmative attestation as probing "+
				"(research/20 gate 20), and no attestation was supplied. The patch's "+
				"content is not a factor: a benign unsolicited fix to a stranger's "+
				"repository is still an unsolicited fix. An operator-owned destination "+
				"does not remove this requirement — \"we own it\" is a claim made by "+
				"putting an \"owner/name\" string in OwnedRepositories, and a claim "+
				"nothing can verify may not also be the thing that deletes the "+
				"authorisation check.",
			"destination: "+redactUntrusted(req.Destination.Repository()),
			"patch:       "+req.Patch.Digest())
	}
	if !req.Attestation.CoversScope(req.Scope) {
		return gateFailed(g, ReasonPushAttestationScopeUnbound,
			"the attestation is bound to a different scope hash than this run's scope. "+
				"Gate 5 binds an attestation to the scope hash so that editing scope "+
				"invalidates it, and a patch delivery authorised by an attestation for "+
				"some other engagement is not authorised.",
			"attestation scope: "+string(req.Attestation.ScopeHash()),
			"run scope:         "+string(req.Scope.Hash()))
	}
	if !req.Attestation.Live(run.Now()) {
		return gateFailed(g, ReasonPushAttestationNotLive,
			"the attestation is expired or not yet valid at this instant. An expired "+
				"authorisation authorises nothing, and a patch delivered under one is "+
				"as unsolicited as a patch delivered under none.",
			"attestation: "+redactUntrusted(string(req.Attestation.ID())),
			"run clock:   "+run.Instant().UTC().Format(time.RFC3339))
	}

	if req.Destination.OperatorOwned() {
		// Pushing to a repository the operator declared they own is not an
		// unsolicited fix to a third party. research/20 gate 20 is about "a
		// repository Anvil's operator does not control".
		//
		// WHAT THIS BRANCH MAY SKIP, AND WHAT IT MAY NOT. Ownership is a
		// SELF-ASSERTION. ClassifyOwnership compares the repository against
		// OwnedRepositories, which is a list of "owner/name" strings the
		// caller supplied, and nothing in this package can check that list
		// against a forge. While this branch sat ABOVE the scope and
		// attestation checks, NewOwnedRepositories("vendor/product") was
		// enough to push a patch to vendor/product with a ZERO Attestation, a
		// ZERO Scope and a ZERO EmbargoState — the gate that exists to stop
		// unsolicited patches reaching third parties, bypassed by asserting
		// that the third party is you.
		//
		// So the claim now removes only what it is actually about: the
		// EMBARGO and the vendor contact, which are meaningless for your own
		// repository. It does not remove the run's authorisation. A false
		// ownership claim costs a live attestation bound to this run's scope,
		// and either way the destination is named in the audit row gate 21
		// writes.
		return gatePassed(g)
	}

	if !req.Embargo.Constructed() {
		return gateFailed(g, ReasonPushNoEmbargoOpened,
			"no embargo was opened for this finding, and an embargo is what records that "+
				"the vendor was contacted through gate 12's resolved reporting channel. "+
				"Without one, this delivery is a patch arriving at a stranger's "+
				"repository from somebody who never wrote to them — which is the "+
				"definition of unsolicited.",
			"finding: "+redactUntrusted(string(req.Finding)))
	}
	if req.Embargo.Finding() != req.Finding {
		return gateFailed(g, ReasonPushFindingMismatch,
			"the embargo supplied is for a different finding, so nothing records that this "+
				"finding's vendor was ever contacted.",
			"requested finding: "+redactUntrusted(string(req.Finding)),
			"embargo finding:   "+redactUntrusted(string(req.Embargo.Finding())))
	}
	return gatePassed(g)
}

// ===========================================================================
// GATE 21 — the immutable audit of every gate decision
// ===========================================================================

// AuditKey is gate 21's join key: an attestation ID and a scope hash, minted
// together and only from an attestation that is actually bound to that scope.
//
// plan/design/dynamic-tier.md gate 21: every decision is "keyed to attestation ID + scope
// hash". Building the key from the two values SEPARATELY would let a row be
// keyed to an attestation that does not cover the scope it names — a row that
// joins, reads as authoritative, and records nothing true. NewAuditKey refuses
// that pairing.
type AuditKey struct {
	attestation AttestationID
	scopeHash   ScopeHash
	mode        Mode
	sealed      bool
}

// NewAuditKey mints the key for a run.
func NewAuditKey(att Attestation, scope Scope) (AuditKey, GateResult) {
	const g = Gate21ImmutableAudit
	if !att.Constructed() {
		return AuditKey{}, gateFailed(g, ReasonAttestationUnconstructed,
			"the audit key needs an attestation ID and this Attestation was never built by "+
				"NewAttestation, so it has none.")
	}
	if !scope.Constructed() {
		return AuditKey{}, gateFailed(g, ReasonScopeUnconstructed,
			"the audit key needs a scope hash and this Scope was never built by NewScope, "+
				"so it has none.")
	}
	if !att.CoversScope(scope) {
		return AuditKey{}, gateFailed(g, ReasonScopeAttestationMismatch,
			"the attestation is bound to a different scope hash than this scope. A row "+
				"keyed to an attestation that does not cover the scope it names joins "+
				"cleanly and records nothing true, which is worse than not joining.",
			"attestation scope: "+string(att.ScopeHash()),
			"scope:             "+string(scope.Hash()))
	}
	mode, err := scope.Mode()
	if err != nil || !mode.Valid() {
		return AuditKey{}, gateFailed(g, ReasonAuditKeyIncomplete,
			"the scope declares no valid mode, and gate 6 has no default and no `auto`. "+
				"Every audit row carries the run's mode, and a row that cannot say "+
				"whether the run was lab or external cannot be read.")
	}
	return AuditKey{
		attestation: att.ID(),
		scopeHash:   scope.Hash(),
		mode:        mode,
		sealed:      true,
	}, gatePassed(g)
}

// Valid reports whether the key is real. False for the zero value.
func (k AuditKey) Valid() bool {
	return k.sealed && k.attestation.Validate() == nil && k.scopeHash.Validate() == nil
}

// AttestationID returns the first half of the key.
func (k AuditKey) AttestationID() AttestationID { return k.attestation }

// ScopeHash returns the second half.
func (k AuditKey) ScopeHash() ScopeHash { return k.scopeHash }

// Mode returns the run's mode, which every row carries.
func (k AuditKey) Mode() Mode { return k.mode }

// AuditSubject is the WHAT of an audit row: the target, finding or repository
// a decision was about.
//
// It is a sealed type rather than a string parameter because GateRecord.Detail
// and GateRecord.Target both end up in a log an agent may later read, and
// the spine's safety section makes the DAST response body "the highest-risk field —
// up to 32 KB of attacker-controlled bytes fed to a repo-credentialed agent".
// Every constructor below builds its text from ALREADY-VALIDATED components —
// a canonical host, a pinned address, an allowlisted finding ID, an
// "owner/name" that parsed — so no free text ever reaches a row and no
// redaction pass is needed to make one safe.
type AuditSubject struct {
	text   string
	sealed bool
}

// SubjectTarget names a target. It cannot fail: Target.String already renders
// an unconstructed Target as "<unconstructed target>", which is an
// Anvil-authored constant and is exactly what the row should say.
func SubjectTarget(t Target) AuditSubject {
	return AuditSubject{text: t.String(), sealed: true}
}

// SubjectFinding names a finding.
func SubjectFinding(f FindingID) (AuditSubject, error) {
	if err := f.Validate(); err != nil {
		return AuditSubject{}, fmt.Errorf("audit subject: %w", err)
	}
	return AuditSubject{text: "finding " + string(f), sealed: true}, nil
}

// SubjectRepository names a repository.
func SubjectRepository(repo string) (AuditSubject, error) {
	if err := validateRepositoryName(repo, "audit subject repository"); err != nil {
		return AuditSubject{}, fmt.Errorf("audit subject: %w", err)
	}
	return AuditSubject{text: "repository " + repo, sealed: true}, nil
}

// subjectUnidentified is the fallback for a decision whose subject did not
// validate.
//
// A decision about something unnameable is still a decision, and gate 21 wants
// it recorded. What it must not do is put the unnameable bytes in the row, so
// the row says so instead. The text is a compiled-in constant.
func subjectUnidentified(kind string) AuditSubject {
	return AuditSubject{text: "<unidentified " + kind + ">", sealed: true}
}

// Constructed reports whether the subject came from a constructor here.
func (s AuditSubject) Constructed() bool { return s.sealed && s.text != "" }

// String renders the subject for the row.
func (s AuditSubject) String() string {
	if !s.Constructed() {
		return ""
	}
	return s.text
}

// phase4PassReasons is the audit token each Phase 4 gate carries on an ALLOW.
//
// gatePassed does not take a Reason — the kernel core's GateResult has no field for one —
// so without this map a Phase 4 allow row would reach GateRecord.Validate with
// an empty reason and be refused. The same problem, and the same solution, as
// per-request enforcement's phase3PassReasons.
//
// Each token is deliberately NEUTRAL about which branch permitted. Gate 18
// permits both an operator-owned finding and a third-party finding whose clock
// ran out; a token naming one of those would put a false statement in the row
// for the other. (Gate 10 has the same two-meanings shape and has two distinct
// tokens on its Ruling path, which is why gate 10 is deliberately absent here:
// see auditReasonFor.)
var phase4PassReasons = map[GateID]Reason{
	Gate18Embargo:             ReasonPublicationPermitted,
	Gate19DisclosureStateInDB: ReasonDisclosurePersisted,
	Gate20NoUnsolicitedFixes:  ReasonPushPermitted,
	Gate21ImmutableAudit:      ReasonAuditRowWritten,
}

// phase1PassReasons is the audit token for a PASSING GateResult from a Phase 1
// Check function.
//
// Run initiation's CheckGate4/5/6 return gatePassed with no token, and run initiation already
// declares a pass Reason for each on the Ruling path; this maps the gate to
// the token run initiation wrote, so no token is invented here. Gate 7's is the one
// exception and is declared at the top of this file, with the reason.
//
// GATES 8, 9, 10 AND 11 ARE ABSENT ON PURPOSE. Gate 10 has TWO pass tokens
// with different meanings — "the address is not in a reserved range" and "the
// reserved address is enumerated in lab scope" — and a single map entry would
// record one of them as the other, which is a false audit row. Gate 11's pass
// token is per-request enforcement's and is already in phase3PassReasons, which auditReasonFor
// falls through to. Gates 8 and 9 are left out with 10 rather than half the
// Phase 2 chain being recordable: their passing GateResults reach the audit
// through Adjudicate's Ruling path, which carries a real reason.
var phase1PassReasons = map[GateID]Reason{
	Gate4ScopeFile:         ReasonScopePermitsTarget,
	Gate5Attestation:       ReasonAttestationLiveAndBound,
	Gate6ModeDeclaration:   ReasonModeDeclaredForRun,
	Gate7TriggerProvenance: ReasonTriggerProvenanceVerified,
}

// auditReasonFor returns the gate-numbered token that belongs on a result's
// audit row, for any phase.
//
// A REFUSAL always carries its own token, so every phase's denials are
// recordable. A PASS needs a map entry, and a pass whose gate has none is
// REFUSED rather than given an invented token: gate 21 requires the row to be
// attributable, and a row whose reason was made up to fill the field is worse
// than no row because it will be believed.
func auditReasonFor(r GateResult) (Reason, error) {
	if r.Passed() {
		if reason, ok := phase4PassReasons[r.Gate()]; ok {
			return reason, nil
		}
		if reason, ok := phase1PassReasons[r.Gate()]; ok {
			return reason, nil
		}
	}
	// per-request enforcement's AuditReason handles every refusal and the Phase 3 pass tokens.
	return AuditReason(r)
}

// GateAudit is gate 21's append-only writer, keyed to one run's attestation ID
// and scope hash.
//
// # What "append-only" means here, and how it is checked
//
// Not "the sink promises". The sink returns a sequence number for every row it
// writes, and this type refuses any sequence that does not ADVANCE. A sink
// that returns 0 did not write; a sink that returns a number it has returned
// before, or a lower one, either rewound the log or overwrote a row, and
// either way the decision that row was paired with is NOT ALLOWED. That is the
// same coupling Adjudicate applies to the admission decision, applied to the
// per-request and per-disclosure decisions Adjudicate never sees.
type GateAudit struct {
	mu      sync.Mutex
	sink    AuditSink
	key     AuditKey
	run     RunClock
	lastSeq AuditSeq
	rows    int
	sealed  bool
}

// NewGateAudit binds a sink to a run's audit key AND to THE RUN'S CLOCK.
//
// The clock is here rather than on each request for the reason types.go's
// RunClock gives: the Phase 4 disclosure decisions are comparisons between
// instants, and while each instant was its own parameter a caller could supply
// a consistent set of lies that no comparison between two of them caught.
// AuditedPublication and AuditedPush read this field; neither takes a clock,
// and PublicationRequest and PushRequest have no clock field to set.
//
// A RunClock cannot be minted outside this package — RunInitiation.RunClock is
// the only exported route — so binding one here binds the writer to a run that
// actually passed Phase 1.
func NewGateAudit(sink AuditSink, key AuditKey, run RunClock) (*GateAudit, GateResult) {
	const g = Gate21ImmutableAudit
	if !run.Valid() {
		return nil, gateFailed(g, ReasonAuditClockUnconstructed,
			"no RUN CLOCK was supplied, so every row this writer wrote would carry an "+
				"instant nobody set and every embargo comparison would be measured "+
				"against 1970. A RunClock is sealed at run initiation; the zero value "+
				"means there is no run behind this writer.")
	}
	if sink == nil {
		return nil, gateFailed(g, ReasonAuditSinkMissing,
			"no audit sink was supplied. Gate 21 makes the audit write part of the "+
				"decision, so a run with nowhere to record decisions makes none.")
	}
	if !key.Valid() {
		return nil, gateFailed(g, ReasonAuditKeyIncomplete,
			"the audit key is not one NewAuditKey minted, so rows written through this "+
				"writer could not be keyed to an attestation and a scope hash. Gate 21 "+
				"requires both.")
	}
	return &GateAudit{sink: sink, key: key, run: run, sealed: true}, gatePassed(g)
}

// RunClock returns the run this writer is bound to. It is the zero RunClock —
// which every gate refuses — for an unconstructed writer.
func (a *GateAudit) RunClock() RunClock {
	if !a.Constructed() {
		return RunClock{}
	}
	return a.run
}

// Constructed reports whether this came from NewGateAudit.
func (a *GateAudit) Constructed() bool { return a != nil && a.sealed && a.sink != nil }

// Key returns the run's audit key.
func (a *GateAudit) Key() AuditKey {
	if !a.Constructed() {
		return AuditKey{}
	}
	return a.key
}

// Rows returns how many rows this writer has durably written.
func (a *GateAudit) Rows() int {
	if !a.Constructed() {
		return 0
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.rows
}

// LastSeq returns the highest sequence number written.
func (a *GateAudit) LastSeq() AuditSeq {
	if !a.Constructed() {
		return 0
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.lastSeq
}

// Record writes ONE gate decision and returns the decision as it now stands.
//
// THIS RETURN VALUE IS GATE 21. If the input result passed and the audit write
// failed, the returned GateResult is a REFUSAL — "a gate decision is not
// 'allowed' if its paired audit write fails". If the input result refused, the
// refusal is returned unchanged once the row is down. There is no path on
// which a passing result survives a failed write.
//
// # Why this one still takes a Clock when gates 18 and 20 do not
//
// Because the two questions are different, and collapsing them would be a
// regression rather than a tightening.
//
// Gates 18 and 20 ask "WHAT DAY IS IT" — has a 45-day deadline elapsed, is a
// 28-day attestation still live. That question has one answer per run, and
// letting the caller answer it separately per call is what made the
// consistently-told January lie work. So they read a.run.
//
// The per-request paths that come through here — AuditedAdmit's rate limits
// and concurrency leases, AuditedObservation's circuit breaker and Retry-After
// — ask "HOW LONG SINCE THE LAST ONE". That question needs time to ADVANCE
// within a run: 10 requests per second per host is not a limit if every
// request in the run is stamped with the instant the run started. Those
// callers therefore supply the instant their request is actually happening at,
// and this function records it.
func (a *GateAudit) Record(res GateResult, subject AuditSubject, at Clock) (AuditSeq, GateResult) {
	const g = Gate21ImmutableAudit

	if !a.Constructed() {
		return 0, gateFailed(g, ReasonAuditSinkMissing,
			"Record was called on a GateAudit that NewGateAudit never built. A writer with "+
				"no sink records nothing, and recording nothing does not allow.")
	}
	// There is deliberately no `if !subject.Constructed()` branch. An
	// AuditSubject's text is unexported and is set only alongside sealed, so
	// an unconstructed subject renders as the empty string, and
	// GateRecord.Validate below refuses a record whose Target is empty — with
	// the same ReasonAuditKeyIncomplete, before the sink is touched. A
	// mutation run showed the branch could never be the only thing refusing
	// anything, so it is gone rather than kept as a layer that cannot fail;
	// the same reasoning per-request enforcement recorded for AuditReason's missing gate check.
	// TestGateAuditRefusesAnUnsetClockAndAnEmptySubject still covers the case.
	if !at.Valid() {
		return 0, gateFailed(g, ReasonAuditClockUnconstructed,
			"the row has no instant. GateRecord.At is the instant the decision was made "+
				"AGAINST, not wall-clock time read inside the sink, so an unset clock "+
				"cannot be repaired downstream.")
	}
	reason, err := auditReasonFor(res)
	if err != nil {
		return 0, gateFailed(g, ReasonAuditRowUnattributable,
			"this gate decision carries no reason token, so the row could not be "+
				"attributed to a gate. An unattributable decision is refused rather "+
				"than recorded under an invented token.",
			"gate:  "+res.Gate().String(),
			"cause: "+err.Error())
	}
	outcome := OutcomeDeny
	detail := ""
	if res.Passed() {
		outcome = OutcomeAllow
		detail = res.Gate().String() + " permitted this decision"
	} else if f := res.Failure(); f != nil {
		detail = f.Detail
	}

	rec := GateRecord{
		Gate:          res.Gate(),
		Outcome:       outcome,
		Reason:        reason,
		Detail:        detail,
		AttestationID: a.key.AttestationID(),
		ScopeHash:     a.key.ScopeHash(),
		Mode:          a.key.Mode(),
		Target:        subject.String(),
		At:            at.Instant(),
	}
	if err := rec.Validate(); err != nil {
		return 0, gateFailed(g, ReasonAuditKeyIncomplete,
			"the decision could not be recorded as a well-formed row, so it is not "+
				"allowed. Gate 21 keys every row on the attestation ID and the scope "+
				"hash; a decision that cannot be keyed is not allowed.",
			"cause: "+err.Error())
	}

	a.mu.Lock()
	defer a.mu.Unlock()
	seq, werr := a.sink.WriteGateDecision(rec)
	switch {
	case werr != nil:
		return 0, gateFailed(g, ReasonAuditWriteFailed,
			"the audit write failed, so this decision is not allowed regardless of what "+
				"the gate ruled.",
			"gate:  "+res.Gate().String(),
			"cause: "+werr.Error())
	case seq == 0:
		return 0, gateFailed(g, ReasonAuditWriteFailed,
			"the audit sink returned sequence 0 with no error, which is what a stub or a "+
				"short-circuited implementation returns. A row that was not written "+
				"cannot make a decision allowed.",
			"gate: "+res.Gate().String())
	case seq <= a.lastSeq:
		return 0, gateFailed(g, ReasonAuditNotAppendOnly,
			"the audit sequence did not advance, so this sink either rewound the log or "+
				"overwrote a row. Gate 21 requires an IMMUTABLE audit; a log that can "+
				"go backwards is a log whose earlier rows cannot be trusted, and the "+
				"decision paired with this write is not allowed.",
			fmt.Sprintf("previous sequence: %d", a.lastSeq),
			fmt.Sprintf("returned:          %d", seq))
	}
	a.lastSeq = seq
	a.rows++
	return seq, res
}

// RecordTrace writes ONE ROW PER GATE in an ordered trace.
//
// The kernel-types review made this point against Adjudicate: gate 21 asks for "an
// immutable audit of every gate decision", and a single row naming the last
// gate records one gate in eight. Per-request enforcement's AdmitTraced returns the whole trace
// precisely so that this function can write all of it.
//
// An EMPTY trace is a refusal, for the reason kernel.go's chain runner refuses
// an empty chain: "no gate objected" is the vacuous truth a for-range over an
// empty slice produces for free.
//
// It STOPS AT THE FIRST REFUSAL and returns it, rather than writing the rest
// of the trace and returning the last result. Both halves matter and both are
// guarded by TestRecordTraceStopsAtTheFirstRefusal, which puts the refusal in
// the SECOND of four positions: without the early return the sink receives
// four rows for a trace that was decided at the second, and the value returned
// is the fourth gate's ALLOW.
func (a *GateAudit) RecordTrace(trace []GateResult, subject AuditSubject, at Clock) GateResult {
	const g = Gate21ImmutableAudit
	if !a.Constructed() {
		return gateFailed(g, ReasonAuditSinkMissing,
			"RecordTrace was called on a GateAudit that NewGateAudit never built.")
	}
	if len(trace) == 0 {
		return gateFailed(g, ReasonAuditTraceEmpty,
			"the trace is empty, so no gate decision was recorded and no gate was "+
				"consulted. An empty trace is a refusal, never a silent pass.")
	}
	var last GateResult
	for _, res := range trace {
		_, out := a.Record(res, subject, at)
		if !out.Passed() {
			return out
		}
		last = out
	}
	return last
}

// AuditedAdmit is the per-request coupling: per-request enforcement's interceptor, with gate 21's
// audit write made part of the decision.
//
// # What happens when the audit write fails on an ADMITTED request
//
// The lease is RELEASED and the request is refused. That is the whole point:
// Per-request enforcement's Admit hands back a concurrency slot on success, and a caller holding a
// lease will issue a request. If the row that records the admission did not
// land, the admission is not an admission, so the slot goes back and the
// caller gets a refusal. TestAuditedAdmitReleasesTheLeaseWhenTheWriteFails is
// the guard.
func (a *GateAudit) AuditedAdmit(gov *Governor, intent RequestIntent, tech Technique, now Clock) (*Lease, GateResult) {
	lease, trace := gov.AdmitTraced(intent, tech, now)
	res := a.RecordTrace(trace, SubjectTarget(intent.Next()), now)
	if !res.Passed() {
		lease.Release()
		return &Lease{}, res
	}
	return lease, res
}

// AuditedObservation records one gate 16 or gate 17 observation.
//
// Gate 21 names "every circuit-breaker trip" and "every redirect refusal"
// explicitly. A redirect refusal arrives as a gate 13 refusal in an
// AuditedAdmit trace; a breaker trip arrives here, because ObserveResponse and
// ObserveConnectionError are where the breaker actually trips and they are not
// part of the admission trace.
//
// It is a one-line wrapper and it is still gate 21's coupling: the value it
// returns is Record's, so a healthy observation whose row did not land comes
// back as a REFUSAL. TestAuditedObservationRefusesWhenTheAuditWriteFails is
// the guard — this was the only audited path in the file without one, which
// mattered because the trip gate 21 names explicitly arrives through here.
func (a *GateAudit) AuditedObservation(res GateResult, target Target, at Clock) GateResult {
	_, out := a.Record(res, SubjectTarget(target), at)
	return out
}

// AuditedPublication runs gate 18 and records the decision, refusing if the
// row did not land.
//
// The store is a parameter because gate 18 READS the recorded disclosure state
// rather than trusting the proof in the request; see checkGate18Publication.
func (a *GateAudit) AuditedPublication(store DisclosureStore, req PublicationRequest) GateResult {
	res := checkGate18Publication(req, a.RunClock(), store)
	subject, err := SubjectFinding(req.Finding)
	if err != nil {
		subject = subjectUnidentified("finding")
	}
	_, out := a.Record(res, subject, a.RunClock().Now())
	return out
}

// AuditedPush runs gate 20 and records the decision, refusing if the row did
// not land.
func (a *GateAudit) AuditedPush(req PushRequest) GateResult {
	res := pushGate(req, a.RunClock())
	subject, err := SubjectRepository(req.Destination.Repository())
	if err != nil {
		subject = subjectUnidentified("repository")
	}
	_, out := a.Record(res, subject, a.RunClock().Now())
	return out
}

// AuditedPersistDisclosure runs gate 19 and records the decision.
//
// The PersistedDisclosure is returned ONLY if the audit row landed. That is
// what makes gate 18's requirement for one meaningful: a disclosure state that
// was written to the store but whose write was never audited does not produce
// the proof gate 18 asks for, so it cannot be used to publish.
//
// # THE AUDIT ROW GOES BEFORE THE DURABLE WRITE, AND THAT ORDER IS THE CONTROL
//
// This function used to run the whole of persistDisclosureState and audit
// afterwards. Withholding the proof was not enough, because the STATE
// TRANSITION had already landed and there is no proof to withhold from a store
// that already holds the row. Measured through this exported route against the
// shipped tree, one shared store, a sink that returns an error — a locked
// table or a full disk, no malicious sink required:
//
//	AuditedPersistDisclosure(store, withheld)                 passed=true
//	AuditedPersistDisclosure(store, released, FAILING SINK)   passed=false
//	    ... and the store now reads `embargoed`, with no audit row
//	AuditedPersistDisclosure(store, embargoed)                passed=true
//	    ... no release reason, no evidence, and gate 19 permits it
//	AuditedPublication(store, ...)                            passed=true
//
// The refusal in the middle consumed the entire withheld-survives-a-second-row
// control and left three indistinguishable allow rows behind it. Gate 21's own
// rule is that a decision is not "allowed" if its paired audit write fails; an
// applied, irreversible side effect makes that rule unenforceable after the
// fact.
//
// So the order is DECIDE, AUDIT, APPLY. It is the same shape as AuditedAdmit's
// lease.Release, reached the other way round: AuditedAdmit cannot decide before
// the slot is taken, so it reverses the side effect; this can decide before
// anything durable happens, so it never takes one.
//
// # What the ordering leaves, stated rather than papered over
//
// An allow row can land for a transition whose write then fails. A second row
// records that failure, the caller gets the refusal, and NOTHING durable
// changed. That residual is strictly the safer one: gate 18 reads the STORE
// and not the audit log, so an allow row with no write behind it unlocks
// nothing, whereas the defect this replaced was a write with no row behind it,
// which unlocked everything downstream of it.
// TestAuditedPersistDisclosureAppliesNothingWhenTheAuditWriteFails is the
// guard, and it is the measurement above run as a test.
func (a *GateAudit) AuditedPersistDisclosure(store DisclosureStore, rec DisclosureRecord) (PersistedDisclosure, GateResult) {
	subject, err := SubjectFinding(rec.Finding())
	if err != nil {
		subject = subjectUnidentified("finding")
	}

	// ---- DECIDE. Nothing durable has happened when this returns. ----
	d, res := decideDisclosurePersist(store, rec)

	// ---- AUDIT. A decision whose row did not land is not a decision. ----
	_, out := a.Record(res, subject, a.RunClock().Now())
	if !out.Passed() {
		return PersistedDisclosure{}, out
	}

	// ---- APPLY. ----
	p, applied := applyDisclosureState(store, rec, d)
	if !applied.Passed() {
		// The allow row above stands and would otherwise read as a completed
		// transition. Record the failure next to it. The refusal is returned
		// whether or not THIS row lands, because nothing durable changed
		// either way.
		a.Record(applied, subject, a.RunClock().Now())
		return PersistedDisclosure{}, applied
	}
	return p, out
}

// ---------------------------------------------------------------------------
// Small shared helpers
// ---------------------------------------------------------------------------

// validateSHA256Hex reports whether s is 64 lowercase hex characters.
//
// It is separate from ScopeHash.Validate rather than reusing it because a
// patch digest is not a scope hash, and a shared method would put "scope hash"
// in the error message for a patch.
func validateSHA256Hex(s, what string) error {
	if s == "" {
		return fmt.Errorf("%w: the %s is empty", ErrRefused, what)
	}
	const want = 64 // sha256, hex
	if len(s) != want {
		return fmt.Errorf("%w: the %s is %d characters; a lowercase-hex SHA-256 is %d",
			ErrRefused, what, len(s), want)
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return fmt.Errorf("%w: the %s has byte %q at offset %d, which is not lowercase hex",
				ErrRefused, what, string(c), i)
		}
	}
	return nil
}

// boundedEvidence bounds and charset-restricts the evidence attached to an
// embargo adjustment.
//
// The charset is an ALLOWLIST of printable ASCII plus nothing else: no
// control characters, no newlines, no tabs, no non-ASCII. Evidence is
// operator- or model-authored text that lands in the record store and may be
// read back by an agent, so it is bounded where it enters rather than wherever
// it is rendered. It is never interpolated into a GateFailure.Detail — Detail
// is Anvil-authored, per the spine's record section — so this text has exactly one
// destination.
func boundedEvidence(s string) (string, error) {
	trimmed := strings.TrimSpace(s)
	if trimmed == "" {
		return "", fmt.Errorf("%w: no evidence was attached", ErrRefused)
	}
	if len(trimmed) > maxEmbargoEvidenceLen {
		return "", fmt.Errorf("%w: evidence is %d bytes; the cap is %d",
			ErrRefused, len(trimmed), maxEmbargoEvidenceLen)
	}
	for i := 0; i < len(trimmed); i++ {
		c := trimmed[i]
		if c < 0x20 || c > 0x7e {
			return "", fmt.Errorf("%w: evidence has byte 0x%02x at offset %d, which is not "+
				"printable ASCII", ErrRefused, c, i)
		}
	}
	return trimmed, nil
}
