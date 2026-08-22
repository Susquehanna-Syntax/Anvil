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
// scope, attestation, clock)". That refusal is D.2's, not this file's, and
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
// plan/00-SPINE.md S1 row 5 collapsed the "8-hour buffer file, then deleted"
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
// plan/50-dast.md's gate table marks gates 19, 20 and 21 "Configurable? No",
// and gate 18 configurable only through "acceleration (active exploitation) /
// extension (core-OS changes)... disabling the embargo outright is not
// configurable".
//
// So there is NO FUNCTION IN THIS FILE THAT TAKES AN EMBARGO DURATION.
// OpenEmbargo takes no duration; DefaultEmbargo is a const; and the only two
// operations that move a deadline are Accelerate and Extend, each of which
// requires a reason drawn from a compiled-in ALLOWLIST of documented cases,
// requires evidence, and is bounded — acceleration cannot go below
// MinAcceleratedEmbargo and extension cannot go past MaxEmbargo. There is no
// config key to find because there is no parameter to set.
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
	ReasonPublicationPermitted           Reason = "gate18.publication_permitted"
)

// Gate 19 reasons.
const (
	ReasonDisclosureRecordUnconstructed Reason = "gate19.disclosure_record_not_constructed"
	ReasonDisclosureStateUnknown        Reason = "gate19.disclosure_state_is_not_on_the_allowlist"
	ReasonDisclosureStoreMissing        Reason = "gate19.no_disclosure_store_was_supplied"
	ReasonDisclosureStoreWrongMedium    Reason = "gate19.store_is_not_the_sqlite_record_store"
	ReasonDisclosureWriteFailed         Reason = "gate19.disclosure_state_write_failed"
	ReasonDisclosureKeyIncomplete       Reason = "gate19.disclosure_row_cannot_be_keyed"
	ReasonDisclosurePersisted           Reason = "gate19.disclosure_state_persisted_in_the_record_store"
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
	ReasonPushNoReportingChannel      Reason = "gate20.gate12_resolved_no_reporting_channel"
	ReasonPushPermitted               Reason = "gate20.patch_delivery_permitted"
)

// Gate 21 reasons.
//
// ReasonAuditWriteFailed, ReasonAuditKeyIncomplete and ReasonAuditSinkMissing
// are D.2's and are reused rather than re-spelled: a second token for one
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
// It is declared here rather than in phase1_run.go for the reason D.6 gave for
// declaring gate 11's pass token in phase3_enforcement.go: D.4's file is
// outside this packet's write scope, and the need for the token is gate 21's.
// CheckGate7TriggerProvenance returns gatePassed, which carries no Reason —
// D.2's GateResult has no field for one — so without this the audit row for a
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
// by humans and by tooling, and plan/00-SPINE.md S7 makes anything derived
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
// plan/00-SPINE.md S7 permit it to be used for. Nothing in this file returns a
// Ruling, so nothing here can put a security.txt result into an admission
// decision even by accident.
type VendorContact struct {
	channel SecurityTxtResult
	at      time.Time
	sealed  bool
}

// RecordVendorContact records first contact through gate 12's resolved
// channel.
func RecordVendorContact(channel SecurityTxtResult, at Clock) (VendorContact, GateResult) {
	const g = Gate18Embargo
	if !at.Valid() {
		return VendorContact{}, gateFailed(g, ReasonEmbargoClockUnconstructed,
			"vendor contact was recorded against a Clock that NewClock never built. The "+
				"embargo deadline is measured from this instant, so an unset one would "+
				"put the deadline in 1970 and the embargo would read as already elapsed.")
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
// configurable" (plan/50-dast.md gate 18) is enforced rather than promised.
const DefaultEmbargo = 45 * 24 * time.Hour

// MinAcceleratedEmbargo is the floor an ACCELERATED embargo cannot go below.
//
// THIS NUMBER IS ANVIL'S, NOT CERT/CC'S. CERT/CC documents acceleration for
// observed active exploitation; it does not publish a floor, and this file
// does not pretend it does. The floor exists for a structural reason: without
// one, "accelerate to now" is how an embargo gets disabled while still being
// called an embargo, and the gate table says disabling is not configurable.
// One day is the shortest window in which a vendor who has just been told
// about active exploitation can act at all.
const MinAcceleratedEmbargo = 24 * time.Hour

// MaxEmbargo is the ceiling an EXTENDED embargo cannot go past, measured from
// first contact.
//
// Also Anvil's number, for the mirror-image reason: an unbounded extension is
// how a finding gets buried while still being called embargoed. research/20
// permits extension for "standards/core-OS-level fixes", which are slow; a
// year is long enough for one and short enough to be a bound.
const MaxEmbargo = 365 * 24 * time.Hour

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
func OpenEmbargo(own Ownership, finding FindingID, contact VendorContact) (EmbargoState, GateResult) {
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
	return EmbargoState{
		finding:      finding,
		ownership:    own,
		contact:      contact,
		firstContact: contact.At(),
		deadline:     contact.At().Add(DefaultEmbargo),
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
// The copy is enough here and would not be enough for a Scope: D.3's critic
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
//  3. The new deadline is FLOORED at MinAcceleratedEmbargo from first
//     contact. Accelerating to "now" on the day of first contact does not
//     produce a zero-length embargo; it produces a one-day one.
func (e EmbargoState) Accelerate(reason EmbargoAccelerationReason, evidence string, at Clock) (EmbargoState, GateResult) {
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
				"plan/50-dast.md calls acceleration a DOCUMENTED exception; an "+
				"exception with no document is a config key.",
			"evidence: "+err.Error())
	}
	if !at.Valid() {
		return EmbargoState{}, gateFailed(g, ReasonEmbargoClockUnconstructed,
			"Accelerate was called with a Clock that NewClock never built, so the new "+
				"deadline would be computed against an instant nobody set.")
	}
	if at.Instant().Before(e.firstContact) {
		return EmbargoState{}, gateFailed(g, ReasonEmbargoClockWentBack,
			"the acceleration instant is before first contact. A clock that went backwards "+
				"is a clock, not a shorter embargo.")
	}
	candidate := at.Instant()
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
		at:       at.Instant(),
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
func (e EmbargoState) Extend(reason EmbargoExtensionReason, evidence string, until Clock) (EmbargoState, GateResult) {
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
		at:       until.Instant(),
		from:     e.deadline,
		to:       until.Instant(),
	})
	next.deadline = until.Instant()
	return next, gatePassed(g)
}

// PublicationRequest is everything gate 18 needs to decide whether a finding
// may be published.
//
// Every field that could be forged is a SEALED type: Ownership comes only from
// ClassifyOwnership, EmbargoState only from OpenEmbargo, PersistedDisclosure
// only from a successful gate 19 write. The two plain fields — a FindingID and
// a Clock — are both validated, and the zero value of each refuses.
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
	// durably written to the record store.
	Persisted PersistedDisclosure
	// Now is the instant the decision is made at.
	Now Clock
}

// CheckGate18Publication is gate 18: "No auto-publication of third-party
// findings, ever."
//
// # The order, and why gate 19's proof is required before the deadline check
//
// Because the deadline check is only meaningful if the deadline is durable.
// An EmbargoState is a value in memory; it can be reconstructed by any caller
// that has the pieces. What makes it a real embargo is that the same state was
// written to the SQLite record store, where the next run — and the run after
// the reboot — will find it. So gate 18 refuses to publish anything whose
// disclosure state gate 19 did not persist, BEFORE it looks at the clock.
func CheckGate18Publication(req PublicationRequest) GateResult {
	const g = Gate18Embargo

	if err := req.Finding.Validate(); err != nil {
		return gateFailed(g, ReasonFindingUnidentified,
			"publication was requested for a finding with no valid identifier. An audit "+
				"row that cannot name what was published records nothing.",
			"finding: "+redactUntrusted(string(req.Finding)))
	}
	if !req.Now.Valid() {
		return gateFailed(g, ReasonEmbargoClockUnconstructed,
			"publication was requested against a Clock that NewClock never built. Every "+
				"embargo comparison is measured against it, and an unset clock reads as "+
				"1970, which is after no deadline and before every one depending on the "+
				"comparison's direction.")
	}
	if !req.Ownership.Classified() {
		return gateFailed(g, ReasonOwnershipUnclassified,
			"the finding's repository was never classified, so gate 18 cannot say whether "+
				"this is the operator's own code or somebody else's. Unclassified is "+
				"refused rather than assumed either way.")
	}
	if req.Ownership.OperatorOwned() {
		// The operator publishing a finding against their own code is not
		// what gate 18 restricts. research/20 gate 18 is about "findings
		// against code Anvil's operator does not own".
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
	if !req.Persisted.Valid() {
		return gateFailed(g, ReasonPublicationStateNotPersisted,
			"this finding's disclosure state was never durably persisted, so gate 19's "+
				"proof is missing. An embargo held only in memory or in the tmpfs "+
				"handoff packet does not survive a reboot, and an embargo that forgets "+
				"itself is an embargo that publishes.")
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
				"overturn it.")
	}
	if !req.Embargo.Elapsed(req.Now) {
		return gateFailed(g, ReasonEmbargoRunning,
			"the embargo clock is still running. A third-party finding is not published "+
				"before its deadline, and the only two ways the deadline moves are "+
				"Accelerate (observed active exploitation) and Extend (standards or "+
				"core-OS change), each of which requires an allowlisted reason and "+
				"evidence.",
			"first contact: "+req.Embargo.FirstContact().UTC().Format(time.RFC3339),
			"deadline:      "+req.Embargo.Deadline().UTC().Format(time.RFC3339),
			"now:           "+req.Now.Instant().UTC().Format(time.RFC3339),
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
	// (plan/00-SPINE.md S1). It is the only medium gate 19 permits.
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
// plan/IMPLEMENTATION-PLAN.md section 6 rules that area 40 (internal/record)
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
	sealed       bool
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

// Key returns the audit key this row is joined on.
func (r DisclosureRecord) Key() AuditKey { return r.key }

// AttestationID returns the first half of the audit key.
func (r DisclosureRecord) AttestationID() AttestationID { return r.key.AttestationID() }

// ScopeHash returns the second half.
func (r DisclosureRecord) ScopeHash() ScopeHash { return r.key.ScopeHash() }

// DisclosureStore is the durable writer gate 19 requires. D.9/D.10 implement
// it over the SQLite record store.
//
// Medium is a declaration, and this package cannot verify it: a kernel that
// imports no store cannot inspect a store's files. The residual risk is
// therefore real and is stated rather than papered over — a store that
// declares MediumRecordStoreSQLite while writing to tmpfs defeats gate 19.
// What the declaration buys is that the honest implementation is the easy one,
// that the dishonest one is a visible lie in a diff, and that the ACCIDENT —
// somebody passing the handoff buffer because it was the store in scope — is
// refused.
type DisclosureStore interface {
	// Medium says where this store keeps bytes.
	Medium() StorageMedium
	// PutDisclosureState durably writes one row and returns its sequence
	// number. Returning (0, nil) is treated as a failed write, for the
	// reason AuditSeq gives.
	PutDisclosureState(DisclosureRecord) (AuditSeq, error)
}

// CheckGate19DisclosureStore is gate 19's location check: is this store the
// record store.
func CheckGate19DisclosureStore(store DisclosureStore) GateResult {
	const g = Gate19DisclosureStateInDB
	if store == nil {
		return gateFailed(g, ReasonDisclosureStoreMissing,
			"no disclosure store was supplied. Disclosure state that is not written "+
				"anywhere is disclosure state that will not be found by the run after "+
				"the reboot, and a finding whose embargo cannot be found is a finding "+
				"nothing is stopping.")
	}
	medium := store.Medium()
	if medium == MediumRecordStoreSQLite {
		return gatePassed(g)
	}
	detail := "disclosure state may live only in the SQLite store of record " +
		"(plan/00-SPINE.md S1, gate 19). "
	switch medium {
	case MediumTmpfsHandoffBuffer:
		detail += "The store offered is the tmpfs handoff buffer. S1 is explicit that " +
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

// PersistDisclosureState is gate 19: write the disclosure state, and only to
// the record store.
//
// The write and the proof are minted together, in that order, for the reason
// Adjudicate mints a grant only after the audit write lands: a proof issued
// before the write would be a proof of an intention.
func PersistDisclosureState(store DisclosureStore, rec DisclosureRecord) (PersistedDisclosure, GateResult) {
	const g = Gate19DisclosureStateInDB
	if !rec.Constructed() {
		return PersistedDisclosure{}, gateFailed(g, ReasonDisclosureRecordUnconstructed,
			"the disclosure row was not built by NewDisclosureRecord, so it carries no "+
				"finding, no state and no audit key. Writing it would put a row in the "+
				"record store that says nothing and reads as \"looked at, nothing "+
				"embargoed\".")
	}
	if res := CheckGate19DisclosureStore(store); !res.Passed() {
		return PersistedDisclosure{}, res
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
		medium:  store.Medium(),
		seq:     seq,
		key:     rec.Key(),
		sealed:  true,
	}, gatePassed(g)
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
	// Now is the instant the decision is made at.
	Now Clock
}

// PushGate is gate 20: no unsolicited fixes pushed to third parties.
//
// It is named PushGate because D.7's expected output schema names it that; the
// other Phase 4 entry points follow the CheckGateNN convention D.4–D.6 use.
//
// # What it requires, and the one thing it deliberately does not
//
// For a THIRD-PARTY destination it requires, in order: an identified patch, a
// classified destination, a valid clock, a constructed scope, an attestation
// that is constructed, bound to that scope and LIVE at this instant, and an
// embargo for THIS finding — which is how the gate-12 reporting channel and
// the recorded vendor contact become preconditions, since OpenEmbargo refuses
// without both.
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
func PushGate(req PushRequest) GateResult {
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
	if !req.Now.Valid() {
		return gateFailed(g, ReasonPushClockUnconstructed,
			"the push was proposed against a Clock that NewClock never built, so the "+
				"attestation's liveness could not be measured against anything.")
	}
	if req.Destination.OperatorOwned() {
		// Pushing to a repository the operator declared they own is not an
		// unsolicited fix to a third party. research/20 gate 20 is about
		// "a repository Anvil's operator does not control".
		return gatePassed(g)
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
			"delivering a patch to a repository the operator does not own requires THE SAME "+
				"affirmative attestation as probing it (research/20 gate 20), and no "+
				"attestation was supplied. The patch's content is not a factor: a "+
				"benign unsolicited fix to a stranger's repository is still an "+
				"unsolicited fix.",
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
	if !req.Attestation.Live(req.Now) {
		return gateFailed(g, ReasonPushAttestationNotLive,
			"the attestation is expired or not yet valid at this instant. An expired "+
				"authorisation authorises nothing, and a patch delivered under one is "+
				"as unsolicited as a patch delivered under none.",
			"attestation: "+redactUntrusted(string(req.Attestation.ID())),
			"now:         "+req.Now.Instant().UTC().Format(time.RFC3339))
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
	if !req.Embargo.Contact().Recorded() {
		return gateFailed(g, ReasonPushNoReportingChannel,
			"the embargo carries no recorded vendor contact through gate 12's channel. "+
				"This is unreachable through OpenEmbargo, which refuses without one, "+
				"and is checked anyway: gate 20's requirement is the channel, and a "+
				"requirement enforced only by another function's invariant is a "+
				"requirement that survives until somebody adds a second constructor.")
	}
	return gatePassed(g)
}

// ===========================================================================
// GATE 21 — the immutable audit of every gate decision
// ===========================================================================

// AuditKey is gate 21's join key: an attestation ID and a scope hash, minted
// together and only from an attestation that is actually bound to that scope.
//
// plan/50-dast.md gate 21: every decision is "keyed to attestation ID + scope
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
// plan/00-SPINE.md S7 makes the DAST response body "the highest-risk field —
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
// gatePassed does not take a Reason — D.2's GateResult has no field for one —
// so without this map a Phase 4 allow row would reach GateRecord.Validate with
// an empty reason and be refused. The same problem, and the same solution, as
// D.6's phase3PassReasons.
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
// D.4's CheckGate4/5/6 return gatePassed with no token, and D.4 already
// declares a pass Reason for each on the Ruling path; this maps the gate to
// the token D.4 wrote, so no token is invented here. Gate 7's is the one
// exception and is declared at the top of this file, with the reason.
//
// GATES 8, 9, 10 AND 11 ARE ABSENT ON PURPOSE. Gate 10 has TWO pass tokens
// with different meanings — "the address is not in a reserved range" and "the
// reserved address is enumerated in lab scope" — and a single map entry would
// record one of them as the other, which is a false audit row. Gate 11's pass
// token is D.6's and is already in phase3PassReasons, which auditReasonFor
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
	// D.6's AuditReason handles every refusal and the Phase 3 pass tokens.
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
	lastSeq AuditSeq
	rows    int
	sealed  bool
}

// NewGateAudit binds a sink to a run's audit key.
func NewGateAudit(sink AuditSink, key AuditKey) (*GateAudit, GateResult) {
	const g = Gate21ImmutableAudit
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
	return &GateAudit{sink: sink, key: key, sealed: true}, gatePassed(g)
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
func (a *GateAudit) Record(res GateResult, subject AuditSubject, at Clock) (AuditSeq, GateResult) {
	const g = Gate21ImmutableAudit

	if !a.Constructed() {
		return 0, gateFailed(g, ReasonAuditSinkMissing,
			"Record was called on a GateAudit that NewGateAudit never built. A writer with "+
				"no sink records nothing, and recording nothing does not allow.")
	}
	if !subject.Constructed() {
		return 0, gateFailed(g, ReasonAuditKeyIncomplete,
			"the row has no subject, so it could not say what the decision was about.")
	}
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
// D.3's critic made this point against Adjudicate: gate 21 asks for "an
// immutable audit of every gate decision", and a single row naming the last
// gate records one gate in eight. D.6's AdmitTraced returns the whole trace
// precisely so that this function can write all of it.
//
// An EMPTY trace is a refusal, for the reason kernel.go's chain runner refuses
// an empty chain: "no gate objected" is the vacuous truth a for-range over an
// empty slice produces for free.
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

// AuditedAdmit is the per-request coupling: D.6's interceptor, with gate 21's
// audit write made part of the decision.
//
// # What happens when the audit write fails on an ADMITTED request
//
// The lease is RELEASED and the request is refused. That is the whole point:
// D.6's Admit hands back a concurrency slot on success, and a caller holding a
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
func (a *GateAudit) AuditedObservation(res GateResult, target Target, at Clock) GateResult {
	_, out := a.Record(res, SubjectTarget(target), at)
	return out
}

// AuditedPublication runs gate 18 and records the decision, refusing if the
// row did not land.
func (a *GateAudit) AuditedPublication(req PublicationRequest) GateResult {
	res := CheckGate18Publication(req)
	subject, err := SubjectFinding(req.Finding)
	if err != nil {
		subject = subjectUnidentified("finding")
	}
	_, out := a.Record(res, subject, req.Now)
	return out
}

// AuditedPush runs gate 20 and records the decision, refusing if the row did
// not land.
func (a *GateAudit) AuditedPush(req PushRequest) GateResult {
	res := PushGate(req)
	subject, err := SubjectRepository(req.Destination.Repository())
	if err != nil {
		subject = subjectUnidentified("repository")
	}
	_, out := a.Record(res, subject, req.Now)
	return out
}

// AuditedPersistDisclosure runs gate 19 and records the decision.
//
// The PersistedDisclosure is returned ONLY if the audit row landed. That is
// what makes gate 18's requirement for one meaningful: a disclosure state that
// was written to the store but whose write was never audited does not produce
// the proof gate 18 asks for, so it cannot be used to publish.
func (a *GateAudit) AuditedPersistDisclosure(store DisclosureStore, rec DisclosureRecord, at Clock) (PersistedDisclosure, GateResult) {
	p, res := PersistDisclosureState(store, rec)
	subject, err := SubjectFinding(rec.Finding())
	if err != nil {
		subject = subjectUnidentified("finding")
	}
	_, out := a.Record(res, subject, at)
	if !out.Passed() {
		return PersistedDisclosure{}, out
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
// is Anvil-authored, per plan/00-SPINE.md S6 — so this text has exactly one
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
