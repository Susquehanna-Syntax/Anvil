// Package lanea populates the Lane-A-owned fields of Anvil's canonical audit
// record: step A.19 of plan/20-lane-a-ingestion-sca.md.
//
// ===========================================================================
// WHAT THIS PACKAGE IS, AND THE ONE THING IT IS NOT
// ===========================================================================
//
// It takes one A.17 MatchResult — "this installed version is inside a range
// this advisory calls vulnerable" — plus the `advisory` row that decided it,
// and produces a record.Result: the SAME struct every other area produces,
// carrying the frozen `anvil/*` property bag.
//
// IT DEFINES NO SECOND FINGERPRINT, NO SECOND FINDING STRUCT AND NO SECOND
// ENUM. plan/IMPLEMENTATION-PLAN.md §1 names this the cross-area edge in
// exactly those words: "Lane A must populate the canonical record and MUST NOT
// INVENT A SECOND FINGERPRINT." So:
//
//   - the digest comes from record.Sca / record.Host (anvil-fp/v1,
//     internal/record/FINGERPRINT-SPEC.md is authoritative). There is no
//     hash function in this file, and emit_test.go asserts the emitted digest
//     against testdata/fingerprint_corpus's GOLDEN values — which were
//     produced by a separate implementation of the spec, not by the Go code
//     this package calls;
//   - every enum value written here is a Go constant from internal/record
//     (record.HalfSast, record.DetectorKindHost, record.TrustUntrusted, ...).
//     There is not one re-spelled string literal;
//   - the output is record.Result. Emission wraps it to carry the two
//     Lane-A-owned facts the frozen contract has no slot for, and carries no
//     copy of anything the Result already holds. See Emission.
//
// A.17 set the precedent this file follows: match.MatchResult carries no
// fingerprint, and match.Purl.Base delegates to record.PurlBase.
//
// ===========================================================================
// THE SEVEN LANE-A-OWNED FIELDS (plan/20 Dependency Summary)
// ===========================================================================
//
//	remediable_by_agent   -> Result.Properties.RemediableByAgent
//	as_of                 -> Result.Properties.Advisory.AsOf
//	staleness_seconds     -> Result.Properties.Advisory.StalenessSeconds
//	                         ** COMPUTED here, see section 3 **
//	parse_degraded        -> Result.Properties.Advisory.ParseDegraded
//	anvil/trust           -> Result.Properties.Trust (+ the excerpt's own)
//	license_spdx          -> Result.Properties.Advisory.LicenseSpdx
//	license_manual_note   -> Emission.LicenseManualNote  ** see DEVIATION 1 **
//
// ===========================================================================
// 1. remediable_by_agent IS FALSE FOR EVERY HOST FINDING. ALWAYS.
// ===========================================================================
//
// The coding agent's write surface is the git repository (plan/00-SPINE.md
// S7), so it CANNOT fix a host package: there is no file to edit, and the host
// agent is read-only "not behind a flag". Handing it a host finding as
// actionable is an authorization defect, not a cosmetic one.
//
// THE GUARD IS AN ALLOWLIST, NOT A HOST CHECK. remediableByAgent below returns
// false unless EVERY condition for the one remediable shape holds. A denylist
// ("false when host") fails open for any collector, detector kind, evidence
// class or ECOSYSTEM that arrives later; this fails closed. It takes no
// options, reads no configuration and consults no clock, so there is no
// location an override could live in — the same construction
// internal/collector/host used when it made RemediableByAgent a method over an
// untyped constant rather than an assignable field.
//
// S7 IS ABOUT THE THING, NOT ABOUT WHO FOUND IT. An OS package is not
// agent-fixable however it was noticed, because the agent's write surface is
// the git repository either way. So the ecosystem is an arm of the allowlist in
// its own right: a `repo-sca` match whose ecosystem is deb, rpm or apk is NOT
// remediable. Without that arm the guarantee held only because
// internal/collector/repo happens to refuse Trivy's os-pkgs class one lane up —
// a guard whose correctness lives in another package while this file's doc
// claims it lives here.
//
// THE FLAG TRAVELS IN THE BYTES. A.12's review found this field present on
// internal/collector/host's own Inventory and MISSING from FindingSeed, the
// artifact that actually crossed to A.17 — the wrong way round. So every shape
// this package emits carries it in its SERIALISED form: record.Result always
// marshals `anvil/remediableByAgent` (no omitempty), and Emission.MarshalJSON
// adds a CLAMPED top-level mirror. emit_test.go asserts the bytes, not the
// struct field, for both.
//
// ===========================================================================
// 2. anvil/trust ON EVERY STRING ORIGINATING OUTSIDE ANVIL
// ===========================================================================
//
// Advisory prose, package names, versions, purls and manifest paths are
// attacker-influenceable text heading for a repo-credentialed agent. Anvil
// assembling a struct around external bytes does not make the bytes Anvil's:
// record.Trust's own doc says "the question TrustLevel answers is 'who wrote
// these bytes', never 'who assigned this field'", and area B was caught
// stamping anvil_generated on verbatim repo source.
//
// So TrustAssertion.Default is record.TrustUntrusted UNCONDITIONALLY on every
// result this package emits, exactly as record.CardTrust does, and Fields
// names only the strings Anvil itself wrote. Today that is exactly one:
// `anvil/reasoning`.
//
// AND THAT ONE IS PROVED, NOT ASSERTED. A sentence that interpolates a package
// name is not Anvil-generated however it is labelled, so the reasoning string
// is not formatted — it is JOINED FROM A CLOSED VOCABULARY of constant
// fragments plus base-10 integers Anvil computed itself (composeReasoning). A
// part outside that vocabulary is refused and no record is emitted. That makes
// "no external byte reaches an anvil_generated string" a property of the
// construction rather than a claim about the format string.
//
// The advisory EXCERPT keeps its own trust inline (record.TrustedString) and
// takes it from the `advisory` row's `anvil_trust` column, whose CHECK admits
// only untrusted|verified. A row carrying anvil_generated is refused here too.
//
// ===========================================================================
// 3. as_of IS THE CACHE WATERMARK; staleness_seconds IS THE INTERVAL SINCE IT
// ===========================================================================
//
// The two fields are DIFFERENT QUANTITIES and the frozen contract defines both:
// AdvisoryContext.AsOf is "when this advisory data was current", and
// AdvisoryContext.StalenessSeconds is "record-assembly time minus AsOf, carried
// explicitly so a consumer never has to know the assembly clock".
//
// SO staleness_seconds IS COMPUTED HERE, NOT COPIED. `advisory.staleness_seconds`
// in the cache is a THIRD quantity — the publisher lag ingestion measured at
// write time — and copying it into this field publishes two definitions under
// one name. The failure it produces is the exact one S6 exists to prevent: a
// feed outage freezes both cache columns, so a finding resting on three-week-old
// data reports the hour of publisher lag that was true at the last successful
// sync, declares itself inside a one-day SLO, and says so in the prose a human
// reads. An absence of information becomes a false assurance.
//
// AND THIS PACKAGE STILL READS NO CLOCK. There is no time.Now() in this file
// and no clock field on Emitter; TestThisPackageReadsNoClock enforces it. The
// assembly instant ARRIVES instead, on Emitter.AssembledAt, from the caller
// that owns the scan — and it is REQUIRED, refused when zero rather than
// defaulted, because a zero default computes an age against the Unix epoch or
// (worse) silently reproduces the copy-through bug. research/06 Risk #5 and
// plan/00-SPINE.md S6 both say the same thing: serve stale data with an `as_of`
// and a `staleness_seconds`, and say so.
//
// KNOWN GAP, STATED RATHER THAN PAPERED OVER: `advisory.as_of` is the cache
// WRITE instant, so the emitted age omits whatever publisher lag preceded that
// write. Closing it means either redefining `advisory.as_of` or carrying the lag
// into the record, and both reach internal/ingest and internal/record. Reported
// to the orchestrator; not decided here. The emitted number is therefore a LOWER
// BOUND on the true age of the data — it is exactly the interval the contract
// defines, and the contract's own `as_of` is the quantity that is imprecise.
//
// Staleness is SURFACED, NOT ACTED ON. A feed outage is the normal case that
// on_failure=serve_stale exists for (internal/ingest/config: there is
// deliberately no fail_scan value), so a finding decided on stale data is
// still a true positive and still actionable — it just says how old the data
// was. Refusing to act on every finding during a two-day outage is the
// over-refusal this project's own coverage reasoning says gets a control
// dismissed.
//
// parse_degraded is different and IS acted on: see remediableByAgent.
//
// ===========================================================================
// FOUR DEVIATIONS FROM THE PACKET, REPORTED RATHER THAN APPLIED QUIETLY
// ===========================================================================
//
//  1. license_manual_note HAS NO SLOT IN THE FROZEN RECORD. record's
//     AdvisoryContext carries LicenseSpdx and nothing else; run-level
//     AdvisorySnapshot carries no licence field either. plan/00-SPINE.md S8's
//     compliance mechanics require the manual-override field carrying the
//     quoted operative sentence — precisely for the sources whose SPDX id is
//     NONE, NOASSERTION or a LicenseRef-, which is where the SPDX id alone
//     establishes nothing. Every slot it could be smuggled into is worse than
//     no slot: LicenseSpdx is an identifier field and prose corrupts it, and
//     Reasoning is anvil_generated while the note is a QUOTATION from a
//     publisher's LICENSE file. So it travels on Emission, typed as a
//     record.TrustedString, and the gap is reported to the orchestrator.
//     Dropping it silently would lose a compliance obligation.
//
//  2. Result.Level IS LEFT UNSET. Severity mapping (advisory severity or CVSS
//     -> SARIF level) is a vocabulary nobody has been assigned and is not one
//     of the seven fields this step owns; inventing one here would be the
//     eleventh defect of the shape plan/IMPLEMENTATION-PLAN.md §6 rules on.
//     Risk (CVSS/EPSS/KEV) IS populated, because the record names Lane A
//     ingestion as its producer in so many words.
//
//  3. parse_degraded CLAMPS remediable_by_agent TO FALSE. A.19's sketched
//     expression reads only the collector. The clamp can only ever move the
//     answer from true to false, and its reason is at remediableByAgent
//     condition 4: the fixed version an agent would bump to was parsed out of
//     the same record A.16 says the parser did not fully understand. The
//     finding is still emitted, as report-only.
//
//  4. `verified` HAS NO SLOT TO NAME ITS VALIDATION STEP IN. record.Trust
//     defines TrustVerified as "the bytes originated outside Anvil AND passed
//     an explicit validation step THAT IS NAMED IN THE RECORD ... Never a
//     default", and the frozen AdvisoryContext has nowhere to put the step's
//     name. Passing `verified` through unaccompanied would publish the label
//     without the thing that makes it mean anything. So a row asserting
//     `verified` without naming its step is REFUSED here
//     (RefusalTrustValidationStep), and the named step travels on
//     Emission.TrustValidationStep — the same treatment, and the same reported
//     record-contract gap, as license_manual_note in deviation 1.
package lanea

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/Susquehanna-Syntax/Anvil/internal/match"
	"github.com/Susquehanna-Syntax/Anvil/internal/record"
)

// ---------------------------------------------------------------------------
// Refusals
// ---------------------------------------------------------------------------

// RefusalReason names why an emission was refused. It is a closed set and a
// named type so a second reason cannot arrive as a bare string, mirroring
// match.RefusalReason.
type RefusalReason string

const (
	// RefusalNoTargetID: the emitter carries no target id. It is field 1 of
	// every anvil-fp/v1 tier and of `UNIQUE (target_id, fingerprint)`.
	RefusalNoTargetID RefusalReason = "no_target_id"

	// RefusalUnrecognisedCollector: the match names a collector outside
	// {host, repo-sca}. remediable_by_agent is derived from it, so a
	// defaulted collector would default an authorization decision.
	RefusalUnrecognisedCollector RefusalReason = "unrecognised_collector"

	// RefusalInconsistentMatch: the match's own frozen enums disagree with
	// its collector — e.g. Collector=host with DetectorKind=sca. Reaching a
	// gate is not obeying it: this package re-derives both from the
	// collector and refuses a disagreement rather than trusting either side.
	RefusalInconsistentMatch RefusalReason = "inconsistent_match"

	// RefusalAdvisoryMismatch: the supplied advisory row is not the row the
	// match was decided on, by (source, source_id) or by CVE alias.
	RefusalAdvisoryMismatch RefusalReason = "advisory_mismatch"

	// RefusalNoAdvisoryID: neither a CVE id nor a source id, so the finding
	// cannot be identified against the advisory table.
	RefusalNoAdvisoryID RefusalReason = "no_advisory_id"

	// RefusalNoPurl: no purl on either the package or the advisory range. A
	// purl is field 4 of the SCA/host formula and this package will not
	// synthesise one — the namespace (debian vs ubuntu, redhat vs fedora)
	// comes from os-release, which a MatchResult does not carry, and a
	// guessed namespace forks identity against every producer that had one.
	RefusalNoPurl RefusalReason = "no_purl"

	// RefusalNoManifestPath: a repo-SCA match with no manifest relpath. It
	// is the SCA tier's locator; two manifests pulling the same vulnerable
	// package are two findings with two owners and two fixes.
	RefusalNoManifestPath RefusalReason = "no_manifest_path"

	// RefusalUnsupportedHostEcosystem: a host match whose ecosystem has no
	// entry in hostPackageManagers. The locator's manager segment is part of
	// the fingerprint, so guessing it forks identity.
	RefusalUnsupportedHostEcosystem RefusalReason = "unsupported_host_ecosystem"

	// RefusalNoWatermark: the advisory row carries no as_of. Emitting
	// without one would leave the record's freshness unstated, which is the
	// state spine S6's as_of/staleness_seconds fields exist to prevent.
	RefusalNoWatermark RefusalReason = "no_watermark"

	// RefusalNoAssemblyTime: the emitter carries no record-assembly instant.
	// staleness_seconds is DEFINED as assembly time minus as_of, and this
	// package holds no clock to supply the first term, so the caller must.
	// It is refused rather than defaulted: a zero default would measure the
	// age against the Unix epoch, and any other default would be this
	// package inventing the emission instant it is forbidden to read.
	RefusalNoAssemblyTime RefusalReason = "no_assembly_time"

	// RefusalNegativeStaleness: a negative age — either on the row's own
	// column (the cache's advisory_staleness_nonneg CHECK refuses it too) or
	// on the computed interval, which means the assembly instant precedes
	// the watermark the data claims to be current at.
	RefusalNegativeStaleness RefusalReason = "negative_staleness"

	// RefusalIllegalAdvisoryTrust: the advisory row claims a trust level
	// that is not legal for a string originating outside Anvil — i.e.
	// anvil_generated. That is the mislabelling record.Trust documents area
	// B committing.
	RefusalIllegalAdvisoryTrust RefusalReason = "illegal_advisory_trust"

	// RefusalTrustValidationStep: the row's trust level and its named
	// validation step disagree. record.Trust says `verified` means the bytes
	// "passed an explicit validation step that is named in the record ...
	// Never a default", so `verified` with no step named is refused; and a
	// step named beside `untrusted` is refused too, because that is a
	// validation claim attached to bytes nothing validated.
	RefusalTrustValidationStep RefusalReason = "trust_validation_step"

	// RefusalExcerptTooLong: the advisory excerpt exceeds
	// record.MaxAdvisoryExcerptBytes. Ingestion is supposed to have trimmed
	// it; this checks rather than assumes, because the excerpt is the
	// highest-risk external string on the record and the read path's cap
	// (taskcard.go) trims only the AGENT-FACING copy — the untrimmed string
	// would still persist in the record and the store.
	RefusalExcerptTooLong RefusalReason = "excerpt_too_long"

	// RefusalNoLicenceDeclared: the advisory row states neither an SPDX id
	// nor a manual note. plan/00-SPINE.md S8 and the cache's
	// advisory_license_declared CHECK: a row that records neither is data
	// Anvil cannot prove it may use, and it must not be re-published into a
	// record.
	RefusalNoLicenceDeclared RefusalReason = "no_licence_declared"

	// RefusalReasoningNotAnvilGenerated: a reasoning part fell outside the
	// closed vocabulary, so the string about to be labelled anvil_generated
	// might carry external bytes. See composeReasoning.
	RefusalReasoningNotAnvilGenerated RefusalReason = "reasoning_not_anvil_generated"

	// RefusalFingerprint: internal/record refused to compute the digest.
	// Reported, never papered over: a finding that cannot be identified
	// cannot be tracked across scans.
	RefusalFingerprint RefusalReason = "fingerprint_refused"

	// RefusalContractViolation: the assembled Result failed
	// internal/record's own validation. It means this file built something
	// the contract forbids, and the finding is refused rather than emitted.
	RefusalContractViolation RefusalReason = "contract_violation"
)

// refusalReasonOrder is every reason, in a fixed order.
var refusalReasonOrder = []RefusalReason{
	RefusalNoTargetID,
	RefusalUnrecognisedCollector,
	RefusalInconsistentMatch,
	RefusalAdvisoryMismatch,
	RefusalNoAdvisoryID,
	RefusalNoPurl,
	RefusalNoManifestPath,
	RefusalUnsupportedHostEcosystem,
	RefusalNoWatermark,
	RefusalNoAssemblyTime,
	RefusalNegativeStaleness,
	RefusalIllegalAdvisoryTrust,
	RefusalTrustValidationStep,
	RefusalExcerptTooLong,
	RefusalNoLicenceDeclared,
	RefusalReasoningNotAnvilGenerated,
	RefusalFingerprint,
	RefusalContractViolation,
}

// RefusalReasons returns every legal reason, in a fixed order.
func RefusalReasons() []RefusalReason {
	out := make([]RefusalReason, len(refusalReasonOrder))
	copy(out, refusalReasonOrder)
	return out
}

// Valid reports whether r is one of the closed set.
func (r RefusalReason) Valid() bool {
	for _, v := range refusalReasonOrder {
		if v == r {
			return true
		}
	}
	return false
}

// Refusal is a refusal to emit one record, carrying enough identity to be
// counted and reported rather than merely logged.
type Refusal struct {
	Reason    RefusalReason
	Collector string
	Package   string
	Source    string
	SourceID  string
	Detail    string
	// Err is internal/record's own error when the refusal came from the
	// fingerprint or the contract, and nil otherwise.
	Err error
}

func (r *Refusal) Error() string {
	var b strings.Builder
	b.WriteString("lanea: refusing to emit: ")
	b.WriteString(string(r.Reason))
	if r.Source != "" || r.SourceID != "" {
		b.WriteString(" [" + r.Source + "/" + r.SourceID + "]")
	}
	if r.Package != "" {
		b.WriteString(" package=" + strconv.Quote(r.Package))
	}
	if r.Collector != "" {
		b.WriteString(" collector=" + strconv.Quote(r.Collector))
	}
	if r.Detail != "" {
		b.WriteString(": " + r.Detail)
	}
	if r.Err != nil {
		b.WriteString(": " + r.Err.Error())
	}
	return b.String()
}

// Unwrap exposes internal/record's own error so a caller can match on it.
func (r *Refusal) Unwrap() error { return r.Err }

// ---------------------------------------------------------------------------
// Inputs
// ---------------------------------------------------------------------------

// AdvisoryRow is the `advisory` row A.17's deciding range came from, as this
// step needs it.
//
// It is a READ SHAPE, not a second finding: it holds nothing the comparator
// already decided and nothing derived. Its fields mirror
// internal/ingest/cache/schema.go's `advisory` columns one for one, plus the
// per-feed freshness SLO, which lives in internal/ingest/config's FeedConfig
// because "a duration written as a Go constant is precisely the hard-coded
// cadence this package forbids".
//
// This package does not import internal/ingest/cache or internal/ingest/config:
// cache links a SQL driver and neither belongs in the dependency graph of a
// pure field-population step, for exactly the reason internal/match states.
// The caller reads the row and fills this in.
type AdvisoryRow struct {
	// Source and SourceID are `advisory`'s primary key. They must be the
	// pair the MatchResult was decided on.
	Source   string
	SourceID string
	// CVEID is the nullable alias, `advisory.cve_id`.
	CVEID string

	// FeedID is the `feed_state` row that supplied this advisory; it becomes
	// AdvisoryContext.SourceFeed.
	FeedID string
	// SnapshotDigest identifies the advisory corpus this row was read from.
	SnapshotDigest string

	// LicenseSPDX is `advisory.license_spdx`, and LicenseManualNote is
	// `advisory.license_manual_note` — spine S8's manual-override field
	// carrying the quoted operative sentence. At least one must be
	// non-blank, mirroring the cache's advisory_license_declared CHECK.
	LicenseSPDX       string
	LicenseManualNote string

	// Trust is `advisory.anvil_trust`. Legal values are untrusted and
	// verified ONLY: every byte in the advisory table originated outside
	// Anvil, and the column's CHECK says so.
	Trust record.Trust
	// TrustValidationStep NAMES the explicit validation step the row's bytes
	// passed, and is REQUIRED when Trust is verified — record.Trust defines
	// that value as "passed an explicit validation step that is named in the
	// record ... Never a default", so the label without the name is not the
	// value the contract describes. It must be EMPTY when Trust is
	// untrusted. There is no cache column for it today; see deviation 4.
	TrustValidationStep string

	// AsOf is `advisory.as_of`: THE CACHE WATERMARK. It is when this data
	// was current, never when the record was assembled. It is the SECOND
	// term of the emitted staleness_seconds; the first is
	// Emitter.AssembledAt.
	AsOf time.Time
	// StalenessSeconds is `advisory.staleness_seconds`: the PUBLISHER LAG
	// ingestion measured at write time (internal/ingest/delta measures it
	// against Last-Modified at the last successful sync).
	//
	// IT IS NOT THE RECORD'S staleness_seconds AND IS NOT EMITTED. The
	// record's field is assembly time minus AsOf — a different quantity,
	// computed in Emit — and copying this column into it publishes two
	// definitions under one name, which during a feed outage reports
	// weeks-old data as an hour old. This field is carried because
	// AdvisoryRow mirrors the cache's columns one for one and because a
	// negative value is a row this package refuses to re-publish, not
	// because the record consumes it.
	StalenessSeconds int
	// FreshnessSLOSeconds is the feed's freshness_slo_seconds. Zero means
	// the caller did not state one, and BeyondFreshnessSLO then answers
	// false rather than guessing a default.
	FreshnessSLOSeconds int

	// ParseDegraded is `advisory.parse_degraded`: A.16 sets it when a record
	// arrived in a dataVersion the parser did not fully understand. See
	// remediableByAgent for what this package does about it.
	ParseDegraded bool
	// DataVersion is `advisory.data_version`, carried for the operator who
	// has to fix the parser.
	DataVersion string

	// ExcerptText is ingestion's advisory excerpt. Empty when there is none.
	//
	// WHAT IS ESTABLISHED HERE AND WHAT IS NOT. The BOUND is checked: Emit
	// refuses an excerpt longer than record.MaxAdvisoryExcerptBytes rather
	// than asserting that ingestion trimmed it, because the read path's cap
	// (record/taskcard.go) trims only the card the agent sees, so an
	// oversized string would still reach the record and the store.
	//
	// SANITISATION IS NOT CHECKED HERE, and this file does not claim it is.
	// A.3 sanitises at ingest — plan/00-SPINE.md S7, "sanitize at ingest, not
	// at prompt time" — and the vocabulary of invisible and bidi characters
	// that check is defined against lives in internal/ingest/invisible, which
	// this package does not import and must not re-spell: a second definition
	// of "invisible" that drifts from the first is the same defect as a
	// second fingerprint. What would settle it is that vocabulary being
	// exported somewhere internal/record may depend on. Until then this is an
	// UNVERIFIED PRECONDITION, stated as one.
	ExcerptText string

	// The ranking inputs research/24 names non-negotiable.
	// CVSSVector is `advisory.cvss_vector` and CVSSScore `advisory.cvss_score`.
	CVSSVector string
	CVSSScore  *float64
	// EPSSScore/EPSSPercentile/EPSSAsOf and the KEV flags.
	EPSSScore        *float64
	EPSSPercentile   *float64
	EPSSAsOf         *time.Time
	KEVMember        bool
	KEVRansomwareUse bool
}

// Emitter carries the scan context a MatchResult does not: the target the scan
// ran against, and the instant this record is being assembled at.
//
// There is deliberately no CLOCK field — no func() time.Time, no interface with
// a Now on it. See the package header, section 3: the assembly instant is a
// VALUE the caller states once for the whole record, not a source this package
// can read repeatedly. That is also why it is here and not on AdvisoryRow: one
// record has one assembly time, and a per-row field would let two findings in
// one record disagree about when that record was built.
type Emitter struct {
	// TargetID is `target.target_id` rendered as text — field 1 of every
	// anvil-fp/v1 tier. Required.
	TargetID string

	// AssembledAt is the record-assembly instant, owned by the caller that
	// owns the scan (O.2 already holds it). REQUIRED: the zero value is
	// refused rather than treated as "unset", because
	// AdvisoryContext.StalenessSeconds is DEFINED as this minus
	// AdvisoryRow.AsOf, and a zero default would either measure the age
	// against the Unix epoch or quietly reinstate the copy-through bug this
	// field exists to remove.
	AssembledAt time.Time
}

// ---------------------------------------------------------------------------
// Output
// ---------------------------------------------------------------------------

// Emission is one emitted finding: the canonical record.Result, plus the two
// Lane-A-owned facts the frozen record contract has no slot for.
//
// IT IS NOT A PARALLEL FINDING STRUCT. It carries no fingerprint, no package
// identity, no advisory identity and no copy of any field Result already
// holds. Everything about the finding is read from Result; these two exist
// because the contract has nowhere to put them and dropping them would lose,
// respectively, a compliance obligation and the only machine-readable
// statement that a feed missed its SLO. Both are reported to the orchestrator
// as record-contract gaps rather than fixed here — this step must not write to
// the record schema.
type Emission struct {
	// Result is the canonical record. Everything about the finding is here.
	Result record.Result `json:"result"`

	// LicenseManualNote is plan/00-SPINE.md S8's manual-override field: the
	// quoted operative sentence from the publisher's own licence text,
	// required whenever the SPDX id is NONE, NOASSERTION or a LicenseRef-.
	// It is a QUOTATION FROM OUTSIDE ANVIL and carries its own trust inline.
	// Nil when the row states none.
	LicenseManualNote *record.TrustedString `json:"licenseManualNote,omitempty"`

	// FreshnessSLOSeconds is the feed's SLO, carried so a consumer can
	// evaluate BeyondFreshnessSLO without holding the feed table. Zero when
	// the caller stated none.
	FreshnessSLOSeconds int `json:"freshnessSloSeconds"`

	// TrustValidationStep names the explicit validation step the advisory
	// row's bytes passed, and is non-empty exactly when the excerpt and the
	// licence note are classified `verified`. See deviation 4: the frozen
	// record has no slot for it, and `verified` without it is not the value
	// record.Trust defines.
	TrustValidationStep string `json:"trustValidationStep,omitempty"`
}

// RemediableByAgent is the CLAMPED answer, never a copy.
//
// It is a method and not a field for the reason internal/collector/host gives:
// a field is an assignable location, and Lane A exit criterion 21 requires
// that no code path, flag or config key be capable of setting this true for a
// host finding.
//
// AND THE CLAMP TRAVELS IN THE BYTES, NOT ONLY IN THIS METHOD. Every shape that
// leaves this package is built from clamped, so a Result that arrived from
// somewhere other than Emit — hand-built, deserialised, or mutated after
// emission — cannot present a host finding as actionable through ANY of them:
// the top-level `remediableByAgent` mirror, the nested canonical record inside
// the same object, and Results(), which is the projection that actually reaches
// the SARIF log and the store. An earlier revision clamped the mirror only, so
// the object disagreed with itself; the claim is now the whole object's, and
// TestAResultThatDidNotComeFromEmitIsClampedInTheCrossingBytes asserts it on the
// SERIALISED BYTES rather than on this method.
func (e Emission) RemediableByAgent() bool {
	return e.Result.Properties.RemediableByAgent && !record.IsHostFinding(&e.Result)
}

// clamped returns a copy of e whose Result carries the clamped answer.
//
// The copy is what makes the guarantee hold for a Result this package did not
// build: e is a value, and Result is a value field on it, so writing the
// clamped answer here cannot reach the caller's own struct. The maps and
// pointers inside Result are shared with that struct and are NOT written.
func (e Emission) clamped() Emission {
	e.Result.Properties.RemediableByAgent = e.RemediableByAgent()
	return e
}

// BeyondFreshnessSLO reports whether the advisory data this finding rests on
// is older than its feed's freshness SLO.
//
// It answers false when no SLO was stated: an unstated SLO is not a met one,
// but it is also not a breach this package can assert, and asserting one from
// a default would be a claim about a feed nobody configured.
func (e Emission) BeyondFreshnessSLO() bool {
	a := e.Result.Properties.Advisory
	return a != nil && e.FreshnessSLOSeconds > 0 && a.StalenessSeconds > e.FreshnessSLOSeconds
}

// MarshalJSON emits the Emission with `remediableByAgent` and
// `beyondFreshnessSlo` included at the top level.
//
// THIS IS THE ARTIFACT THAT CROSSES THE BOUNDARY, so it is the one that most
// needs both guarantees to travel in the BYTES rather than in a method a
// consumer has to know to call. A.12 found exactly this omission on the
// analogous artifact one lane over. BOTH LEVELS carry the clamped value — the
// mirror and the nested record — so no part of the serialised form can disagree
// with the method or with any other part.
func (e Emission) MarshalJSON() ([]byte, error) {
	c := e.clamped()
	type alias Emission
	return json.Marshal(struct {
		alias
		RemediableByAgent  bool `json:"remediableByAgent"`
		BeyondFreshnessSLO bool `json:"beyondFreshnessSlo"`
	}{alias(c), c.RemediableByAgent(), c.BeyondFreshnessSLO()})
}

// Results projects emissions onto the record.Results a Run carries, in the
// order given. The order is the caller's: match.Match already imposes a total
// order on its output, and re-sorting here would create a second one.
//
// EACH RESULT IS CLAMPED ON THE WAY OUT. This is the projection that reaches
// the SARIF log, record.Validate and the store, so it is the one on which "a
// Result that did not come from Emit cannot present a host finding as
// actionable" has to be true rather than merely documented.
func Results(es []Emission) []record.Result {
	out := make([]record.Result, 0, len(es))
	for _, e := range es {
		out = append(out, e.clamped().Result)
	}
	return out
}

// ---------------------------------------------------------------------------
// The host locator vocabulary
// ---------------------------------------------------------------------------

// hostPackageManagers maps a host ecosystem onto the `package_manager`
// segment of the anvil-fp/v1 host locator.
//
// IT IS AN EXACT-MATCH ALLOWLIST and an unlisted ecosystem is refused, because
// the manager segment is hashed: a guessed manager forks the identity of every
// finding for that ecosystem at once, silently, and fingerprint-keyed
// suppression stops applying with nothing logging an error.
//
// THE `deb` ENTRY IS `apt`, NOT `dpkg`, AND THE CHOICE IS NOT FREE. The frozen
// conformance vector testdata/fingerprint_corpus/host-01-openssl-debian.json
// hashes the locator `apt:openssl:amd64` for a Debian host package, and its
// golden digest was produced by an independent implementation of
// FINGERPRINT-SPEC.md. Spelling it `dpkg` here would produce a valid-looking
// digest that disagrees with the corpus — the exact silent fork S6's
// one-fingerprint rule exists to prevent. emit_test.go pins the emitted digest
// against that golden file rather than against this map.
var hostPackageManagers = map[string]string{
	match.EcosystemDeb: "apt",
	match.EcosystemRPM: "rpm",
	match.EcosystemAPK: "apk",
}

// HostPackageManager resolves a host ecosystem to its locator segment.
func HostPackageManager(ecosystem string) (string, bool) {
	m, ok := hostPackageManagers[ecosystem]
	return m, ok
}

// hostIdentifier composes the host tier's `host_identifier`: the package
// identity as the manager names it.
//
// The architecture suffix is INCLUDED when the collector reported one.
// `openssl:amd64` and `openssl:i386` are two installed packages the manager
// treats separately, so they are two findings — the corpus vector says so in
// its own notes, and internal/collector/host moved the `:arch` qualifier off
// the name precisely so that this decision is made here and not by accident.
// Dropping it would collide two findings onto one digest on every multi-arch
// host.
func hostIdentifier(m match.MatchResult) string {
	if m.Arch == "" {
		return m.Package
	}
	return m.Package + ":" + m.Arch
}

// ---------------------------------------------------------------------------
// The reasoning vocabulary
// ---------------------------------------------------------------------------

// The closed set of sentence fragments `anvil/reasoning` may be built from.
//
// A string classified anvil_generated must be one Anvil wrote — not one Anvil
// formatted around bytes that came from elsewhere. A format string with a %s
// in it cannot make that promise, so there is no format string here: the
// reasoning is JOINED from these constants and from base-10 integers computed
// in this process, and composeReasoning refuses anything else.
const (
	reasonDeterministic = "Deterministic version comparison: the installed version falls inside a range the advisory declares affected. " +
		"No model, no network and no clock participated in this decision."
	reasonVendorRange     = "The deciding range came from a vendor advisory rather than an upstream one."
	reasonVendorDefended  = "A vendor advisory range displaced at least one upstream range for the same advisory and package."
	reasonHostReadOnly    = "This is a host package finding. The coding agent's write surface is the git repository, so it cannot remediate a host package and is never handed one as actionable."
	reasonRepoFixedNamed  = "A fixed version is named, so a dependency version bump is expressible."
	reasonRepoNoFixed     = "The advisory names no fixed version, so there is no bump to propose."
	reasonParseDegraded   = "The advisory record parsed with loss, so this finding is partial: it is reported, and it is not offered to the coding agent as actionable."
	reasonWatermark       = "Age is measured from the ingestion cache watermark to the instant this record was assembled, which the caller supplied; no clock was read while deciding this finding."
	reasonBeyondSLO       = "The advisory data is older than the feed's stated freshness SLO."
	reasonStaleThenSLONum = "Staleness in seconds, then the SLO in seconds:"
	reasonStaleNum        = "Staleness in seconds:"
)

// reasoningVocabulary is the closed set above, as a set.
var reasoningVocabulary = map[string]bool{
	reasonDeterministic:   true,
	reasonVendorRange:     true,
	reasonVendorDefended:  true,
	reasonHostReadOnly:    true,
	reasonRepoFixedNamed:  true,
	reasonRepoNoFixed:     true,
	reasonParseDegraded:   true,
	reasonWatermark:       true,
	reasonBeyondSLO:       true,
	reasonStaleThenSLONum: true,
	reasonStaleNum:        true,
}

// composeReasoning joins parts into the `anvil/reasoning` string, refusing any
// part that is neither a member of reasoningVocabulary nor a base-10 integer.
//
// This is the guard that makes the anvil_generated label on this one string
// true by construction. It is reachable — TestComposeReasoningRefusesAnExternalString
// drives it with a package name and asserts the refusal — because a guard that
// has never failed has not been tested.
func composeReasoning(parts []string) (string, error) {
	if len(parts) == 0 {
		return "", &Refusal{
			Reason: RefusalReasoningNotAnvilGenerated,
			Detail: "no reasoning parts; an empty explanation is not an explanation",
		}
	}
	for i, p := range parts {
		if reasoningVocabulary[p] || isBase10Integer(p) {
			continue
		}
		return "", &Refusal{
			Reason: RefusalReasoningNotAnvilGenerated,
			Detail: "reasoning part " + strconv.Itoa(i) + " " + strconv.Quote(p) +
				" is neither a member of the closed reasoning vocabulary nor an integer Anvil computed; " +
				"a string that interpolates external bytes cannot be labelled " + string(record.TrustAnvilGenerated),
		}
	}
	return strings.Join(parts, " "), nil
}

// isBase10Integer reports whether s is one or more ASCII digits and nothing
// else. No sign, no separators, no Unicode digits: strconv.Atoi would accept a
// leading '+' or '-' and a Unicode-aware check would accept digits from other
// scripts, and neither is something this package produces.
func isBase10Integer(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

// ---------------------------------------------------------------------------
// remediable_by_agent — the ONE place this flag is computed
// ---------------------------------------------------------------------------

// remediableByAgent answers whether the coding agent may be handed this
// finding as actionable.
//
// IT IS AN ALLOWLIST. The answer is false unless every condition below holds,
// so a collector, detector kind, evidence class or ecosystem that does not
// exist today arrives as NOT remediable rather than as remediable-by-omission.
// A denylist of the form "false when host" fails open on precisely the case
// nobody anticipated, and this project has already paid for that shape once.
//
// The conditions, and why each is necessary:
//
//  1. collector == repo-sca. plan/00-SPINE.md S7: the agent writes to the git
//     repository and the host agent is read-only, "not behind a flag". A host
//     package has no file for the agent to edit.
//  2. detectorKind == sca AND evidenceClass == sca. These are re-derived from
//     the collector by detectorFor, and Emit refuses a MatchResult whose own
//     values disagree. Both are checked here as well because
//     record.IsHostFinding reads BOTH, and internal/record's own validator
//     rejects a remediable result carrying either host value — a guard that
//     trusts one field to imply another is a guard with a seam in it.
//  3. THE ECOSYSTEM IS NOT AN OS PACKAGE MANAGER'S. S7 is about the THING,
//     not about who found it: `openssl` from apt is unfixable by a coding
//     agent whether a host collector or a repo-SCA collector noticed it,
//     because the write surface is the git repository either way. Without
//     this arm a repo-sca match carrying Ecosystem=deb emits
//     remediable_by_agent=true, and the agent is handed "bump openssl in
//     Dockerfile" as actionable work against an apt package. That path is not
//     reachable today only because internal/collector/repo refuses Trivy's
//     os-pkgs class — one lane up, in a package this one's guarantee must not
//     depend on. The test is membership of hostPackageManagers, the map this
//     file already owns, so the ecosystem dimension is an allowlist rather
//     than a denylist-by-omission.
//  4. fixedVersion != "". With no fixed version there is no bump to make, and
//     dispatching an agent after a patch that does not exist wastes the one
//     tier that costs money.
//  5. !parseDegraded. A.16 sets parse_degraded when the advisory arrived in a
//     dataVersion the parser did not fully understand — and the fixed version
//     in condition 4 was parsed out of that same record. Handing a
//     repo-credentialed agent a bump to a version half-parsed from a record
//     Anvil admits it did not understand is the "partial finding presenting
//     as whole" defect A.16 exists to prevent. The finding is still EMITTED;
//     it is emitted as report-only. THIS IS A DEVIATION from A.19's sketched
//     expression, which reads only the collector, and it is reported: it can
//     only ever move the answer from true to false.
//
// The function takes no options, reads no configuration and consults no clock,
// so there is no location for an override to live in.
func remediableByAgent(
	collector string,
	kind record.DetectorKind,
	class record.EvidenceClass,
	ecosystem string,
	fixedVersion string,
	parseDegraded bool,
) bool {
	if collector != match.CollectorRepoSCA {
		return false
	}
	if kind != record.DetectorKindSCA || class != record.EvidenceClassSCA {
		return false
	}
	if isHostEcosystem(ecosystem) {
		return false
	}
	if fixedVersion == "" {
		return false
	}
	return !parseDegraded
}

// isHostEcosystem reports whether an ecosystem names an OS package manager's
// world — i.e. whether hostPackageManagers can resolve it.
//
// One map, read from both directions: the host tier uses it to build the
// locator segment, and the allowlist above uses it to refuse an OS package that
// arrived under a repository collector's label. Two lists would drift.
func isHostEcosystem(ecosystem string) bool {
	_, ok := hostPackageManagers[ecosystem]
	return ok
}

// detectorFor re-derives the frozen enums from the collector.
//
// They are DERIVED, not copied off the MatchResult, and Emit then refuses a
// MatchResult whose own values disagree. Reaching a gate is not obeying it:
// trusting a struct field that says `sca` next to a collector that says `host`
// is how an authorization decision gets made by whichever producer wrote the
// struct last.
func detectorFor(collector string) (record.DetectorKind, record.EvidenceClass, bool) {
	switch collector {
	case match.CollectorHost:
		return record.DetectorKindHost, record.EvidenceClassHost, true
	case match.CollectorRepoSCA:
		return record.DetectorKindSCA, record.EvidenceClassSCA, true
	default:
		return "", "", false
	}
}

// ---------------------------------------------------------------------------
// Emit
// ---------------------------------------------------------------------------

// Emit produces the canonical record for one A.17 match.
//
// a must be the `advisory` row the match's deciding range came from; a
// mismatch on (source, source_id) or on the CVE alias is refused rather than
// reconciled, because a record that attributes a finding to the wrong advisory
// is worse than no record.
//
// Every failure is a *Refusal. Nothing is defaulted, and nothing is emitted
// partially: a finding this package cannot state completely is one it declines
// to state.
func (e Emitter) Emit(m match.MatchResult, a AdvisoryRow) (Emission, error) {
	refuse := func(reason RefusalReason, detail string, err error) (Emission, error) {
		return Emission{}, &Refusal{
			Reason:    reason,
			Collector: m.Collector,
			Package:   m.Package,
			Source:    m.Source,
			SourceID:  m.SourceID,
			Detail:    detail,
			Err:       err,
		}
	}

	if strings.TrimSpace(e.TargetID) == "" {
		return refuse(RefusalNoTargetID,
			"the emitter carries no target id; it is field 1 of every anvil-fp/v1 tier", nil)
	}
	if e.AssembledAt.IsZero() {
		return refuse(RefusalNoAssemblyTime,
			"the emitter carries no record-assembly instant; staleness_seconds is defined as "+
				"assembly time minus as_of, this package holds no clock to supply the first term, "+
				"and defaulting it would either measure the age against the Unix epoch or report "+
				"stale feed data as fresh", nil)
	}

	kind, class, ok := detectorFor(m.Collector)
	if !ok {
		return refuse(RefusalUnrecognisedCollector,
			"collector must be "+strconv.Quote(match.CollectorHost)+" or "+
				strconv.Quote(match.CollectorRepoSCA)+"; remediable_by_agent is derived from it "+
				"and an authorization decision must not be defaulted", nil)
	}
	if m.Detector != kind || m.EvidenceClass != class {
		return refuse(RefusalInconsistentMatch,
			"collector implies detector="+string(kind)+" evidenceClass="+string(class)+
				" but the match carries detector="+string(m.Detector)+
				" evidenceClass="+string(m.EvidenceClass), nil)
	}

	// The row must be the row this match was decided on.
	if a.Source != m.Source || a.SourceID != m.SourceID {
		return refuse(RefusalAdvisoryMismatch,
			"advisory row is ["+a.Source+"/"+a.SourceID+"] but the match was decided on ["+
				m.Source+"/"+m.SourceID+"]", nil)
	}
	if a.CVEID != "" && m.CVEID != "" && a.CVEID != m.CVEID {
		return refuse(RefusalAdvisoryMismatch,
			"advisory row's cve alias is "+strconv.Quote(a.CVEID)+
				" but the match carries "+strconv.Quote(m.CVEID), nil)
	}

	advisoryID := advisoryIDOf(m)
	if advisoryID == "" {
		return refuse(RefusalNoAdvisoryID,
			"the match carries neither a cve id nor a source id", nil)
	}
	if m.Purl == "" {
		return refuse(RefusalNoPurl,
			"neither the package nor the deciding advisory range carried a purl, and this step "+
				"will not synthesise one: the namespace comes from os-release, which a MatchResult "+
				"does not carry, and a guessed namespace forks identity", nil)
	}

	// --- The advisory row's own invariants. ---
	if a.AsOf.IsZero() {
		return refuse(RefusalNoWatermark,
			"the advisory row carries no as_of; a finding whose data age is unstated reports "+
				"stale data as fresh, which converts an absence into a false assurance", nil)
	}
	if a.StalenessSeconds < 0 {
		return refuse(RefusalNegativeStaleness,
			"the row's own publisher-lag column is "+strconv.Itoa(a.StalenessSeconds)+
				"; the cache's advisory_staleness_nonneg CHECK refuses it too", nil)
	}
	// THE CONTRACT'S OWN QUANTITY: record-assembly time minus as_of. Not the
	// row's publisher-lag column, which is a different measurement under the
	// same name — see the package header, section 3.
	staleness, ok := stalenessSeconds(e.AssembledAt, a.AsOf)
	if !ok {
		return refuse(RefusalNegativeStaleness,
			"the record is being assembled at "+e.AssembledAt.UTC().Format(time.RFC3339)+
				", which precedes the advisory watermark "+a.AsOf.UTC().Format(time.RFC3339)+
				"; a negative age is not a freshness claim this step can make", nil)
	}
	if n := len(a.ExcerptText); n > record.MaxAdvisoryExcerptBytes {
		return refuse(RefusalExcerptTooLong,
			"the advisory excerpt is "+strconv.Itoa(n)+" bytes and the record's cap is "+
				strconv.Itoa(record.MaxAdvisoryExcerptBytes)+"; the read path trims only the "+
				"agent-facing card, so an untrimmed excerpt would persist in the record and the store", nil)
	}
	if !a.Trust.Valid() {
		return refuse(RefusalIllegalAdvisoryTrust,
			"advisory anvil_trust "+strconv.Quote(string(a.Trust))+" is not a legal record.Trust value", nil)
	}
	if !a.Trust.LegalForExternalString() {
		return refuse(RefusalIllegalAdvisoryTrust,
			"advisory anvil_trust is "+strconv.Quote(string(a.Trust))+
				"; every byte in the advisory table originated outside Anvil, so only "+
				string(record.TrustUntrusted)+" and "+string(record.TrustVerified)+" are legal", nil)
	}
	step := strings.TrimSpace(a.TrustValidationStep)
	if a.Trust == record.TrustVerified && step == "" {
		return refuse(RefusalTrustValidationStep,
			"the advisory row asserts "+string(record.TrustVerified)+" and names no validation step; "+
				"record.Trust defines that value as bytes that passed an explicit validation step "+
				"NAMED IN THE RECORD, never as a default, and a verified label with nothing behind "+
				"it is the mislabelling the trust vocabulary exists to prevent", nil)
	}
	if a.Trust != record.TrustVerified && step != "" {
		return refuse(RefusalTrustValidationStep,
			"the advisory row names the validation step "+strconv.Quote(step)+" but is classified "+
				strconv.Quote(string(a.Trust))+"; a validation claim attached to bytes nothing "+
				"validated launders the step's name onto untrusted text", nil)
	}
	if strings.TrimSpace(a.LicenseSPDX) == "" && strings.TrimSpace(a.LicenseManualNote) == "" {
		return refuse(RefusalNoLicenceDeclared,
			"the advisory row states neither license_spdx nor license_manual_note; spine S8 makes "+
				"that a row Anvil cannot prove it may use, and it must not be re-published into a record", nil)
	}

	// --- The fingerprint. anvil-fp/v1, computed by internal/record. ---
	var (
		digest string
		err    error
	)
	switch kind {
	case record.DetectorKindHost:
		manager, known := HostPackageManager(m.Ecosystem)
		if !known {
			return refuse(RefusalUnsupportedHostEcosystem,
				"host ecosystem "+strconv.Quote(m.Ecosystem)+" has no package-manager mapping; "+
					"the manager segment is hashed into the locator and guessing it forks identity", nil)
		}
		digest, err = record.Host(record.HostInput{
			TargetID:       e.TargetID,
			AdvisoryID:     advisoryID,
			Purl:           m.Purl,
			PackageManager: manager,
			HostIdentifier: hostIdentifier(m),
		})
	case record.DetectorKindSCA:
		if m.ManifestRelPath == "" {
			return refuse(RefusalNoManifestPath,
				"a repo-sca match carries no manifest relpath; it is the SCA tier's locator, and "+
					"the same package pulled in by two manifests is two findings", nil)
		}
		digest, err = record.Sca(record.ScaInput{
			TargetID:        e.TargetID,
			AdvisoryID:      advisoryID,
			Purl:            m.Purl,
			ManifestRelPath: m.ManifestRelPath,
		})
	}
	if err != nil {
		return refuse(RefusalFingerprint,
			"internal/record refused to compute the anvil-fp/v1 digest", err)
	}

	// --- The seven Lane-A-owned fields. ---
	remediable := remediableByAgent(m.Collector, kind, class, m.Ecosystem, m.FixedVersion, a.ParseDegraded)

	beyondSLO := a.FreshnessSLOSeconds > 0 && staleness > a.FreshnessSLOSeconds

	reasoning, err := composeReasoning(reasoningParts(m, a, staleness, beyondSLO))
	if err != nil {
		return Emission{}, err
	}

	res := record.Result{
		RuleID:  advisoryID,
		Message: record.Message{Text: messageText(m, advisoryID)},
		PartialFingerprints: map[string]string{
			record.PartialFingerprintAnvilFindingID: digest,
		},
		Properties: record.ResultProperties{
			FindingID: digest,
			Half:      record.HalfSast,
			// Detector certainty, not data freshness. The comparison is
			// deterministic, so it is 1. Degradation is expressed as a
			// VERDICT, per plan/00-SPINE.md S6: "INSUFFICIENT_CONTEXT as a
			// valid detector verdict, not just a confidence float."
			Confidence:        1,
			Verdict:           verdictFor(a.ParseDegraded),
			RemediableByAgent: remediable,
			Reasoning:         reasoning,
			Detector: record.DetectorRef{
				Kind: kind,
				// Model and Revision are EMPTY, and that is the honest
				// statement: plan/00-SPINE.md S1 makes Lane A zero-inference
				// and internal/match documents that there is no model
				// anywhere in its call graph. Naming one here would assert
				// an inference step that does not exist. The build stamp
				// belongs on run.tool.driver, which this step does not own.
				AdvisoryItemID: advisoryID,
			},
			EvidenceClass: class,
			Trust: record.TrustAssertion{
				// UNCONDITIONALLY untrusted. Package names, versions, purls,
				// manifest paths, advisory ids and the excerpt all came from
				// outside Anvil, and so does every string composed around
				// them. Fields names the one string Anvil itself wrote, and
				// composeReasoning is what makes that label true.
				Default: record.TrustUntrusted,
				Fields: map[string]record.Trust{
					reasoningPointer: record.TrustAnvilGenerated,
				},
			},
			Advisory: &record.AdvisoryContext{
				IDs:            []string{advisoryID},
				CveIDs:         cveIDs(m, a),
				SourceFeed:     a.FeedID,
				SnapshotDigest: a.SnapshotDigest,
				LicenseSpdx:    a.LicenseSPDX,
				// AsOf IS THE CACHE WATERMARK, never a clock reading.
				// StalenessSeconds is the contract's own interval — the
				// caller's assembly instant minus that watermark — and NOT
				// the row's publisher-lag column, which measures something
				// else. See the package header, section 3.
				AsOf:             a.AsOf.UTC(),
				StalenessSeconds: staleness,
				ParseDegraded:    a.ParseDegraded,
				Excerpt:          excerpt(a),
			},
			Risk: riskOf(a),
		},
	}
	if loc := manifestLocation(m); loc != nil {
		res.Locations = []record.Location{*loc}
	}

	// The contract's own validator, applied before this leaves the function.
	// It re-checks the host rule from the other side (it refuses a remediable
	// result carrying DetectorKindHost or EvidenceClassHost) and it re-checks
	// the trust classification. A producer that fails here has built something
	// the record forbids, and must not hand it on.
	if err := validateEmitted(&res); err != nil {
		return refuse(RefusalContractViolation,
			"the assembled result failed internal/record's own validation", err)
	}

	return Emission{
		Result:              res,
		LicenseManualNote:   manualNote(a),
		FreshnessSLOSeconds: a.FreshnessSLOSeconds,
		TrustValidationStep: step,
	}, nil
}

// stalenessSeconds is AdvisoryContext.StalenessSeconds as the frozen contract
// defines it: record-assembly time minus the advisory watermark, in whole
// seconds, truncated toward zero.
//
// It reports false rather than a negative number when the watermark is in the
// future relative to assembly. A negative age is not a freshness claim this
// step can make, and clamping it to zero would state "current as of now" about
// data whose own timestamps say otherwise.
func stalenessSeconds(assembledAt, asOf time.Time) (int, bool) {
	d := assembledAt.Sub(asOf)
	if d < 0 {
		return 0, false
	}
	return int(d / time.Second), true
}

// EmitAll emits every match in order, resolving each one's advisory row
// through lookup.
//
// The order is the caller's — match.Match already imposes a total order on its
// output — and the first refusal stops the run, which is deterministic for the
// same reason. A match whose advisory row cannot be resolved is a refusal, not
// a skip: a finding silently dropped between the comparator and the record is
// indistinguishable from a clean scan.
func (e Emitter) EmitAll(
	ms []match.MatchResult,
	lookup func(source, sourceID string) (AdvisoryRow, bool),
) ([]Emission, error) {
	if lookup == nil {
		return nil, &Refusal{
			Reason: RefusalAdvisoryMismatch,
			Detail: "EmitAll needs a lookup for the advisory rows the matches were decided on",
		}
	}
	out := make([]Emission, 0, len(ms))
	for _, m := range ms {
		row, ok := lookup(m.Source, m.SourceID)
		if !ok {
			return nil, &Refusal{
				Reason:    RefusalAdvisoryMismatch,
				Collector: m.Collector,
				Package:   m.Package,
				Source:    m.Source,
				SourceID:  m.SourceID,
				Detail: "no advisory row resolved for the range that decided this match; " +
					"a finding dropped here is indistinguishable from a clean scan",
			}
		}
		em, err := e.Emit(m, row)
		if err != nil {
			return nil, err
		}
		out = append(out, em)
	}
	return out, nil
}

// ---------------------------------------------------------------------------
// Field derivation
// ---------------------------------------------------------------------------

// reasoningPointer is the RFC 6901 pointer, relative to the result, of the
// `anvil/reasoning` string. The '/' inside the property key is escaped as
// '~1' per RFC 6901 §3.
const reasoningPointer = "/properties/anvil~1reasoning"

// advisoryIDOf is the advisory identity hashed into the fingerprint and
// written to `ruleId`.
//
// The CVE id when there is one, the source id otherwise. That is A.17's own
// precedence group (AffectedRange.advisoryKey), and it is the right way round:
// GHSA advisories frequently carry no CVE at all (research/06 Risk #2), and
// grouping those under one empty key would let unrelated advisories collide.
// It is used VERBATIM and never case-folded — GHSA identifiers mix case
// meaningfully and folding them would fork identity against the advisory
// table (FINGERPRINT-SPEC.md §2.2, field 3).
func advisoryIDOf(m match.MatchResult) string {
	if m.CVEID != "" {
		return m.CVEID
	}
	return m.SourceID
}

// cveIDs returns the CVE aliases, or nil when the advisory carries none. Nil
// rather than a one-element slice holding "": an empty string in a list of
// identifiers is a value a consumer will try to look up.
func cveIDs(m match.MatchResult, a AdvisoryRow) []string {
	switch {
	case m.CVEID != "":
		return []string{m.CVEID}
	case a.CVEID != "":
		return []string{a.CVEID}
	default:
		return nil
	}
}

// verdictFor maps A.16's parse_degraded flag onto the record's verdict.
//
// A deterministic version comparison against a fully-understood advisory is a
// true positive by construction: the installed version IS inside the declared
// range. When the advisory record parsed with loss, the range itself is
// partial, and plan/00-SPINE.md S6's insufficient_context is the exact
// statement — "this may well be a real defect and the detector could not see
// enough to tell". The consumption pipeline demotes it to report-only and
// never silently drops it, which is the handling a partial finding needs.
//
// STALENESS DOES NOT ENTER HERE. See the package header, section 3.
func verdictFor(parseDegraded bool) record.Verdict {
	if parseDegraded {
		return record.VerdictInsufficientContext
	}
	return record.VerdictTruePositive
}

// reasoningParts builds the ordered parts of `anvil/reasoning`. Every element
// is a constant from the closed vocabulary or an integer computed here;
// composeReasoning enforces that.
//
// staleness is the COMPUTED interval Emit wrote onto the record, passed in
// rather than re-derived, so that the number a human reads in the prose and the
// number a machine reads in the field cannot drift apart.
func reasoningParts(m match.MatchResult, a AdvisoryRow, staleness int, beyondSLO bool) []string {
	parts := []string{reasonDeterministic}
	if m.VendorAdvisory {
		parts = append(parts, reasonVendorRange)
	}
	if m.DistroBackportDefended {
		parts = append(parts, reasonVendorDefended)
	}
	if m.Collector == match.CollectorHost {
		parts = append(parts, reasonHostReadOnly)
	} else if m.FixedVersion != "" {
		parts = append(parts, reasonRepoFixedNamed)
	} else {
		parts = append(parts, reasonRepoNoFixed)
	}
	if a.ParseDegraded {
		parts = append(parts, reasonParseDegraded)
	}
	parts = append(parts, reasonWatermark)
	if beyondSLO {
		parts = append(parts, reasonBeyondSLO, reasonStaleThenSLONum,
			strconv.Itoa(staleness), strconv.Itoa(a.FreshnessSLOSeconds))
	} else {
		parts = append(parts, reasonStaleNum, strconv.Itoa(staleness))
	}
	return parts
}

// messageText is the human-readable statement of the finding.
//
// It INTERPOLATES EXTERNAL STRINGS — the package name, the installed version,
// the advisory id, the range expression — and is therefore untrusted, which
// the result's TrustAssertion.Default already says. That is exactly why the
// reasoning string is built separately and from constants: one field states
// the facts as reported, the other states what Anvil did, and only the second
// can honestly be labelled anvil_generated.
func messageText(m match.MatchResult, advisoryID string) string {
	var b strings.Builder
	b.WriteString(advisoryID)
	b.WriteString(": ")
	b.WriteString(m.Package)
	if m.Arch != "" {
		b.WriteString(" (")
		b.WriteString(m.Arch)
		b.WriteString(")")
	}
	b.WriteString(" ")
	b.WriteString(m.InstalledVersion)
	b.WriteString(" is inside the affected range ")
	b.WriteString(m.MatchedRange)
	if m.FixedVersion != "" {
		b.WriteString("; fixed in ")
		b.WriteString(m.FixedVersion)
	} else {
		b.WriteString("; the advisory names no fixed version")
	}
	b.WriteString(".")
	return b.String()
}

// excerpt wraps the advisory excerpt with the trust the `advisory` row itself
// recorded. Nil when there is no excerpt: an empty TrustedString would put an
// empty quotation on the record.
//
// The BOUND is checked by Emit before this is reached, and `verified` without a
// named validation step is refused there too. Sanitisation is NOT established
// here; AdvisoryRow.ExcerptText says exactly what is and is not known about
// these bytes, and this function makes no claim beyond that.
func excerpt(a AdvisoryRow) *record.TrustedString {
	if a.ExcerptText == "" {
		return nil
	}
	return &record.TrustedString{Text: a.ExcerptText, Trust: a.Trust}
}

// manualNote wraps spine S8's manual-override sentence with its trust. It is a
// QUOTATION from a publisher's LICENSE file, so it is external text and takes
// the row's own trust level — never anvil_generated, however Anvil-shaped the
// struct around it looks.
func manualNote(a AdvisoryRow) *record.TrustedString {
	if strings.TrimSpace(a.LicenseManualNote) == "" {
		return nil
	}
	return &record.TrustedString{Text: a.LicenseManualNote, Trust: a.Trust}
}

// cvss40Prefix is the CVSS v4.0 vector prefix. record.Risk.CvssV4Base is
// explicitly the v4 base score.
const cvss40Prefix = "CVSS:4.0/"

// riskOf carries research/24's ranking inputs. record.Risk names Lane A
// ingestion as its producer, which is this step.
//
// CvssV4Base IS SET ONLY FOR A v4 VECTOR. The cache stores one cvss_score
// column beside one cvss_vector, and the score for a v3.1 vector is not a v4
// base score: writing it into a field named CvssV4Base would put a number in
// the record that is wrong in a way no consumer can detect. A v3.1 row
// therefore contributes EPSS and KEV and leaves the CVSS slot null, which is
// the honest reading.
func riskOf(a AdvisoryRow) *record.Risk {
	r := record.Risk{
		EpssScore:        a.EPSSScore,
		EpssPercentile:   a.EPSSPercentile,
		EpssModelDate:    a.EPSSAsOf,
		KevMember:        a.KEVMember,
		KevRansomwareUse: a.KEVRansomwareUse,
	}
	if a.CVSSScore != nil && strings.HasPrefix(a.CVSSVector, cvss40Prefix) {
		r.CvssV4Base = a.CVSSScore
	}
	if r.CvssV4Base == nil && r.EpssScore == nil && r.EpssPercentile == nil &&
		r.EpssModelDate == nil && !r.KevMember && !r.KevRansomwareUse {
		return nil
	}
	return &r
}

// manifestLocation is the SARIF-native location for a repository dependency:
// the manifest that declared it.
//
// There is no Region, so no line hash is required and none is invented — the
// dependency is declared by the file, not by a line, and a fabricated line
// number would be a claim about the file this step has not read. A host
// package has no repo-relative location at all and gets none, which is also
// what makes it visibly not something the agent can edit.
func manifestLocation(m match.MatchResult) *record.Location {
	if m.Collector != match.CollectorRepoSCA || m.ManifestRelPath == "" {
		return nil
	}
	uri := record.CanonicalRepoRelPath(m.ManifestRelPath)
	if uri == "" {
		return nil
	}
	return &record.Location{
		PhysicalLocation: &record.PhysicalLocation{
			ArtifactLocation: record.ArtifactLocation{URI: uri},
		},
	}
}

// validateEmitted runs internal/record's own per-result checks on a freshly
// assembled result, by putting it through the contract's whole-record
// validator inside a minimal, well-formed envelope.
//
// The envelope is scaffolding for the check and is thrown away: this step does
// not own the audit envelope, and the scan controller (O.2) assembles the real
// one. What matters is that Result.validate runs — it is where the record
// refuses a remediable host finding from the other side, and where
// ValidateResultTrust refuses an anvil_generated classification on an external
// string.
func validateEmitted(res *record.Result) error {
	// THE RECORD'S OWN TRUST VALIDATOR IS VACUOUS FOR A LANE A RESULT, AND
	// SAYING SO IS THE POINT. record.Result.ExternalStringPointers enumerates
	// SARIF-native slots that hold external text — region snippets, code-flow
	// snippets, the DAST response body — and an SCA or host finding carries
	// none of them. So ValidateResultTrust below iterates an empty list and
	// would accept ANY Default, including the anvil_generated that record.Trust
	// documents area B being caught with. Verified empirically: setting Default
	// to anvil_generated in this file passes record's whole-record Validate.
	//
	// The untrusted default is therefore not enforced by the contract for this
	// shape; it is enforced HERE, on the emitted value, so that the guarantee
	// is a property of the code rather than of a test that could be deleted.
	if res.Properties.Trust.Default != record.TrustUntrusted {
		return fmt.Errorf(
			"anvil/trust.default is %q; every Lane A result is built from package names, "+
				"versions, purls, manifest paths and advisory text that originated outside "+
				"Anvil, so the default is %q unconditionally (00-SPINE.md S6)",
			res.Properties.Trust.Default, record.TrustUntrusted)
	}
	for ptr, tr := range res.Properties.Trust.Fields {
		if tr == record.TrustAnvilGenerated && ptr != reasoningPointer {
			return fmt.Errorf(
				"%s is classified %q; the only string this step writes itself is %s",
				ptr, tr, reasoningPointer)
		}
	}

	sealedAt := time.Unix(0, 0).UTC()
	createdAt := time.Unix(0, 0).UTC()
	log := record.SARIFLog{
		Schema:  record.SARIFSchemaURI,
		Version: record.SARIFVersion,
		Properties: record.AuditProperties{
			SchemaVersion: record.SchemaVersion,
			AuditID:       "validate-emitted",
			State:         record.StateBothSealed,
			Version:       1,
			CreatedAt:     createdAt,
			// Placeholders in throwaway scaffolding: the enums have no
			// "not applicable" member and this envelope is never emitted.
			Target: record.Target{
				Provenance:   record.TargetProvenanceNoTargetDeclared,
				Provisioning: record.TargetProvisioningEphemeralManifest,
			},
			DastStatus: record.DastStatusNotRun,
			Deadline: record.Deadline{
				DeadlineAt:          createdAt.Add(record.DefaultClaimTimeoutSeconds * time.Second),
				ClaimTimeoutSeconds: record.DefaultClaimTimeoutSeconds,
			},
		},
		Runs: []record.Run{{
			AutomationDetails: record.RunAutomationDetails{CorrelationGUID: "validate-emitted"},
			Results:           []record.Result{*res},
			Properties: record.RunProperties{
				Half:     record.HalfSast,
				Status:   record.HalfStatusSealed,
				SealedAt: &sealedAt,
			},
		}},
	}
	if err := log.Validate(); err != nil {
		return err
	}
	// Belt and braces: ValidateResultTrust is reached through Validate, but
	// it is the check that would have caught area B's mislabelling and it is
	// cheap enough to state twice rather than to depend on one call chain.
	return record.ValidateResultTrust(res)
}

// assert at compile time that Emission satisfies json.Marshaler, so that a
// future edit removing MarshalJSON — and with it the serialised
// remediableByAgent guarantee — fails to build rather than silently shipping.
var _ json.Marshaler = Emission{}
