// Package record aggregates area D's per-tier inventory facts into the
// record-level coverage fields internal/record freezes: `dast_coverage`
// (record.DastCoverage), `endpoint_coverage`, `server_line_coverage` and
// `inventory_provenance`, plus the two target fields `target_provenance`
// (record.TargetProvenance) and `target.provisioning`
// (record.TargetProvisioning).
//
// This is plan/50-dast.md D.26. It produces THE NUMBER AN OPERATOR TRUSTS, so
// every design decision below is about the number looking better than the
// evidence behind it.
//
// # It declares no record enum and it derives no status by hand
//
// plan/50-dast.md:1149's five-value `dast_status` enum is STALE.
// internal/record/contract.go owns the ten-value anvil/dastStatus vocabulary
// and internal/record/contract_test.go rejects the plan's literals by name.
// Nothing here writes a status literal: Summary.DeriveDastStatus calls
// record.DeriveDastStatus with a record.DastOutcome, so the mapping lives in
// exactly one place and this package supplies only the one bit it is qualified
// to supply — PartialCoverage.
//
// Likewise plan/50-dast.md:1150's `target_provenance` {ephemeral_manifest,
// live_url_authorized} is stale: those two literals are
// record.TargetProvisioning, a SEPARATE FIELD from record.TargetProvenance's
// boot/reachability outcome (plan/IMPLEMENTATION-PLAN.md section 6, rulings
// G4+G7). Both travel through Summary and neither is merged into the other.
//
// # The four ways the fraction lies, and what is done about each
//
// endpoint_coverage is confirmed-probed endpoints over the union of the Tier
// 0-2 inventory. Never a raw request count — the request count is available
// separately as inventory.ConfirmResult.Issued(), and the two are deliberately
// not the same number so a reader can see how many requests bought how many
// confirmations.
//
//  1. THE NUMERATOR INFLATED. Watched by everyone, and already structurally
//     defended by D.22: only an endpoint Anvil OBSERVED through the kernel is
//     confirmed. This package re-runs D.22's two evidence assertions
//     (AssertEveryConfirmationHasEvidence, its converse) as part of
//     Summarize, so a numerator that cannot be traced to kernel-admitted
//     requests never reaches a record. plan/50-dast.md:632-635 calls Tier 1
//     routes "confirmed"; that is overridden — a document is not an
//     observation.
//
//  2. THE DENOMINATOR SHRUNK, so coverage goes UP. Nobody investigates a
//     number that improved. Three shrinking mechanisms are handled here:
//
//     a. Surface a tier SAW and could not represent. Each tier reports it as
//     DenominatorFloor() minus its route count — per-operation refusals plus
//     floor-raising caveats. Those items are not in the merged union (they
//     never became routes), so InventoryUnionCount() adds them. They can
//     double-count across tiers; that direction is pessimistic and therefore
//     the acceptable one.
//
//     b. An unsupported language (D.21). It hides an UNKNOWN number of
//     endpoints, so D.21 deliberately adds nothing to its floor and returns
//     an error from AssertDenominatorIsComplete instead. Consumed here as
//     QualifierUnsupportedLanguage, direction Overstates.
//
//     c. Truncation at a coded bound, in the union or in a tier. Same
//     direction, its own qualifier.
//
//  3. THE DENOMINATOR INFLATED by duplicates, so coverage goes DOWN. Nobody
//     investigates that either. D.22's merge is the defence: the union is
//     keyed on (method, canonical path) using the package's single
//     canonicalizer, and an endpoint named by three tiers is ONE row with
//     three provenances. That is why InventoryProvenanceMix is a mix whose
//     values sum to more than the denominator, and why AssertMixDecomposes
//     checks the mix against the per-endpoint rows rather than against a
//     second tally of the same list.
//
//  4. GRAPHQL COLLAPSE, the deflation D.22 hands over as OperationCount().
//     THE DECISION, and the reason: OperationCount does NOT become the
//     denominator. record.ValidateDastCoverage checks EndpointCoverage
//     against ProbedCount/InventoryUnionCount, and ProbedCount is confirmed
//     ENDPOINTS; dividing endpoints by operations is not a smaller fraction,
//     it is a type error, and one confirmed address over forty root fields is
//     not "2.5% covered" in any sense an operator could act on. But
//     collapsing forty root fields onto one address does mean one
//     confirmation buys the whole address, which OVERSTATES. So the number
//     stays commensurable and the collapse is made VISIBLE: OperationCount()
//     is carried beside EndpointCount() on the Summary, and whenever it
//     exceeds it, QualifierOperationsCollapsed records both numbers with
//     direction Overstates. Priced in silently it would be invisible;
//     substituted into the denominator it would be wrong.
//
// # Zero coverage and unknown coverage are different facts
//
// An operator acts differently on "we probed 50 endpoints and confirmed none"
// and "we never probed anything". Both would render as 0.0. So Coverage()
// RETURNS AN ERROR rather than a fraction when the number cannot be computed
// honestly — an empty union, a handoff that was never wired, a confirmation
// loop the target never answered. Determinacy() names which of the three
// states the summary is in and Qualifiers() decomposes it.
//
// # server_line_coverage is nullable and the nil is load-bearing
//
// It is populated on scheduled full scans only, by a language coverage agent
// inside the sandbox. NULL on incremental scans, NOT zero: zero reads as "we
// measured and covered nothing", which is the same silent-clean failure as
// reporting an unscanned target clean. ScanModeIncremental with a non-nil
// value is REFUSED rather than quietly dropped, because dropping it and
// keeping it are both wrong and only a refusal makes the caller decide.
//
// Sources: plan/50-dast.md D.26 (lines 833-869) and the Coverage Reporting
// Contract (lines 1142-1160); plan/00-SPINE.md S6; internal/record/contract.go
// (DastCoverage, InventoryProvenance, TargetProvenance, TargetProvisioning);
// research/22-attack-surface-discovery.md lines 364-374 and Risk #4;
// research/23-dast-signal-sources.md Risk #1.
package record

import (
	"errors"
	"fmt"
	"math"
	"sort"
	"strings"

	"github.com/Susquehanna-Syntax/Anvil/internal/dast/inventory"
	rec "github.com/Susquehanna-Syntax/Anvil/internal/record"
)

// ---------------------------------------------------------------------------
// Sentinel errors
// ---------------------------------------------------------------------------

var (
	// ErrRefused is the package's refusal sentinel, matching the convention
	// the rest of the DAST tree uses.
	ErrRefused = errors.New("dastrecord: refused")

	// ErrUnconstructed is returned when a value that has exactly one
	// constructor arrives without having been through it.
	ErrUnconstructed = errors.New("dastrecord: value did not come from its constructor")

	// ErrCoverageNotComputable is what Coverage() returns when there is no
	// honest fraction to report.
	//
	// It is an error and not a 0.0 because zero coverage and unknown
	// coverage are different facts. A caller that wants to write a record
	// anyway has to handle this explicitly, which is the point.
	ErrCoverageNotComputable = errors.New("dastrecord: endpoint_coverage cannot be computed honestly")

	// ErrTiersNotMerged is returned when the tier results handed to
	// Summarize are not the ones that produced the union.
	//
	// The unrepresented-surface arithmetic subtracts each tier's route count
	// from its DenominatorFloor and adds the remainder to the denominator.
	// That is only sound if those routes are exactly the routes the merge
	// consumed. A mismatch means the denominator would be assembled from two
	// different runs, so it refuses rather than producing a plausible number.
	ErrTiersNotMerged = errors.New("dastrecord: the tier results are not the ones that produced the union")

	// ErrMixDoesNotDecompose is returned when the record-level provenance
	// summary cannot be reconstructed from the per-endpoint rows.
	//
	// inventory_provenance is per-route and is "aggregated to a record-level
	// summary in D.26. This is what makes the SAST->DAST handoff auditable."
	// A summary nobody can decompose is a claim, not evidence.
	ErrMixDoesNotDecompose = errors.New("dastrecord: the provenance summary does not decompose into its rows")
)

// ---------------------------------------------------------------------------
// ScanMode — the reason server_line_coverage is a pointer
// ---------------------------------------------------------------------------

// ScanMode says which kind of scan this record describes.
//
// FAIL CLOSED: the zero value is ScanModeUnset and Summarize refuses it. There
// is no default, because the default would decide whether a nil
// server_line_coverage is legal, and that is exactly the decision the caller
// must make explicitly.
type ScanMode string

const (
	// ScanModeUnset is the zero value and names nothing.
	ScanModeUnset ScanMode = ""

	// ScanModeIncremental is the per-change scan. server_line_coverage is
	// NULL on these — not zero. There is no coverage agent in the loop, so
	// there is no measurement, and zero would read as one.
	ScanModeIncremental ScanMode = "incremental"

	// ScanModeScheduledFull is the scheduled full scan, the only mode in
	// which a language coverage agent runs inside the sandbox and the only
	// mode in which server_line_coverage may carry a number. It may still be
	// NULL here: a full scan whose coverage agent did not run measured
	// nothing, and nothing is not zero.
	ScanModeScheduledFull ScanMode = "scheduled_full"
)

// ScanModeValues returns every legal literal, excluding the zero value.
func ScanModeValues() []ScanMode { return []ScanMode{ScanModeIncremental, ScanModeScheduledFull} }

// Valid reports whether m is one of the legal literals.
func (m ScanMode) Valid() bool {
	for _, k := range ScanModeValues() {
		if k == m {
			return true
		}
	}
	return false
}

// AllowsServerLineCoverage reports whether this mode may carry a
// server_line_coverage value at all.
func (m ScanMode) AllowsServerLineCoverage() bool { return m == ScanModeScheduledFull }

// ---------------------------------------------------------------------------
// Determinacy — what kind of thing the number is
// ---------------------------------------------------------------------------

// Determinacy says whether endpoint_coverage is a measurement, a measurement
// with known distortion, or not a measurement at all.
type Determinacy string

const (
	// DeterminacyUnset is the zero value and names nothing.
	DeterminacyUnset Determinacy = ""

	// DeterminacyMeasured: every tier that ran reported a complete
	// denominator, nothing truncated, the confirmation loop reached the
	// target and the budget sufficed. The fraction means what it says.
	DeterminacyMeasured Determinacy = "measured"

	// DeterminacyQualified: a fraction exists and at least one qualifier
	// says which direction it is wrong in. Qualifiers() names each.
	DeterminacyQualified Determinacy = "qualified"

	// DeterminacyUnknown: there is no honest fraction. Coverage() refuses.
	// This is NOT 0.0 and a consumer must not render it as one.
	DeterminacyUnknown Determinacy = "unknown"
)

// DeterminacyValues returns every legal literal, excluding the zero value.
func DeterminacyValues() []Determinacy {
	return []Determinacy{DeterminacyMeasured, DeterminacyQualified, DeterminacyUnknown}
}

// Valid reports whether d is one of the legal literals.
func (d Determinacy) Valid() bool {
	for _, k := range DeterminacyValues() {
		if k == d {
			return true
		}
	}
	return false
}

// Computable reports whether a fraction may be published at all.
func (d Determinacy) Computable() bool {
	return d == DeterminacyMeasured || d == DeterminacyQualified
}

// ---------------------------------------------------------------------------
// Qualifier — the direction the number is wrong in
// ---------------------------------------------------------------------------

// Direction names which way a qualifier moves the reported number relative to
// the truth. It is relative to TRUE coverage, never to some other computation.
type Direction string

const (
	// DirectionUnset is the zero value and names nothing.
	DirectionUnset Direction = ""

	// DirectionOverstates: the reported fraction is HIGHER than the truth,
	// because the denominator is missing surface that exists. This is the
	// dangerous direction — the metric improves because the tool got worse.
	DirectionOverstates Direction = "overstates"

	// DirectionUnderstates: the reported fraction is LOWER than the truth,
	// because Anvil's own limits suppressed the numerator. research/22's
	// Risk #4, the phpBB regression, is this one.
	DirectionUnderstates Direction = "understates"

	// DirectionUncomputable: there is no fraction to be wrong.
	DirectionUncomputable Direction = "uncomputable"
)

// QualifierReason enumerates every way this package knows the fraction is not
// a plain measurement.
type QualifierReason string

const (
	// QualifierUnset is the zero value and names nothing.
	QualifierUnset QualifierReason = ""

	// QualifierUnsupportedLanguage: D.21 found source in a language with no
	// extractor. Its endpoints are absent from the union by an UNKNOWN
	// amount, which is why D.21 refuses to add one to its own floor.
	QualifierUnsupportedLanguage QualifierReason = "unsupported_language_present"

	// QualifierUnionTruncated: the merge hit its coded endpoint bound.
	QualifierUnionTruncated QualifierReason = "union_hit_a_coded_bound"

	// QualifierTierTruncated: a tier stopped adding at a coded bound.
	QualifierTierTruncated QualifierReason = "tier_hit_a_coded_bound"

	// QualifierTierHandoffUnwired: a tier ran against nothing — the SAST
	// harvest was skipped, or no endpoint was ever reached. Its share of the
	// denominator is a fact about Anvil, not about the target.
	QualifierTierHandoffUnwired QualifierReason = "tier_handoff_unwired"

	// QualifierTierFactsAbsent: NO tier result was supplied at all, so the
	// denominator is the merged union with no floor correction on it.
	//
	// It is a qualifier and not a refusal because the union itself is real
	// and its numerator is real. What is missing is every tier's record of
	// surface it SAW and could not represent — refusals and floor-raising
	// caveats — and that omission can only shrink the denominator. The
	// magnitude is unknown, which is exactly why this cannot be corrected
	// for and can only be stated.
	QualifierTierFactsAbsent QualifierReason = "tier_facts_absent"

	// QualifierOperationsCollapsed: more operations than addresses. See the
	// package doc, decision 4.
	QualifierOperationsCollapsed QualifierReason = "operations_collapsed_onto_addresses"

	// QualifierProbeBudgetExhausted: endpoints in the union were never
	// attempted because the configured budget was spent. The fraction is a
	// statement about the budget as much as about the target.
	QualifierProbeBudgetExhausted QualifierReason = "probe_budget_exhausted"

	// QualifierNothingProbed: the confirmation loop never got an answer out
	// of the target, so the numerator is zero for a reason that is about
	// Anvil's reach. Uncomputable.
	QualifierNothingProbed QualifierReason = "target_never_answered"

	// QualifierEmptyUnion: no tier contributed anything. Uncomputable — a
	// denominator of zero is the shape every "100% covered" report is made
	// of.
	QualifierEmptyUnion QualifierReason = "inventory_union_is_empty"

	// QualifierInventoryAbsent: there is no inventory at all, because the
	// DAST half never got that far. Uncomputable.
	QualifierInventoryAbsent QualifierReason = "no_inventory_was_produced"
)

// QualifierReasonValues returns every legal reason, in the order they are
// reported.
func QualifierReasonValues() []QualifierReason {
	return []QualifierReason{
		QualifierInventoryAbsent, QualifierEmptyUnion, QualifierNothingProbed,
		QualifierUnsupportedLanguage, QualifierUnionTruncated, QualifierTierTruncated,
		QualifierTierHandoffUnwired, QualifierTierFactsAbsent,
		QualifierOperationsCollapsed, QualifierProbeBudgetExhausted,
	}
}

// qualifierDirections is the ALLOWLIST mapping each reason onto the direction
// it moves the number.
//
// It is a map from the enum rather than a field on each Qualifier value for
// the reason every other allowlist in this tree is a map: a per-instance
// direction is a per-instance typo, and two call sites emitting the same
// reason with opposite directions would be undetectable. A reason absent from
// this map is not a legal reason, and Qualifier.Valid says so.
func qualifierDirections() map[QualifierReason]Direction {
	return map[QualifierReason]Direction{
		QualifierUnsupportedLanguage:  DirectionOverstates,
		QualifierUnionTruncated:       DirectionOverstates,
		QualifierTierTruncated:        DirectionOverstates,
		QualifierTierHandoffUnwired:   DirectionOverstates,
		QualifierTierFactsAbsent:      DirectionOverstates,
		QualifierOperationsCollapsed:  DirectionOverstates,
		QualifierProbeBudgetExhausted: DirectionUnderstates,
		QualifierNothingProbed:        DirectionUncomputable,
		QualifierEmptyUnion:           DirectionUncomputable,
		QualifierInventoryAbsent:      DirectionUncomputable,
	}
}

// Recognised reports whether q is one of the enumerated reasons.
func (q QualifierReason) Recognised() bool {
	_, ok := qualifierDirections()[q]
	return ok
}

// Direction returns which way this reason moves the reported number.
// DirectionUnset for an unrecognised reason: an unknown distortion is not a
// harmless one, and Qualifier.Valid refuses it.
func (q QualifierReason) Direction() Direction { return qualifierDirections()[q] }

// Uncomputable reports whether this reason means no fraction may be published.
func (q QualifierReason) Uncomputable() bool { return q.Direction() == DirectionUncomputable }

// Qualifier is one stated reason the fraction is not a plain measurement.
//
// It is RETURNED rather than logged, for the reason inventory.Refusal and
// inventory.CoverageCaveat are: a distortion nobody can read is a distortion
// that silently becomes the number.
type Qualifier struct {
	// Reason is the enumerated cause.
	Reason QualifierReason

	// Count is the magnitude where one is known — endpoints starved by the
	// budget, languages with no extractor. It is 0 where the magnitude is
	// genuinely unknown, and MagnitudeKnown says which.
	Count int

	// Detail is a short human-readable note. It carries no untrusted target
	// bytes: every string this package composes comes from enum literals and
	// from counts, and the tier packages redact anything else before it
	// reaches a Refusal or a CoverageCaveat.
	Detail string
}

// Valid reports whether q carries a recognised reason.
func (q Qualifier) Valid() bool { return q.Reason.Recognised() }

// Direction is the direction its reason moves the number.
func (q Qualifier) Direction() Direction { return q.Reason.Direction() }

// MagnitudeKnown reports whether Count is a measured magnitude.
//
// QualifierUnsupportedLanguage is the one that matters: Count is the number of
// LANGUAGES, not the number of hidden endpoints, and the number of hidden
// endpoints is exactly what nobody knows.
func (q Qualifier) MagnitudeKnown() bool {
	switch q.Reason {
	case QualifierUnsupportedLanguage, QualifierUnionTruncated, QualifierTierTruncated,
		QualifierTierHandoffUnwired, QualifierTierFactsAbsent:
		return false
	default:
		return q.Count > 0
	}
}

// String renders the qualifier for a report line.
func (q Qualifier) String() string {
	s := fmt.Sprintf("%s (%s", q.Reason, q.Direction())
	if q.Count > 0 {
		s += fmt.Sprintf(", n=%d", q.Count)
	}
	s += ")"
	if q.Detail != "" {
		s += ": " + q.Detail
	}
	return s
}

func sortQualifiers(qs []Qualifier) {
	order := map[QualifierReason]int{}
	for i, r := range QualifierReasonValues() {
		order[r] = i
	}
	sort.SliceStable(qs, func(i, j int) bool {
		if order[qs[i].Reason] != order[qs[j].Reason] {
			return order[qs[i].Reason] < order[qs[j].Reason]
		}
		return qs[i].Detail < qs[j].Detail
	})
}

// ---------------------------------------------------------------------------
// ProvenanceRow — the per-route facts the summary must not lose
// ---------------------------------------------------------------------------

// ProvenanceRow is one (endpoint, provenance) pair: the granularity at which
// inventory_provenance is actually a per-route fact.
//
// # Why the row is per (endpoint, provenance) and not per contributing route
//
// inventory.ConfirmResult.Routes() returns one Route per CONTRIBUTOR, and two
// routes from the SAME tier can name one endpoint. Tallying those would
// produce a mix that does not match
// inventory.ConfirmResult.InventoryProvenanceMix(), which counts an endpoint
// once under each DISTINCT provenance that named it. Rows at that same
// granularity are what make AssertMixDecomposes a real check rather than a
// restatement.
//
// The row is the decomposition of the record-level summary. An operator
// auditing the SAST->DAST handoff asks "which tier's candidates actually
// became confirmations", and that question is answerable from these rows and
// from nothing else in the record.
type ProvenanceRow struct {
	// Method and Path identify the endpoint, canonicalized by D.20's single
	// canonicalizer during the merge. Path is already redacted by D.22 when
	// it reaches any string this package composes; it is carried verbatim
	// here because a row is data for a caller, not a log line.
	Method string
	Path   string

	// Provenance is one of the tiers that named this endpoint. An endpoint
	// named by three tiers produces three rows.
	Provenance rec.InventoryProvenance

	// Confirmed is whether Anvil OBSERVED this endpoint through the kernel.
	// It is the endpoint's fact, repeated on each of its rows, because
	// confirmation is a property of the address and not of the tier that
	// pointed at it.
	Confirmed bool

	// Outcome is D.22's ConfirmOutcome as a string — why the endpoint is or
	// is not confirmed. It is what turns "40 static_extraction candidates,
	// 0 confirmed" from a mystery into a diagnosis.
	Outcome string

	// Operations are the operation names this endpoint carries, sorted. It
	// is non-empty mainly for GraphQL, where many operations share one
	// address; see the package doc, decision 4.
	Operations []string
}

// Key is the row's identity for deterministic ordering and for tests that
// assert a table rather than a length.
func (r ProvenanceRow) Key() string {
	return r.Method + " " + r.Path + " " + string(r.Provenance)
}

func cloneRows(in []ProvenanceRow) []ProvenanceRow {
	if in == nil {
		return nil
	}
	out := make([]ProvenanceRow, len(in))
	for i, r := range in {
		out[i] = r
		if r.Operations != nil {
			ops := make([]string, len(r.Operations))
			copy(ops, r.Operations)
			out[i].Operations = ops
		}
	}
	return out
}

// SortRows orders rows deterministically. Map iteration is randomized and an
// unstable report makes an unchanged repository look changed.
func SortRows(rs []ProvenanceRow) {
	sort.SliceStable(rs, func(i, j int) bool { return rs[i].Key() < rs[j].Key() })
}

// ---------------------------------------------------------------------------
// TierContribution — the per-tier decomposition of the denominator
// ---------------------------------------------------------------------------

// TierName names one inventory tier, for the denominator's decomposition.
type TierName string

const (
	// TierRuntimeSpec is D.18, Tier 0.
	TierRuntimeSpec TierName = "tier0_runtime_spec"
	// TierRepoSpec is D.19, Tier 1.
	TierRepoSpec TierName = "tier1_repo_spec"
	// TierGoExtraction is D.20, the Go half of Tier 2.
	TierGoExtraction TierName = "tier2_go_extraction"
	// TierOtherExtraction is D.21, the non-Go half of Tier 2.
	TierOtherExtraction TierName = "tier2_other_extraction"
)

// TierNameValues returns every tier, in tier order.
func TierNameValues() []TierName {
	return []TierName{TierRuntimeSpec, TierRepoSpec, TierGoExtraction, TierOtherExtraction}
}

// TierContribution is what one tier put into the denominator.
//
// It exists so InventoryUnionCount is decomposable. A denominator an operator
// cannot take apart is the same unfalsifiable claim as a bare percentage, one
// level down.
type TierContribution struct {
	// Tier names the source.
	Tier TierName

	// Ran is whether this tier was supplied to Summarize at all. False means
	// the tier did not run; it is not the same as a tier that ran and found
	// nothing, and both are visible here.
	Ran bool

	// Routes is how many routes this tier handed to the merge. These are
	// already in the merged union, possibly collapsed with other tiers'.
	Routes int

	// Floor is the tier's own DenominatorFloor: routes plus everything it
	// saw and could not represent.
	Floor int

	// Unrepresented is Floor minus Routes — surface this tier demonstrably
	// saw that never became a route and therefore is NOT in the merged
	// union. It is what InventoryUnionCount adds on top of the merge.
	Unrepresented int
}

func cloneContributions(in []TierContribution) []TierContribution {
	if in == nil {
		return nil
	}
	out := make([]TierContribution, len(in))
	copy(out, in)
	return out
}

// ---------------------------------------------------------------------------
// Inputs
// ---------------------------------------------------------------------------

// Inputs is everything Summarize needs. Nothing in it has a default that means
// "permitted" or "complete".
type Inputs struct {
	// Mode is required; ScanModeUnset is refused. It decides whether
	// ServerLineCoverage may be present at all.
	Mode ScanMode

	// Union is D.22's merge-and-confirm result: the denominator and the
	// numerator both come from it.
	//
	// NIL IS A LEGAL AND MEANINGFUL VALUE: it says the DAST half never
	// produced an inventory — a manifest-absent skip, a target that never
	// booted, a half that died before D.22. It yields DeterminacyUnknown and
	// a Coverage() that refuses, never a 0.0.
	Union *inventory.ConfirmResult

	// Tier0..Tier2Other are the per-tier results that fed the merge. A nil
	// pointer means the tier did not run. A non-nil pointer that its own
	// constructor never sealed is refused.
	//
	// They are required in the sense that arithmetic depends on them: the
	// sum of their route counts must equal Union.Offered(), or the
	// unrepresented-surface correction would be assembled from a different
	// run and Summarize returns ErrTiersNotMerged.
	Tier0      *inventory.Result
	Tier1      *inventory.IngestResult
	Tier2Go    *inventory.ExtractResult
	Tier2Other *inventory.OtherExtractResult

	// ServerLineCoverage is the language coverage agent's measurement, in
	// [0,1]. NIL MEANS NOT MEASURED and stays nil all the way into the
	// record. Legal only on ScanModeScheduledFull; a non-nil value on an
	// incremental scan is refused rather than dropped.
	ServerLineCoverage *float64

	// Provenance is the target's boot/reachability outcome (D.1, D.10). It
	// is what record.DeriveDastStatus consults FIRST, which is what keeps a
	// target that never booted from reading as "scanned clean". Required;
	// the empty value is refused.
	Provenance rec.TargetProvenance

	// Provisioning is which provisioning path was taken —
	// anvil/target.provisioning, a DIFFERENT MEASUREMENT from Provenance.
	//
	// The empty string is legal and means OMIT THE FIELD: record.
	// TargetProvisioning has exactly two literals and both assert a target
	// existed, so a no-manifest skip has no honest value and containment's
	// ProvisionError.Provisioning refuses to invent one.
	Provisioning rec.TargetProvisioning
}

// ---------------------------------------------------------------------------
// Summary
// ---------------------------------------------------------------------------

// Summary is one record's worth of DAST coverage, sealed.
//
// Every field is unexported and there is one constructor, for the reason every
// other sealed type in this tree has one: a composite literal elsewhere would
// produce a Summary whose Determinacy is the empty string and whose coverage
// is 0.0, which is precisely the "unscanned reads as clean" failure this
// package exists to prevent.
type Summary struct {
	mode         ScanMode
	determinacy  Determinacy
	qualifiers   []Qualifier
	rows         []ProvenanceRow
	tiers        []TierContribution
	mix          map[rec.InventoryProvenance]int
	confirmedMix map[rec.InventoryProvenance]int

	merged        int
	unrepresented int
	confirmed     int
	operations    int
	issued        int
	answered      int

	serverLine   *float64
	provenance   rec.TargetProvenance
	provisioning rec.TargetProvisioning

	sealed bool
}

// Constructed reports whether s came from Summarize.
func (s Summary) Constructed() bool { return s.sealed }

// Mode is the scan mode this summary was computed under.
func (s Summary) Mode() ScanMode { return s.mode }

// Determinacy says what kind of number Coverage() will or will not produce.
func (s Summary) Determinacy() Determinacy { return s.determinacy }

// Qualifiers returns a COPY of every stated distortion, in reported order.
func (s Summary) Qualifiers() []Qualifier {
	if s.qualifiers == nil {
		return nil
	}
	out := make([]Qualifier, len(s.qualifiers))
	copy(out, s.qualifiers)
	return out
}

// Rows returns a COPY of the per-(endpoint, provenance) decomposition.
func (s Summary) Rows() []ProvenanceRow { return cloneRows(s.rows) }

// TierContributions returns a COPY of the per-tier decomposition of the
// denominator, in tier order, including tiers that did not run.
func (s Summary) TierContributions() []TierContribution { return cloneContributions(s.tiers) }

// MergedEndpointCount is the size of D.22's union: distinct (method, canonical
// path) addresses. It is NOT the whole denominator.
func (s Summary) MergedEndpointCount() int { return s.merged }

// UnrepresentedCount is surface the tiers saw and could not represent, summed
// across tiers. It is added to the denominator because those endpoints exist
// and are not in the merged union.
func (s Summary) UnrepresentedCount() int { return s.unrepresented }

// InventoryUnionCount is endpoint_coverage's DENOMINATOR: the merged union
// plus the unrepresented surface.
//
// It is deliberately LARGER than D.22's endpoint count. Every per-tier
// DenominatorFloor documents itself as "the smallest number of endpoints D.26
// may use"; publishing the merge alone would go below all four floors at once,
// and a denominator below its floor is the shrink that makes coverage look
// better for free.
func (s Summary) InventoryUnionCount() int { return s.merged + s.unrepresented }

// ConfirmedCount is endpoint_coverage's NUMERATOR: endpoints Anvil observed
// through the kernel. Never a request count.
func (s Summary) ConfirmedCount() int { return s.confirmed }

// CandidateCount is the rest of the denominator. Unrepresented surface is
// counted here: it was certainly not confirmed.
func (s Summary) CandidateCount() int { return s.InventoryUnionCount() - s.confirmed }

// OperationCount is D.22's second number: distinct (endpoint, operation)
// pairs. Reported BESIDE the endpoint count, never substituted into the
// denominator. See the package doc, decision 4.
func (s Summary) OperationCount() int { return s.operations }

// RequestsIssued is how many requests actually left through the seam.
//
// It is here so a reader can compare it against ConfirmedCount and see how
// many requests bought how many confirmations. It is NEVER part of
// endpoint_coverage — plan/50-dast.md:1152, in bold.
func (s Summary) RequestsIssued() int { return s.issued }

// TargetAnswered is how many confirmation probes the TARGET answered, whatever
// the status.
//
// It is the number that separates "these endpoints do not exist" from "Anvil
// never reached this application", and it is why a numerator of zero is
// sometimes a measurement and sometimes DeterminacyUnknown.
func (s Summary) TargetAnswered() int { return s.answered }

// ProvenanceMix is the record-level inventory_provenance summary: endpoint
// count per provenance literal, computed from Rows().
//
// IT IS A MIX AND NOT A PARTITION. An endpoint named by three tiers counts
// once under each, so the values sum to more than MergedEndpointCount. That is
// the honest shape; the alternative is picking one tier and discarding the
// fact that two others found it.
func (s Summary) ProvenanceMix() map[rec.InventoryProvenance]int { return copyMix(s.mix) }

// ConfirmedProvenanceMix is the same mix restricted to CONFIRMED endpoints.
//
// This is the number that audits the SAST->DAST handoff. "static_extraction
// contributed 40 candidates and 0 confirmations" is a finding about the
// handoff; the unrestricted mix cannot express it.
func (s Summary) ConfirmedProvenanceMix() map[rec.InventoryProvenance]int {
	return copyMix(s.confirmedMix)
}

func copyMix(in map[rec.InventoryProvenance]int) map[rec.InventoryProvenance]int {
	out := make(map[rec.InventoryProvenance]int, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

// ServerLineCoverage returns the nullable server_line_coverage as it will be
// written: a POINTER, nil when nothing measured it.
//
// The returned pointer is a fresh copy, so a caller cannot reach back through
// it and change what the summary says.
func (s Summary) ServerLineCoverage() *float64 {
	if s.serverLine == nil {
		return nil
	}
	v := *s.serverLine
	return &v
}

// ServerLineCoverageMeasured reports whether a measurement exists at all.
//
// It is the predicate a consumer should branch on. `*p == 0` cannot tell a
// measured zero from an unmeasured one, and treating them alike is the same
// silent-clean failure as reporting an unscanned target clean.
func (s Summary) ServerLineCoverageMeasured() bool { return s.serverLine != nil }

// Provenance is the target's boot/reachability outcome, carried through
// unchanged.
func (s Summary) Provenance() rec.TargetProvenance { return s.provenance }

// Provisioning is which provisioning path was taken. The second return is
// false when the field must be OMITTED because no provisioning path was taken.
func (s Summary) Provisioning() (rec.TargetProvisioning, bool) {
	if s.provisioning == "" {
		return "", false
	}
	return s.provisioning, true
}

// PartialCoverage is the one bit record.DastOutcome asks this package for.
//
// True whenever the half did not provably cover the whole discovered surface:
// a numerator short of the denominator, or a Determinacy that is not a plain
// measurement. An unknown coverage is partial — it is certainly not proof that
// everything was covered, and DastStatusCompletedClean must not be reachable
// from a summary that could not compute a fraction.
func (s Summary) PartialCoverage() bool {
	if !s.sealed {
		return true
	}
	if s.determinacy != DeterminacyMeasured {
		return true
	}
	return s.confirmed < s.InventoryUnionCount()
}

// ---------------------------------------------------------------------------
// The two outputs
// ---------------------------------------------------------------------------

// Coverage renders the summary as record.DastCoverage, or refuses.
//
// It returns ErrCoverageNotComputable rather than a fraction when
// Determinacy() is DeterminacyUnknown. A caller that must write a record
// anyway has to handle that explicitly, and record.SarifRun's DAST half then
// carries no anvil/dastCoverage rather than carrying a fabricated one.
func (s Summary) Coverage() (rec.DastCoverage, error) {
	if !s.sealed {
		return rec.DastCoverage{}, fmt.Errorf("%w: Coverage was called on a Summary "+
			"Summarize never built", ErrUnconstructed)
	}
	if err := s.AssertCoverageIsComputable(); err != nil {
		return rec.DastCoverage{}, err
	}
	union := s.InventoryUnionCount()
	frac := float64(s.confirmed) / float64(union)
	c := rec.DastCoverage{
		ProbedCount:            s.confirmed,
		InventoryUnionCount:    union,
		EndpointCoverage:       frac,
		ServerLineCoverage:     s.ServerLineCoverage(),
		InventoryProvenanceMix: s.ProvenanceMix(),
		ConfirmedCount:         s.confirmed,
		CandidateCount:         union - s.confirmed,
	}
	// The contract's own validator is the authority on this shape. Running
	// it here means a drift in either file is caught at construction rather
	// than at the store's NOT NULL constraint.
	if err := rec.ValidateDastCoverage(&c); err != nil {
		return rec.DastCoverage{}, fmt.Errorf("%w: the assembled coverage does not satisfy "+
			"internal/record's own validator: %w", ErrRefused, err)
	}
	return c, nil
}

// AssertCoverageIsComputable reports whether a fraction may be published,
// naming every uncomputable qualifier if not.
//
// Zero coverage and unknown coverage are different facts and an operator acts
// differently on each. This is the predicate that keeps them apart.
func (s Summary) AssertCoverageIsComputable() error {
	if !s.sealed {
		return fmt.Errorf("%w: AssertCoverageIsComputable was called on a Summary "+
			"Summarize never built", ErrUnconstructed)
	}
	if s.determinacy.Computable() {
		return nil
	}
	var why []string
	for _, q := range s.qualifiers {
		if q.Reason.Uncomputable() {
			why = append(why, q.String())
		}
	}
	return fmt.Errorf("%w: %s. Zero coverage and unknown coverage are different facts: "+
		"0.0 would read as \"we probed the surface and confirmed none of it\", which is not "+
		"what happened. The record must carry no anvil/dastCoverage rather than a fabricated one",
		ErrCoverageNotComputable, strings.Join(why, "; "))
}

// DeriveDastStatus maps this summary and the half's own outcome onto the
// audit-level anvil/dastStatus.
//
// NOTHING HERE WRITES A STATUS LITERAL. record.DeriveDastStatus owns the
// mapping and record.DastStatus owns the vocabulary; this method supplies the
// two facts area D is qualified to supply — the target's provenance and
// whether coverage was partial — and lets the record decide. That is what
// keeps plan/50-dast.md:1149's stale five-value enum out of the record, and it
// is why a manifest-absent skip cannot be equal-compared to a clean run: they
// arrive at different literals through a total function.
func (s Summary) DeriveDastStatus(tierInstalled bool, half rec.HalfStatus, findingCount int) (rec.DastStatus, error) {
	if !s.sealed {
		return "", fmt.Errorf("%w: DeriveDastStatus was called on a Summary Summarize "+
			"never built", ErrUnconstructed)
	}
	if findingCount < 0 {
		return "", fmt.Errorf("%w: a finding count of %d is not a count", ErrRefused, findingCount)
	}
	return rec.DeriveDastStatus(half, rec.DastOutcome{
		TierInstalled:   tierInstalled,
		Provenance:      s.provenance,
		FindingCount:    findingCount,
		PartialCoverage: s.PartialCoverage(),
	})
}

// ---------------------------------------------------------------------------
// The decomposition assertions
// ---------------------------------------------------------------------------

// AssertMixDecomposes proves the record-level provenance summary can be taken
// apart into the per-route facts it was aggregated from.
//
// The contract says inventory_provenance is per-route and is "aggregated to a
// record-level summary in D.26. This is what makes the SAST->DAST handoff
// auditable." An aggregate nobody can decompose is a claim, not evidence — so
// this recomputes the mix from Rows() and compares it against the mix D.22
// computed independently from its own endpoint list. Two computations that
// agree is a check; one computation restated is not.
func (s Summary) AssertMixDecomposes() error {
	if !s.sealed {
		return fmt.Errorf("%w: AssertMixDecomposes was called on a Summary Summarize "+
			"never built", ErrUnconstructed)
	}
	fromRows := map[rec.InventoryProvenance]int{}
	confirmedFromRows := map[rec.InventoryProvenance]int{}
	addrs := map[string]bool{}
	for _, r := range s.rows {
		fromRows[r.Provenance]++
		if r.Confirmed {
			confirmedFromRows[r.Provenance]++
		}
		addrs[r.Method+" "+r.Path] = true
	}
	if err := sameMix("inventory_provenance", s.mix, fromRows); err != nil {
		return err
	}
	if err := sameMix("inventory_provenance (confirmed)", s.confirmedMix, confirmedFromRows); err != nil {
		return err
	}
	if len(addrs) != s.merged {
		return fmt.Errorf("%w: the rows name %d distinct addresses and the merged union has "+
			"%d. Every endpoint in the union must produce at least one row, or the summary "+
			"describes a different inventory than the denominator does",
			ErrMixDoesNotDecompose, len(addrs), s.merged)
	}
	return nil
}

func sameMix(what string, want, got map[rec.InventoryProvenance]int) error {
	for _, p := range rec.InventoryProvenanceValues() {
		if want[p] != got[p] {
			return fmt.Errorf("%w: %s says %d endpoint(s) under %q and its rows tally %d",
				ErrMixDoesNotDecompose, what, want[p], p, got[p])
		}
	}
	// A key outside the frozen vocabulary in either map is a naming drift,
	// and it would be invisible to the loop above.
	for p := range want {
		if err := rec.ValidateInventoryProvenance(string(p)); err != nil {
			return fmt.Errorf("%w: %s carries %w", ErrMixDoesNotDecompose, what, err)
		}
	}
	for p := range got {
		if err := rec.ValidateInventoryProvenance(string(p)); err != nil {
			return fmt.Errorf("%w: %s rows carry %w", ErrMixDoesNotDecompose, what, err)
		}
	}
	return nil
}

// AssertDenominatorDecomposes proves InventoryUnionCount is the sum of the
// parts TierContributions reports, so an operator can take the denominator
// apart the same way they can take the mix apart.
func (s Summary) AssertDenominatorDecomposes() error {
	if !s.sealed {
		return fmt.Errorf("%w: AssertDenominatorDecomposes was called on a Summary "+
			"Summarize never built", ErrUnconstructed)
	}
	sum := 0
	for _, c := range s.tiers {
		if c.Unrepresented != c.Floor-c.Routes {
			return fmt.Errorf("%w: %s reports floor %d, routes %d and unrepresented %d",
				ErrRefused, c.Tier, c.Floor, c.Routes, c.Unrepresented)
		}
		sum += c.Unrepresented
	}
	if sum != s.unrepresented {
		return fmt.Errorf("%w: the tier contributions sum to %d unrepresented endpoint(s) "+
			"and the summary reports %d", ErrRefused, sum, s.unrepresented)
	}
	if s.confirmed > s.InventoryUnionCount() {
		return fmt.Errorf("%w: %d confirmed endpoint(s) over a denominator of %d",
			ErrRefused, s.confirmed, s.InventoryUnionCount())
	}
	return nil
}

// String renders the summary as one report line, numerator and denominator
// visible, never as a bare percentage.
func (s Summary) String() string {
	if !s.sealed {
		return "dast coverage: <unconstructed>"
	}
	head := fmt.Sprintf("dast coverage [%s/%s]: ", s.mode, s.determinacy)
	if !s.determinacy.Computable() {
		return head + fmt.Sprintf("NOT COMPUTED (%d qualifier(s))", len(s.qualifiers))
	}
	union := s.InventoryUnionCount()
	line := fmt.Sprintf("%s%d/%d endpoints (%d merged + %d unrepresented), %d operation(s), "+
		"%d request(s) issued", head, s.confirmed, union, s.merged, s.unrepresented,
		s.operations, s.issued)
	if s.serverLine == nil {
		line += ", server_line_coverage=null"
	} else {
		line += fmt.Sprintf(", server_line_coverage=%.4f", *s.serverLine)
	}
	if len(s.qualifiers) > 0 {
		line += fmt.Sprintf(", %d qualifier(s)", len(s.qualifiers))
	}
	return line
}

// ---------------------------------------------------------------------------
// Summarize
// ---------------------------------------------------------------------------

// Summarize aggregates the tier results and D.22's union into one Summary.
//
// The order of what it does is the point:
//
//  1. validate the mode and the nullable server_line_coverage against it,
//     because an incremental scan carrying a line-coverage number is a
//     caller defect and not a value to silently drop
//  2. validate the target provenance, because record.DeriveDastStatus
//     consults it BEFORE the half's own status and a missing one would let a
//     never-booted target reach a "clean" reading
//  3. if there is no union, stop: DeterminacyUnknown, no fraction
//  4. re-run D.22's own numerator assertions, so a confirmation with no
//     kernel-admitted request behind it never reaches a record
//  5. cross-check that the tier results are the ones that produced the union
//  6. build the per-(endpoint, provenance) rows and tally the mix from them
//  7. add the unrepresented surface to the denominator
//  8. collect every qualifier, and let the uncomputable ones decide
//     Determinacy
func Summarize(in Inputs) (Summary, error) {
	if !in.Mode.Valid() {
		return Summary{}, fmt.Errorf("%w: %q is not a scan mode. There is no default: the "+
			"mode decides whether a nil server_line_coverage is a measurement or a missing "+
			"one, and that decision belongs to the caller", ErrRefused, string(in.Mode))
	}
	sl, err := validateServerLine(in.Mode, in.ServerLineCoverage)
	if err != nil {
		return Summary{}, err
	}
	if err := rec.ValidateTargetProvenance(string(in.Provenance)); err != nil {
		return Summary{}, fmt.Errorf("%w: the target's boot/reachability outcome is "+
			"required, because record.DeriveDastStatus reads it before the half's own "+
			"status and that ordering is what keeps a target that never booted from "+
			"reading as scanned clean: %w", ErrRefused, err)
	}
	if in.Provisioning != "" {
		if err := rec.ValidateTargetProvisioning(string(in.Provisioning)); err != nil {
			return Summary{}, fmt.Errorf("%w: %w", ErrRefused, err)
		}
	}

	s := Summary{
		mode:         in.Mode,
		serverLine:   sl,
		provenance:   in.Provenance,
		provisioning: in.Provisioning,
		mix:          map[rec.InventoryProvenance]int{},
		confirmedMix: map[rec.InventoryProvenance]int{},
		sealed:       true,
	}

	contribs, offered, anyTier, quals, err := collectTiers(in)
	if err != nil {
		return Summary{}, err
	}
	s.tiers = contribs
	for _, c := range contribs {
		s.unrepresented += c.Unrepresented
	}

	if in.Union == nil {
		// No inventory at all. The unrepresented surface is real but there
		// is no numerator and no merge, so no fraction is honest.
		s.unrepresented = 0
		s.tiers = zeroContributions()
		s.qualifiers = []Qualifier{{
			Reason: QualifierInventoryAbsent,
			Detail: fmt.Sprintf("the DAST half produced no inventory; target provenance is %q",
				string(in.Provenance)),
		}}
		s.determinacy = DeterminacyUnknown
		return s, nil
	}
	u := *in.Union
	if !u.Constructed() {
		return Summary{}, fmt.Errorf("%w: the union is a ConfirmResult MergeAndConfirm "+
			"never built. A composite literal there would report zero endpoints and zero "+
			"confirmations, which renders as 0.0 coverage over an empty surface",
			ErrUnconstructed)
	}
	if err := u.AssertEveryConfirmationHasEvidence(); err != nil {
		return Summary{}, fmt.Errorf("%w: this union cannot supply a numerator: %w",
			ErrRefused, err)
	}
	if err := u.AssertNoUnconfirmedEndpointClaimsConfirmation(); err != nil {
		return Summary{}, fmt.Errorf("%w: this union cannot supply a numerator: %w",
			ErrRefused, err)
	}
	if anyTier && offered != u.Offered() {
		return Summary{}, fmt.Errorf("%w: the supplied tier results carry %d route(s) and "+
			"the union was offered %d. InventoryUnionCount subtracts each tier's route "+
			"count from its DenominatorFloor, so a mismatch would assemble the denominator "+
			"from two different runs", ErrTiersNotMerged, offered, u.Offered())
	}
	if !anyTier && u.Offered() > 0 {
		// The equality check above cannot run, so the weakness is stated
		// instead of assumed away.
		quals = append(quals, Qualifier{
			Reason: QualifierTierFactsAbsent,
			Detail: fmt.Sprintf("%d route(s) were merged and no tier result was supplied, "+
				"so the denominator carries no DenominatorFloor correction from any tier. "+
				"Surface a tier saw and could not represent is missing from it by an "+
				"unknown amount", u.Offered()),
		})
	}

	s.merged = u.EndpointCount()
	s.confirmed = u.ConfirmedCount()
	s.operations = u.OperationCount()
	s.issued = u.Issued()
	s.answered = u.Answered()
	s.rows = buildRows(u)
	SortRows(s.rows)
	for _, r := range s.rows {
		s.mix[r.Provenance]++
		if r.Confirmed {
			s.confirmedMix[r.Provenance]++
		}
	}

	quals = append(quals, unionQualifiers(u)...)
	sortQualifiers(quals)
	s.qualifiers = quals
	s.determinacy = determinacyOf(quals)

	// The mix this package publishes must agree with the one D.22 computed
	// from its own endpoint list. They are computed from different data —
	// rows here, endpoints there — so agreement is evidence.
	if err := sameMix("inventory_provenance", u.InventoryProvenanceMix(), s.mix); err != nil {
		return Summary{}, fmt.Errorf("%w: the rows this package built disagree with D.22's "+
			"own mix: %w", ErrRefused, err)
	}
	if err := s.AssertMixDecomposes(); err != nil {
		return Summary{}, err
	}
	if err := s.AssertDenominatorDecomposes(); err != nil {
		return Summary{}, err
	}
	return s, nil
}

// validateServerLine enforces the nullable field's whole contract.
func validateServerLine(mode ScanMode, p *float64) (*float64, error) {
	if p == nil {
		return nil, nil
	}
	if !mode.AllowsServerLineCoverage() {
		return nil, fmt.Errorf("%w: server_line_coverage was supplied on a %q scan. It is "+
			"populated on scheduled full scans only, by a language coverage agent inside "+
			"the sandbox; on an incremental scan the field is NULL and not 0. Dropping the "+
			"value silently and keeping it are both wrong, so this refuses and the caller "+
			"decides", ErrRefused, string(mode))
	}
	v := *p
	if math.IsNaN(v) || math.IsInf(v, 0) {
		return nil, fmt.Errorf("%w: server_line_coverage is not a finite number", ErrRefused)
	}
	if v < 0 || v > 1 {
		return nil, fmt.Errorf("%w: server_line_coverage %v is outside [0,1]", ErrRefused, v)
	}
	return &v, nil
}

// collectTiers builds the per-tier decomposition and the qualifiers each tier
// raises, and returns the total route count for the merge cross-check.
func collectTiers(in Inputs) ([]TierContribution, int, bool, []Qualifier, error) {
	out := zeroContributions()
	var quals []Qualifier
	total := 0
	any := false

	set := func(name TierName, routes, floor int) {
		any = true
		for i := range out {
			if out[i].Tier == name {
				out[i] = TierContribution{
					Tier: name, Ran: true, Routes: routes, Floor: floor,
					Unrepresented: floor - routes,
				}
			}
		}
		total += routes
	}

	if r := in.Tier0; r != nil {
		if !r.Constructed() {
			return nil, 0, false, nil, unsealed(TierRuntimeSpec, "inventory.ProbeRuntimeSpecs")
		}
		set(TierRuntimeSpec, len(r.Routes()), r.DenominatorFloor())
		if err := r.AssertNotSilentlyEmpty(); err != nil {
			quals = append(quals, Qualifier{
				Reason: QualifierTierHandoffUnwired,
				Detail: string(TierRuntimeSpec) + ": " + err.Error(),
			})
		}
		if r.Truncated() {
			quals = append(quals, Qualifier{
				Reason: QualifierTierTruncated,
				Detail: string(TierRuntimeSpec) + ": a served document exceeded the coded route bound",
			})
		}
	}
	if r := in.Tier1; r != nil {
		if !r.Constructed() {
			return nil, 0, false, nil, unsealed(TierRepoSpec, "inventory.IngestRepoSpecs")
		}
		set(TierRepoSpec, len(r.Routes()), r.DenominatorFloor())
		if err := r.AssertNotSilentlyEmpty(); err != nil {
			quals = append(quals, Qualifier{
				Reason: QualifierTierHandoffUnwired,
				Detail: string(TierRepoSpec) + ": " + err.Error(),
			})
		}
		if r.Truncated() {
			quals = append(quals, Qualifier{
				Reason: QualifierTierTruncated,
				Detail: string(TierRepoSpec) + ": a harvested file exceeded the coded route bound",
			})
		}
	}
	if r := in.Tier2Go; r != nil {
		if !r.Constructed() {
			return nil, 0, false, nil, unsealed(TierGoExtraction, "inventory.ExtractGoRoutes")
		}
		set(TierGoExtraction, len(r.Routes()), r.DenominatorFloor())
		if err := r.AssertNotSilentlyEmpty(); err != nil {
			quals = append(quals, Qualifier{
				Reason: QualifierTierHandoffUnwired,
				Detail: string(TierGoExtraction) + ": " + err.Error(),
			})
		}
		if r.Truncated() {
			quals = append(quals, Qualifier{
				Reason: QualifierTierTruncated,
				Detail: string(TierGoExtraction) + ": extraction stopped at a coded bound",
			})
		}
	}
	if r := in.Tier2Other; r != nil {
		if !r.Constructed() {
			return nil, 0, false, nil, unsealed(TierOtherExtraction, "inventory.ExtractNonGoRoutes")
		}
		set(TierOtherExtraction, len(r.Routes()), r.DenominatorFloor())
		if err := r.AssertNotSilentlyEmpty(); err != nil {
			quals = append(quals, Qualifier{
				Reason: QualifierTierHandoffUnwired,
				Detail: string(TierOtherExtraction) + ": " + err.Error(),
			})
		}
		if r.Truncated() {
			quals = append(quals, Qualifier{
				Reason: QualifierTierTruncated,
				Detail: string(TierOtherExtraction) + ": extraction stopped at a coded bound",
			})
		}
		// D.21's whole packet. An unsupported language hides an UNKNOWN
		// number of endpoints, so it adds nothing to any floor and instead
		// returns an error that a caller computing coverage has to handle in
		// code. This is that line of code.
		if err := r.AssertDenominatorIsComplete(); err != nil {
			quals = append(quals, Qualifier{
				Reason: QualifierUnsupportedLanguage,
				Count:  len(r.UnsupportedLanguages()),
				Detail: err.Error(),
			})
		}
	}
	return out, total, any, quals, nil
}

func zeroContributions() []TierContribution {
	out := make([]TierContribution, 0, len(TierNameValues()))
	for _, n := range TierNameValues() {
		out = append(out, TierContribution{Tier: n})
	}
	return out
}

func unsealed(name TierName, ctor string) error {
	return fmt.Errorf("%w: the %s result did not come from %s. Its route list would read as "+
		"empty and its DenominatorFloor as zero, which shrinks the denominator and makes "+
		"coverage look better", ErrUnconstructed, name, ctor)
}

// unionQualifiers collects everything D.22's own assertions say about the
// union, plus the GraphQL collapse.
func unionQualifiers(u inventory.ConfirmResult) []Qualifier {
	var quals []Qualifier

	if err := u.AssertNotSilentlyEmpty(); err != nil {
		return []Qualifier{{Reason: QualifierEmptyUnion, Detail: err.Error()}}
	}
	// The numerator is zero because nobody looked, not because nothing
	// confirmed. u.Answered() is the number that separates "these endpoints
	// do not exist" from "Anvil never reached this application", and it is
	// zero both when confirmation was never requested and when every probe
	// failed to leave.
	if u.Answered() == 0 {
		quals = append(quals, Qualifier{
			Reason: QualifierNothingProbed,
			Count:  u.EndpointCount(),
			Detail: fmt.Sprintf("%d endpoint(s) in the union, %d attempted, %d request(s) "+
				"issued, %d answered. A numerator of %d here is a fact about Anvil's reach",
				u.EndpointCount(), u.Attempted(), u.Issued(), u.Answered(), u.ConfirmedCount()),
		})
	}
	if err := u.AssertBudgetSufficed(); err != nil {
		quals = append(quals, Qualifier{
			Reason: QualifierProbeBudgetExhausted,
			Count:  len(u.UnprobedEndpoints()),
			Detail: err.Error(),
		})
	}
	if u.Truncated() {
		quals = append(quals, Qualifier{
			Reason: QualifierUnionTruncated,
			Detail: "the merge hit its coded endpoint bound, so the union is not the whole union",
		})
	}
	// Decision 4: reported beside the denominator, never inside it.
	if ops, eps := u.OperationCount(), u.EndpointCount(); ops > eps {
		quals = append(quals, Qualifier{
			Reason: QualifierOperationsCollapsed,
			Count:  ops - eps,
			Detail: fmt.Sprintf("%d operation(s) share %d address(es). Confirming an address "+
				"confirms every operation on it, so the fraction reads higher than the "+
				"operation-level truth. The operation count is reported beside the endpoint "+
				"count and is NEVER the denominator: confirmed endpoints over operations is "+
				"not a smaller fraction, it is a type error", ops, eps),
		})
	}
	return quals
}

func determinacyOf(quals []Qualifier) Determinacy {
	for _, q := range quals {
		if q.Reason.Uncomputable() {
			return DeterminacyUnknown
		}
	}
	if len(quals) > 0 {
		return DeterminacyQualified
	}
	return DeterminacyMeasured
}

// buildRows explodes the union into one row per (endpoint, distinct
// provenance). See ProvenanceRow's doc for why that granularity and not the
// contributing-route granularity.
func buildRows(u inventory.ConfirmResult) []ProvenanceRow {
	var out []ProvenanceRow
	for _, e := range u.Endpoints() {
		ops := e.Operations()
		sort.Strings(ops)
		for _, p := range e.Provenances() {
			out = append(out, ProvenanceRow{
				Method:     string(e.Method()),
				Path:       e.Path(),
				Provenance: p,
				Confirmed:  e.Confirmed(),
				Outcome:    string(e.Outcome()),
				Operations: ops,
			})
		}
	}
	return out
}
