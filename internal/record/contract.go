// Package record defines Anvil's single frozen audit-record contract: the
// SARIF 2.1.0 wire shape Anvil produces, the typed `anvil/*` property-bag
// extension that carries what stock SARIF cannot, and — since the
// 2026-08-07 orchestrator ruling — every enum shared across Anvil's areas.
//
// # Authority
//
// This file is the single point where shared cross-area vocabulary is fixed.
// plan/IMPLEMENTATION-PLAN.md §6 (rulings G2–G10) found ten confirmed
// produce/consume defects whose common cause was that eight agents who could
// not see each other each declared the shared vocabulary from their own side:
// one area wrote literals another area's NOT NULL column could not accept.
// The ruling: "area 40 owns every shared enum, because it owns the record
// contract, and no other area may declare one."
//
// So: every enum below is declared here ONCE and consumed everywhere else.
// An area that produces a value emits these literals directly, or applies an
// explicitly named and tested mapping at a named step (see AreaMappingOwners).
// Adding a value to any enum here is an amendment to
// plan/40-record-and-storage.md and plan/IMPLEMENTATION-PLAN.md §6, not a
// local edit.
//
// # Conventions
//
//   - Lowercase snake_case is the record's literal convention throughout.
//     Any area whose in-process vocabulary is SCREAMING_CASE maps at its own
//     boundary (plan/IMPLEMENTATION-PLAN.md §6; e.g. B.12 owns the mapping
//     from Lane B's `Verdict.Result` onto Verdict below).
//   - `anvil/*` keys are hierarchical camelCase, per SARIF §3.8's
//     recommendation for property names (research/18-unified-audit-record.md,
//     "The Anvil extension, normatively").
//   - A SARIF-native slot is never duplicated into an `anvil/*` key. Where a
//     native mechanism exists (correlationGuid, partialFingerprints,
//     provenance, fixes, region/contextRegion/snippet, logicalLocations,
//     taxonomies/taxa, webRequest/webResponse, codeFlows) it is used, and the
//     `anvil/*` bag carries only what SARIF has no slot for.
//
// # Scope of the Go types here
//
// These types cover the SARIF 2.1.0 subset Anvil produces and consumes, not
// all of SARIF. plan/40-record-and-storage.md's Pinned Versions table names
// `owenrumney/go-sarif` as the intended SARIF library, but that module is not
// in go.mod and adding a dependency is the orchestrator's licence decision,
// so the subset below is stdlib-only. A full third-party SARIF reader should
// still be used for INGESTING foreign SARIF; these types are for Anvil's own
// records.
//
// Sources: plan/00-SPINE.md S1, S6, S7, S10, S12;
// plan/IMPLEMENTATION-PLAN.md §6; plan/40-record-and-storage.md ("Record
// Field Contract", "Fingerprint Specification", "Store Schema");
// research/18-unified-audit-record.md ("Recommendation For Anvil", the
// annotated record, Risks); research/24-coding-agent-consumption.md ("What
// the audit record must carry").
package record

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

// ---------------------------------------------------------------------------
// Pinned wire identifiers
// ---------------------------------------------------------------------------

const (
	// SARIFVersion is pinned to SARIF 2.1.0 exactly. Do not pin to the 2.2
	// draft: it is unratified, and research/18 Risk #9 records that no
	// published 2.2 content or timeline could be verified.
	SARIFVersion = "2.1.0"

	// SARIFSchemaURI is the value of `sarifLog.$schema`. It must match
	// SARIFVersion; a record carrying one without the other is invalid.
	SARIFSchemaURI = "https://json.schemastore.org/sarif-2.1.0.json"

	// AnvilSchemaURI identifies this contract's own JSON Schema, which
	// constrains the `anvil/*` property bags on top of stock SARIF.
	AnvilSchemaURI = "https://anvil.invalid/schemas/anvil-record-v1.schema.json"

	// SchemaVersion is the value of `anvil/schemaVersion`. Bump the minor
	// component for an additive change, the major for a breaking one; the
	// store's migration ledger keys off it.
	SchemaVersion = "1.0.0"
)

// Fingerprint identifiers. R.2 owns the algorithm; this file owns the key
// names it writes into, so that R.2, the store, and the GitHub projection
// cannot disagree about where a digest lives.
const (
	// FingerprintAlgV1 is the name of the one and only Anvil fingerprint
	// algorithm. plan/00-SPINE.md S6: "One fingerprint algorithm, defined
	// once, in the record. Two branches specified different /v1 algorithms
	// under the same name; two producers emitting different hashes means
	// regression matching silently fails forever."
	FingerprintAlgV1 = "anvil-fp/v1"

	// PartialFingerprintAnvilFindingID is the `result.partialFingerprints`
	// key carrying the full, never-truncated 64-hex-character anvil-fp/v1
	// digest. SARIF §3.5.4 versioned hierarchical string.
	PartialFingerprintAnvilFindingID = "anvilFindingId/v1"

	// PartialFingerprintPrimaryLocationLineHash is the ONLY partial
	// fingerprint GitHub code scanning reads (research/18, "What GitHub
	// actually accepts"). Required on every result that has a physical
	// location; consumed only by the GitHub projection (R.14).
	PartialFingerprintPrimaryLocationLineHash = "primaryLocationLineHash"

	// PartialFingerprintRegionSHA256 carries research/24's
	// `fingerprint.region_sha256`. DEVIATION: this key has no row in
	// plan/40-record-and-storage.md's Record Field Contract table, but
	// research/24 lists region_sha256 among its non-negotiable handoff
	// fields. Reserved here, optional on the wire; R.2 decides whether to
	// populate it. See CONTRACT.md "Logged deviations", item 2.
	PartialFingerprintRegionSHA256 = "regionSha256"
)

// Byte-level constants of the anvil-fp/v1 algorithm that other areas must not
// re-derive. The algorithm itself is R.2's (internal/record/fingerprint.go);
// these are the parts that are contract, not implementation.
const (
	// FingerprintFieldSeparator joins every hashed field. U+001F (ASCII Unit
	// Separator) is chosen over any printable glyph because a printable
	// separator can appear inside a snippet or symbol name and create a
	// field-boundary collision; U+001F cannot appear in normalized source
	// text. plan/40-record-and-storage.md, Fingerprint Specification.
	FingerprintFieldSeparator = "\x1f"

	// FingerprintDigestHexLen is the length of a full SHA-256 digest in
	// lowercase hex. The digest is NEVER truncated: truncating a
	// cryptographic digest without a forcing constraint only adds collision
	// risk for no benefit.
	FingerprintDigestHexLen = 64
)

// Body caps, matching OWASP ZAP's SARIF reporter (research/18 [S8]). Enforced
// by the masking pipeline (R.8) and the read path (R.13); the remainder
// spills to a content-addressed Tier-2 blob rather than being dropped.
const (
	MaxInlineRequestBodyBytes  = 8 * 1024
	MaxInlineResponseBodyBytes = 32 * 1024

	// RedactedPlaceholder is the exact value a masked header is replaced
	// with. Fixed here so a substring-absence test (Exit Criterion 8) and
	// the masker agree on one token.
	RedactedPlaceholder = "***REDACTED***"
)

// ---------------------------------------------------------------------------
// Enum machinery
// ---------------------------------------------------------------------------

// EnumError reports a value that is not a member of a frozen enum. It names
// the field and every legal literal, because the failure mode this contract
// exists to prevent is an area emitting a literal another area's NOT NULL
// column cannot accept — and a bare "invalid value" error does not tell the
// author which vocabulary they were supposed to use.
type EnumError struct {
	Field   string   // the anvil/* key or column the value was destined for
	Value   string   // the rejected literal
	Allowed []string // every legal literal, in declaration order
}

func (e *EnumError) Error() string {
	return fmt.Sprintf("record: %q is not a legal %s; legal values are %s",
		e.Value, e.Field, strings.Join(e.Allowed, "|"))
}

func inEnum[T ~string](v T, allowed []T) bool {
	for _, a := range allowed {
		if v == a {
			return true
		}
	}
	return false
}

func validateEnum[T ~string](field string, v T, allowed []T) error {
	if inEnum(v, allowed) {
		return nil
	}
	legal := make([]string, len(allowed))
	for i, a := range allowed {
		legal[i] = string(a)
	}
	return &EnumError{Field: field, Value: string(v), Allowed: legal}
}

// ---------------------------------------------------------------------------
// FROZEN ENUM 1 of 6 — anvil/state
// ---------------------------------------------------------------------------

// State is the audit-level lifecycle state, `sarifLog.properties["anvil/state"]`
// and `audit_record.state`.
//
// FROZEN by plan/IMPLEMENTATION-PLAN.md §6 ruling G2. Area O previously
// declared a four-state machine (`open → sast_sealed → sealed → expired`);
// that is struck. O.2 emits these literals.
type State string

// The six legal anvil/state literals.
//
// WHY StateDastSealed AND StateBothSealed EXIST — do not "simplify" this to a
// single `sealed`:
//
// plan/00-SPINE.md S1 requires "One audit identity, two INDEPENDENTLY-sealed
// halves, a re-entrant consumer." A state machine whose only sealing path is
// SAST-then-DAST cannot express a DAST-first seal at all — and a DAST-first
// seal is reachable in practice, because the SAST half can be slow or can
// fail while the DAST half completes. Collapsing dast_sealed and both_sealed
// into one `sealed` value also makes `sealed` terminal, which makes
// StateConsumed unreachable, which silently disables the re-entrant consumer
// read gate (R.6). Each of the six is reachable and each means something a
// consumer branches on.
const (
	// StateCollecting: neither half has sealed. No consumer may read either
	// half's results (R.6's read gate).
	StateCollecting State = "collecting"
	// StateSastSealed: the SAST half has sealed; the DAST half has not.
	StateSastSealed State = "sast_sealed"
	// StateDastSealed: the DAST half has sealed; the SAST half has not.
	// Reachable, and not a typo for sast_sealed — see the note above.
	StateDastSealed State = "dast_sealed"
	// StateBothSealed: both halves have sealed. A DAST-disabled audit
	// reaches this state with DastStatusNotRun (R.6), never with a NULL or
	// an invented "n/a" status.
	StateBothSealed State = "both_sealed"
	// StateConsumed: the coding-agent consumption pipeline has taken the
	// record. Unreachable if `sealed` is made terminal.
	StateConsumed State = "consumed"
	// StateExpired: the claim timeout elapsed. The tmpfs packet and
	// `audit_record.payload` are dropped; the DB row and the finding history
	// are NOT deleted (plan/40-record-and-storage.md, "Two independent
	// clocks").
	StateExpired State = "expired"
)

// StateValues returns every legal anvil/state literal, in lifecycle order.
func StateValues() []State {
	return []State{
		StateCollecting, StateSastSealed, StateDastSealed,
		StateBothSealed, StateConsumed, StateExpired,
	}
}

// Valid reports whether s is one of the six legal anvil/state literals.
func (s State) Valid() bool { return inEnum(s, StateValues()) }

// ValidateState reports whether v is a legal anvil/state literal, returning an
// *EnumError naming every legal value if it is not.
func ValidateState(v string) error {
	return validateEnum("anvil/state", State(v), StateValues())
}

// ---------------------------------------------------------------------------
// FROZEN ENUM 2 of 6 — anvil/status (per half)
// ---------------------------------------------------------------------------

// HalfStatus is the per-half run status, `run.properties["anvil/status"]` and
// `audit_record.sast_status` / `.dast_status`'s sealing counterpart.
//
// FROZEN by plan/IMPLEMENTATION-PLAN.md §6 ruling G5. Area O previously
// declared `complete|failed|timed_out`; `complete` is struck in favour of
// HalfStatusSealed, and `timed_out` is adopted from O.
type HalfStatus string

// The five legal per-half anvil/status literals.
//
// HalfStatusSealed is load-bearing, not cosmetic: R.6 makes `sealed` the hard
// consumer read gate ("do not allow a consumer to read a half's results
// before that half's status equals sealed"). An area keying its transition on
// any other token means the gate never opens and the consumer never runs.
const (
	// HalfStatusRunning: the half is still producing results.
	HalfStatusRunning HalfStatus = "running"
	// HalfStatusSealed: the half is complete and readable. This exact token
	// is R.6's read gate.
	HalfStatusSealed HalfStatus = "sealed"
	// HalfStatusFailed: the half terminated abnormally. Results, if any, are
	// not readable — a failed half is not a clean half.
	HalfStatusFailed HalfStatus = "failed"
	// HalfStatusTimedOut: the half exceeded its own deadline
	// (Deadline.DastDeadlineSeconds for the DAST half). Distinct from
	// HalfStatusFailed so an operator can tell "it broke" from "it ran out
	// of clock".
	HalfStatusTimedOut HalfStatus = "timed_out"
	// HalfStatusSkipped: the half was not run at all (e.g. the DAST tier is
	// not installed — plan/00-SPINE.md S9-AMENDED ships DAST as a separate
	// distribution artifact, so most halves will be skipped).
	HalfStatusSkipped HalfStatus = "skipped"
)

// HalfStatusValues returns every legal per-half anvil/status literal.
func HalfStatusValues() []HalfStatus {
	return []HalfStatus{
		HalfStatusRunning, HalfStatusSealed, HalfStatusFailed,
		HalfStatusTimedOut, HalfStatusSkipped,
	}
}

// Valid reports whether s is one of the five legal per-half status literals.
func (s HalfStatus) Valid() bool { return inEnum(s, HalfStatusValues()) }

// ValidateHalfStatus reports whether v is a legal per-half anvil/status
// literal.
func ValidateHalfStatus(v string) error {
	return validateEnum("anvil/status", HalfStatus(v), HalfStatusValues())
}

// ---------------------------------------------------------------------------
// FROZEN ENUM 3 of 6 — anvil/dastStatus
// ---------------------------------------------------------------------------

// DastStatus is the audit-level DAST outcome,
// `sarifLog.properties["anvil/dastStatus"]` and `audit_record.dast_status`.
// It is NEVER null and never absent.
//
// FROZEN by plan/IMPLEMENTATION-PLAN.md §6 rulings G3+G6, found independently
// by two critics. Area 40 declared seven values and area D declared five with
// ZERO literal overlap — D could not have written a single row into 40's NOT
// NULL column. The frozen set is the union of both plus D's `partial`
// (renamed `completed_partial`), which is nine values. D.26 emits these.
//
// This value is DERIVED from the DAST half's HalfStatus and from
// TargetProvenance (the boot/reachability outcome), never from
// TargetProvisioning (which provisioning path was used).
type DastStatus string

// The nine legal anvil/dastStatus literals.
//
// WHY DastStatusSkippedNoManifest IS DISTINCT FROM DastStatusNotRun — do not
// merge them:
//
//   - DastStatusNotRun means the DAST tier is not installed at all. Under
//     plan/00-SPINE.md S9-AMENDED, DAST ships as a separate distribution
//     artifact, so this is the common case and it says nothing about the
//     target.
//   - DastStatusSkippedNoManifest means the DAST tier IS installed and ran,
//     and no target manifest was declared, so there was nothing to scan.
//     That is a configuration gap in the target, and it is actionable.
//
// plan/00-SPINE.md S6 requires that "a target that failed to boot must be
// distinguishable from 'scanned clean'"; the same argument applies one level
// up. research/23-dast-signal-sources.md Risk #1: "Anvil must never report
// '0 DAST findings' as 'no dynamic vulnerabilities'." Merging these two makes
// exactly that mistake unfixable at the schema level.
const (
	// DastStatusNotRun: the DAST tier is not installed. Default for the
	// SAST-only distribution artifact.
	DastStatusNotRun DastStatus = "not_run"
	// DastStatusSkippedNoManifest: the DAST tier ran; no target manifest was
	// declared. NOT the same as not_run — see above.
	DastStatusSkippedNoManifest DastStatus = "skipped_no_manifest"
	// DastStatusRunning: the DAST half has not reached a terminal state.
	DastStatusRunning DastStatus = "running"
	// DastStatusCompletedClean: the DAST half completed and found nothing.
	// The ONLY value that may be read as "dynamically scanned, no findings".
	DastStatusCompletedClean DastStatus = "completed_clean"
	// DastStatusCompletedFindings: the DAST half completed with findings.
	DastStatusCompletedFindings DastStatus = "completed_findings"
	// DastStatusCompletedPartial: the DAST half completed against only part
	// of the discovered attack surface. Adopted from area D's `partial`;
	// coverage detail lives in DastCoverage, which is what makes this value
	// interpretable rather than merely worrying.
	DastStatusCompletedPartial DastStatus = "completed_partial"
	// DastStatusTargetBootFailed: the target never booted, so nothing was
	// scanned. Derived from TargetProvenanceBootFailed or
	// TargetProvenanceBuildFailed.
	DastStatusTargetBootFailed DastStatus = "target_boot_failed"
	// DastStatusTargetUnreachable: the target booted but was not reachable
	// at scan time. Derived from TargetProvenanceUnreachableAtScanTime.
	DastStatusTargetUnreachable DastStatus = "target_unreachable"
	// DastStatusTimedOut: the DAST half exceeded Deadline.DastDeadlineSeconds.
	DastStatusTimedOut DastStatus = "timed_out"
)

// DastStatusValues returns every legal anvil/dastStatus literal.
func DastStatusValues() []DastStatus {
	return []DastStatus{
		DastStatusNotRun, DastStatusSkippedNoManifest, DastStatusRunning,
		DastStatusCompletedClean, DastStatusCompletedFindings,
		DastStatusCompletedPartial, DastStatusTargetBootFailed,
		DastStatusTargetUnreachable, DastStatusTimedOut,
	}
}

// Valid reports whether s is one of the nine legal anvil/dastStatus literals.
func (s DastStatus) Valid() bool { return inEnum(s, DastStatusValues()) }

// ValidateDastStatus reports whether v is a legal anvil/dastStatus literal.
func ValidateDastStatus(v string) error {
	return validateEnum("anvil/dastStatus", DastStatus(v), DastStatusValues())
}

// MeansDynamicallyScannedClean reports whether s is the one value a consumer
// may treat as "this target was dynamically scanned and nothing was found".
// Every other value — including the three that merely mean "no findings were
// recorded" — must not be read that way.
//
// Provided so consumers do not write `if s != "completed_findings"`, which is
// the naive equality check D.26's own validation forbids.
func (s DastStatus) MeansDynamicallyScannedClean() bool {
	return s == DastStatusCompletedClean
}

// ---------------------------------------------------------------------------
// FROZEN ENUM 4 of 6 — anvil/target.provenance
// ---------------------------------------------------------------------------

// TargetProvenance is the target's BOOT AND REACHABILITY OUTCOME,
// `sarifLog.properties["anvil/target"].provenance` and
// `audit_record.target_provenance`.
//
// FROZEN by plan/IMPLEMENTATION-PLAN.md §6 rulings G4+G7, found independently
// by two critics. Produced by the target lifecycle harness (area D); this
// area only reserves the field and owns the vocabulary.
//
// WHY THIS IS SEPARATE FROM TargetProvisioning — do not merge them back into
// one field:
//
// They are two different measurements that were previously one field name
// carrying two meanings. TargetProvenance answers "what happened when we
// tried to run the target"; TargetProvisioning answers "which provisioning
// path did we take to get one". DastStatus is derived from the FORMER
// (booted_clean → the DAST half's own outcome; boot_failed/build_failed →
// target_boot_failed; unreachable_at_scan_time → target_unreachable). A merged
// field cannot support that derivation, and plan/00-SPINE.md S6 requires that
// "a target that failed to boot must be distinguishable from scanned clean" —
// which is information a merged field loses.
type TargetProvenance string

// The five legal anvil/target.provenance literals.
const (
	// TargetProvenanceBootedClean: the target came up and stayed up.
	TargetProvenanceBootedClean TargetProvenance = "booted_clean"
	// TargetProvenanceBootFailed: the target image built but would not start
	// or never became healthy.
	TargetProvenanceBootFailed TargetProvenance = "boot_failed"
	// TargetProvenanceBuildFailed: the target image never built, so a boot
	// was never attempted. Distinct from boot_failed because the remediation
	// is different (a build break, not a runtime break).
	TargetProvenanceBuildFailed TargetProvenance = "build_failed"
	// TargetProvenanceNoTargetDeclared: no runtime target was declared for
	// this scan. Maps to DastStatusSkippedNoManifest, not to a boot failure.
	TargetProvenanceNoTargetDeclared TargetProvenance = "no_target_declared"
	// TargetProvenanceUnreachableAtScanTime: the target was declared and
	// believed healthy, but was not reachable when the DAST half ran.
	TargetProvenanceUnreachableAtScanTime TargetProvenance = "unreachable_at_scan_time"
)

// TargetProvenanceValues returns every legal anvil/target.provenance literal.
func TargetProvenanceValues() []TargetProvenance {
	return []TargetProvenance{
		TargetProvenanceBootedClean, TargetProvenanceBootFailed,
		TargetProvenanceBuildFailed, TargetProvenanceNoTargetDeclared,
		TargetProvenanceUnreachableAtScanTime,
	}
}

// Valid reports whether p is one of the five legal provenance literals.
func (p TargetProvenance) Valid() bool { return inEnum(p, TargetProvenanceValues()) }

// ValidateTargetProvenance reports whether v is a legal
// anvil/target.provenance literal.
func ValidateTargetProvenance(v string) error {
	return validateEnum("anvil/target.provenance", TargetProvenance(v), TargetProvenanceValues())
}

// ---------------------------------------------------------------------------
// FROZEN ENUM 5 of 6 — anvil/target.provisioning (NEW required field)
// ---------------------------------------------------------------------------

// TargetProvisioning is WHICH PROVISIONING PATH produced the runtime target,
// `sarifLog.properties["anvil/target"].provisioning`.
//
// NEW REQUIRED FIELD, created by plan/IMPLEMENTATION-PLAN.md §6 rulings
// G4+G7. Area D previously wrote these two literals into a field it called
// `target_provenance`, which collided with area 40's boot-outcome field of
// the same name; the ruling split them rather than picking one, because they
// are genuinely different measurements and both are required. D.26 writes
// this field.
//
// The authorization consequence is why this cannot be folded into a comment:
// plan/00-SPINE.md S7 makes the authorization kernel a pure function of
// (target, scope, attestation, clock). A live, third-party-owned URL and a
// throwaway container Anvil built itself are not the same authorization
// question, and the record must state which one was scanned.
type TargetProvisioning string

// The two legal anvil/target.provisioning literals.
const (
	// TargetProvisioningEphemeralManifest: Anvil built and ran the target
	// itself from a declared manifest, in its own sandbox.
	TargetProvisioningEphemeralManifest TargetProvisioning = "ephemeral_manifest"
	// TargetProvisioningLiveURLAuthorized: an already-running URL was
	// scanned under an explicit authorization record. Never inferred from
	// reachability, and never from security.txt — plan/00-SPINE.md S7:
	// "security.txt resolves a reporting channel and never grants
	// permission."
	TargetProvisioningLiveURLAuthorized TargetProvisioning = "live_url_authorized"
)

// TargetProvisioningValues returns every legal anvil/target.provisioning
// literal.
func TargetProvisioningValues() []TargetProvisioning {
	return []TargetProvisioning{
		TargetProvisioningEphemeralManifest,
		TargetProvisioningLiveURLAuthorized,
	}
}

// Valid reports whether p is one of the two legal provisioning literals.
func (p TargetProvisioning) Valid() bool { return inEnum(p, TargetProvisioningValues()) }

// ValidateTargetProvisioning reports whether v is a legal
// anvil/target.provisioning literal.
func ValidateTargetProvisioning(v string) error {
	return validateEnum("anvil/target.provisioning", TargetProvisioning(v), TargetProvisioningValues())
}

// ---------------------------------------------------------------------------
// FROZEN ENUM 6 of 6 — anvil/verdict
// ---------------------------------------------------------------------------

// Verdict is the triage judgment about a FINDING,
// `result.properties["anvil/verdict"]` and `finding.verdict`.
//
// FROZEN by plan/IMPLEMENTATION-PLAN.md §6 ruling G8. Lane B keeps its own
// in-process `Verdict.Result` vocabulary (`EXHIBITS|…`), which is a judgment
// about the CODE; B.12 owns the explicit, tested mapping onto these literals,
// including the case normalisation, at the point it places findings on the
// record. A mapping with an owner and a test is not the same thing as two
// vocabularies drifting.
type Verdict string

// The three legal anvil/verdict literals.
//
// WHY VerdictInsufficientContext IS A VERDICT AND NOT A LOW CONFIDENCE SCORE —
// do not replace it with a threshold on Confidence:
//
// plan/00-SPINE.md S6 is explicit: "INSUFFICIENT_CONTEXT as a valid detector
// verdict, not just a confidence float." A low confidence score means "this
// is probably not a real defect". `insufficient_context` means "this may well
// be a real defect and the detector could not see enough to tell" — usually
// because the sink is behind a dynamic dispatch, a framework boundary, or a
// file the scan did not have. Those two demand opposite handling: the first
// is dropped, the second is escalated to a human or to the DAST half, and is
// exactly the population a confidence threshold silently discards. The
// consumption pipeline drops VerdictFalsePositive and demotes
// VerdictInsufficientContext to report-only; it must be able to tell them
// apart, and a float cannot.
const (
	// VerdictTruePositive: the finding is a real defect. The only verdict
	// the coding-agent consumption pipeline acts on.
	VerdictTruePositive Verdict = "true_positive"
	// VerdictFalsePositive: the finding is not a real defect. Dropped by the
	// consumption pipeline.
	VerdictFalsePositive Verdict = "false_positive"
	// VerdictInsufficientContext: the detector could not decide with the
	// context it had. Report-only; never silently dropped. See above.
	VerdictInsufficientContext Verdict = "insufficient_context"
)

// VerdictValues returns every legal anvil/verdict literal.
func VerdictValues() []Verdict {
	return []Verdict{VerdictTruePositive, VerdictFalsePositive, VerdictInsufficientContext}
}

// Valid reports whether v is one of the three legal anvil/verdict literals.
func (v Verdict) Valid() bool { return inEnum(v, VerdictValues()) }

// ValidateVerdict reports whether v is a legal anvil/verdict literal.
func ValidateVerdict(v string) error {
	return validateEnum("anvil/verdict", Verdict(v), VerdictValues())
}

// ---------------------------------------------------------------------------
// anvil/trust — required by plan/00-SPINE.md S6 on EVERY string originating
// outside Anvil. Frozen here for the same reason as the six above.
// ---------------------------------------------------------------------------

// Trust classifies where a string came from. plan/00-SPINE.md S6 requires it
// "on every string originating outside Anvil"; plan/00-SPINE.md S7 makes it
// enforceable: the prompt builder must never treat untrusted text as
// instructions, and "the DAST response body is the highest-risk field — up to
// 32 KB of attacker-controlled bytes fed to a repo-credentialed agent."
type Trust string

// The three legal anvil/trust literals.
const (
	// TrustUntrusted: the bytes originated outside Anvil and have not been
	// validated. Target-repo source, advisory feed text, DAST response
	// bodies, and imported third-party SARIF are all untrusted.
	//
	// THE MISTAKE THIS EXISTS TO PREVENT: a repo source snippet is
	// `untrusted` even though Anvil is the component that put it in the
	// struct. Area B was found stamping TrustAnvilGenerated on a struct
	// whose Snippet field is verbatim target-repo source. That would have
	// disabled the prompt-injection containment check on the exact string
	// that most needs it — an attacker who can commit to the scanned repo
	// can write agent instructions into a comment. The question TrustLevel
	// answers is "who wrote these bytes", never "who assigned this field".
	TrustUntrusted Trust = "untrusted"
	// TrustAnvilGenerated: Anvil itself produced the bytes — detector
	// reasoning, derived summaries, computed digests. Not merely
	// "assembled by Anvil".
	TrustAnvilGenerated Trust = "anvil_generated"
	// TrustVerified: the bytes originated outside Anvil AND passed an
	// explicit validation step that is named in the record (e.g. a
	// signature-checked advisory snapshot). Never a default.
	TrustVerified Trust = "verified"
)

// TrustValues returns every legal anvil/trust literal.
func TrustValues() []Trust {
	return []Trust{TrustUntrusted, TrustAnvilGenerated, TrustVerified}
}

// Valid reports whether t is one of the three legal anvil/trust literals.
func (t Trust) Valid() bool { return inEnum(t, TrustValues()) }

// ValidateTrust reports whether v is a legal anvil/trust literal.
func ValidateTrust(v string) error {
	return validateEnum("anvil/trust", Trust(v), TrustValues())
}

// LegalForExternalString reports whether t may be applied to a string that
// originated outside Anvil. TrustAnvilGenerated may not: that is precisely
// the mislabelling ruled on above.
func (t Trust) LegalForExternalString() bool {
	return t == TrustUntrusted || t == TrustVerified
}

// ---------------------------------------------------------------------------
// handoff.state — frozen alongside the six, per plan/IMPLEMENTATION-PLAN.md
// §6's enum block. The TABLE is R.4's; the VOCABULARY is this file's.
// ---------------------------------------------------------------------------

// HandoffState is the disposition of one finding in the handoff queue,
// `handoff.state`.
//
// FROZEN by plan/IMPLEMENTATION-PLAN.md §6 rulings G9+G10. Area X was
// building a second table (`anvil_ledger`) carrying the same dispositions;
// that is collapsed into `handoff`, because R.4's own Forbidden actions
// already say a second durable copy is a direct plan/00-SPINE.md S1
// violation. The concrete failure the critic traced: X.9 wrote
// `SKIPPED_BUDGET` to `anvil_ledger` while 40's ready-set index still saw the
// finding as `ready`, so it was re-leased forever.
//
// R.4 owns the DDL; every area emits these literals.
type HandoffState string

// The thirteen legal handoff.state literals: area 40's original nine plus the
// four dispositions only area X had.
const (
	HandoffStateReady                HandoffState = "ready"
	HandoffStateLeased               HandoffState = "leased"
	HandoffStateValidated            HandoffState = "validated"
	HandoffStateFailedValidation     HandoffState = "failed_validation"
	HandoffStateFailedFormat         HandoffState = "failed_format"
	HandoffStateSkippedBudget        HandoffState = "skipped_budget"
	HandoffStateFalsePositive        HandoffState = "false_positive"
	HandoffStateRegressionIntroduced HandoffState = "regression_introduced"
	// The four from area X:
	HandoffStateFixedIncidentally HandoffState = "fixed_incidentally"
	HandoffStateSplitRequired     HandoffState = "split_required"
	HandoffStateWithdrawn         HandoffState = "withdrawn"
	HandoffStateSuperseded        HandoffState = "superseded"
	// HandoffStateExpired is set at claim-timeout expiry. Only the tmpfs
	// packet is dropped; the row is kept.
	HandoffStateExpired HandoffState = "expired"
)

// HandoffStateValues returns every legal handoff.state literal.
func HandoffStateValues() []HandoffState {
	return []HandoffState{
		HandoffStateReady, HandoffStateLeased, HandoffStateValidated,
		HandoffStateFailedValidation, HandoffStateFailedFormat,
		HandoffStateSkippedBudget, HandoffStateFalsePositive,
		HandoffStateRegressionIntroduced, HandoffStateFixedIncidentally,
		HandoffStateSplitRequired, HandoffStateWithdrawn,
		HandoffStateSuperseded, HandoffStateExpired,
	}
}

// Valid reports whether s is one of the thirteen legal handoff.state literals.
func (s HandoffState) Valid() bool { return inEnum(s, HandoffStateValues()) }

// ValidateHandoffState reports whether v is a legal handoff.state literal.
func ValidateHandoffState(v string) error {
	return validateEnum("handoff.state", HandoffState(v), HandoffStateValues())
}

// ConsumptionClass gates whether a finding may be acted on from static
// evidence alone, `handoff.consumption_class`. Merged into the handoff table
// by plan/IMPLEMENTATION-PLAN.md §6 ruling G9 (it came from area O.3, and
// nothing else in the schema can express the gate).
type ConsumptionClass string

const (
	// ConsumptionClassStaticOnly: static evidence is sufficient to propose a
	// patch.
	ConsumptionClassStaticOnly ConsumptionClass = "static_only"
	// ConsumptionClassRequiresDynamicConfirmation: a DAST reproduction must
	// exist before the coding agent acts. plan/00-SPINE.md S7: "Only a DAST
	// reproduction that now fails earns 'verified fixed.'"
	ConsumptionClassRequiresDynamicConfirmation ConsumptionClass = "requires_dynamic_confirmation"
)

// ConsumptionClassValues returns every legal handoff.consumption_class
// literal.
func ConsumptionClassValues() []ConsumptionClass {
	return []ConsumptionClass{
		ConsumptionClassStaticOnly,
		ConsumptionClassRequiresDynamicConfirmation,
	}
}

// Valid reports whether c is a legal consumption_class literal.
func (c ConsumptionClass) Valid() bool { return inEnum(c, ConsumptionClassValues()) }

// ValidateConsumptionClass reports whether v is a legal
// handoff.consumption_class literal.
func ValidateConsumptionClass(v string) error {
	return validateEnum("handoff.consumption_class", ConsumptionClass(v), ConsumptionClassValues())
}

// ---------------------------------------------------------------------------
// Area-40-owned supporting vocabularies. Not among the six §6 named, but
// shared across areas and therefore declared here for the same reason.
// ---------------------------------------------------------------------------

// Half names which of the two independently-sealed halves produced a run or a
// result: `run.properties["anvil/half"]`, `result.properties["anvil/half"]`.
type Half string

const (
	HalfSast Half = "sast"
	HalfDast Half = "dast"
)

// HalfValues returns every legal anvil/half literal.
func HalfValues() []Half { return []Half{HalfSast, HalfDast} }

// Valid reports whether h is a legal anvil/half literal.
func (h Half) Valid() bool { return inEnum(h, HalfValues()) }

// ValidateHalf reports whether v is a legal anvil/half literal.
func ValidateHalf(v string) error { return validateEnum("anvil/half", Half(v), HalfValues()) }

// EvidenceClass says HOW STRONG the evidence for a finding is,
// `result.properties["anvil/evidenceClass"]` and `finding.evidence_class`.
// research/24-coding-agent-consumption.md: "this is the field that makes
// tier-0 ordering possible". Consumed by the queue re-cut (R.11) and the read
// path (R.13).
type EvidenceClass string

const (
	// EvidenceClassDastConfirmed: a runtime reproduction exists. The class
	// R.11 reserves budget for.
	EvidenceClassDastConfirmed EvidenceClass = "dast_confirmed"
	// EvidenceClassSastReachable: static analysis proved a path from an
	// untrusted source to the sink.
	EvidenceClassSastReachable EvidenceClass = "sast_reachable"
	// EvidenceClassSastStaticOnly: the sink matched, reachability was not
	// established.
	EvidenceClassSastStaticOnly EvidenceClass = "sast_static_only"
	// EvidenceClassSCA: a dependency matched a vulnerable version range
	// (Lane A, zero inference).
	EvidenceClassSCA EvidenceClass = "sca"
	// EvidenceClassHost: a host package matched. Always
	// RemediableByAgent=false — plan/00-SPINE.md S7 makes the host agent
	// read-only, "no package manager in a mutating mode, not behind a flag."
	EvidenceClassHost EvidenceClass = "host"
)

// EvidenceClassValues returns every legal anvil/evidenceClass literal, in
// descending evidence strength — which is also the default rank order.
func EvidenceClassValues() []EvidenceClass {
	return []EvidenceClass{
		EvidenceClassDastConfirmed, EvidenceClassSastReachable,
		EvidenceClassSastStaticOnly, EvidenceClassSCA, EvidenceClassHost,
	}
}

// Valid reports whether e is a legal anvil/evidenceClass literal.
func (e EvidenceClass) Valid() bool { return inEnum(e, EvidenceClassValues()) }

// ValidateEvidenceClass reports whether v is a legal anvil/evidenceClass
// literal.
func ValidateEvidenceClass(v string) error {
	return validateEnum("anvil/evidenceClass", EvidenceClass(v), EvidenceClassValues())
}

// DetectorKind selects the fingerprint tier (R.2) and populates
// `finding.detector`. It is deliberately NOT the same enum as EvidenceClass:
// `sast_reachable` and `sast_static_only` are both produced by the `sast`
// detector and must hash identically per tier.
type DetectorKind string

const (
	DetectorKindSast DetectorKind = "sast"
	DetectorKindDast DetectorKind = "dast"
	DetectorKindSCA  DetectorKind = "sca"
	DetectorKindHost DetectorKind = "host"
)

// DetectorKindValues returns every legal finding.detector literal.
func DetectorKindValues() []DetectorKind {
	return []DetectorKind{DetectorKindSast, DetectorKindDast, DetectorKindSCA, DetectorKindHost}
}

// Valid reports whether d is a legal finding.detector literal.
func (d DetectorKind) Valid() bool { return inEnum(d, DetectorKindValues()) }

// ValidateDetectorKind reports whether v is a legal finding.detector literal.
func ValidateDetectorKind(v string) error {
	return validateEnum("finding.detector", DetectorKind(v), DetectorKindValues())
}

// InjectionPoint is WHERE a DAST payload was injected. Hashed by the DAST
// fingerprint tier (R.2), so the vocabulary is contract, not implementation.
type InjectionPoint string

const (
	InjectionPointQuery  InjectionPoint = "query"
	InjectionPointBody   InjectionPoint = "body"
	InjectionPointHeader InjectionPoint = "header"
	InjectionPointCookie InjectionPoint = "cookie"
	InjectionPointPath   InjectionPoint = "path"
)

// InjectionPointValues returns every legal injection-point literal.
func InjectionPointValues() []InjectionPoint {
	return []InjectionPoint{
		InjectionPointQuery, InjectionPointBody, InjectionPointHeader,
		InjectionPointCookie, InjectionPointPath,
	}
}

// Valid reports whether i is a legal injection-point literal.
func (i InjectionPoint) Valid() bool { return inEnum(i, InjectionPointValues()) }

// ValidateInjectionPoint reports whether v is a legal injection-point literal.
func ValidateInjectionPoint(v string) error {
	return validateEnum("anvil/repro.injectionPoint.kind", InjectionPoint(v), InjectionPointValues())
}

// EvidenceSignal is HOW a DAST vulnerability was observed. Independent of
// InjectionPoint — where the payload went in and how the defect showed up are
// two different facts — and hashed as a separate field by the DAST
// fingerprint tier (plan/40-record-and-storage.md, Fingerprint Specification).
type EvidenceSignal string

const (
	EvidenceSignalResponseStackTrace EvidenceSignal = "responseStackTrace"
	EvidenceSignalStatusCodeFlip     EvidenceSignal = "statusCodeFlip"
	EvidenceSignalDBErrorString      EvidenceSignal = "dbErrorString"
	EvidenceSignalTimingSideChannel  EvidenceSignal = "timingSideChannel"
	EvidenceSignalReflectedPayload   EvidenceSignal = "reflectedPayload"
	EvidenceSignalOther              EvidenceSignal = "other"
)

// EvidenceSignalValues returns every legal evidence-signal literal.
func EvidenceSignalValues() []EvidenceSignal {
	return []EvidenceSignal{
		EvidenceSignalResponseStackTrace, EvidenceSignalStatusCodeFlip,
		EvidenceSignalDBErrorString, EvidenceSignalTimingSideChannel,
		EvidenceSignalReflectedPayload, EvidenceSignalOther,
	}
}

// Valid reports whether s is a legal evidence-signal literal.
func (s EvidenceSignal) Valid() bool { return inEnum(s, EvidenceSignalValues()) }

// ValidateEvidenceSignal reports whether v is a legal evidence-signal literal.
func ValidateEvidenceSignal(v string) error {
	return validateEnum("anvil/repro.observedSignal.kind", EvidenceSignal(v), EvidenceSignalValues())
}

// CorrelationSignal names one independent correlation signal.
// research/18-unified-audit-record.md Table 2 and its correlation policy:
// at least two independent signals are required before a link may be emitted,
// and CorrelationSignalCweMatch is BANNED as a sole signal.
type CorrelationSignal string

const (
	CorrelationSignalResponseStackTrace CorrelationSignal = "responseStackTrace"
	CorrelationSignalRouteTable         CorrelationSignal = "routeTable"
	CorrelationSignalCallGraphReach     CorrelationSignal = "callGraphReach"
	CorrelationSignalParameterName      CorrelationSignal = "parameterName"
	CorrelationSignalCweMatch           CorrelationSignal = "cweMatch"
	CorrelationSignalRerunFlip          CorrelationSignal = "rerunFlip"
)

// CorrelationSignalValues returns every legal correlation-signal literal.
func CorrelationSignalValues() []CorrelationSignal {
	return []CorrelationSignal{
		CorrelationSignalResponseStackTrace, CorrelationSignalRouteTable,
		CorrelationSignalCallGraphReach, CorrelationSignalParameterName,
		CorrelationSignalCweMatch, CorrelationSignalRerunFlip,
	}
}

// Valid reports whether s is a legal correlation-signal literal.
func (s CorrelationSignal) Valid() bool { return inEnum(s, CorrelationSignalValues()) }

// ValidateCorrelationSignal reports whether v is a legal correlation-signal
// literal.
func ValidateCorrelationSignal(v string) error {
	return validateEnum("anvil/correlation.signals[].name", CorrelationSignal(v), CorrelationSignalValues())
}

// SufficientForVerified reports whether s is one of the two signals that may
// set Correlation.Verified. plan/00-SPINE.md S7: "Only a DAST reproduction
// that now fails earns 'verified fixed.' A clean SAST rescan does not."
// Confidence alone never qualifies.
func (s CorrelationSignal) SufficientForVerified() bool {
	return s == CorrelationSignalResponseStackTrace || s == CorrelationSignalRerunFlip
}

// FindingState is the durable lifecycle state of a finding, `finding.state`.
type FindingState string

const (
	FindingStateOpen       FindingState = "open"
	FindingStateResolved   FindingState = "resolved"
	FindingStateSuppressed FindingState = "suppressed"
	FindingStateRegressed  FindingState = "regressed"
)

// FindingStateValues returns every legal finding.state literal.
func FindingStateValues() []FindingState {
	return []FindingState{
		FindingStateOpen, FindingStateResolved,
		FindingStateSuppressed, FindingStateRegressed,
	}
}

// Valid reports whether s is a legal finding.state literal.
func (s FindingState) Valid() bool { return inEnum(s, FindingStateValues()) }

// ValidateFindingState reports whether v is a legal finding.state literal.
func ValidateFindingState(v string) error {
	return validateEnum("finding.state", FindingState(v), FindingStateValues())
}

// ScanRunStatus is the whole-scan status, `scan_run.status`. Written by the
// scan controller (area O), read by area 40's store.
type ScanRunStatus string

const (
	ScanRunStatusRunning ScanRunStatus = "running"
	ScanRunStatusOK      ScanRunStatus = "ok"
	ScanRunStatusFailed  ScanRunStatus = "failed"
	ScanRunStatusPartial ScanRunStatus = "partial"
)

// ScanRunStatusValues returns every legal scan_run.status literal.
func ScanRunStatusValues() []ScanRunStatus {
	return []ScanRunStatus{
		ScanRunStatusRunning, ScanRunStatusOK,
		ScanRunStatusFailed, ScanRunStatusPartial,
	}
}

// Valid reports whether s is a legal scan_run.status literal.
func (s ScanRunStatus) Valid() bool { return inEnum(s, ScanRunStatusValues()) }

// ValidateScanRunStatus reports whether v is a legal scan_run.status literal.
func ValidateScanRunStatus(v string) error {
	return validateEnum("scan_run.status", ScanRunStatus(v), ScanRunStatusValues())
}

// InventoryProvenance says how an endpoint entered the DAST inventory.
//
// NOT one of the six frozen enums. Area D (D.18–D.25) produces it per route
// and aggregates it into DastCoverage.InventoryProvenanceMix. It is mirrored
// here so the record's shape is knowable and so a naming drift is caught at
// this file rather than at integration; if area D needs to change the
// vocabulary, it amends this file rather than diverging from it. Flagged to
// the orchestrator as a candidate seventh frozen enum.
type InventoryProvenance string

const (
	// InventoryProvenanceRuntimeSpec: an OpenAPI/GraphQL spec served by the
	// running target.
	InventoryProvenanceRuntimeSpec InventoryProvenance = "runtime_spec"
	// InventoryProvenanceRepoSpec: a spec file committed to the repo.
	InventoryProvenanceRepoSpec InventoryProvenance = "repo_spec"
	// InventoryProvenanceStaticExtraction: routes extracted from source.
	InventoryProvenanceStaticExtraction InventoryProvenance = "static_extraction"
	// InventoryProvenanceCrawl: routes found by crawling. Weakest evidence.
	InventoryProvenanceCrawl InventoryProvenance = "crawl"
)

// InventoryProvenanceValues returns every legal inventory-provenance literal,
// strongest evidence first.
func InventoryProvenanceValues() []InventoryProvenance {
	return []InventoryProvenance{
		InventoryProvenanceRuntimeSpec, InventoryProvenanceRepoSpec,
		InventoryProvenanceStaticExtraction, InventoryProvenanceCrawl,
	}
}

// Valid reports whether p is a legal inventory-provenance literal.
func (p InventoryProvenance) Valid() bool { return inEnum(p, InventoryProvenanceValues()) }

// ValidateInventoryProvenance reports whether v is a legal
// inventory-provenance literal.
func ValidateInventoryProvenance(v string) error {
	return validateEnum("anvil/dastCoverage.inventoryProvenanceMix", InventoryProvenance(v), InventoryProvenanceValues())
}

// SARIF-native enums. Listed for completeness and constant-safety; these are
// OASIS's vocabulary, not Anvil's, and must not be extended.
type (
	// Level is SARIF §3.27.10 `result.level` — severity, not confidence.
	Level string
	// Kind is SARIF §3.27.9 `result.kind`.
	Kind string
)

const (
	LevelNone    Level = "none"
	LevelNote    Level = "note"
	LevelWarning Level = "warning"
	LevelError   Level = "error"

	KindNotApplicable Kind = "notApplicable"
	KindPass          Kind = "pass"
	KindFail          Kind = "fail"
	KindReview        Kind = "review"
	KindOpen          Kind = "open"
	KindInformational Kind = "informational"
)

// LevelValues returns every legal SARIF result.level literal.
func LevelValues() []Level { return []Level{LevelNone, LevelNote, LevelWarning, LevelError} }

// Valid reports whether l is a legal SARIF result.level literal.
func (l Level) Valid() bool { return inEnum(l, LevelValues()) }

// KindValues returns every legal SARIF result.kind literal.
func KindValues() []Kind {
	return []Kind{KindNotApplicable, KindPass, KindFail, KindReview, KindOpen, KindInformational}
}

// Valid reports whether k is a legal SARIF result.kind literal.
func (k Kind) Valid() bool { return inEnum(k, KindValues()) }

// ---------------------------------------------------------------------------
// anvil/* property-key constants
//
// Every extension key, in one place, so no area spells one by hand. Grouped
// by the SARIF object whose `properties` bag carries it.
// ---------------------------------------------------------------------------

// Keys in `sarifLog.properties`.
const (
	PropAuditSchemaVersion = "anvil/schemaVersion"
	PropAuditID            = "anvil/auditId"
	PropAuditState         = "anvil/state"
	PropAuditVersion       = "anvil/version"
	PropAuditCreatedAt     = "anvil/createdAt"
	PropAuditTarget        = "anvil/target"
	PropAuditTrigger       = "anvil/trigger"
	PropAuditDeadline      = "anvil/deadline"
	PropAuditDB            = "anvil/db"
	PropAuditIndex         = "anvil/index"
	PropAuditDastStatus    = "anvil/dastStatus"
)

// Keys in `run.properties`.
const (
	PropRunHalf             = "anvil/half"
	PropRunStatus           = "anvil/status"
	PropRunSealedAt         = "anvil/sealedAt"
	PropRunDastCoverage     = "anvil/dastCoverage"
	PropRunRouteTableDigest = "anvil/routeTableDigest"
	PropRunAdvisorySnapshot = "anvil/advisorySnapshot"
	PropRunRuntimeTarget    = "anvil/runtimeTarget"
)

// Keys in `result.properties`.
const (
	PropResultFindingID         = "anvil/findingId"
	PropResultHalf              = "anvil/half"
	PropResultConfidence        = "anvil/confidence"
	PropResultVerdict           = "anvil/verdict"
	PropResultRemediableByAgent = "anvil/remediableByAgent"
	PropResultReasoning         = "anvil/reasoning"
	PropResultDetector          = "anvil/detector"
	PropResultAdvisory          = "anvil/advisory"
	PropResultTrust             = "anvil/trust"
	PropResultPatchContext      = "anvil/patchContext"
	PropResultCorrelation       = "anvil/correlation"
	PropResultRepro             = "anvil/repro"
	PropResultChunkRef          = "anvil/chunkRef"
	PropResultEvidenceClass     = "anvil/evidenceClass"
	PropResultLocus             = "anvil/locus"
	PropResultGroupID           = "anvil/groupId"
	PropResultRisk              = "anvil/risk"
)

// Keys in `location.properties` (SARIF §3.28.6).
const (
	PropLocationKind          = "anvil/locationKind"
	PropLocationRouteTemplate = "anvil/routeTemplate"
)

// ---------------------------------------------------------------------------
// Audit envelope — sarifLog and its anvil/* bag
// ---------------------------------------------------------------------------

// SARIFLog is the top-level SARIF 2.1.0 object Anvil produces: one audit
// identity carrying two independently-sealed halves as two runs
// (plan/00-SPINE.md S1).
type SARIFLog struct {
	Schema     string          `json:"$schema"`
	Version    string          `json:"version"`
	Runs       []Run           `json:"runs"`
	Properties AuditProperties `json:"properties"`
}

// AuditProperties is the typed `anvil/*` bag on `sarifLog.properties`.
type AuditProperties struct {
	// SchemaVersion is this contract's version. Producer: record assembler.
	// Consumer: store, migrations, coding agent.
	SchemaVersion string `json:"anvil/schemaVersion"`

	// AuditID is the audit identity, assigned once at scan start. Producer:
	// scan controller. Consumer: store (PK), handoff, coding agent, report.
	// It is also the value of `run.automationDetails.correlationGuid` in
	// BOTH runs — the SARIF-native "these runs are one audit" mechanism.
	AuditID string `json:"anvil/auditId"`

	// State is the audit lifecycle state. Producer: scan controller (O.2).
	// Consumer: handoff consumer, store, report.
	State State `json:"anvil/state"`

	// Version is a monotonic integer, bumped on every re-scan of the same
	// audit. Producer: scan controller. Consumer: the queue re-cut (R.11) —
	// plan/00-SPINE.md S6 requires re-cutting the work queue on every bump,
	// "otherwise incremental publication silently inverts the priority
	// scheme."
	Version int `json:"anvil/version"`

	// CreatedAt is scan start. Producer: scan controller. Consumer: store,
	// reaper.
	CreatedAt time.Time `json:"anvil/createdAt"`

	// Target identifies what was scanned. Producer: scan controller (repo
	// fields) and the target lifecycle harness (Provenance, Provisioning).
	// Consumer: coding agent, correlation, report.
	Target Target `json:"anvil/target"`

	// Trigger REFERENCES the policy that fired; the condition itself is
	// never encoded in the record (research/18: "No trigger condition is
	// ever encoded in the schema itself"). Producer: scan controller.
	// Consumer: report, audit trail.
	Trigger Trigger `json:"anvil/trigger"`

	// Deadline replaces branch 18's `anvil/buffer`, per the plan/00-SPINE.md
	// S1 correction: the 8 hours is a CLAIM TIMEOUT, not a deletion policy
	// and not a confidentiality control. Producer: scan controller and the
	// config loader. Consumer: reaper, handoff, coding agent.
	Deadline Deadline `json:"anvil/deadline"`

	// DB is populated after the store commits. Producer: store writer.
	// Consumer: audit trail. Null before commit.
	DB *DBRef `json:"anvil/db,omitempty"`

	// Index is the Tier-0 manifest (target <= 8 KB). Producer: record
	// assembler. Consumer: coding agent's first read.
	Index Index `json:"anvil/index"`

	// DastStatus is the audit-level mirror of the DAST half's outcome.
	// REQUIRED AND NEVER NULL. Producer: scan controller, derived from the
	// DAST run's HalfStatus and from Target.Provenance. Consumer: coding
	// agent, which must not treat an absent DAST half as "scanned clean".
	DastStatus DastStatus `json:"anvil/dastStatus"`
}

// Target identifies the scanned repository and, when DAST is enabled, the
// runtime target. `anvil/target`.
type Target struct {
	RepoURL string `json:"repoUrl"`
	Ref     string `json:"ref"`
	Commit  string `json:"commit"`
	Subpath string `json:"subpath"`

	// RuntimeBaseURL is required only when DAST is enabled.
	RuntimeBaseURL string `json:"runtimeBaseUrl,omitempty"`

	// Provenance is the BOOT/REACHABILITY OUTCOME. DastStatus is derived
	// from this field. Producer: target lifecycle harness (area D).
	Provenance TargetProvenance `json:"provenance"`

	// Provisioning is WHICH PROVISIONING PATH was taken. A different
	// measurement from Provenance; see TargetProvisioning's doc comment for
	// why merging them loses information plan/00-SPINE.md S6 requires.
	// Producer: target lifecycle harness (D.26).
	Provisioning TargetProvisioning `json:"provisioning"`
}

// Trigger names the configured policy that fired. `anvil/trigger`.
type Trigger struct {
	Kind         string    `json:"kind"`
	PolicyID     string    `json:"policyId"`
	PolicyRef    string    `json:"policyRef"`
	ConfigSource string    `json:"configSource"`
	Actor        string    `json:"actor"`
	ResolvedAt   time.Time `json:"resolvedAt"`
}

// Deadline carries the claim clock. `anvil/deadline`.
//
// DeadlineAt and the per-half SealedAt are INDEPENDENT CLOCKS with
// independent semantics and must never be conflated (R.6's forbidden
// actions): SealedAt records per-half completion, DeadlineAt records when an
// unclaimed finding stops being eligible.
type Deadline struct {
	// DeadlineAt = scan_run.started_at + ClaimTimeoutSeconds, computed ONCE
	// at scan START and never recomputed from any write timestamp. Anchoring
	// it to the last write makes the timeout unbounded for a chatty scan.
	DeadlineAt time.Time `json:"deadlineAt"`

	// ClaimTimeoutSeconds defaults to DefaultClaimTimeoutSeconds and is
	// config-driven. Producer: config loader. Consumer: reaper.
	ClaimTimeoutSeconds int `json:"claimTimeoutSeconds"`

	// DastDeadlineSeconds is an INDEPENDENT clock from ClaimTimeoutSeconds,
	// null when DAST is disabled. Producer: config loader. Consumer: DAST
	// worker, target lifecycle harness.
	DastDeadlineSeconds *int `json:"dastDeadlineSeconds"`
}

// DefaultClaimTimeoutSeconds is 8 hours. It is a claim timeout, not a
// retention or confidentiality guarantee — see internal/record/SECRETS.md
// (R.9). Config-driven; this is only the documented default.
const DefaultClaimTimeoutSeconds = 28800

// DBRef records where the audit landed in the store. `anvil/db`.
type DBRef struct {
	RecordID  string    `json:"recordId"`
	WrittenAt time.Time `json:"writtenAt"`
}

// Index is the Tier-0 read plan the coding agent reads first. `anvil/index`.
// Target size <= 8 KB (research/18, "Size — the three-tier read path").
type Index struct {
	Counts IndexCounts `json:"counts"`

	// ReadOrder is DETERMINISTIC and not model-chosen: correlated clusters
	// first (they carry runtime proof), then SAST-only by rank, then
	// DAST-only. See DefaultReadOrder.
	ReadOrder []string `json:"readOrder"`

	ByCluster map[string][]string `json:"byCluster"`
	ByCwe     map[string][]string `json:"byCwe"`
	ByPath    map[string][]string `json:"byPath"`

	// TaskCards and Blobs are the Tier-1 and Tier-2 path prefixes.
	TaskCards string `json:"taskCards"`
	Blobs     string `json:"blobs"`
}

// IndexCounts are the Tier-0 counts.
type IndexCounts struct {
	Total       int `json:"total"`
	Sast        int `json:"sast"`
	Dast        int `json:"dast"`
	Clusters    int `json:"clusters"`
	Unclustered int `json:"unclustered"`
}

// DefaultReadOrder is the deterministic Tier-0 read order. R.13 must not
// emit any other order without an explicit, logged override.
func DefaultReadOrder() []string { return []string{"clusters", "sastByRank", "dastByRank"} }

// MaxTier0ManifestBytes is the Tier-0 budget (research/18).
const MaxTier0ManifestBytes = 8 * 1024

// MaxTier1CardTokens is the Tier-1 task-card budget in approximate tokens
// (research/18: ~1,500–2,500 tokens/card).
const MaxTier1CardTokens = 2500

// MaxAdvisoryExcerptTokens caps an inlined advisory excerpt
// (research/24: "<=800 tokens, pre-trimmed by the ingestion side, never a
// whole advisory").
const MaxAdvisoryExcerptTokens = 800

// ---------------------------------------------------------------------------
// Per-half run
// ---------------------------------------------------------------------------

// Run is one half of the audit — the SAST half or the DAST half. Both runs
// carry the SAME `automationDetails.correlationGuid`, which is the
// SARIF-native (§3.17.5) statement that they are one audit.
type Run struct {
	Tool                           Tool                            `json:"tool"`
	AutomationDetails              RunAutomationDetails            `json:"automationDetails"`
	OriginalURIBaseIDs             map[string]ArtifactLocation     `json:"originalUriBaseIds,omitempty"`
	Taxonomies                     []ToolComponent                 `json:"taxonomies,omitempty"`
	Results                        []Result                        `json:"results"`
	ExternalPropertyFileReferences *ExternalPropertyFileReferences `json:"externalPropertyFileReferences,omitempty"`
	Properties                     RunProperties                   `json:"properties"`
}

// RunProperties is the typed `anvil/*` bag on `run.properties`.
type RunProperties struct {
	// Half names which half produced this run. Producer: SAST/DAST worker.
	// Consumer: routing.
	Half Half `json:"anvil/half"`

	// Status is the per-half seal status. HalfStatusSealed is R.6's hard
	// consumer read gate. Producer: SAST/DAST worker at seal time.
	// Consumer: the re-entrant consumer, report.
	Status HalfStatus `json:"anvil/status"`

	// SealedAt is plan/00-SPINE.md S6's per-half `sealedAt`, stored as
	// `audit_record.sast_sealed_at` / `.dast_sealed_at`. It is required once
	// Status == HalfStatusSealed, and is
	// explicitly null otherwise (not omitted — a missing key and an
	// unsealed half must not be the same observation). Producer: SAST/DAST
	// worker. Consumer: re-entrant consumer read gate, deadline math.
	SealedAt *time.Time `json:"anvil/sealedAt"`

	// DastCoverage is required on the DAST run. Producer: attack-surface
	// discovery (area D, D.26). Consumer: coding agent (confidence
	// weighting), report.
	DastCoverage *DastCoverage `json:"anvil/dastCoverage,omitempty"`

	// RouteTableDigest is required on the DAST run. Producer: DAST worker.
	// Consumer: audit trail, correlation replay.
	RouteTableDigest string `json:"anvil/routeTableDigest,omitempty"`

	// AdvisorySnapshot is required on the SAST run. Producer: ingestion
	// subsystem (area A). Consumer: coding agent (staleness), report.
	AdvisorySnapshot *AdvisorySnapshot `json:"anvil/advisorySnapshot,omitempty"`

	// RuntimeTarget is required on the DAST run. Producer: DAST worker.
	// Consumer: correlation, reproduction replay.
	RuntimeTarget *RuntimeTarget `json:"anvil/runtimeTarget,omitempty"`
}

// DastCoverage reports what fraction of the discovered attack surface was
// actually probed. `anvil/dastCoverage`.
//
// It carries a NUMERATOR AND A DENOMINATOR AND A PROVENANCE MIX, never a bare
// ratio (research/14 critique m6, carried into
// plan/40-record-and-storage.md's contract table). A bare "62% covered" is
// unfalsifiable; ProbedCount=31 of InventoryUnionCount=50, of which 40 came
// from a runtime spec and 10 from a crawl, is not.
//
// This struct consolidates plan/00-SPINE.md S6's `dast_coverage`,
// `endpoint_coverage` and `inventory_provenance` into one field. Open
// Question 5 in plan/40-record-and-storage.md asks the attack-surface area to
// confirm no information is lost by that consolidation; nothing here forbids
// splitting it later.
type DastCoverage struct {
	// ProbedCount is confirmed-probed endpoints. NEVER a request count.
	ProbedCount int `json:"probedCount"`

	// InventoryUnionCount is the union of the Tier 0-2 inventory — the
	// denominator D.26 is required to use.
	InventoryUnionCount int `json:"inventoryUnionCount"`

	// EndpointCoverage is plan/00-SPINE.md S6's `endpoint_coverage`:
	// ProbedCount / InventoryUnionCount, in [0,1]. Carried explicitly so a
	// consumer never has to guess the denominator, and validated against the
	// two counts by ValidateDastCoverage.
	EndpointCoverage float64 `json:"endpointCoverage"`

	// ServerLineCoverage is populated on scheduled full scans only, via a
	// language coverage agent inside the sandbox. Null (NOT zero) on
	// incremental scans — zero would read as "we ran and covered nothing."
	ServerLineCoverage *float64 `json:"serverLineCoverage"`

	// InventoryProvenanceMix is plan/00-SPINE.md S6's `inventory_provenance`
	// aggregated to the record level: endpoint count per InventoryProvenance
	// literal. This is what makes the SAST->DAST handoff auditable.
	InventoryProvenanceMix map[InventoryProvenance]int `json:"inventoryProvenanceMix"`

	// ConfirmedCount and CandidateCount split the inventory by whether the
	// endpoint was confirmed to exist or only inferred.
	ConfirmedCount int `json:"confirmedCount"`
	CandidateCount int `json:"candidateCount"`
}

// AdvisorySnapshot identifies the advisory corpus the SAST half read.
// `anvil/advisorySnapshot`.
type AdvisorySnapshot struct {
	FeedIDs        []string  `json:"feedIds"`
	SnapshotDigest string    `json:"snapshotDigest"`
	ScrapedAt      time.Time `json:"scrapedAt"`
}

// RuntimeTarget records the DAST scope actually used.
// `anvil/runtimeTarget`.
type RuntimeTarget struct {
	BaseURL string `json:"baseUrl"`
	// AuthProfileRef points at a config file and revision. The record never
	// carries credentials.
	AuthProfileRef string   `json:"authProfileRef"`
	Scope          []string `json:"scope"`
	Excluded       []string `json:"excluded"`
}

// RunAutomationDetails is SARIF §3.17. CorrelationGuid must be identical in
// both runs and equal to AuditProperties.AuditID.
type RunAutomationDetails struct {
	ID              string   `json:"id"`
	GUID            string   `json:"guid"`
	CorrelationGUID string   `json:"correlationGuid"`
	Description     *Message `json:"description,omitempty"`
}

// ---------------------------------------------------------------------------
// Per-finding result
// ---------------------------------------------------------------------------

// Result is one finding. SARIF-native slots carry everything SARIF can carry;
// Properties carries only what it cannot.
type Result struct {
	RuleID    string   `json:"ruleId"`
	RuleIndex *int     `json:"ruleIndex,omitempty"`
	Kind      Kind     `json:"kind,omitempty"`
	Level     Level    `json:"level,omitempty"`
	Rank      *float64 `json:"rank,omitempty"`
	GUID      string   `json:"guid,omitempty"`

	// CorrelationGUID is assigned per CLUSTER, not per finding (SARIF
	// §3.27.4): every finding asserted to be the same underlying defect
	// shares it. Present only on clustered findings. Producer: the
	// correlation engine (R.12).
	CorrelationGUID string `json:"correlationGuid,omitempty"`

	Message Message `json:"message"`

	// Locations carries the SAST half's file/line/snippet and the DAST
	// half's endpoint. Required for SAST; a pure-DAST result has no file.
	Locations        []Location `json:"locations,omitempty"`
	RelatedLocations []Location `json:"relatedLocations,omitempty"`
	CodeFlows        []CodeFlow `json:"codeFlows,omitempty"`

	Taxa []ReportingDescriptorReference `json:"taxa,omitempty"`

	// WebRequest and WebResponse are the SARIF-native DAST evidence slots
	// (§3.27.14/15). MASKED BY R.8 BEFORE STORAGE — research/18 Risk #10:
	// "an 8-hour TTL is not a security control for a token that is still
	// valid."
	WebRequest  *WebRequest  `json:"webRequest,omitempty"`
	WebResponse *WebResponse `json:"webResponse,omitempty"`

	// PartialFingerprints keys are the Partial* constants above.
	PartialFingerprints map[string]string `json:"partialFingerprints,omitempty"`

	// Provenance is SARIF §3.48 regression history. Producer: the store, on
	// read-back. Consumer: regression history, report.
	Provenance *ResultProvenance `json:"provenance,omitempty"`

	// Fixes is written only after a coding-agent proposal (SARIF §3.27.30).
	// plan/00-SPINE.md S7: "Never auto-merge. Propose only."
	Fixes []Fix `json:"fixes,omitempty"`

	Properties ResultProperties `json:"properties"`
}

// ResultProperties is the typed `anvil/*` bag on `result.properties`.
type ResultProperties struct {
	// FindingID is the record-local cross-reference used by task cards and
	// the DB. Producer: record assembler.
	FindingID string `json:"anvil/findingId"`

	// Half names the producing half. Producer: detector.
	Half Half `json:"anvil/half"`

	// Confidence is DETECTOR CERTAINTY in [0,1], and is deliberately NOT
	// SARIF's `rank`: rank means priority and level means severity, so a
	// consumer that reads rank as certainty cannot tell "high severity" from
	// "high confidence" (research/18, "What Anvil loses by choosing SARIF").
	// research/18 Risk #8 additionally requires that `rank` on INGESTED
	// third-party SARIF be treated as untrusted and re-derived.
	Confidence float64 `json:"anvil/confidence"`

	// Verdict is the triage judgment. Producer: detector model / triage
	// gate, via B.12's mapping. Consumer: the consumption pipeline, which
	// drops VerdictFalsePositive and demotes VerdictInsufficientContext to
	// report-only.
	Verdict Verdict `json:"anvil/verdict"`

	// RemediableByAgent is plan/00-SPINE.md S6's `remediable_by_agent`, and
	// is stored as `finding.remediable_by_agent`. It is false for every host
	// finding, always (plan/00-SPINE.md S7 read-only host agent), and the
	// store enforces that with a CHECK constraint. Producer: record
	// assembler, derived from Detector. Consumer: coding agent.
	RemediableByAgent bool `json:"anvil/remediableByAgent"`

	// Reasoning is the detector's explanation. Anvil-generated.
	Reasoning string `json:"anvil/reasoning"`

	// Detector identifies the model and prompt that produced the finding.
	Detector DetectorRef `json:"anvil/detector"`

	// EvidenceClass drives ranking and the queue re-cut.
	EvidenceClass EvidenceClass `json:"anvil/evidenceClass"`

	// Trust classifies every string in this result that originated outside
	// Anvil. REQUIRED on every result. See TrustAssertion.
	Trust TrustAssertion `json:"anvil/trust"`

	// Advisory is required when an advisory is linked. Producer: ingestion
	// subsystem at record-assembly time. Consumer: coding agent (down-weight
	// stale or degraded context), report.
	Advisory *AdvisoryContext `json:"anvil/advisory,omitempty"`

	// Risk carries research/24's non-negotiable ranking inputs.
	// DEVIATION: no row for it exists in plan/40-record-and-storage.md's
	// Record Field Contract table; research/24 lists it as non-negotiable
	// "because there is no orchestrator to compute them later". See
	// CONTRACT.md "Logged deviations", item 1.
	Risk *Risk `json:"anvil/risk,omitempty"`

	// PatchContext is what the coding agent needs to write the patch without
	// further lookups.
	PatchContext *PatchContext `json:"anvil/patchContext,omitempty"`

	// Correlation is present only on clustered findings. Producer: R.12.
	Correlation *Correlation `json:"anvil/correlation,omitempty"`

	// Repro is required on any reproducer. Producer: DAST worker or the
	// dynamic-analysis harness. Consumer: the verification pipeline —
	// plan/00-SPINE.md S7 lets only a DAST reproduction that now fails earn
	// "verified fixed", and the sanitizer/ASLR state qualifies that claim.
	Repro *Repro `json:"anvil/repro,omitempty"`

	// Locus.ProximityClass drives fix-grouping.
	Locus *Locus `json:"anvil/locus,omitempty"`

	// ChunkRef is the Tier-1 task-card pointer. Producer: R.13.
	ChunkRef string `json:"anvil/chunkRef,omitempty"`

	// GroupID is RESERVED here and ASSIGNED BY THE CODING-AGENT CONSUMPTION
	// PIPELINE, not by this area. Empty on a freshly assembled record.
	GroupID string `json:"anvil/groupId,omitempty"`
}

// TrustAssertion states the trust level of every string in a result that
// originated outside Anvil. `anvil/trust`.
//
// DEVIATION FROM THE PLAN'S CONTRACT TABLE, deliberate: the table types
// `anvil/trust` as a bare enum, but plan/00-SPINE.md S6 requires trust "on
// EVERY string originating outside Anvil" and one result carries several
// strings of different provenance at once — a repo snippet, a
// model-generated explanation, an attacker-controlled response body. A single
// enum per result cannot express that, and the way it fails is to collapse to
// the most permissive value. The literals are unchanged. See CONTRACT.md
// "Logged deviations", item 3.
type TrustAssertion struct {
	// Default applies to any string not named in Fields. A result carrying a
	// WebResponse must set Default to TrustUntrusted: plan/00-SPINE.md S7
	// names the DAST response body the highest-risk field in the system.
	Default Trust `json:"default"`

	// Fields maps an RFC 6901 JSON Pointer, relative to this RESULT object,
	// to the trust level of the string at that pointer. Every pointer
	// returned by Result.ExternalStringPointers must appear here or be
	// covered by an untrusted Default.
	Fields map[string]Trust `json:"fields,omitempty"`
}

// DetectorRef identifies the model and prompt behind a finding.
// `anvil/detector`.
type DetectorRef struct {
	// Kind selects the fingerprint tier (R.2) and populates
	// `finding.detector`.
	Kind DetectorKind `json:"kind"`

	Model    string `json:"model"`
	Revision string `json:"revision"`
	// PromptDigest makes a detector decision replayable without storing the
	// prompt.
	PromptDigest   string `json:"promptDigest,omitempty"`
	AdvisoryItemID string `json:"advisoryItemId,omitempty"`
}

// AdvisoryContext links a finding to advisory data and states how stale that
// data is. `anvil/advisory`.
type AdvisoryContext struct {
	IDs            []string `json:"ids"`
	CveIDs         []string `json:"cveIds"`
	SourceFeed     string   `json:"sourceFeed"`
	SnapshotDigest string   `json:"snapshotDigest"`
	// LicenseSpdx is carried per finding because the feed licence attaches
	// to the text, not to Anvil (plan/00-SPINE.md S8, plan/80-compliance.md).
	LicenseSpdx string `json:"licenseSpdx,omitempty"`

	// AsOf is plan/00-SPINE.md S6's `as_of`: when this advisory data was
	// current.
	AsOf time.Time `json:"asOf"`
	// StalenessSeconds is S6's `staleness_seconds`: record-assembly time
	// minus AsOf. Carried explicitly so a consumer never has to know the
	// assembly clock.
	StalenessSeconds int `json:"stalenessSeconds"`
	// ParseDegraded is S6's `parse_degraded`: the feed parsed with loss.
	// A consumer must down-weight, not silently trust, degraded context.
	ParseDegraded bool `json:"parseDegraded"`

	// Excerpt is <= MaxAdvisoryExcerptTokens, pre-trimmed by ingestion,
	// never a whole advisory (research/24). It is EXTERNAL TEXT and
	// therefore carries its own trust inline.
	Excerpt *TrustedString `json:"excerpt,omitempty"`
}

// TrustedString is a string that originated outside Anvil, carrying its own
// trust level inline. Used for `anvil/*` extension strings; SARIF-native
// strings cannot change shape, so those are classified by pointer in
// TrustAssertion.Fields instead.
type TrustedString struct {
	Text  string `json:"text"`
	Trust Trust  `json:"trust"`
}

// Risk carries the ranking inputs research/24 names non-negotiable.
// `anvil/risk`. Producer: Lane A ingestion. Consumer: ranking (R.11, R.13).
type Risk struct {
	CvssV4Base       *float64   `json:"cvssV4Base,omitempty"`
	EpssScore        *float64   `json:"epssScore,omitempty"`
	EpssPercentile   *float64   `json:"epssPercentile,omitempty"`
	EpssModelDate    *time.Time `json:"epssModelDate,omitempty"`
	KevMember        bool       `json:"kevMember"`
	KevRansomwareUse bool       `json:"kevRansomwareUse"`
}

// PatchContext is everything the coding agent needs to write the patch with
// no further lookups. `anvil/patchContext`.
type PatchContext struct {
	Language        string   `json:"language"`
	LanguageVersion string   `json:"languageVersion,omitempty"`
	Framework       string   `json:"framework,omitempty"`
	DBDriver        string   `json:"dbDriver,omitempty"`
	Imports         []string `json:"imports,omitempty"`
	TestCommand     string   `json:"testCommand,omitempty"`
	BuildCommand    string   `json:"buildCommand,omitempty"`
	EditableFiles   []string `json:"editableFiles"`
}

// Correlation is the LINK assertion. `anvil/correlation`.
//
// LINK, NEVER MERGE: both findings always survive independently in the
// record. The SAST finding owns the file and line; the DAST finding owns the
// proof; merging destroys exactly what the other contributes
// (research/18, "Correlation policy — link, never merge"). Merged is
// therefore unconditionally false in every code path.
type Correlation struct {
	ClusterID string   `json:"clusterId"`
	Role      Half     `json:"role"`
	Peers     []string `json:"peers"`
	Method    string   `json:"method,omitempty"`

	// Signals must contain at least MinCorrelationSignals independent
	// entries, and CorrelationSignalCweMatch alone is never sufficient.
	Signals []SignalWeight `json:"signals"`

	Confidence float64 `json:"confidence"`

	// Verified is true only when a signal in Signals satisfies
	// SufficientForVerified. Confidence alone never qualifies.
	Verified           bool   `json:"verified"`
	VerificationMethod string `json:"verificationMethod,omitempty"`

	// Merged is always false. See the type comment.
	Merged bool `json:"merged"`

	// Caveat records why this cluster should or should not be trusted.
	Caveat string `json:"caveat,omitempty"`
}

// MinCorrelationSignals is research/18's ">=2 independent signals before
// emitting a link at all".
const MinCorrelationSignals = 2

// SignalWeight is one weighted correlation signal.
type SignalWeight struct {
	Name   CorrelationSignal `json:"name"`
	Weight float64           `json:"weight"`
	Detail string            `json:"detail,omitempty"`
}

// Repro is a replayable reproduction. `anvil/repro`.
type Repro struct {
	Curl             string            `json:"curl,omitempty"`
	InjectionPoint   ReproInjection    `json:"injectionPoint"`
	Payload          string            `json:"payload,omitempty"`
	PayloadEncoding  string            `json:"payloadEncoding,omitempty"`
	Steps            []string          `json:"steps,omitempty"`
	Baseline         *ReproBaseline    `json:"baseline,omitempty"`
	ObservedSignal   ReproSignal       `json:"observedSignal"`
	ExpectedAfterFix *ReproExpectation `json:"expectedAfterFix,omitempty"`
	SideEffects      string            `json:"sideEffects,omitempty"`
	TargetStateRef   string            `json:"targetStateRef,omitempty"`

	// Env qualifies what "reproduced" means. Required on any reproducer.
	Env ReproEnv `json:"env"`
}

// ReproEnv records the dynamic-analysis environment.
//
// Sanitizers and AslrEnabled are plan/00-SPINE.md S6's required
// "sanitizer + ASLR state on any reproducer", and they are not bookkeeping:
// a crash that reproduces only under ASan is a different claim from one that
// reproduces on a stock build, and a use-after-free that reproduces only with
// ASLR disabled may not be exploitable as shipped. plan/00-SPINE.md S7 lets
// only a reproduction that now FAILS earn "verified fixed" — a verification
// re-run under a different sanitizer or ASLR setting than the original is not
// the same experiment, and without these fields nothing can detect that.
type ReproEnv struct {
	// Sanitizers are the sanitizer names active during reproduction, e.g.
	// "asan", "ubsan", "msan", "tsan". Empty means a stock build.
	Sanitizers []string `json:"sanitizers"`
	// AslrEnabled is the ASLR state during reproduction.
	AslrEnabled bool `json:"aslrEnabled"`
	// Arch and OS pin the rest of the environment.
	Arch string `json:"arch,omitempty"`
	OS   string `json:"os,omitempty"`
}

// ReproInjection says where the payload went in.
type ReproInjection struct {
	Kind InjectionPoint `json:"kind"`
	Name string         `json:"name"`
}

// ReproBaseline is the pre-payload observation the reproduction is measured
// against.
type ReproBaseline struct {
	StatusCode int `json:"statusCode"`
	LatencyMs  int `json:"latencyMs,omitempty"`
}

// ReproSignal says how the defect was observed.
type ReproSignal struct {
	Kind EvidenceSignal `json:"kind"`
	// Match is a regex-extracted evidence SPAN, never the raw body
	// (plan/00-SPINE.md S7: "Hash-and-reference by default; inline only a
	// regex-extracted evidence span"). It is attacker-controlled text and
	// carries its own trust inline.
	Match *TrustedString `json:"match,omitempty"`
	// BodySha256 references the full body as a Tier-2 blob.
	BodySha256 string `json:"bodySha256,omitempty"`
	BodyOffset int    `json:"bodyOffset,omitempty"`
}

// ReproExpectation is the accept oracle for a fix.
type ReproExpectation struct {
	StatusCode     int      `json:"statusCode,omitempty"`
	MustNotContain []string `json:"mustNotContain,omitempty"`
}

// Locus is the fix-grouping input. `anvil/locus`.
//
// Only ProximityClass lives here: path, start line, end line and enclosing
// symbol are SARIF-native (physicalLocation.region and logicalLocations) and
// duplicating them into the property bag would create two sources of truth
// for the same fact.
type Locus struct {
	// ProximityClass drives fix-grouping per research/24's Hunk4J citation.
	// The vocabulary is owned by the coding-agent consumption area and is
	// NOT frozen here; it must be registered in this file before a second
	// area consumes it, or it becomes the eleventh defect of the same shape.
	ProximityClass string `json:"proximityClass"`
}

// ---------------------------------------------------------------------------
// SARIF-native supporting types (the subset Anvil produces)
// ---------------------------------------------------------------------------

// Message is SARIF §3.11.
type Message struct {
	Text string `json:"text"`
}

// Tool is SARIF §3.18.
type Tool struct {
	Driver ToolComponent `json:"driver"`
}

// ToolComponent is SARIF §3.19. Also used for taxonomies (e.g. CWE).
type ToolComponent struct {
	Name             string                `json:"name"`
	GUID             string                `json:"guid,omitempty"`
	Version          string                `json:"version,omitempty"`
	Organization     string                `json:"organization,omitempty"`
	InformationURI   string                `json:"informationUri,omitempty"`
	ShortDescription *Message              `json:"shortDescription,omitempty"`
	IsComprehensive  *bool                 `json:"isComprehensive,omitempty"`
	Rules            []ReportingDescriptor `json:"rules,omitempty"`
	Taxa             []ReportingDescriptor `json:"taxa,omitempty"`
}

// ReportingDescriptor is SARIF §3.49 — a rule or a taxon.
type ReportingDescriptor struct {
	ID                   string                            `json:"id"`
	Name                 string                            `json:"name,omitempty"`
	ShortDescription     *Message                          `json:"shortDescription,omitempty"`
	FullDescription      *Message                          `json:"fullDescription,omitempty"`
	Help                 *Message                          `json:"help,omitempty"`
	HelpURI              string                            `json:"helpUri,omitempty"`
	DefaultConfiguration *ReportingConfiguration           `json:"defaultConfiguration,omitempty"`
	Relationships        []ReportingDescriptorRelationship `json:"relationships,omitempty"`
}

// ReportingConfiguration is SARIF §3.50.
type ReportingConfiguration struct {
	Level Level `json:"level,omitempty"`
}

// ReportingDescriptorRelationship is SARIF §3.53 — how a rule relates to a
// taxon. This is the spec-preferred CWE mechanism (§3.8.2), not tags.
type ReportingDescriptorRelationship struct {
	Target ReportingDescriptorReference `json:"target"`
	Kinds  []string                     `json:"kinds,omitempty"`
}

// ReportingDescriptorReference is SARIF §3.52.
type ReportingDescriptorReference struct {
	ID            string            `json:"id,omitempty"`
	Index         *int              `json:"index,omitempty"`
	GUID          string            `json:"guid,omitempty"`
	ToolComponent *ToolComponentRef `json:"toolComponent,omitempty"`
}

// ToolComponentRef is SARIF §3.54.
type ToolComponentRef struct {
	Name  string `json:"name,omitempty"`
	Index *int   `json:"index,omitempty"`
	GUID  string `json:"guid,omitempty"`
}

// Location is SARIF §3.28.
type Location struct {
	ID               *int              `json:"id,omitempty"`
	PhysicalLocation *PhysicalLocation `json:"physicalLocation,omitempty"`
	LogicalLocations []LogicalLocation `json:"logicalLocations,omitempty"`
	Message          *Message          `json:"message,omitempty"`
	Properties       map[string]any    `json:"properties,omitempty"`
}

// PhysicalLocation is SARIF §3.29.
type PhysicalLocation struct {
	ArtifactLocation ArtifactLocation `json:"artifactLocation"`
	// Region is the exact defect (§3.29.4).
	Region *Region `json:"region,omitempty"`
	// ContextRegion is the surrounding context the agent needs to patch
	// (§3.29.5).
	ContextRegion *Region `json:"contextRegion,omitempty"`
}

// ArtifactLocation is SARIF §3.4.
type ArtifactLocation struct {
	URI       string `json:"uri"`
	URIBaseID string `json:"uriBaseId,omitempty"`
	Index     *int   `json:"index,omitempty"`
}

// Region is SARIF §3.30.
//
// Line and column numbers live HERE and are never hashed into a fingerprint:
// code motion is the documented killer of fingerprint stability
// (research/18 Risk #5).
type Region struct {
	StartLine   int      `json:"startLine,omitempty"`
	StartColumn int      `json:"startColumn,omitempty"`
	EndLine     int      `json:"endLine,omitempty"`
	EndColumn   int      `json:"endColumn,omitempty"`
	Snippet     *Snippet `json:"snippet,omitempty"`
}

// Snippet is SARIF §3.30.13 `region.snippet`.
//
// Its Text is VERBATIM TARGET-REPO SOURCE. It is TrustUntrusted even though
// Anvil is what put it in the struct. See Trust's doc comment.
type Snippet struct {
	Text string `json:"text"`
}

// LogicalLocation is SARIF §3.33.
type LogicalLocation struct {
	Name               string `json:"name,omitempty"`
	FullyQualifiedName string `json:"fullyQualifiedName"`
	Kind               string `json:"kind,omitempty"`
}

// CodeFlow is SARIF §3.36 — the taint path from source to sink.
type CodeFlow struct {
	Message     *Message     `json:"message,omitempty"`
	ThreadFlows []ThreadFlow `json:"threadFlows"`
}

// ThreadFlow is SARIF §3.37.
type ThreadFlow struct {
	Locations []ThreadFlowLocation `json:"locations"`
}

// ThreadFlowLocation is SARIF §3.38.
type ThreadFlowLocation struct {
	Importance string   `json:"importance,omitempty"`
	Location   Location `json:"location"`
}

// WebRequest is SARIF §3.46.
type WebRequest struct {
	Index      *int              `json:"index,omitempty"`
	Protocol   string            `json:"protocol,omitempty"`
	Version    string            `json:"version,omitempty"`
	Target     string            `json:"target,omitempty"`
	Method     string            `json:"method,omitempty"`
	Headers    map[string]string `json:"headers,omitempty"`
	Parameters map[string]string `json:"parameters,omitempty"`
	Body       *ArtifactContent  `json:"body,omitempty"`
}

// WebResponse is SARIF §3.47.
//
// Its Body is the highest-risk field in the entire record: up to 32 KB of
// attacker-controlled bytes headed for a repo-credentialed agent
// (plan/00-SPINE.md S7). It is masked by R.8 before storage, capped at
// MaxInlineResponseBodyBytes, and always TrustUntrusted.
type WebResponse struct {
	Index              *int              `json:"index,omitempty"`
	Protocol           string            `json:"protocol,omitempty"`
	Version            string            `json:"version,omitempty"`
	StatusCode         int               `json:"statusCode,omitempty"`
	ReasonPhrase       string            `json:"reasonPhrase,omitempty"`
	Headers            map[string]string `json:"headers,omitempty"`
	Body               *ArtifactContent  `json:"body,omitempty"`
	NoResponseReceived bool              `json:"noResponseReceived,omitempty"`
}

// ArtifactContent is SARIF §3.3.
type ArtifactContent struct {
	Text string `json:"text,omitempty"`
}

// ResultProvenance is SARIF §3.48 — regression history, written by the store
// on read-back.
type ResultProvenance struct {
	FirstDetectionTimeUtc *time.Time `json:"firstDetectionTimeUtc,omitempty"`
	LastDetectionTimeUtc  *time.Time `json:"lastDetectionTimeUtc,omitempty"`
	FirstDetectionRunGUID string     `json:"firstDetectionRunGuid,omitempty"`
	LastDetectionRunGUID  string     `json:"lastDetectionRunGuid,omitempty"`
	InvocationIndex       *int       `json:"invocationIndex,omitempty"`
}

// Fix is SARIF §3.27.30 — a PROPOSED patch. Never applied automatically.
type Fix struct {
	Description     *Message         `json:"description,omitempty"`
	ArtifactChanges []ArtifactChange `json:"artifactChanges"`
}

// ArtifactChange is SARIF §3.56.
type ArtifactChange struct {
	ArtifactLocation ArtifactLocation `json:"artifactLocation"`
	Replacements     []Replacement    `json:"replacements"`
}

// Replacement is SARIF §3.57.
type Replacement struct {
	DeletedRegion   Region           `json:"deletedRegion"`
	InsertedContent *ArtifactContent `json:"insertedContent,omitempty"`
}

// ExternalPropertyFileReferences is SARIF §3.15 — the native mechanism for
// externalising the arrays that blow up the Tier-0 budget.
type ExternalPropertyFileReferences struct {
	Results      []ExternalPropertyFileReference `json:"results,omitempty"`
	Artifacts    []ExternalPropertyFileReference `json:"artifacts,omitempty"`
	WebRequests  []ExternalPropertyFileReference `json:"webRequests,omitempty"`
	WebResponses []ExternalPropertyFileReference `json:"webResponses,omitempty"`
}

// ExternalPropertyFileReference is SARIF §3.16.
type ExternalPropertyFileReference struct {
	Location  *ArtifactLocation `json:"location,omitempty"`
	GUID      string            `json:"guid,omitempty"`
	ItemCount *int              `json:"itemCount,omitempty"`
}

// ---------------------------------------------------------------------------
// Trust classification helpers
// ---------------------------------------------------------------------------

// ExternalStringPointers returns the RFC 6901 JSON Pointers, relative to this
// result object, of every string it carries that originated OUTSIDE Anvil.
//
// This is the list plan/00-SPINE.md S6's "on every string originating outside
// Anvil" resolves to in practice. It deliberately includes region snippets:
// a repo source snippet is external even though Anvil assembled the struct,
// and treating it as Anvil-generated is what disables the containment check
// on the string most likely to carry an injected instruction.
func (r *Result) ExternalStringPointers() []string {
	var ptrs []string
	add := func(p string) { ptrs = append(ptrs, p) }

	locPtrs := func(prefix string, locs []Location) {
		for i, loc := range locs {
			if loc.PhysicalLocation == nil {
				continue
			}
			base := prefix + "/" + strconv.Itoa(i) + "/physicalLocation"
			if loc.PhysicalLocation.Region != nil && loc.PhysicalLocation.Region.Snippet != nil {
				add(base + "/region/snippet/text")
			}
			if loc.PhysicalLocation.ContextRegion != nil && loc.PhysicalLocation.ContextRegion.Snippet != nil {
				add(base + "/contextRegion/snippet/text")
			}
		}
	}
	locPtrs("/locations", r.Locations)
	locPtrs("/relatedLocations", r.RelatedLocations)

	for i, cf := range r.CodeFlows {
		for j, tf := range cf.ThreadFlows {
			for k, tfl := range tf.Locations {
				pl := tfl.Location.PhysicalLocation
				if pl == nil || pl.Region == nil || pl.Region.Snippet == nil {
					continue
				}
				add(fmt.Sprintf("/codeFlows/%d/threadFlows/%d/locations/%d/location/physicalLocation/region/snippet/text", i, j, k))
			}
		}
	}

	if r.WebResponse != nil {
		if r.WebResponse.Body != nil {
			add("/webResponse/body/text")
		}
		if len(r.WebResponse.Headers) > 0 {
			add("/webResponse/headers")
		}
	}
	return ptrs
}

// ValidateResultTrust reports whether r's TrustAssertion covers every string
// that originated outside Anvil, and whether each such string is classified
// legally.
//
// A pointer may be classified TrustUntrusted or TrustVerified. It may NOT be
// classified TrustAnvilGenerated, and if it is not named in Fields then
// Default must itself be legal for external strings. This is the check that
// would have caught area B stamping anvil_generated on a verbatim
// target-repo snippet.
func ValidateResultTrust(r *Result) error {
	if err := ValidateTrust(string(r.Properties.Trust.Default)); err != nil {
		return err
	}
	for ptr, t := range r.Properties.Trust.Fields {
		if err := ValidateTrust(string(t)); err != nil {
			return fmt.Errorf("anvil/trust.fields[%q]: %w", ptr, err)
		}
	}
	for _, ptr := range r.ExternalStringPointers() {
		t, named := r.Properties.Trust.Fields[ptr]
		if !named {
			t = r.Properties.Trust.Default
		}
		if !t.LegalForExternalString() {
			return fmt.Errorf(
				"record: %s is a string originating outside Anvil but is classified %q; "+
					"external strings must be %q or %q (a repo snippet is untrusted even though Anvil assembled it)",
				ptr, t, TrustUntrusted, TrustVerified)
		}
	}
	if r.WebResponse != nil && r.Properties.Trust.Default != TrustUntrusted {
		return fmt.Errorf(
			"record: a result carrying a webResponse must set anvil/trust.default to %q, got %q "+
				"(00-SPINE.md S7: the DAST response body is the highest-risk field)",
			TrustUntrusted, r.Properties.Trust.Default)
	}
	return nil
}

// ---------------------------------------------------------------------------
// Whole-record validation
// ---------------------------------------------------------------------------

// Validate checks a SARIFLog against the parts of this contract that are
// checkable in Go: the pinned SARIF version, every frozen enum, the required
// envelope fields, the per-half seal invariants, and the trust classification
// of every result.
//
// It is deliberately NOT a JSON Schema replacement — schemas/
// anvil-record-v1.schema.json is the wire gate. This is the in-process gate,
// so a producer fails at assembly time rather than at the store boundary.
func (l *SARIFLog) Validate() error {
	if l.Version != SARIFVersion {
		return fmt.Errorf("record: version must be %q exactly, got %q "+
			"(do not track the unratified SARIF 2.2 draft)", SARIFVersion, l.Version)
	}
	if l.Schema != SARIFSchemaURI {
		return fmt.Errorf("record: $schema must be %q, got %q", SARIFSchemaURI, l.Schema)
	}

	p := &l.Properties
	if p.SchemaVersion == "" {
		return fmt.Errorf("record: %s is required", PropAuditSchemaVersion)
	}
	if p.AuditID == "" {
		return fmt.Errorf("record: %s is required", PropAuditID)
	}
	if err := ValidateState(string(p.State)); err != nil {
		return err
	}
	if p.Version < 1 {
		return fmt.Errorf("record: %s must be a positive monotonic integer, got %d",
			PropAuditVersion, p.Version)
	}
	if p.CreatedAt.IsZero() {
		return fmt.Errorf("record: %s is required", PropAuditCreatedAt)
	}
	if err := ValidateTargetProvenance(string(p.Target.Provenance)); err != nil {
		return err
	}
	if err := ValidateTargetProvisioning(string(p.Target.Provisioning)); err != nil {
		return err
	}
	if err := ValidateDastStatus(string(p.DastStatus)); err != nil {
		return err
	}
	if p.Deadline.DeadlineAt.IsZero() {
		return fmt.Errorf("record: %s.deadlineAt is required and is computed once at scan START", PropAuditDeadline)
	}
	if p.Deadline.ClaimTimeoutSeconds <= 0 {
		return fmt.Errorf("record: %s.claimTimeoutSeconds must be positive, got %d",
			PropAuditDeadline, p.Deadline.ClaimTimeoutSeconds)
	}
	// The deadline is anchored to scan start, never to the last write.
	want := p.CreatedAt.Add(time.Duration(p.Deadline.ClaimTimeoutSeconds) * time.Second)
	if !p.Deadline.DeadlineAt.Equal(want) {
		return fmt.Errorf("record: %s.deadlineAt is %s but createdAt+claimTimeoutSeconds is %s; "+
			"the deadline is anchored to scan START and never recomputed",
			PropAuditDeadline, p.Deadline.DeadlineAt.UTC().Format(time.RFC3339), want.UTC().Format(time.RFC3339))
	}
	if p.Deadline.DastDeadlineSeconds != nil && *p.Deadline.DastDeadlineSeconds <= 0 {
		return fmt.Errorf("record: %s.dastDeadlineSeconds must be null or positive", PropAuditDeadline)
	}

	seenHalf := map[Half]bool{}
	for i := range l.Runs {
		run := &l.Runs[i]
		if err := run.validate(p.AuditID); err != nil {
			return fmt.Errorf("runs[%d]: %w", i, err)
		}
		if seenHalf[run.Properties.Half] {
			return fmt.Errorf("runs[%d]: duplicate half %q; an audit has at most one run per half",
				i, run.Properties.Half)
		}
		seenHalf[run.Properties.Half] = true
	}
	return l.validateStateAgainstHalves(seenHalf)
}

// validateStateAgainstHalves enforces that anvil/state agrees with the two
// halves' seal status. This is where a DAST-first seal has to be expressible:
// if it were not, the only reachable states would be collecting and
// sast_sealed, and plan/00-SPINE.md S1's "two INDEPENDENTLY-sealed halves"
// would be false in the implementation while true in the document.
func (l *SARIFLog) validateStateAgainstHalves(seen map[Half]bool) error {
	sastSealed, dastSealed := false, false
	for i := range l.Runs {
		rp := &l.Runs[i].Properties
		if rp.Status != HalfStatusSealed {
			continue
		}
		switch rp.Half {
		case HalfSast:
			sastSealed = true
		case HalfDast:
			dastSealed = true
		}
	}
	// A DAST-disabled audit reaches both_sealed with DastStatusNotRun (R.6),
	// so an absent DAST run counts as sealed for state purposes only when
	// the audit-level DastStatus says the half was never going to run.
	if !seen[HalfDast] {
		switch l.Properties.DastStatus {
		case DastStatusNotRun, DastStatusSkippedNoManifest:
			dastSealed = true
		}
	}

	var want State
	switch {
	case sastSealed && dastSealed:
		want = StateBothSealed
	case sastSealed:
		want = StateSastSealed
	case dastSealed:
		want = StateDastSealed
	default:
		want = StateCollecting
	}

	got := l.Properties.State
	// consumed and expired are terminal states reached after both_sealed or
	// after the claim clock ran out; they are not derivable from the halves.
	if got == StateConsumed || got == StateExpired {
		return nil
	}
	if got != want {
		return fmt.Errorf("record: %s is %q but the halves imply %q "+
			"(sastSealed=%t dastSealed=%t)", PropAuditState, got, want, sastSealed, dastSealed)
	}
	return nil
}

func (r *Run) validate(auditID string) error {
	if err := ValidateHalf(string(r.Properties.Half)); err != nil {
		return err
	}
	if err := ValidateHalfStatus(string(r.Properties.Status)); err != nil {
		return err
	}
	if r.Properties.Status == HalfStatusSealed && r.Properties.SealedAt == nil {
		return fmt.Errorf("%s is %q so %s is required", PropRunStatus, HalfStatusSealed, PropRunSealedAt)
	}
	if r.Properties.Status != HalfStatusSealed && r.Properties.SealedAt != nil {
		return fmt.Errorf("%s is %q so %s must be null", PropRunStatus, r.Properties.Status, PropRunSealedAt)
	}
	if r.AutomationDetails.CorrelationGUID != auditID {
		return fmt.Errorf("automationDetails.correlationGuid is %q but the audit id is %q; "+
			"both runs must carry the audit id, which is the SARIF-native statement that they are one audit",
			r.AutomationDetails.CorrelationGUID, auditID)
	}
	if r.Properties.Half == HalfDast {
		if r.Properties.DastCoverage == nil {
			return fmt.Errorf("%s is required on the DAST run", PropRunDastCoverage)
		}
		if err := ValidateDastCoverage(r.Properties.DastCoverage); err != nil {
			return err
		}
	}
	for i := range r.Results {
		if err := r.Results[i].validate(r.Properties.Half); err != nil {
			return fmt.Errorf("results[%d]: %w", i, err)
		}
	}
	return nil
}

// ValidateDastCoverage checks that coverage is reported as a numerator and a
// denominator whose ratio matches the stated EndpointCoverage — never as a
// bare, unfalsifiable percentage — and that ServerLineCoverage is null rather
// than zero when it was not measured.
func ValidateDastCoverage(c *DastCoverage) error {
	if c.ProbedCount < 0 || c.InventoryUnionCount < 0 {
		return fmt.Errorf("%s: counts must be non-negative", PropRunDastCoverage)
	}
	if c.ProbedCount > c.InventoryUnionCount {
		return fmt.Errorf("%s: probedCount %d exceeds inventoryUnionCount %d",
			PropRunDastCoverage, c.ProbedCount, c.InventoryUnionCount)
	}
	var want float64
	if c.InventoryUnionCount > 0 {
		want = float64(c.ProbedCount) / float64(c.InventoryUnionCount)
	}
	if diff := c.EndpointCoverage - want; diff > 1e-9 || diff < -1e-9 {
		return fmt.Errorf("%s: endpointCoverage %v does not equal probedCount/inventoryUnionCount %v "+
			"(endpoint_coverage is confirmed-probed endpoints over the Tier 0-2 inventory union, never a request count)",
			PropRunDastCoverage, c.EndpointCoverage, want)
	}
	if c.ServerLineCoverage != nil && (*c.ServerLineCoverage < 0 || *c.ServerLineCoverage > 1) {
		return fmt.Errorf("%s: serverLineCoverage must be null or within [0,1]", PropRunDastCoverage)
	}
	for prov := range c.InventoryProvenanceMix {
		if err := ValidateInventoryProvenance(string(prov)); err != nil {
			return err
		}
	}
	return nil
}

func (r *Result) validate(runHalf Half) error {
	p := &r.Properties
	if p.FindingID == "" {
		return fmt.Errorf("%s is required", PropResultFindingID)
	}
	if err := ValidateHalf(string(p.Half)); err != nil {
		return err
	}
	if p.Half != runHalf {
		return fmt.Errorf("%s is %q inside the %q run", PropResultHalf, p.Half, runHalf)
	}
	if p.Confidence < 0 || p.Confidence > 1 {
		return fmt.Errorf("%s must be within [0,1], got %v (it is detector certainty, not SARIF rank)",
			PropResultConfidence, p.Confidence)
	}
	if err := ValidateVerdict(string(p.Verdict)); err != nil {
		return err
	}
	if err := ValidateEvidenceClass(string(p.EvidenceClass)); err != nil {
		return err
	}
	if err := ValidateDetectorKind(string(p.Detector.Kind)); err != nil {
		return err
	}
	// plan/00-SPINE.md S7: the host agent is read-only, "not behind a flag."
	// The store enforces the same rule with a CHECK constraint; enforcing it
	// here too means a producer fails before it reaches the store.
	if p.Detector.Kind == DetectorKindHost && p.RemediableByAgent {
		return fmt.Errorf("%s must be false for a host finding (00-SPINE.md S7: the host agent is read-only)",
			PropResultRemediableByAgent)
	}
	if p.EvidenceClass == EvidenceClassHost && p.RemediableByAgent {
		return fmt.Errorf("%s must be false when %s is %q",
			PropResultRemediableByAgent, PropResultEvidenceClass, EvidenceClassHost)
	}
	if r.PartialFingerprints[PartialFingerprintAnvilFindingID] == "" {
		return fmt.Errorf("partialFingerprints[%q] is required", PartialFingerprintAnvilFindingID)
	}
	if fp := r.PartialFingerprints[PartialFingerprintAnvilFindingID]; len(fp) != FingerprintDigestHexLen {
		return fmt.Errorf("partialFingerprints[%q] must be %d lowercase hex characters (never truncated), got %d",
			PartialFingerprintAnvilFindingID, FingerprintDigestHexLen, len(fp))
	}
	if r.hasPhysicalCodeLocation() && r.PartialFingerprints[PartialFingerprintPrimaryLocationLineHash] == "" {
		return fmt.Errorf("partialFingerprints[%q] is required when a physical code location exists (the GitHub projection reads only this key)",
			PartialFingerprintPrimaryLocationLineHash)
	}
	if p.Advisory != nil {
		if p.Advisory.AsOf.IsZero() {
			return fmt.Errorf("%s.asOf is required when an advisory is linked", PropResultAdvisory)
		}
		if p.Advisory.StalenessSeconds < 0 {
			return fmt.Errorf("%s.stalenessSeconds must be non-negative", PropResultAdvisory)
		}
		if p.Advisory.Excerpt != nil && !p.Advisory.Excerpt.Trust.LegalForExternalString() {
			return fmt.Errorf("%s.excerpt is external text and cannot be %q",
				PropResultAdvisory, TrustAnvilGenerated)
		}
	}
	if p.Repro != nil {
		if err := ValidateInjectionPoint(string(p.Repro.InjectionPoint.Kind)); err != nil {
			return err
		}
		if err := ValidateEvidenceSignal(string(p.Repro.ObservedSignal.Kind)); err != nil {
			return err
		}
		if p.Repro.Env.Sanitizers == nil {
			return fmt.Errorf("%s.env.sanitizers is required on any reproducer (use an empty array for a stock build, not null)",
				PropResultRepro)
		}
	}
	if p.Correlation != nil {
		if err := validateCorrelation(p.Correlation); err != nil {
			return err
		}
		if r.CorrelationGUID == "" {
			return fmt.Errorf("a clustered result must carry the SARIF-native result.correlationGuid")
		}
	}
	return ValidateResultTrust(r)
}

func (r *Result) hasPhysicalCodeLocation() bool {
	for _, loc := range r.Locations {
		if loc.PhysicalLocation != nil && loc.PhysicalLocation.Region != nil &&
			loc.PhysicalLocation.Region.StartLine > 0 {
			return true
		}
	}
	return false
}

func validateCorrelation(c *Correlation) error {
	if c.Merged {
		return fmt.Errorf("%s.merged must be false: link, never merge — the SAST finding owns the file and line, the DAST finding owns the proof, and merging destroys what the other contributes",
			PropResultCorrelation)
	}
	if len(c.Signals) < MinCorrelationSignals {
		return fmt.Errorf("%s.signals needs at least %d independent signals, got %d",
			PropResultCorrelation, MinCorrelationSignals, len(c.Signals))
	}
	onlyCwe := true
	verifiable := false
	for _, s := range c.Signals {
		if err := ValidateCorrelationSignal(string(s.Name)); err != nil {
			return err
		}
		if s.Name != CorrelationSignalCweMatch {
			onlyCwe = false
		}
		if s.Name.SufficientForVerified() {
			verifiable = true
		}
	}
	if onlyCwe {
		return fmt.Errorf("%s: a CWE-only match is banned as a sole signal", PropResultCorrelation)
	}
	if c.Verified && !verifiable {
		return fmt.Errorf("%s.verified is true but no %q or %q signal is present; confidence alone never qualifies (00-SPINE.md S7)",
			PropResultCorrelation, CorrelationSignalResponseStackTrace, CorrelationSignalRerunFlip)
	}
	if c.Confidence < 0 || c.Confidence > 1 {
		return fmt.Errorf("%s.confidence must be within [0,1]", PropResultCorrelation)
	}
	return nil
}

// ---------------------------------------------------------------------------
// Cross-area ownership, recorded in code so it survives the plan documents
// ---------------------------------------------------------------------------

// AreaMappingOwners names the boundary steps that are permitted to translate
// a foreign vocabulary onto this file's literals, per
// plan/IMPLEMENTATION-PLAN.md §6. Anything not listed here must emit these
// literals directly. "A mapping with an owner and a test is not the same
// thing as two vocabularies drifting."
var AreaMappingOwners = map[string]string{
	"anvil/verdict": "B.12 — maps Lane B's in-process Verdict.Result (EXHIBITS|...) onto Verdict, " +
		"including case normalisation, at the point it places findings on the record (ruling G8).",
	"anvil/state":  "O.2 — emits State directly; its former open|sast_sealed|sealed|expired machine is struck (ruling G2).",
	"anvil/status": "O.2 — keys per-half transitions on HalfStatusSealed, not on a `complete` token (ruling G5).",
	"anvil/dastStatus": "D.26 — emits DastStatus directly; its former five-value set shared zero literals " +
		"with the record's column and could not be stored (rulings G3+G6).",
	"anvil/target.provisioning": "D.26 — writes the provisioning path here, NOT into target.provenance (rulings G4+G7).",
	"handoff.state":             "R.4 owns the DDL; X.8/X.9 read and write it. Area X's anvil_ledger is deleted (rulings G9+G10).",
}
