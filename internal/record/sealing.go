// Per-half sealing: the state machine behind plan/00-SPINE.md S1's "one audit
// identity, two independently-sealed halves, a re-entrant consumer" (step
// R.6).
//
// # What this file owns
//
// Three things that plan/40-record-and-storage.md keeps deliberately apart and
// that every previous draft of this design conflated:
//
//  1. The PER-HALF SEAL — `run.properties["anvil/status"]` (a HalfStatus) and
//     `run.properties["anvil/sealedAt"]`, stored as `audit_record.sast_status`
//     / `.sast_sealed_at` / `.dast_status` / `.dast_sealed_at`.
//  2. The AUDIT-LEVEL LIFECYCLE — `sarifLog.properties["anvil/state"]` (a
//     State), stored as `audit_record.state`, DERIVED from the two half
//     seals and never written independently of them.
//  3. The CLAIM CLOCK — `anvil/deadline.deadlineAt`, stored as
//     `audit_record.deadline_at`. It is `scan_run.started_at +
//     claim_timeout_seconds`, computed ONCE in BeginAudit and never
//     recomputed by anything in this file.
//
// R.6's forbidden actions name the conflation this file must not commit:
// "Do not conflate `anvil/sealedAt` (per-half completion) with
// `anvil/deadline.deadlineAt` (the claim-timeout clock) — they are
// independent clocks with independent semantics." Sealing a half a week late
// does not move DeadlineAt by one nanosecond; TestDeadlineUnchangedByLateSeal
// asserts exactly that.
//
// # `sealed` is the hard read gate
//
// plan/IMPLEMENTATION-PLAN.md §6 ruling G5: "`sealed` is load-bearing: R.6
// makes it the hard read gate ('do not allow a consumer to read a half's
// results before that half's `status` equals `sealed`'), so O.2 keying
// transitions on `complete` means the gate never opens." Area O's `complete`
// is struck; HalfStatusSealed — and no other token, not HalfStatusFailed, not
// HalfStatusTimedOut, not HalfStatusSkipped — opens ReadHalf.
//
// # Terminal is not the same as readable
//
// The distinction that makes a DAST-disabled audit work. FOUR half statuses
// are TERMINAL (sealed, failed, timed_out, skipped): the half will produce
// nothing further, so the audit-level State may advance. Exactly ONE of them
// is READABLE (sealed): the consumer may look at that half's results.
//
// So a Tier S install with no `anvil-dast` artifact (plan/00-SPINE.md
// S9-AMENDED) reaches StateBothSealed — its DAST half is terminally
// HalfStatusSkipped with DastStatusNotRun — while `dastReady` stays false
// forever, because there are no DAST results to read. Collapsing the two
// notions either wedges every SAST-only audit in StateSastSealed (the
// consumer never runs) or opens the gate onto a half that never ran (the
// consumer reads emptiness as "scanned clean", which is research/23 Risk #1).
//
// # This file holds no database handle
//
// internal/store's tests import internal/record to prove the SQL CHECK
// vocabularies and the Go enums have not drifted; importing internal/store
// back would be an import cycle. So this is an in-memory model of the
// `audit_record` sealing columns, and the store writer projects an AuditSeal
// onto those columns. Every literal it produces comes from contract.go, which
// is the same source ddl_test.go checks the SQL against.
//
// (Free-floating file comment: contract.go carries the package doc.)

package record

import (
	"errors"
	"fmt"
	"sync"
	"time"
)

// ---------------------------------------------------------------------------
// Errors — every refusal is typed, per R.6's stop condition
// ---------------------------------------------------------------------------

// Sentinel causes. Every error this file returns wraps exactly one of these,
// so callers can branch with errors.Is while still recovering the full
// context (which audit, which half, which status) with errors.As.
var (
	// ErrUnknownAudit: no BeginAudit has been called for this audit id.
	ErrUnknownAudit = errors.New("record: unknown audit")

	// ErrDuplicateAudit: BeginAudit was called twice for one audit id.
	// Re-beginning would recompute DeadlineAt, which R.6 forbids.
	ErrDuplicateAudit = errors.New("record: audit already begun")

	// ErrInvalidAuditConfig: the AuditConfig cannot produce a legal
	// `audit_record` row (empty id, zero start, non-positive timeout).
	ErrInvalidAuditConfig = errors.New("record: invalid audit configuration")

	// ErrNotSealable: the status handed to SealHalf is not terminal.
	// HalfStatusRunning is the value this catches: "still running" is not a
	// seal.
	ErrNotSealable = errors.New("record: status is not a terminal half status")

	// ErrHalfAlreadySealed: the half already reached a terminal status and a
	// DIFFERENT one was offered. A half seals once.
	ErrHalfAlreadySealed = errors.New("record: half already sealed")

	// ErrAuditTerminal: the audit is consumed or expired; its halves no
	// longer accept seals.
	ErrAuditTerminal = errors.New("record: audit is consumed or expired")

	// ErrHalfNotSealed: THE READ GATE. A consumer asked for a half whose
	// status is not HalfStatusSealed, or whose audit has expired.
	ErrHalfNotSealed = errors.New("record: half is not sealed; consumer read refused")

	// ErrNotBothSealed: Consume was called before both halves reached a
	// terminal status.
	ErrNotBothSealed = errors.New("record: audit has not reached both_sealed")
)

// SealingError reports a refused sealing or lifecycle transition. It names
// the audit, the half, and the observed state so the message identifies the
// offending caller rather than merely the offence — the same reasoning that
// makes EnumError list every legal literal.
type SealingError struct {
	Op      string     // "BeginAudit" | "SealHalf" | "Consume" | ...
	AuditID string     // anvil/auditId
	Half    Half       // empty when the operation is not half-scoped
	State   State      // the audit's anvil/state at the moment of refusal
	Status  HalfStatus // the half's anvil/status at the moment of refusal
	Reason  string     // human-readable specifics
	Err     error      // one of the sentinels above, or an *EnumError
}

func (e *SealingError) Error() string {
	msg := fmt.Sprintf("record: %s(%q)", e.Op, e.AuditID)
	if e.Half != "" {
		msg += fmt.Sprintf(" half=%s", e.Half)
	}
	if e.State != "" {
		msg += fmt.Sprintf(" state=%s", e.State)
	}
	if e.Status != "" {
		msg += fmt.Sprintf(" status=%s", e.Status)
	}
	return msg + ": " + e.Reason
}

// Unwrap exposes the sentinel cause (or the underlying *EnumError) to
// errors.Is and errors.As.
func (e *SealingError) Unwrap() error { return e.Err }

// ReadGateError is the refusal a consumer gets when it reaches for a half
// that has not sealed. R.6's stop condition: "a consumer attempting to read
// an unsealed half is rejected with a typed error, not a partial/zero-value
// result."
//
// ReadHalf returns the zero HalfSeal alongside this error, as Go requires;
// the contract is that the zero value carries no information and must not be
// inspected when err != nil.
type ReadGateError struct {
	AuditID string     // anvil/auditId
	Half    Half       // the half the consumer reached for
	Status  HalfStatus // that half's actual anvil/status
	State   State      // the audit's anvil/state
	Reason  string
}

func (e *ReadGateError) Error() string {
	return fmt.Sprintf(
		"record: read of %s half of audit %q refused: status is %q, state is %q; %s (the gate opens only at anvil/status=%q)",
		e.Half, e.AuditID, e.Status, e.State, e.Reason, HalfStatusSealed)
}

// Unwrap makes every read refusal match errors.Is(err, ErrHalfNotSealed).
func (e *ReadGateError) Unwrap() error { return ErrHalfNotSealed }

// ---------------------------------------------------------------------------
// Half-status classification
// ---------------------------------------------------------------------------

// TerminalHalfStatuses returns the four HalfStatus values that mean the half
// will produce nothing further. Only these may be handed to SealHalf, and
// only when BOTH halves hold one does the audit reach StateBothSealed.
//
// HalfStatusRunning is deliberately absent: it is the one non-terminal value
// and the reason SealHalf can refuse a caller that mistakes "started" for
// "sealed".
func TerminalHalfStatuses() []HalfStatus {
	return []HalfStatus{
		HalfStatusSealed, HalfStatusFailed, HalfStatusTimedOut, HalfStatusSkipped,
	}
}

// IsTerminalHalfStatus reports whether s means the half is finished, in any
// sense — cleanly sealed, broken, out of clock, or never run.
func IsTerminalHalfStatus(s HalfStatus) bool { return inEnum(s, TerminalHalfStatuses()) }

// IsReadableHalfStatus reports whether the half's STATUS arm of the read gate
// is open. It is true for HalfStatusSealed and for nothing else.
//
// Written as a named predicate on purpose: `if status != HalfStatusRunning`
// and `if IsTerminalHalfStatus(status)` are both wrong here and both look
// plausible at a glance. A failed half is not a clean half; a skipped half
// has no results at all.
//
// IT IS HALF OF THE GATE, NOT THE GATE. Every caller that wants to know
// whether a consumer may read a half's results must call HalfReadGate (or
// HalfSeal.Readable, which is the same answer as a bool) — see the read-gate
// section below for why calling this predicate alone is a bug that has now
// been made four times.
func IsReadableHalfStatus(s HalfStatus) bool { return s == HalfStatusSealed }

// ---------------------------------------------------------------------------
// THE READ GATE — one predicate, one answer, and the reason there is only one
// ---------------------------------------------------------------------------
//
// "May a consumer read this half's results?" is a TWO-ARM question:
//
//	IsReadableHalfStatus(status)  AND  the audit has not expired
//
// Four independent authors have now derived that answer locally instead of
// calling one gate, and each got a different arm wrong:
//
//	CRITIQUE-02 M2 — ReadPacket checked neither arm.
//	CRITIQUE-02 M3 — Sealer.Inspect handed out HalfSeals with no state at all,
//	                 so Readable() said true on an audit ReadHalf refused.
//	CRITIQUE-03 B1 — the GitHub projection consulted neither arm and published
//	                 an unsealed half's results to a third party.
//	CRITIQUE-03 M1 — readpath.go's readOrder and ManifestFromLog checked the
//	                 status arm only, so an EXPIRED audit was fully readable and
//	                 handed a coding agent actionable task cards against a claim
//	                 window that had already closed.
//
// The pattern, not any one of those four, is the defect. So the question is
// answered in exactly ONE function body — halfReadRefusal — and every other
// spelling in this package is a thin wrapper over it:
//
//	HalfReadGate      the typed refusal, for a caller that must report WHY.
//	HalfSeal.Readable the same answer as a bool, for a caller that must branch.
//	Sealer.ReadHalf   the in-memory consumer gate.
//	Sealer.ReadyForConsumption
//	                  the per-half form R.4's handoff rows key on.
//	readpath.go / taskcard.go / sarif_github.go
//	                  the record-side callers, via halfSealOfRun.
//
// THREE GUARDS WATCH THIS, and it took three rounds to get them to fail on
// purpose. None of them is sufficient alone:
//
//	TestEveryResultBearingEntryPointIsGated (readpath_test.go)
//	  BEHAVIOUR. Runs every listed entry point against every state in which no
//	  half may be read and fails if anything comes back. It is the only one
//	  that executes the code, and it only covers entry points someone listed.
//
//	TestResultReachingEntryPointsAreGated (readpath_test.go)
//	  SOURCE REACHABILITY. Walks the package's own AST and fails when an
//	  exported entry point can reach a half's results while nothing in its call
//	  graph reaches this gate. It replaced a whitelist of return TYPES, which
//	  did not name Result, []string or []byte and so let three leaks through.
//
//	TestReadGateArmsAppearOnlyInsideTheGate (sealing_test.go)
//	  ONE-ARM DETECTION. Fails when IsReadableHalfStatus is called, or a state
//	  compared against StateExpired, or a status against HalfStatusSealed,
//	  anywhere outside halfReadRefusal without an allowlisted reason. It
//	  replaced a check that required BOTH arms in one body — which is why it
//	  could not see CRITIQUE-03 M1, whose defect was one arm.
//
// The last two carry negative controls that re-introduce the historical
// defects on every run, because a guard that has never been seen to fail has
// not been tested. This package has now paid for that lesson three times.

// halfReadRefusal returns the reason a consumer may NOT read this half's
// results, or "" when the gate is open. It is THE definition of readability
// and the only place the two arms are combined.
//
// The expiry arm is checked FIRST so that an expired audit holding a cleanly
// sealed half reports the expiry — the fact the caller can act on — rather
// than a status that is, on its own, fine.
func halfReadRefusal(h HalfSeal) string {
	if h.AuditState == StateExpired {
		return "the claim timeout elapsed and the payload was dropped"
	}
	if !IsReadableHalfStatus(h.Status) {
		return "this half has no readable results"
	}
	return ""
}

// HalfReadGate is the ONE read gate. It returns nil when a consumer may read
// h's results, and a *ReadGateError naming the arm that refused when it may
// not.
//
// Every refusal it returns satisfies errors.Is(err, ErrHalfNotSealed) and
// carries the half, its status and the audit state, so a caller can report the
// refusal instead of merely obeying it. auditID is used only to build that
// message; pass "" when there is no audit context to name.
//
// Callers hold a HalfSeal because that is the value that already carries every
// input the gate needs — status and audit state — and because reusing it means
// there is no second vocabulary for "a half's readiness". A record-side caller
// builds one with halfSealOfRun.
func HalfReadGate(auditID string, h HalfSeal) error {
	reason := halfReadRefusal(h)
	if reason == "" {
		return nil
	}
	return &ReadGateError{
		AuditID: auditID, Half: h.Half, Status: h.Status, State: h.AuditState,
		Reason: reason,
	}
}

// halfSealOfRun projects one run of an ASSEMBLED RECORD onto the HalfSeal the
// gate takes: the per-half seal from `run.properties` and the audit-level
// lifecycle state from `sarifLog.properties`.
//
// It exists so that no reader of a record ever has to remember that the second
// arm of the gate lives on a different object from the first. That is exactly
// the mistake CRITIQUE-03 M1 records: `run.Properties.Status` is right there
// and `l.Properties.State` is one dereference further away, so three of four
// call sites reached for the near one and stopped.
func halfSealOfRun(l *SARIFLog, run *Run) HalfSeal {
	var state State
	if l != nil {
		state = l.Properties.State
	}
	return HalfSeal{
		Half:       run.Properties.Half,
		Status:     run.Properties.Status,
		SealedAt:   copyTime(run.Properties.SealedAt),
		AuditState: state,
	}
}

// ---------------------------------------------------------------------------
// Value types
// ---------------------------------------------------------------------------

// HalfSeal is one half's seal: `run.properties["anvil/status"]` and
// `run.properties["anvil/sealedAt"]`, i.e. `audit_record.sast_status` +
// `.sast_sealed_at` (or the DAST pair).
type HalfSeal struct {
	// Half is HalfSast or HalfDast.
	Half Half

	// Status is the per-half anvil/status.
	Status HalfStatus

	// SealedAt is non-nil ONLY when Status == HalfStatusSealed. contract.go:
	// SealedAt "is required once Status == HalfStatusSealed, and is
	// explicitly null otherwise (not omitted — a missing key and an unsealed
	// half must not be the same observation)". A failed, timed-out or
	// skipped half therefore has a nil SealedAt, which is what makes
	// `audit_record.sast_sealed_at IS NULL` mean "never cleanly sealed"
	// rather than "we forgot to write it".
	//
	// This is NOT the claim clock. See AuditSeal.DeadlineAt.
	SealedAt *time.Time

	// AuditState is the anvil/state of the audit this half belongs to, as it
	// stood when the seal was observed. It is carried so that Readable() can
	// answer the WHOLE read-gate question rather than half of it.
	//
	// CRITIQUE-02 F6: ReadHalf refuses an expired audit and Inspect handed out
	// the same HalfSeal values with no state check at all, so
	// Inspect(...).Sast.Readable() said true on an audit ReadHalf refused.
	// Readable() is exported and is what a caller branches on; two exported
	// readiness paths giving two answers is a gate that is only advisory.
	//
	// A hand-constructed HalfSeal leaves this empty, which is not StateExpired
	// and therefore does not silently suppress a real seal — the zero value
	// means "no audit context", and only an audit context can withdraw
	// readability.
	AuditState State
}

// Readable reports whether a consumer may read this half's results.
//
// It is HalfReadGate as a bool — literally the same function body — so a
// caller that branches and a caller that reports a typed refusal can never
// disagree. TestInspectAgreesWithReadHalfOnEveryState asserts the two never
// disagree for any (state, status) pair.
func (h HalfSeal) Readable() bool { return halfReadRefusal(h) == "" }

// DastOutcome is what the DAST half (or its absence) reports, and the sole
// input from which the audit-level DastStatus is derived.
//
// contract.go: DastStatus "is DERIVED from the DAST half's HalfStatus and
// from TargetProvenance (the boot/reachability outcome), never from
// TargetProvisioning (which provisioning path was used)". This struct carries
// exactly those inputs and nothing that would let a caller state the derived
// value directly.
type DastOutcome struct {
	// TierInstalled is plan/00-SPINE.md S9-AMENDED's split: `anvil` ships
	// with no network-probing capability compiled in and `anvil-dast` is a
	// separately installed artifact. False here is the common case and is
	// the ONLY route to DastStatusNotRun.
	//
	// The Sealer overwrites whatever a caller puts here with the audit's own
	// AuditConfig.DastEnabled, so a DAST outcome cannot claim a tier the
	// audit was not started with.
	TierInstalled bool

	// Provenance is the target's boot/reachability outcome, from the target
	// lifecycle harness (area D). Required when TierInstalled; ignored
	// otherwise.
	Provenance TargetProvenance

	// FindingCount is the number of DAST results in the sealed half. It
	// separates DastStatusCompletedFindings from DastStatusCompletedClean —
	// and it is only ever consulted once the provenance checks have already
	// ruled out "we never actually scanned the target".
	FindingCount int

	// PartialCoverage is true when the half probed only part of the
	// discovered attack surface, yielding DastStatusCompletedPartial. The
	// numerator/denominator detail lives in DastCoverage; this is the bit
	// that keeps a 3-of-50 scan from reporting DastStatusCompletedClean.
	PartialCoverage bool
}

// AuditConfig is the input to BeginAudit: everything needed to fix the claim
// clock and to decide whether this installation has a DAST half at all.
type AuditConfig struct {
	// AuditID is `anvil/auditId`, assigned once at scan start. Required.
	AuditID string

	// StartedAt is `scan_run.started_at`. DeadlineAt is computed from THIS
	// and from nothing else. Required, and must be non-zero: a zero start
	// would silently anchor the claim clock to the year 1.
	StartedAt time.Time

	// ClaimTimeoutSeconds is `audit_record.claim_timeout_seconds`. Zero
	// means DefaultClaimTimeoutSeconds (8h); negative is rejected, matching
	// the schema's ck_audit_record_claim_timeout_positive.
	//
	// It is a CLAIM timeout — how long an unclaimed finding stays eligible —
	// not a deletion policy and not a confidentiality control
	// (plan/00-SPINE.md S1 correction #5).
	ClaimTimeoutSeconds int

	// DastEnabled is false in the core `anvil` distribution artifact
	// (plan/00-SPINE.md S9-AMENDED). When false, BeginAudit immediately and
	// terminally seals the DAST half as HalfStatusSkipped /
	// DastStatusNotRun, so the audit can reach StateBothSealed with no DAST
	// worker in the process to seal it. Without that, every SAST-only audit
	// would wedge in StateSastSealed and the consumer would never run.
	DastEnabled bool

	// DastDeadlineSeconds is `audit_record.dast_deadline_seconds`, an
	// INDEPENDENT clock from ClaimTimeoutSeconds. Nil when DAST is disabled;
	// must be positive when set, matching
	// ck_audit_record_dast_deadline_positive. Nothing in this file derives
	// DeadlineAt from it.
	DastDeadlineSeconds *int
}

// AuditSeal is an immutable snapshot of one audit's sealing state — the
// projection the store writer maps onto the `audit_record` columns.
type AuditSeal struct {
	AuditID string // audit_record via scan_run; anvil/auditId
	State   State  // audit_record.state; anvil/state

	Sast HalfSeal // audit_record.sast_status, .sast_sealed_at
	Dast HalfSeal // audit_record.dast_sealed_at (status below)

	// DastStatus is `audit_record.dast_status` / `anvil/dastStatus`. NEVER
	// empty: the schema column is NOT NULL and the enum has no zero value
	// meaning "unknown". It is derived, never assigned by a caller.
	DastStatus DastStatus

	// StartedAt is scan_run.started_at, kept so DeadlineAt is auditable.
	StartedAt time.Time

	// DeadlineAt is `audit_record.deadline_at` = StartedAt +
	// ClaimTimeoutSeconds, computed once at BeginAudit. No seal, no
	// consumption and no read ever changes it.
	DeadlineAt time.Time

	ClaimTimeoutSeconds int
	DastDeadlineSeconds *int
}

// ComputeDeadline returns `scan_run.started_at + claim_timeout_seconds`, the
// one and only formula for `audit_record.deadline_at`.
//
// R.6's forbidden actions: "Do not compute `deadline_at` from any write
// timestamp — it must be `scan_run.started_at + claim_timeout_seconds`,
// computed once and never recomputed." Anchoring it to the last write makes
// the timeout unbounded for a chatty scan, which quietly defeats the reaper.
func ComputeDeadline(startedAt time.Time, claimTimeoutSeconds int) time.Time {
	return startedAt.Add(time.Duration(claimTimeoutSeconds) * time.Second)
}

// ---------------------------------------------------------------------------
// DastStatus derivation
// ---------------------------------------------------------------------------

// DeriveDastStatus maps a DAST HalfStatus plus a DastOutcome onto the
// audit-level DastStatus. It is pure, so the mapping can be tested value by
// value without a Sealer.
//
// THE ORDER OF THESE RULES IS THE POINT. plan/00-SPINE.md S6: "a target that
// failed to boot must be distinguishable from 'scanned clean'". The
// provenance checks therefore run BEFORE the sealed/failed branch, so a half
// that sealed with zero findings against a target that never booted reports
// DastStatusTargetBootFailed and not DastStatusCompletedClean.
//
//  1. tier not installed          -> not_run              (the S9-AMENDED common case)
//  2. status running              -> running
//  3. provenance boot_failed
//     or build_failed             -> target_boot_failed
//  4. provenance unreachable      -> target_unreachable
//  5. provenance no_target        -> skipped_no_manifest
//  6. status skipped              -> skipped_no_manifest  (tier present, half not run)
//  7. status timed_out            -> timed_out
//  8. status failed               -> completed_failed     (booted_clean only; see below)
//  9. status sealed, partial      -> completed_partial
//  10. status sealed, findings > 0 -> completed_findings
//  11. status sealed, findings = 0 -> completed_clean      (the ONLY route to it)
//
// THE FUNCTION IS TOTAL. Every (TargetProvenance, HalfStatus) pair — five
// times five, with and without the tier installed — has exactly one image, and
// TestDeriveDastStatusIsTotal enumerates all of them. There is no pair for
// which this returns an empty DastStatus with a nil error, which matters
// because `audit_record.dast_status` is NOT NULL and the enum has no value
// meaning "unknown".
//
// RULE 8 WAS THE HOLE, AND IT IS NOW CLOSED. The previously frozen nine-value
// enum had no "the DAST half broke" literal, so this function mapped a
// HalfStatusFailed half against a cleanly-booted target onto
// DastStatusCompletedPartial. That was wrong in the same way S6 says a failed
// target must not read as "scanned clean": a half that CRASHED is not a half
// that COVERED PART of the surface, and merging them makes DastCoverage
// uninterpretable — 31 of 50 endpoints reads as a deliberate scope when in
// fact the scanner died. plan/IMPLEMENTATION-PLAN.md §6 was amended with a
// tenth literal, DastStatusCompletedFailed, and rule 8 now uses it. Rules 3-5
// still run first, so this value is reachable ONLY for a genuine mid-scan
// failure against TargetProvenanceBootedClean.
func DeriveDastStatus(status HalfStatus, o DastOutcome) (DastStatus, error) {
	if err := ValidateHalfStatus(string(status)); err != nil {
		return "", err
	}

	// 1. The tier is not installed. Says nothing about the target, and is
	// the ONLY value that may be produced without a valid provenance.
	if !o.TierInstalled {
		return DastStatusNotRun, nil
	}

	if err := ValidateTargetProvenance(string(o.Provenance)); err != nil {
		return "", err
	}

	// 2. Not yet terminal.
	if status == HalfStatusRunning {
		return DastStatusRunning, nil
	}

	// 3-5. What happened to the target outranks what happened to the half.
	switch o.Provenance {
	case TargetProvenanceBootFailed, TargetProvenanceBuildFailed:
		return DastStatusTargetBootFailed, nil
	case TargetProvenanceUnreachableAtScanTime:
		return DastStatusTargetUnreachable, nil
	case TargetProvenanceNoTargetDeclared:
		return DastStatusSkippedNoManifest, nil
	}

	// 6-11. The target booted clean; the half's own status decides.
	switch status {
	case HalfStatusSkipped:
		return DastStatusSkippedNoManifest, nil
	case HalfStatusTimedOut:
		return DastStatusTimedOut, nil
	case HalfStatusFailed:
		// The target was up and the half broke anyway. That is a DAST-side
		// failure, not a coverage decision, and it has its own literal.
		return DastStatusCompletedFailed, nil
	case HalfStatusSealed:
		switch {
		case o.PartialCoverage:
			return DastStatusCompletedPartial, nil
		case o.FindingCount > 0:
			return DastStatusCompletedFindings, nil
		default:
			return DastStatusCompletedClean, nil
		}
	}

	// Unreachable: ValidateHalfStatus admitted the value and every legal
	// literal is handled above.
	return "", &EnumError{
		Field: "anvil/status",
		Value: string(status),
		Allowed: []string{string(HalfStatusRunning), string(HalfStatusSealed),
			string(HalfStatusFailed), string(HalfStatusTimedOut), string(HalfStatusSkipped)},
	}
}

// DeriveState maps the two half statuses onto `anvil/state`.
//
// TERMINAL, not readable, is the test — see this file's header. A DAST half
// that is terminally HalfStatusSkipped advances the audit exactly as a sealed
// one does; what it does not do is open ReadHalf.
//
// StateConsumed and StateExpired are never produced here: they are explicit
// transitions (Consume, ExpireIfDue), not functions of the halves.
func DeriveState(sast, dast HalfStatus) State {
	sastDone := IsTerminalHalfStatus(sast)
	dastDone := IsTerminalHalfStatus(dast)
	switch {
	case sastDone && dastDone:
		return StateBothSealed
	case sastDone:
		return StateSastSealed
	case dastDone:
		return StateDastSealed
	default:
		return StateCollecting
	}
}

// ---------------------------------------------------------------------------
// Sealer
// ---------------------------------------------------------------------------

// audit is the mutable per-audit record. Guarded by Sealer.mu.
type audit struct {
	id                  string
	state               State
	startedAt           time.Time
	deadlineAt          time.Time // written once, in BeginAudit
	claimTimeoutSeconds int
	dastDeadlineSeconds *int
	dastEnabled         bool

	sastStatus   HalfStatus
	sastSealedAt *time.Time
	dastStatus   HalfStatus
	dastSealedAt *time.Time

	dastOutcome DastOutcome
	dastDerived DastStatus
}

// Sealer tracks per-half sealing for in-flight audits. The zero value is not
// usable; call NewSealer.
//
// It is safe for concurrent use: the SAST worker, the DAST worker and the
// consumer all touch the same audit from different goroutines, and the read
// gate is worth nothing if it can be observed mid-update.
type Sealer struct {
	mu     sync.Mutex
	now    func() time.Time
	audits map[string]*audit
}

// NewSealer returns an empty Sealer using the wall clock.
func NewSealer() *Sealer {
	return &Sealer{now: time.Now, audits: make(map[string]*audit)}
}

// SetClock replaces the clock used for `anvil/sealedAt` and for ExpireIfDue's
// due check. It does NOT affect DeadlineAt, which is a function of
// AuditConfig.StartedAt alone.
//
// Passing nil restores time.Now.
func (s *Sealer) SetClock(now func() time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if now == nil {
		now = time.Now
	}
	s.now = now
}

// BeginAudit registers an audit and fixes its claim clock.
//
// DeadlineAt is computed here, once, from cfg.StartedAt. Nothing else in this
// package writes it.
//
// When cfg.DastEnabled is false the DAST half is sealed immediately and
// terminally as HalfStatusSkipped with DastStatusNotRun, and the audit's
// state starts at StateDastSealed rather than StateCollecting. That is what
// lets a core-`anvil` install — which has no DAST code compiled in to call
// SealHalf — still reach StateBothSealed the moment its SAST half seals.
func (s *Sealer) BeginAudit(cfg AuditConfig) (AuditSeal, error) {
	if cfg.AuditID == "" {
		return AuditSeal{}, &SealingError{
			Op: "BeginAudit", AuditID: cfg.AuditID,
			Reason: "anvil/auditId is empty", Err: ErrInvalidAuditConfig,
		}
	}
	if cfg.StartedAt.IsZero() {
		return AuditSeal{}, &SealingError{
			Op: "BeginAudit", AuditID: cfg.AuditID,
			Reason: "scan_run.started_at is the zero time; deadline_at is anchored to scan START and cannot be computed from it",
			Err:    ErrInvalidAuditConfig,
		}
	}
	timeout := cfg.ClaimTimeoutSeconds
	if timeout == 0 {
		timeout = DefaultClaimTimeoutSeconds
	}
	if timeout < 0 {
		return AuditSeal{}, &SealingError{
			Op: "BeginAudit", AuditID: cfg.AuditID,
			Reason: fmt.Sprintf("claim_timeout_seconds is %d; the schema requires > 0", timeout),
			Err:    ErrInvalidAuditConfig,
		}
	}
	if cfg.DastDeadlineSeconds != nil && *cfg.DastDeadlineSeconds <= 0 {
		return AuditSeal{}, &SealingError{
			Op: "BeginAudit", AuditID: cfg.AuditID,
			Reason: fmt.Sprintf("dast_deadline_seconds is %d; the schema requires NULL or > 0", *cfg.DastDeadlineSeconds),
			Err:    ErrInvalidAuditConfig,
		}
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.audits[cfg.AuditID]; exists {
		return AuditSeal{}, &SealingError{
			Op: "BeginAudit", AuditID: cfg.AuditID,
			Reason: "already begun; re-beginning would recompute deadline_at, which R.6 forbids",
			Err:    ErrDuplicateAudit,
		}
	}

	a := &audit{
		id:                  cfg.AuditID,
		startedAt:           cfg.StartedAt,
		deadlineAt:          ComputeDeadline(cfg.StartedAt, timeout),
		claimTimeoutSeconds: timeout,
		dastDeadlineSeconds: copyInt(cfg.DastDeadlineSeconds),
		dastEnabled:         cfg.DastEnabled,
		sastStatus:          HalfStatusRunning,
		dastStatus:          HalfStatusRunning,
		// Default provenance until the target lifecycle harness reports one.
		// no_target_declared derives skipped_no_manifest, so an audit whose
		// DAST half seals without anyone calling RecordDastOutcome can never
		// land on completed_clean by omission.
		dastOutcome: DastOutcome{
			TierInstalled: cfg.DastEnabled,
			Provenance:    TargetProvenanceNoTargetDeclared,
		},
	}

	if !cfg.DastEnabled {
		// The DAST tier is not installed: terminally skipped, never sealed,
		// so SealedAt stays nil and the read gate stays shut.
		a.dastStatus = HalfStatusSkipped
		a.dastSealedAt = nil
	}

	derived, err := DeriveDastStatus(a.dastStatus, a.dastOutcome)
	if err != nil {
		return AuditSeal{}, &SealingError{
			Op: "BeginAudit", AuditID: cfg.AuditID, Half: HalfDast,
			Reason: "cannot derive anvil/dastStatus: " + err.Error(), Err: err,
		}
	}
	a.dastDerived = derived
	a.state = DeriveState(a.sastStatus, a.dastStatus)

	s.audits[cfg.AuditID] = a
	return a.snapshot(), nil
}

// RecordDastOutcome stores the target lifecycle and coverage facts the DAST
// status is derived from. Call it before sealing the DAST half; the last
// value recorded is the one the derivation uses.
//
// o.TierInstalled is IGNORED and replaced with the audit's own
// AuditConfig.DastEnabled, so no caller can report a DAST outcome for a tier
// the audit was not started with.
func (s *Sealer) RecordDastOutcome(auditID string, o DastOutcome) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	a, err := s.lookup("RecordDastOutcome", auditID)
	if err != nil {
		return err
	}
	if a.state == StateConsumed || a.state == StateExpired {
		return &SealingError{
			Op: "RecordDastOutcome", AuditID: auditID, Half: HalfDast, State: a.state,
			Reason: "audit is no longer accepting outcome updates", Err: ErrAuditTerminal,
		}
	}
	if IsTerminalHalfStatus(a.dastStatus) {
		return &SealingError{
			Op: "RecordDastOutcome", AuditID: auditID, Half: HalfDast,
			State: a.state, Status: a.dastStatus,
			Reason: "the DAST half has already sealed; its outcome is frozen",
			Err:    ErrHalfAlreadySealed,
		}
	}

	o.TierInstalled = a.dastEnabled
	if o.TierInstalled {
		if err := ValidateTargetProvenance(string(o.Provenance)); err != nil {
			return &SealingError{
				Op: "RecordDastOutcome", AuditID: auditID, Half: HalfDast, State: a.state,
				Reason: "illegal anvil/target.provenance: " + err.Error(), Err: err,
			}
		}
	} else {
		o.Provenance = TargetProvenanceNoTargetDeclared
	}
	a.dastOutcome = o

	derived, err := DeriveDastStatus(a.dastStatus, a.dastOutcome)
	if err != nil {
		return &SealingError{
			Op: "RecordDastOutcome", AuditID: auditID, Half: HalfDast, State: a.state,
			Reason: "cannot derive anvil/dastStatus: " + err.Error(), Err: err,
		}
	}
	a.dastDerived = derived
	return nil
}

// SealHalf gives one half its terminal status.
//
// status must be one of TerminalHalfStatuses; HalfStatusRunning is refused
// with ErrNotSealable, because "started" is not "sealed". `anvil/sealedAt` is
// stamped only for HalfStatusSealed, per contract.go's RunProperties.SealedAt
// rule.
//
// Re-sealing a half with the IDENTICAL status is a no-op and preserves the
// original SealedAt, so a retried store write cannot move a seal timestamp.
// Re-sealing with a different status is ErrHalfAlreadySealed.
//
// DeadlineAt is not touched. Ever.
func (s *Sealer) SealHalf(auditID string, half Half, status HalfStatus) error {
	if err := ValidateHalf(string(half)); err != nil {
		return &SealingError{
			Op: "SealHalf", AuditID: auditID,
			Reason: "illegal anvil/half: " + err.Error(), Err: err,
		}
	}
	if err := ValidateHalfStatus(string(status)); err != nil {
		return &SealingError{
			Op: "SealHalf", AuditID: auditID, Half: half,
			Reason: "illegal anvil/status: " + err.Error(), Err: err,
		}
	}
	if !IsTerminalHalfStatus(status) {
		return &SealingError{
			Op: "SealHalf", AuditID: auditID, Half: half, Status: status,
			Reason: fmt.Sprintf("%q is not terminal; a half seals with one of %v", status, TerminalHalfStatuses()),
			Err:    ErrNotSealable,
		}
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	a, err := s.lookup("SealHalf", auditID)
	if err != nil {
		return err
	}
	if a.state == StateConsumed || a.state == StateExpired {
		return &SealingError{
			Op: "SealHalf", AuditID: auditID, Half: half, State: a.state, Status: status,
			Reason: "audit is no longer accepting seals", Err: ErrAuditTerminal,
		}
	}

	current := a.sastStatus
	if half == HalfDast {
		current = a.dastStatus
	}
	if IsTerminalHalfStatus(current) {
		if current == status {
			return nil // idempotent; SealedAt preserved
		}
		return &SealingError{
			Op: "SealHalf", AuditID: auditID, Half: half, State: a.state, Status: current,
			Reason: fmt.Sprintf("already sealed as %q; cannot re-seal as %q", current, status),
			Err:    ErrHalfAlreadySealed,
		}
	}

	var sealedAt *time.Time
	if status == HalfStatusSealed {
		t := s.now().UTC()
		sealedAt = &t
	}

	if half == HalfSast {
		a.sastStatus = status
		a.sastSealedAt = sealedAt
	} else {
		a.dastStatus = status
		a.dastSealedAt = sealedAt
		derived, derr := DeriveDastStatus(a.dastStatus, a.dastOutcome)
		if derr != nil {
			return &SealingError{
				Op: "SealHalf", AuditID: auditID, Half: half, State: a.state, Status: status,
				Reason: "cannot derive anvil/dastStatus: " + derr.Error(), Err: derr,
			}
		}
		a.dastDerived = derived
	}

	a.state = DeriveState(a.sastStatus, a.dastStatus)
	return nil
}

// ReadyForConsumption reports, per half, whether a consumer may read that
// half's results now. An unknown audit reports (false, false).
//
// This is the gate plan/IMPLEMENTATION-PLAN.md §6 ruling G9 wires the handoff
// table to: `handoff.consumption_class = 'static_only'` rows become claimable
// when sastReady is true, and `'requires_dynamic_confirmation'` rows must
// wait for dastReady. plan/00-SPINE.md S7: "Only a DAST reproduction that now
// fails earns 'verified fixed'."
//
// dastReady stays false for a DAST-disabled audit even after it reaches
// StateBothSealed — there are no DAST results, and "no findings recorded" is
// not "dynamically scanned clean".
func (s *Sealer) ReadyForConsumption(auditID string) (sastReady, dastReady bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	a, ok := s.audits[auditID]
	if !ok {
		return false, false
	}
	// The SAME gate ReadHalf enforces, asked twice. Asking
	// IsReadableHalfStatus here and handling expiry separately is how the two
	// answers drift apart; see the read-gate section above.
	return a.halfSeal(HalfSast).Readable(), a.halfSeal(HalfDast).Readable()
}

// ReadHalf is the consumer's read gate. It returns the half's seal only when
// that half's `anvil/status` is exactly HalfStatusSealed; every other status
// — running, failed, timed_out, skipped — is refused with a *ReadGateError,
// as is any read of an expired audit, whose payload the reaper has dropped.
//
// A consumed audit is still readable: plan/00-SPINE.md S1 requires a
// RE-ENTRANT consumer, so taking the record once must not shut the gate.
//
// On refusal the returned HalfSeal is the zero value and carries no
// information; callers must check the error.
func (s *Sealer) ReadHalf(auditID string, half Half) (HalfSeal, error) {
	if err := ValidateHalf(string(half)); err != nil {
		return HalfSeal{}, &SealingError{
			Op: "ReadHalf", AuditID: auditID,
			Reason: "illegal anvil/half: " + err.Error(), Err: err,
		}
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	a, ok := s.audits[auditID]
	if !ok {
		return HalfSeal{}, &SealingError{
			Op: "ReadHalf", AuditID: auditID, Half: half,
			Reason: "no such audit", Err: ErrUnknownAudit,
		}
	}

	seal := a.halfSeal(half)
	if err := HalfReadGate(auditID, seal); err != nil {
		return HalfSeal{}, err
	}
	return seal, nil
}

// Consume marks the audit taken by the coding-agent consumption pipeline
// (`audit_record.consumed_at`, StateConsumed). It requires StateBothSealed;
// consuming a half-finished audit is what the read gate exists to prevent.
//
// Consuming an already-consumed audit is a no-op, because the consumer is
// re-entrant by design.
func (s *Sealer) Consume(auditID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	a, err := s.lookup("Consume", auditID)
	if err != nil {
		return err
	}
	switch a.state {
	case StateConsumed:
		return nil
	case StateExpired:
		return &SealingError{
			Op: "Consume", AuditID: auditID, State: a.state,
			Reason: "the claim timeout elapsed", Err: ErrAuditTerminal,
		}
	case StateBothSealed:
		a.state = StateConsumed
		return nil
	default:
		return &SealingError{
			Op: "Consume", AuditID: auditID, State: a.state,
			Reason: fmt.Sprintf("state is %q; consumption requires %q", a.state, StateBothSealed),
			Err:    ErrNotBothSealed,
		}
	}
}

// ExpireIfDue moves the audit to StateExpired if and only if the clock has
// reached DeadlineAt, and reports whether it did.
//
// There is deliberately no unconditional Expire. The claim timeout is the
// only thing that may expire an audit, and DeadlineAt is fixed at scan start,
// so no amount of late activity can bring expiry forward or push it back.
// An already-consumed audit is never expired out from under its consumer.
func (s *Sealer) ExpireIfDue(auditID string) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	a, err := s.lookup("ExpireIfDue", auditID)
	if err != nil {
		return false, err
	}
	switch a.state {
	case StateExpired:
		return false, nil
	case StateConsumed:
		return false, nil
	}
	if s.now().Before(a.deadlineAt) {
		return false, nil
	}
	a.state = StateExpired
	return true, nil
}

// Inspect returns a snapshot of the audit's sealing state, or ok=false if the
// audit is unknown. The snapshot shares no mutable state with the Sealer.
//
// Inspect is a DIAGNOSTIC: it deliberately still reports the true status of an
// expired audit's halves, because "this audit expired holding a sealed SAST
// half" is exactly what an operator needs to see. What it does not do any more
// is claim those halves are readable — every HalfSeal it hands out carries the
// audit state, so Readable() honours the expiry arm of the read gate that
// ReadHalf enforces. See CRITIQUE-02 F6.
func (s *Sealer) Inspect(auditID string) (AuditSeal, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	a, ok := s.audits[auditID]
	if !ok {
		return AuditSeal{}, false
	}
	return a.snapshot(), true
}

// Forget drops an audit from the in-memory tracker. The durable row in
// `audit_record` is unaffected — plan/40-record-and-storage.md is explicit
// that the reaper drops the payload and never the row.
func (s *Sealer) Forget(auditID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.audits, auditID)
}

// lookup requires s.mu.
func (s *Sealer) lookup(op, auditID string) (*audit, error) {
	a, ok := s.audits[auditID]
	if !ok {
		return nil, &SealingError{
			Op: op, AuditID: auditID, Reason: "no such audit", Err: ErrUnknownAudit,
		}
	}
	return a, nil
}

// halfSeal requires Sealer.mu.
//
// AuditState is stamped here, on every path — ReadHalf's, Inspect's and
// snapshot's alike — so there is no way to obtain a HalfSeal from a Sealer
// whose Readable() answers a different question from ReadHalf's gate.
func (a *audit) halfSeal(half Half) HalfSeal {
	if half == HalfDast {
		return HalfSeal{
			Half: HalfDast, Status: a.dastStatus,
			SealedAt: copyTime(a.dastSealedAt), AuditState: a.state,
		}
	}
	return HalfSeal{
		Half: HalfSast, Status: a.sastStatus,
		SealedAt: copyTime(a.sastSealedAt), AuditState: a.state,
	}
}

// snapshot requires Sealer.mu.
func (a *audit) snapshot() AuditSeal {
	return AuditSeal{
		AuditID:             a.id,
		State:               a.state,
		Sast:                a.halfSeal(HalfSast),
		Dast:                a.halfSeal(HalfDast),
		DastStatus:          a.dastDerived,
		StartedAt:           a.startedAt,
		DeadlineAt:          a.deadlineAt,
		ClaimTimeoutSeconds: a.claimTimeoutSeconds,
		DastDeadlineSeconds: copyInt(a.dastDeadlineSeconds),
	}
}

func copyTime(t *time.Time) *time.Time {
	if t == nil {
		return nil
	}
	v := *t
	return &v
}

func copyInt(n *int) *int {
	if n == nil {
		return nil
	}
	v := *n
	return &v
}

// ---------------------------------------------------------------------------
// Package-level default Sealer
// ---------------------------------------------------------------------------

// defaultSealer backs the package-level functions below.
var defaultSealer = NewSealer()

// DefaultSealer returns the Sealer the package-level functions operate on.
// A process that wants isolated sealing state (tests, or a tool auditing two
// scans at once) should use NewSealer instead.
func DefaultSealer() *Sealer { return defaultSealer }

// BeginAudit registers an audit on the default Sealer. See Sealer.BeginAudit.
func BeginAudit(cfg AuditConfig) (AuditSeal, error) { return defaultSealer.BeginAudit(cfg) }

// RecordDastOutcome records DAST lifecycle facts on the default Sealer. See
// Sealer.RecordDastOutcome.
func RecordDastOutcome(auditID string, o DastOutcome) error {
	return defaultSealer.RecordDastOutcome(auditID, o)
}

// SealHalf seals one half on the default Sealer.
//
// This is R.6's mandated signature, taking `half` and `status` as strings
// because it is the boundary a scan controller calls across. Both are
// validated against contract.go's frozen enums before anything is mutated, so
// a bare literal that is not an enum member is rejected here rather than
// three layers down at a NOT NULL CHECK constraint. Callers inside Go should
// pass `string(HalfSast)` and `string(HalfStatusSealed)` — never a hand-typed
// "sast"/"sealed" — or use the typed Sealer.SealHalf method directly.
func SealHalf(auditID, half string, status string) error {
	return defaultSealer.SealHalf(auditID, Half(half), HalfStatus(status))
}

// ReadyForConsumption reports per-half consumer readiness on the default
// Sealer. See Sealer.ReadyForConsumption.
func ReadyForConsumption(auditID string) (sastReady, dastReady bool) {
	return defaultSealer.ReadyForConsumption(auditID)
}

// ReadHalf is the read gate on the default Sealer. See Sealer.ReadHalf.
func ReadHalf(auditID string, half Half) (HalfSeal, error) {
	return defaultSealer.ReadHalf(auditID, half)
}

// Consume marks an audit consumed on the default Sealer. See Sealer.Consume.
func Consume(auditID string) error { return defaultSealer.Consume(auditID) }

// ExpireIfDue expires a due audit on the default Sealer. See
// Sealer.ExpireIfDue.
func ExpireIfDue(auditID string) (bool, error) { return defaultSealer.ExpireIfDue(auditID) }

// Inspect snapshots an audit on the default Sealer. See Sealer.Inspect.
func Inspect(auditID string) (AuditSeal, bool) { return defaultSealer.Inspect(auditID) }
