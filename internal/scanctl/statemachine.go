// The scan controller's state machine (step O.2): the wiring that turns
// worker events into plan/00-SPINE.md S10's "one state machine with one
// owner", and the version-bump watermarks that make research/21
// Recommendation §5's incremental publication happen without a per-finding
// write storm.
//
// # THIS FILE IMPLEMENTS NO STATE MACHINE OF ITS OWN
//
// plan/IMPLEMENTATION-PLAN.md §6 ruling G2 struck O.2's original
// `open | sast_sealed | sealed | expired` machine outright, on two grounds
// that are worth restating because both are easy to re-derive by accident:
//
//   - It could not express a DAST-FIRST seal at all. plan/00-SPINE.md S1
//     requires "two INDEPENDENTLY-sealed halves", and the SAST half can be
//     slow, or can fail, while the DAST half finishes first.
//   - It made `sealed` terminal, which makes `consumed` unreachable, which
//     silently disables the re-entrant consumer the same spine item requires.
//
// The replacement is not a re-drawn machine in this file. It is
// record.Sealer, which already owns:
//
//	record.State / record.StateValues     the six-value anvil/state enum
//	record.DeriveState                    halves -> anvil/state
//	record.DeriveDastStatus               (half status, provenance) -> anvil/dastStatus
//	record.Sealer.BeginAudit              fixes deadline_at, once
//	record.Sealer.SealHalf                the per-half terminal transition
//	record.Sealer.RecordDastOutcome       the target-lifecycle facts
//	record.Sealer.Consume                 both_sealed -> consumed
//	record.Sealer.ExpireIfDue             -> expired, and only when due (clock 2)
//	record.Sealer.SealDastIfDeadlineDue   -> dast timed_out, when due (clock 3)
//	record.Sealer.ReadyForConsumption     the per-half consumption gate
//	record.Sealer.ReadHalf                THE read gate, over a seal it mints
//
// Every one of those is called from here and none of them is re-derived here.
// A second DeriveState in this package would be ruling G2 being broken a
// second time; a locally re-derived read gate would be the defect
// internal/record/sealing.go's header records FIVE authors making.
//
// WHAT THIS FILE ADDS, and it is only these four things:
//
//  1. AuditRecord — research/21 §5's `audit_record` shape as a Go value, with
//     the four fields the Sealer does not carry: the monotonic `version`, the
//     per-half `findings[]`, the `correlation` clusters, and the two deadline
//     instants from deadlines.go (O.1). It is a SNAPSHOT; see below.
//  2. Event — the vocabulary of things that happen TO an audit. It is
//     deliberately NOT a state vocabulary; the states are record's.
//  3. Transition — apply one event, then re-project from the Sealer, so the
//     lifecycle fields on the returned record are always the Sealer's answer
//     and never this file's opinion.
//  4. WatermarkPolicy — research/21 §5's "version-bump on watermarks, not per
//     finding", as config rather than constants.
//
// # THE CONTROLLER OWNS THE MUTABLE STATE; AN AuditRecord IS A SNAPSHOT OF IT
//
// This is the shape CRITIQUE O.4 forced, and three of its findings are one
// mistake seen from three sides. The buffers, the version counter and the
// watermark bookkeeping used to live on the AuditRecord value the CALLER held,
// with the Sealer holding only the lifecycle. That had two consequences:
//
//   - Fan-in lost RESULTS. Eight workers each cloning their own copy of one
//     record and each returning a new one meant the last writer won: the critic
//     measured 21 of 24 DAST findings silently dropped, on a security scanner
//     (O4-M3). The doc called that "a skipped version bump, not a corrupt
//     lifecycle" — true of the lifecycle, and wrong about the findings, which
//     is the half an implementer would have acted on.
//   - Every guard read a value the caller owned. The read gate and the two
//     write guards were asked about `rec.State`, which stops tracking the
//     Sealer the moment the caller stops calling Transition, so an EXPIRED
//     audit was both readable and writable through a record taken before it
//     expired (O4-B1, O4-M2).
//
// So Controller holds one `auditState` per audit under one mutex, and an
// AuditRecord is a value PROJECTED from (that state, the Sealer's AuditSeal) at
// the instant it was produced. Transition reads the audit id off the record it
// is handed and NOTHING ELSE: two goroutines passing in the same stale snapshot
// both append, and neither can overwrite the other. Controller.Record is the
// refresh path whose absence O4-B1 turned into a readable expired audit.
//
// A snapshot is still a snapshot: it can be stale, and it carries no gate. That
// is why Findings and Readable are METHODS ON THE CONTROLLER, which re-Inspect
// and go through record.Sealer.ReadHalf, rather than methods on AuditRecord,
// which could only ever answer about the past.
//
// # PER-HALF TRANSITIONS KEY ON `sealed`, NEVER ON `complete`
//
// Ruling G5. `complete` is struck from the vocabulary; record.HalfStatusSealed
// is the token, and R.6 makes it the hard consumer read gate. A controller
// keying its transition on any other token is a controller whose read gate
// never opens. There is no `complete` anywhere in this package, and no bare
// string literal for any enum value — a second copy of a literal is a second
// definition, which is how nine of §6's ten defects happened.
//
// # WHERE `created_at` WENT
//
// research/21 §5 writes the record shape with a `created_at` field and glosses
// `deadline_at` as `created_at + 8h`, "anchored to scan START, never to last
// write". deadlines.go resolved that spelling against the frozen schema: the
// anchor is `scan_run.started_at`, and `audit_record.created_at` is a separate
// WRITE timestamp owned by the store writer. So AuditRecord carries no
// `CreatedAt`; the scan-start instant research/21 meant is
// AuditRecord.Deadlines.StartedAt(), in one place, spelled the schema's way.
// Carrying a second copy under research/21's name is exactly the
// "two areas meaning different things by the same field name" class §6 was
// convened over.
//
// (Free-floating file comment: deadlines.go carries the package doc.)

package scanctl

import (
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/Susquehanna-Syntax/Anvil/internal/record"
)

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

// The sentinels this file adds. There are only three, and each names a
// refusal internal/record has no opinion about. Every OTHER refusal a
// transition can produce is record's own — record.ErrUnknownAudit,
// record.ErrNotSealable, record.ErrHalfAlreadySealed, record.ErrAuditTerminal,
// record.ErrNotBothSealed, record.ErrHalfNotSealed, *record.EnumError — and is
// returned UNWRAPPED, so a caller branching with errors.Is sees the frozen
// package's answer rather than a re-spelling of it. Wrapping them in a scanctl
// error type would be a second refusal vocabulary over a frozen one.
var (
	// ErrUnknownEvent: the Event's Kind is not one of EventKindValues.
	// The zero Event lands here, which is deliberate — an accidentally
	// zero-valued event must not silently mean "tick".
	ErrUnknownEvent = errors.New("scanctl: unknown event kind")

	// ErrEmptyEvent: the event carries no payload and would therefore be a
	// silent no-op. O.2's validation requirement is that an illegal
	// transition "returns an error, not a panic or a silent no-op"; an
	// event that changes nothing is the no-op case.
	ErrEmptyEvent = errors.New("scanctl: event carries no payload")

	// ErrHalfNotAccepting: findings arrived for a half that has already
	// reached one of record.TerminalHalfStatuses. A sealed half's results
	// are frozen; appending to them after the fact would move what a
	// consumer already read.
	ErrHalfNotAccepting = errors.New("scanctl: half is terminal and accepts no further findings")

	// ErrInvalidWatermarkPolicy: a negative N or M. Zero means "use the
	// derived default" and is not an error.
	ErrInvalidWatermarkPolicy = errors.New("scanctl: invalid watermark policy")
)

// TransitionError reports a refused transition, naming the event, the audit,
// and the lifecycle state at the moment of refusal — the same shape as
// record.SealingError and scanctl.PolicyError, for the same reason: the
// message should identify the offending caller, not merely the offence.
type TransitionError struct {
	Kind    EventKind    // the event that was refused
	AuditID string       // anvil/auditId
	Half    record.Half  // empty when the event is not half-scoped
	State   record.State // anvil/state at the moment of refusal
	Reason  string
	Err     error // one of the sentinels above, or a *record.EnumError
}

func (e *TransitionError) Error() string {
	msg := fmt.Sprintf("scanctl: event %s on audit %q", e.Kind, e.AuditID)
	if e.Half != "" {
		msg += fmt.Sprintf(" half=%s", e.Half)
	}
	if e.State != "" {
		msg += fmt.Sprintf(" state=%s", e.State)
	}
	return msg + ": " + e.Reason
}

// Unwrap exposes the sentinel to errors.Is.
func (e *TransitionError) Unwrap() error { return e.Err }

// ---------------------------------------------------------------------------
// WatermarkPolicy — research/21 §5's "bump on watermarks, not per finding"
// ---------------------------------------------------------------------------

// WatermarkPolicy is the configuration behind research/21 §5's version-bump
// rule, verbatim: "Version-bump on watermarks, not per finding: bump on (a)
// `sast.status -> complete`, (b) every N DAST findings or every M minutes,
// whichever first, (c) `dast` terminal state. Per-finding publication turns
// the buffer into a write-amplification hotspot on the same disk the DB is
// on."
//
// (a) and (c) need no configuration — they are events, and this file bumps on
// ANY terminal seal of EITHER half. The generalisation is deliberate:
// plan/00-SPINE.md S6 requires the work queue to be re-cut on every version
// bump, and a SAST half that reached record.HalfStatusFailed has changed the
// record just as materially as one that reached record.HalfStatusSealed — the
// queue must learn that no more SAST findings are coming. (research/21 wrote
// (a) as `complete`, which ruling G5 struck; record.HalfStatusSealed is the
// token, and "terminal" is the classification record.IsTerminalHalfStatus
// owns.)
//
// N and M are (b), and they are DATA, never constants: plan/00-SPINE.md S1
// makes "no hard-coded triggers" a hard constraint and research/21 §5 extends
// it to the companion controls explicitly. The zero WatermarkPolicy is
// meaningful and resolves to the derived defaults below; it is not an error.
type WatermarkPolicy struct {
	// DastFindings is N: publish once this many DAST findings have arrived
	// since the last publication. Zero means DefaultWatermarkDastFindings.
	// Negative is rejected. One would be per-finding publication, which is
	// the thing research/21 §5 names as the failure; it is permitted rather
	// than rejected, because refusing a value the research merely advises
	// against would make this package a second, stricter policy authority
	// (see Deadlines.DastDeadlineBinds for the same argument made once
	// already).
	DastFindings int

	// Interval is M: publish once this long has elapsed since the last
	// publication AND at least one DAST finding is unpublished. Zero means
	// the value DefaultWatermarkInterval derives from the audit's DAST
	// budget. Negative is rejected.
	//
	// It fires only on EventKindTick. Nothing in this package runs a timer;
	// see Controller.NextWake for the instant a daemon must wake at.
	Interval time.Duration
}

// DefaultWatermarkDastFindings is N's default: 50.
//
// DERIVED, not chosen. research/21 §4 bounds each per-scan finding ring at
// "5,000 findings / 64 MiB per side per scan (suggested defaults,
// configurable)". Publishing every 1% of that bound means a ring that fills
// completely produces at most 100 publications instead of 5,000 — two orders
// of magnitude off the per-finding write amplification §5 forbids, while still
// giving a consumer roughly a hundred progressively better cuts of the queue
// over the worst-case scan. Both numbers move together if an operator
// re-sizes the ring, which is why the relation is written down here and the
// value is config.
const DefaultWatermarkDastFindings = 50

// WatermarkIntervalDivisor is the number of time-triggered publications the
// default M allows across one audit's whole DAST budget: 16, i.e. staleness
// bounded at 6.25% of the budget.
//
// It is a RELATION rather than a duration for the same reason
// DefaultDastDeadlineSeconds is: writing "15 minutes" down would silently
// decouple publication from the budget the moment an operator shortened it,
// and an M longer than the DAST deadline is a watermark that can never fire.
const WatermarkIntervalDivisor = 16

// DefaultWatermarkInterval returns M derived from an audit's DAST budget:
// budget / WatermarkIntervalDivisor, clamped to a minimum of one second so a
// test fixture's tiny budget cannot produce a zero or negative interval.
//
// At research/21 §5's shipped default budget of 4h it returns 15 minutes.
//
// WHAT "budget" IS. The resolved DAST deadline when the installation has a
// DAST half, and half the claim window otherwise — which is the same quantity
// DefaultDastDeadlineSeconds computes, so the derived M does not jump when an
// operator installs `anvil-dast` and accepts the default deadline.
// Controller.Resolve does that selection once; callers should not repeat it.
func DefaultWatermarkInterval(budget time.Duration) time.Duration {
	if d := budget / WatermarkIntervalDivisor; d > 0 {
		return d
	}
	return time.Second
}

// Resolve fills in the derived defaults and validates. budget is the audit's
// DAST budget, as described on DefaultWatermarkInterval.
//
// Resolve is idempotent: resolving an already-resolved policy against the same
// budget returns it unchanged.
func (w WatermarkPolicy) Resolve(budget time.Duration) (WatermarkPolicy, error) {
	out := WatermarkPolicy{}

	switch {
	case w.DastFindings < 0:
		return WatermarkPolicy{}, &PolicyError{
			Field: "watermark.dastFindings", Value: fmt.Sprint(w.DastFindings),
			Reason: "N is a count of findings and cannot be negative",
			Err:    ErrInvalidWatermarkPolicy,
		}
	case w.DastFindings == 0:
		out.DastFindings = DefaultWatermarkDastFindings
	default:
		out.DastFindings = w.DastFindings
	}

	switch {
	case w.Interval < 0:
		return WatermarkPolicy{}, &PolicyError{
			Field: "watermark.interval", Value: w.Interval.String(),
			Reason: "M is an elapsed duration and cannot be negative",
			Err:    ErrInvalidWatermarkPolicy,
		}
	case w.Interval == 0:
		out.Interval = DefaultWatermarkInterval(budget)
	default:
		out.Interval = w.Interval
	}

	return out, nil
}

// ---------------------------------------------------------------------------
// Events
// ---------------------------------------------------------------------------

// EventKind names a thing that HAPPENS TO an audit.
//
// IT IS NOT A STATE VOCABULARY, and none of its literals is a record enum
// token. That separation is load-bearing: plan/IMPLEMENTATION-PLAN.md §6's
// through-line ruling is that area 40 owns every shared enum "because it owns
// the record contract, and no other area may declare one". An event kind is
// not a record field, is never serialised onto a record, and is never written
// to a column — it is this package's internal dispatch tag, and it is spelled
// so that it cannot be mistaken for one of R.1's six frozen enums.
type EventKind string

// The six event kinds. Each maps onto exactly one record.Sealer entry point,
// except EventKindTick (two clocks) and EventKindFindings (none — findings
// buffer in this package until a watermark publishes them).
const (
	// EventKindFindings: a worker produced findings for one half. Buffered;
	// publishes only on watermark (b). Refused once the half is terminal.
	EventKindFindings EventKind = "findings"

	// EventKindDastOutcome: the target lifecycle harness (area D) reported
	// provenance and coverage facts. Forwarded to
	// record.Sealer.RecordDastOutcome, which is where anvil/dastStatus is
	// derived from. Never a publication on its own.
	EventKindDastOutcome EventKind = "dast_outcome"

	// EventKindSealHalf: a half reached a terminal status. Forwarded to
	// record.Sealer.SealHalf. Publishes — watermarks (a) and (c).
	EventKindSealHalf EventKind = "seal_half"

	// EventKindTick: the daemon woke. Drives clock 3 (the DAST deadline,
	// due-check record.Sealer.SealDastIfDeadlineDue) and then clock 2 (the
	// claim timeout, due-check record.Sealer.ExpireIfDue), plus watermark
	// (b)'s time arm. Neither due-check is this package's; see applyTick.
	// Idempotent: ticking an expired audit is not an error.
	EventKindTick EventKind = "tick"

	// EventKindCorrelate: R.12's correlator produced clusters. Stored on the
	// record; NOT a publication watermark, because research/21 §5 lists
	// three and this is not one of them — the clusters land with the DAST
	// terminal bump that follows.
	EventKindCorrelate EventKind = "correlate"

	// EventKindConsume: the coding-agent consumption pipeline took the
	// record. Forwarded to record.Sealer.Consume, which requires
	// record.StateBothSealed. Not a publication: consumption does not
	// re-publish, and the consumer is re-entrant.
	EventKindConsume EventKind = "consume"
)

// EventKindValues returns every legal EventKind, in the order the doc above
// lists them.
func EventKindValues() []EventKind {
	return []EventKind{
		EventKindFindings, EventKindDastOutcome, EventKindSealHalf,
		EventKindTick, EventKindCorrelate, EventKindConsume,
	}
}

// Valid reports whether k is one of EventKindValues.
func (k EventKind) Valid() bool {
	for _, v := range EventKindValues() {
		if k == v {
			return true
		}
	}
	return false
}

// Event is one thing that happened to an audit. Build one with the
// constructors below rather than by hand: the zero Event has an invalid Kind
// and Transition refuses it with ErrUnknownEvent, which is the intended
// treatment of an accidentally-zero event but a poor way to write one on
// purpose.
type Event struct {
	Kind EventKind

	// Half is set by EventKindFindings and EventKindSealHalf.
	Half record.Half

	// Status is set by EventKindSealHalf. It must be one of
	// record.TerminalHalfStatuses; record.Sealer.SealHalf enforces that and
	// returns record.ErrNotSealable otherwise. record.HalfStatusRunning is
	// the value this catches — "started" is not "sealed".
	Status record.HalfStatus

	// Findings is set by EventKindFindings.
	Findings []record.Result

	// Outcome is set by EventKindDastOutcome. Its TierInstalled field is
	// overwritten by the Sealer with the audit's own AuditConfig.DastEnabled,
	// so a caller cannot report an outcome for a tier the audit was not
	// started with.
	Outcome record.DastOutcome

	// Correlation is set by EventKindCorrelate.
	Correlation []record.Correlation
}

// FindingsEvent reports findings arriving on one half.
func FindingsEvent(half record.Half, findings ...record.Result) Event {
	return Event{Kind: EventKindFindings, Half: half, Findings: findings}
}

// SealHalfEvent reports one half reaching a terminal status. status must be
// one of record.TerminalHalfStatuses.
func SealHalfEvent(half record.Half, status record.HalfStatus) Event {
	return Event{Kind: EventKindSealHalf, Half: half, Status: status}
}

// DastOutcomeEvent reports the target lifecycle and coverage facts
// record.DeriveDastStatus consumes.
func DastOutcomeEvent(o record.DastOutcome) Event {
	return Event{Kind: EventKindDastOutcome, Half: record.HalfDast, Outcome: o}
}

// TickEvent reports that the daemon woke and the clocks should be evaluated.
func TickEvent() Event { return Event{Kind: EventKindTick} }

// CorrelateEvent reports correlation clusters from R.12's correlator.
//
// EACH BATCH IS THE COMPLETE SET. It REPLACES whatever clusters the audit was
// carrying; it does not accumulate. A correlator that emits partial batches
// would lose the earlier ones, so it must emit its whole current answer each
// time. See applyCorrelation for why replacement rather than accumulation is
// the contract this package can actually honour.
func CorrelateEvent(clusters ...record.Correlation) Event {
	return Event{Kind: EventKindCorrelate, Correlation: clusters}
}

// ConsumeEvent reports the consumption pipeline taking the record.
func ConsumeEvent() Event { return Event{Kind: EventKindConsume} }

// ---------------------------------------------------------------------------
// AuditRecord
// ---------------------------------------------------------------------------

// HalfRecord is one half of research/21 §5's record shape: `{ status,
// sealed_at, findings[] }`.
//
// Status and SealedAt are PROJECTIONS of record.Sealer's answer, re-read from
// the Sealer after every transition. Assigning to them on a copy changes
// nothing durable and is overwritten by the next Transition; the Sealer is the
// authority and this struct is a view of it.
type HalfRecord struct {
	// Half is record.HalfSast or record.HalfDast.
	Half record.Half

	// Status is the per-half `anvil/status` — R.1's frozen five-value enum,
	// in which record.HalfStatusSealed and nothing else is the read gate.
	Status record.HalfStatus

	// SealedAt is `anvil/sealedAt`, non-nil only when Status is
	// record.HalfStatusSealed. It is NOT the claim clock; see
	// AuditRecord.Deadlines.
	SealedAt *time.Time

	// findings is `findings[]`. UNEXPORTED on purpose: reading a half's
	// results is gated, and an exported slice field is an ungated read.
	// Controller.Findings is the gated accessor.
	findings []record.Result
}

// FindingCount reports how many findings this half has buffered.
//
// IT IS NOT GATED, and that is deliberate rather than an oversight. A count is
// audit-level metadata, not results: record.DastOutcome.FindingCount is the
// input record.DeriveDastStatus uses to tell record.DastStatusCompletedClean
// from record.DastStatusCompletedFindings, and that derivation runs BEFORE the
// half seals, so a gated count could not exist. What the gate protects is the
// results themselves — see AuditRecord.Findings.
func (h HalfRecord) FindingCount() int { return len(h.findings) }

// AuditRecord is one audit as the scan controller holds it: research/21 §5's
// `audit_record` shape, re-cut by plan/IMPLEMENTATION-PLAN.md §6's rulings.
//
// It is a VALUE. Transition takes one and returns a new one; the input is
// never mutated, so a caller may keep the previous version to diff against
// (which is what VersionBumped and DurableWriteDue do).
//
// The lifecycle fields — State, the two Status/SealedAt pairs, DastStatus —
// are re-projected from record.Sealer after every transition. Nothing a caller
// writes into them survives, and nothing in this package computes them.
type AuditRecord struct {
	// AuditID is research/21 §5's `scan_id`, spelled the record contract's
	// way: `anvil/auditId`, `scan_run.audit_id`. Assigned once at scan start.
	AuditID string

	// Version is `anvil/version` / `audit_record.audit_version`, the
	// monotonic integer research/21 §5 requires. It starts at 1 (the
	// schema's ck_audit_record_audit_version_positive requires >= 1) and is
	// bumped by the three watermarks WatermarkPolicy documents. Every bump
	// obliges plan/00-SPINE.md S6's queue re-cut (R.11), "otherwise
	// incremental publication silently inverts the priority scheme".
	Version int

	// State is `anvil/state`: R.1's frozen six-value enum, as derived by
	// record.DeriveState and advanced by record.Sealer. Never assigned here.
	State record.State

	// Sast and Dast are the two independently-sealed halves.
	Sast HalfRecord
	Dast HalfRecord

	// DastStatus is `anvil/dastStatus`, derived by record.DeriveDastStatus
	// from the DAST half's status and the target's provenance. Never null:
	// `audit_record.dast_status` is NOT NULL and the enum has no value
	// meaning "unknown".
	DastStatus record.DastStatus

	// Deadlines carries both scan-scoped clocks, fixed once at scan start by
	// DeadlinePolicy.At. Deadlines.StartedAt() is `scan_run.started_at` — the
	// instant research/21 §5 called `created_at`; see this file's header for
	// why there is no second copy under that name.
	//
	// It is a DIAGNOSTIC COPY. Deadlines has no exported field so nothing can
	// move an instant on it, and nothing reads this copy to decide anything:
	// scheduling reads the Controller's own copy and both due-checks are the
	// Sealer's. Assigning a whole different Deadlines here therefore changes
	// what a caller sees and nothing else, which is what CRITIQUE O.4 blocker 2
	// asked for.
	Deadlines Deadlines

	// Correlation is research/21 §5's `correlation { ... }`, "populated as
	// both sides land". Produced by R.12's correlator and delivered by
	// EventKindCorrelate; nothing here computes a cluster.
	//
	// Each EventKindCorrelate REPLACES this whole slice — see CorrelateEvent.
	Correlation []record.Correlation

	// ConsumedAt is `audit_record.consumed_at`, stamped when
	// record.Sealer.Consume accepts. Nil until then. Re-consuming does not
	// move it: the consumer is re-entrant and the first take is the one the
	// audit trail records.
	ConsumedAt *time.Time

	// PublishedAt is the instant of the most recent version bump, and the
	// anchor watermark (b)'s M is measured from. Set to Deadlines.StartedAt()
	// at Begin, because version 1 is itself a publication.
	PublishedAt time.Time

	// PendingDastFindings is how many DAST findings have arrived since the
	// last publication — watermark (b)'s N counter. Reset to zero by every
	// bump, whichever watermark caused it.
	PendingDastFindings int
}

// THERE IS NO AuditRecord.HalfSeal, AuditRecord.Readable OR AuditRecord.Findings.
//
// There were, and CRITIQUE O.4 blocker 1 is what they cost. `HalfSeal` built the
// record.HalfSeal the gate takes out of TWO FIELDS OF THE CALLER'S OWN VALUE —
// `Status` from the record's half and `AuditState` from the record's `State` —
// and `Findings` then handed that to record.HalfReadGate. The gate was called
// and neither arm was reimplemented, which is what made the mistake so hard to
// see: what was wrong was not the predicate but the SUBJECT. The value stopped
// tracking the Sealer the moment the caller stopped calling Transition, and
// there was no refresh path at all. The critic's probe P3 read one finding out
// of an EXPIRED audit through a record taken before the expiry, with
// `Readable()` answering true, while record.Sealer.ReadHalf on the same audit
// refused.
//
// Two things changed, and BOTH are necessary:
//
//  1. internal/record made a hand-built seal unusable. record.HalfSeal now
//     carries unexported provenance, so a seal no producer minted is refused
//     with record.ErrSealNotFromProducer, and a genuinely-minted seal held
//     across a state change is refused as stale. A composite literal in this
//     package cannot set an unexported field — that is a compile error, not a
//     lint — so the old HalfSeal method could not have survived even if it had
//     been kept.
//  2. This package stopped asking the question from a snapshot. The result
//     surface is Controller.Findings / Controller.Readable, which re-Inspect
//     the audit and route through record.Sealer.ReadHalf: the seal is minted by
//     the producer, checked against the live audit, and gated, all inside
//     internal/record. There is nothing left here for a caller's stale value to
//     be substituted into.
//
// What remains on AuditRecord is HalfRecord.FindingCount, which is metadata and
// is documented as ungated for a reason that has not changed.

// copyTime defensively copies an optional instant, so two AuditRecords never
// share a *time.Time. record.copyTime does the same for the same reason; this
// package cannot call it, because it is unexported there.
func copyTime(t *time.Time) *time.Time {
	if t == nil {
		return nil
	}
	c := *t
	return &c
}

// ---------------------------------------------------------------------------
// Publication diffs — what a caller does BETWEEN two records
// ---------------------------------------------------------------------------

// VersionBumped reports whether the transition from before to after published
// a new version, and therefore whether plan/00-SPINE.md S6's queue re-cut is
// owed: "re-cut the work queue on every version bump and reserve a
// configurable fraction (default 50%) of remaining budget for late
// DAST-confirmed arrivals". The reservation fraction is R.11's; the trigger is
// this.
func VersionBumped(before, after AuditRecord) bool { return after.Version > before.Version }

// DurableWriteDue reports whether this transition is the ONE at which the
// audit should be written to the store.
//
// O.2's forbidden actions: "Do not write the DB record more than once (only at
// final seal — the buffer carries incremental versions)." research/21 §5 says
// the same from the other side: "The DB write happens once, at seal, with the
// final version — the buffer carries the incremental versions, the knowledge
// base carries the settled one. This keeps regression checking querying stable
// rows."
//
// So this is true exactly on the transition INTO a settled state and false
// forever after, which makes at most one write per audit:
//
//	collecting/sast_sealed/dast_sealed -> both_sealed   true  (the seal)
//	collecting/sast_sealed/dast_sealed -> expired       true  (see below)
//	both_sealed -> consumed                             false (already written)
//	both_sealed -> expired                              false (already written)
//	anything -> itself                                  false
//
// WHY EXPIRY ALSO SETTLES. An audit whose claim window closes before both
// halves sealed never reaches record.StateBothSealed, and a rule keyed only on
// that state would leave it with no row at all. plan/40-record-and-storage.md
// is explicit that the reaper "drops the payload and never the row", which
// presupposes a row exists; record.StateExpired is a legal
// `ck_audit_record_state` value for the same reason. This is one write or the
// other, never both, because the two settled states are reached by disjoint
// paths and a settled record never becomes unsettled.
func DurableWriteDue(before, after AuditRecord) bool {
	return !settled(before.State) && settled(after.State)
}

// settled reports whether a state means the audit's durable row is final.
//
// THIS IS A DURABILITY PREDICATE, NOT A READ GATE, and the distinction
// matters because it compares an anvil/state against record.StateExpired,
// which is one arm of the read gate and which internal/record's own source
// guard (TestReadGateArmsAppearOnlyInsideTheGate) exists to keep out of
// readability decisions — and which this package now has its own guard for,
// TestReadGateArmsAreNotReDerivedInThisPackage, whose allowlist names this
// function and acceptsWrites and nothing else. Nothing here decides whether
// anything may be READ: record.Sealer.ReadHalf answers that, Controller.Findings
// is its only caller in this package, and neither consults this function. What
// this answers is "has the store writer's one chance arrived", which record has
// no opinion about because it holds no database handle.
//
// record.StateConsumed is listed for totality. It is unreachable without
// passing through record.StateBothSealed (record.Sealer.Consume refuses every
// other state with record.ErrNotBothSealed), so it never produces a write of
// its own.
func settled(s record.State) bool {
	return s == record.StateBothSealed || s == record.StateConsumed || s == record.StateExpired
}

// acceptsWrites reports whether an audit in state s still accepts new
// findings.
//
// It is this package's mirror of the guard record.Sealer.SealHalf and
// record.Sealer.RecordDastOutcome apply before every mutation ("audit is no
// longer accepting seals", record.ErrAuditTerminal). It exists because
// EventKindFindings buffers in THIS package and so reaches no Sealer entry
// point that could refuse it — without this, findings would keep piling onto
// an expired audit that record has already given up on.
//
// TestAcceptsWritesAgreesWithTheSealer drives a Sealer into all six states and
// asserts this function's answer matches whether SealHalf returns
// record.ErrAuditTerminal, so the mirror cannot drift from the original.
//
// THE MIRROR WAS NEVER THE PROBLEM; THE INPUT WAS. CRITIQUE O.4 finding O4-M2:
// this function was called with the CALLER's `rec.State`, so an audit record had
// already expired kept accepting findings — the exact outcome the paragraph
// above says this exists to prevent. Its callers now pass the state projected
// from a record.AuditSeal taken under the controller's lock.
func acceptsWrites(s record.State) bool {
	return !(s == record.StateConsumed || s == record.StateExpired)
}

// ---------------------------------------------------------------------------
// Controller
// ---------------------------------------------------------------------------

// auditState is the mutable per-audit state THIS package owns: everything in
// research/21 §5's record shape that record.Sealer does not carry.
//
// It lives on the Controller, behind Controller.mu, and NOT on the AuditRecord
// value callers hold. See the file header for why; the short version is that
// eight workers fanning findings into one audit through caller-owned buffers
// lost seven eighths of them.
type auditState struct {
	version     int
	sast        []record.Result
	dast        []record.Result
	correlation []record.Correlation
	consumedAt  *time.Time
	publishedAt time.Time
	pendingDast int

	// deadlines is the controller's own copy of the two scan-scoped instants,
	// fixed once by DeadlinePolicy.At at Begin. Scheduling reads THIS, never
	// the copy on a caller's AuditRecord, so a caller cannot move its own wake
	// schedule by handing back an edited snapshot. Neither copy decides
	// anything; both due-checks are the Sealer's.
	deadlines Deadlines
}

// clone is the working copy Transition mutates. Committing it is one
// assignment at the very end of Transition, AFTER every path that can return an
// error — which is what makes "a refused transition changes nothing" total
// rather than nearly total (CRITIQUE O.4 finding O4-m1: applyTick used to seal
// the DAST half, bump the version and only then hit an error return, losing the
// bump and leaving the caller's record permanently disagreeing with the Sealer).
func (s *auditState) clone() auditState {
	out := *s
	out.sast = append([]record.Result(nil), s.sast...)
	out.dast = append([]record.Result(nil), s.dast...)
	out.correlation = append([]record.Correlation(nil), s.correlation...)
	out.consumedAt = copyTime(s.consumedAt)
	return out
}

// Controller is `anvil-scanctl`'s state machine owner: plan/00-SPINE.md S10's
// "one named scan controller with one state machine and one owner, or it will
// be re-implemented inconsistently in four places."
//
// It holds ONE record.Sealer, and that Sealer is the state machine. The
// Controller supplies the three things the Sealer deliberately does not have:
// the configured clocks (deadlines.go), the publication watermarks, and the
// per-audit buffers research/21 §5 puts on the record.
//
// # CONCURRENCY, STATED AS WHAT IT ACTUALLY DOES
//
// It is safe for concurrent use, including fan-in from several workers on ONE
// audit, and this is a guarantee rather than an instruction to the caller.
// `mu` guards the audit map, every `auditState` in it and the clock; the Sealer
// holds its own mutex under that. Transition takes `mu` for the whole event,
// applies it to a working copy and commits with one assignment, so:
//
//   - two goroutines handing in the SAME stale AuditRecord both land their
//     findings; neither overwrites the other, and the version counter counts
//     every publication rather than the last writer's;
//   - a refused transition leaves the controller byte-identical;
//   - SetClock is safe against a concurrent Transition, which it was not
//     (O4-m4: it wrote `c.now` with no lock while four readers read it).
//
// The previous doc said "the failure mode is a skipped version bump, not a
// corrupt lifecycle" and told callers to serialise per audit. The lifecycle
// claim was true — the Sealer's mutex saw to that — but the findings claim was
// not, and the critic measured 21 of 24 findings lost through exactly the shape
// the doc described as safe. Serialising per audit would not have been enough
// either: the loss came from two goroutines cloning one caller-owned value, so
// it survives any amount of external serialisation as long as both hold their
// own copy. TestConcurrentFanInLosesNoFindings is the live probe, and CI runs it
// under -race on Linux (this repository already has one concurrency bug that
// only -race on CI caught: internal/handoff/reaper.go:415).
//
// LOCK ORDER is Controller.mu then record.Sealer.mu, on every path. The Sealer
// never calls back into this package, so there is no second order to conflict
// with.
type Controller struct {
	policy DeadlinePolicy  // resolved, immutable after NewController
	marks  WatermarkPolicy // resolved, immutable after NewController
	sealer *record.Sealer

	mu     sync.Mutex
	now    func() time.Time
	audits map[string]*auditState
}

// NewController resolves both policies and returns a Controller over a fresh
// record.Sealer.
//
// The watermark interval's default is derived from THIS policy's DAST budget —
// the resolved DAST deadline when the installation has a DAST half, and half
// the claim window otherwise (see DefaultWatermarkInterval).
func NewController(policy DeadlinePolicy, marks WatermarkPolicy) (*Controller, error) {
	resolvedPolicy, err := policy.Resolve()
	if err != nil {
		return nil, err
	}

	budget, ok := resolvedPolicy.DastDeadline()
	if !ok {
		// No DAST half, so no DAST deadline. Half the claim window is the
		// same quantity DefaultDastDeadlineSeconds would have produced had
		// the tier been installed, which keeps M stable across an
		// `anvil-dast` install that accepts the default.
		budget = resolvedPolicy.ClaimTimeout() / 2
	}
	resolvedMarks, err := marks.Resolve(budget)
	if err != nil {
		return nil, err
	}

	return &Controller{
		policy: resolvedPolicy,
		marks:  resolvedMarks,
		sealer: record.NewSealer(),
		now:    time.Now,
		audits: make(map[string]*auditState),
	}, nil
}

// SetClock replaces the clock used for `anvil/sealedAt`, for the DAST deadline
// due-check, for `consumed_at`, and for the publication watermarks. Passing
// nil restores time.Now.
//
// ONE CLOCK, not two: it is pushed into the Sealer as well, so a test that
// advances time cannot end up with a Sealer stamping wall-clock seals onto a
// record whose watermarks are running on a fake clock. Neither clock affects
// Deadlines, which are a function of scan start alone.
//
// IT TAKES THE MUTEX, for the same reason record.Sealer.SetClock takes its own
// (O4-m4). Construction-time use was always safe; a daemon that re-clocks at
// runtime raced four readers — Transition, applyTick, publish and NextWake —
// and the race detector cannot run on the Windows dev host, so only CI would
// ever have seen it.
func (c *Controller) SetClock(now func() time.Time) {
	if now == nil {
		now = time.Now
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = now
	// Under c.mu, so the documented lock order (Controller.mu then Sealer.mu)
	// holds here as it does on every other path, and so a Transition in flight
	// cannot observe the controller and the Sealer on two different clocks.
	c.sealer.SetClock(now)
}

// Policy and Watermarks return the resolved configuration, for diagnostics and
// for O.3's adapter.
func (c *Controller) Policy() DeadlinePolicy      { return c.policy }
func (c *Controller) Watermarks() WatermarkPolicy { return c.marks }

// Sealer exposes the ONE record.Sealer this controller owns.
//
// It is exported so that internal/scanctl/handoff.go (O.3) can ask
// record.Sealer.ReadyForConsumption which halves a `handoff` row's
// consumption class may key on, WITHOUT constructing a second Sealer. Two
// Sealers over one audit would be two answers to the read gate, which is the
// defect class internal/record/sealing.go's header is written about.
func (c *Controller) Sealer() *record.Sealer { return c.sealer }

// Begin registers an audit and returns its version-1 record.
//
// It calls record.Sealer.BeginAudit, which computes `deadline_at` once via
// record.ComputeDeadline and — when DAST is disabled — immediately and
// terminally seals the DAST half as record.HalfStatusSkipped /
// record.DastStatusNotRun, so a core-`anvil` install starts in
// record.StateDastSealed and reaches record.StateBothSealed the moment its
// SAST half seals. Nothing in this file re-derives that.
func (c *Controller) Begin(auditID string, startedAt time.Time) (AuditRecord, error) {
	cfg, err := c.policy.AuditConfig(auditID, startedAt)
	if err != nil {
		return AuditRecord{}, err
	}
	deadlines, err := c.policy.At(startedAt)
	if err != nil {
		return AuditRecord{}, err
	}
	c.mu.Lock()
	defer c.mu.Unlock()

	seal, err := c.sealer.BeginAudit(cfg)
	if err != nil {
		return AuditRecord{}, err
	}

	st := &auditState{
		version:     1, // ck_audit_record_audit_version_positive: >= 1
		publishedAt: startedAt,
		deadlines:   deadlines,
	}
	c.audits[auditID] = st
	return c.snapshotLocked(auditID, st, seal), nil
}

// Record re-projects an audit the controller already knows: the CURRENT
// lifecycle from record.Sealer, the current buffers and version from here.
//
// It is the refresh path, and its absence is half of CRITIQUE O.4 blocker 1.
// The Controller exposed Policy, Watermarks, Sealer, Begin, Transition and
// NextWake, and nothing that would re-project a record a caller was already
// holding — so a caller that wanted a current answer had no way to ask for one
// except to invent an event. A daemon that wakes, reads and decides should call
// this rather than trust the last AuditRecord it happens to have.
//
// ok is false for an audit this controller never began or has forgotten.
func (c *Controller) Record(auditID string) (AuditRecord, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	st, known := c.audits[auditID]
	if !known {
		return AuditRecord{}, false
	}
	seal, sealed := c.sealer.Inspect(auditID)
	if !sealed {
		return AuditRecord{}, false
	}
	return c.snapshotLocked(auditID, st, seal), true
}

// Transition applies one event and returns the resulting record. The input is
// never mutated.
//
// ON REFUSAL it returns the INPUT RECORD UNCHANGED alongside the error, not a
// zero record. The idiom this package expects is `rec, err = ctl.Transition(rec,
// ev)`, and handing back a zero AuditRecord there would turn a refused
// transition into a destroyed one — a caller that mishandles the error would
// lose the audit id, the deadlines and every buffered finding. A refused
// transition changes nothing, in the Sealer or in the returned value.
//
// Every lifecycle field on the result is re-read from record.Sealer after the
// event is applied. Version, findings, correlation and the watermark
// bookkeeping are this package's; State, the per-half statuses and
// `sealedAt`s, and DastStatus are record's.
//
// # ONLY rec.AuditID IS READ FROM rec
//
// Not its state, not its buffers, not its version, not its deadlines. Those all
// live on the Controller and are re-read here under the lock, which is what
// makes concurrent fan-in lossless and what stops a stale snapshot from
// answering a guard. Handing in a record from ten minutes ago applies the event
// to the audit as it stands NOW, and returns the audit as it stands after.
func (c *Controller) Transition(rec AuditRecord, ev Event) (AuditRecord, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	st, known := c.audits[rec.AuditID]
	before, sealed := c.sealer.Inspect(rec.AuditID)
	if !known || !sealed {
		return rec, &TransitionError{
			Kind: ev.Kind, AuditID: rec.AuditID, State: rec.State,
			Reason: "no such audit in this controller; call Begin first",
			Err:    record.ErrUnknownAudit,
		}
	}

	// THE LIVE PROJECTION, taken BEFORE the switch. Every guard below reads its
	// State and its per-half statuses from this value and never from `rec`.
	// CRITIQUE O.4 finding O4-M2: applyFindings and applyCorrelation guarded on
	// the caller's `rec.State`, so findings and correlation landed on an audit
	// record had already expired — with acceptsWrites' own doc naming that as
	// the thing it existed to prevent.
	live := c.snapshotLocked(rec.AuditID, st, before)

	// The working copy. Committed at the bottom, after every error return.
	w := st.clone()

	switch ev.Kind {
	case EventKindFindings:
		if err := c.applyFindings(&w, live, ev); err != nil {
			return rec, err
		}
	case EventKindDastOutcome:
		if err := c.sealer.RecordDastOutcome(rec.AuditID, ev.Outcome); err != nil {
			return rec, err
		}
	case EventKindSealHalf:
		if err := c.sealer.SealHalf(rec.AuditID, ev.Half, ev.Status); err != nil {
			return rec, err
		}
		// Watermarks (a) and (c): a half reached a terminal status, so the
		// record changed materially and the queue must be re-cut.
		//
		// ONLY IF IT ACTUALLY CHANGED. record.Sealer.SealHalf is documented
		// idempotent — "Re-sealing a half with the IDENTICAL status is a no-op
		// and preserves the original SealedAt" — and returns nil for that case,
		// which this code could not previously tell from a real seal. CRITIQUE
		// O.4 finding O4-M1: a redelivered seal event bumped `audit_version`,
		// and a bump is not cosmetic. It obliges S6's queue re-cut (R.11) and
		// internal/handoff re-checks `audit_record.audit_version` on EVERY
		// mutation (claim.go:641), answering handoff.ErrRecordVersionChanged —
		// so one duplicated worker message, the ordinary consequence of
		// at-least-once delivery, invalidated every in-flight lease on the
		// audit for a transition that changed nothing.
		after, stillSealed := c.sealer.Inspect(rec.AuditID)
		if stillSealed && sealChanged(before, after) {
			c.publish(&w)
		}
	case EventKindTick:
		if err := c.applyTick(rec.AuditID, &w); err != nil {
			return rec, err
		}
	case EventKindCorrelate:
		if err := c.applyCorrelation(&w, live, ev); err != nil {
			return rec, err
		}
	case EventKindConsume:
		if err := c.sealer.Consume(rec.AuditID); err != nil {
			return rec, err
		}
		if w.consumedAt == nil {
			// Re-entrant: the first take is the one recorded.
			t := c.now().UTC()
			w.consumedAt = &t
		}
	default:
		return rec, &TransitionError{
			Kind: ev.Kind, AuditID: rec.AuditID, State: rec.State,
			Reason: fmt.Sprintf("legal kinds are %v", EventKindValues()),
			Err:    ErrUnknownEvent,
		}
	}

	seal, known := c.sealer.Inspect(rec.AuditID)
	if !known {
		// Unreachable: nothing in this function forgets an audit, and the
		// same lookup succeeded above under the same lock. Reported rather than
		// ignored, because silently returning an unprojected record would hand
		// the caller a lifecycle this package invented. The working copy is
		// discarded, which is the same treatment every other refusal gets.
		return rec, &TransitionError{
			Kind: ev.Kind, AuditID: rec.AuditID, State: rec.State,
			Reason: "the audit vanished from the sealer mid-transition",
			Err:    record.ErrUnknownAudit,
		}
	}

	// THE COMMIT. One assignment, after every error return in this function, so
	// "A refused transition changes nothing, in the Sealer or in the returned
	// value" is total for this package's own state rather than nearly total.
	*st = w
	return c.snapshotLocked(rec.AuditID, st, seal), nil
}

// sealChanged reports whether two record.AuditSeal snapshots of one audit
// describe different lifecycles — i.e. whether the Sealer call between them did
// anything.
//
// It compares field by field rather than with ==, and that is not stylistic:
// record.HalfSeal carries an unexported provenance pointer that is freshly
// allocated on every mint, so `before.Sast == after.Sast` is false for two
// snapshots of an audit that did not move. Comparing the whole struct would
// have made the O4-M1 fix silently no-op.
func sealChanged(before, after record.AuditSeal) bool {
	return before.State != after.State ||
		before.DastStatus != after.DastStatus ||
		halfSealChanged(before.Sast, after.Sast) ||
		halfSealChanged(before.Dast, after.Dast)
}

func halfSealChanged(before, after record.HalfSeal) bool {
	if before.Status != after.Status {
		return true
	}
	switch {
	case before.SealedAt == nil && after.SealedAt == nil:
		return false
	case before.SealedAt == nil || after.SealedAt == nil:
		return true
	default:
		return !before.SealedAt.Equal(*after.SealedAt)
	}
}

// applyFindings buffers findings on one half and applies watermark (b)'s count
// arm. It reaches no Sealer entry point, so it carries both refusals itself.
//
// EVERY GUARD READS `live`, WHICH IS THE SEALER'S ANSWER, and never the caller's
// snapshot. `live` was projected from a record.AuditSeal taken moments earlier
// under the same lock. That is finding O4-M2's fix: the mirror (acceptsWrites)
// was always faithful — TestAcceptsWritesAgreesWithTheSealer proves it against
// record.ErrAuditTerminal — and the INPUT was not.
func (c *Controller) applyFindings(w *auditState, live AuditRecord, ev Event) error {
	if err := record.ValidateHalf(string(ev.Half)); err != nil {
		return &TransitionError{
			Kind: ev.Kind, AuditID: live.AuditID, Half: ev.Half, State: live.State,
			Reason: "illegal anvil/half: " + err.Error(), Err: err,
		}
	}
	if len(ev.Findings) == 0 {
		return &TransitionError{
			Kind: ev.Kind, AuditID: live.AuditID, Half: ev.Half, State: live.State,
			Reason: "no findings; a transition that changes nothing is a silent no-op",
			Err:    ErrEmptyEvent,
		}
	}
	if !acceptsWrites(live.State) {
		return &TransitionError{
			Kind: ev.Kind, AuditID: live.AuditID, Half: ev.Half, State: live.State,
			Reason: "the audit is consumed or expired and accepts no further findings",
			Err:    record.ErrAuditTerminal,
		}
	}

	status, buffer := live.Sast.Status, &w.sast
	if ev.Half == record.HalfDast {
		status, buffer = live.Dast.Status, &w.dast
	}
	if record.IsTerminalHalfStatus(status) {
		return &TransitionError{
			Kind: ev.Kind, AuditID: live.AuditID, Half: ev.Half, State: live.State,
			Reason: fmt.Sprintf("the half is %q; its results are frozen", status),
			Err:    ErrHalfNotAccepting,
		}
	}

	*buffer = append(*buffer, ev.Findings...)

	if ev.Half == record.HalfDast {
		w.pendingDast += len(ev.Findings)
		if w.pendingDast >= c.marks.DastFindings {
			c.publish(w) // watermark (b), count arm
		}
	}
	// The SAST half does not have a count watermark. research/21 §5 scopes
	// (b) to DAST findings, and reason 2 says why: "DAST's tail is the
	// enemy... over three orders of magnitude of duration variance." A SAST
	// half is a bounded batch that publishes once, at its seal, under (a).
	return nil
}

// applyTick drives clock 3, then clock 2, then this package's own watermark
// bookkeeping. The order of the two CLOCKS is load-bearing; the bookkeeping is
// last for a different reason.
//
//	Clock 3 FIRST, because record.Sealer refuses a seal on an audit that has
//	already reached record.StateExpired. Expiring first would mean a DAST half
//	whose deadline and whose claim window fell on the same wake never records
//	that it timed out, and `anvil/dastStatus` would keep the value it held
//	while running.
//
//	NEITHER DUE-CHECK IS THIS PACKAGE'S. Clock 2's is
//	record.Sealer.ExpireIfDue; clock 3's is record.Sealer.SealDastIfDeadlineDue,
//	which internal/record added for exactly this reason. Both compare against
//	the audit's own `startedAt` plus the offsets record.Sealer.BeginAudit fixed,
//	so neither can be moved by anything a caller holds. CRITIQUE O.4 blocker 2:
//	this function used to read clock 3 out of `AuditRecord.Deadlines`, an
//	exported field on the caller's value, and probe P10 moved the DAST deadline
//	by assigning to it — the forced seal never fired and the half stayed
//	`running` past its budget.
//
//	THE BOOKKEEPING RUNS AFTER EVERY ERROR RETURN. Finding O4-m1: the old
//	order sealed the DAST half, bumped the version, and only then called a
//	function that could return an error — on which path the bump was discarded
//	while the Sealer kept the seal. Publication is pure local arithmetic and
//	neither clock's outcome depends on it, so moving it below both calls costs
//	nothing and makes Transition's "a refused transition changes nothing"
//	honest.
//
// A tick is IDEMPOTENT and a tick on a settled audit is not an error. Daemons
// wake on a schedule; making a routine wake fail would mean every expired
// audit logs an error forever. Both Sealer calls return (false, nil) — not an
// error — for every ordinary reason to do nothing.
func (c *Controller) applyTick(auditID string, w *auditState) error {
	// Clock 3 — the DAST deadline. record.Sealer.SealDastIfDeadlineDue both
	// decides and seals, so there is no window in which this package has been
	// told "due" and has not yet acted, and no second opinion about what "due"
	// means. It seals with record.HalfStatusTimedOut and lets
	// record.DeriveDastStatus decide the audit-level `anvil/dastStatus` from
	// that plus the target's provenance.
	dastTimedOut, err := c.sealer.SealDastIfDeadlineDue(auditID)
	if err != nil {
		return err
	}

	// Clock 2 — the claim timeout.
	if _, err := c.sealer.ExpireIfDue(auditID); err != nil {
		return err
	}

	switch {
	case dastTimedOut:
		// Watermark (c): a half reached a terminal status.
		c.publish(w)
	case w.pendingDast > 0 && !c.now().Before(w.publishedAt.Add(c.marks.Interval)):
		// Watermark (b), time arm: M elapsed with DAST findings still
		// unpublished. Mutually exclusive with the clause above, because that
		// one zeroes the pending counter.
		c.publish(w)
	}
	return nil
}

// applyCorrelation stores R.12's clusters. It is not a watermark.
//
// # A BATCH REPLACES; IT DOES NOT ACCUMULATE
//
// This is the contract, stated because CRITIQUE O.4 finding O4-m3 observed that
// nothing stated it. research/21 §5 describes correlation as "populated as both
// sides land", which reads incremental, and this function assigns rather than
// appends — so a correlator emitting a SAST-side batch and then a DAST-side
// batch would lose the first.
//
// The contract is REPLACEMENT, and the reason is that the alternative cannot be
// made correct here. A cluster is a statement about which SAST and DAST findings
// are the same issue; appending two batches would produce duplicate cluster ids
// and no rule for reconciling a cluster whose membership grew, and this package
// has no correlation vocabulary with which to write that rule (R.12 owns it).
// Replacement makes the correlator's own latest answer the answer, which is a
// contract it can honour by emitting the complete set each time — and one whose
// violation is visible (clusters disappear) rather than silent (clusters
// duplicate).
//
// CorrelateEvent's doc states the same thing from the caller's side.
// TestACorrelationBatchReplacesTheWholeSet is the regression.
func (c *Controller) applyCorrelation(w *auditState, live AuditRecord, ev Event) error {
	if len(ev.Correlation) == 0 {
		return &TransitionError{
			Kind: ev.Kind, AuditID: live.AuditID, State: live.State,
			Reason: "no clusters; a transition that changes nothing is a silent no-op",
			Err:    ErrEmptyEvent,
		}
	}
	// The Sealer's answer, not the caller's; see applyFindings (O4-M2).
	if !acceptsWrites(live.State) {
		return &TransitionError{
			Kind: ev.Kind, AuditID: live.AuditID, State: live.State,
			Reason: "the audit is consumed or expired and accepts no further correlation",
			Err:    record.ErrAuditTerminal,
		}
	}
	w.correlation = append([]record.Correlation(nil), ev.Correlation...)
	return nil
}

// publish is the ONE version bump. Every watermark routes through it, so the
// three bookkeeping fields can never disagree about whether a publication
// happened. It requires c.mu.
func (c *Controller) publish(w *auditState) {
	w.version++
	w.publishedAt = c.now().UTC()
	w.pendingDast = 0
}

// snapshotLocked projects (this package's state, record.Sealer's answer) onto
// the AuditRecord value callers hold. It requires c.mu.
//
// Every slice and every optional instant is COPIED, so nothing a caller does to
// a snapshot can reach the controller's state or another snapshot of it.
func (c *Controller) snapshotLocked(auditID string, st *auditState, seal record.AuditSeal) AuditRecord {
	rec := AuditRecord{
		AuditID:             auditID,
		Version:             st.version,
		Deadlines:           st.deadlines,
		Correlation:         append([]record.Correlation(nil), st.correlation...),
		ConsumedAt:          copyTime(st.consumedAt),
		PublishedAt:         st.publishedAt,
		PendingDastFindings: st.pendingDast,
	}
	rec.Sast.findings = append([]record.Result(nil), st.sast...)
	rec.Dast.findings = append([]record.Result(nil), st.dast...)
	return project(seal, rec)
}

// project overwrites every lifecycle field with record.Sealer's answer.
//
// It is the reason this file cannot drift from the frozen state machine: there
// is no code path on which State, a per-half Status or SealedAt, or DastStatus
// is assigned from anything but a record.AuditSeal.
func project(seal record.AuditSeal, out AuditRecord) AuditRecord {
	out.State = seal.State
	out.DastStatus = seal.DastStatus
	out.Sast.Half = record.HalfSast
	out.Sast.Status = seal.Sast.Status
	out.Sast.SealedAt = copyTime(seal.Sast.SealedAt)
	out.Dast.Half = record.HalfDast
	out.Dast.Status = seal.Dast.Status
	out.Dast.SealedAt = copyTime(seal.Dast.SealedAt)
	return out
}

// ---------------------------------------------------------------------------
// The result surface — CRITIQUE O.4 blocker 1
// ---------------------------------------------------------------------------

// Findings returns a copy of one half's `findings[]`, gated by the ONE read
// gate, over a seal MINTED BY ITS PRODUCER against the audit as it stands now.
//
// It is a Controller method and not an AuditRecord method, and that is the whole
// point. The gate's answer is only worth anything if the value it is asked about
// describes a real half of a real record NOW; the previous version assembled a
// record.HalfSeal from two fields of the caller's own snapshot, which meant the
// gate answered honestly about a record that had stopped existing. Probe P3 read
// findings out of an EXPIRED audit that way.
//
// The seal here comes from record.Sealer.ReadHalf, which is one of the two
// legitimate producers of seal provenance and applies record.HalfReadGate to
// what it mints. So both arms are the frozen package's, the subject is the live
// audit, and this package neither builds a seal nor re-derives a predicate.
// A refusal is record's own: it satisfies errors.Is(err, record.ErrHalfNotSealed)
// and names the arm that shut — a status that is not sealed, or an expired audit
// whose payload the reaper has dropped.
//
// The findings themselves come from the controller's buffer rather than from
// `rec`, so a caller holding an old snapshot gets the current results or a
// refusal, never a silently truncated read. `rec` supplies the audit id and
// nothing else.
//
// On refusal the returned slice is nil and carries nothing.
func (c *Controller) Findings(rec AuditRecord, half record.Half) ([]record.Result, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	st, err := c.readGateLocked(rec, half)
	if err != nil {
		return nil, err
	}
	src := st.sast
	if half == record.HalfDast {
		src = st.dast
	}
	out := make([]record.Result, len(src))
	copy(out, src)
	return out, nil
}

// Readable reports whether a consumer may read this half's results.
//
// It is Findings' own gate as a bool — literally the same function body — so a
// caller that branches and a caller that reports a typed refusal can never
// disagree. TestReadableAgreesWithFindingsEverywhere asserts that across every
// state and both halves.
func (c *Controller) Readable(rec AuditRecord, half record.Half) bool {
	c.mu.Lock()
	defer c.mu.Unlock()

	_, err := c.readGateLocked(rec, half)
	return err == nil
}

// readGateLocked is the one gate call, shared by Findings and Readable. It
// requires c.mu and returns the audit's state only when the gate is open.
func (c *Controller) readGateLocked(rec AuditRecord, half record.Half) (*auditState, error) {
	if err := record.ValidateHalf(string(half)); err != nil {
		return nil, &TransitionError{
			AuditID: rec.AuditID, Half: half, State: rec.State,
			Reason: "illegal anvil/half: " + err.Error(), Err: err,
		}
	}
	st, known := c.audits[rec.AuditID]
	if !known {
		return nil, &TransitionError{
			AuditID: rec.AuditID, Half: half, State: rec.State,
			Reason: "no such audit in this controller; call Begin first",
			Err:    record.ErrUnknownAudit,
		}
	}
	// THE GATE. Producer-minted seal, live audit, record's own predicate.
	if _, err := c.sealer.ReadHalf(rec.AuditID, half); err != nil {
		return nil, err
	}
	return st, nil
}

// NextWake returns the earliest instant at which this controller has something
// to do for rec, for a daemon timer to sleep until. ok is false when there is
// nothing left to wait for.
//
// It is Deadlines.NextWake — the two deadline instants — WIDENED by watermark
// (b)'s time arm, which Deadlines cannot know about because M is not a
// deadline. A daemon that slept only on Deadlines.NextWake would hold DAST
// findings unpublished for up to the whole DAST budget whenever fewer than N
// of them arrived, which is the staleness bound M exists to cap.
//
// IT IS A SCHEDULING ANSWER, NOT A DECISION, and deadlines.go's warning
// applies unchanged: a caller that infers "the returned instant is the DAST
// deadline, therefore the DAST half has not timed out" has substituted a
// scheduling hint for a due-check.
//
// It reads the CONTROLLER's deadlines and watermark bookkeeping, not `rec`'s.
// `rec` supplies the audit id. A caller cannot advance or delay its own wake by
// handing back an edited snapshot, and an unknown audit has nothing to wait for.
func (c *Controller) NextWake(rec AuditRecord) (time.Time, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	st, known := c.audits[rec.AuditID]
	if !known {
		return time.Time{}, false
	}

	now := c.now()
	next, found := st.deadlines.NextWake(now)

	if st.pendingDast > 0 {
		if at := st.publishedAt.Add(c.marks.Interval); at.After(now) {
			if !found || at.Before(next) {
				next, found = at, true
			}
		}
	}
	return next, found
}
