// The coding-agent claim path as the scan controller sees it (step O.3).
//
// # THIS FILE IS AN ADAPTER. IT OWNS NO TABLE, NO PROTOCOL AND NO STATE.
//
// plan/IMPLEMENTATION-PLAN.md §6 ruling G9 found the `handoff` table defined
// and created TWICE, in two migrations, with two Go APIs, and ruled:
//
//	"Area 40 owns the table and the claim/lease protocol. […] O.3 no longer
//	 writes a migration; internal/scanctl/handoff.go becomes a thin adapter
//	 over internal/handoff."
//
// So everything load-bearing lives elsewhere and is CALLED from here:
//
//	internal/store/schema.sql        the ONE `handoff` table definition,
//	                                 including O.3's `consumption_class`
//	                                 (static_only | requires_dynamic_confirmation),
//	                                 which survived the merge intact
//	internal/record/contract.go      the thirteen frozen handoff.state literals
//	handoff.Queue.AcquireLease       the grant
//	handoff.Queue.Claim              the grant, narrowed to one fingerprint
//	handoff.Queue.RenewLease         the heartbeat
//	handoff.Queue.ReleaseLease       the disposition
//	handoff.Queue.ReclaimExpired     the crash path (clock 1)
//	handoff.Queue.ExpireClaimTimeouts the claim-timeout sweep (clock 2, store side)
//	handoff.Queue.Reap               both sweeps, in the load-bearing order
//	handoff.Queue.Run                the sweep loop
//	handoff.Queue.ReadPacket         the gated result surface
//	handoff.CheckTransition          the state machine
//	handoff.ExhaustedState           "the attempt did not produce a validated fix"
//
// There is no SQL in this file, no second definition of the consumption gate,
// no second lease clock and no second reaper. CRITIQUE-02 then found a
// double-grant bug (F1) in the one implementation that does exist; a second
// implementation would not have been safer, it would have been a second place
// for that bug to hide.
//
// # WHAT THIS FILE ADDS, and it is only these three things
//
//  1. LeaseOptions / NewConsumer — the ONE number the scan controller owns
//     that internal/handoff cannot know: the relation between the lease and
//     the claim window. See "Two clocks" below.
//  2. Task — a handoff.Handle projected onto a value a coding agent may be
//     handed. It carries the lease privately, so a Task cannot be forged and
//     cannot be mistaken for a lease token, and it carries nothing that widens
//     scope: plan/00-SPINE.md S7 grants "may act on this finding" and never
//     merge authority, so there is no field here that could express one.
//  3. ConsumeOne — acquire, apply, dispose, exactly once per call, with the
//     failure disposition chosen the same way the reaper chooses it.
//
// # TWO CLOCKS, AND THE ONE RELATION BETWEEN THEM
//
// `buffer.lease` (research/08 §4: 15–30 minutes, heartbeat-renewed, "never 8
// hours") and `audit_record.claim_timeout_seconds` (deadlines.go clock 2, 8h
// by default) are different measurements with different owners. internal/handoff
// holds the first; deadlines.go holds the second. Neither can check the
// relation between them alone, and the relation is what makes the retry budget
// reachable:
//
//	lease < claim window
//
// If a lease is as long as the claim window, ONE attempt consumes the whole
// window. A consumer that is OOM-killed at minute two holds the finding until
// the window closes, ReclaimExpired never gets to requeue it inside the
// window, `max_attempts` is unreachable, and the finding is swept to
// 'expired' having been attempted once. The retry the schema pays a column
// for silently stops existing. NewConsumer refuses that configuration rather
// than letting it be discovered as a lost finding months later.
//
// # RE-ENTRANCY AND IDEMPOTENCE ARE NOT IMPLEMENTED HERE EITHER
//
// The packet requires "reclaiming an expired lease and re-processing must be
// idempotent, keyed by (finding fingerprint, record version)". That property
// is already produced by two mechanisms in internal/handoff, and this file's
// job is to not break them and to make the key impossible to ignore:
//
//   - The dead holder cannot land its work. Every mutation is a
//     compare-and-swap on the exact (state='leased', claimed_by,
//     lease_expires_at) triple, so an OOM-killed consumer that wakes up and
//     reports success after its successor took over affects zero rows and gets
//     handoff.ErrLeaseLost. Task carries that lease privately for precisely
//     this reason: a caller cannot route around the CAS by rebuilding a handle.
//   - The successor's work is recognisable as the SAME work. Task.IdempotencyKey
//     is sha256(anvil/auditId ‖ fingerprint ‖ base commit SHA) — stable across
//     crash and reclaim, and identical to the git trailer the coding agent
//     writes — so a duplicate side effect is detectable by whoever applies it.
//     ConsumeOne puts it in front of every applier.
//
// ConsumeOne deliberately does NOT retry internally. A retry inside one call
// would be a second attempt that `attempts` never counted, which is the one
// thing that could make the counter — and therefore the reaper's requeue rule
// — lie.
//
// # WHO DRIVES THE REAPER — clock 2 has two owners and they must run together
//
// CRITIQUE O.4 finding O4-M5: deadlines.go names two owners for clock 2's
// due-check — "record.Sealer.ExpireIfDue in memory, and
// handoff.Queue.ExpireClaimTimeouts against the store" — and O.2's tick drove
// the first while NOTHING IN THE TREE drove the second. Four comments named an
// owner with no call site anywhere. That is not a documentation gap; §6 ruling
// G10 catalogues the resulting divergence exactly: the controller marks an audit
// `expired` in memory while its `handoff` rows stay 'ready' and keep being
// leased, "so it is re-leased forever".
//
// This adapter is the only file in the tree that sees both clocks, so the wiring
// is here:
//
//	Consumer.ReclaimExpired  clock 1 only — lapsed leases, the crash path
//	Consumer.Reap            BOTH sweeps, leases first (handoff.Queue.Reap)
//	Consumer.Run             Reap on an interval until the context is cancelled
//
// A DAEMON MUST DRIVE Consumer.Run (or call Consumer.Reap on its own schedule).
// The in-memory half of clock 2 is driven by O.2's EventKindTick, on the
// schedule Controller.NextWake computes; the store half is driven here. Running
// only one of the two is the divergence above, and running the reaper's two
// sweeps out of order costs a crashed finding a whole extra interval — which is
// why Reap is delegated whole rather than re-composed from its two halves in
// this file.
//
// The interval is internal/handoff's business (handoff.DefaultReaperInterval,
// with research/08 §4's "must be <= ttl/8" written down at its definition), and
// this file does not acquire an opinion about it: Run passes it through.
//
// # WHY THERE IS NO READ GATE IN THIS FILE
//
// internal/record/sealing.go's header records FIVE authors re-deriving
// readability locally and all five getting an arm wrong. The defence is that
// there is exactly ONE predicate, record.HalfReadGate, and every other
// spelling is a thin wrapper over it. So this file adds no sixth spelling:
//
//   - It never returns a half's results directly. The one result surface it
//     exposes, Packet, delegates to handoff.Queue.ReadPacket, which R.7 gates
//     with packetGate — "a cache of the payload cannot be less protected than
//     the payload" (CRITIQUE-02 F5).
//   - The producer side, where a half's findings leave a record for the queue,
//     is Controller.Findings in statemachine.go, which routes through
//     record.Sealer.ReadHalf — the gate, over a seal that package minted. It is
//     not duplicated here.
//   - Whether a finding's consumption gate is open is decided by ONE SQL
//     expression in internal/handoff (consumptionGate), evaluated atomically
//     with the grant. A Go re-check here would be a second definition that
//     could disagree, and it could not be atomic with anything.
//
// (Free-floating file comment: deadlines.go carries the package doc.)

package scanctl

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/Susquehanna-Syntax/Anvil/internal/handoff"
	"github.com/Susquehanna-Syntax/Anvil/internal/record"
)

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

// The sentinels this file adds. There are only two, and both name a refusal
// internal/handoff has no opinion about because it cannot see a DeadlinePolicy.
// Every OTHER refusal a claim can produce is internal/handoff's own —
// handoff.ErrNoWork, handoff.ErrAlreadyClaimed, handoff.ErrNotEligible,
// handoff.ErrExhausted, handoff.ErrLeaseLost, handoff.ErrRecordVersionChanged,
// handoff.ErrNoDynamicEvidence, handoff.ErrIllegalTransition — and is returned
// UNWRAPPED, so a caller branching with errors.Is sees the owning package's
// answer rather than a re-spelling of it. A second refusal vocabulary over a
// frozen one is the same defect class as a second enum.
var (
	// ErrNoQueue: a Consumer was asked for without the handoff.Queue it
	// adapts. There is no fallback and there must not be one — constructing a
	// Queue here would be this file acquiring the protocol it exists not to
	// own.
	ErrNoQueue = errors.New("scanctl: a Consumer requires a *handoff.Queue")

	// ErrNoApplier: ConsumeOne was called with a nil Applier. It is refused
	// BEFORE any lease is taken, so a mistake cannot burn an attempt.
	ErrNoApplier = errors.New("scanctl: ConsumeOne requires a non-nil Applier")

	// ErrLeaseExceedsClaimWindow: `buffer.lease` is not shorter than
	// `audit_record.claim_timeout_seconds`, so one attempt consumes the whole
	// claim window and the retry budget is unreachable. See the file header.
	ErrLeaseExceedsClaimWindow = errors.New("scanctl: lease is not shorter than the claim window")

	// ErrNonPositiveLease: a lease of zero or less. handoff.Options treats
	// zero as "use handoff.DefaultLease", so a zero only reaches this check
	// after LeaseOptions has already had its chance to fill it in — at which
	// point it means the Queue was built with something else.
	ErrNonPositiveLease = errors.New("scanctl: lease must be positive")
)

// LeaseError reports a refused lease/claim-window relation, naming BOTH
// durations rather than merely the offence — the same shape as PolicyError and
// record.SealingError, for the same reason: an operator reading this needs to
// know which of the two numbers to change.
type LeaseError struct {
	Lease       time.Duration // buffer.lease, from handoff.Options
	ClaimWindow time.Duration // DeadlinePolicy.ClaimTimeout()
	Reason      string
	Err         error // ErrLeaseExceedsClaimWindow or ErrNonPositiveLease
}

func (e *LeaseError) Error() string {
	return fmt.Sprintf("scanctl: lease %s against a claim window of %s is invalid: %s",
		e.Lease, e.ClaimWindow, e.Reason)
}

// Unwrap exposes the sentinel to errors.Is.
func (e *LeaseError) Unwrap() error { return e.Err }

// ---------------------------------------------------------------------------
// The lease/claim-window relation
// ---------------------------------------------------------------------------

// CheckLease is THE relation between the two clocks, written once.
//
// It is exported because the check is needed at two moments that are not the
// same moment: LeaseOptions runs it before a Queue exists, and NewConsumer
// runs it against a Queue somebody else may have built. One function, two call
// sites — the same discipline internal/handoff applies to its consumption
// gate.
//
// The comparison is strict. A lease EQUAL to the claim window is refused for
// the same reason a longer one is: the second attempt would begin exactly as
// the window closes, which is not a retry.
func CheckLease(lease time.Duration, policy DeadlinePolicy) error {
	if lease <= 0 {
		return &LeaseError{
			Lease: lease, ClaimWindow: policy.ClaimTimeout(),
			Reason: "research/08 §4's buffer.lease is a positive duration; " +
				"zero means 'use handoff.DefaultLease' only at handoff.Options, not here",
			Err: ErrNonPositiveLease,
		}
	}
	window := policy.ClaimTimeout()
	if window <= 0 {
		// The policy itself is what is wrong. Report it in the policy's own
		// vocabulary rather than inventing a lease complaint about it.
		if _, err := policy.Resolve(); err != nil {
			return err
		}
		return &PolicyError{
			Field: "claimTimeoutSeconds", Value: fmt.Sprint(policy.ClaimTimeoutSeconds),
			Reason: "the claim window resolved to zero, so no lease can be shorter than it",
			Err:    ErrInvalidDeadlinePolicy,
		}
	}
	if lease >= window {
		return &LeaseError{
			Lease: lease, ClaimWindow: window,
			Reason: "one attempt would consume the whole claim window, so a crashed holder " +
				"could never be reclaimed and re-attempted inside it and handoff.max_attempts " +
				"would be unreachable",
			Err: ErrLeaseExceedsClaimWindow,
		}
	}
	return nil
}

// LeaseOptions validates a handoff.Options against this controller's
// DeadlinePolicy and returns it with `Lease` made concrete.
//
// It fills in handoff.DefaultLease for a zero Lease — research/08 §4's
// 20 minutes, NOT a number invented here — and then checks the relation. Every
// other field (Clock, PacketDir, MaxAttempts) is passed through untouched:
// this function has no opinion about them and must not acquire one, because
// they are handoff.Options' business and a default written twice is a default
// that will drift.
//
// The caller then builds the Queue itself, with handoff.New. This function
// deliberately does not, so that there is exactly one constructor for a Queue
// and it is the owning package's.
func LeaseOptions(policy DeadlinePolicy, base handoff.Options) (handoff.Options, error) {
	out := base
	if out.Lease == 0 {
		out.Lease = handoff.DefaultLease
	}
	if err := CheckLease(out.Lease, policy); err != nil {
		return handoff.Options{}, err
	}
	return out, nil
}

// ---------------------------------------------------------------------------
// Task — one lease, projected
// ---------------------------------------------------------------------------

// Task is one finding a worker holds the lease on, in the shape the coding
// agent's side of the boundary sees.
//
// It is handoff.Handle with the lease made unreachable. Every exported field
// here is a fact the applier needs; the lease itself is not one of them,
// because a value the applier can copy, store and replay is precisely the
// thing that must not be able to authorise a write. Release, Renew and Packet
// take a Task and unwrap the lease internally, so the compare-and-swap that
// stops an OOM-killed consumer's late write cannot be routed around.
//
// plan/00-SPINE.md S7: a lease grants "may act on this finding" and nothing
// more. There is deliberately no field here naming a branch, a pull request,
// a merge, or any other finding — a Task cannot express widened scope because
// it has nowhere to put it.
type Task struct {
	// Fingerprint is the anvil-fp/v1 digest, full 64 hex, never truncated.
	Fingerprint string

	// IdempotencyKey is sha256(anvil/auditId ‖ fingerprint ‖ base commit SHA),
	// computed by handoff.IdempotencyKey. It is STABLE ACROSS CRASH AND
	// RECLAIM: the consumer that picks the finding up after a dead holder gets
	// the same key the dead holder had, which is what makes a duplicate side
	// effect recognisable. It is the value the coding agent writes into its git
	// trailer, so the two sides of a crash can be matched up afterwards.
	IdempotencyKey string

	// RecordVersion is audit_record.audit_version at the moment the lease was
	// granted. With Fingerprint it is the (fingerprint, record version) key the
	// packet requires re-processing to be idempotent under. A bump re-cuts the
	// queue (plan/00-SPINE.md S6), and every mutation through this adapter
	// re-checks it, so work against a stale version is refused rather than
	// applied to a record that has moved.
	RecordVersion int64

	// ConsumptionClass is the gate the finding passed: static_only findings
	// waited on the SAST half, requires_dynamic_confirmation findings waited on
	// the DAST half (research/21 §5). It is the STORED value, authoritative
	// over any derivation.
	ConsumptionClass record.ConsumptionClass

	// DastStatus is the audit's DAST half status at claim time, carried so an
	// applier can see that the half ended with no dynamic evidence rather than
	// assume a clean dynamic scan. It is not advisory: releasing a
	// requires_dynamic_confirmation finding as 'validated' without it is
	// refused by internal/handoff with handoff.ErrNoDynamicEvidence.
	DastStatus record.DastStatus

	// WorkerID is the lease holder.
	WorkerID string

	// Attempt is this lease's ordinal — 1 for the first, 2 after one crash and
	// one reclaim — and MaxAttempts is the budget. Attempts are counted at
	// CLAIM time, because a consumer that is OOM-killed never gets to count
	// anything itself.
	Attempt     int
	MaxAttempts int

	// LeaseExpiresAt is when ReclaimExpired will presume this holder dead. It
	// is the lease clock, NOT audit_record.deadline_at; see the file header on
	// the two clocks.
	LeaseExpiresAt time.Time

	// PacketPath is where the regenerable tmpfs packet lives, or "" when no
	// PacketDir is configured. The packet is a cache: if it is missing,
	// regenerate it from the store (research/08 §1). Its absence is not an
	// error, and it is never the source of truth.
	PacketPath string

	// lease is the handoff.Handle this Task projects. Unexported so a Task
	// cannot be forged: only handoff.Queue.AcquireLease and .Claim mint one,
	// and only the methods on Consumer can spend it.
	lease handoff.Handle
}

// HandoffID is the `handoff` row this Task holds, for logs and for a caller
// that must correlate with internal/handoff's own reports.
func (t Task) HandoffID() int64 { return t.lease.HandoffID }

// Held reports whether this Task carries a lease at all. The zero Task does
// not, and every method that would spend one refuses it.
func (t Task) Held() bool { return t.lease.HandoffID != 0 && t.lease.WorkerID != "" }

// AttemptsRemaining is how many further leases the finding may be granted
// after this one ends. Zero means this attempt is the last.
func (t Task) AttemptsRemaining() int {
	if t.Attempt >= t.MaxAttempts {
		return 0
	}
	return t.MaxAttempts - t.Attempt
}

// taskOf projects a Handle. It is the only place a Task is built, so no field
// can be populated from anywhere but the lease that was actually granted.
func taskOf(h handoff.Handle) Task {
	return Task{
		Fingerprint:      h.Fingerprint,
		IdempotencyKey:   h.IdempotencyKey,
		RecordVersion:    h.RecordVersion,
		ConsumptionClass: h.ConsumptionClass,
		DastStatus:       h.DastStatus,
		WorkerID:         h.WorkerID,
		Attempt:          h.Attempt,
		MaxAttempts:      h.MaxAttempts,
		LeaseExpiresAt:   h.LeaseExpiresAt,
		PacketPath:       h.PacketPath,
		lease:            h,
	}
}

// errUnheld names the one mistake every Task-taking method has to refuse the
// same way: a zero or hand-built Task.
func errUnheld(op string) error {
	return fmt.Errorf("scanctl: %s requires a Task from AcquireLease or Claim: %w",
		op, handoff.ErrLeaseLost)
}

// ---------------------------------------------------------------------------
// Consumer
// ---------------------------------------------------------------------------

// Applier is the coding agent's side of one attempt. It receives the Task and
// returns the disposition to record.
//
// The returned state must be a legal successor of 'leased' — one of the
// eleven dispositions in the frozen thirteen-value handoff.state enum, or
// record.HandoffStateReady to hand the finding back for someone else. It is
// checked by handoff.CheckTransition before anything is written, so an
// out-of-order or out-of-vocabulary value never reaches the database.
//
// AN APPLIER MUST BE IDEMPOTENT IN Task.IdempotencyKey. It may be called for a
// key some earlier, dead attempt already applied — that is the crash path
// working as designed, not a defect — and the key is the only thing that makes
// the two calls recognisable as one unit of work.
type Applier func(ctx context.Context, t Task) (record.HandoffState, error)

// Outcome is what one ConsumeOne call did.
type Outcome struct {
	// Task is the lease that was granted. Its zero value means none was.
	Task Task

	// State is the disposition actually written, or "" when nothing was.
	State record.HandoffState

	// Applied reports whether the Applier ran to completion and chose State
	// itself. False means State is the fallback disposition — see
	// failureDisposition — or that nothing was written at all.
	Applied bool

	// ApplyErr is the Applier's own error, preserved so a caller can inspect
	// it with errors.As after ConsumeOne has already wrapped it.
	ApplyErr error
}

// Consumer is the scan controller's view of the claim path: a handoff.Queue
// plus the DeadlinePolicy whose claim window the lease must fit inside.
//
// It is safe for concurrent use because it holds no mutable state of its own;
// every mutation is one conditional UPDATE inside internal/handoff.
type Consumer struct {
	q      *handoff.Queue
	policy DeadlinePolicy
}

// NewConsumer adapts an existing handoff.Queue to a DeadlinePolicy.
//
// It re-runs CheckLease against the Queue's ACTUAL lease rather than trusting
// that LeaseOptions was used, because a Queue built directly with handoff.New
// is a perfectly ordinary thing to have and would otherwise skip the one check
// this file exists to make.
func NewConsumer(q *handoff.Queue, policy DeadlinePolicy) (*Consumer, error) {
	if q == nil {
		return nil, ErrNoQueue
	}
	resolved, err := policy.Resolve()
	if err != nil {
		return nil, err
	}
	if err := CheckLease(q.Lease(), resolved); err != nil {
		return nil, err
	}
	return &Consumer{q: q, policy: resolved}, nil
}

// Queue returns the adapted queue.
//
// It is exported because this file is an adapter and not a wall: enqueueing,
// disposal without a lease, the claim-timeout sweep and the state machine all
// live in internal/handoff and callers reach them THERE. Re-exporting each one
// through a method here would be the second API §6 G9 forbids, one delegation
// at a time.
func (c *Consumer) Queue() *handoff.Queue { return c.q }

// Policy returns the resolved DeadlinePolicy this Consumer was built against.
func (c *Consumer) Policy() DeadlinePolicy { return c.policy }

// Lease is the configured lease duration — handoff.Options.Lease, resolved.
func (c *Consumer) Lease() time.Duration { return c.q.Lease() }

// RenewInterval is how often a holder should heartbeat: one third of the
// lease.
//
// DERIVATION, not a magic number. research/08 §4 specifies a lease renewed by
// heartbeat but no interval. The constraint is that a heartbeat may be missed
// — a GC pause, a slow database, one lost scheduler quantum — without the
// lease lapsing under a holder that is demonstrably alive. At lease/3 two
// consecutive heartbeats can be missed and a third still lands before
// lease_expires_at. At lease/2 a single miss leaves no margin, and any
// interval below lease/3 buys margin only by spending writes on a queue whose
// whole design avoids per-finding write storms (research/21 §5).
//
// It is a floor of one heartbeat per lease: a lease shorter than 3ns is a test
// fixture, not a deployment, and returning zero there would be an infinite
// heartbeat loop.
func (c *Consumer) RenewInterval() time.Duration {
	if d := c.q.Lease() / 3; d > 0 {
		return d
	}
	return c.q.Lease()
}

// AcquireLease takes the lease on the oldest claimable finding and returns it
// as a Task. It is handoff.Queue.AcquireLease; the name is deliberately the
// same, because it is the same operation and a synonym would be the beginning
// of a second vocabulary.
//
// handoff.ErrNoWork means idle, not failure: nothing is ready, or nothing
// ready has passed its consumption gate. A requires_dynamic_confirmation
// finding whose DAST half has not reached a terminal state is exactly that
// case, and it is decided by internal/handoff's SQL gate, atomically with the
// grant — not by a check in this file.
func (c *Consumer) AcquireLease(workerID string) (Task, error) {
	return c.AcquireLeaseContext(context.Background(), workerID)
}

// AcquireLeaseContext is AcquireLease with a caller-supplied context.
func (c *Consumer) AcquireLeaseContext(ctx context.Context, workerID string) (Task, error) {
	h, err := c.q.AcquireLeaseContext(ctx, workerID)
	if err != nil {
		return Task{}, err
	}
	return taskOf(h), nil
}

// Claim takes the lease on one named finding: AcquireLease narrowed to a
// fingerprint. It is handoff.Queue.Claim.
//
// Exactly one concurrent caller wins; every loser gets
// handoff.ErrAlreadyClaimed.
func (c *Consumer) Claim(fingerprint, workerID string) (Task, error) {
	return c.ClaimContext(context.Background(), fingerprint, workerID)
}

// ClaimContext is Claim with a caller-supplied context.
func (c *Consumer) ClaimContext(ctx context.Context, fingerprint, workerID string) (Task, error) {
	h, err := c.q.ClaimContext(ctx, fingerprint, workerID)
	if err != nil {
		return Task{}, err
	}
	return taskOf(h), nil
}

// RenewLease is the heartbeat. It returns a FRESH Task; the old one is dead
// and must be discarded, exactly as with the handoff.Handle underneath.
//
// It refuses with handoff.ErrLeaseLost when the lease is no longer this
// worker's on this exact grant — the crash-and-reclaim case — and with
// handoff.ErrRecordVersionChanged when the audit version moved underneath.
func (c *Consumer) RenewLease(t Task) (Task, error) {
	return c.RenewLeaseContext(context.Background(), t)
}

// RenewLeaseContext is RenewLease with a caller-supplied context.
func (c *Consumer) RenewLeaseContext(ctx context.Context, t Task) (Task, error) {
	if !t.Held() {
		return Task{}, errUnheld("RenewLease")
	}
	h, err := c.q.RenewLeaseContext(ctx, t.lease)
	if err != nil {
		return Task{}, err
	}
	return taskOf(h), nil
}

// ReleaseLease ends one attempt and records its disposition.
//
// The transition is checked by handoff.CheckTransition; 'validated' on a
// requires_dynamic_confirmation finding additionally requires the DAST half to
// have produced a reproduction (handoff.ErrNoDynamicEvidence, plan/00-SPINE.md
// S7). Neither rule is restated here, because a restated rule is a rule with
// two versions.
func (c *Consumer) ReleaseLease(t Task, to record.HandoffState) error {
	return c.ReleaseLeaseContext(context.Background(), t, to)
}

// ReleaseLeaseContext is ReleaseLease with a caller-supplied context.
func (c *Consumer) ReleaseLeaseContext(ctx context.Context, t Task, to record.HandoffState) error {
	if !t.Held() {
		return errUnheld("ReleaseLease")
	}
	return c.q.ReleaseLeaseContext(ctx, t.lease, to)
}

// ReclaimExpired sweeps lapsed leases: the crash path. A holder that was
// OOM-killed loses its finding back to the ready set if an attempt remains,
// and to handoff.ExhaustedState if none does.
//
// It is handoff.Queue.ReclaimExpired and nothing else — there is no second
// reaper, no second expiry rule and no second exhaustion mapping in this
// package. The report is returned rather than logged because research/08 §4
// point 4 asks for the expiry rate to be alertable: "a nonzero expired rate is
// the load signal that the coding agent is undersized relative to detector
// throughput."
func (c *Consumer) ReclaimExpired() (handoff.ReapReport, error) {
	return c.q.ReclaimExpiredContext(context.Background())
}

// ReclaimExpiredContext is ReclaimExpired with a caller-supplied context.
func (c *Consumer) ReclaimExpiredContext(ctx context.Context) (handoff.ReapReport, error) {
	return c.q.ReclaimExpiredContext(ctx)
}

// ExpireClaimTimeouts sweeps findings whose audit's claim window has closed:
// clock 2, against the store.
//
// IT IS THE STORE-SIDE HALF OF A DUE-CHECK O.2 ALREADY DRIVES IN MEMORY. Prefer
// Reap, which runs it in the right order relative to the lease sweep; this
// exists so the two owners deadlines.go names are both REACHABLE from the one
// file that sees both clocks. Before CRITIQUE O.4 finding O4-M5 it was named in
// four comments here and called from nowhere in the tree.
func (c *Consumer) ExpireClaimTimeouts() (handoff.ReapReport, error) {
	return c.q.ExpireClaimTimeoutsContext(context.Background())
}

// ExpireClaimTimeoutsContext is ExpireClaimTimeouts with a caller-supplied
// context.
func (c *Consumer) ExpireClaimTimeoutsContext(ctx context.Context) (handoff.ReapReport, error) {
	return c.q.ExpireClaimTimeoutsContext(ctx)
}

// Reap runs BOTH sweeps — lapsed leases (clock 1) then closed claim windows
// (clock 2) — and is what a daemon should call if it is not calling Run.
//
// It is handoff.Queue.Reap, delegated whole rather than re-composed here, and
// the ORDER is why. reaper.go: "A finding whose holder crashed AND whose audit
// deadline has passed must first be reclaimed out of 'leased' — the lease sweep
// is the only thing allowed to touch a leased row — and only then can the
// claim-timeout sweep see it as 'ready' and expire it." Composing the two calls
// in this file would be a second copy of that ordering rule, in the file whose
// entire premise is that it holds no second copy of anything.
func (c *Consumer) Reap() (handoff.ReapReport, error) {
	return c.q.ReapContext(context.Background())
}

// ReapContext is Reap with a caller-supplied context.
func (c *Consumer) ReapContext(ctx context.Context) (handoff.ReapReport, error) {
	return c.q.ReapContext(ctx)
}

// Run drives Reap every interval until ctx is cancelled, handing each report to
// observe. It returns ctx.Err().
//
// THIS IS THE CALL THAT WAS MISSING. deadlines.go names two owners for clock
// 2's due-check; Controller's EventKindTick drives the in-memory one and this
// drives the durable one. A deployment that runs only the first marks audits
// `expired` in memory while their `handoff` rows stay 'ready' and keep being
// leased — §6 ruling G10's exact shape. Start this alongside whatever loop
// consumes Controller.NextWake.
//
// interval <= 0 means handoff.DefaultReaperInterval. The bound on that value
// (research/08 §4: "must be <= ttl/8") belongs to internal/handoff and is stated
// at its definition; this adapter passes the number through and has no opinion
// about it, exactly as LeaseOptions passes handoff.Options' other fields.
//
// observe may be nil, and a sweep error does not stop the loop. Cancellation is
// not reported as a sweep error — see handoff.Queue.Run, which found that the
// hard way under CI's race detector.
func (c *Consumer) Run(ctx context.Context, interval time.Duration, observe func(handoff.ReapReport, error)) error {
	return c.q.Run(ctx, interval, observe)
}

// Packet returns the finding's regenerable packet bytes to the lease holder.
//
// This is the ONE result-bearing surface this file exposes, and it does not
// decide anything: handoff.Queue.ReadPacket re-asserts R.6's read gate at the
// packet — the lease must still be this Task's, the record version must not
// have moved, and the audit's consumption gate must still be open. See
// packetGate in internal/handoff, and CRITIQUE-02 F5 for what happened when
// those bytes were reachable without it.
//
// A missing packet is reported with os.ErrNotExist so the caller can
// regenerate from the store; the packet is a cache and its absence is not an
// error in itself.
func (c *Consumer) Packet(t Task) ([]byte, error) {
	return c.PacketContext(context.Background(), t)
}

// PacketContext is Packet with a caller-supplied context.
func (c *Consumer) PacketContext(ctx context.Context, t Task) ([]byte, error) {
	if !t.Held() {
		return nil, errUnheld("Packet")
	}
	return c.q.ReadPacketContext(ctx, t.lease)
}

// WritePacket materialises the packet for a finding this worker holds, through
// the same gate. It is handoff.Queue.WritePacket.
func (c *Consumer) WritePacket(t Task, data []byte) (string, error) {
	return c.WritePacketContext(context.Background(), t, data)
}

// WritePacketContext is WritePacket with a caller-supplied context.
func (c *Consumer) WritePacketContext(ctx context.Context, t Task, data []byte) (string, error) {
	if !t.Held() {
		return "", errUnheld("WritePacket")
	}
	return c.q.WritePacketContext(ctx, t.lease, data)
}

// ---------------------------------------------------------------------------
// ConsumeOne
// ---------------------------------------------------------------------------

// failureDisposition is where an attempt lands when the Applier returns an
// error, i.e. when the consumer did not decide anything itself.
//
// IT IS THE REAPER'S RULE, APPLIED TO A SECOND TRIGGER, not a second rule.
// handoff.ReclaimExpired maps a lapsed lease to 'ready' when an attempt
// remains and to handoff.ExhaustedState when none does; a failed applier is
// the same situation reached by a different route — an attempt started, an
// attempt ended, nothing decided — so it maps the same way. Two triggers, one
// policy.
//
// What it must NOT do is invent a verdict. record.HandoffStateFailedValidation
// asserts that a fix failed validation and 'false_positive' asserts the
// finding was wrong; an applier that returned an error asserted neither, and
// this file has no standing to assert them on its behalf. 'ready' asserts
// nothing, and the attempt counter — incremented at claim time, so a crashed
// consumer cannot dodge it — is what stops the finding looping forever.
//
// handoff.ExhaustedState is referenced, never re-picked. internal/handoff
// chose record.HandoffStateFailedValidation for the exhausted case and gave
// its reasons; naming the constant here means the two can never disagree.
func failureDisposition(t Task) record.HandoffState {
	if t.AttemptsRemaining() == 0 {
		return handoff.ExhaustedState
	}
	return record.HandoffStateReady
}

// ConsumeOne performs exactly one attempt: acquire a lease, run apply, record
// the disposition.
//
// It returns handoff.ErrNoWork when nothing is claimable, which is idle and
// not a failure. It does NOT retry, does not loop, and does not renew the
// lease — an applier that may outlive c.Lease() must call RenewLease itself,
// every c.RenewInterval(). A retry inside one call would be an attempt the
// `attempts` counter never saw, and that counter is the only measurement a
// crashed consumer can be judged by.
//
// The error returned is non-nil whenever anything went wrong, INCLUDING when
// the Applier failed but the fallback disposition was written successfully.
// Swallowing an applier's error because the protocol recovered from it is how
// a consumer that fails on every finding looks healthy. Outcome carries the
// detail either way, and Outcome.ApplyErr is wrapped, so errors.Is and
// errors.As against the applier's own sentinels keep working.
//
// THE LEASE IS LEFT HELD if the applier's chosen disposition is refused —
// an illegal transition, or 'validated' on a requires_dynamic_confirmation
// finding with no dynamic evidence (handoff.ErrNoDynamicEvidence). That is
// deliberate. The alternatives are to write some other disposition, which
// would mean this file overruling the applier's verdict with one it invented,
// or to swallow the refusal. Instead the caller gets the refusal and a Task
// that still holds its lease: it may release with a legal disposition, or drop
// it and let ReclaimExpired requeue it at the lease deadline.
func (c *Consumer) ConsumeOne(ctx context.Context, workerID string, apply Applier) (Outcome, error) {
	if apply == nil {
		return Outcome{}, ErrNoApplier
	}

	t, err := c.AcquireLeaseContext(ctx, workerID)
	if err != nil {
		return Outcome{}, err
	}

	to, applyErr := apply(ctx, t)
	if applyErr != nil {
		fallback := failureDisposition(t)
		out := Outcome{Task: t, ApplyErr: applyErr}
		if relErr := c.ReleaseLeaseContext(ctx, t, fallback); relErr != nil {
			return out, fmt.Errorf(
				"scanctl: applier for %s failed and the lease could not be released as %s: %w",
				t.Fingerprint, fallback, relErr)
		}
		out.State = fallback
		return out, fmt.Errorf("scanctl: applier for %s failed, released as %s: %w",
			t.Fingerprint, fallback, applyErr)
	}

	if err := c.ReleaseLeaseContext(ctx, t, to); err != nil {
		// The lease is still held; see the doc comment. Applied is true
		// because the applier DID run and DID choose — what failed is the
		// recording of its choice, and conflating the two would hide which.
		return Outcome{Task: t, Applied: true}, err
	}
	return Outcome{Task: t, State: to, Applied: true}, nil
}
