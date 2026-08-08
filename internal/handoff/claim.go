package handoff

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"github.com/Susquehanna-Syntax/Anvil/internal/record"
)

// Handle is proof that one worker holds one lease on one finding, at one
// version of one audit record.
//
// plan/00-SPINE.md S7: a lease grants "may act on this finding" and nothing
// more. There is deliberately no field here that widens scope, authorises a
// merge, or records a verdict — a Handle cannot be mistaken for permission to
// do any of those because it carries no such value.
//
// The lease token is unexported: RenewLease and ReleaseLease compare-and-swap
// against the exact (claimed_by, lease_expires_at) pair this Handle was issued
// with, so a stale Handle — the one an OOM-killed consumer still has in memory
// when it wakes up — cannot write over its successor's work. It gets
// ErrLeaseLost instead.
type Handle struct {
	HandoffID     int64
	FindingID     int64
	AuditRecordID int64

	// Fingerprint is the anvil-fp/v1 digest, full 64 hex, never truncated.
	Fingerprint string

	// WorkerID is the lease holder, `handoff.claimed_by` (O.3's lease_owner).
	WorkerID string

	// RecordVersion is audit_record.audit_version as it stood when the lease
	// was granted. Together with Fingerprint it is the (fingerprint, record
	// version) key the plan requires reclaim/re-processing to be idempotent
	// under: a version bump re-cuts the queue (S6), so a Handle whose version
	// has moved describes work that no longer exists and is refused.
	RecordVersion int64

	ConsumptionClass record.ConsumptionClass

	// DastStatus is the audit's DAST half status at claim time. It is carried
	// so a consumer of a requires_dynamic_confirmation finding can see that
	// the half ended 'not_run', 'target_boot_failed' or 'skipped_no_manifest'
	// — i.e. that no dynamic evidence exists — rather than assume a clean
	// dynamic scan. S6 exists to keep those cases distinguishable; dropping
	// the field here would re-merge them at the only point that acts on them.
	//
	// It is NOT advisory. ReleaseLease reads it: a requires_dynamic_confirmation
	// finding whose DAST half produced no reproduction cannot be recorded
	// 'validated' (checkDynamicEvidence, and plan/00-SPINE.md S7).
	DastStatus record.DastStatus

	// Attempt is this lease's ordinal: 1 for the first, 2 after one crash and
	// one reclaim. It equals handoff.attempts after the claim.
	Attempt     int
	MaxAttempts int

	// LeaseExpiresAt is when ReclaimExpired will presume this holder dead. It
	// is Options.Lease after the claim, NOT audit_record.claim_timeout_seconds.
	LeaseExpiresAt time.Time

	// IdempotencyKey is stable across crash and reclaim: the second consumer
	// of the same finding at the same record version gets the same key the
	// first had, which is how a duplicate side effect is recognised and
	// suppressed downstream. It mirrors the git trailer.
	IdempotencyKey string

	// PacketPath is where the regenerable tmpfs packet lives, or "" when no
	// PacketDir is configured. The packet is a cache: if it is missing,
	// regenerate it from the store (research/08 §1). It is never the source of
	// truth and its absence is not an error.
	PacketPath string

	// leaseToken is the exact lease_expires_at text stored at claim time. It
	// is the CAS witness, not a duplicate of LeaseExpiresAt: comparing the
	// stored text avoids any dependence on timestamp formatting round-trips.
	leaseToken string
}

// consumptionGate is THE consumption gate, written once so there is one
// definition of "this finding's half is readable".
//
// research/21 §5, as quoted by O.3: static_only findings are claimable once
// the SAST half is sealed; requires_dynamic_confirmation findings must wait on
// the DAST half. Expressed against R.6's sealing signals:
//
//   - static_only needs audit_record.sast_status = 'sealed' AND the audit to
//     have actually sealed that half (state 'sast_sealed', 'both_sealed' or
//     'consumed'). R.6 makes 'sealed' the hard read gate; a consumer must not
//     read a half before it says so.
//   - requires_dynamic_confirmation needs the audit to have reached
//     'both_sealed' (or moved on to 'consumed'), which are the only states in
//     which the DAST half is final, plus dast_status <> 'running' as a
//     belt-and-braces check.
//
// 'consumed' IS IN BOTH SETS, AND THAT IS THE POINT. plan/00-SPINE.md S1
// requires a RE-ENTRANT consumer, and R.6 already implements it in the other
// direction — sealing.go's ReadHalf says so outright: "A consumed audit is
// still readable: S1 requires a RE-ENTRANT consumer, so taking the record once
// must not shut the gate." Before this fix the queue disagreed with the
// sealer. Because one audit_record fans out to MANY handoff rows, the first
// consumption pass marking the audit 'consumed' stranded every sibling finding
// still in 'ready': permanently unclaimable, then swept to 'expired' by
// ExpireClaimTimeouts at the deadline. The row survived; the finding was never
// handed to an agent in that scan. That is silent work loss on the exact axis
// S1 names, and CRITIQUE-02 F2 reproduced it.
//
// 'expired' is deliberately NOT in either set: R.6's read gate refuses an
// expired audit because the reaper has dropped its payload, and a claim on a
// finding whose evidence is gone is worse than no claim.
//
// The audit state test is load-bearing and not redundant with dast_status:
// schema.sql DEFAULTs dast_status to 'not_run', so a still-collecting audit
// whose DAST half has not started is indistinguishable from a finished audit
// on which DAST was disabled if you look at dast_status alone. Gating on the
// sealed state closes that hole. The consequence for a
// requires_dynamic_confirmation finding on a DAST-disabled audit is that it is
// claimable once both halves seal, with DastStatus = 'not_run' visible on the
// Handle — deliberately, because refusing forever would only push the finding
// to its claim timeout, and research/08 §4 is explicit that missing the window
// costs latency, not the finding. What such a finding may NOT do is reach
// 'validated'; see ReleaseLeaseContext.
const consumptionGate = `(
	        (h.consumption_class = ? AND a.sast_status = ? AND a.state IN (?, ?, ?))
	     OR (h.consumption_class = ? AND a.state IN (?, ?) AND a.dast_status <> ?)
	      )`

// gateArgs binds consumptionGate's nine placeholders. Every value is a
// constant from internal/record — no enum literal is re-typed as a bare string
// here or anywhere else in this package.
func gateArgs() []any {
	return []any{
		string(record.ConsumptionClassStaticOnly),
		string(record.HalfStatusSealed),
		string(record.StateSastSealed),
		string(record.StateBothSealed),
		string(record.StateConsumed),
		string(record.ConsumptionClassRequiresDynamicConfirmation),
		string(record.StateBothSealed),
		string(record.StateConsumed),
		string(record.DastStatusRunning),
	}
}

// noSiblingLease is the ONE-LIVE-LEASE-PER-(fingerprint, record version)
// invariant, enforced in the queries that grant a lease.
//
// WHY IT IS HERE AND NOT IN schema.sql. The protocol promises reclaim and
// re-processing are idempotent under (fingerprint, record version); the table
// only enforces UNIQUE (finding_id, audit_record_id). A re-scan produces a NEW
// audit_record row — scan_run_id is UNIQUE, so it must — and audit_version
// DEFAULTs to 1 on each. One fingerprint therefore ends up with several rows,
// ALL AT VERSION 1, each independently leasable. The two entry points then
// actively diverged onto different rows: AcquireLease ordered by created_at
// (oldest) and Claim by audit_record_id DESC (newest), so two workers took two
// live leases on one defect at one record version and both recorded
// 'validated'. checkRecordVersion cannot see it — it compares a Handle against
// ITS OWN row's audit_version, which never moved. CRITIQUE-02 F1 reproduced
// exactly that, and it is the outcome research/08 §4 point 2 forbids: "a
// second agent write[s] a competing fix for the same defect."
//
// R.4's schema.sql is a frozen interface, so the durable constraint that would
// express this — a partial unique index over (fingerprint, audit_version)
// where state = 'leased' — cannot be added here; it is reported to the
// orchestrator instead. What IS available is a guard inside the same statement
// that grants the lease. SQLite serialises writers, so the NOT EXISTS is
// evaluated as part of the granting UPDATE and cannot interleave with a
// competing grant: of two concurrent claims on sibling rows, exactly one sees
// no live sibling and wins. That is the same argument that makes the
// `state = 'ready'` guard atomic, applied to a wider key.
//
// It appears in TWO places on purpose. In the eligibility SELECT it keeps
// AcquireLease from repeatedly picking a row it cannot have (which would burn
// the race budget and return ErrNoWork while other work waited); in the UPDATE
// it is the guarantee, because only the UPDATE is atomic with the grant.
const noSiblingLease = `NOT EXISTS (
	        SELECT 1
	          FROM handoff o
	          JOIN audit_record oa ON oa.audit_record_id = o.audit_record_id
	         WHERE o.fingerprint = h.fingerprint
	           AND o.handoff_id <> h.handoff_id
	           AND o.state = ?
	           AND oa.audit_version = a.audit_version
	      )`

// eligibleFrom is the claimable set: the consumption gate, plus the attempt
// budget, plus the one-live-lease invariant.
//
// `h.attempts < h.max_attempts` is here, not only in the reaper, so a row that
// somehow re-entered 'ready' with its attempts burned cannot be re-leased
// forever — the exact failure §6 G10 traced.
const eligibleFrom = `
	FROM handoff h
	JOIN audit_record a ON a.audit_record_id = h.audit_record_id
	WHERE h.state = ?
	  AND h.attempts < h.max_attempts
	  AND ` + consumptionGate + `
	  AND ` + noSiblingLease

// eligibleArgs binds eligibleFrom's placeholders, in statement order.
func eligibleArgs() []any {
	args := make([]any, 0, 11)
	args = append(args, string(record.HandoffStateReady))
	args = append(args, gateArgs()...)
	args = append(args, string(record.HandoffStateLeased))
	return args
}

// Claim takes the lease on one named finding. It is the R.7 packet's entry
// point and a narrowing of AcquireLease: same query, same CAS, same state
// machine.
//
// Exactly one concurrent caller wins. Every loser gets ErrAlreadyClaimed,
// because the winner's UPDATE moved the row out of 'ready' and SQLite
// serialises the two writes.
//
// Errors worth distinguishing: ErrNotFound (no such fingerprint in the queue),
// ErrAlreadyClaimed (someone holds it), ErrNotEligible (consumption gate shut,
// or every row for it is terminal), ErrExhausted (attempts burned).
func (q *Queue) Claim(fingerprint string, workerID string) (Handle, error) {
	return q.ClaimContext(context.Background(), fingerprint, workerID)
}

// ClaimContext is Claim with a caller-supplied context.
func (q *Queue) ClaimContext(ctx context.Context, fingerprint, workerID string) (Handle, error) {
	if err := ValidateFingerprint(fingerprint); err != nil {
		return Handle{}, err
	}
	if workerID == "" {
		return Handle{}, errors.New("handoff: Claim requires a non-empty workerID")
	}

	args := append(eligibleArgs(), fingerprint)
	var handoffID int64
	err := q.db.QueryRowContext(ctx,
		`SELECT h.handoff_id`+eligibleFrom+`
		   AND h.fingerprint = ?
		 ORDER BY h.audit_record_id DESC, h.handoff_id DESC
		 LIMIT 1`, args...).Scan(&handoffID)
	if errors.Is(err, sql.ErrNoRows) {
		return Handle{}, q.explainUnclaimable(ctx, fingerprint)
	}
	if err != nil {
		return Handle{}, fmt.Errorf("handoff: selecting a claimable row for %s: %w", fingerprint, err)
	}

	h, won, err := q.tryClaim(ctx, handoffID, workerID)
	if err != nil {
		return Handle{}, err
	}
	if !won {
		// Lost the race between SELECT and UPDATE. Re-read to say why.
		return Handle{}, q.explainUnclaimable(ctx, fingerprint)
	}
	return h, nil
}

// AcquireLease takes the lease on the oldest claimable finding, whichever it
// is. This is O.3's entry point; Claim is the same operation with a
// fingerprint filter.
//
// It returns ErrNoWork when nothing is claimable, which is the idle case and
// not a failure.
func (q *Queue) AcquireLease(workerID string) (Handle, error) {
	return q.AcquireLeaseContext(context.Background(), workerID)
}

// AcquireLeaseContext is AcquireLease with a caller-supplied context.
func (q *Queue) AcquireLeaseContext(ctx context.Context, workerID string) (Handle, error) {
	if workerID == "" {
		return Handle{}, errors.New("handoff: AcquireLease requires a non-empty workerID")
	}

	// Bounded retry: each lost race consumes one candidate, and the loop
	// re-selects rather than spinning on the same row. The bound exists so a
	// pathological producer inserting ready rows faster than this worker can
	// lose races cannot wedge the call forever.
	const maxRaces = 64
	for i := 0; i < maxRaces; i++ {
		var handoffID int64
		err := q.db.QueryRowContext(ctx,
			`SELECT h.handoff_id`+eligibleFrom+`
			 ORDER BY h.created_at, h.handoff_id
			 LIMIT 1`, eligibleArgs()...).Scan(&handoffID)
		if errors.Is(err, sql.ErrNoRows) {
			return Handle{}, ErrNoWork
		}
		if err != nil {
			return Handle{}, fmt.Errorf("handoff: selecting a claimable row: %w", err)
		}

		h, won, err := q.tryClaim(ctx, handoffID, workerID)
		if err != nil {
			return Handle{}, err
		}
		if won {
			return h, nil
		}
	}
	return Handle{}, fmt.Errorf("handoff: lost %d consecutive claim races: %w", maxRaces, ErrNoWork)
}

// tryClaim is THE claim. One conditional UPDATE, guarded on `state = 'ready'`
// AND on no sibling row for this fingerprint holding a live lease at this
// record version, is what makes the protocol atomic: SQLite serialises
// writers, so of any number of concurrent callers exactly one sees
// RowsAffected() == 1.
//
// The sibling guard is written against handoff_id rather than against a value
// this function read earlier, so the fingerprint and the audit_version it
// compares are the ones the database holds AT THE MOMENT OF THE WRITE. Reading
// them in Go first and passing them down would reintroduce the window the
// guard exists to close. See noSiblingLease.
//
// attempts is incremented here, at claim time, not at release time. That is
// what makes the counter a record of attempts STARTED, which is the only
// counter a crashed consumer can be measured by — a consumer that dies never
// gets to increment anything itself.
func (q *Queue) tryClaim(ctx context.Context, handoffID int64, workerID string) (Handle, bool, error) {
	now := q.Now()
	expiry := formatTime(now.Add(q.opts.lease()))

	res, err := q.db.ExecContext(ctx,
		`UPDATE handoff
		    SET state = ?, claimed_by = ?, lease_expires_at = ?,
		        attempts = attempts + 1, updated_at = ?
		  WHERE handoff_id = ? AND state = ?
		    AND NOT EXISTS (
		          SELECT 1
		            FROM handoff o
		            JOIN audit_record oa ON oa.audit_record_id = o.audit_record_id
		           WHERE o.state = ?
		             AND o.handoff_id <> ?
		             AND o.fingerprint = (SELECT t.fingerprint FROM handoff t WHERE t.handoff_id = ?)
		             AND oa.audit_version = (SELECT ta.audit_version
		                                       FROM audit_record ta
		                                       JOIN handoff th ON th.audit_record_id = ta.audit_record_id
		                                      WHERE th.handoff_id = ?)
		        )`,
		string(record.HandoffStateLeased), workerID, expiry, formatTime(now),
		handoffID, string(record.HandoffStateReady),
		string(record.HandoffStateLeased), handoffID, handoffID, handoffID)
	if err != nil {
		return Handle{}, false, fmt.Errorf("handoff: claiming row %d: %w", handoffID, err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return Handle{}, false, fmt.Errorf("handoff: claiming row %d: %w", handoffID, err)
	}
	if n == 0 {
		return Handle{}, false, nil
	}

	h, err := q.handleFor(ctx, handoffID, expiry)
	if err != nil {
		return Handle{}, false, err
	}
	return h, true, nil
}

// handleFor reads back the row this worker just claimed, joined to the audit
// record for the version and DAST status the Handle carries.
func (q *Queue) handleFor(ctx context.Context, handoffID int64, leaseToken string) (Handle, error) {
	row := q.db.QueryRowContext(ctx,
		`SELECT `+rowColumns+`, a.audit_version, a.dast_status
		   FROM handoff h
		   JOIN audit_record a ON a.audit_record_id = h.audit_record_id
		  WHERE h.handoff_id = ?`, handoffID)

	var (
		r           Row
		groupID     sql.NullString
		claimedBy   sql.NullString
		leaseExpiry sql.NullString
		idemKey     sql.NullString
		state       string
		class       string
		createdAt   string
		updatedAt   string
		version     int64
		dastStatus  string
	)
	if err := row.Scan(
		&r.HandoffID, &r.FindingID, &r.AuditRecordID, &r.Fingerprint, &groupID, &state,
		&class, &claimedBy, &leaseExpiry, &r.Attempts, &r.MaxAttempts,
		&idemKey, &createdAt, &updatedAt, &version, &dastStatus,
	); err != nil {
		return Handle{}, fmt.Errorf("handoff: reading back claimed row %d: %w", handoffID, err)
	}
	if err := record.ValidateConsumptionClass(class); err != nil {
		return Handle{}, fmt.Errorf("handoff: row %d: %w", handoffID, err)
	}
	if err := record.ValidateDastStatus(dastStatus); err != nil {
		return Handle{}, fmt.Errorf("handoff: audit_record %d: %w", r.AuditRecordID, err)
	}
	expiresAt, err := parseTime("handoff.lease_expires_at", leaseExpiry.String)
	if err != nil {
		return Handle{}, err
	}

	h := Handle{
		HandoffID:        r.HandoffID,
		FindingID:        r.FindingID,
		AuditRecordID:    r.AuditRecordID,
		Fingerprint:      r.Fingerprint,
		WorkerID:         claimedBy.String,
		RecordVersion:    version,
		ConsumptionClass: record.ConsumptionClass(class),
		DastStatus:       record.DastStatus(dastStatus),
		Attempt:          r.Attempts,
		MaxAttempts:      r.MaxAttempts,
		LeaseExpiresAt:   expiresAt,
		IdempotencyKey:   idemKey.String,
		leaseToken:       leaseToken,
	}
	if path, err := q.PacketPath(r.Fingerprint); err == nil {
		h.PacketPath = path
	}
	return h, nil
}

// explainUnclaimable turns "the eligibility query matched nothing" into the
// specific reason, by re-reading the rows for that fingerprint. The
// classification order matters: a losing racer must learn ErrAlreadyClaimed,
// not ErrNotEligible.
//
// Reporting ErrAlreadyClaimed when ANY row for the fingerprint is leased is
// exact, not approximate: since noSiblingLease, one live lease on a
// fingerprint at a record version blocks every sibling row for it, so "someone
// holds this finding" is precisely what a caller needs to hear.
func (q *Queue) explainUnclaimable(ctx context.Context, fingerprint string) error {
	rows, err := q.FindContext(ctx, fingerprint)
	if err != nil {
		return err
	}
	if len(rows) == 0 {
		return fmt.Errorf("handoff: fingerprint %s: %w", fingerprint, ErrNotFound)
	}
	for _, r := range rows {
		if r.State == record.HandoffStateLeased {
			return fmt.Errorf("handoff: fingerprint %s is held by %q until %s: %w",
				fingerprint, r.ClaimedBy, formatTime(r.LeaseExpiresAt), ErrAlreadyClaimed)
		}
	}
	for _, r := range rows {
		if r.State == record.HandoffStateReady && r.AttemptsRemaining() == 0 {
			return fmt.Errorf("handoff: fingerprint %s has used %d of %d attempts: %w",
				fingerprint, r.Attempts, r.MaxAttempts, ErrExhausted)
		}
	}
	for _, r := range rows {
		if r.State == record.HandoffStateReady {
			return fmt.Errorf("handoff: fingerprint %s is ready but its %s gate is shut: %w",
				fingerprint, r.ConsumptionClass, ErrNotEligible)
		}
	}
	return fmt.Errorf("handoff: fingerprint %s is terminal (%s): %w",
		fingerprint, rows[0].State, ErrNotEligible)
}

// RenewLease is the heartbeat. It extends the lease by Options.Lease from now
// and returns a fresh Handle; the old one is dead and must be discarded.
//
// It refuses, with ErrLeaseLost, if the row is no longer leased by this worker
// on this exact lease — which is precisely the case after a crash-and-reclaim.
// It refuses with ErrRecordVersionChanged if audit_record.audit_version moved,
// because a version bump re-cuts the queue and this work unit no longer exists.
//
// A heartbeat that arrives slightly after lease_expires_at but before the
// reaper has acted is honoured: the holder is demonstrably alive, and the
// reaper's own CAS will then find the lease moved and leave it alone.
func (q *Queue) RenewLease(h Handle) (Handle, error) {
	return q.RenewLeaseContext(context.Background(), h)
}

// RenewLeaseContext is RenewLease with a caller-supplied context.
func (q *Queue) RenewLeaseContext(ctx context.Context, h Handle) (Handle, error) {
	if err := q.checkRecordVersion(ctx, h); err != nil {
		return Handle{}, err
	}

	now := q.Now()
	expiry := formatTime(now.Add(q.opts.lease()))
	res, err := q.db.ExecContext(ctx,
		`UPDATE handoff SET lease_expires_at = ?, updated_at = ?
		  WHERE handoff_id = ? AND state = ? AND claimed_by = ? AND lease_expires_at = ?`,
		expiry, formatTime(now),
		h.HandoffID, string(record.HandoffStateLeased), h.WorkerID, h.leaseToken)
	if err != nil {
		return Handle{}, fmt.Errorf("handoff: renewing lease on row %d: %w", h.HandoffID, err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return Handle{}, fmt.Errorf("handoff: renewing lease on row %d: %w", h.HandoffID, err)
	}
	if n == 0 {
		return Handle{}, q.explainLeaseLost(ctx, h)
	}
	return q.handleFor(ctx, h.HandoffID, expiry)
}

// ReleaseLease ends one attempt and records its outcome.
//
// `to` must be a legal successor of 'leased' — one of the eleven dispositions,
// or 'ready' to hand the finding back unattempted-in-effect for another worker
// to pick up. It is checked against the state machine before anything is
// written, so an out-of-vocabulary or out-of-order value never reaches the
// database.
//
// 'validated' carries ONE further condition, because it is the one disposition
// that asserts a defect is verified fixed: a requires_dynamic_confirmation
// finding needs dynamic evidence to have existed. See checkDynamicEvidence.
//
// THE CRASH CASE. The UPDATE is conditional on (state='leased', claimed_by,
// lease_expires_at) still matching this Handle. An OOM-killed consumer whose
// lease expired and was reclaimed, and whose process then came back and tried
// to report success, affects zero rows and gets ErrLeaseLost. Its successor's
// work is untouched. That is the mechanism by which reclaiming and
// re-processing is idempotent: not a lock, a compare-and-swap on the exact
// lease.
func (q *Queue) ReleaseLease(h Handle, to record.HandoffState) error {
	return q.ReleaseLeaseContext(context.Background(), h, to)
}

// ReleaseLeaseContext is ReleaseLease with a caller-supplied context.
func (q *Queue) ReleaseLeaseContext(ctx context.Context, h Handle, to record.HandoffState) error {
	if err := CheckTransition(record.HandoffStateLeased, to); err != nil {
		return err
	}
	if err := checkDynamicEvidence(h, to); err != nil {
		return err
	}
	if err := q.checkRecordVersion(ctx, h); err != nil {
		return err
	}

	res, err := q.db.ExecContext(ctx,
		`UPDATE handoff
		    SET state = ?, claimed_by = NULL, lease_expires_at = NULL, updated_at = ?
		  WHERE handoff_id = ? AND state = ? AND claimed_by = ? AND lease_expires_at = ?`,
		string(to), formatTime(q.Now()),
		h.HandoffID, string(record.HandoffStateLeased), h.WorkerID, h.leaseToken)
	if err != nil {
		return fmt.Errorf("handoff: releasing row %d as %s: %w", h.HandoffID, to, err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("handoff: releasing row %d as %s: %w", h.HandoffID, to, err)
	}
	if n == 0 {
		return q.explainLeaseLost(ctx, h)
	}

	// A finished finding has no further use for its cache file. The state
	// change above is already durable; a failure to unlink is reported but
	// does not un-finish the finding.
	if IsTerminal(to) {
		if err := q.DropPacket(h.Fingerprint); err != nil {
			return fmt.Errorf("handoff: row %d is %s but its packet remains: %w", h.HandoffID, to, err)
		}
	}
	return nil
}

// HasDynamicEvidence reports whether a DAST half that ended in this state can
// have produced a reproduction of a finding.
//
// It is true for exactly two of the ten anvil/dastStatus literals:
//
//   - completed_findings — the half ran and produced dynamic findings.
//   - completed_partial  — the half ran to its own conclusion over part of the
//     discovered surface, so a reproduction for this finding may exist; which
//     endpoints were probed is DastCoverage's business, not the queue's.
//
// It is false for the other eight, and each exclusion is deliberate:
//
//   - not_run, skipped_no_manifest       — the half never scanned anything.
//   - running                            — the half has not concluded.
//   - target_boot_failed, target_unreachable — there was no live target, which
//     is the case plan/00-SPINE.md S6 exists to keep distinguishable from
//     "scanned clean".
//   - timed_out, completed_failed        — the half did not finish; a crashed
//     or truncated scan has produced no verdict about this finding.
//   - completed_clean                    — the half DID scan and found nothing
//     dynamically. This is the subtle one, and it is excluded on purpose: a
//     requires_dynamic_confirmation finding on an audit whose DAST half came
//     back clean has no dynamic reproduction at all, so there is nothing that
//     can "now fail". Such a finding wants triage, not a validation verdict.
func HasDynamicEvidence(s record.DastStatus) bool {
	switch s {
	case record.DastStatusCompletedFindings, record.DastStatusCompletedPartial:
		return true
	default:
		return false
	}
}

// checkDynamicEvidence enforces plan/00-SPINE.md S7 at the one place a verdict
// is actually written into the database.
//
// S7: "Only a DAST reproduction that now fails earns 'verified fixed'." This
// package's own doc has always said so, and then let any lease holder release
// ANY finding as 'validated' regardless of its ConsumptionClass and
// DastStatus — including a requires_dynamic_confirmation finding whose DAST
// half was 'not_run', where no reproduction can exist to have been re-run.
// CRITIQUE-02 F9 reproduced that. "The judgement is made elsewhere" is not an
// answer when handoff.state = 'validated' is written HERE, by the claimant,
// unchecked; S7 is "enforce in code, not documentation".
//
// The rule is scoped to the class that asks for it. A static_only finding is
// by definition one no dynamic evidence was ever required for, and refusing
// its 'validated' would make the disposition unreachable for the majority of
// findings. What is refused is the combination the spine forbids: a finding
// whose class SAYS it needs dynamic confirmation, recorded as verified fixed
// on the strength of a static rescan.
func checkDynamicEvidence(h Handle, to record.HandoffState) error {
	if to != record.HandoffStateValidated {
		return nil
	}
	if h.ConsumptionClass != record.ConsumptionClassRequiresDynamicConfirmation {
		return nil
	}
	if HasDynamicEvidence(h.DastStatus) {
		return nil
	}
	return fmt.Errorf(
		"handoff: row %d is %s and its audit's DAST half ended %q, so no dynamic reproduction exists to have been re-run: %w",
		h.HandoffID, record.ConsumptionClassRequiresDynamicConfirmation, h.DastStatus, ErrNoDynamicEvidence)
}

// checkRecordVersion enforces the (fingerprint, record version) key. A lease
// is only valid at the audit_version it was granted at.
func (q *Queue) checkRecordVersion(ctx context.Context, h Handle) error {
	var version int64
	err := q.db.QueryRowContext(ctx,
		`SELECT audit_version FROM audit_record WHERE audit_record_id = ?`, h.AuditRecordID).Scan(&version)
	if errors.Is(err, sql.ErrNoRows) {
		return fmt.Errorf("handoff: audit_record %d: %w", h.AuditRecordID, ErrNotFound)
	}
	if err != nil {
		return fmt.Errorf("handoff: reading audit_record %d version: %w", h.AuditRecordID, err)
	}
	if version != h.RecordVersion {
		return fmt.Errorf("handoff: audit_record %d moved from version %d to %d: %w",
			h.AuditRecordID, h.RecordVersion, version, ErrRecordVersionChanged)
	}
	return nil
}

// explainLeaseLost says which way the lease was lost, without ever implying
// the caller may proceed.
func (q *Queue) explainLeaseLost(ctx context.Context, h Handle) error {
	current, err := q.GetContext(ctx, h.HandoffID)
	if err != nil {
		return err
	}
	switch {
	case current.State != record.HandoffStateLeased:
		return fmt.Errorf("handoff: row %d is now %s, not leased by %q: %w",
			h.HandoffID, current.State, h.WorkerID, ErrLeaseLost)
	case current.ClaimedBy != h.WorkerID:
		return fmt.Errorf("handoff: row %d is leased by %q, not %q: %w",
			h.HandoffID, current.ClaimedBy, h.WorkerID, ErrLeaseLost)
	default:
		return fmt.Errorf("handoff: row %d holds a newer lease for %q (expires %s): %w",
			h.HandoffID, h.WorkerID, formatTime(current.LeaseExpiresAt), ErrLeaseLost)
	}
}

// ---------------------------------------------------------------------------
// The regenerable tmpfs packet.
//
// It is a CACHE. The store is the source of truth (plan/00-SPINE.md S1: one
// SQLite store, one handoff table, a regenerable tmpfs packet — there is no
// second durable buffer file). If a packet is missing, regenerate it; its
// absence is never an error and never loses a finding.
// ---------------------------------------------------------------------------

// ErrNoPacketDir means the Queue was configured without a PacketDir, so there
// is nowhere to materialise a packet. Reading it as fatal would be wrong: a
// deployment that hands the consumer bytes instead of a path needs no packet
// directory at all.
var ErrNoPacketDir = errors.New("handoff: no PacketDir is configured")

// PacketPath returns where a fingerprint's packet lives. The fingerprint is
// validated as 64 hex first, which is also what stops a crafted value from
// escaping PacketDir.
func (q *Queue) PacketPath(fingerprint string) (string, error) {
	if err := ValidateFingerprint(fingerprint); err != nil {
		return "", err
	}
	if q.opts.PacketDir == "" {
		return "", ErrNoPacketDir
	}
	return filepath.Join(q.opts.PacketDir, fingerprint+".sarif"), nil
}

// packetGate is R.6's read gate, re-asserted at the packet.
//
// THE PACKET IS A CACHE OF THE PAYLOAD, NOT A SEPARATE ARTEFACT. R.6's gate —
// "do not allow a consumer to read a half's results before that half's status
// equals sealed" — means nothing if the same bytes are reachable through a
// file beside it. CRITIQUE-02 F5: WritePacket materialised a packet for an
// audit that had sealed nothing, and ReadPacket returned a half's actual
// results with no seal check, no audit-state check and no lease check, one
// line after the claim gate had correctly refused the same fingerprint.
// ReadPacket was the ONLY exported function in this package that returns a
// half's results, and it was the one that checked nothing.
//
// It re-asserts three things, all in one statement against the database rather
// than against the Handle's own copy of them, because a Handle is a snapshot
// and the whole point is that the world may have moved:
//
//  1. This exact lease is still held — (state='leased', claimed_by,
//     lease_expires_at), the same CAS triple RenewLease and ReleaseLease use.
//     A reclaimed holder gets ErrLeaseLost here too, so it cannot read the
//     successor's packet.
//  2. The audit's consumption gate is STILL open for this row's class, using
//     the same consumptionGate expression the claim uses. One definition, two
//     call sites.
//  3. The record version has not moved (checkRecordVersion), because S6 re-cuts
//     the queue on a bump and the packet then describes work that is gone.
func (q *Queue) packetGate(ctx context.Context, h Handle) error {
	if err := ValidateFingerprint(h.Fingerprint); err != nil {
		return err
	}
	if h.WorkerID == "" {
		return errors.New("handoff: a packet operation requires a Handle from Claim or AcquireLease")
	}
	if err := q.checkRecordVersion(ctx, h); err != nil {
		return err
	}

	args := []any{
		h.HandoffID, h.Fingerprint,
		string(record.HandoffStateLeased), h.WorkerID, h.leaseToken,
	}
	args = append(args, gateArgs()...)

	var one int
	err := q.db.QueryRowContext(ctx,
		`SELECT 1
		   FROM handoff h
		   JOIN audit_record a ON a.audit_record_id = h.audit_record_id
		  WHERE h.handoff_id = ?
		    AND h.fingerprint = ?
		    AND h.state = ?
		    AND h.claimed_by = ?
		    AND h.lease_expires_at = ?
		    AND `+consumptionGate, args...).Scan(&one)
	if errors.Is(err, sql.ErrNoRows) {
		// Either the lease moved or the gate is shut. Say which.
		current, gerr := q.GetContext(ctx, h.HandoffID)
		if gerr != nil {
			return gerr
		}
		if current.State != record.HandoffStateLeased ||
			current.ClaimedBy != h.WorkerID ||
			formatTime(current.LeaseExpiresAt) != h.leaseToken {
			return q.explainLeaseLost(ctx, h)
		}
		return fmt.Errorf("handoff: row %d holds a lease but its %s gate is shut; "+
			"R.6 refuses a read before the half seals: %w",
			h.HandoffID, current.ConsumptionClass, ErrNotEligible)
	}
	if err != nil {
		return fmt.Errorf("handoff: checking the packet gate for row %d: %w", h.HandoffID, err)
	}
	return nil
}

// WritePacket materialises a packet for a finding this worker holds the lease
// on, using research/08 §C's durable recipe:
// write an exclusively-created temp file in the SAME directory, fsync it,
// close it, rename it over the final name, then fsync the parent directory.
//
// It takes a Handle, not a bare fingerprint, because the packet carries a
// half's results and R.6's read gate governs those bytes wherever they live.
// See packetGate.
//
// The parent fsync is not optional decoration. fsync(2): "Calling fsync() does
// not necessarily ensure that the entry in the directory containing the file
// has also reached disk. For that an explicit fsync() on a file descriptor for
// the directory is also needed." Omitting it passes every test on ext4 —
// because auto_da_alloc papers over it — and loses data on XFS or
// data=writeback. This code does not depend on that heuristic.
//
// Windows has no fsync-able directory handle, so the parent fsync is skipped
// there and only there. Anvil's packet lives on tmpfs on Linux; Windows is a
// development host.
func (q *Queue) WritePacket(h Handle, data []byte) (string, error) {
	return q.WritePacketContext(context.Background(), h, data)
}

// WritePacketContext is WritePacket with a caller-supplied context.
func (q *Queue) WritePacketContext(ctx context.Context, h Handle, data []byte) (string, error) {
	if err := q.packetGate(ctx, h); err != nil {
		return "", err
	}
	fingerprint := h.Fingerprint
	final, err := q.PacketPath(fingerprint)
	if err != nil {
		return "", err
	}
	dir := filepath.Dir(final)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", fmt.Errorf("handoff: creating packet directory %s: %w", dir, err)
	}

	tmp, err := os.CreateTemp(dir, fingerprint+".*.tmp")
	if err != nil {
		return "", fmt.Errorf("handoff: creating packet temp file in %s: %w", dir, err)
	}
	tmpName := tmp.Name()
	cleanup := func() {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
	}
	if _, err := tmp.Write(data); err != nil {
		cleanup()
		return "", fmt.Errorf("handoff: writing packet %s: %w", tmpName, err)
	}
	if err := tmp.Sync(); err != nil {
		cleanup()
		return "", fmt.Errorf("handoff: fsyncing packet %s: %w", tmpName, err)
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpName)
		return "", fmt.Errorf("handoff: closing packet %s: %w", tmpName, err)
	}
	if err := os.Rename(tmpName, final); err != nil {
		_ = os.Remove(tmpName)
		return "", fmt.Errorf("handoff: publishing packet %s: %w", final, err)
	}
	if err := syncDir(dir); err != nil {
		return "", fmt.Errorf("handoff: fsyncing packet directory %s: %w", dir, err)
	}
	return final, nil
}

// ReadPacket returns a packet's bytes to the worker that holds the lease on
// the finding, and to nobody else.
//
// It is the only exported function in this package that hands back a half's
// actual results, so it is gated exactly as R.6 gates a half read: the lease
// must still be this Handle's, the record version must not have moved, and the
// audit's consumption gate must be open. See packetGate for why a cache of the
// payload cannot be less protected than the payload.
//
// A missing packet is reported with os.ErrNotExist so the caller can
// regenerate rather than fail — the packet is a cache and its absence is never
// an error in itself (research/08 §1).
func (q *Queue) ReadPacket(h Handle) ([]byte, error) {
	return q.ReadPacketContext(context.Background(), h)
}

// ReadPacketContext is ReadPacket with a caller-supplied context.
func (q *Queue) ReadPacketContext(ctx context.Context, h Handle) ([]byte, error) {
	if err := q.packetGate(ctx, h); err != nil {
		return nil, err
	}
	path, err := q.PacketPath(h.Fingerprint)
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("handoff: reading packet %s: %w", path, err)
	}
	return data, nil
}

// DropPacket unlinks a packet. Nothing more.
//
// This is an unlink, not an erasure, and this package makes no claim that the
// bytes are unrecoverable afterwards. research/08 §F establishes why any such
// claim would be false: shred(1) "assumes the file system and hardware
// overwrite data in place", which does not hold for Btrfs, ZFS, XFS, ext3/4 in
// data=journal, compressed, snapshotting or RAID filesystems, and on SSDs wear
// levelling means "'overwritten' data blocks are still present in the
// underlying device". The control that actually applies is keeping the
// plaintext packet off persistent media in the first place — tmpfs, ideally
// with noswap — which is a deployment property, not something code can assert.
//
// Dropping a packet that is not there is success, because the packet is a
// cache and its absence is the desired state.
func (q *Queue) DropPacket(fingerprint string) error {
	path, err := q.PacketPath(fingerprint)
	if errors.Is(err, ErrNoPacketDir) {
		return nil
	}
	if err != nil {
		return err
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("handoff: unlinking packet %s: %w", path, err)
	}
	return nil
}

// syncDir fsyncs a directory so a rename into it is durable. See WritePacket
// for why, and for why Windows is exempt.
func syncDir(dir string) error {
	if runtime.GOOS == "windows" {
		return nil
	}
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer func() { _ = d.Close() }()
	return d.Sync()
}
