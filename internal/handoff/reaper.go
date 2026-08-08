package handoff

import (
	"context"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/Susquehanna-Syntax/Anvil/internal/record"
)

// THE REAPER RUNS TWO INDEPENDENT CLOCKS. They are not the same clock, they do
// not expire together, and they produce different state transitions. Conflating
// them is the defect plan/00-SPINE.md S1 names outright.
//
//	ReclaimExpired      drives handoff.lease_expires_at — Options.Lease, 15-30
//	                    minutes, heartbeat-renewed. It governs ONE consumer
//	                    attempt. Expiry means "the holder is presumed dead":
//	                    attempts < max_attempts  -> back to 'ready' (this is
//	                                                the retried-exactly-once
//	                                                guarantee)
//	                    attempts >= max_attempts -> ExhaustedState, terminal
//
//	ExpireClaimTimeouts drives audit_record.deadline_at — scan_run.started_at
//	                    plus claim_timeout_seconds, 8h by default. It governs
//	                    how long an UNCLAIMED finding stays eligible. Expiry
//	                    means 'expired': the tmpfs packet is unlinked, the row
//	                    is KEPT.
//
// Neither ever touches a live claim. ExpireClaimTimeouts only considers rows in
// 'ready', which is what research/08 §4 point 2 requires: "Never expire a live
// claim. A finding at expires_at whose lease is still alive must be allowed to
// finish. Expiring it would let a second agent write a competing fix for the
// same defect." A leased row past its audit deadline reaches 'expired' only
// after its lease lapses and ReclaimExpired returns it to 'ready' — that is the
// long way round, on purpose.
//
// WHAT THE REAPER DOES NOT DO. It deletes no row: not `handoff`, not `finding`,
// not `finding_state_event`. "8 hours" is a claim timeout, not a deletion
// policy and not a confidentiality control. A finding that expires is not lost;
// it is re-presented at the next scheduled scan, so missing the window costs
// latency, not the finding.
//
// It also does not NULL audit_record.payload, although schema.sql's comment
// anticipates "the reaper" doing so. One audit_record fans out to many handoff
// rows: purging the shared payload because ONE finding's claim window lapsed
// would blind every sibling finding still leased against the same record. Per-
// audit payload purging is an audit-record-level sweep keyed on
// audit_record.deadline_at, and it belongs to whoever owns audit_record's
// lifecycle, not to the per-finding queue. Flagged to the orchestrator rather
// than quietly implemented here.

// Reclaimed records one lease that lapsed and what became of the finding.
type Reclaimed struct {
	HandoffID     int64
	Fingerprint   string
	AuditRecordID int64

	// WorkerID is the holder presumed dead.
	WorkerID string

	// To is record.HandoffStateReady when a retry remains, ExhaustedState when
	// none does.
	To record.HandoffState

	// Attempts is the count as it stood when the lease lapsed: attempts
	// STARTED, incremented at claim time, because a consumer that is
	// OOM-killed never gets to count anything itself.
	Attempts    int
	MaxAttempts int

	// LeaseExpiredAt is the lapsed lease_expires_at, kept for the load signal
	// research/08 §4 point 4 asks for.
	LeaseExpiredAt time.Time
}

// Requeued reports whether this reclaim returned the finding to the ready set.
func (r Reclaimed) Requeued() bool { return r.To == record.HandoffStateReady }

// Expired records one finding whose claim window closed before anyone took it.
type Expired struct {
	HandoffID     int64
	Fingerprint   string
	AuditRecordID int64

	// DeadlineAt is audit_record.deadline_at, computed once by R.6 from
	// scan_run.started_at + claim_timeout_seconds and never recomputed. The
	// reaper reads it; it does not derive it, and it does not write it.
	DeadlineAt time.Time

	// PacketDropped is true when a tmpfs packet existed and was unlinked. An
	// unlink is all it is — see DropPacket for why no stronger claim is made.
	PacketDropped bool
}

// ReapReport is one sweep's output. research/08 §4 point 4: "Alert on expiry,
// don't just log it. A nonzero expired rate is the load signal that the coding
// agent is undersized relative to detector throughput." The counts are
// returned rather than logged so a caller can act on them.
type ReapReport struct {
	At        time.Time
	Reclaimed []Reclaimed
	Expired   []Expired
}

// Requeued counts leases that lapsed with a retry still available.
func (r ReapReport) Requeued() int {
	n := 0
	for _, c := range r.Reclaimed {
		if c.Requeued() {
			n++
		}
	}
	return n
}

// Exhausted counts leases that lapsed with no retry left.
func (r ReapReport) Exhausted() int { return len(r.Reclaimed) - r.Requeued() }

// Empty reports whether the sweep changed nothing.
func (r ReapReport) Empty() bool { return len(r.Reclaimed) == 0 && len(r.Expired) == 0 }

// ReclaimExpired sweeps lapsed leases. This is the crash path: a consumer
// acquires a lease, is OOM-killed mid-work, its lease lapses, and this returns
// the finding to the queue for someone else.
//
// It is idempotent in the two senses that matter:
//
//   - Calling it twice changes nothing the second time. Each transition is a
//     compare-and-swap on (state='leased', claimed_by, lease_expires_at); once
//     the row has moved, no second sweep matches it, so attempts cannot be
//     double-incremented and a finding cannot be requeued twice for one crash.
//   - Re-processing after reclaim is safe. The finding keeps its
//     idempotency_key and its audit_version, so the successor's work carries
//     the same (fingerprint, record version) identity the dead holder's did,
//     and the dead holder's own late ReleaseLease is rejected with
//     ErrLeaseLost rather than landing on top of it.
func (q *Queue) ReclaimExpired() (ReapReport, error) {
	return q.ReclaimExpiredContext(context.Background())
}

// ReclaimExpiredContext is ReclaimExpired with a caller-supplied context.
func (q *Queue) ReclaimExpiredContext(ctx context.Context) (ReapReport, error) {
	now := q.Now()
	report := ReapReport{At: now}

	type candidate struct {
		id            int64
		fingerprint   string
		auditRecordID int64
		worker        string
		expiryText    string
		expiry        time.Time
		attempts      int
		maxAttempts   int
	}

	rows, err := q.db.QueryContext(ctx,
		`SELECT h.handoff_id, h.fingerprint, h.audit_record_id, h.claimed_by,
		        h.lease_expires_at, h.attempts, h.max_attempts
		   FROM handoff h
		  WHERE h.state = ?
		  ORDER BY h.handoff_id`, string(record.HandoffStateLeased))
	if err != nil {
		return report, fmt.Errorf("handoff: scanning leases: %w", err)
	}

	var due []candidate
	for rows.Next() {
		var c candidate
		if err := rows.Scan(&c.id, &c.fingerprint, &c.auditRecordID, &c.worker,
			&c.expiryText, &c.attempts, &c.maxAttempts); err != nil {
			_ = rows.Close()
			return report, fmt.Errorf("handoff: scanning leases: %w", err)
		}
		// Expiry is decided here, in Go, against parsed time values — never as
		// a TEXT comparison in SQL, because timestamps in this database are
		// written by several steps and RFC 3339 has more than one spelling of
		// the same instant. See timeLayout.
		c.expiry, err = parseTime("handoff.lease_expires_at", c.expiryText)
		if err != nil {
			_ = rows.Close()
			return report, err
		}
		if now.Before(c.expiry) {
			continue // live claim; leave it entirely alone
		}
		due = append(due, c)
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return report, fmt.Errorf("handoff: scanning leases: %w", err)
	}
	if err := rows.Close(); err != nil {
		return report, fmt.Errorf("handoff: scanning leases: %w", err)
	}

	for _, c := range due {
		to := record.HandoffStateReady
		if c.attempts >= c.maxAttempts {
			to = ExhaustedState
		}
		// CAS on the exact lease. If the holder heartbeat-renewed between the
		// SELECT and here, lease_expires_at no longer matches and the live
		// claim survives untouched — which is the correct outcome, not a lost
		// update.
		res, err := q.db.ExecContext(ctx,
			`UPDATE handoff
			    SET state = ?, claimed_by = NULL, lease_expires_at = NULL, updated_at = ?
			  WHERE handoff_id = ? AND state = ? AND claimed_by = ? AND lease_expires_at = ?`,
			string(to), formatTime(now),
			c.id, string(record.HandoffStateLeased), c.worker, c.expiryText)
		if err != nil {
			return report, fmt.Errorf("handoff: reclaiming row %d: %w", c.id, err)
		}
		n, err := res.RowsAffected()
		if err != nil {
			return report, fmt.Errorf("handoff: reclaiming row %d: %w", c.id, err)
		}
		if n == 0 {
			continue
		}
		if IsTerminal(to) {
			if err := q.DropPacket(c.fingerprint); err != nil {
				return report, err
			}
		}
		report.Reclaimed = append(report.Reclaimed, Reclaimed{
			HandoffID:      c.id,
			Fingerprint:    c.fingerprint,
			AuditRecordID:  c.auditRecordID,
			WorkerID:       c.worker,
			To:             to,
			Attempts:       c.attempts,
			MaxAttempts:    c.maxAttempts,
			LeaseExpiredAt: c.expiry,
		})
	}
	return report, nil
}

// ExpireClaimTimeouts sweeps findings whose claim window closed with nobody
// having taken them: audit_record.deadline_at has passed and the row is still
// 'ready'.
//
// The transition is 'ready' -> 'expired', the tmpfs packet is unlinked, and
// the database row stays exactly where it is. Nothing here deletes a record,
// and nothing here is a confidentiality measure — the same detail lives in the
// store by design, which is why S1 calls this a claim timeout and not a
// deletion policy.
//
// Leased rows are not considered at all. That is how "never expire a live
// claim" is enforced: structurally, by the query, not by a check someone can
// forget.
func (q *Queue) ExpireClaimTimeouts() (ReapReport, error) {
	return q.ExpireClaimTimeoutsContext(context.Background())
}

// ExpireClaimTimeoutsContext is ExpireClaimTimeouts with a caller-supplied
// context.
func (q *Queue) ExpireClaimTimeoutsContext(ctx context.Context) (ReapReport, error) {
	now := q.Now()
	report := ReapReport{At: now}

	type candidate struct {
		id            int64
		fingerprint   string
		auditRecordID int64
		deadline      time.Time
	}

	rows, err := q.db.QueryContext(ctx,
		`SELECT h.handoff_id, h.fingerprint, h.audit_record_id, a.deadline_at
		   FROM handoff h
		   JOIN audit_record a ON a.audit_record_id = h.audit_record_id
		  WHERE h.state = ?
		  ORDER BY h.handoff_id`, string(record.HandoffStateReady))
	if err != nil {
		return report, fmt.Errorf("handoff: scanning claim timeouts: %w", err)
	}

	var due []candidate
	for rows.Next() {
		var (
			c            candidate
			deadlineText string
		)
		if err := rows.Scan(&c.id, &c.fingerprint, &c.auditRecordID, &deadlineText); err != nil {
			_ = rows.Close()
			return report, fmt.Errorf("handoff: scanning claim timeouts: %w", err)
		}
		c.deadline, err = parseTime("audit_record.deadline_at", deadlineText)
		if err != nil {
			_ = rows.Close()
			return report, err
		}
		if now.Before(c.deadline) {
			continue
		}
		due = append(due, c)
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return report, fmt.Errorf("handoff: scanning claim timeouts: %w", err)
	}
	if err := rows.Close(); err != nil {
		return report, fmt.Errorf("handoff: scanning claim timeouts: %w", err)
	}

	for _, c := range due {
		res, err := q.db.ExecContext(ctx,
			`UPDATE handoff SET state = ?, updated_at = ?
			  WHERE handoff_id = ? AND state = ?`,
			string(record.HandoffStateExpired), formatTime(now),
			c.id, string(record.HandoffStateReady))
		if err != nil {
			return report, fmt.Errorf("handoff: expiring row %d: %w", c.id, err)
		}
		n, err := res.RowsAffected()
		if err != nil {
			return report, fmt.Errorf("handoff: expiring row %d: %w", c.id, err)
		}
		if n == 0 {
			// Somebody claimed it in the gap between SELECT and UPDATE. The
			// live claim wins; this finding is not expired.
			continue
		}

		dropped, err := q.dropPacketIfPresent(c.fingerprint)
		if err != nil {
			return report, err
		}
		report.Expired = append(report.Expired, Expired{
			HandoffID:     c.id,
			Fingerprint:   c.fingerprint,
			AuditRecordID: c.auditRecordID,
			DeadlineAt:    c.deadline,
			PacketDropped: dropped,
		})
	}
	return report, nil
}

// dropPacketIfPresent unlinks a packet and reports whether one was there. A
// Queue with no PacketDir has nothing to drop, which is not an error.
func (q *Queue) dropPacketIfPresent(fingerprint string) (bool, error) {
	path, err := q.PacketPath(fingerprint)
	if errors.Is(err, ErrNoPacketDir) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	_, statErr := os.Stat(path)
	if err := q.DropPacket(fingerprint); err != nil {
		return false, err
	}
	return statErr == nil, nil
}

// Reap runs both sweeps, leases first.
//
// The order is load-bearing. A finding whose holder crashed AND whose audit
// deadline has passed must first be reclaimed out of 'leased' — the lease
// sweep is the only thing allowed to touch a leased row — and only then can
// the claim-timeout sweep see it as 'ready' and expire it. Running the sweeps
// in the other order would make a crashed finding wait a whole extra interval
// for no reason.
func (q *Queue) Reap() (ReapReport, error) {
	return q.ReapContext(context.Background())
}

// ReapContext is Reap with a caller-supplied context.
func (q *Queue) ReapContext(ctx context.Context) (ReapReport, error) {
	leases, err := q.ReclaimExpiredContext(ctx)
	if err != nil {
		return leases, err
	}
	timeouts, err := q.ExpireClaimTimeoutsContext(ctx)
	if err != nil {
		return leases, err
	}
	return ReapReport{
		At:        leases.At,
		Reclaimed: leases.Reclaimed,
		Expired:   timeouts.Expired,
	}, nil
}

// Run sweeps every interval until ctx is cancelled, handing each report to
// observe. It returns ctx.Err().
//
// interval <= 0 means DefaultReaperInterval. research/08 §4 states the real
// constraint on the value: "must be <= ttl/8; do NOT rely on tmpfiles' 1d
// timer" — an Age=8h tmpfiles rule fires somewhere between 8h and ~32h after
// creation, so it is a backstop, never the mechanism.
//
// observe may be nil. A sweep error is passed to observe and the loop
// continues: a transient database error must not silently stop the only thing
// that unwedges crashed consumers.
//
// Cancellation is NOT a sweep error. If ctx is cancelled while a sweep is
// mid-query, that query returns context.Canceled, and reporting it to observe
// would put "handoff: scanning leases: context canceled" in the operator's log
// on every single shutdown. That is not a harmless cosmetic difference: the
// whole value of reporting sweep errors is that a real one gets noticed, and a
// channel that cries wolf on every restart is a channel nobody reads. So an
// interrupted sweep returns ctx.Err() and stays silent.
//
// Found by CI, not locally: the race detector slows execution enough to widen
// the cancel-during-sweep window from rare to reliable. It reproduced on
// ubuntu-latest under -race while passing every run on the Windows dev host,
// which is precisely why -race is a required check rather than an optional one.
func (q *Queue) Run(ctx context.Context, interval time.Duration, observe func(ReapReport, error)) error {
	if interval <= 0 {
		interval = DefaultReaperInterval
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			report, err := q.ReapContext(ctx)
			// Both conditions are required. ctx.Err() alone would swallow a
			// genuine database failure that happened to land in the same
			// instant as a shutdown; errors.Is alone would swallow a
			// context.Canceled arriving from some caller-supplied context
			// nested inside the sweep, which IS a real fault worth reporting.
			if err != nil && ctx.Err() != nil &&
				(errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded)) {
				return ctx.Err()
			}
			if observe != nil {
				observe(report, err)
			}
		}
	}
}
