// Package handoff implements the claim/lease protocol for the single
// `handoff` table defined by internal/store/schema.sql (step R.4).
//
// WHAT THIS PACKAGE IS, AND WHY THERE IS ONLY ONE OF IT.
// plan/IMPLEMENTATION-PLAN.md §6 ruling G9: "Area 40 owns the table and the
// claim/lease protocol." O.3 no longer writes a migration and no longer
// defines a second lease API — internal/scanctl/handoff.go becomes a thin
// adapter over this package. So this package deliberately serves both shapes
// the plan asks for, over one table and one state column:
//
//   - R.7's packet shape:  Claim(fingerprint, workerID) (Handle, error),
//     returning ErrAlreadyClaimed on a losing race.
//   - O.3's lease shape:   AcquireLease / RenewLease / ReleaseLease /
//     ReclaimExpired.
//
// Claim is AcquireLease narrowed to one fingerprint. They share one query,
// one CAS update and one state machine; there is no second code path and no
// second notion of "claimed".
//
// TWO CLOCKS, NEVER CONFLATED (plan/00-SPINE.md S1, research/08 §4).
//
//	handoff.lease_expires_at            15–30 min (Options.Lease, default 20m),
//	                                    heartbeat-renewed, governs ONE consumer
//	                                    attempt. Expiry is handled by
//	                                    ReclaimExpired: requeue or exhaust.
//	audit_record.claim_timeout_seconds  default 8h, already materialised by R.6
//	                                    as audit_record.deadline_at. It governs
//	                                    how long an UNCLAIMED finding stays
//	                                    eligible. Expiry is handled by
//	                                    ExpireClaimTimeouts: state 'expired',
//	                                    tmpfs packet unlinked, ROW KEPT.
//
// "8 hours" is a CLAIM TIMEOUT. It is not a deletion policy and it is not a
// confidentiality control (S1, and research/08 §A: "the same exploitable
// detail persists in the database indefinitely by design"). Nothing in this
// package deletes a `handoff`, `finding` or `finding_state_event` row, and
// nothing in it claims that unlinking a packet destroys anything beyond the
// link itself — see DropPacket for why no stronger claim would be true.
//
// WHAT A LEASE GRANTS (plan/00-SPINE.md S7). "May act on this finding", and
// nothing else. It is not merge authority, not widened scope, and not a
// verdict.
//
// "Only a DAST reproduction that now fails earns 'verified fixed'" is
// enforced HERE, not deferred to an unnamed elsewhere: ReleaseLease refuses
// HandoffStateValidated for a requires_dynamic_confirmation finding whose
// audit's DAST half produced no reproduction, with ErrNoDynamicEvidence. See
// checkDynamicEvidence in claim.go for the per-status reasoning. `validated`
// is written into this table by the claimant, so this is the only place the
// rule can be enforced rather than described.
//
// WHAT ARBITRATES A CLAIM, AND A DELIBERATE DEVIATION FROM THE PACKET TEXT.
// The R.7 packet names `renameat2(..., RENAME_NOREPLACE)` and OFD locks as the
// claim primitives. This implementation arbitrates the claim with a single
// conditional UPDATE against `handoff` instead, for three reasons:
//
//  1. research/08's own Recommendation §1 makes SQLite the buffer ("mechanism
//     #5, primary pick") and the file queue "the file-facing veneer over #5".
//     A rename-arbitrated claim plus a `state` column is two sources of truth
//     for one fact — exactly the defect §6 G9/G10 closed when they deleted the
//     second table.
//  2. renameat2 and F_OFD_SETLK have no binding in the standard library.
//     Reaching them needs golang.org/x/sys, which is an indirect dependency
//     today; promoting it is a go.mod edit this packet may not make.
//  3. SQLite serialises writers, so `UPDATE ... WHERE state = 'ready'` has the
//     property RENAME_NOREPLACE was wanted for: exactly one caller sees one
//     affected row, every other caller sees zero and gets ErrAlreadyClaimed.
//
// The Forbidden action that matters is honoured absolutely: this package takes
// no classic fcntl record locks anywhere — not one — so the
// close()-drops-all-locks footgun documented at research/08 §D cannot occur.
// The tmpfs packet is still written by research/08 §C's durable recipe
// (exclusive temp file in the same directory, fsync, rename, fsync parent) and
// never relies on ext4's auto_da_alloc; see WritePacket.
package handoff

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/Susquehanna-Syntax/Anvil/internal/record"
)

// DefaultLease is research/08 §4's `buffer.lease`: 15–30 minutes with
// heartbeat renewal, never 8 hours. "An 8-hour lease means a crashed agent
// blocks a finding for a whole shift."
const DefaultLease = 20 * time.Minute

// DefaultMaxAttempts is research/08 §4's `buffer.max_attempts`: 2, i.e. one
// retry after one crash. It matches schema.sql's own column default.
const DefaultMaxAttempts = 2

// DefaultReaperInterval is research/08 §4's `buffer.reaper_interval`. The
// constraint it satisfies is stated there: "must be <= ttl/8; do NOT rely on
// tmpfiles' 1d timer".
const DefaultReaperInterval = 5 * time.Minute

// ExhaustedState is where a finding lands when its lease expires for the last
// time — attempts have reached max_attempts and no retry remains.
//
// The thirteen handoff.state literals are frozen by §6 and contain no generic
// `failed`; research/08's pseudocode says `state='failed'` because it was
// written before the enum was frozen. Of the two failure literals that do
// exist, HandoffStateFailedFormat is specifically a defect in the packet's
// format, which a crashed consumer is not. So an exhausted attempt is recorded
// as HandoffStateFailedValidation: the attempt did not produce a validated
// fix. This is a mapping decision, made once, here, rather than at each call
// site.
const ExhaustedState = record.HandoffStateFailedValidation

// timeLayout is the on-disk timestamp format for every column this package
// writes. It is fixed-width on purpose.
//
// time.RFC3339Nano trims trailing zeros from the fractional part, which makes
// it non-monotonic under lexicographic comparison: "10:00:00Z" sorts AFTER
// "10:00:00.5Z" because 'Z' > '.'. Any SQL that compared lease deadlines as
// TEXT with that format would silently mis-order them. This package does not
// rely on that either way — every expiry decision is made in Go against parsed
// time.Time values (see parseTime) — but it writes a format that would also be
// correct if someone later added an index range scan.
const timeLayout = "2006-01-02T15:04:05.000000000Z"

// formatTime renders t for storage: UTC, fixed width, RFC 3339 parseable.
func formatTime(t time.Time) string { return t.UTC().Format(timeLayout) }

// parseTime reads a stored timestamp. It accepts any RFC 3339 spelling, not
// just timeLayout's, because audit_record.deadline_at is written by R.6 and
// schema_migration.applied_at by R.5; this package must read their formats
// without dictating them.
func parseTime(field, s string) (time.Time, error) {
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return time.Time{}, fmt.Errorf("handoff: %s is not an RFC 3339 timestamp: %w", field, err)
	}
	return t.UTC(), nil
}

// Sentinel errors. Callers distinguish these; the text is not an interface.
var (
	// ErrAlreadyClaimed is returned to the loser of a claim race, and to any
	// caller asking for a finding another worker currently holds.
	ErrAlreadyClaimed = errors.New("handoff: finding is already claimed")

	// ErrNotFound means no handoff row exists for the identifier given.
	ErrNotFound = errors.New("handoff: no such handoff row")

	// ErrNoWork means the ready set is empty or nothing in it has passed its
	// consumption gate yet. It is not an error condition; it is "idle".
	ErrNoWork = errors.New("handoff: no claimable finding")

	// ErrNotEligible means the row exists and is ready, but its consumption
	// gate is shut: research/21 §5's static_only findings wait on the SAST
	// half, requires_dynamic_confirmation findings wait on the DAST half.
	ErrNotEligible = errors.New("handoff: finding has not passed its consumption gate")

	// ErrExhausted means the row is ready but has already burned every
	// attempt, so re-leasing it would loop forever.
	ErrExhausted = errors.New("handoff: finding has exhausted its attempts")

	// ErrLeaseLost means the Handle no longer describes the row: the lease
	// expired and was reclaimed, another worker holds it now, or it was
	// disposed of. A consumer that gets this MUST NOT apply its work — this is
	// the guard that stops an OOM-killed consumer's late write from landing on
	// top of its successor's.
	ErrLeaseLost = errors.New("handoff: lease is no longer held")

	// ErrRecordVersionChanged means audit_record.audit_version moved under the
	// lease. Per plan/00-SPINE.md S6 a version bump re-cuts the work queue, so
	// the work unit the Handle describes no longer exists. It implies
	// ErrLeaseLost.
	ErrRecordVersionChanged = errors.New("handoff: audit record version changed under the lease")

	// ErrIllegalTransition is the class of every rejected state change; see
	// TransitionError.
	ErrIllegalTransition = errors.New("handoff: illegal state transition")

	// ErrNoDynamicEvidence means a requires_dynamic_confirmation finding was
	// released as 'validated' on an audit whose DAST half produced no
	// reproduction. plan/00-SPINE.md S7: only a DAST reproduction that now
	// FAILS earns "verified fixed"; a clean static rescan does not. See
	// checkDynamicEvidence.
	ErrNoDynamicEvidence = errors.New("handoff: 'validated' requires dynamic evidence for this finding")
)

// TransitionError reports a state change the machine forbids.
type TransitionError struct {
	From record.HandoffState
	To   record.HandoffState
}

func (e *TransitionError) Error() string {
	return fmt.Sprintf("handoff: illegal state transition %q -> %q", e.From, e.To)
}

// Is makes errors.Is(err, ErrIllegalTransition) true for every TransitionError.
func (e *TransitionError) Is(target error) bool { return target == ErrIllegalTransition }

// legalTransitions is the whole state machine. Every one of the thirteen
// frozen handoff.state literals is a key; the terminal ones map to nothing,
// which is what makes them terminal. handoff_test.go asserts key coverage
// against record.HandoffStateValues() so a future enum addition cannot land
// here as a silent hole.
//
// Two edges are absent on purpose:
//
//   - leased -> expired. research/08 §4 point 2: "Never expire a live claim. A
//     finding at expires_at whose lease is still alive must be allowed to
//     finish. Expiring it would let a second agent write a competing fix for
//     the same defect." A leased row reaches 'expired' only the long way:
//     ReclaimExpired returns it to 'ready' first.
//   - anything -> ready from a terminal state. Terminal is terminal. Re-cutting
//     a superseded finding creates a NEW row for the new audit_record, which is
//     what UNIQUE (finding_id, audit_record_id) is shaped for.
var legalTransitions = map[record.HandoffState][]record.HandoffState{
	record.HandoffStateReady: {
		record.HandoffStateLeased,
		record.HandoffStateExpired,
		record.HandoffStateSkippedBudget,
		record.HandoffStateFalsePositive,
		record.HandoffStateFixedIncidentally,
		record.HandoffStateSplitRequired,
		record.HandoffStateWithdrawn,
		record.HandoffStateSuperseded,
	},
	record.HandoffStateLeased: {
		record.HandoffStateReady,
		record.HandoffStateValidated,
		record.HandoffStateFailedValidation,
		record.HandoffStateFailedFormat,
		record.HandoffStateRegressionIntroduced,
		record.HandoffStateSkippedBudget,
		record.HandoffStateFalsePositive,
		record.HandoffStateFixedIncidentally,
		record.HandoffStateSplitRequired,
		record.HandoffStateWithdrawn,
		record.HandoffStateSuperseded,
	},
	record.HandoffStateValidated:            nil,
	record.HandoffStateFailedValidation:     nil,
	record.HandoffStateFailedFormat:         nil,
	record.HandoffStateSkippedBudget:        nil,
	record.HandoffStateFalsePositive:        nil,
	record.HandoffStateRegressionIntroduced: nil,
	record.HandoffStateFixedIncidentally:    nil,
	record.HandoffStateSplitRequired:        nil,
	record.HandoffStateWithdrawn:            nil,
	record.HandoffStateSuperseded:           nil,
	record.HandoffStateExpired:              nil,
}

// LegalTransitions returns a copy of the state machine, keyed by source state.
func LegalTransitions() map[record.HandoffState][]record.HandoffState {
	out := make(map[record.HandoffState][]record.HandoffState, len(legalTransitions))
	for from, to := range legalTransitions {
		out[from] = append([]record.HandoffState(nil), to...)
	}
	return out
}

// CanTransition reports whether from -> to is legal.
func CanTransition(from, to record.HandoffState) bool {
	for _, candidate := range legalTransitions[from] {
		if candidate == to {
			return true
		}
	}
	return false
}

// CheckTransition returns nil if from -> to is legal, a *TransitionError
// otherwise. An unknown literal on either side is rejected by
// record.ValidateHandoffState first, so a typo cannot masquerade as a state.
func CheckTransition(from, to record.HandoffState) error {
	if err := record.ValidateHandoffState(string(from)); err != nil {
		return err
	}
	if err := record.ValidateHandoffState(string(to)); err != nil {
		return err
	}
	if !CanTransition(from, to) {
		return &TransitionError{From: from, To: to}
	}
	return nil
}

// IsTerminal reports whether s admits no further transition. 'ready' and
// 'leased' are the only live states; the other eleven are terminal.
func IsTerminal(s record.HandoffState) bool {
	return s.Valid() && len(legalTransitions[s]) == 0
}

// IsLive reports whether s is a state the queue still works on.
func IsLive(s record.HandoffState) bool {
	return s == record.HandoffStateReady || s == record.HandoffStateLeased
}

// Options configures a Queue. The zero value is usable: every field falls back
// to the Default* constant above, which are research/08 §4's configuration
// keys and not magic numbers invented here.
type Options struct {
	// Lease is `buffer.lease` — how long one consumer attempt may hold a
	// finding before ReclaimExpired presumes the holder dead.
	Lease time.Duration

	// MaxAttempts is `buffer.max_attempts` for rows this Queue enqueues. Each
	// row carries its own handoff.max_attempts; this is only the default
	// written at insert time.
	MaxAttempts int

	// PacketDir is the tmpfs directory holding regenerable packets, e.g.
	// systemd's RuntimeDirectory=anvil. Empty disables packet materialisation
	// entirely, which is legal: the packet is a cache, never a source of
	// truth, and research/08 §1 says so ("if it vanishes, regenerate it from
	// the DB").
	PacketDir string

	// Clock is injectable so the lease clock and the claim-timeout clock can
	// be driven independently in tests. nil means time.Now.
	Clock func() time.Time
}

func (o Options) lease() time.Duration {
	if o.Lease <= 0 {
		return DefaultLease
	}
	return o.Lease
}

func (o Options) maxAttempts() int {
	if o.MaxAttempts <= 0 {
		return DefaultMaxAttempts
	}
	return o.MaxAttempts
}

// Queue is the claim/lease protocol over the `handoff` table. It is safe for
// concurrent use: every mutation is a single conditional UPDATE and SQLite
// serialises writers.
type Queue struct {
	db   *sql.DB
	opts Options
}

// New returns a Queue over an already-migrated store. It does not create,
// alter or migrate any table: internal/store/schema.sql owns `handoff` and
// declares itself a frozen interface (§6 G9).
func New(db *sql.DB, opts Options) (*Queue, error) {
	if db == nil {
		return nil, errors.New("handoff: New requires a non-nil *sql.DB")
	}
	if opts.Clock == nil {
		opts.Clock = time.Now
	}
	return &Queue{db: db, opts: opts}, nil
}

// Now is the Queue's clock, in UTC.
func (q *Queue) Now() time.Time { return q.opts.Clock().UTC() }

// Lease reports the configured claim-lease duration.
func (q *Queue) Lease() time.Duration { return q.opts.lease() }

// Row is one `handoff` row, read back.
type Row struct {
	HandoffID        int64
	FindingID        int64
	AuditRecordID    int64
	Fingerprint      string
	GroupID          string
	State            record.HandoffState
	ConsumptionClass record.ConsumptionClass
	ClaimedBy        string
	LeaseExpiresAt   time.Time // zero when not leased
	Attempts         int
	MaxAttempts      int
	IdempotencyKey   string
	CreatedAt        time.Time
	UpdatedAt        time.Time
}

// AttemptsRemaining reports how many further leases the row may be granted.
func (r Row) AttemptsRemaining() int {
	if r.Attempts >= r.MaxAttempts {
		return 0
	}
	return r.MaxAttempts - r.Attempts
}

// rowColumns is qualified with the alias `h` because several of these names —
// `state` above all — also exist on audit_record, which the eligibility query
// joins. An unqualified `state` there would be ambiguous at best and silently
// the wrong table's at worst, so every query in this package aliases handoff
// as h and selects through this constant.
const rowColumns = `h.handoff_id, h.finding_id, h.audit_record_id, h.fingerprint, h.group_id, h.state,
	h.consumption_class, h.claimed_by, h.lease_expires_at, h.attempts, h.max_attempts,
	h.idempotency_key, h.created_at, h.updated_at`

type rowScanner interface {
	Scan(dest ...any) error
}

func scanRow(sc rowScanner) (Row, error) {
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
	)
	if err := sc.Scan(
		&r.HandoffID, &r.FindingID, &r.AuditRecordID, &r.Fingerprint, &groupID, &state,
		&class, &claimedBy, &leaseExpiry, &r.Attempts, &r.MaxAttempts,
		&idemKey, &createdAt, &updatedAt,
	); err != nil {
		return Row{}, err
	}
	// The literals come out of the database, so they are validated on the way
	// in rather than trusted: a row written by an older binary, or by hand,
	// must not put an unknown state into the state machine.
	if err := record.ValidateHandoffState(state); err != nil {
		return Row{}, fmt.Errorf("handoff: row %d: %w", r.HandoffID, err)
	}
	if err := record.ValidateConsumptionClass(class); err != nil {
		return Row{}, fmt.Errorf("handoff: row %d: %w", r.HandoffID, err)
	}
	r.State = record.HandoffState(state)
	r.ConsumptionClass = record.ConsumptionClass(class)
	r.GroupID = groupID.String
	r.ClaimedBy = claimedBy.String
	r.IdempotencyKey = idemKey.String

	var err error
	if leaseExpiry.Valid {
		if r.LeaseExpiresAt, err = parseTime("handoff.lease_expires_at", leaseExpiry.String); err != nil {
			return Row{}, err
		}
	}
	if r.CreatedAt, err = parseTime("handoff.created_at", createdAt); err != nil {
		return Row{}, err
	}
	if r.UpdatedAt, err = parseTime("handoff.updated_at", updatedAt); err != nil {
		return Row{}, err
	}
	return r, nil
}

// Get returns one row by primary key. It reports ErrNotFound, never a
// zero-value Row, when the row is absent.
func (q *Queue) Get(handoffID int64) (Row, error) {
	return q.GetContext(context.Background(), handoffID)
}

// GetContext is Get with a caller-supplied context.
func (q *Queue) GetContext(ctx context.Context, handoffID int64) (Row, error) {
	r, err := scanRow(q.db.QueryRowContext(ctx,
		`SELECT `+rowColumns+` FROM handoff h WHERE h.handoff_id = ?`, handoffID))
	if errors.Is(err, sql.ErrNoRows) {
		return Row{}, fmt.Errorf("handoff: id %d: %w", handoffID, ErrNotFound)
	}
	if err != nil {
		return Row{}, fmt.Errorf("handoff: reading row %d: %w", handoffID, err)
	}
	return r, nil
}

// Find returns every handoff row carrying a fingerprint, newest audit record
// first. A fingerprint is not unique in this table — it is denormalised for
// the reaper's WHERE clause, and one finding legitimately has one row per
// audit record it appears in.
func (q *Queue) Find(fingerprint string) ([]Row, error) {
	return q.FindContext(context.Background(), fingerprint)
}

// FindContext is Find with a caller-supplied context.
func (q *Queue) FindContext(ctx context.Context, fingerprint string) ([]Row, error) {
	if err := ValidateFingerprint(fingerprint); err != nil {
		return nil, err
	}
	rows, err := q.db.QueryContext(ctx,
		`SELECT `+rowColumns+` FROM handoff h WHERE h.fingerprint = ?
		 ORDER BY h.audit_record_id DESC, h.handoff_id DESC`, fingerprint)
	if err != nil {
		return nil, fmt.Errorf("handoff: querying fingerprint %s: %w", fingerprint, err)
	}
	defer func() { _ = rows.Close() }()

	var out []Row
	for rows.Next() {
		r, err := scanRow(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("handoff: querying fingerprint %s: %w", fingerprint, err)
	}
	return out, nil
}

// EnqueueRequest describes one finding entering the ready set.
type EnqueueRequest struct {
	FindingID     int64
	AuditRecordID int64

	// AuditID is `anvil/auditId`, the audit's own identity as assigned at scan
	// start — NOT the `audit_record_id` rowid. It is required, because it is
	// the first component of IdempotencyKey and the key is what the coding
	// agent writes into a git trailer; a rowid there would be a value no other
	// process can interpret (CRITIQUE-02 F7).
	//
	// It is supplied by the caller rather than read from the store because
	// `audit_record` has no column for it. That gap is reported to the
	// orchestrator: until schema.sql carries an `audit_id`, the key cannot be
	// re-derived from the database alone, only recomputed by whoever still
	// holds the record.
	AuditID string

	// Fingerprint is the full 64-hex anvil-fp/v1 digest, never truncated
	// (internal/record/FINGERPRINT-SPEC.md, and ck_handoff_fingerprint_hex).
	Fingerprint string

	// ConsumptionClass gates the finding. It has no default here for the same
	// reason schema.sql gives it no column default: a default would silently
	// grant every row the permissive value.
	ConsumptionClass record.ConsumptionClass

	// GroupID is the fix-group id, assigned by the consumption pipeline.
	// Optional.
	GroupID string

	// MaxAttempts overrides Options.MaxAttempts for this row.
	MaxAttempts int
}

// Enqueue inserts one finding into the ready set and returns the resulting
// row. It is idempotent: re-enqueueing the same (finding_id, audit_record_id)
// returns the existing row unchanged rather than failing or duplicating, so a
// crashed producer that re-runs cannot double-enqueue.
func (q *Queue) Enqueue(req EnqueueRequest) (Row, error) {
	return q.EnqueueContext(context.Background(), req)
}

// EnqueueContext is Enqueue with a caller-supplied context.
func (q *Queue) EnqueueContext(ctx context.Context, req EnqueueRequest) (Row, error) {
	if err := ValidateFingerprint(req.Fingerprint); err != nil {
		return Row{}, err
	}
	if err := record.ValidateConsumptionClass(string(req.ConsumptionClass)); err != nil {
		return Row{}, err
	}
	if req.AuditID == "" {
		return Row{}, errors.New(
			"handoff: Enqueue requires anvil/auditId; the idempotency key is " +
				"sha256(audit_id || finding_fingerprint || base_commit_sha) and audit_record_id is a rowid, not an audit identity")
	}
	maxAttempts := req.MaxAttempts
	if maxAttempts <= 0 {
		maxAttempts = q.opts.maxAttempts()
	}

	// The idempotency key mirrors the git trailer the coding agent writes, so
	// the same unit of work is recognisable on both sides of a crash. Its
	// definition is schema.sql's, quoted: sha256(audit_id || finding_fingerprint
	// || base_commit_sha).
	var commitSHA sql.NullString
	err := q.db.QueryRowContext(ctx,
		`SELECT s.commit_sha FROM audit_record a
		 JOIN scan_run s ON s.scan_run_id = a.scan_run_id
		 WHERE a.audit_record_id = ?`, req.AuditRecordID).Scan(&commitSHA)
	if errors.Is(err, sql.ErrNoRows) {
		return Row{}, fmt.Errorf("handoff: audit_record %d: %w", req.AuditRecordID, ErrNotFound)
	}
	if err != nil {
		return Row{}, fmt.Errorf("handoff: reading base commit for audit_record %d: %w", req.AuditRecordID, err)
	}
	key := IdempotencyKey(req.AuditID, req.Fingerprint, commitSHA.String)

	now := formatTime(q.Now())
	var groupID any
	if req.GroupID != "" {
		groupID = req.GroupID
	}
	if _, err := q.db.ExecContext(ctx,
		`INSERT INTO handoff
		   (finding_id, audit_record_id, fingerprint, group_id, state, consumption_class,
		    attempts, max_attempts, idempotency_key, created_at, updated_at)
		 VALUES (?, ?, ?, ?, ?, ?, 0, ?, ?, ?, ?)
		 ON CONFLICT DO NOTHING`,
		req.FindingID, req.AuditRecordID, req.Fingerprint, groupID,
		string(record.HandoffStateReady), string(req.ConsumptionClass),
		maxAttempts, key, now, now,
	); err != nil {
		return Row{}, fmt.Errorf("handoff: enqueueing finding %d: %w", req.FindingID, err)
	}

	r, err := scanRow(q.db.QueryRowContext(ctx,
		`SELECT `+rowColumns+` FROM handoff h WHERE h.finding_id = ? AND h.audit_record_id = ?`,
		req.FindingID, req.AuditRecordID))
	if errors.Is(err, sql.ErrNoRows) {
		// ON CONFLICT DO NOTHING swallowed a conflict on some OTHER unique
		// key — idempotency_key is UNIQUE across the whole table. Say so
		// instead of returning a confusing "not found".
		return Row{}, fmt.Errorf(
			"handoff: enqueueing finding %d into audit_record %d inserted nothing and no such row exists; "+
				"idempotency key %s is already held by a different row",
			req.FindingID, req.AuditRecordID, key)
	}
	if err != nil {
		return Row{}, fmt.Errorf("handoff: reading back enqueued finding %d: %w", req.FindingID, err)
	}
	return r, nil
}

// Dispose moves a READY row straight to a terminal state, without a lease.
// It is how the triage gate records 'false_positive', how the queue re-cut
// records 'skipped_budget', 'withdrawn' and 'superseded', and how a finding
// fixed by someone else's patch records 'fixed_incidentally'.
//
// A leased row is not disposable this way — ReleaseLease is the only exit from
// 'leased', because only the lease holder may decide the outcome of its own
// attempt.
func (q *Queue) Dispose(handoffID int64, to record.HandoffState) error {
	return q.DisposeContext(context.Background(), handoffID, to)
}

// DisposeContext is Dispose with a caller-supplied context.
func (q *Queue) DisposeContext(ctx context.Context, handoffID int64, to record.HandoffState) error {
	if err := CheckTransition(record.HandoffStateReady, to); err != nil {
		return err
	}
	if to == record.HandoffStateLeased {
		return &TransitionError{From: record.HandoffStateReady, To: to}
	}
	res, err := q.db.ExecContext(ctx,
		`UPDATE handoff SET state = ?, updated_at = ? WHERE handoff_id = ? AND state = ?`,
		string(to), formatTime(q.Now()), handoffID, string(record.HandoffStateReady))
	if err != nil {
		return fmt.Errorf("handoff: disposing row %d as %s: %w", handoffID, to, err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("handoff: disposing row %d as %s: %w", handoffID, to, err)
	}
	if n == 1 {
		return nil
	}

	current, err := q.GetContext(ctx, handoffID)
	if err != nil {
		return err
	}
	if current.State == record.HandoffStateLeased {
		return fmt.Errorf("handoff: row %d is leased by %q: %w", handoffID, current.ClaimedBy, ErrAlreadyClaimed)
	}
	return &TransitionError{From: current.State, To: to}
}

// IdempotencyKey computes schema.sql's `handoff.idempotency_key`:
// sha256(audit_id || finding_fingerprint || base_commit_sha), hex. It is
// exported because the coding agent writes the same value into a git trailer,
// and the two must be computed the same way or the trailer proves nothing.
//
// auditID IS `anvil/auditId`, NOT `audit_record.audit_record_id`. That
// distinction is the whole of CRITIQUE-02 F7: this function used to hash the
// autoincrement rowid, which is not the audit identity by any definition. The
// consequences were concrete — the exported value "the coding agent writes into
// a git trailer" was an internal database rowid, which is not a portable
// identity and means nothing outside one copy of one database file, and two
// competing leases on one finding carried DIFFERENT keys, so the downstream
// duplicate-suppression the Handle doc promises could not have caught the
// double grant either.
//
// The components are joined by a NUL byte so that no two different triples can
// produce the same input string by shifting a boundary.
func IdempotencyKey(auditID, fingerprint, baseCommitSHA string) string {
	h := sha256.New()
	h.Write([]byte(auditID))
	h.Write([]byte{0})
	h.Write([]byte(fingerprint))
	h.Write([]byte{0})
	h.Write([]byte(baseCommitSHA))
	return hex.EncodeToString(h.Sum(nil))
}

// ValidateFingerprint enforces the same shape ck_handoff_fingerprint_hex
// enforces: 64 lowercase hex characters, never truncated. It runs before any
// fingerprint reaches a query or a packet path, so a malformed value fails
// here rather than as a constraint violation or a traversed path.
func ValidateFingerprint(fp string) error {
	if len(fp) != 64 {
		return fmt.Errorf("handoff: fingerprint %q is %d characters, want 64 (anvil-fp/v1 digests are never truncated)", fp, len(fp))
	}
	if strings.ToLower(fp) != fp {
		return fmt.Errorf("handoff: fingerprint %q must be lowercase hex", fp)
	}
	if _, err := hex.DecodeString(fp); err != nil {
		return fmt.Errorf("handoff: fingerprint %q is not hex: %w", fp, err)
	}
	return nil
}
