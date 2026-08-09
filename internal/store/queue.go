// The queue re-cut rule (step R.11).
//
// plan/00-SPINE.md S6, in full, because the second half is the part that gets
// lost: "re-cut the work queue on every version bump and **reserve a
// configurable fraction (default 50%) of remaining budget for late
// DAST-confirmed arrivals** — otherwise incremental publication silently
// inverts the priority scheme, because nothing is DAST-confirmed when the
// queue is first cut."
//
// WHY THE RESERVATION IS NOT REDUNDANT WITH RANKING. Within a single cut the
// reservation buys nothing: `dast_confirmed` is the first component of
// research/24 step 7's rank_key, so a cut that sorts by rank already puts the
// proof-carrying findings first. The reservation exists because **a cut is a
// commitment across time**, and DAST runs after SAST. At the first cut the DAST
// half has not concluded, so `evidence_class = 'dast_confirmed'` matches zero
// rows; ranking has nothing to rank. A cut with no reservation therefore
// commits the entire budget to unconfirmed static findings, and when the DAST
// half seals and its confirmed findings are enqueued at the next version, the
// re-cut finds a budget that is already spent. The highest-value findings in
// the audit — the only ones carrying a working reproduction — become
// `skipped_budget`, i.e. *found, not fixed*, while 24%-precision static alarms
// (research/24 Table 3, 105 TP / 433 alarms) get the whole window. That is the
// inversion, and queue_test.go's TestRecutInvertsPriorityWithoutReservation
// reproduces it end to end rather than asserting that a float equals 0.5.
//
// The reservation is a FLOOR FOR dast_confirmed, NOT A CEILING. A cut holds
// back `fraction * remaining` and refuses to let any other evidence class draw
// on it; `dast_confirmed` rows draw on the reserve first and on the open
// budget after. Nothing is capped, and nothing is spent on a class that does
// not exist yet.
//
// WHAT THIS FILE DOES NOT DO — the CRITIQUE-02 §7 open question, decided.
// §7 records as unresolved "whether R.11's queue re-cut is intended to
// Dispose(..., superseded) every stale row of a bumped audit". IT IS NOT.
// A re-cut never touches a `leased` row, and never writes `superseded`.
// Reasons, in the order they are load-bearing:
//
//  1. internal/handoff already makes a stale lease inert. checkRecordVersion
//     runs on RenewLease, ReleaseLease and the packet gate, so a Handle taken
//     at audit_version N cannot renew, cannot record any disposition, and
//     cannot read or write its packet once the version moves to N+1. It gets
//     ErrRecordVersionChanged. The lease therefore cannot be extended, expires
//     on its own clock, and ReclaimExpired — the ONE component authorised to
//     touch a lease it does not hold — returns the row to 'ready' or exhausts
//     it. The row rejoins the candidate set of the *next* cut with no action
//     from here. The guard is sufficient because it guards the writes, which
//     is where a stale version can do damage, rather than the row state, where
//     it cannot.
//  2. Doing otherwise would expire a live claim. research/08 §4 point 2:
//     "Never expire a live claim. A finding at expires_at whose lease is still
//     alive must be allowed to finish. Expiring it would let a second agent
//     write a competing fix for the same defect." CRITIQUE-02 verdict (e)
//     ("reaper never drops a live claim") is a PASS that a re-cut yanking
//     leased rows would turn into a FAIL, and R.7's noSiblingLease invariant —
//     one live lease per (fingerprint, audit_version) — is defended by
//     refusing a SECOND grant, not by cancelling the first.
//  3. It is not expressible without fighting the owner. handoff.Dispose
//     refuses a leased row on purpose ("only the lease holder may decide the
//     outcome of its own attempt"), and internal/store cannot call into
//     internal/handoff at all: handoff imports store, so the edge only runs
//     one way. A raw-SQL back door here would make internal/store a second
//     writer to the lease protocol, which is the defect class
//     plan/IMPLEMENTATION-PLAN.md §6 G9 and G10 exist to prevent.
//  4. `superseded` is the wrong verb for this actor. A re-cut is a BUDGET
//     decision and its only disposition is `skipped_budget` (research/24 step
//     9: "everything past the cut is marked SKIPPED_BUDGET and goes into the
//     report as *found, not fixed* — never silently dropped"). Deciding that a
//     version bump made a finding obsolete is a correlation judgement about
//     identity, which belongs to R.12, not to the component that divides
//     tokens.
//
// A row this file defers is 'ready' -> 'skipped_budget', which is a legal edge
// of internal/handoff's state machine and is terminal there. That is deliberate
// and it is why a re-cut can only ever narrow the admitted set: the machine has
// no 'skipped_budget' -> 'ready' edge ("Terminal is terminal"), so a later cut
// with a larger budget cannot re-admit a row it already deferred. The cut is
// consequently monotone, which is also what makes it safe to repeat.

package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"math"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Susquehanna-Syntax/Anvil/internal/record"
)

// DefaultDastReserveFraction is the documented default for
// RecutConfig.DastReserveFraction: plan/00-SPINE.md S6's "configurable
// fraction (default 50%)".
//
// It is a DEFAULT, not the value. RecutConfig carries the configured fraction
// and queue_test.go proves the arithmetic changes when the configuration
// changes, because a constant that is read from exactly one place is
// indistinguishable from a hardcoded one.
const DefaultDastReserveFraction = 0.5

// DefaultTokensPerCandidate is the default per-finding charge against the
// budget, in prompt tokens.
//
// research/24-coding-agent-consumption.md Table 4 derives the 8-hour window's
// throughput from a 10,000-token prompt per fix group, and step 12 of the same
// document asserts a hard ceiling of 12,000 with SPLIT_REQUIRED above 16,000.
// 10,000 is that document's own working figure and it is stated there to be
// arithmetic rather than measurement, so it is a configurable default here.
//
// It is per CANDIDATE, not per fix group. Grouping (research/24 step 8:
// same file, same enclosing symbol, capped at 5 findings) happens downstream
// of this file and would only ever make the true cost LOWER, so charging per
// finding is the conservative direction: a cut errs toward deferring work, not
// toward overcommitting the window.
const DefaultTokensPerCandidate = 10000

var (
	// ErrNoSuchAudit means the audit id did not resolve to an audit_record row.
	ErrNoSuchAudit = errors.New("store: no such audit record")

	// ErrInvalidReserveFraction means a configured reserve fraction is outside
	// [0, 1] or is not a number. A fraction above 1 would reserve more than the
	// whole remaining budget, which silently starves every class at once.
	ErrInvalidReserveFraction = errors.New("store: DAST reserve fraction must be in [0, 1]")

	// ErrInvalidBudget means a negative remaining budget was passed. Zero is
	// legal and means "the window is spent"; negative is a caller bug and
	// clamping it would hide the caller's arithmetic error inside a component
	// whose whole job is arithmetic.
	ErrInvalidBudget = errors.New("store: remaining budget must not be negative")
)

// ReserveFraction boxes a fraction for RecutConfig.DastReserveFraction.
//
// The field is a pointer precisely so that 0 is expressible. A plain float64
// with "zero means default" would make "reserve nothing" unreachable through
// configuration, and "reserve nothing" is the control arm that demonstrates the
// inversion S6 describes — the one setting a test must be able to select.
func ReserveFraction(f float64) *float64 { return &f }

// RecutConfig is the queue re-cut's configuration. The zero value is usable
// and means: default reserve fraction, default per-candidate cost, no severity
// ordering, wall clock.
type RecutConfig struct {
	// DastReserveFraction is S6's "configurable fraction (default 50%) of
	// remaining budget" held for late dast_confirmed arrivals. nil selects
	// DefaultDastReserveFraction. Use ReserveFraction to set it.
	DastReserveFraction *float64

	// TokensPerCandidate is the flat charge per candidate when CostTokens is
	// nil. Zero or negative selects DefaultTokensPerCandidate.
	TokensPerCandidate int

	// CostTokens overrides the flat charge per candidate. It exists so a later
	// step can charge a measured prompt size (research/24 step 12's six
	// sections) without editing this file. A non-positive return is treated as
	// TokensPerCandidate; a cost-free candidate would let an unbounded number
	// of rows through the cut, which is not a budget.
	CostTokens func(Candidate) int

	// SeverityRank orders findings within one evidence class, lower first.
	// It is a map and not a Go enum ON PURPOSE: `finding.severity` is one of
	// the vocabularies schema.sql deliberately leaves unconstrained because
	// internal/record does not own it, and freezing it here would be area 40
	// inventing another area's vocabulary — the exact defect
	// plan/IMPLEMENTATION-PLAN.md §6 exists to stop. A severity absent from
	// the map ranks last among its class; nil ranks every severity equally and
	// the cut falls through to finding_id.
	SeverityRank map[string]int

	// Clock supplies handoff.updated_at. nil means time.Now.
	Clock func() time.Time
}

func (c RecutConfig) reserveFraction() float64 {
	if c.DastReserveFraction == nil {
		return DefaultDastReserveFraction
	}
	return *c.DastReserveFraction
}

func (c RecutConfig) tokensPerCandidate() int {
	if c.TokensPerCandidate <= 0 {
		return DefaultTokensPerCandidate
	}
	return c.TokensPerCandidate
}

func (c RecutConfig) cost(cand Candidate) int {
	if c.CostTokens != nil {
		if n := c.CostTokens(cand); n > 0 {
			return n
		}
	}
	return c.tokensPerCandidate()
}

func (c RecutConfig) now() time.Time {
	if c.Clock == nil {
		return time.Now().UTC()
	}
	return c.Clock().UTC()
}

func (c RecutConfig) validate() error {
	f := c.reserveFraction()
	if math.IsNaN(f) || f < 0 || f > 1 {
		return fmt.Errorf("%w, got %v", ErrInvalidReserveFraction, f)
	}
	return nil
}

// recutTimestampLayout is the timestamp format written into
// handoff.updated_at.
//
// It must stay identical to internal/handoff/state_machine.go's timeLayout.
// That constant is unexported and internal/store cannot import internal/handoff
// (handoff imports store; the edge runs one way), so this is a deliberate
// second copy of a FORMAT — not of a vocabulary. If the two ever diverge, the
// handoff reaper's string comparisons over lease_expires_at and updated_at
// start comparing differently-shaped strings; queue_test.go pins the exact
// layout so a change here fails loudly rather than at 3am in a reaper.
const recutTimestampLayout = "2006-01-02T15:04:05.000000000Z"

func formatRecutTime(t time.Time) string { return t.UTC().Format(recutTimestampLayout) }

// Candidate is one `handoff` row the cut can see, joined to the `finding` it
// carries.
type Candidate struct {
	HandoffID     int64
	FindingID     int64
	Fingerprint   string
	State         record.HandoffState
	EvidenceClass record.EvidenceClass
	Severity      string

	// CostTokens is what this row was charged, filled in by the cut.
	CostTokens int
}

// DastConfirmed reports whether this candidate is in the class S6 reserves
// budget for. It reads the frozen enum constant, never the literal.
func (c Candidate) DastConfirmed() bool {
	return c.EvidenceClass == record.EvidenceClassDastConfirmed
}

// Cut is one re-cut, reported in full so a caller — and a test — can see the
// arithmetic instead of inferring it from the resulting row states.
type Cut struct {
	AuditRecordID int64
	AuditVersion  int64
	DastStatus    record.DastStatus

	// Performed is false when the version guard declined to re-cut. S6 and the
	// R.11 packet both say a re-cut is triggered by an audit_version bump and
	// by nothing else; NotCutReason says which guard declined.
	Performed    bool
	NotCutReason string

	// RemainingBudgetTokens is what the caller passed in.
	RemainingBudgetTokens int

	// ReserveFraction is the fraction actually applied. It is 0 when
	// LateDastArrivalsPossible is false, whatever the configuration says.
	ReserveFraction          float64
	LateDastArrivalsPossible bool

	// ReservedTokens is floor(ReserveFraction * RemainingBudgetTokens) — of
	// REMAINING budget at re-cut time, never of the window's total. OpenTokens
	// is the rest, and is the only pool a non-dast_confirmed row may draw on.
	ReservedTokens int
	OpenTokens     int

	// InFlightTokens is what currently-leased rows were charged before any
	// candidate was considered. InFlightOverdraftTokens is the amount by which
	// they exceeded the remaining budget, which is a real state (the caller's
	// budget estimate shrank while leases were out) and is reported rather than
	// hidden.
	InFlightTokens          int
	InFlightOverdraftTokens int

	// Admitted rows keep handoff.state = 'ready'. Deferred rows were moved to
	// 'skipped_budget'. Contended rows were deferred by the arithmetic but had
	// left 'ready' before the write landed — a claim won the race — and were
	// therefore left alone.
	Admitted  []Candidate
	Deferred  []Candidate
	Contended []Candidate
}

// AdmittedTokens is the total charged to admitted candidates.
func (c Cut) AdmittedTokens() int { return sumCost(c.Admitted) }

// AdmittedDastConfirmedTokens is the total charged to admitted candidates in
// the class S6 reserves for. It is the number the reservation exists to keep
// above ReservedTokens once such candidates exist.
func (c Cut) AdmittedDastConfirmedTokens() int {
	total := 0
	for _, cand := range c.Admitted {
		if cand.DastConfirmed() {
			total += cand.CostTokens
		}
	}
	return total
}

// DeferredDastConfirmed counts admitted-nothing in the highest-value class.
// A cut where this is non-zero while a lower class was admitted is the
// inversion S6 forbids.
func (c Cut) DeferredDastConfirmed() int {
	n := 0
	for _, cand := range c.Deferred {
		if cand.DastConfirmed() {
			n++
		}
	}
	return n
}

// InvertedPriority reports the failure mode S6 names: at least one
// dast_confirmed candidate was pushed past the cut while at least one weaker
// evidence class was admitted. It is a property of ONE cut; the inversion S6
// describes is produced across cuts, and queue_test.go drives both.
func (c Cut) InvertedPriority() bool {
	if c.DeferredDastConfirmed() == 0 {
		return false
	}
	for _, cand := range c.Admitted {
		if !cand.DastConfirmed() {
			return true
		}
	}
	return false
}

func sumCost(cands []Candidate) int {
	total := 0
	for _, c := range cands {
		total += c.CostTokens
	}
	return total
}

// Recutter re-cuts one store's work queues.
//
// It is safe for concurrent use: every re-cut holds the Recutter's mutex for
// its whole duration, including its database work. A re-cut is a rare,
// audit-scoped operation triggered by a version bump, so serialising them costs
// nothing and removes the whole class of interleaving between the version
// guard's read and the cut's writes.
type Recutter struct {
	db  *sql.DB
	cfg RecutConfig

	mu sync.Mutex
	// lastCut records the audit_version each audit was last cut at. See
	// RecutQueueContext for why losing it across a restart is safe.
	lastCut map[int64]int64
}

// NewRecutter returns a Recutter over an already-migrated store.
func NewRecutter(db *sql.DB, cfg RecutConfig) (*Recutter, error) {
	if db == nil {
		return nil, errors.New("store: NewRecutter requires a non-nil *sql.DB")
	}
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	return &Recutter{db: db, cfg: cfg, lastCut: make(map[int64]int64)}, nil
}

// ReserveFraction reports the configured fraction, after defaulting.
func (r *Recutter) ReserveFraction() float64 { return r.cfg.reserveFraction() }

// RecutQueue is the R.11 packet's entry point: re-cut the work queue for one
// audit against the budget remaining at this moment.
//
// It re-cuts only when the audit's `audit_version` has moved since the last cut
// this Recutter performed, which is the S6 trigger and the only one — a write
// to `handoff` is not a trigger, and the packet forbids making it one. Use
// RecutQueueContext when the arithmetic matters to the caller.
func (r *Recutter) RecutQueue(auditID string, remainingBudgetTokens int) error {
	_, err := r.RecutQueueContext(context.Background(), auditID, remainingBudgetTokens)
	return err
}

// RecutQueueContext is RecutQueue with a caller-supplied context, returning the
// full arithmetic.
//
// THE VERSION GUARD IS AN OPTIMISATION, NOT AN INVARIANT. It lives in memory,
// so a process restart re-cuts once at the current version. That is safe
// because a cut is a pure function of (candidate set, remaining budget,
// configuration) and its only write is 'ready' -> 'skipped_budget': repeating
// it with the same inputs defers nothing further, and repeating it with a
// smaller budget defers more, which is the correct response to a shrinking
// window. Making the guard durable would need a column, and schema.sql is a
// frozen interface this step may not extend.
func (r *Recutter) RecutQueueContext(ctx context.Context, auditID string, remainingBudgetTokens int) (Cut, error) {
	if remainingBudgetTokens < 0 {
		return Cut{}, fmt.Errorf("%w, got %d", ErrInvalidBudget, remainingBudgetTokens)
	}
	if err := r.cfg.validate(); err != nil {
		return Cut{}, err
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	auditRecordID, err := ResolveAuditRecordID(ctx, r.db, auditID)
	if err != nil {
		return Cut{}, err
	}

	var (
		version    int64
		dastStatus string
	)
	err = r.db.QueryRowContext(ctx,
		`SELECT audit_version, dast_status FROM audit_record WHERE audit_record_id = ?`,
		auditRecordID).Scan(&version, &dastStatus)
	if errors.Is(err, sql.ErrNoRows) {
		return Cut{}, fmt.Errorf("store: audit_record %d: %w", auditRecordID, ErrNoSuchAudit)
	}
	if err != nil {
		return Cut{}, fmt.Errorf("store: reading audit_record %d: %w", auditRecordID, err)
	}
	if err := record.ValidateDastStatus(dastStatus); err != nil {
		return Cut{}, fmt.Errorf("store: audit_record %d: %w", auditRecordID, err)
	}

	cut := Cut{
		AuditRecordID:         auditRecordID,
		AuditVersion:          version,
		DastStatus:            record.DastStatus(dastStatus),
		RemainingBudgetTokens: remainingBudgetTokens,
	}

	if previous, seen := r.lastCut[auditRecordID]; seen && previous == version {
		cut.NotCutReason = fmt.Sprintf(
			"audit_record %d is still at audit_version %d, already cut at that version; "+
				"S6 re-cuts on a version bump, not on a handoff write",
			auditRecordID, version)
		return cut, nil
	}

	cut, err = r.performCut(ctx, cut)
	if err != nil {
		return cut, err
	}
	r.lastCut[auditRecordID] = version
	return cut, nil
}

// performCut does the arithmetic and writes the deferrals. The caller holds
// r.mu.
func (r *Recutter) performCut(ctx context.Context, cut Cut) (Cut, error) {
	inFlight, candidates, err := r.loadRows(ctx, cut.AuditRecordID)
	if err != nil {
		return cut, err
	}

	cut.Performed = true
	cut.LateDastArrivalsPossible = LateDastArrivalsPossible(cut.DastStatus)
	if cut.LateDastArrivalsPossible {
		cut.ReserveFraction = r.cfg.reserveFraction()
	}

	// floor, not round: reserving a token more than the fraction allows would
	// be the component's own arithmetic quietly outvoting the configuration.
	cut.ReservedTokens = int(math.Floor(cut.ReserveFraction * float64(cut.RemainingBudgetTokens)))
	if cut.ReservedTokens > cut.RemainingBudgetTokens {
		cut.ReservedTokens = cut.RemainingBudgetTokens
	}
	cut.OpenTokens = cut.RemainingBudgetTokens - cut.ReservedTokens

	p := &pools{reserve: cut.ReservedTokens, open: cut.OpenTokens}

	// In-flight leases are charged first and cannot be refused: the work is
	// already happening and the tokens are already being spent. They are the
	// reason a re-cut must not simply divide the budget among candidates as if
	// the queue were idle. See this file's header for why they are never
	// deferred, superseded, or otherwise touched.
	for i := range inFlight {
		inFlight[i].CostTokens = r.cfg.cost(inFlight[i])
		over := p.chargeInFlight(inFlight[i].DastConfirmed(), inFlight[i].CostTokens)
		cut.InFlightTokens += inFlight[i].CostTokens
		cut.InFlightOverdraftTokens += over
	}

	sortCandidates(candidates, r.cfg.SeverityRank)

	// A cut, not a knapsack. research/24 step 9: "everything past the cut is
	// marked SKIPPED_BUDGET". Once a pool cannot pay for the next candidate in
	// rank order, that pool is closed and every later candidate drawing on it
	// is deferred — including a cheaper one. Continuing to scan for something
	// that fits is exactly how a budget re-orders itself behind the priority
	// scheme's back.
	dastClosed, openClosed := false, false
	for i := range candidates {
		cand := candidates[i]
		cand.CostTokens = r.cfg.cost(cand)

		closed := openClosed
		if cand.DastConfirmed() {
			closed = dastClosed
		}
		if closed || !p.charge(cand.DastConfirmed(), cand.CostTokens) {
			if cand.DastConfirmed() {
				// A dast_confirmed row draws on reserve + open. If the pair
				// cannot pay for it, `open` alone cannot pay for anything at
				// least as expensive either, so both pools close.
				dastClosed, openClosed = true, true
			} else {
				openClosed = true
			}
			cut.Deferred = append(cut.Deferred, cand)
			continue
		}
		cut.Admitted = append(cut.Admitted, cand)
	}

	deferred, contended, err := r.applyDeferrals(ctx, cut.Deferred)
	if err != nil {
		return cut, err
	}
	cut.Deferred = deferred
	cut.Contended = contended
	return cut, nil
}

// pools is the two-pool budget. The reserve is drawable only by
// dast_confirmed; the open pool is drawable by everything.
type pools struct {
	reserve int
	open    int
}

// charge takes cost from the pools, or reports that it will not fit and takes
// nothing. It never leaves a partial draw behind.
func (p *pools) charge(dastConfirmed bool, cost int) bool {
	if !dastConfirmed {
		if p.open < cost {
			return false
		}
		p.open -= cost
		return true
	}
	if p.reserve+p.open < cost {
		return false
	}
	fromReserve := cost
	if fromReserve > p.reserve {
		fromReserve = p.reserve
	}
	p.reserve -= fromReserve
	p.open -= cost - fromReserve
	return true
}

// chargeInFlight charges work that is already running and therefore cannot be
// refused. It returns the overdraft, i.e. how much of the cost the pools could
// not cover, and drains them rather than going negative.
func (p *pools) chargeInFlight(dastConfirmed bool, cost int) int {
	if p.charge(dastConfirmed, cost) {
		return 0
	}
	available := p.open
	if dastConfirmed {
		available += p.reserve
		p.reserve = 0
	}
	p.open = 0
	return cost - available
}

// loadRows reads the audit's live handoff rows: the leased ones (in flight)
// and the ready ones (candidates). Terminal rows are neither — they are
// already paid for and a re-cut has nothing to say about them.
func (r *Recutter) loadRows(ctx context.Context, auditRecordID int64) (inFlight, candidates []Candidate, err error) {
	rows, err := r.db.QueryContext(ctx, `
		SELECT h.handoff_id, h.finding_id, h.fingerprint, h.state, f.evidence_class, f.severity
		  FROM handoff h
		  JOIN finding f ON f.finding_id = h.finding_id
		 WHERE h.audit_record_id = ?
		   AND h.state IN (?, ?)
		 ORDER BY h.handoff_id`,
		auditRecordID,
		string(record.HandoffStateReady),
		string(record.HandoffStateLeased))
	if err != nil {
		return nil, nil, fmt.Errorf("store: loading the queue for audit_record %d: %w", auditRecordID, err)
	}
	defer func() { _ = rows.Close() }()

	for rows.Next() {
		var (
			c     Candidate
			state string
			class string
		)
		if err := rows.Scan(&c.HandoffID, &c.FindingID, &c.Fingerprint, &state, &class, &c.Severity); err != nil {
			return nil, nil, fmt.Errorf("store: scanning the queue for audit_record %d: %w", auditRecordID, err)
		}
		if err := record.ValidateHandoffState(state); err != nil {
			return nil, nil, fmt.Errorf("store: handoff %d: %w", c.HandoffID, err)
		}
		if err := record.ValidateEvidenceClass(class); err != nil {
			return nil, nil, fmt.Errorf("store: finding %d: %w", c.FindingID, err)
		}
		c.State = record.HandoffState(state)
		c.EvidenceClass = record.EvidenceClass(class)

		if c.State == record.HandoffStateLeased {
			inFlight = append(inFlight, c)
			continue
		}
		candidates = append(candidates, c)
	}
	if err := rows.Err(); err != nil {
		return nil, nil, fmt.Errorf("store: reading the queue for audit_record %d: %w", auditRecordID, err)
	}
	return inFlight, candidates, nil
}

// applyDeferrals writes 'ready' -> 'skipped_budget' for everything past the
// cut, in one transaction.
//
// The UPDATE is guarded on state = 'ready', so a row a consumer claimed between
// the SELECT and this write is left exactly as the consumer left it: the claim
// wins. Losing that race is not an error and does not lose the finding — the
// row is leased, it will be worked or reclaimed, and the next cut sees it.
func (r *Recutter) applyDeferrals(ctx context.Context, toDefer []Candidate) (deferred, contended []Candidate, err error) {
	if len(toDefer) == 0 {
		return nil, nil, nil
	}
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("store: beginning the queue re-cut: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	now := formatRecutTime(r.cfg.now())
	for _, cand := range toDefer {
		res, execErr := tx.ExecContext(ctx,
			`UPDATE handoff SET state = ?, updated_at = ? WHERE handoff_id = ? AND state = ?`,
			string(record.HandoffStateSkippedBudget), now, cand.HandoffID, string(record.HandoffStateReady))
		if execErr != nil {
			return nil, nil, fmt.Errorf("store: deferring handoff %d as %s: %w",
				cand.HandoffID, record.HandoffStateSkippedBudget, execErr)
		}
		n, rowsErr := res.RowsAffected()
		if rowsErr != nil {
			return nil, nil, fmt.Errorf("store: deferring handoff %d as %s: %w",
				cand.HandoffID, record.HandoffStateSkippedBudget, rowsErr)
		}
		if n == 1 {
			cand.State = record.HandoffStateSkippedBudget
			deferred = append(deferred, cand)
			continue
		}
		contended = append(contended, cand)
	}
	if err := tx.Commit(); err != nil {
		return nil, nil, fmt.Errorf("store: committing the queue re-cut: %w", err)
	}
	return deferred, contended, nil
}

// sortCandidates puts the queue in rank order: evidence class first (which is
// research/24 step 7's first rank_key component and the order
// record.EvidenceClassValues() is documented to return), then the configured
// severity rank, then finding_id as a total, stable tiebreak.
//
// The rest of research/24's rank_key — KEV membership, KEV ransomware use,
// EPSS, reachability, CVSS base, proximity — is not orderable here: no column
// in schema.sql carries any of it, and that document is explicit that all six
// weights come from configuration, never code. RecutConfig.SeverityRank and
// the deterministic finding_id fallback are what this step can honestly
// provide; a later step supplies the rest by ordering the candidate set before
// it reaches the budget arithmetic.
func sortCandidates(candidates []Candidate, severityRank map[string]int) {
	sort.SliceStable(candidates, func(i, j int) bool {
		a, b := candidates[i], candidates[j]
		if ra, rb := EvidenceClassRank(a.EvidenceClass), EvidenceClassRank(b.EvidenceClass); ra != rb {
			return ra < rb
		}
		if ra, rb := severityOrder(severityRank, a.Severity), severityOrder(severityRank, b.Severity); ra != rb {
			return ra < rb
		}
		return a.FindingID < b.FindingID
	})
}

func severityOrder(severityRank map[string]int, severity string) int {
	if rank, ok := severityRank[severity]; ok {
		return rank
	}
	return math.MaxInt
}

// evidenceClassRanks is derived from record.EvidenceClassValues(), which
// internal/record documents as returning "every legal anvil/evidenceClass
// literal, in descending evidence strength — which is also the default rank
// order". Deriving it means this file holds no second copy of that ordering and
// no bare evidence-class literal: adding a class to the frozen enum ranks it
// here automatically, in the position R.1 put it.
var evidenceClassRanks = func() map[record.EvidenceClass]int {
	values := record.EvidenceClassValues()
	ranks := make(map[record.EvidenceClass]int, len(values))
	for i, v := range values {
		ranks[v] = i
	}
	return ranks
}()

// EvidenceClassRank reports an evidence class's position in the frozen enum's
// documented strength order, lower being stronger. An unknown class ranks last;
// it cannot reach here through loadRows, which validates against the enum
// first.
func EvidenceClassRank(e record.EvidenceClass) int {
	if rank, ok := evidenceClassRanks[e]; ok {
		return rank
	}
	return math.MaxInt
}

// LateDastArrivalsPossible reports whether an audit whose DAST half is in this
// state can still contribute `evidence_class = 'dast_confirmed'` rows to the
// queue after this cut. It is the gate on the reservation: holding budget for a
// class that provably cannot arrive would starve the classes that did.
//
// The switch is total over record.DastStatusValues() and queue_test.go asserts
// that, so the eleventh dastStatus value cannot land as a silent default.
//
// IT IS NOT internal/handoff's HasDynamicEvidence AND MUST NOT BE ALIGNED WITH
// IT. That predicate answers "can a reproduction exist NOW for the finding in
// hand", which gates the `validated` disposition. This one answers "can more
// proof-carrying findings still show up", which gates a budget reservation.
// The two genuinely disagree on four values and each disagreement is correct:
//
//   - running: no reproduction has been sealed yet (HasDynamicEvidence false),
//     but the half is still working and arrivals are exactly what is expected
//     (true here). This is S6's central case.
//   - completed_failed, timed_out: the half did not finish, so it has produced
//     no verdict about any particular finding (HasDynamicEvidence false) — but
//     findings it confirmed before it crashed or ran out of clock are real and
//     still get enqueued (true here). Reserving for them is right even though
//     they cannot reach `validated` on this audit: a proof-carrying finding is
//     still the highest-value patch Anvil can propose, and S7 withholds the
//     "verified fixed" verdict, not the fix.
//
// False for exactly the five states in which no dynamic evidence exists or can:
// not_run (the DAST tier is not installed at all), skipped_no_manifest (it ran
// and there was nothing to scan), completed_clean (it scanned and found
// nothing), target_boot_failed and target_unreachable (there was never a live
// target — the distinction plan/00-SPINE.md S6 exists to preserve).
func LateDastArrivalsPossible(s record.DastStatus) bool {
	switch s {
	case record.DastStatusRunning,
		record.DastStatusCompletedFindings,
		record.DastStatusCompletedPartial,
		record.DastStatusCompletedFailed,
		record.DastStatusTimedOut:
		return true
	case record.DastStatusNotRun,
		record.DastStatusSkippedNoManifest,
		record.DastStatusCompletedClean,
		record.DastStatusTargetBootFailed,
		record.DastStatusTargetUnreachable:
		return false
	default:
		// Unreachable through RecutQueueContext, which validates against the
		// frozen enum first. Conservative if it is ever reached another way:
		// reserving for an unknown state protects the class S6 protects.
		return true
	}
}

// ResolveAuditRecordID turns the R.11 packet's `auditID string` into the store's
// audit_record primary key.
//
// THE PACKET NAMES A STRING AND THE SCHEMA HAS NO STRING KEY. `anvil/auditId`
// is a required record field (plan/40-record-and-storage.md's Record Field
// Contract) but schema.sql carries NO `audit_id` column — it is a frozen
// interface and R.11 may not add one. So this resolver accepts the decimal
// `audit_record_id` and says exactly that when it cannot.
//
// It is deliberately NOT the CRITIQUE-02 F7 mistake. F7 was about EXPORTING a
// rowid as a portable identity — hashing it into a git trailer where it means
// nothing outside one copy of one database file. This is the opposite
// direction: a local lookup key, never emitted, never hashed, never handed to
// another process. When a later step adds the `anvil/auditId` column, this
// function is the single place that changes and every caller keeps its
// signature.
func ResolveAuditRecordID(ctx context.Context, db *sql.DB, auditID string) (int64, error) {
	trimmed := strings.TrimSpace(auditID)
	if trimmed == "" {
		return 0, fmt.Errorf("store: empty audit id: %w", ErrNoSuchAudit)
	}
	id, err := strconv.ParseInt(trimmed, 10, 64)
	if err != nil || id <= 0 {
		return 0, fmt.Errorf(
			"store: audit id %q is not a positive audit_record_id, and schema.sql has no anvil/auditId "+
				"column to resolve it against: %w", auditID, ErrNoSuchAudit)
	}
	var found int64
	err = db.QueryRowContext(ctx,
		`SELECT audit_record_id FROM audit_record WHERE audit_record_id = ?`, id).Scan(&found)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, fmt.Errorf("store: audit_record %d: %w", id, ErrNoSuchAudit)
	}
	if err != nil {
		return 0, fmt.Errorf("store: resolving audit id %q: %w", auditID, err)
	}
	return found, nil
}
