package handoff

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Susquehanna-Syntax/Anvil/internal/record"
	"github.com/Susquehanna-Syntax/Anvil/internal/store"

	_ "modernc.org/sqlite" // cgo-free driver, plan/00-SPINE.md S12
)

// ---------------------------------------------------------------------------
// Fixture. The schema under test is internal/store/schema.sql applied through
// R.5's real migration path — never a hand-copied DDL, because a second copy
// of a frozen interface is the defect §6 G9/G10 exist to prevent, and a test
// that invents its own `handoff` table would prove nothing about the shipped
// one.
// ---------------------------------------------------------------------------

// fakeClock drives the two expiry clocks independently of wall time.
type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func newFakeClock() *fakeClock {
	return &fakeClock{t: time.Date(2026, 8, 8, 9, 0, 0, 0, time.UTC)}
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

type fixture struct {
	t         *testing.T
	db        *sql.DB
	q         *Queue
	clock     *fakeClock
	packetDir string
	targetID  int64
}

// newFixture builds an on-disk store so the claim race runs over real,
// separate connections rather than one serialised pool slot. The pragmas ride
// on the DSN because they are per connection and the pool opens more than one.
func newFixture(t *testing.T, opts Options) *fixture {
	t.Helper()

	dir := t.TempDir()
	dbPath := filepath.ToSlash(filepath.Join(dir, "anvil.db"))
	dsn := "file:" + strings.ReplaceAll(dbPath, " ", "%20") +
		"?_pragma=busy_timeout(10000)&_pragma=foreign_keys(1)" +
		"&_pragma=journal_mode(WAL)&_pragma=synchronous(NORMAL)"

	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		t.Fatalf("sql.Open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	// Prove the DSN pragmas were honoured. If they silently were not, the
	// concurrency test below would flake on SQLITE_BUSY and be blamed on the
	// claim protocol instead of on the connection setup.
	var busy int
	if err := db.QueryRow(`PRAGMA busy_timeout`).Scan(&busy); err != nil {
		t.Fatalf("PRAGMA busy_timeout: %v", err)
	}
	if busy != 10000 {
		t.Fatalf("busy_timeout = %d, want 10000: DSN pragmas were not applied", busy)
	}

	if _, err := store.Migrate(context.Background(), db, ""); err != nil {
		t.Fatalf("store.Migrate: %v", err)
	}

	clock := newFakeClock()
	packetDir := filepath.Join(dir, "packets")
	if opts.PacketDir == "" {
		opts.PacketDir = packetDir
	}
	opts.Clock = clock.Now

	q, err := New(db, opts)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	f := &fixture{t: t, db: db, q: q, clock: clock, packetDir: opts.PacketDir}

	res, err := db.Exec(`INSERT INTO target (kind, locator) VALUES (?, ?)`, "repo", "https://example.invalid/repo.git")
	if err != nil {
		t.Fatalf("insert target: %v", err)
	}
	if f.targetID, err = res.LastInsertId(); err != nil {
		t.Fatalf("target id: %v", err)
	}
	return f
}

// fp returns a distinct, well-formed 64-hex anvil-fp/v1-shaped digest.
func fp(n int) string { return strings.Repeat(fmt.Sprintf("%02x", n%256), 32) }

// newAudit inserts a scan_run plus its audit_record with the half statuses and
// the deadline the test needs. deadline_at is supplied, never derived here:
// R.6 computes it once from scan_run.started_at + claim_timeout_seconds and
// this package only ever reads it.
func (f *fixture) newAudit(state record.State, sast record.HalfStatus, dast record.DastStatus, deadline time.Time) int64 {
	f.t.Helper()
	id, err := f.tryNewAudit(state, sast, dast, deadline)
	if err != nil {
		f.t.Fatalf("newAudit: %v", err)
	}
	return id
}

// tryNewAudit is newAudit without the Fatalf, for the one test that must be
// able to tell "the schema will not hold this literal" from "the test is
// broken". See TestValidatedRequiresDynamicEvidence.
func (f *fixture) tryNewAudit(state record.State, sast record.HalfStatus, dast record.DastStatus, deadline time.Time) (int64, error) {
	f.t.Helper()

	res, err := f.db.Exec(
		`INSERT INTO scan_run (target_id, started_at, ruleset_version, status, commit_sha)
		 VALUES (?, ?, ?, ?, ?)`,
		f.targetID, formatTime(f.clock.Now()), "anvil-rules/v1",
		string(record.ScanRunStatusRunning), "9f1c0de9f1c0de9f1c0de9f1c0de9f1c0de9f1c0")
	if err != nil {
		return 0, fmt.Errorf("insert scan_run: %w", err)
	}
	scanRunID, err := res.LastInsertId()
	if err != nil {
		return 0, fmt.Errorf("scan_run id: %w", err)
	}

	var sastStatus any
	if sast != "" {
		sastStatus = string(sast)
	}
	res, err = f.db.Exec(
		`INSERT INTO audit_record
		   (scan_run_id, schema_version, state, sast_status, dast_status,
		    target_provenance, deadline_at, payload_sha256, created_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		scanRunID, "anvil/1", string(state), sastStatus, string(dast),
		string(record.TargetProvenanceBootedClean), formatTime(deadline),
		strings.Repeat("b", 64), formatTime(f.clock.Now()))
	if err != nil {
		return 0, fmt.Errorf("insert audit_record: %w", err)
	}
	auditID, err := res.LastInsertId()
	if err != nil {
		return 0, fmt.Errorf("audit_record id: %w", err)
	}
	return auditID, nil
}

// sealedAudit is the common case: both halves sealed, DAST clean, an 8-hour
// claim window that has not closed.
func (f *fixture) sealedAudit() int64 {
	f.t.Helper()
	return f.newAudit(record.StateBothSealed, record.HalfStatusSealed,
		record.DastStatusCompletedClean, f.clock.Now().Add(8*time.Hour))
}

func (f *fixture) newFinding(fingerprint string) int64 {
	f.t.Helper()
	res, err := f.db.Exec(
		`INSERT INTO finding
		   (target_id, fingerprint, detector, evidence_class, rule_id, severity, title,
		    state, remediable_by_agent, first_seen_scan, first_seen_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, (SELECT MAX(scan_run_id) FROM scan_run), ?)`,
		f.targetID, fingerprint, string(record.DetectorKindSast),
		string(record.EvidenceClassSastStaticOnly), "anvil.py.sqli/v3", "high",
		"SQL injection", "open", 1, formatTime(f.clock.Now()))
	if err != nil {
		f.t.Fatalf("insert finding: %v", err)
	}
	id, err := res.LastInsertId()
	if err != nil {
		f.t.Fatalf("finding id: %v", err)
	}
	return id
}

// auditUUID is the `anvil/auditId` for an audit_record row. It is a separate
// identity from the rowid on purpose: IdempotencyKey hashes THIS, because a
// rowid is not something a coding agent's git trailer can carry meaningfully
// (CRITIQUE-02 F7).
func auditUUID(auditRecordID int64) string {
	return fmt.Sprintf("11111111-2222-4333-8444-%012d", auditRecordID)
}

// enqueue seeds one ready finding and returns its fingerprint and row.
func (f *fixture) enqueue(n int, class record.ConsumptionClass, auditID int64) (string, Row) {
	f.t.Helper()
	fingerprint := fp(n)
	findingID := f.newFinding(fingerprint)
	row, err := f.q.Enqueue(EnqueueRequest{
		FindingID:        findingID,
		AuditRecordID:    auditID,
		AuditID:          auditUUID(auditID),
		Fingerprint:      fingerprint,
		ConsumptionClass: class,
	})
	if err != nil {
		f.t.Fatalf("Enqueue: %v", err)
	}
	if row.State != record.HandoffStateReady {
		f.t.Fatalf("enqueued state = %q, want %q", row.State, record.HandoffStateReady)
	}
	return fingerprint, row
}

func (f *fixture) state(handoffID int64) record.HandoffState {
	f.t.Helper()
	row, err := f.q.Get(handoffID)
	if err != nil {
		f.t.Fatalf("Get(%d): %v", handoffID, err)
	}
	return row.State
}

// packetExists stats the packet file directly, WITHOUT going through
// ReadPacket. It is what the reaper/lease tests need: those assertions are
// about whether the cache file survived a sweep, and ReadPacket now — quite
// correctly — refuses a caller who does not hold the lease, so using it there
// would test the gate instead of the sweep.
func (f *fixture) packetExists(fingerprint string) bool {
	f.t.Helper()
	path, err := f.q.PacketPath(fingerprint)
	if err != nil {
		f.t.Fatalf("PacketPath: %v", err)
	}
	_, err = os.Stat(path)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		f.t.Fatalf("stat packet: %v", err)
	}
	return err == nil
}

func (f *fixture) countHandoffRows() int {
	f.t.Helper()
	var n int
	if err := f.db.QueryRow(`SELECT COUNT(*) FROM handoff`).Scan(&n); err != nil {
		f.t.Fatalf("count handoff: %v", err)
	}
	return n
}

// ---------------------------------------------------------------------------
// The state machine itself.
// ---------------------------------------------------------------------------

func TestStateMachineCoversEveryFrozenState(t *testing.T) {
	transitions := LegalTransitions()
	for _, s := range record.HandoffStateValues() {
		if _, ok := transitions[s]; !ok {
			t.Errorf("handoff.state %q has no entry in the state machine", s)
		}
	}
	if len(transitions) != len(record.HandoffStateValues()) {
		t.Errorf("state machine has %d states, the frozen enum has %d",
			len(transitions), len(record.HandoffStateValues()))
	}

	// Exactly two states are live; the other eleven are terminal.
	var live, terminal int
	for _, s := range record.HandoffStateValues() {
		if IsLive(s) {
			live++
		}
		if IsTerminal(s) {
			terminal++
		}
	}
	if live != 2 || terminal != 11 {
		t.Errorf("live=%d terminal=%d, want 2 and 11", live, terminal)
	}

	// Never expire a live claim: there is no direct leased -> expired edge.
	if CanTransition(record.HandoffStateLeased, record.HandoffStateExpired) {
		t.Error("leased -> expired must not be a legal edge: research/08 §4 forbids expiring a live claim")
	}
	// A terminal state is terminal.
	if CanTransition(record.HandoffStateValidated, record.HandoffStateReady) {
		t.Error("validated -> ready must not be legal")
	}

	err := CheckTransition(record.HandoffStateLeased, record.HandoffStateExpired)
	if !errors.Is(err, ErrIllegalTransition) {
		t.Errorf("CheckTransition error = %v, want ErrIllegalTransition", err)
	}
	var te *TransitionError
	if !errors.As(err, &te) || te.From != record.HandoffStateLeased {
		t.Errorf("CheckTransition error = %v, want a *TransitionError naming the source state", err)
	}
	if err := CheckTransition(record.HandoffState("not_a_state"), record.HandoffStateReady); err == nil {
		t.Error("an unknown state literal must be rejected by the record contract")
	}
}

func TestExhaustedStateIsAFrozenLiteral(t *testing.T) {
	if err := record.ValidateHandoffState(string(ExhaustedState)); err != nil {
		t.Fatalf("ExhaustedState is not a legal handoff.state: %v", err)
	}
	if !IsTerminal(ExhaustedState) {
		t.Error("ExhaustedState must be terminal")
	}
}

// ---------------------------------------------------------------------------
// The claim race. This is the packet's first required test.
// ---------------------------------------------------------------------------

func TestClaimRaceExactlyOneWinner(t *testing.T) {
	f := newFixture(t, Options{})
	audit := f.sealedAudit()
	fingerprint, row := f.enqueue(1, record.ConsumptionClassStaticOnly, audit)

	const workers = 8
	var (
		wg      sync.WaitGroup
		mu      sync.Mutex
		winners []Handle
		losers  int
		other   []error
	)
	start := make(chan struct{})
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			h, err := f.q.Claim(fingerprint, fmt.Sprintf("worker-%d", i))
			mu.Lock()
			defer mu.Unlock()
			switch {
			case err == nil:
				winners = append(winners, h)
			case errors.Is(err, ErrAlreadyClaimed):
				losers++
			default:
				other = append(other, err)
			}
		}(i)
	}
	close(start)
	wg.Wait()

	for _, err := range other {
		t.Errorf("unexpected claim error: %v", err)
	}
	if len(winners) != 1 {
		t.Fatalf("%d workers won the claim, want exactly 1", len(winners))
	}
	if losers != workers-1 {
		t.Errorf("%d workers got ErrAlreadyClaimed, want %d", losers, workers-1)
	}

	// The winner's lease is the only one recorded, and attempts advanced by
	// exactly one — not once per racer.
	got, err := f.q.Get(row.HandoffID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.State != record.HandoffStateLeased {
		t.Errorf("state = %q, want %q", got.State, record.HandoffStateLeased)
	}
	if got.ClaimedBy != winners[0].WorkerID {
		t.Errorf("claimed_by = %q, want %q", got.ClaimedBy, winners[0].WorkerID)
	}
	if got.Attempts != 1 {
		t.Errorf("attempts = %d after one successful claim among %d racers, want 1", got.Attempts, workers)
	}
	if winners[0].Attempt != 1 {
		t.Errorf("Handle.Attempt = %d, want 1", winners[0].Attempt)
	}
}

// TestClaimCASAdmitsExactlyOneWinner races the conditional UPDATE itself.
//
// It exists because the end-to-end race above cannot be trusted to reach the
// interleaving that matters: in practice one goroutine usually finishes its
// whole claim before the next one's eligibility SELECT runs, so the SELECT —
// not the CAS — does the arbitrating and the test would still pass with the
// `state = 'ready'` guard deleted. Here every goroutine starts from the same
// already-selected candidate id, which is exactly the state two workers are in
// when their SELECTs interleave, and only the guard can separate them.
func TestClaimCASAdmitsExactlyOneWinner(t *testing.T) {
	f := newFixture(t, Options{})
	audit := f.sealedAudit()
	_, row := f.enqueue(20, record.ConsumptionClassStaticOnly, audit)

	const workers = 16
	var (
		wg     sync.WaitGroup
		mu     sync.Mutex
		won    int
		lost   int
		errs   []error
		handle Handle
	)
	start := make(chan struct{})
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			h, ok, err := f.q.tryClaim(context.Background(), row.HandoffID, fmt.Sprintf("worker-%d", i))
			mu.Lock()
			defer mu.Unlock()
			switch {
			case err != nil:
				errs = append(errs, err)
			case ok:
				won++
				handle = h
			default:
				lost++
			}
		}(i)
	}
	close(start)
	wg.Wait()

	for _, err := range errs {
		t.Errorf("unexpected error: %v", err)
	}
	if won != 1 {
		t.Fatalf("%d of %d workers won the compare-and-swap, want exactly 1", won, workers)
	}
	if lost != workers-1 {
		t.Errorf("%d workers lost, want %d", lost, workers-1)
	}
	after, err := f.q.Get(row.HandoffID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if after.Attempts != 1 {
		t.Errorf("attempts = %d after %d racing claims, want 1", after.Attempts, workers)
	}
	if after.ClaimedBy != handle.WorkerID {
		t.Errorf("claimed_by = %q, want the winner %q", after.ClaimedBy, handle.WorkerID)
	}
}

// ---------------------------------------------------------------------------
// The consumption gate (research/21 §5, carried by O.3's consumption_class).
// ---------------------------------------------------------------------------

func TestStaticOnlyWaitsForTheSastSeal(t *testing.T) {
	f := newFixture(t, Options{})
	audit := f.newAudit(record.StateCollecting, "", record.DastStatusNotRun, f.clock.Now().Add(8*time.Hour))
	fingerprint, _ := f.enqueue(2, record.ConsumptionClassStaticOnly, audit)

	if _, err := f.q.Claim(fingerprint, "worker-a"); !errors.Is(err, ErrNotEligible) {
		t.Fatalf("claim while collecting: err = %v, want ErrNotEligible", err)
	}
	if _, err := f.q.AcquireLease("worker-a"); !errors.Is(err, ErrNoWork) {
		t.Fatalf("AcquireLease while collecting: err = %v, want ErrNoWork", err)
	}

	// R.6 seals the SAST half.
	if _, err := f.db.Exec(`UPDATE audit_record SET state = ?, sast_status = ? WHERE audit_record_id = ?`,
		string(record.StateSastSealed), string(record.HalfStatusSealed), audit); err != nil {
		t.Fatalf("seal sast half: %v", err)
	}
	if _, err := f.q.Claim(fingerprint, "worker-a"); err != nil {
		t.Fatalf("claim after the SAST seal: %v", err)
	}
}

func TestRequiresDynamicConfirmationWaitsForTheDastHalf(t *testing.T) {
	f := newFixture(t, Options{})
	audit := f.newAudit(record.StateSastSealed, record.HalfStatusSealed,
		record.DastStatusRunning, f.clock.Now().Add(8*time.Hour))
	fingerprint, _ := f.enqueue(3, record.ConsumptionClassRequiresDynamicConfirmation, audit)

	// The SAST half is sealed, which is enough for a static_only finding and
	// deliberately not enough for this one.
	if _, err := f.q.Claim(fingerprint, "worker-a"); !errors.Is(err, ErrNotEligible) {
		t.Fatalf("claim before the DAST half is final: err = %v, want ErrNotEligible", err)
	}

	if _, err := f.db.Exec(`UPDATE audit_record SET state = ?, dast_status = ? WHERE audit_record_id = ?`,
		string(record.StateBothSealed), string(record.DastStatusCompletedFindings), audit); err != nil {
		t.Fatalf("seal dast half: %v", err)
	}
	h, err := f.q.Claim(fingerprint, "worker-a")
	if err != nil {
		t.Fatalf("claim after the DAST seal: %v", err)
	}
	// S7: the Handle exposes what the dynamic half actually concluded, so a
	// consumer can tell "confirmed" from "never ran".
	if h.DastStatus != record.DastStatusCompletedFindings {
		t.Errorf("Handle.DastStatus = %q, want %q", h.DastStatus, record.DastStatusCompletedFindings)
	}
	if h.ConsumptionClass != record.ConsumptionClassRequiresDynamicConfirmation {
		t.Errorf("Handle.ConsumptionClass = %q", h.ConsumptionClass)
	}
}

// ---------------------------------------------------------------------------
// The crash. This is the scenario S7 and O.3 both name: a consumer acquires a
// lease, is OOM-killed mid-work, the lease expires, another consumer reclaims.
// ---------------------------------------------------------------------------

func TestOOMKilledConsumerReclaimIsIdempotent(t *testing.T) {
	f := newFixture(t, Options{Lease: 20 * time.Minute, MaxAttempts: 2})
	audit := f.sealedAudit()
	fingerprint, row := f.enqueue(4, record.ConsumptionClassStaticOnly, audit)

	dead, err := f.q.Claim(fingerprint, "worker-oomed")
	if err != nil {
		t.Fatalf("Claim: %v", err)
	}
	if dead.Attempt != 1 {
		t.Fatalf("first lease Attempt = %d, want 1", dead.Attempt)
	}
	// The packet is materialised by the lease holder: it is a cache of the
	// half's results, and R.6's read gate governs those bytes wherever they
	// live, so writing one takes a Handle.
	if _, err := f.q.WritePacket(dead, []byte(`{"packet":"regenerable"}`)); err != nil {
		t.Fatalf("WritePacket: %v", err)
	}

	// The holder is OOM-killed here. It never renews and never releases.
	f.clock.Advance(21 * time.Minute)

	report, err := f.q.ReclaimExpired()
	if err != nil {
		t.Fatalf("ReclaimExpired: %v", err)
	}
	if len(report.Reclaimed) != 1 || report.Requeued() != 1 {
		t.Fatalf("reclaimed %d (requeued %d), want 1 requeued", len(report.Reclaimed), report.Requeued())
	}
	if report.Reclaimed[0].To != record.HandoffStateReady {
		t.Errorf("reclaimed to %q, want %q", report.Reclaimed[0].To, record.HandoffStateReady)
	}
	if report.Reclaimed[0].WorkerID != "worker-oomed" {
		t.Errorf("reclaim named worker %q", report.Reclaimed[0].WorkerID)
	}
	if got := f.state(row.HandoffID); got != record.HandoffStateReady {
		t.Fatalf("state after reclaim = %q, want %q", got, record.HandoffStateReady)
	}

	// Idempotent sweep: a second reclaim must find nothing and must not touch
	// the attempt counter.
	if second, err := f.q.ReclaimExpired(); err != nil {
		t.Fatalf("second ReclaimExpired: %v", err)
	} else if !second.Empty() {
		t.Errorf("second ReclaimExpired reclaimed %d rows, want 0", len(second.Reclaimed))
	}
	after, err := f.q.Get(row.HandoffID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if after.Attempts != 1 {
		t.Errorf("attempts = %d after one crash and two sweeps, want 1", after.Attempts)
	}

	// The packet is a cache for work that is still to be done: a requeue must
	// not drop it.
	if !f.packetExists(fingerprint) {
		t.Error("packet was dropped by a requeue")
	}

	// The successor picks the same work up.
	live, err := f.q.AcquireLease("worker-successor")
	if err != nil {
		t.Fatalf("AcquireLease after reclaim: %v", err)
	}
	if live.HandoffID != dead.HandoffID {
		t.Fatalf("successor got row %d, want %d", live.HandoffID, dead.HandoffID)
	}
	if live.Attempt != 2 {
		t.Errorf("successor Attempt = %d, want 2", live.Attempt)
	}
	// The (fingerprint, record version) key is unchanged across the crash, so
	// the successor's work is recognisably the same unit of work — that is
	// what makes re-processing idempotent downstream rather than duplicated.
	if live.Fingerprint != dead.Fingerprint || live.RecordVersion != dead.RecordVersion {
		t.Errorf("work identity moved across the crash: (%s,%d) -> (%s,%d)",
			dead.Fingerprint, dead.RecordVersion, live.Fingerprint, live.RecordVersion)
	}
	if live.IdempotencyKey != dead.IdempotencyKey || live.IdempotencyKey == "" {
		t.Errorf("idempotency key moved across the crash: %q -> %q", dead.IdempotencyKey, live.IdempotencyKey)
	}

	// The dead holder now wakes up and tries to report. Neither call may land.
	if _, err := f.q.RenewLease(dead); !errors.Is(err, ErrLeaseLost) {
		t.Errorf("dead holder RenewLease: err = %v, want ErrLeaseLost", err)
	}
	if err := f.q.ReleaseLease(dead, record.HandoffStateValidated); !errors.Is(err, ErrLeaseLost) {
		t.Errorf("dead holder ReleaseLease: err = %v, want ErrLeaseLost", err)
	}
	stillLeased, err := f.q.Get(row.HandoffID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if stillLeased.State != record.HandoffStateLeased || stillLeased.ClaimedBy != "worker-successor" {
		t.Fatalf("the dead holder's late write landed: state=%q claimed_by=%q",
			stillLeased.State, stillLeased.ClaimedBy)
	}

	// The live holder finishes. Exactly one attempt is applied, and exactly
	// one row exists: no duplicate side effect is observable.
	if err := f.q.ReleaseLease(live, record.HandoffStateValidated); err != nil {
		t.Fatalf("ReleaseLease: %v", err)
	}
	final, err := f.q.Get(row.HandoffID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if final.State != record.HandoffStateValidated {
		t.Errorf("final state = %q, want %q", final.State, record.HandoffStateValidated)
	}
	if final.Attempts != 2 {
		t.Errorf("attempts = %d, want 2 (one crashed, one completed)", final.Attempts)
	}
	if final.ClaimedBy != "" || !final.LeaseExpiresAt.IsZero() {
		t.Errorf("a finished row still carries a lease: claimed_by=%q expires=%v",
			final.ClaimedBy, final.LeaseExpiresAt)
	}
	if n := f.countHandoffRows(); n != 1 {
		t.Errorf("%d handoff rows, want 1: the crash must not duplicate the finding", n)
	}
	if f.packetExists(fingerprint) {
		t.Error("packet survived a terminal release")
	}
}

func TestLeaseExhaustionAfterMaxAttempts(t *testing.T) {
	f := newFixture(t, Options{Lease: 20 * time.Minute, MaxAttempts: 2})
	audit := f.sealedAudit()
	fingerprint, row := f.enqueue(5, record.ConsumptionClassStaticOnly, audit)

	for attempt := 1; attempt <= 2; attempt++ {
		h, err := f.q.Claim(fingerprint, fmt.Sprintf("worker-%d", attempt))
		if err != nil {
			t.Fatalf("claim %d: %v", attempt, err)
		}
		if _, err := f.q.WritePacket(h, []byte("packet")); err != nil {
			t.Fatalf("WritePacket %d: %v", attempt, err)
		}
		f.clock.Advance(21 * time.Minute)
		report, err := f.q.ReclaimExpired()
		if err != nil {
			t.Fatalf("ReclaimExpired %d: %v", attempt, err)
		}
		if len(report.Reclaimed) != 1 {
			t.Fatalf("sweep %d reclaimed %d rows, want 1", attempt, len(report.Reclaimed))
		}
		want := record.HandoffStateReady
		if attempt == 2 {
			want = ExhaustedState
		}
		if report.Reclaimed[0].To != want {
			t.Fatalf("sweep %d moved the row to %q, want %q", attempt, report.Reclaimed[0].To, want)
		}
	}

	if report, err := f.q.ReclaimExpired(); err != nil {
		t.Fatalf("ReclaimExpired: %v", err)
	} else if report.Exhausted() != 0 || !report.Empty() {
		t.Errorf("a terminal row was swept again: %+v", report)
	}
	if got := f.state(row.HandoffID); got != ExhaustedState {
		t.Errorf("state = %q, want %q", got, ExhaustedState)
	}
	// Terminal means no further lease, ever.
	if _, err := f.q.Claim(fingerprint, "worker-3"); !errors.Is(err, ErrNotEligible) {
		t.Errorf("claiming a terminal row: err = %v, want ErrNotEligible", err)
	}
	if f.packetExists(fingerprint) {
		t.Error("packet survived exhaustion")
	}
	// The row is kept. Nothing in this package deletes findings.
	if n := f.countHandoffRows(); n != 1 {
		t.Errorf("%d handoff rows after exhaustion, want 1", n)
	}
}

// ---------------------------------------------------------------------------
// The two clocks. They must fire independently and produce different
// transitions.
// ---------------------------------------------------------------------------

func TestLeaseExpiryFiresWithoutTheClaimTimeout(t *testing.T) {
	f := newFixture(t, Options{Lease: 20 * time.Minute, MaxAttempts: 2})
	// An 8-hour claim window: far beyond the 20-minute lease.
	audit := f.newAudit(record.StateBothSealed, record.HalfStatusSealed,
		record.DastStatusCompletedClean, f.clock.Now().Add(8*time.Hour))
	fingerprint, row := f.enqueue(6, record.ConsumptionClassStaticOnly, audit)

	if _, err := f.q.Claim(fingerprint, "worker-a"); err != nil {
		t.Fatalf("Claim: %v", err)
	}
	f.clock.Advance(21 * time.Minute)

	// The claim-timeout clock has not moved anywhere near its deadline.
	timeouts, err := f.q.ExpireClaimTimeouts()
	if err != nil {
		t.Fatalf("ExpireClaimTimeouts: %v", err)
	}
	if len(timeouts.Expired) != 0 {
		t.Fatalf("the claim-timeout sweep fired at 21 minutes into an 8-hour window: %+v", timeouts.Expired)
	}

	leases, err := f.q.ReclaimExpired()
	if err != nil {
		t.Fatalf("ReclaimExpired: %v", err)
	}
	if len(leases.Reclaimed) != 1 || leases.Reclaimed[0].To != record.HandoffStateReady {
		t.Fatalf("lease sweep = %+v, want one requeue to ready", leases.Reclaimed)
	}
	if got := f.state(row.HandoffID); got != record.HandoffStateReady {
		t.Errorf("state = %q, want %q — the lease clock requeues, it never expires", got, record.HandoffStateReady)
	}
}

func TestClaimTimeoutNeverExpiresALiveClaimAndKeepsTheRow(t *testing.T) {
	f := newFixture(t, Options{Lease: 20 * time.Minute, MaxAttempts: 2})
	deadline := f.clock.Now().Add(8 * time.Hour)
	audit := f.newAudit(record.StateBothSealed, record.HalfStatusSealed,
		record.DastStatusCompletedClean, deadline)
	fingerprint, row := f.enqueue(7, record.ConsumptionClassStaticOnly, audit)

	handle, err := f.q.Claim(fingerprint, "worker-long-runner")
	if err != nil {
		t.Fatalf("Claim: %v", err)
	}
	if _, err := f.q.WritePacket(handle, []byte("packet")); err != nil {
		t.Fatalf("WritePacket: %v", err)
	}

	// Walk past the 8-hour claim deadline while heartbeating, the way a
	// consumer that is genuinely still working does.
	for i := 0; i < 27; i++ {
		f.clock.Advance(19 * time.Minute)
		if handle, err = f.q.RenewLease(handle); err != nil {
			t.Fatalf("RenewLease at step %d: %v", i, err)
		}
	}
	if !f.clock.Now().After(deadline) {
		t.Fatalf("clock is at %s, which is not past the %s claim deadline: the test proves nothing",
			formatTime(f.clock.Now()), formatTime(deadline))
	}

	report, err := f.q.Reap()
	if err != nil {
		t.Fatalf("Reap: %v", err)
	}
	if !report.Empty() {
		t.Fatalf("the reaper touched a live claim past its audit deadline: %+v", report)
	}
	live, err := f.q.Get(row.HandoffID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if live.State != record.HandoffStateLeased || live.ClaimedBy != "worker-long-runner" {
		t.Fatalf("live claim was disturbed: state=%q claimed_by=%q", live.State, live.ClaimedBy)
	}
	if !f.packetExists(fingerprint) {
		t.Error("a live claim's packet was dropped")
	}
	// And the holder can still read it: the lease is live and the gate is open.
	if _, err := f.q.ReadPacket(handle); err != nil {
		t.Errorf("the live holder cannot read its own packet: %v", err)
	}

	// Now the holder stops heartbeating. The lease clock requeues it, and only
	// then does the claim-timeout clock see a 'ready' row past its deadline.
	f.clock.Advance(21 * time.Minute)
	report, err = f.q.Reap()
	if err != nil {
		t.Fatalf("Reap: %v", err)
	}
	if report.Requeued() != 1 {
		t.Errorf("lease sweep requeued %d, want 1", report.Requeued())
	}
	if len(report.Expired) != 1 {
		t.Fatalf("claim-timeout sweep expired %d rows, want 1", len(report.Expired))
	}
	if !report.Expired[0].PacketDropped {
		t.Error("the expiring finding's packet was not dropped")
	}
	if got := f.state(row.HandoffID); got != record.HandoffStateExpired {
		t.Errorf("state = %q, want %q", got, record.HandoffStateExpired)
	}
	if f.packetExists(fingerprint) {
		t.Error("packet survived the claim timeout")
	}

	// S1: a claim timeout is not a deletion policy. The row, the finding and
	// the audit record are all still here.
	if n := f.countHandoffRows(); n != 1 {
		t.Errorf("%d handoff rows after expiry, want 1: the reaper must not delete rows", n)
	}
	var findings, audits int
	if err := f.db.QueryRow(`SELECT COUNT(*) FROM finding`).Scan(&findings); err != nil {
		t.Fatalf("count finding: %v", err)
	}
	if err := f.db.QueryRow(`SELECT COUNT(*) FROM audit_record`).Scan(&audits); err != nil {
		t.Fatalf("count audit_record: %v", err)
	}
	if findings != 1 || audits != 1 {
		t.Errorf("finding rows = %d, audit_record rows = %d, want 1 and 1", findings, audits)
	}
	// And the payload it points at is untouched: purging a shared payload
	// because one finding's window lapsed would blind its siblings.
	var payloadSHA string
	if err := f.db.QueryRow(`SELECT payload_sha256 FROM audit_record WHERE audit_record_id = ?`, audit).Scan(&payloadSHA); err != nil {
		t.Fatalf("read payload_sha256: %v", err)
	}
	if payloadSHA == "" {
		t.Error("payload_sha256 must survive: it is the proof of what was handed over")
	}
}

func TestLateHeartbeatKeepsTheClaim(t *testing.T) {
	f := newFixture(t, Options{Lease: 20 * time.Minute, MaxAttempts: 2})
	audit := f.sealedAudit()
	fingerprint, row := f.enqueue(21, record.ConsumptionClassStaticOnly, audit)

	stale, err := f.q.Claim(fingerprint, "worker-slow")
	if err != nil {
		t.Fatalf("Claim: %v", err)
	}

	// The heartbeat arrives after the nominal expiry but before the sweep. The
	// holder is demonstrably alive, so it keeps the finding.
	f.clock.Advance(21 * time.Minute)
	fresh, err := f.q.RenewLease(stale)
	if err != nil {
		t.Fatalf("late RenewLease: %v", err)
	}
	if !fresh.LeaseExpiresAt.After(f.clock.Now()) {
		t.Fatalf("renewed lease expires at %s, which is not in the future", formatTime(fresh.LeaseExpiresAt))
	}

	report, err := f.q.ReclaimExpired()
	if err != nil {
		t.Fatalf("ReclaimExpired: %v", err)
	}
	if !report.Empty() {
		t.Fatalf("the reaper took a renewed claim: %+v", report)
	}
	live, err := f.q.Get(row.HandoffID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if live.State != record.HandoffStateLeased || live.ClaimedBy != "worker-slow" {
		t.Fatalf("claim was disturbed: state=%q claimed_by=%q", live.State, live.ClaimedBy)
	}
	if live.Attempts != 1 {
		t.Errorf("attempts = %d; a renewal is not a new attempt", live.Attempts)
	}

	// The pre-renewal Handle is dead: renewing produces a new one and the old
	// one may no longer speak for the lease.
	if _, err := f.q.RenewLease(stale); !errors.Is(err, ErrLeaseLost) {
		t.Errorf("stale handle RenewLease: err = %v, want ErrLeaseLost", err)
	}
	if err := f.q.ReleaseLease(stale, record.HandoffStateValidated); !errors.Is(err, ErrLeaseLost) {
		t.Errorf("stale handle ReleaseLease: err = %v, want ErrLeaseLost", err)
	}
	if err := f.q.ReleaseLease(fresh, record.HandoffStateValidated); err != nil {
		t.Errorf("fresh handle ReleaseLease: %v", err)
	}
}

func TestExpireClaimTimeoutIsIdempotent(t *testing.T) {
	f := newFixture(t, Options{})
	audit := f.newAudit(record.StateBothSealed, record.HalfStatusSealed,
		record.DastStatusCompletedClean, f.clock.Now().Add(time.Hour))
	_, row := f.enqueue(8, record.ConsumptionClassStaticOnly, audit)

	f.clock.Advance(2 * time.Hour)
	first, err := f.q.ExpireClaimTimeouts()
	if err != nil {
		t.Fatalf("ExpireClaimTimeouts: %v", err)
	}
	if len(first.Expired) != 1 {
		t.Fatalf("expired %d rows, want 1", len(first.Expired))
	}
	second, err := f.q.ExpireClaimTimeouts()
	if err != nil {
		t.Fatalf("second ExpireClaimTimeouts: %v", err)
	}
	if !second.Empty() {
		t.Errorf("second sweep expired %d rows, want 0", len(second.Expired))
	}
	if got := f.state(row.HandoffID); got != record.HandoffStateExpired {
		t.Errorf("state = %q, want %q", got, record.HandoffStateExpired)
	}
}

// TestRunSweepsUntilCancelled exercises the reaper loop itself. Its ticker is
// wall-clock — a periodic timer is not something the injected clock drives —
// so the interval here is small and the assertion is only that sweeps happen
// and that cancellation ends the loop.
func TestRunSweepsUntilCancelled(t *testing.T) {
	f := newFixture(t, Options{Lease: 20 * time.Minute, MaxAttempts: 2})
	audit := f.sealedAudit()
	fingerprint, row := f.enqueue(22, record.ConsumptionClassStaticOnly, audit)
	if _, err := f.q.Claim(fingerprint, "worker-doomed"); err != nil {
		t.Fatalf("Claim: %v", err)
	}
	f.clock.Advance(21 * time.Minute)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	reclaimed := make(chan Reclaimed, 4)
	done := make(chan error, 1)
	go func() {
		done <- f.q.Run(ctx, 2*time.Millisecond, func(report ReapReport, err error) {
			if err != nil {
				t.Errorf("sweep error: %v", err)
				return
			}
			for _, c := range report.Reclaimed {
				select {
				case reclaimed <- c:
				default:
				}
			}
		})
	}()

	select {
	case c := <-reclaimed:
		if c.HandoffID != row.HandoffID || c.To != record.HandoffStateReady {
			t.Errorf("reclaimed %+v, want row %d requeued to ready", c, row.HandoffID)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the reaper loop never swept the expired lease")
	}

	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Errorf("Run returned %v, want context.Canceled", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Run did not return after cancellation")
	}
}

// ---------------------------------------------------------------------------
// Lease authority: what a Handle may and may not do.
// ---------------------------------------------------------------------------

func TestRecordVersionBumpVoidsTheLease(t *testing.T) {
	f := newFixture(t, Options{})
	audit := f.sealedAudit()
	fingerprint, row := f.enqueue(9, record.ConsumptionClassStaticOnly, audit)

	handle, err := f.q.Claim(fingerprint, "worker-a")
	if err != nil {
		t.Fatalf("Claim: %v", err)
	}
	if handle.RecordVersion != 1 {
		t.Fatalf("RecordVersion = %d, want 1", handle.RecordVersion)
	}

	// S6: a version bump re-cuts the work queue. The leased work unit is gone.
	if _, err := f.db.Exec(`UPDATE audit_record SET audit_version = 2 WHERE audit_record_id = ?`, audit); err != nil {
		t.Fatalf("bump audit_version: %v", err)
	}

	if _, err := f.q.RenewLease(handle); !errors.Is(err, ErrRecordVersionChanged) {
		t.Errorf("RenewLease after a version bump: err = %v, want ErrRecordVersionChanged", err)
	}
	if err := f.q.ReleaseLease(handle, record.HandoffStateValidated); !errors.Is(err, ErrRecordVersionChanged) {
		t.Errorf("ReleaseLease after a version bump: err = %v, want ErrRecordVersionChanged", err)
	}
	if got := f.state(row.HandoffID); got != record.HandoffStateLeased {
		t.Errorf("state = %q: a refused release must not change the row", got)
	}
}

func TestReleaseLeaseRejectsIllegalOutcomes(t *testing.T) {
	f := newFixture(t, Options{})
	audit := f.sealedAudit()
	fingerprint, _ := f.enqueue(10, record.ConsumptionClassStaticOnly, audit)
	handle, err := f.q.Claim(fingerprint, "worker-a")
	if err != nil {
		t.Fatalf("Claim: %v", err)
	}

	// 'expired' belongs to the claim-timeout clock, not to a consumer.
	if err := f.q.ReleaseLease(handle, record.HandoffStateExpired); !errors.Is(err, ErrIllegalTransition) {
		t.Errorf("release as expired: err = %v, want ErrIllegalTransition", err)
	}
	// A state outside the frozen thirteen never reaches the database.
	if err := f.q.ReleaseLease(handle, record.HandoffState("done")); err == nil {
		t.Error("release as an unknown state must be rejected")
	}
	// Handing the finding back is legal and clears the lease.
	if err := f.q.ReleaseLease(handle, record.HandoffStateReady); err != nil {
		t.Fatalf("release back to ready: %v", err)
	}
	row, err := f.q.Get(handle.HandoffID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if row.State != record.HandoffStateReady || row.ClaimedBy != "" {
		t.Errorf("after release: state=%q claimed_by=%q", row.State, row.ClaimedBy)
	}
}

func TestDisposeOnlyLeavesReady(t *testing.T) {
	f := newFixture(t, Options{})
	audit := f.sealedAudit()
	fingerprint, row := f.enqueue(11, record.ConsumptionClassStaticOnly, audit)

	// The queue re-cut skips a ready finding for budget without leasing it.
	if err := f.q.Dispose(row.HandoffID, record.HandoffStateSkippedBudget); err != nil {
		t.Fatalf("Dispose: %v", err)
	}
	if got := f.state(row.HandoffID); got != record.HandoffStateSkippedBudget {
		t.Fatalf("state = %q, want %q", got, record.HandoffStateSkippedBudget)
	}
	// G10's failure mode: the disposition and the ready-set index must agree,
	// so a skipped finding is not re-leased forever.
	if _, err := f.q.Claim(fingerprint, "worker-a"); !errors.Is(err, ErrNotEligible) {
		t.Errorf("a skipped_budget finding was still claimable: err = %v", err)
	}
	if err := f.q.Dispose(row.HandoffID, record.HandoffStateWithdrawn); !errors.Is(err, ErrIllegalTransition) {
		t.Errorf("disposing a terminal row: err = %v, want ErrIllegalTransition", err)
	}

	// A leased row is not disposable behind its holder's back.
	audit2 := f.sealedAudit()
	fingerprint2, row2 := f.enqueue(12, record.ConsumptionClassStaticOnly, audit2)
	if _, err := f.q.Claim(fingerprint2, "worker-b"); err != nil {
		t.Fatalf("Claim: %v", err)
	}
	if err := f.q.Dispose(row2.HandoffID, record.HandoffStateSkippedBudget); !errors.Is(err, ErrAlreadyClaimed) {
		t.Errorf("disposing a leased row: err = %v, want ErrAlreadyClaimed", err)
	}
	if err := f.q.Dispose(row2.HandoffID, record.HandoffStateLeased); !errors.Is(err, ErrIllegalTransition) {
		t.Errorf("Dispose must never grant a lease: err = %v", err)
	}
}

// ---------------------------------------------------------------------------
// Enqueue, keys and packets.
// ---------------------------------------------------------------------------

func TestEnqueueIsIdempotent(t *testing.T) {
	f := newFixture(t, Options{})
	audit := f.sealedAudit()
	fingerprint := fp(13)
	findingID := f.newFinding(fingerprint)

	req := EnqueueRequest{
		FindingID:        findingID,
		AuditRecordID:    audit,
		AuditID:          auditUUID(audit),
		Fingerprint:      fingerprint,
		ConsumptionClass: record.ConsumptionClassStaticOnly,
	}
	first, err := f.q.Enqueue(req)
	if err != nil {
		t.Fatalf("Enqueue: %v", err)
	}
	if _, err := f.q.Claim(fingerprint, "worker-a"); err != nil {
		t.Fatalf("Claim: %v", err)
	}

	// A producer that crashed after inserting and re-runs must not duplicate
	// the row, and must not reset the lease.
	second, err := f.q.Enqueue(req)
	if err != nil {
		t.Fatalf("re-Enqueue: %v", err)
	}
	if second.HandoffID != first.HandoffID {
		t.Errorf("re-enqueue produced row %d, want %d", second.HandoffID, first.HandoffID)
	}
	if second.State != record.HandoffStateLeased {
		t.Errorf("re-enqueue reset the state to %q", second.State)
	}
	if n := f.countHandoffRows(); n != 1 {
		t.Errorf("%d handoff rows, want 1", n)
	}
	if second.IdempotencyKey != first.IdempotencyKey || first.IdempotencyKey == "" {
		t.Errorf("idempotency key is not stable: %q vs %q", first.IdempotencyKey, second.IdempotencyKey)
	}
	want := IdempotencyKey(auditUUID(audit), fingerprint, "9f1c0de9f1c0de9f1c0de9f1c0de9f1c0de9f1c0")
	if first.IdempotencyKey != want {
		t.Errorf("idempotency key = %s, want sha256(audit_id || fingerprint || base commit) = %s",
			first.IdempotencyKey, want)
	}
}

// TestIdempotencyKeyUsesTheDocumentedInputs is CRITIQUE-02 F7. schema.sql and
// this package's own doc both say sha256(audit_id || finding_fingerprint ||
// base_commit_sha); the implementation hashed `audit_record_id`, an
// autoincrement rowid. A rowid is not an audit identity, and the value is
// EXPORTED for the coding agent to write into a git trailer, where a rowid
// means nothing to anyone who does not hold that exact database file.
func TestIdempotencyKeyUsesTheDocumentedInputs(t *testing.T) {
	const (
		auditID = "0f9c2b1e-4a7d-4c33-9f21-6b8a0d5e7c14"
		commit  = "9f1c0de9f1c0de9f1c0de9f1c0de9f1c0de9f1c0"
	)
	fingerprint := fp(60)

	// The key is a pure function of the three documented components.
	if got, want := IdempotencyKey(auditID, fingerprint, commit),
		IdempotencyKey(auditID, fingerprint, commit); got != want {
		t.Fatalf("IdempotencyKey is not deterministic")
	}
	// Each component moves it.
	base := IdempotencyKey(auditID, fingerprint, commit)
	for _, other := range []string{
		IdempotencyKey("0f9c2b1e-4a7d-4c33-9f21-6b8a0d5e7c15", fingerprint, commit),
		IdempotencyKey(auditID, fp(61), commit),
		IdempotencyKey(auditID, fingerprint, "0000000000000000000000000000000000000000"),
	} {
		if other == base {
			t.Error("a component of the documented triple does not affect the key")
		}
	}
	// No rowid can reproduce it. This is the regression: if the function ever
	// goes back to hashing audit_record_id, the key for the same audit
	// identity changes, and no small integer spelling of the rowid produces
	// the documented value.
	for id := int64(0); id < 64; id++ {
		if IdempotencyKey(fmt.Sprint(id), fingerprint, commit) == base {
			t.Errorf("IdempotencyKey(audit_record_id=%d, ...) collides with the documented key; "+
				"the first component must be anvil/auditId", id)
		}
	}
	// Boundary shifting cannot forge a collision either: the NUL joiner is
	// what stops ("ab", "c") and ("a", "bc") hashing the same.
	if IdempotencyKey("ab", "c"+fingerprint[1:], commit) == IdempotencyKey("a", "bc"+fingerprint[1:], commit) {
		t.Error("components are not delimited; a boundary shift forges a collision")
	}
}

// TestEnqueueRequiresTheAuditIdentity: rather than silently substituting the
// rowid when the caller omits anvil/auditId, Enqueue refuses. A key computed
// from the wrong identity is worse than no key, because downstream dedup would
// trust it.
func TestEnqueueRequiresTheAuditIdentity(t *testing.T) {
	f := newFixture(t, Options{})
	audit := f.sealedAudit()
	fingerprint := fp(62)
	findingID := f.newFinding(fingerprint)

	if _, err := f.q.Enqueue(EnqueueRequest{
		FindingID: findingID, AuditRecordID: audit, Fingerprint: fingerprint,
		ConsumptionClass: record.ConsumptionClassStaticOnly,
	}); err == nil {
		t.Error("Enqueue accepted a request with no anvil/auditId")
	}
	if n := f.countHandoffRows(); n != 0 {
		t.Errorf("%d rows were inserted despite the refusal", n)
	}
}

func TestEnqueueRejectsMalformedInput(t *testing.T) {
	f := newFixture(t, Options{})
	audit := f.sealedAudit()
	fingerprint := fp(14)
	findingID := f.newFinding(fingerprint)

	if _, err := f.q.Enqueue(EnqueueRequest{
		FindingID: findingID, AuditRecordID: audit, AuditID: auditUUID(audit),
		Fingerprint:      fingerprint[:16], // truncated digests are never legal
		ConsumptionClass: record.ConsumptionClassStaticOnly,
	}); err == nil {
		t.Error("a truncated fingerprint must be rejected")
	}
	if _, err := f.q.Enqueue(EnqueueRequest{
		FindingID: findingID, AuditRecordID: audit, AuditID: auditUUID(audit),
		Fingerprint:      fingerprint,
		ConsumptionClass: record.ConsumptionClass(""),
	}); err == nil {
		t.Error("consumption_class has no default and must be rejected when empty")
	}
}

func TestPacketWriteReadDrop(t *testing.T) {
	f := newFixture(t, Options{})
	audit := f.sealedAudit()
	fingerprint, _ := f.enqueue(15, record.ConsumptionClassStaticOnly, audit)
	h, err := f.q.Claim(fingerprint, "worker-a")
	if err != nil {
		t.Fatalf("Claim: %v", err)
	}

	path, err := f.q.WritePacket(h, []byte("first"))
	if err != nil {
		t.Fatalf("WritePacket: %v", err)
	}
	if filepath.Dir(path) != f.packetDir {
		t.Errorf("packet landed in %s, want %s", filepath.Dir(path), f.packetDir)
	}
	// Replacement is a rename over the same name: no torn read is observable.
	if _, err := f.q.WritePacket(h, []byte("second")); err != nil {
		t.Fatalf("re-WritePacket: %v", err)
	}
	data, err := f.q.ReadPacket(h)
	if err != nil {
		t.Fatalf("ReadPacket: %v", err)
	}
	if string(data) != "second" {
		t.Errorf("packet = %q, want %q", data, "second")
	}
	// No temp files left behind.
	entries, err := os.ReadDir(f.packetDir)
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	if len(entries) != 1 {
		t.Errorf("packet directory holds %d entries, want 1", len(entries))
	}

	if err := f.q.DropPacket(fingerprint); err != nil {
		t.Fatalf("DropPacket: %v", err)
	}
	// Dropping a packet that is not there is success: the packet is a cache
	// and its absence is the desired state.
	if err := f.q.DropPacket(fingerprint); err != nil {
		t.Errorf("second DropPacket: %v", err)
	}
}

func TestPacketPathRejectsTraversal(t *testing.T) {
	f := newFixture(t, Options{})
	for _, bad := range []string{
		"../../../etc/passwd",
		strings.Repeat("A", 64), // uppercase hex is not the contract's spelling
		"",
		strings.Repeat("z", 64),
	} {
		if _, err := f.q.PacketPath(bad); err == nil {
			t.Errorf("PacketPath(%q) was accepted", bad)
		}
	}
}

func TestPacketDirIsOptional(t *testing.T) {
	f := newFixture(t, Options{})
	// A Queue without a packet directory is legal: the packet is a cache, and
	// a deployment that hands the consumer bytes needs no directory at all.
	q, err := New(f.db, Options{Clock: f.clock.Now})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if _, err := q.PacketPath(fp(16)); !errors.Is(err, ErrNoPacketDir) {
		t.Errorf("PacketPath without a dir: err = %v, want ErrNoPacketDir", err)
	}
	if err := q.DropPacket(fp(16)); err != nil {
		t.Errorf("DropPacket without a dir: %v", err)
	}

	audit := f.sealedAudit()
	fingerprint := fp(17)
	findingID := f.newFinding(fingerprint)
	if _, err := q.Enqueue(EnqueueRequest{
		FindingID: findingID, AuditRecordID: audit, AuditID: auditUUID(audit),
		Fingerprint:      fingerprint,
		ConsumptionClass: record.ConsumptionClassStaticOnly,
	}); err != nil {
		t.Fatalf("Enqueue: %v", err)
	}
	h, err := q.Claim(fingerprint, "worker-a")
	if err != nil {
		t.Fatalf("Claim: %v", err)
	}
	if h.PacketPath != "" {
		t.Errorf("Handle.PacketPath = %q, want empty", h.PacketPath)
	}
	if err := q.ReleaseLease(h, record.HandoffStateValidated); err != nil {
		t.Errorf("ReleaseLease with no packet directory: %v", err)
	}
}

func TestClaimUnknownFingerprint(t *testing.T) {
	f := newFixture(t, Options{})
	if _, err := f.q.Claim(fp(18), "worker-a"); !errors.Is(err, ErrNotFound) {
		t.Errorf("claiming an unqueued fingerprint: err = %v, want ErrNotFound", err)
	}
	if _, err := f.q.Claim("not-a-fingerprint", "worker-a"); err == nil {
		t.Error("a malformed fingerprint must be rejected before it reaches SQL")
	}
	if _, err := f.q.Claim(fp(18), ""); err == nil {
		t.Error("an empty workerID must be rejected")
	}
}

func TestTimestampsAreFixedWidthAndOrdered(t *testing.T) {
	// The lease and deadline comparisons are made in Go, but the stored format
	// is still fixed width so that a later index range scan cannot be wrong.
	// time.RFC3339Nano would fail this: "…00Z" sorts after "…00.5Z".
	base := time.Date(2026, 8, 8, 10, 0, 0, 0, time.UTC)
	a := formatTime(base)
	b := formatTime(base.Add(500 * time.Millisecond))
	if len(a) != len(b) {
		t.Fatalf("timestamps are not fixed width: %q vs %q", a, b)
	}
	if !(a < b) {
		t.Errorf("%q must sort before %q", a, b)
	}
	if rfc := base.Format(time.RFC3339Nano); rfc < base.Add(500*time.Millisecond).Format(time.RFC3339Nano) {
		t.Log("note: RFC3339Nano happened to order correctly for this pair; the format is still not fixed width")
	}
	back, err := parseTime("test", a)
	if err != nil || !back.Equal(base) {
		t.Errorf("round trip: %v, %v", back, err)
	}
}

// ---------------------------------------------------------------------------
// The stop condition: no code path claims secure deletion.
//
// This is checked structurally rather than with a naive text grep, because the
// package deliberately DOCUMENTS why shred is not a control here (research/08
// §F) and that explanation must survive. What must not exist is an executed
// reference or an affirmative claim.
// ---------------------------------------------------------------------------

func TestNoSecureDeletionClaimOrCall(t *testing.T) {
	fset := token.NewFileSet()
	// Test files are excluded from both scans: this file necessarily contains
	// the denylist itself, and the stop condition is about the shipped code
	// paths.
	implementationOnly := func(fi os.FileInfo) bool {
		return strings.HasSuffix(fi.Name(), ".go") && !strings.HasSuffix(fi.Name(), "_test.go")
	}
	pkgs, err := parser.ParseDir(fset, ".", implementationOnly, parser.ParseComments)
	if err != nil {
		t.Fatalf("parsing the package: %v", err)
	}
	if len(pkgs) == 0 {
		t.Fatal("no package parsed")
	}

	// Executed code: no identifier and no string literal may name an erasure
	// tool, and nothing may shell out at all.
	forbiddenTokens := []string{"shred", "rm -p", "rm -f -p", "secure_delete", "blkdiscard"}
	for _, pkg := range pkgs {
		for name, file := range pkg.Files {
			for _, imp := range file.Imports {
				if imp.Path.Value == `"os/exec"` {
					t.Errorf("%s imports os/exec: this package runs no external eraser", name)
				}
			}
			ast.Inspect(file, func(n ast.Node) bool {
				switch v := n.(type) {
				case *ast.Ident:
					for _, bad := range forbiddenTokens {
						if strings.Contains(strings.ToLower(v.Name), strings.ReplaceAll(bad, " ", "")) {
							t.Errorf("%s: identifier %q references an erasure primitive", name, v.Name)
						}
					}
				case *ast.BasicLit:
					if v.Kind != token.STRING {
						return true
					}
					lower := strings.ToLower(v.Value)
					for _, bad := range forbiddenTokens {
						if strings.Contains(lower, bad) {
							t.Errorf("%s: string literal %s references an erasure primitive", name, v.Value)
						}
					}
				}
				return true
			})
		}
	}

	// Prose: no affirmative claim of secure destruction anywhere, comments
	// included. The negations the package does make ("makes no claim that the
	// bytes are unrecoverable") are not on this list, and must not be.
	claims := []string{
		"securely delet", "securely destroy", "securely eras", "secure erasure",
		"cryptographically eras", "we shred", "shred the", "wiped from disk",
		"unrecoverably",
	}
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".go") || strings.HasSuffix(e.Name(), "_test.go") {
			continue
		}
		src, err := os.ReadFile(e.Name())
		if err != nil {
			t.Fatalf("ReadFile %s: %v", e.Name(), err)
		}
		lower := strings.ToLower(string(src))
		for _, claim := range claims {
			if strings.Contains(lower, claim) {
				t.Errorf("%s claims secure deletion (%q); research/08 §F: shred cannot deliver it on "+
					"Btrfs, ZFS, XFS, snapshotting or RAID filesystems, or on any SSD", e.Name(), claim)
			}
		}
	}

	// And the affirmative disclaimer is present, so the reasoning is not lost
	// the next time someone proposes adding one.
	src, err := os.ReadFile("claim.go")
	if err != nil {
		t.Fatalf("ReadFile claim.go: %v", err)
	}
	if !strings.Contains(string(src), "unlink, not an erasure") {
		t.Error("DropPacket must state plainly that it unlinks and does not erase")
	}
}

// ---------------------------------------------------------------------------
// Enum discipline: no handoff.state or consumption_class literal is re-typed
// as a bare string in this package. Every one comes from internal/record.
// ---------------------------------------------------------------------------

func TestNoBareEnumLiteralsInPackageCode(t *testing.T) {
	var vocabulary []string
	for _, s := range record.HandoffStateValues() {
		vocabulary = append(vocabulary, string(s))
	}
	for _, c := range record.ConsumptionClassValues() {
		vocabulary = append(vocabulary, string(c))
	}
	for _, s := range record.HalfStatusValues() {
		vocabulary = append(vocabulary, string(s))
	}

	fset := token.NewFileSet()
	pkgs, err := parser.ParseDir(fset, ".", func(fi os.FileInfo) bool {
		// The test file itself may not name them either, but it legitimately
		// contains English prose in messages; only the implementation files
		// are checked for literals.
		return strings.HasSuffix(fi.Name(), ".go") && !strings.HasSuffix(fi.Name(), "_test.go")
	}, parser.ParseComments)
	if err != nil {
		t.Fatalf("parsing the package: %v", err)
	}

	for _, pkg := range pkgs {
		for name, file := range pkg.Files {
			ast.Inspect(file, func(n ast.Node) bool {
				lit, ok := n.(*ast.BasicLit)
				if !ok || lit.Kind != token.STRING {
					return true
				}
				value := strings.Trim(lit.Value, "`\"")
				for _, word := range vocabulary {
					if value == word {
						t.Errorf("%s: %q is an enum literal re-typed as a bare string; "+
							"use the internal/record constant", filepath.Base(name), value)
					}
				}
				return true
			})
		}
	}
}

// ---------------------------------------------------------------------------
// Regression guards for CRITIQUE-02 (R.10 critic gate 2).
// ---------------------------------------------------------------------------

// enqueueInto puts an EXISTING finding into a second audit_record's ready set.
// This is the shape a re-scan produces: one fingerprint, one finding row, and
// one handoff row per audit_record it appears in — which is legal, and which
// is what UNIQUE (finding_id, audit_record_id) permits.
func (f *fixture) enqueueInto(findingID int64, fingerprint string, class record.ConsumptionClass, auditID int64) Row {
	f.t.Helper()
	row, err := f.q.Enqueue(EnqueueRequest{
		FindingID:        findingID,
		AuditRecordID:    auditID,
		AuditID:          auditUUID(auditID),
		Fingerprint:      fingerprint,
		ConsumptionClass: class,
	})
	if err != nil {
		f.t.Fatalf("Enqueue into audit %d: %v", auditID, err)
	}
	return row
}

// TestOneLiveLeasePerFingerprintAndRecordVersion is CRITIQUE-02 F1.
//
// A re-scan makes a NEW audit_record (scan_run_id is UNIQUE, so it must), and
// audit_version DEFAULTs to 1 on each, so one fingerprint ends up with several
// rows ALL AT VERSION 1. The two entry points then diverged onto different
// rows — AcquireLease took the oldest, Claim the newest — and granted two live
// leases on one defect at one record version. Both workers renewed, both
// released, both wrote 'validated'. research/08 §4 point 2 forbids exactly
// that outcome: "Expiring it would let a second agent write a competing fix
// for the same defect."
//
// checkRecordVersion cannot catch it: it compares a Handle against ITS OWN
// row's audit_version, which never moved.
func TestOneLiveLeasePerFingerprintAndRecordVersion(t *testing.T) {
	f := newFixture(t, Options{Lease: 20 * time.Minute, MaxAttempts: 2})

	first := f.sealedAudit()
	second := f.sealedAudit() // the re-scan
	fingerprint := fp(40)
	findingID := f.newFinding(fingerprint)
	older := f.enqueueInto(findingID, fingerprint, record.ConsumptionClassStaticOnly, first)
	newer := f.enqueueInto(findingID, fingerprint, record.ConsumptionClassStaticOnly, second)
	if older.HandoffID == newer.HandoffID {
		t.Fatalf("fixture bug: both enqueues produced row %d; the test needs two rows", older.HandoffID)
	}

	// Both rows are at record version 1, which is what makes this a double
	// grant at ONE version rather than two versions of the work.
	for _, row := range []Row{older, newer} {
		var version int64
		if err := f.db.QueryRow(`SELECT audit_version FROM audit_record WHERE audit_record_id = ?`,
			row.AuditRecordID).Scan(&version); err != nil {
			t.Fatalf("read audit_version: %v", err)
		}
		if version != 1 {
			t.Fatalf("fixture bug: audit_record %d is at version %d, want 1", row.AuditRecordID, version)
		}
	}

	held, err := f.q.Claim(fingerprint, "worker-1")
	if err != nil {
		t.Fatalf("first Claim: %v", err)
	}

	// The second worker must be refused, by BOTH entry points, however it
	// arrives. Claim names the fingerprint; AcquireLease scans the queue and
	// would previously have picked the OTHER row.
	if _, err := f.q.Claim(fingerprint, "worker-2"); !errors.Is(err, ErrAlreadyClaimed) {
		t.Errorf("second Claim on a live fingerprint: err = %v, want ErrAlreadyClaimed", err)
	}
	if h, err := f.q.AcquireLease("worker-2"); err == nil {
		t.Errorf("AcquireLease granted a SECOND live lease on %s (row %d, holder %q); "+
			"row %d is already held by %q at record version %d",
			h.Fingerprint, h.HandoffID, h.WorkerID, held.HandoffID, held.WorkerID, held.RecordVersion)
	} else if !errors.Is(err, ErrNoWork) {
		t.Errorf("AcquireLease: err = %v, want ErrNoWork", err)
	}

	// Exactly one row is leased.
	var leased int
	if err := f.db.QueryRow(`SELECT COUNT(*) FROM handoff WHERE fingerprint = ? AND state = ?`,
		fingerprint, string(record.HandoffStateLeased)).Scan(&leased); err != nil {
		t.Fatalf("count leased: %v", err)
	}
	if leased != 1 {
		t.Fatalf("%d live leases on one fingerprint at one record version, want 1", leased)
	}

	// The invariant is not "nothing else is ever claimable": OTHER work must
	// still flow, or the guard would have converted a double grant into a
	// stall.
	otherAudit := f.sealedAudit()
	otherFP, _ := f.enqueue(41, record.ConsumptionClassStaticOnly, otherAudit)
	other, err := f.q.AcquireLease("worker-2")
	if err != nil {
		t.Fatalf("AcquireLease for unrelated work: %v", err)
	}
	if other.Fingerprint != otherFP {
		t.Errorf("AcquireLease returned %s, want the unrelated finding %s", other.Fingerprint, otherFP)
	}

	// And once the holder finishes, the sibling row becomes claimable again —
	// the guard is about LIVE leases, not about the fingerprint forever.
	if err := f.q.ReleaseLease(held, record.HandoffStateFailedValidation); err != nil {
		t.Fatalf("ReleaseLease: %v", err)
	}
	successor, err := f.q.Claim(fingerprint, "worker-3")
	if err != nil {
		t.Fatalf("Claim after the first lease ended: %v", err)
	}
	if successor.HandoffID == held.HandoffID {
		t.Errorf("the terminal row %d was re-leased", held.HandoffID)
	}
}

// TestConcurrentClaimsAcrossSiblingRowsGrantOneLease races the guard itself,
// at the CAS, the way TestClaimCASAdmitsExactlyOneWinner races the
// `state = 'ready'` guard. Every goroutine starts from an already-selected
// candidate, so only the guard inside the UPDATE can separate them.
func TestConcurrentClaimsAcrossSiblingRowsGrantOneLease(t *testing.T) {
	f := newFixture(t, Options{})
	fingerprint := fp(42)

	// Every audit_record exists before the finding, because finding.first_seen_scan
	// references the newest scan_run.
	const siblings = 6
	var audits []int64
	for i := 0; i < siblings; i++ {
		audits = append(audits, f.sealedAudit())
	}
	findingID := f.newFinding(fingerprint)

	var rows []Row
	for _, audit := range audits {
		rows = append(rows, f.enqueueInto(findingID, fingerprint,
			record.ConsumptionClassStaticOnly, audit))
	}

	var (
		wg   sync.WaitGroup
		mu   sync.Mutex
		won  int
		errs []error
	)
	start := make(chan struct{})
	for i, row := range rows {
		wg.Add(1)
		go func(i int, row Row) {
			defer wg.Done()
			<-start
			_, ok, err := f.q.tryClaim(context.Background(), row.HandoffID, fmt.Sprintf("worker-%d", i))
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				errs = append(errs, err)
				return
			}
			if ok {
				won++
			}
		}(i, row)
	}
	close(start)
	wg.Wait()

	for _, err := range errs {
		t.Errorf("unexpected error: %v", err)
	}
	if won != 1 {
		t.Errorf("%d of %d sibling rows were leased concurrently, want exactly 1: "+
			"one fingerprint at one record version admits one live lease", won, siblings)
	}
}

// TestConsumedAuditKeepsTheQueueOpen is CRITIQUE-02 F2.
//
// 'consumed' is a legal audit_record.state that R.6's Consume sets, and R.6's
// own ReadHalf keeps a consumed audit READABLE because plan/00-SPINE.md S1
// requires a re-entrant consumer. The queue's gate listed only
// ('sast_sealed','both_sealed'), so the first consumption pass stranded every
// sibling finding still in 'ready' — unclaimable forever, then swept to
// 'expired' at the deadline. One audit fans out to many findings, so this was
// silent work loss on the exact axis S1 names.
func TestConsumedAuditKeepsTheQueueOpen(t *testing.T) {
	for _, class := range record.ConsumptionClassValues() {
		t.Run(string(class), func(t *testing.T) {
			f := newFixture(t, Options{})
			deadline := f.clock.Now().Add(time.Hour)
			audit := f.newAudit(record.StateBothSealed, record.HalfStatusSealed,
				record.DastStatusCompletedFindings, deadline)
			taken, takenRow := f.enqueue(43, class, audit)
			sibling, siblingRow := f.enqueue(44, class, audit)

			// The consumer takes the first finding and the pipeline marks the
			// shared audit consumed. That must not shut the gate on the rest.
			h, err := f.q.Claim(taken, "worker-a")
			if err != nil {
				t.Fatalf("Claim before consumption: %v", err)
			}
			if _, err := f.db.Exec(`UPDATE audit_record SET state = ? WHERE audit_record_id = ?`,
				string(record.StateConsumed), audit); err != nil {
				t.Fatalf("mark consumed: %v", err)
			}

			if _, err := f.q.Claim(sibling, "worker-b"); err != nil {
				t.Fatalf("a ready sibling finding became unclaimable once the audit was consumed: %v", err)
			}
			// A re-entrant consumer coming back for more work finds it.
			f.enqueue(45, class, audit)
			if _, err := f.q.AcquireLease("worker-c"); err != nil {
				t.Errorf("AcquireLease on a consumed audit: err = %v, want work", err)
			}
			// The lease holder from before consumption is unaffected, and can
			// still reach its own packet.
			if _, err := f.q.WritePacket(h, []byte("packet")); err != nil {
				t.Errorf("the holder cannot write its packet after consumption: %v", err)
			}
			if _, err := f.q.ReadPacket(h); err != nil {
				t.Errorf("the holder cannot read its packet after consumption: %v", err)
			}

			// And nothing is stranded into 'expired' at the deadline, which is
			// the second half of the defect: unclaimable rows were swept.
			f.clock.Advance(2 * time.Hour)
			report, err := f.q.ExpireClaimTimeouts()
			if err != nil {
				t.Fatalf("ExpireClaimTimeouts: %v", err)
			}
			for _, e := range report.Expired {
				if e.HandoffID == takenRow.HandoffID || e.HandoffID == siblingRow.HandoffID {
					t.Errorf("row %d was expired although it had been claimed", e.HandoffID)
				}
			}
		})
	}
}

// TestExpiredAuditStaysShut is the other side of the same gate: 'consumed' is
// readable, 'expired' is not, because R.6 refuses a read of an expired audit
// whose payload the reaper has dropped.
func TestExpiredAuditStaysShut(t *testing.T) {
	f := newFixture(t, Options{})
	audit := f.newAudit(record.StateBothSealed, record.HalfStatusSealed,
		record.DastStatusCompletedFindings, f.clock.Now().Add(time.Hour))
	fingerprint, _ := f.enqueue(46, record.ConsumptionClassStaticOnly, audit)

	if _, err := f.db.Exec(`UPDATE audit_record SET state = ? WHERE audit_record_id = ?`,
		string(record.StateExpired), audit); err != nil {
		t.Fatalf("mark expired: %v", err)
	}
	if _, err := f.q.Claim(fingerprint, "worker-a"); !errors.Is(err, ErrNotEligible) {
		t.Errorf("claiming against an expired audit: err = %v, want ErrNotEligible", err)
	}
}

// TestPacketReadIsGated is CRITIQUE-02 F5.
//
// ReadPacket is the only exported function in this package that returns a
// half's actual results. It verified neither seal state, nor audit state, nor
// lease ownership — a complete bypass of R.6's read gate, one line after the
// claim gate had correctly refused the same fingerprint. WritePacket likewise
// materialised a packet for an audit that had sealed nothing.
func TestPacketReadIsGated(t *testing.T) {
	t.Run("an unsealed audit has no readable packet", func(t *testing.T) {
		f := newFixture(t, Options{})
		audit := f.newAudit(record.StateCollecting, "", record.DastStatusNotRun,
			f.clock.Now().Add(8*time.Hour))
		fingerprint, row := f.enqueue(47, record.ConsumptionClassStaticOnly, audit)

		// The claim gate refuses, as designed.
		if _, err := f.q.Claim(fingerprint, "worker-a"); !errors.Is(err, ErrNotEligible) {
			t.Fatalf("Claim on an unsealed audit: err = %v, want ErrNotEligible", err)
		}
		// So must the packet, whatever Handle is presented for it.
		forged := Handle{
			HandoffID: row.HandoffID, FindingID: row.FindingID,
			AuditRecordID: row.AuditRecordID, Fingerprint: fingerprint,
			WorkerID: "worker-a", RecordVersion: 1,
			leaseToken: formatTime(f.clock.Now()),
		}
		if _, err := f.q.WritePacket(forged, []byte("results")); err == nil {
			t.Error("WritePacket materialised a packet for an audit that has sealed nothing")
		}
		if _, err := f.q.ReadPacket(forged); err == nil {
			t.Error("ReadPacket returned an unsealed half's results with no lease and no seal check")
		}
	})

	t.Run("only the lease holder may read", func(t *testing.T) {
		f := newFixture(t, Options{Lease: 20 * time.Minute, MaxAttempts: 2})
		audit := f.sealedAudit()
		fingerprint, _ := f.enqueue(48, record.ConsumptionClassStaticOnly, audit)
		h, err := f.q.Claim(fingerprint, "worker-a")
		if err != nil {
			t.Fatalf("Claim: %v", err)
		}
		if _, err := f.q.WritePacket(h, []byte("results")); err != nil {
			t.Fatalf("WritePacket: %v", err)
		}
		if _, err := f.q.ReadPacket(h); err != nil {
			t.Fatalf("the holder cannot read its own packet: %v", err)
		}

		// A different worker holding a Handle it did not earn.
		impostor := h
		impostor.WorkerID = "worker-b"
		if _, err := f.q.ReadPacket(impostor); !errors.Is(err, ErrLeaseLost) {
			t.Errorf("a non-holder read the packet: err = %v, want ErrLeaseLost", err)
		}
		if _, err := f.q.WritePacket(impostor, []byte("overwrite")); !errors.Is(err, ErrLeaseLost) {
			t.Errorf("a non-holder overwrote the packet: err = %v, want ErrLeaseLost", err)
		}

		// The OOM-killed holder wakes up after its lease was reclaimed. Its
		// Handle must not reach the successor's bytes either.
		f.clock.Advance(21 * time.Minute)
		if _, err := f.q.ReclaimExpired(); err != nil {
			t.Fatalf("ReclaimExpired: %v", err)
		}
		if _, err := f.q.ReadPacket(h); !errors.Is(err, ErrLeaseLost) {
			t.Errorf("a reclaimed holder read the packet: err = %v, want ErrLeaseLost", err)
		}
	})

	t.Run("a record version bump voids packet access", func(t *testing.T) {
		f := newFixture(t, Options{})
		audit := f.sealedAudit()
		fingerprint, _ := f.enqueue(49, record.ConsumptionClassStaticOnly, audit)
		h, err := f.q.Claim(fingerprint, "worker-a")
		if err != nil {
			t.Fatalf("Claim: %v", err)
		}
		if _, err := f.q.WritePacket(h, []byte("results")); err != nil {
			t.Fatalf("WritePacket: %v", err)
		}
		if _, err := f.db.Exec(`UPDATE audit_record SET audit_version = 2 WHERE audit_record_id = ?`, audit); err != nil {
			t.Fatalf("bump audit_version: %v", err)
		}
		if _, err := f.q.ReadPacket(h); !errors.Is(err, ErrRecordVersionChanged) {
			t.Errorf("ReadPacket after a version bump: err = %v, want ErrRecordVersionChanged", err)
		}
	})

	t.Run("a shut gate refuses even a live lease", func(t *testing.T) {
		f := newFixture(t, Options{})
		audit := f.sealedAudit()
		fingerprint, _ := f.enqueue(50, record.ConsumptionClassStaticOnly, audit)
		h, err := f.q.Claim(fingerprint, "worker-a")
		if err != nil {
			t.Fatalf("Claim: %v", err)
		}
		if _, err := f.q.WritePacket(h, []byte("results")); err != nil {
			t.Fatalf("WritePacket: %v", err)
		}
		// R.6 un-seals nothing in practice, but the gate must be re-evaluated
		// rather than trusted from claim time.
		if _, err := f.db.Exec(`UPDATE audit_record SET state = ?, sast_status = ? WHERE audit_record_id = ?`,
			string(record.StateCollecting), string(record.HalfStatusRunning), audit); err != nil {
			t.Fatalf("unseal: %v", err)
		}
		if _, err := f.q.ReadPacket(h); !errors.Is(err, ErrNotEligible) {
			t.Errorf("ReadPacket with the gate shut: err = %v, want ErrNotEligible", err)
		}
	})

	t.Run("a missing packet is still regenerable, not fatal", func(t *testing.T) {
		f := newFixture(t, Options{})
		audit := f.sealedAudit()
		fingerprint, _ := f.enqueue(51, record.ConsumptionClassStaticOnly, audit)
		h, err := f.q.Claim(fingerprint, "worker-a")
		if err != nil {
			t.Fatalf("Claim: %v", err)
		}
		if _, err := f.q.ReadPacket(h); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("reading an absent packet: err = %v, want os.ErrNotExist so the caller regenerates", err)
		}
	})
}

// TestValidatedRequiresDynamicEvidence is CRITIQUE-02 F9.
//
// plan/00-SPINE.md S7: "Only a DAST reproduction that now fails earns 'verified
// fixed'." ReleaseLease accepted 'validated' from any holder regardless of the
// Handle's ConsumptionClass and DastStatus, so a requires_dynamic_confirmation
// finding could be recorded verified-fixed on an audit whose DAST half was
// 'not_run' — a state in which no reproduction can exist to have been re-run.
func TestValidatedRequiresDynamicEvidence(t *testing.T) {
	for _, status := range record.DastStatusValues() {
		if status == record.DastStatusRunning {
			continue // a running half is not claimable at all; see the gate
		}
		t.Run(string(status), func(t *testing.T) {
			f := newFixture(t, Options{})
			audit, err := f.tryNewAudit(record.StateBothSealed, record.HalfStatusSealed,
				status, f.clock.Now().Add(8*time.Hour))
			if err != nil {
				if strings.Contains(err.Error(), "ck_audit_record_dast_status") {
					// The section 6 amendment added `completed_failed` to
					// internal/record; internal/store/schema.sql is a frozen
					// interface this packet may not edit, so the column cannot
					// hold the literal yet. The DDL is reported to the
					// orchestrator. The classification itself is still
					// asserted, without a database, by
					// TestHasDynamicEvidenceClassifiesEveryDastStatus.
					t.Skipf("ck_audit_record_dast_status does not admit %q yet; "+
						"schema.sql needs: dast_status IN (..., 'completed_failed', ...)", status)
				}
				t.Fatalf("newAudit: %v", err)
			}
			fingerprint, row := f.enqueue(52, record.ConsumptionClassRequiresDynamicConfirmation, audit)

			h, cerr := f.q.Claim(fingerprint, "worker-a")
			if cerr != nil {
				t.Fatalf("Claim: %v", cerr)
			}
			if h.DastStatus != status {
				t.Fatalf("Handle.DastStatus = %q, want %q", h.DastStatus, status)
			}

			err = f.q.ReleaseLease(h, record.HandoffStateValidated)
			if HasDynamicEvidence(status) {
				if err != nil {
					t.Fatalf("'validated' refused although the DAST half produced evidence (%q): %v", status, err)
				}
				if got := f.state(row.HandoffID); got != record.HandoffStateValidated {
					t.Errorf("state = %q, want %q", got, record.HandoffStateValidated)
				}
				return
			}

			if !errors.Is(err, ErrNoDynamicEvidence) {
				t.Fatalf("a requires_dynamic_confirmation finding was recorded 'validated' "+
					"with dast_status = %q: err = %v, want ErrNoDynamicEvidence", status, err)
			}
			// A refused release must not change the row: the lease is still
			// live and the worker may still record an honest outcome.
			if got := f.state(row.HandoffID); got != record.HandoffStateLeased {
				t.Fatalf("state = %q after a refused release, want %q", got, record.HandoffStateLeased)
			}
			if err := f.q.ReleaseLease(h, record.HandoffStateFailedValidation); err != nil {
				t.Errorf("an honest outcome was refused too: %v", err)
			}
		})
	}
}

// TestStaticOnlyMayStillValidate scopes the rule above. A static_only finding
// is by definition one no dynamic evidence was required for; refusing its
// 'validated' would make the disposition unreachable for most findings, which
// is not what S7 says.
func TestStaticOnlyMayStillValidate(t *testing.T) {
	f := newFixture(t, Options{})
	audit := f.newAudit(record.StateSastSealed, record.HalfStatusSealed,
		record.DastStatusNotRun, f.clock.Now().Add(8*time.Hour))
	fingerprint, row := f.enqueue(53, record.ConsumptionClassStaticOnly, audit)

	h, err := f.q.Claim(fingerprint, "worker-a")
	if err != nil {
		t.Fatalf("Claim: %v", err)
	}
	if err := f.q.ReleaseLease(h, record.HandoffStateValidated); err != nil {
		t.Fatalf("a static_only finding could not be validated: %v", err)
	}
	if got := f.state(row.HandoffID); got != record.HandoffStateValidated {
		t.Errorf("state = %q, want %q", got, record.HandoffStateValidated)
	}
}

// TestHasDynamicEvidenceClassifiesEveryDastStatus keeps the predicate honest
// against the frozen enum: every literal is classified, and the ones that mean
// "no dynamic scan concluded over this finding" are all false. In particular
// completed_clean is false — the half scanned and produced NO dynamic finding,
// so there is no reproduction that can now fail.
func TestHasDynamicEvidenceClassifiesEveryDastStatus(t *testing.T) {
	want := map[record.DastStatus]bool{
		record.DastStatusNotRun:            false,
		record.DastStatusSkippedNoManifest: false,
		record.DastStatusRunning:           false,
		record.DastStatusCompletedClean:    false,
		record.DastStatusCompletedFindings: true,
		record.DastStatusCompletedPartial:  true,
		record.DastStatusCompletedFailed:   false,
		record.DastStatusTargetBootFailed:  false,
		record.DastStatusTargetUnreachable: false,
		record.DastStatusTimedOut:          false,
	}
	for _, s := range record.DastStatusValues() {
		expected, ok := want[s]
		if !ok {
			t.Errorf("anvil/dastStatus %q is not classified by this test; a new literal "+
				"must be decided deliberately, not defaulted", s)
			continue
		}
		if got := HasDynamicEvidence(s); got != expected {
			t.Errorf("HasDynamicEvidence(%q) = %v, want %v", s, got, expected)
		}
	}
	if len(want) != len(record.DastStatusValues()) {
		t.Errorf("the table classifies %d statuses, the enum has %d",
			len(want), len(record.DastStatusValues()))
	}
}
