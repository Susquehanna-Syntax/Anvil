package scanctl

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Susquehanna-Syntax/Anvil/internal/handoff"
	"github.com/Susquehanna-Syntax/Anvil/internal/record"
	"github.com/Susquehanna-Syntax/Anvil/internal/store"

	_ "modernc.org/sqlite" // cgo-free driver, plan/00-SPINE.md S12
)

// ---------------------------------------------------------------------------
// Fixture
//
// The table under test is internal/store/schema.sql, applied through R.5's
// real migration path. Never a hand-copied DDL: a second copy of a frozen
// interface is the defect §6 G9 exists to prevent, and this step in particular
// was ruled out of writing its own migration. A fixture that invented a
// `handoff` table would prove nothing about the shipped one, and would prove
// it while demonstrating the exact sin.
// ---------------------------------------------------------------------------

// hfTime is the on-disk timestamp format. internal/handoff writes this shape
// and accepts any RFC 3339 spelling on read; the test writes the same one so a
// fixture row is indistinguishable from a production one.
const hfTime = "2006-01-02T15:04:05.000000000Z"

func hfFormat(t time.Time) string { return t.UTC().Format(hfTime) }

// hfClock drives the lease clock independently of wall time. Every expiry
// assertion below advances it explicitly; nothing sleeps.
type hfClock struct{ at time.Time }

func newHFClock() *hfClock { return &hfClock{at: baseTime} }

func (c *hfClock) Now() time.Time { return c.at }

func (c *hfClock) advance(d time.Duration) { c.at = c.at.Add(d) }

type hfFixture struct {
	t        *testing.T
	db       *sql.DB
	q        *handoff.Queue
	c        *Consumer
	clock    *hfClock
	targetID int64
}

// hfPolicy is the shipped default claim window: 8 hours, DAST installed.
func hfPolicy() DeadlinePolicy { return DeadlinePolicy{DastEnabled: true} }

// newHFFixture builds an on-disk store, migrates it, and returns a Consumer
// over it. On-disk rather than :memory: because the queue's atomicity argument
// is about real separate connections, and because store.Migrate's own ledger
// wants a durable file.
func newHFFixture(t *testing.T, opts handoff.Options) *hfFixture {
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

	if _, err := store.Migrate(context.Background(), db, ""); err != nil {
		t.Fatalf("store.Migrate: %v", err)
	}

	clock := newHFClock()
	opts.Clock = clock.Now
	if opts.PacketDir == "" {
		opts.PacketDir = filepath.Join(dir, "packets")
	}

	resolved, err := LeaseOptions(hfPolicy(), opts)
	if err != nil {
		t.Fatalf("LeaseOptions: %v", err)
	}
	q, err := handoff.New(db, resolved)
	if err != nil {
		t.Fatalf("handoff.New: %v", err)
	}
	c, err := NewConsumer(q, hfPolicy())
	if err != nil {
		t.Fatalf("NewConsumer: %v", err)
	}

	f := &hfFixture{t: t, db: db, q: q, c: c, clock: clock}

	res, err := db.Exec(`INSERT INTO target (kind, locator) VALUES (?, ?)`,
		"repo", "https://example.invalid/repo.git")
	if err != nil {
		t.Fatalf("insert target: %v", err)
	}
	if f.targetID, err = res.LastInsertId(); err != nil {
		t.Fatalf("target id: %v", err)
	}
	return f
}

// hfFingerprint returns a distinct, well-formed 64-hex anvil-fp/v1 digest.
func hfFingerprint(n int) string { return strings.Repeat(fmt.Sprintf("%02x", n%256), 32) }

// newAudit inserts a scan_run and its audit_record with the lifecycle values
// the test needs. deadline_at is supplied rather than derived: R.6 computes it
// once and this package only reads it.
func (f *hfFixture) newAudit(state record.State, sast record.HalfStatus, dast record.DastStatus) int64 {
	f.t.Helper()

	res, err := f.db.Exec(
		`INSERT INTO scan_run (target_id, started_at, ruleset_version, status, commit_sha)
		 VALUES (?, ?, ?, ?, ?)`,
		f.targetID, hfFormat(f.clock.Now()), "anvil-rules/v1",
		string(record.ScanRunStatusRunning),
		"9f1c0de9f1c0de9f1c0de9f1c0de9f1c0de9f1c0")
	if err != nil {
		f.t.Fatalf("insert scan_run: %v", err)
	}
	scanRunID, err := res.LastInsertId()
	if err != nil {
		f.t.Fatalf("scan_run id: %v", err)
	}

	var sastStatus any
	if sast != "" {
		sastStatus = string(sast)
	}
	deadline := f.clock.Now().Add(hfPolicy().ClaimTimeout())
	res, err = f.db.Exec(
		`INSERT INTO audit_record
		   (scan_run_id, schema_version, state, sast_status, dast_status,
		    target_provenance, deadline_at, payload_sha256, created_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		scanRunID, "anvil/1", string(state), sastStatus, string(dast),
		string(record.TargetProvenanceBootedClean), hfFormat(deadline),
		strings.Repeat("b", 64), hfFormat(f.clock.Now()))
	if err != nil {
		f.t.Fatalf("insert audit_record: %v", err)
	}
	auditRecordID, err := res.LastInsertId()
	if err != nil {
		f.t.Fatalf("audit_record id: %v", err)
	}
	return auditRecordID
}

// sealedAudit is the common case: both halves sealed, DAST clean.
func (f *hfFixture) sealedAudit() int64 {
	f.t.Helper()
	return f.newAudit(record.StateBothSealed, record.HalfStatusSealed, record.DastStatusCompletedClean)
}

// setAudit moves an existing audit's lifecycle columns, so a test can watch a
// gate open rather than only observing it open.
func (f *hfFixture) setAudit(auditRecordID int64, state record.State, sast record.HalfStatus, dast record.DastStatus) {
	f.t.Helper()
	if _, err := f.db.Exec(
		`UPDATE audit_record SET state = ?, sast_status = ?, dast_status = ? WHERE audit_record_id = ?`,
		string(state), string(sast), string(dast), auditRecordID); err != nil {
		f.t.Fatalf("update audit_record: %v", err)
	}
}

func (f *hfFixture) newFinding(fingerprint string) int64 {
	f.t.Helper()
	res, err := f.db.Exec(
		`INSERT INTO finding
		   (target_id, fingerprint, detector, evidence_class, rule_id, severity, title,
		    state, remediable_by_agent, first_seen_scan, first_seen_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, (SELECT MAX(scan_run_id) FROM scan_run), ?)`,
		f.targetID, fingerprint, string(record.DetectorKindSast),
		string(record.EvidenceClassSastStaticOnly), "anvil.py.sqli/v3", "high",
		"SQL injection", string(record.FindingStateOpen), 1, hfFormat(f.clock.Now()))
	if err != nil {
		f.t.Fatalf("insert finding: %v", err)
	}
	id, err := res.LastInsertId()
	if err != nil {
		f.t.Fatalf("finding id: %v", err)
	}
	return id
}

// hfAuditUUID is `anvil/auditId` — a separate identity from the rowid, because
// handoff.IdempotencyKey hashes THIS (CRITIQUE-02 F7).
func hfAuditUUID(auditRecordID int64) string {
	return fmt.Sprintf("11111111-2222-4333-8444-%012d", auditRecordID)
}

// enqueue seeds one ready finding through internal/handoff's own Enqueue.
// There is no scanctl-side enqueue and there must not be one: the producer
// path lives with whoever holds the rowids.
func (f *hfFixture) enqueue(n int, class record.ConsumptionClass, auditRecordID int64, maxAttempts int) (string, handoff.Row) {
	f.t.Helper()
	fingerprint := hfFingerprint(n)
	row, err := f.q.Enqueue(handoff.EnqueueRequest{
		FindingID:        f.newFinding(fingerprint),
		AuditRecordID:    auditRecordID,
		AuditID:          hfAuditUUID(auditRecordID),
		Fingerprint:      fingerprint,
		ConsumptionClass: class,
		MaxAttempts:      maxAttempts,
	})
	if err != nil {
		f.t.Fatalf("Enqueue: %v", err)
	}
	return fingerprint, row
}

func (f *hfFixture) rowState(handoffID int64) record.HandoffState {
	f.t.Helper()
	row, err := f.q.Get(handoffID)
	if err != nil {
		f.t.Fatalf("Get(%d): %v", handoffID, err)
	}
	return row.State
}

func (f *hfFixture) row(handoffID int64) handoff.Row {
	f.t.Helper()
	row, err := f.q.Get(handoffID)
	if err != nil {
		f.t.Fatalf("Get(%d): %v", handoffID, err)
	}
	return row
}

// ---------------------------------------------------------------------------
// The lease/claim-window relation
// ---------------------------------------------------------------------------

func TestCheckLeaseAgainstTheClaimWindow(t *testing.T) {
	eightHours := DeadlinePolicy{DastEnabled: true}
	oneHour := DeadlinePolicy{ClaimTimeoutSeconds: 3600}

	cases := []struct {
		name   string
		lease  time.Duration
		policy DeadlinePolicy
		want   error
	}{
		{"the shipped defaults", handoff.DefaultLease, eightHours, nil},
		{"a short lease in a short window", time.Minute, oneHour, nil},
		{"one second under the window", time.Hour - time.Second, oneHour, nil},
		{"exactly the window is not a retry", time.Hour, oneHour, ErrLeaseExceedsClaimWindow},
		{"longer than the window", 9 * time.Hour, eightHours, ErrLeaseExceedsClaimWindow},
		{"zero after Options had its chance", 0, eightHours, ErrNonPositiveLease},
		{"negative", -time.Minute, eightHours, ErrNonPositiveLease},
		{"an invalid policy is reported as a policy error",
			time.Minute, DeadlinePolicy{ClaimTimeoutSeconds: -1}, ErrInvalidDeadlinePolicy},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := CheckLease(tc.lease, tc.policy)
			if tc.want == nil {
				if err != nil {
					t.Fatalf("CheckLease(%s) = %v, want nil", tc.lease, err)
				}
				return
			}
			if !errors.Is(err, tc.want) {
				t.Fatalf("CheckLease(%s) = %v, want %v", tc.lease, err, tc.want)
			}
		})
	}
}

// The refusal must name BOTH durations. An operator told only "invalid lease"
// cannot tell which of the two numbers to change.
func TestLeaseErrorNamesBothClocks(t *testing.T) {
	err := CheckLease(9*time.Hour, hfPolicy())
	var le *LeaseError
	if !errors.As(err, &le) {
		t.Fatalf("CheckLease error = %T, want *LeaseError", err)
	}
	if le.Lease != 9*time.Hour {
		t.Errorf("LeaseError.Lease = %s, want 9h", le.Lease)
	}
	if le.ClaimWindow != 8*time.Hour {
		t.Errorf("LeaseError.ClaimWindow = %s, want 8h", le.ClaimWindow)
	}
	for _, want := range []string{"9h", "8h"} {
		if !strings.Contains(le.Error(), want) {
			t.Errorf("LeaseError.Error() = %q, want it to mention %s", le.Error(), want)
		}
	}
}

func TestLeaseOptionsFillsTheDefaultAndPassesEverythingElseThrough(t *testing.T) {
	clock := newHFClock()
	base := handoff.Options{PacketDir: "/run/anvil", MaxAttempts: 7, Clock: clock.Now}

	got, err := LeaseOptions(hfPolicy(), base)
	if err != nil {
		t.Fatalf("LeaseOptions: %v", err)
	}
	if got.Lease != handoff.DefaultLease {
		t.Errorf("Lease = %s, want handoff.DefaultLease (%s)", got.Lease, handoff.DefaultLease)
	}
	if got.PacketDir != base.PacketDir {
		t.Errorf("PacketDir = %q, want %q", got.PacketDir, base.PacketDir)
	}
	if got.MaxAttempts != base.MaxAttempts {
		t.Errorf("MaxAttempts = %d, want %d", got.MaxAttempts, base.MaxAttempts)
	}
	if got.Clock == nil || !got.Clock().Equal(clock.Now()) {
		t.Error("Clock was not passed through")
	}

	if _, err := LeaseOptions(hfPolicy(), handoff.Options{Lease: 9 * time.Hour}); !errors.Is(err, ErrLeaseExceedsClaimWindow) {
		t.Fatalf("LeaseOptions with a 9h lease = %v, want ErrLeaseExceedsClaimWindow", err)
	}
}

// NewConsumer must not trust that LeaseOptions was used. A Queue built
// straight from handoff.New is an ordinary thing to have, and it is exactly
// the one that would otherwise skip the only check this file exists to make.
func TestNewConsumerRechecksAQueueItDidNotBuild(t *testing.T) {
	db, err := sql.Open("sqlite", "file:"+filepath.ToSlash(filepath.Join(t.TempDir(), "a.db")))
	if err != nil {
		t.Fatalf("sql.Open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	bad, err := handoff.New(db, handoff.Options{Lease: 24 * time.Hour})
	if err != nil {
		t.Fatalf("handoff.New: %v", err)
	}
	if _, err := NewConsumer(bad, hfPolicy()); !errors.Is(err, ErrLeaseExceedsClaimWindow) {
		t.Fatalf("NewConsumer over a 24h lease = %v, want ErrLeaseExceedsClaimWindow", err)
	}

	good, err := handoff.New(db, handoff.Options{})
	if err != nil {
		t.Fatalf("handoff.New: %v", err)
	}
	if _, err := NewConsumer(good, hfPolicy()); err != nil {
		t.Fatalf("NewConsumer over the default lease: %v", err)
	}
	if _, err := NewConsumer(nil, hfPolicy()); !errors.Is(err, ErrNoQueue) {
		t.Fatalf("NewConsumer(nil) = %v, want ErrNoQueue", err)
	}
}

func TestRenewIntervalLeavesRoomForTwoMissedHeartbeats(t *testing.T) {
	f := newHFFixture(t, handoff.Options{Lease: 30 * time.Minute})
	got := f.c.RenewInterval()
	if got != 10*time.Minute {
		t.Fatalf("RenewInterval = %s, want 10m (one third of a 30m lease)", got)
	}
	// The derivation, asserted as arithmetic rather than as a comment: two
	// heartbeats may be missed and a third still lands before expiry.
	if 3*got > f.c.Lease() {
		t.Fatalf("three intervals (%s) exceed the lease (%s)", 3*got, f.c.Lease())
	}
	if got <= 0 {
		t.Fatal("RenewInterval must never be zero: that is an infinite heartbeat loop")
	}
}

// ---------------------------------------------------------------------------
// THE CRASH PATH — the packet's first required scenario
// ---------------------------------------------------------------------------

// sideEffects stands in for whatever a coding agent does to the world: a
// branch, a commit, a comment. It is keyed by handoff idempotency key, which
// is the only key the packet says re-processing must be idempotent under
// (fingerprint, record version — both of which the key contains, transitively,
// via the audit identity and the base commit).
type sideEffects struct {
	applied map[string]int
	order   []string
}

func newSideEffects() *sideEffects {
	return &sideEffects{applied: map[string]int{}}
}

// apply is the idempotent write every applier is required to be. It records
// the attempt either way, so the test can tell "the second consumer never ran"
// (which would not prove idempotence) from "the second consumer ran and
// recognised the key" (which does).
func (s *sideEffects) apply(key string) {
	s.order = append(s.order, key)
	if _, seen := s.applied[key]; seen {
		return
	}
	s.applied[key] = 1
}

func TestCrashedHolderIsReclaimedAndReprocessedWithoutDoubleApplying(t *testing.T) {
	f := newHFFixture(t, handoff.Options{Lease: 20 * time.Minute})
	audit := f.sealedAudit()
	fingerprint, row := f.enqueue(1, record.ConsumptionClassStaticOnly, audit, 2)

	effects := newSideEffects()

	// --- attempt 1: the holder takes the lease, does its work, and dies
	// before it can report. No ReleaseLease is ever called for it.
	dead, err := f.c.Claim(fingerprint, "worker-a")
	if err != nil {
		t.Fatalf("Claim: %v", err)
	}
	if dead.Attempt != 1 {
		t.Fatalf("first Attempt = %d, want 1", dead.Attempt)
	}
	effects.apply(dead.IdempotencyKey)
	if f.rowState(row.HandoffID) != record.HandoffStateLeased {
		t.Fatalf("state after claim = %q, want %q", f.rowState(row.HandoffID), record.HandoffStateLeased)
	}

	// --- the lease lapses and the reaper requeues it. One attempt remains.
	f.clock.advance(21 * time.Minute)
	report, err := f.c.ReclaimExpired()
	if err != nil {
		t.Fatalf("ReclaimExpired: %v", err)
	}
	if len(report.Reclaimed) != 1 {
		t.Fatalf("Reclaimed = %d rows, want 1", len(report.Reclaimed))
	}
	if got := report.Reclaimed[0].To; got != record.HandoffStateReady {
		t.Fatalf("reclaimed to %q, want %q — a retry remained", got, record.HandoffStateReady)
	}
	if report.Requeued() != 1 || report.Exhausted() != 0 {
		t.Fatalf("report Requeued/Exhausted = %d/%d, want 1/0", report.Requeued(), report.Exhausted())
	}

	// --- attempt 2: a different worker re-processes through ConsumeOne.
	out, err := f.c.ConsumeOne(context.Background(), "worker-b", func(_ context.Context, task Task) (record.HandoffState, error) {
		effects.apply(task.IdempotencyKey)
		return record.HandoffStateValidated, nil
	})
	if err != nil {
		t.Fatalf("ConsumeOne: %v", err)
	}
	if !out.Applied || out.State != record.HandoffStateValidated {
		t.Fatalf("Outcome = %+v, want Applied with %q", out, record.HandoffStateValidated)
	}
	if out.Task.Attempt != 2 {
		t.Fatalf("second Attempt = %d, want 2", out.Task.Attempt)
	}

	// THE ASSERTION THE PACKET ASKS FOR, in three parts.

	// 1. The successor saw the SAME key. If it did not, re-processing could
	//    not have been recognised as the same unit of work by anything
	//    downstream, and the git trailer would name a different unit.
	if out.Task.IdempotencyKey != dead.IdempotencyKey {
		t.Fatalf("idempotency key changed across reclaim: %q then %q",
			dead.IdempotencyKey, out.Task.IdempotencyKey)
	}
	if out.Task.RecordVersion != dead.RecordVersion {
		t.Fatalf("record version changed across reclaim: %d then %d",
			dead.RecordVersion, out.Task.RecordVersion)
	}

	// 2. Both attempts really did run — otherwise part 3 proves nothing.
	if len(effects.order) != 2 {
		t.Fatalf("appliers ran %d times, want 2", len(effects.order))
	}

	// 3. The side effect exists exactly once.
	if len(effects.applied) != 1 {
		t.Fatalf("distinct side effects = %d, want 1: %v", len(effects.applied), effects.applied)
	}
	if effects.applied[dead.IdempotencyKey] != 1 {
		t.Fatalf("side effect applied %d times, want 1", effects.applied[dead.IdempotencyKey])
	}

	// --- and the row itself was not double-counted.
	final := f.row(row.HandoffID)
	if final.State != record.HandoffStateValidated {
		t.Fatalf("final state = %q, want %q", final.State, record.HandoffStateValidated)
	}
	if final.Attempts != 2 {
		t.Fatalf("attempts = %d, want 2 — one per lease granted", final.Attempts)
	}
}

// The other half of "not double-applied": the dead holder waking up. Its Task
// is a snapshot of a lease that no longer exists, and every operation that
// could land work must refuse it.
func TestAStaleTaskCanNeitherRenewReleaseNorRead(t *testing.T) {
	f := newHFFixture(t, handoff.Options{Lease: 20 * time.Minute})
	audit := f.sealedAudit()
	fingerprint, row := f.enqueue(2, record.ConsumptionClassStaticOnly, audit, 2)

	dead, err := f.c.Claim(fingerprint, "worker-a")
	if err != nil {
		t.Fatalf("Claim: %v", err)
	}
	if _, err := f.c.WritePacket(dead, []byte(`{"runs":[]}`)); err != nil {
		t.Fatalf("WritePacket: %v", err)
	}

	f.clock.advance(21 * time.Minute)
	if _, err := f.c.ReclaimExpired(); err != nil {
		t.Fatalf("ReclaimExpired: %v", err)
	}
	live, err := f.c.Claim(fingerprint, "worker-b")
	if err != nil {
		t.Fatalf("second Claim: %v", err)
	}

	// The OOM-killed process comes back and tries to report success.
	if err := f.c.ReleaseLease(dead, record.HandoffStateValidated); !errors.Is(err, handoff.ErrLeaseLost) {
		t.Fatalf("stale ReleaseLease = %v, want handoff.ErrLeaseLost", err)
	}
	if _, err := f.c.RenewLease(dead); !errors.Is(err, handoff.ErrLeaseLost) {
		t.Fatalf("stale RenewLease = %v, want handoff.ErrLeaseLost", err)
	}
	if _, err := f.c.Packet(dead); !errors.Is(err, handoff.ErrLeaseLost) {
		t.Fatalf("stale Packet = %v, want handoff.ErrLeaseLost", err)
	}
	if _, err := f.c.WritePacket(dead, []byte(`{}`)); !errors.Is(err, handoff.ErrLeaseLost) {
		t.Fatalf("stale WritePacket = %v, want handoff.ErrLeaseLost", err)
	}

	// The successor's lease is untouched by any of that.
	if got := f.rowState(row.HandoffID); got != record.HandoffStateLeased {
		t.Fatalf("state after the stale writes = %q, want %q", got, record.HandoffStateLeased)
	}
	if err := f.c.ReleaseLease(live, record.HandoffStateValidated); err != nil {
		t.Fatalf("live ReleaseLease: %v", err)
	}
	if got := f.rowState(row.HandoffID); got != record.HandoffStateValidated {
		t.Fatalf("final state = %q, want %q", got, record.HandoffStateValidated)
	}
}

// A live holder that heartbeats survives the sweep. Without this, the test
// above would pass on an implementation that simply reclaimed everything.
func TestAHeartbeatingHolderIsNotReclaimed(t *testing.T) {
	f := newHFFixture(t, handoff.Options{Lease: 20 * time.Minute})
	audit := f.sealedAudit()
	fingerprint, row := f.enqueue(3, record.ConsumptionClassStaticOnly, audit, 2)

	task, err := f.c.Claim(fingerprint, "worker-a")
	if err != nil {
		t.Fatalf("Claim: %v", err)
	}
	for i := 0; i < 4; i++ {
		f.clock.advance(f.c.RenewInterval())
		if task, err = f.c.RenewLease(task); err != nil {
			t.Fatalf("RenewLease %d: %v", i, err)
		}
		report, err := f.c.ReclaimExpired()
		if err != nil {
			t.Fatalf("ReclaimExpired: %v", err)
		}
		if !report.Empty() {
			t.Fatalf("sweep %d reclaimed a live lease: %+v", i, report)
		}
	}
	if got := f.rowState(row.HandoffID); got != record.HandoffStateLeased {
		t.Fatalf("state = %q, want %q after four heartbeats", got, record.HandoffStateLeased)
	}
	if got := f.row(row.HandoffID).Attempts; got != 1 {
		t.Fatalf("attempts = %d, want 1: a heartbeat is not an attempt", got)
	}
}

// ---------------------------------------------------------------------------
// THE CONSUMPTION GATE — the packet's second required scenario
// ---------------------------------------------------------------------------

func TestRequiresDynamicConfirmationWaitsForTheDastHalf(t *testing.T) {
	f := newHFFixture(t, handoff.Options{})
	// A SAST-sealed audit whose DAST half is still running. This is the sharp
	// case: the static half IS readable, so anything gating on it alone would
	// hand the dynamic finding out early.
	audit := f.newAudit(record.StateSastSealed, record.HalfStatusSealed, record.DastStatusRunning)

	staticFP, staticRow := f.enqueue(10, record.ConsumptionClassStaticOnly, audit, 2)
	dynamicFP, dynamicRow := f.enqueue(11, record.ConsumptionClassRequiresDynamicConfirmation, audit, 2)

	// The static_only finding is claimable now.
	if _, err := f.c.Claim(staticFP, "worker-a"); err != nil {
		t.Fatalf("static_only Claim on a sast_sealed audit: %v", err)
	}

	// The requires_dynamic_confirmation one is not, and says why.
	if _, err := f.c.Claim(dynamicFP, "worker-b"); !errors.Is(err, handoff.ErrNotEligible) {
		t.Fatalf("requires_dynamic_confirmation Claim = %v, want handoff.ErrNotEligible", err)
	}
	if got := f.rowState(dynamicRow.HandoffID); got != record.HandoffStateReady {
		t.Fatalf("refused row state = %q, want %q — a refusal must not move the row", got, record.HandoffStateReady)
	}

	// AcquireLease must not hand it out either. The static row is already
	// leased, so the ready set contains only the dynamic one.
	if _, err := f.c.AcquireLease("worker-c"); !errors.Is(err, handoff.ErrNoWork) {
		t.Fatalf("AcquireLease with only a gated finding ready = %v, want handoff.ErrNoWork", err)
	}

	// Now the DAST half reaches a terminal state and the audit seals.
	f.setAudit(audit, record.StateBothSealed, record.HalfStatusSealed, record.DastStatusCompletedFindings)

	task, err := f.c.Claim(dynamicFP, "worker-b")
	if err != nil {
		t.Fatalf("Claim after both halves sealed: %v", err)
	}
	if task.ConsumptionClass != record.ConsumptionClassRequiresDynamicConfirmation {
		t.Fatalf("ConsumptionClass = %q, want %q", task.ConsumptionClass,
			record.ConsumptionClassRequiresDynamicConfirmation)
	}
	if task.DastStatus != record.DastStatusCompletedFindings {
		t.Fatalf("DastStatus = %q, want %q", task.DastStatus, record.DastStatusCompletedFindings)
	}
	_ = staticRow
}

// The gate, walked across the whole frozen ten-value dastStatus enum rather
// than at one or two sampled values. A future addition to the enum lands in
// this table automatically.
func TestTheGateIsTotalOverTheDastStatusEnum(t *testing.T) {
	if got := len(record.DastStatusValues()); got != 10 {
		t.Fatalf("anvil/dastStatus has %d values, want the frozen 10; this table must be revisited", got)
	}
	for i, dast := range record.DastStatusValues() {
		t.Run(string(dast), func(t *testing.T) {
			f := newHFFixture(t, handoff.Options{})
			audit := f.newAudit(record.StateBothSealed, record.HalfStatusSealed, dast)
			fingerprint, _ := f.enqueue(20+i, record.ConsumptionClassRequiresDynamicConfirmation, audit, 2)

			_, err := f.c.Claim(fingerprint, "worker")
			// 'running' is the one value that means the half has not
			// concluded, and it is refused even from a both_sealed audit —
			// the belt-and-braces arm internal/handoff spells out.
			if dast == record.DastStatusRunning {
				if !errors.Is(err, handoff.ErrNotEligible) {
					t.Fatalf("dast_status=%q Claim = %v, want handoff.ErrNotEligible", dast, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("dast_status=%q Claim = %v, want a grant", dast, err)
			}
		})
	}
}

// A finding whose half has not sealed at all is claimable in no lifecycle
// state that is not one of the four the gate names. This is the arm that
// stops a still-collecting audit's default 'not_run' from reading as a
// finished DAST-disabled scan.
func TestNoClassIsClaimableWhileTheAuditIsStillCollecting(t *testing.T) {
	for _, class := range record.ConsumptionClassValues() {
		t.Run(string(class), func(t *testing.T) {
			f := newHFFixture(t, handoff.Options{})
			audit := f.newAudit(record.StateCollecting, record.HalfStatusRunning, record.DastStatusNotRun)
			fingerprint, _ := f.enqueue(40, class, audit, 2)

			if _, err := f.c.Claim(fingerprint, "worker"); !errors.Is(err, handoff.ErrNotEligible) {
				t.Fatalf("%s Claim on a collecting audit = %v, want handoff.ErrNotEligible", class, err)
			}
			if _, err := f.c.AcquireLease("worker"); !errors.Is(err, handoff.ErrNoWork) {
				t.Fatalf("%s AcquireLease on a collecting audit = %v, want handoff.ErrNoWork", class, err)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// ConsumeOne
// ---------------------------------------------------------------------------

// errApplier is the applier's own sentinel. ConsumeOne must wrap it, not
// replace it: a caller that branches on its own error type has to keep working
// through the adapter.
var errApplier = errors.New("test: the coding agent gave up")

func TestFailedApplierRequeuesThenExhausts(t *testing.T) {
	f := newHFFixture(t, handoff.Options{})
	audit := f.sealedAudit()
	_, row := f.enqueue(50, record.ConsumptionClassStaticOnly, audit, 2)

	fail := func(_ context.Context, _ Task) (record.HandoffState, error) {
		return "", errApplier
	}

	// Attempt 1 of 2: nothing was decided, so the finding goes back to the
	// ready set. 'ready' asserts nothing about the finding; a verdict would.
	out, err := f.c.ConsumeOne(context.Background(), "worker-a", fail)
	if !errors.Is(err, errApplier) {
		t.Fatalf("ConsumeOne error = %v, want it to wrap the applier's own error", err)
	}
	if out.Applied {
		t.Error("Outcome.Applied = true after the applier failed")
	}
	if !errors.Is(out.ApplyErr, errApplier) {
		t.Errorf("Outcome.ApplyErr = %v, want errApplier", out.ApplyErr)
	}
	if out.State != record.HandoffStateReady {
		t.Fatalf("fallback state = %q, want %q while an attempt remains", out.State, record.HandoffStateReady)
	}
	if got := f.rowState(row.HandoffID); got != record.HandoffStateReady {
		t.Fatalf("row state = %q, want %q", got, record.HandoffStateReady)
	}

	// Attempt 2 of 2: the budget is spent, so it lands where the reaper would
	// have put it. Same policy, second trigger.
	out, err = f.c.ConsumeOne(context.Background(), "worker-b", fail)
	if !errors.Is(err, errApplier) {
		t.Fatalf("second ConsumeOne error = %v, want it to wrap errApplier", err)
	}
	if out.State != handoff.ExhaustedState {
		t.Fatalf("fallback state = %q, want handoff.ExhaustedState (%q)", out.State, handoff.ExhaustedState)
	}
	if got := f.rowState(row.HandoffID); got != handoff.ExhaustedState {
		t.Fatalf("row state = %q, want %q", got, handoff.ExhaustedState)
	}

	// And it is not re-leasable: the attempt budget is spent and terminal is
	// terminal.
	if _, err := f.c.AcquireLease("worker-c"); !errors.Is(err, handoff.ErrNoWork) {
		t.Fatalf("AcquireLease after exhaustion = %v, want handoff.ErrNoWork", err)
	}
}

// The disposition an applier chooses may be refused. When it is, this file
// must not substitute a verdict of its own — the lease stays held and the
// caller decides.
func TestConsumeOneLeavesTheLeaseHeldWhenTheDispositionIsRefused(t *testing.T) {
	f := newHFFixture(t, handoff.Options{})
	// A DAST half that came back CLEAN: it ran, and it produced no
	// reproduction of this finding. plan/00-SPINE.md S7 says that cannot earn
	// 'validated' for a requires_dynamic_confirmation finding.
	audit := f.newAudit(record.StateBothSealed, record.HalfStatusSealed, record.DastStatusCompletedClean)
	_, row := f.enqueue(60, record.ConsumptionClassRequiresDynamicConfirmation, audit, 2)

	out, err := f.c.ConsumeOne(context.Background(), "worker-a",
		func(_ context.Context, _ Task) (record.HandoffState, error) {
			return record.HandoffStateValidated, nil
		})
	if !errors.Is(err, handoff.ErrNoDynamicEvidence) {
		t.Fatalf("ConsumeOne = %v, want handoff.ErrNoDynamicEvidence", err)
	}
	if !out.Applied {
		t.Error("Outcome.Applied = false: the applier ran and chose; what failed was recording it")
	}
	if out.State != "" {
		t.Errorf("Outcome.State = %q, want empty: nothing was written", out.State)
	}
	if got := f.rowState(row.HandoffID); got != record.HandoffStateLeased {
		t.Fatalf("row state = %q, want %q — the lease must survive a refused disposition",
			got, record.HandoffStateLeased)
	}
	// The caller can still land a legal disposition with the Task it holds.
	if err := f.c.ReleaseLease(out.Task, record.HandoffStateFailedValidation); err != nil {
		t.Fatalf("ReleaseLease after the refusal: %v", err)
	}
	if got := f.rowState(row.HandoffID); got != record.HandoffStateFailedValidation {
		t.Fatalf("row state = %q, want %q", got, record.HandoffStateFailedValidation)
	}
}

// An illegal disposition is refused by the frozen state machine, not by a
// second copy of it here.
func TestConsumeOneRefusesADispositionTheStateMachineForbids(t *testing.T) {
	f := newHFFixture(t, handoff.Options{})
	audit := f.sealedAudit()
	_, row := f.enqueue(61, record.ConsumptionClassStaticOnly, audit, 2)

	_, err := f.c.ConsumeOne(context.Background(), "worker-a",
		func(_ context.Context, _ Task) (record.HandoffState, error) {
			return record.HandoffStateLeased, nil
		})
	if !errors.Is(err, handoff.ErrIllegalTransition) {
		t.Fatalf("ConsumeOne returning 'leased' = %v, want handoff.ErrIllegalTransition", err)
	}
	if got := f.rowState(row.HandoffID); got != record.HandoffStateLeased {
		t.Fatalf("row state = %q, want %q", got, record.HandoffStateLeased)
	}
}

func TestConsumeOneWithNoApplierBurnsNoAttempt(t *testing.T) {
	f := newHFFixture(t, handoff.Options{})
	audit := f.sealedAudit()
	_, row := f.enqueue(62, record.ConsumptionClassStaticOnly, audit, 2)

	if _, err := f.c.ConsumeOne(context.Background(), "worker-a", nil); !errors.Is(err, ErrNoApplier) {
		t.Fatalf("ConsumeOne(nil applier) = %v, want ErrNoApplier", err)
	}
	got := f.row(row.HandoffID)
	if got.Attempts != 0 {
		t.Fatalf("attempts = %d, want 0: the refusal must come before the lease", got.Attempts)
	}
	if got.State != record.HandoffStateReady {
		t.Fatalf("state = %q, want %q", got.State, record.HandoffStateReady)
	}
}

func TestConsumeOneIsIdleWhenNothingIsClaimable(t *testing.T) {
	f := newHFFixture(t, handoff.Options{})
	out, err := f.c.ConsumeOne(context.Background(), "worker-a",
		func(_ context.Context, _ Task) (record.HandoffState, error) {
			t.Fatal("the applier ran with an empty queue")
			return "", nil
		})
	if !errors.Is(err, handoff.ErrNoWork) {
		t.Fatalf("ConsumeOne on an empty queue = %v, want handoff.ErrNoWork", err)
	}
	if out.Task.Held() {
		t.Error("an idle ConsumeOne returned a Task holding a lease")
	}
}

// ---------------------------------------------------------------------------
// Task carries no authority
// ---------------------------------------------------------------------------

func TestAHandBuiltTaskGrantsNothing(t *testing.T) {
	f := newHFFixture(t, handoff.Options{})
	audit := f.sealedAudit()
	fingerprint, row := f.enqueue(70, record.ConsumptionClassStaticOnly, audit, 2)

	granted, err := f.c.Claim(fingerprint, "worker-a")
	if err != nil {
		t.Fatalf("Claim: %v", err)
	}

	// Every exported field copied; the lease is not, because it cannot be.
	forged := Task{
		Fingerprint:      granted.Fingerprint,
		IdempotencyKey:   granted.IdempotencyKey,
		RecordVersion:    granted.RecordVersion,
		ConsumptionClass: granted.ConsumptionClass,
		DastStatus:       granted.DastStatus,
		WorkerID:         granted.WorkerID,
		Attempt:          granted.Attempt,
		MaxAttempts:      granted.MaxAttempts,
		LeaseExpiresAt:   granted.LeaseExpiresAt,
		PacketPath:       granted.PacketPath,
	}
	if forged.Held() {
		t.Fatal("a hand-built Task reports Held()")
	}
	for name, err := range map[string]error{
		"ReleaseLease": f.c.ReleaseLease(forged, record.HandoffStateValidated),
		"RenewLease":   second(f.c.RenewLease(forged)),
		"Packet":       secondBytes(f.c.Packet(forged)),
		"WritePacket":  secondString(f.c.WritePacket(forged, []byte(`{}`))),
	} {
		if !errors.Is(err, handoff.ErrLeaseLost) {
			t.Errorf("%s on a forged Task = %v, want handoff.ErrLeaseLost", name, err)
		}
	}
	if got := f.rowState(row.HandoffID); got != record.HandoffStateLeased {
		t.Fatalf("row state = %q, want %q", got, record.HandoffStateLeased)
	}
}

func second(_ Task, err error) error         { return err }
func secondBytes(_ []byte, err error) error  { return err }
func secondString(_ string, err error) error { return err }

func TestTaskAttemptsRemaining(t *testing.T) {
	cases := []struct{ attempt, max, want int }{
		{1, 2, 1},
		{2, 2, 0},
		{3, 2, 0},
		{1, 1, 0},
	}
	for _, tc := range cases {
		got := Task{Attempt: tc.attempt, MaxAttempts: tc.max}.AttemptsRemaining()
		if got != tc.want {
			t.Errorf("Task{Attempt:%d, MaxAttempts:%d}.AttemptsRemaining() = %d, want %d",
				tc.attempt, tc.max, got, tc.want)
		}
	}
}

// failureDisposition is the reaper's rule applied to a second trigger. If the
// two ever diverge, this fails.
func TestFailureDispositionMirrorsTheReaper(t *testing.T) {
	if got := (Task{Attempt: 1, MaxAttempts: 2}); failureDisposition(got) != record.HandoffStateReady {
		t.Errorf("with an attempt remaining = %q, want %q", failureDisposition(got), record.HandoffStateReady)
	}
	if got := (Task{Attempt: 2, MaxAttempts: 2}); failureDisposition(got) != handoff.ExhaustedState {
		t.Errorf("with no attempt remaining = %q, want handoff.ExhaustedState", failureDisposition(got))
	}
	if handoff.ExhaustedState == record.HandoffStateReady {
		t.Fatal("handoff.ExhaustedState collapsed onto 'ready'; the two branches are no longer distinguishable")
	}
}

// ---------------------------------------------------------------------------
// SOURCE GUARDS — the whole package, not one file of it
//
// §6 G9 was "the handoff table defined and created twice, in two migrations,
// with two Go APIs". The ruling made handoff.go a thin adapter; nothing about a
// ruling stops a later author adding one convenient query. These guards fail the
// build when it happens.
//
// THEY COVER EVERY NON-TEST FILE IN THE PACKAGE, and that widening is CRITIQUE
// O.4 finding O4-m2. They used to parse `handoff.go` alone while being named for
// "the adapter", so statemachine.go and deadlines.go — two thirds of the package
// and the two files the blockers were found in — were unguarded. A guard that
// covers one file of three while appearing to cover the package is worse than no
// guard: it is the false confidence this repository has now paid for three
// times. packageSources is derived by READING THE DIRECTORY rather than from a
// list, so a fourth file added tomorrow is covered the day it lands.
// ---------------------------------------------------------------------------

// packageSources returns every non-test .go file in this package, parsed. Tests
// run in the package directory, so "." is the package under test.
//
// It fails if it finds fewer than three files: this package has deadlines.go,
// statemachine.go and handoff.go today, and a guard that silently scanned an
// empty set would pass for the wrong reason.
func packageSources(t *testing.T) (*token.FileSet, map[string]*ast.File) {
	t.Helper()

	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("reading the package directory: %v", err)
	}
	fset := token.NewFileSet()
	files := map[string]*ast.File{}
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, name, nil, parser.ParseComments)
		if err != nil {
			t.Fatalf("parsing %s: %v", name, err)
		}
		files[name] = f
	}
	if len(files) < 3 {
		t.Fatalf("found %d non-test source files (%v); the package has at least three and this guard "+
			"is only worth anything if it scans all of them", len(files), slices.Sorted(maps.Keys(files)))
	}
	return fset, files
}

// sourceNames returns the parsed file names in a stable order, so a failure
// message reads the same on every host.
func sourceNames(files map[string]*ast.File) []string {
	names := make([]string, 0, len(files))
	for name := range files {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

func TestThePackageOpensNoDatabaseAndWritesNoSQL(t *testing.T) {
	fset, files := packageSources(t)

	// 1. Nothing here imports the database or the store. Every row this
	//    package touches is touched through internal/handoff.
	forbidden := map[string]string{
		`"database/sql"`: "no file here may hold a *sql.DB; internal/handoff owns the connection",
		`"github.com/Susquehanna-Syntax/Anvil/internal/store"`: "no file here may reach the schema directly; §6 G9",
	}
	// 2. No string literal anywhere looks like SQL. A second query is a
	//    second definition of whatever it queries.
	keywords := []string{"select ", "insert ", "update ", "delete ", "create table", " from handoff", "handoff h"}

	for _, name := range sourceNames(files) {
		file := files[name]
		for _, imp := range file.Imports {
			if why, bad := forbidden[imp.Path.Value]; bad {
				t.Errorf("%s: forbidden import %s: %s", fset.Position(imp.Pos()), imp.Path.Value, why)
			}
		}
		ast.Inspect(file, func(n ast.Node) bool {
			lit, ok := n.(*ast.BasicLit)
			if !ok || lit.Kind != token.STRING {
				return true
			}
			lower := strings.ToLower(lit.Value)
			for _, kw := range keywords {
				if strings.Contains(lower, kw) {
					t.Errorf("%s: string literal looks like SQL (%q): internal/handoff owns every query over the handoff table",
						fset.Position(lit.Pos()), kw)
				}
			}
			return true
		})
	}

	// Negative control: the guard must be able to fail. If these do not trip
	// the same predicate, the loop above is checking nothing.
	for _, probe := range []string{`"SELECT 1 FROM handoff"`, `"create table handoff (x)"`} {
		lower := strings.ToLower(probe)
		hit := false
		for _, kw := range keywords {
			if strings.Contains(lower, kw) {
				hit = true
			}
		}
		if !hit {
			t.Errorf("negative control %s did not trip the SQL guard", probe)
		}
	}
}

// frozenEnumLiterals is every value of every enum internal/record freezes.
// A bare string literal equal to one of them, anywhere in this package's
// adapter, is a second definition of that value — which is how nine of §6's
// ten defects happened.
func strs[T ~string](vs []T) []string {
	s := make([]string, len(vs))
	for i, v := range vs {
		s[i] = string(v)
	}
	return s
}

func frozenEnumLiterals() map[string]string {
	out := map[string]string{}
	add := func(enum string, values ...string) {
		for _, v := range values {
			out[v] = enum
		}
	}
	add("anvil/state", strs(record.StateValues())...)
	add("anvil/status", strs(record.HalfStatusValues())...)
	add("anvil/dastStatus", strs(record.DastStatusValues())...)
	add("anvil/target.provenance", strs(record.TargetProvenanceValues())...)
	add("anvil/target.provisioning", strs(record.TargetProvisioningValues())...)
	add("anvil/verdict", strs(record.VerdictValues())...)
	add("handoff.state", strs(record.HandoffStateValues())...)
	add("handoff.consumption_class", strs(record.ConsumptionClassValues())...)
	return out
}

func TestThePackageUsesNoBareEnumLiteral(t *testing.T) {
	frozen := frozenEnumLiterals()
	if len(frozen) < 40 {
		t.Fatalf("collected %d frozen enum literals, want the full set; the guard is not covering them", len(frozen))
	}
	if _, ok := frozen["both_sealed"]; !ok {
		t.Fatal("negative control: 'both_sealed' is not in the frozen set, so the guard is looking at the wrong thing")
	}

	fset, files := packageSources(t)
	for _, name := range sourceNames(files) {
		ast.Inspect(files[name], func(n ast.Node) bool {
			lit, ok := n.(*ast.BasicLit)
			if !ok || lit.Kind != token.STRING {
				return true
			}
			v, err := strconv.Unquote(lit.Value)
			if err != nil {
				return true
			}
			if enum, bad := frozen[v]; bad {
				t.Errorf("%s: bare literal %q is a %s value; use the record constant",
					fset.Position(lit.Pos()), v, enum)
			}
			return true
		})
	}
}

// ---------------------------------------------------------------------------
// The read-gate guard — CRITIQUE O.4 finding O4-m2, second half
//
// internal/record has TestReadGateArmsAppearOnlyInsideTheGate, which parses "."
// and therefore watches internal/record and nothing else. The critic's point
// was that nothing watched THIS package, and O4-B1 is what walked through that
// gap: a readability decision assembled here out of the two arms of a gate that
// lives there.
//
// So this is that guard, for this package. The rule it enforces:
//
//	record.HalfStatusSealed and record.IsReadableHalfStatus may not be named
//	here AT ALL. "Which status is readable" is internal/record's question and
//	has exactly one answer, inside internal/record.
//
//	record.StateExpired and record.StateConsumed may be named ONLY inside the
//	two functions that are documented as non-readability predicates, and each
//	of those already carries the argument for why it is not a read gate.
//
// The allowlist is by ENCLOSING FUNCTION, not by file, so a new helper in
// statemachine.go cannot inherit settled's licence by living next to it.
// ---------------------------------------------------------------------------

// readGateArms are the record identifiers that decide readability. Naming one
// outside internal/record is re-deriving the gate.
var readGateArms = map[string]string{
	"HalfStatusSealed":       "the readable status; ask record.Sealer.ReadHalf or record.HalfSeal.Readable instead",
	"IsReadableHalfStatus":   "record's own readability predicate; it is not exported for re-use in a second gate",
	"HalfReadGate":           "the gate itself; reach it through record.Sealer.ReadHalf, which mints the seal it gates",
	"ErrSealNotFromProducer": "a provenance refusal is record's to raise, not this package's to reproduce",
}

// stateArmAllowlist names the functions permitted to compare an anvil/state
// against a terminal value, with the reason each is not a readability decision.
var stateArmAllowlist = map[string]string{
	"settled":       "a DURABILITY predicate: has the store writer's one chance arrived",
	"acceptsWrites": "a WRITE guard: mirrors record.Sealer's own ErrAuditTerminal check",
}

var terminalStateArms = map[string]bool{
	"StateExpired": true, "StateConsumed": true,
}

// recordSelector reports the identifier X in an expression `record.X`.
func recordSelector(n ast.Node) (string, bool) {
	sel, ok := n.(*ast.SelectorExpr)
	if !ok {
		return "", false
	}
	pkg, ok := sel.X.(*ast.Ident)
	if !ok || pkg.Name != "record" {
		return "", false
	}
	return sel.Sel.Name, true
}

// scanReadGateArms walks one file and reports every violation as a string.
// It is shared by the guard and by its negative control, so the control
// exercises the same code the guard runs.
func scanReadGateArms(fset *token.FileSet, file *ast.File) []string {
	var found []string
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok {
			continue
		}
		ast.Inspect(fn, func(n ast.Node) bool {
			name, ok := recordSelector(n)
			if !ok {
				return true
			}
			if why, banned := readGateArms[name]; banned {
				found = append(found, fmt.Sprintf("%s: %s names record.%s: %s",
					fset.Position(n.Pos()), fn.Name.Name, name, why))
				return true
			}
			if terminalStateArms[name] {
				if _, allowed := stateArmAllowlist[fn.Name.Name]; !allowed {
					found = append(found, fmt.Sprintf(
						"%s: %s compares an anvil/state against record.%s; that is an arm of the read gate. "+
							"If this is a durability or write decision, say so in its doc and add it to stateArmAllowlist; "+
							"if it is a readability decision, it belongs to record.Sealer.ReadHalf",
						fset.Position(n.Pos()), fn.Name.Name, name))
				}
			}
			return true
		})
	}
	return found
}

func TestReadGateArmsAreNotReDerivedInThisPackage(t *testing.T) {
	fset, files := packageSources(t)
	for _, name := range sourceNames(files) {
		for _, v := range scanReadGateArms(fset, files[name]) {
			t.Error(v)
		}
	}

	// The allowlist must not outlive the functions it names. An entry for a
	// function that no longer exists is a licence nobody asked for, sitting
	// where the next author will read it as precedent.
	live := map[string]bool{}
	for _, name := range sourceNames(files) {
		for _, decl := range files[name].Decls {
			if fn, ok := decl.(*ast.FuncDecl); ok {
				live[fn.Name.Name] = true
			}
		}
	}
	for name := range stateArmAllowlist {
		if !live[name] {
			t.Errorf("stateArmAllowlist names %q, which no longer exists in this package", name)
		}
	}

	// NEGATIVE CONTROL. The guard must be able to fail, and it must fail on
	// both arms: the banned identifier and the un-allowlisted state comparison.
	// Without this the loop above is a test that asserts nothing.
	probe := `package scanctl

import "github.com/Susquehanna-Syntax/Anvil/internal/record"

func sneakyReadable(s record.State, h record.HalfStatus) bool {
	return s != record.StateExpired && h == record.HalfStatusSealed
}
`
	probeSet := token.NewFileSet()
	probeFile, err := parser.ParseFile(probeSet, "probe.go", probe, parser.ParseComments)
	if err != nil {
		t.Fatalf("parsing the negative control: %v", err)
	}
	hits := scanReadGateArms(probeSet, probeFile)
	if len(hits) != 2 {
		t.Errorf("negative control produced %d violations, want 2 (one per arm): %v", len(hits), hits)
	}

	// And the allowlist must really allow: the same body inside `settled` must
	// trip only the HalfStatusSealed arm, not the state arm.
	allowed := strings.Replace(probe, "sneakyReadable", "settled", 1)
	allowedFile, err := parser.ParseFile(probeSet, "allowed.go", allowed, parser.ParseComments)
	if err != nil {
		t.Fatalf("parsing the allowlist control: %v", err)
	}
	if hits := scanReadGateArms(probeSet, allowedFile); len(hits) != 1 {
		t.Errorf("allowlist control produced %d violations, want 1 (the state arm must be allowed in settled): %v",
			len(hits), hits)
	}
}

// The adapter must not be the only thing standing between a caller and the
// queue: Queue() is the documented escape hatch, and the packet path it
// returns is the same one the Task carries. If those two ever disagree, a
// caller reaching around the adapter reads a different file from one going
// through it.
func TestTheEscapeHatchAgreesWithTheAdapter(t *testing.T) {
	f := newHFFixture(t, handoff.Options{})
	audit := f.sealedAudit()
	fingerprint, _ := f.enqueue(80, record.ConsumptionClassStaticOnly, audit, 2)

	task, err := f.c.Claim(fingerprint, "worker-a")
	if err != nil {
		t.Fatalf("Claim: %v", err)
	}
	direct, err := f.c.Queue().PacketPath(fingerprint)
	if err != nil {
		t.Fatalf("PacketPath: %v", err)
	}
	if task.PacketPath != direct {
		t.Fatalf("Task.PacketPath = %q, Queue().PacketPath = %q", task.PacketPath, direct)
	}

	body := []byte(`{"version":"2.1.0","runs":[]}`)
	if _, err := f.c.WritePacket(task, body); err != nil {
		t.Fatalf("WritePacket: %v", err)
	}
	got, err := f.c.Packet(task)
	if err != nil {
		t.Fatalf("Packet: %v", err)
	}
	if string(got) != string(body) {
		t.Fatalf("Packet round trip = %q, want %q", got, body)
	}

	// Terminal disposition drops the cache; its absence is not an error.
	if err := f.c.ReleaseLease(task, record.HandoffStateValidated); err != nil {
		t.Fatalf("ReleaseLease: %v", err)
	}
	if _, err := os.Stat(direct); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("stat packet after a terminal disposition = %v, want os.ErrNotExist", err)
	}
}
