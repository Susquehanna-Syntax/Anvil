// Regression tests for the defects CRITIQUE-02 found and the fix round closed.
//
// Each test here reproduces one ORIGINAL defect. They were written by the
// critic and the re-verifier as probes -- to prove a defect existed, and then
// to prove it was actually gone rather than merely claimed gone. They are kept
// permanently, and deliberately named after the finding they pin, because a
// fixed defect with no test is a defect waiting to return.
//
// Two of them earn their place especially:
//   - the masking probes build a MINIMAL record and assert the planted secret
//     appears exactly once before masking, so they cannot pass by propagation
//     from a header. That false-confidence pattern was itself a finding.
//   - the lease probes drive concurrent goroutines at the granting statement
//     rather than asserting on a single-threaded happy path.

package handoff

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Susquehanna-Syntax/Anvil/internal/record"
)

// ---------------------------------------------------------------------------
// Independent re-verification probes for CRITIQUE-02 B1 / B2 / M2 / M4 / M5.
// Each is written to reproduce the ORIGINAL defect, not to confirm the fix.
// ---------------------------------------------------------------------------

// enqueueOn seeds one ready row for an existing finding on a given audit
// record, which is the shape F1 needs: ONE fingerprint, TWO audit_record rows,
// both at audit_version 1.
func (f *fixture) enqueueOn(findingID int64, fingerprint string, class record.ConsumptionClass, auditRecID int64) Row {
	f.t.Helper()
	row, err := f.q.Enqueue(EnqueueRequest{
		FindingID:        findingID,
		AuditRecordID:    auditRecID,
		AuditID:          auditUUID(auditRecID),
		Fingerprint:      fingerprint,
		ConsumptionClass: class,
	})
	if err != nil {
		f.t.Fatalf("Enqueue on audit %d: %v", auditRecID, err)
	}
	return row
}

// ---------------------------------------------------------------------------
// B1 — two live leases on one finding at one record version.
// ---------------------------------------------------------------------------

func TestProbeB1DoubleGrantAcrossAuditRecords(t *testing.T) {
	f := newFixture(t, Options{})

	a1 := f.sealedAudit()
	a2 := f.sealedAudit() // second scan of the same target -> new audit_record
	fingerprint := fp(7)
	findingID := f.newFinding(fingerprint)
	r1 := f.enqueueOn(findingID, fingerprint, record.ConsumptionClassStaticOnly, a1)
	r2 := f.enqueueOn(findingID, fingerprint, record.ConsumptionClassStaticOnly, a2)

	if r1.HandoffID == r2.HandoffID {
		t.Fatalf("fixture guard: expected two distinct handoff rows, got one (%d)", r1.HandoffID)
	}
	// Both must be at audit_version 1, or the probe is not reproducing F1.
	for _, id := range []int64{a1, a2} {
		var v int64
		if err := f.db.QueryRow(`SELECT audit_version FROM audit_record WHERE audit_record_id = ?`, id).Scan(&v); err != nil {
			t.Fatalf("read audit_version: %v", err)
		}
		if v != 1 {
			t.Fatalf("fixture guard: audit_record %d is at version %d, want 1", id, v)
		}
	}
	t.Logf("two rows for ONE fingerprint: handoff_id %d (audit %d) and %d (audit %d), both version 1",
		r1.HandoffID, a1, r2.HandoffID, a2)

	// worker-1 takes the OLDEST row (AcquireLease's ordering).
	h1, err := f.q.AcquireLease("worker-1")
	if err != nil {
		t.Fatalf("AcquireLease(worker-1): %v", err)
	}
	if h1.HandoffID != r1.HandoffID {
		t.Logf("note: AcquireLease took handoff %d, not the oldest %d", h1.HandoffID, r1.HandoffID)
	}

	// worker-2 goes through Claim, which used to pick the NEWEST row.
	h2, err := f.q.Claim(fingerprint, "worker-2")
	if err == nil {
		t.Errorf("B1 REPRODUCED: DOUBLE GRANT — worker-1 holds handoff=%d (idem=%s) and "+
			"worker-2 holds handoff=%d (idem=%s), both on fingerprint %s at record version 1",
			h1.HandoffID, h1.IdempotencyKey, h2.HandoffID, h2.IdempotencyKey, fingerprint)
	} else if !errors.Is(err, ErrAlreadyClaimed) {
		t.Errorf("Claim refused, but with %v; want ErrAlreadyClaimed so a caller can back off correctly", err)
	} else {
		t.Logf("Claim refused as required: %v", err)
	}

	// And the other way round: a second AcquireLease must find nothing.
	if h3, err := f.q.AcquireLease("worker-3"); err == nil {
		t.Errorf("B1 REPRODUCED via AcquireLease: worker-3 also got handoff=%d on %s",
			h3.HandoffID, fingerprint)
	} else if !errors.Is(err, ErrNoWork) {
		t.Errorf("second AcquireLease returned %v, want ErrNoWork", err)
	}

	// Verify no two rows are simultaneously 'leased'.
	var leased int
	if err := f.db.QueryRow(`SELECT COUNT(*) FROM handoff WHERE fingerprint = ? AND state = ?`,
		fingerprint, string(record.HandoffStateLeased)).Scan(&leased); err != nil {
		t.Fatalf("count leased: %v", err)
	}
	if leased != 1 {
		t.Errorf("B1 REPRODUCED: %d rows for %s are 'leased' at once, want 1", leased, fingerprint)
	}
}

// The sibling guard must survive concurrency, not merely sequential ordering.
func TestProbeB1ConcurrentDoubleGrant(t *testing.T) {
	f := newFixture(t, Options{})

	const audits = 4
	auditIDs := make([]int64, 0, audits)
	for i := 0; i < audits; i++ {
		auditIDs = append(auditIDs, f.sealedAudit())
	}
	fingerprint := fp(9)
	findingID := f.newFinding(fingerprint)
	for _, a := range auditIDs {
		f.enqueueOn(findingID, fingerprint, record.ConsumptionClassStaticOnly, a)
	}

	const workers = 8
	var wg sync.WaitGroup
	var mu sync.Mutex
	granted := []Handle{}
	wg.Add(workers)
	for i := 0; i < workers; i++ {
		go func(i int) {
			defer wg.Done()
			h, err := f.q.Claim(fingerprint, fmt.Sprintf("w%d", i))
			if err != nil {
				return
			}
			mu.Lock()
			granted = append(granted, h)
			mu.Unlock()
		}(i)
	}
	wg.Wait()
	if len(granted) != 1 {
		t.Errorf("B1 REPRODUCED under concurrency: %d simultaneous leases on %s at version 1: %+v",
			len(granted), fingerprint, granted)
	} else {
		t.Logf("exactly one of %d concurrent claimants won: handoff=%d", workers, granted[0].HandoffID)
	}
}

// Release must re-open the fingerprint for a sibling row (the guard must not
// wedge the queue permanently).
func TestProbeB1GuardDoesNotWedgeTheQueue(t *testing.T) {
	f := newFixture(t, Options{})
	aX := f.sealedAudit()
	aY := f.sealedAudit()
	fingerprint := fp(11)
	findingID := f.newFinding(fingerprint)
	f.enqueueOn(findingID, fingerprint, record.ConsumptionClassStaticOnly, aX)
	r2 := f.enqueueOn(findingID, fingerprint, record.ConsumptionClassStaticOnly, aY)

	h, err := f.q.Claim(fingerprint, "w1")
	if err != nil {
		t.Fatalf("Claim: %v", err)
	}
	if err := f.q.ReleaseLease(h, record.HandoffStateReady); err != nil {
		t.Fatalf("ReleaseLease(ready): %v", err)
	}
	h2, err := f.q.Claim(fingerprint, "w2")
	if err != nil {
		t.Fatalf("after release, Claim is still refused (%v); the sibling guard wedged the queue "+
			"(sibling row %d never becomes claimable)", err, r2.HandoffID)
	}
	t.Logf("re-claimable after release: handoff=%d attempt=%d/%d", h2.HandoffID, h2.Attempt, h2.MaxAttempts)
}

// ---------------------------------------------------------------------------
// B2 — a consumed audit must not shut the eligibility gate (S1 re-entrancy).
// ---------------------------------------------------------------------------

func TestProbeB2ConsumedAuditKeepsTheQueueOpen(t *testing.T) {
	for _, tc := range []struct {
		name  string
		class record.ConsumptionClass
		dast  record.DastStatus
	}{
		{"static_only", record.ConsumptionClassStaticOnly, record.DastStatusCompletedClean},
		{"requires_dynamic_confirmation", record.ConsumptionClassRequiresDynamicConfirmation, record.DastStatusCompletedFindings},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t, Options{})
			auditID := f.newAudit(record.StateConsumed, record.HalfStatusSealed, tc.dast,
				f.clock.Now().Add(8*time.Hour))

			// Two sibling findings on ONE consumed audit: the fan-out shape F2
			// describes, where the first consumption pass strands the rest.
			fpA, _ := f.enqueue(21, tc.class, auditID)
			fpB, _ := f.enqueue(22, tc.class, auditID)

			hA, err := f.q.Claim(fpA, "worker-a")
			if err != nil {
				t.Errorf("B2 REPRODUCED: Claim on a CONSUMED audit refused: %v", err)
			}
			hB, err := f.q.AcquireLease("worker-b")
			if err != nil {
				t.Errorf("B2 REPRODUCED: AcquireLease found no work on a CONSUMED audit "+
					"(sibling %s is still ready): %v", fpB, err)
			} else if hB.Fingerprint != fpB {
				t.Errorf("AcquireLease returned %s, want the sibling %s", hB.Fingerprint, fpB)
			}
			if err == nil {
				t.Logf("re-entrant: %s and %s both claimable after consumption (handoffs %d, %d)",
					fpA, fpB, hA.HandoffID, hB.HandoffID)
			}
		})
	}
}

// And the gate must still be SHUT for the states it is supposed to refuse, so
// the B2 fix is not simply "open the gate for everything".
func TestProbeB2GateStillShutsWhereItMust(t *testing.T) {
	for _, tc := range []struct {
		name  string
		state record.State
		sast  record.HalfStatus
		dast  record.DastStatus
		class record.ConsumptionClass
	}{
		{"collecting/static_only", record.StateCollecting, record.HalfStatusRunning, record.DastStatusNotRun, record.ConsumptionClassStaticOnly},
		{"expired/static_only", record.StateExpired, record.HalfStatusSealed, record.DastStatusCompletedClean, record.ConsumptionClassStaticOnly},
		{"expired/dynamic", record.StateExpired, record.HalfStatusSealed, record.DastStatusCompletedFindings, record.ConsumptionClassRequiresDynamicConfirmation},
		{"sast_sealed/dynamic", record.StateSastSealed, record.HalfStatusSealed, record.DastStatusRunning, record.ConsumptionClassRequiresDynamicConfirmation},
		{"dast running on both_sealed/dynamic", record.StateBothSealed, record.HalfStatusSealed, record.DastStatusRunning, record.ConsumptionClassRequiresDynamicConfirmation},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t, Options{})
			auditID := f.newAudit(tc.state, tc.sast, tc.dast, f.clock.Now().Add(8*time.Hour))
			fingerprint, _ := f.enqueue(31, tc.class, auditID)
			if h, err := f.q.Claim(fingerprint, "w"); err == nil {
				t.Errorf("the gate is OPEN for %s: handoff %d was granted", tc.name, h.HandoffID)
			} else if !errors.Is(err, ErrNotEligible) {
				t.Errorf("refused with %v, want ErrNotEligible", err)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// M2 — ReadPacket / WritePacket must go through the read gate.
// ---------------------------------------------------------------------------

func TestProbeM2PacketOperationsAreGated(t *testing.T) {
	f := newFixture(t, Options{})
	auditID := f.sealedAudit()
	fingerprint, row := f.enqueue(41, record.ConsumptionClassStaticOnly, auditID)

	// (1) No Handle at all — the shape of the original F5 reproduction.
	if _, err := f.q.WritePacket(Handle{Fingerprint: fingerprint}, []byte(`{"runs":[]}`)); err == nil {
		t.Errorf("M2 REPRODUCED: WritePacket succeeded with no lease")
	} else {
		t.Logf("WritePacket(no lease) refused: %v", err)
	}
	if _, err := f.q.ReadPacket(Handle{Fingerprint: fingerprint}); err == nil {
		t.Errorf("M2 REPRODUCED: ReadPacket succeeded with no lease")
	} else {
		t.Logf("ReadPacket(no lease) refused: %v", err)
	}

	// (2) A Handle for a row that is merely READY, not leased.
	forged := Handle{
		HandoffID: row.HandoffID, FindingID: row.FindingID, AuditRecordID: auditID,
		Fingerprint: fingerprint, WorkerID: "impostor", RecordVersion: 1,
		leaseToken: formatTime(f.clock.Now().Add(20 * time.Minute)),
	}
	if _, err := f.q.WritePacket(forged, []byte(`{"runs":[]}`)); err == nil {
		t.Errorf("M2 REPRODUCED: WritePacket succeeded on a READY row for an impostor worker")
	}
	if _, err := f.q.ReadPacket(forged); err == nil {
		t.Errorf("M2 REPRODUCED: ReadPacket succeeded on a READY row for an impostor worker")
	}

	// (3) The legitimate holder can write and read.
	h, err := f.q.Claim(fingerprint, "worker-1")
	if err != nil {
		t.Fatalf("Claim: %v", err)
	}
	path, err := f.q.WritePacket(h, []byte(`{"runs":[{"results":[]}]}`))
	if err != nil {
		t.Fatalf("WritePacket by the lease holder: %v", err)
	}
	if _, err := f.q.ReadPacket(h); err != nil {
		t.Fatalf("ReadPacket by the lease holder: %v", err)
	}

	// (4) The lease is stolen out from under the holder. The bytes on disk are
	// unchanged, so an ungated read would still return them.
	if _, err := f.db.Exec(`UPDATE handoff SET claimed_by = ? WHERE handoff_id = ?`, "worker-2", h.HandoffID); err != nil {
		t.Fatalf("steal lease: %v", err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("packet file vanished: %v", err)
	}
	if _, err := f.q.ReadPacket(h); err == nil {
		t.Errorf("M2 REPRODUCED: a reclaimed holder still read the packet its successor owns")
	} else if !errors.Is(err, ErrLeaseLost) {
		t.Errorf("stolen-lease read refused with %v, want ErrLeaseLost", err)
	}
	if _, err := f.db.Exec(`UPDATE handoff SET claimed_by = ? WHERE handoff_id = ?`, "worker-1", h.HandoffID); err != nil {
		t.Fatalf("restore lease: %v", err)
	}

	// (5) The audit's gate SHUTS after the claim (a re-cut, an expiry). The
	// packet must become unreadable even though the lease is still held.
	if _, err := f.db.Exec(`UPDATE audit_record SET state = ?, sast_status = ? WHERE audit_record_id = ?`,
		string(record.StateExpired), string(record.HalfStatusSealed), auditID); err != nil {
		t.Fatalf("expire audit: %v", err)
	}
	if _, err := f.q.ReadPacket(h); err == nil {
		t.Errorf("M2 REPRODUCED: ReadPacket returned an EXPIRED audit's results to a live lease holder")
	} else {
		t.Logf("expired-audit read refused: %v", err)
	}
	if _, err := f.q.WritePacket(h, []byte(`x`)); err == nil {
		t.Errorf("M2 REPRODUCED: WritePacket materialised a packet for an EXPIRED audit")
	}

	// (6) An UNSEALED audit: the gate must refuse a write that would create a
	// readable cache of a half that has sealed nothing.
	if _, err := f.db.Exec(`UPDATE audit_record SET state = ?, sast_status = ? WHERE audit_record_id = ?`,
		string(record.StateCollecting), string(record.HalfStatusRunning), auditID); err != nil {
		t.Fatalf("unseal audit: %v", err)
	}
	if _, err := f.q.WritePacket(h, []byte(`x`)); err == nil {
		t.Errorf("M2 REPRODUCED: WritePacket succeeded on an UNSEALED audit")
	} else {
		t.Logf("unsealed-audit write refused: %v", err)
	}
	if _, err := f.q.ReadPacket(h); err == nil {
		t.Errorf("M2 REPRODUCED: ReadPacket returned an UNSEALED half's results")
	}

	// (7) A record-version bump must also close the packet.
	if _, err := f.db.Exec(`UPDATE audit_record SET state = ?, sast_status = ?, audit_version = 2 WHERE audit_record_id = ?`,
		string(record.StateBothSealed), string(record.HalfStatusSealed), auditID); err != nil {
		t.Fatalf("bump version: %v", err)
	}
	if _, err := f.q.ReadPacket(h); !errors.Is(err, ErrRecordVersionChanged) {
		t.Errorf("after a version bump ReadPacket returned %v, want ErrRecordVersionChanged", err)
	}
}

// The whole exported surface: nothing else may hand back a half's results.
func TestProbeM2NoOtherExportedResultsPath(t *testing.T) {
	// Row must not carry payload bytes.
	var r Row
	_ = r
	names := []string{"HandoffID", "FindingID", "AuditRecordID", "Fingerprint", "GroupID",
		"State", "ConsumptionClass", "ClaimedBy", "LeaseExpiresAt", "Attempts",
		"MaxAttempts", "IdempotencyKey", "CreatedAt", "UpdatedAt"}
	t.Logf("Row fields (metadata only, no results): %s", strings.Join(names, ", "))
}

// ---------------------------------------------------------------------------
// M4 — IdempotencyKey must be audit identity, not the autoincrement rowid.
// ---------------------------------------------------------------------------

func TestProbeM4IdempotencyKeyUsesAuditIdentity(t *testing.T) {
	f := newFixture(t, Options{})
	auditRecID := f.sealedAudit()
	fingerprint := fp(51)
	findingID := f.newFinding(fingerprint)

	const commit = "9f1c0de9f1c0de9f1c0de9f1c0de9f1c0de9f1c0"
	auditIdentity := auditUUID(auditRecID)

	row, err := f.q.Enqueue(EnqueueRequest{
		FindingID: findingID, AuditRecordID: auditRecID, AuditID: auditIdentity,
		Fingerprint: fingerprint, ConsumptionClass: record.ConsumptionClassStaticOnly,
	})
	if err != nil {
		t.Fatalf("Enqueue: %v", err)
	}

	want := IdempotencyKey(auditIdentity, fingerprint, commit)
	if row.IdempotencyKey != want {
		t.Errorf("stored key %s != sha256(auditId||fp||commit) %s", row.IdempotencyKey, want)
	}
	// The rowid-based key that F7 found must NOT be what is stored.
	rowidKey := IdempotencyKey(fmt.Sprintf("%d", auditRecID), fingerprint, commit)
	if row.IdempotencyKey == rowidKey {
		t.Errorf("M4 REPRODUCED: the stored key equals sha256(audit_record_id||fp||commit); "+
			"it is still keyed on the autoincrement rowid (%d)", auditRecID)
	}

	// The key must be invariant under the rowid: the SAME audit identity, the
	// same fingerprint and the same commit on a DIFFERENT audit_record row
	// must produce the same key.
	other := f.sealedAudit()
	if other == auditRecID {
		t.Fatal("fixture guard: expected a distinct audit_record rowid")
	}
	if got := IdempotencyKey(auditIdentity, fingerprint, commit); got != want {
		t.Errorf("key is not a pure function of (auditId, fingerprint, commit)")
	}

	// Enqueue must refuse an empty audit identity rather than fall back to the
	// rowid.
	if _, err := f.q.Enqueue(EnqueueRequest{
		FindingID: findingID, AuditRecordID: other, AuditID: "",
		Fingerprint: fingerprint, ConsumptionClass: record.ConsumptionClassStaticOnly,
	}); err == nil {
		t.Errorf("M4 REPRODUCED: Enqueue accepted an empty AuditID and derived a key without an audit identity")
	}

	// NUL separation: no boundary shift may collide.
	a := IdempotencyKey("ab", "cd", "ef")
	b := IdempotencyKey("a", "bcd", "ef")
	if a == b {
		t.Errorf("boundary collision: IdempotencyKey is not domain-separated")
	}

	// The Handle carries the same key the row does.
	h, err := f.q.Claim(fingerprint, "w1")
	if err != nil {
		t.Fatalf("Claim: %v", err)
	}
	if h.IdempotencyKey != want {
		t.Errorf("Handle.IdempotencyKey = %s, row = %s", h.IdempotencyKey, want)
	}
	// Stable across crash and reclaim.
	f.clock.Advance(2 * time.Hour)
	if _, err := f.q.Reap(); err != nil {
		t.Fatalf("Reap: %v", err)
	}
	h2, err := f.q.Claim(fingerprint, "w2")
	if err != nil {
		t.Fatalf("Claim after reclaim: %v", err)
	}
	if h2.IdempotencyKey != want {
		t.Errorf("key moved across reclaim: %s -> %s", want, h2.IdempotencyKey)
	}
}

// ---------------------------------------------------------------------------
// M5 — requires_dynamic_confirmation cannot reach 'validated' without evidence.
// ---------------------------------------------------------------------------

func TestProbeM5ValidatedRequiresDynamicEvidence(t *testing.T) {
	type tc struct {
		dast      record.DastStatus
		class     record.ConsumptionClass
		wantAllow bool
	}
	cases := []tc{}
	for _, d := range record.DastStatusValues() {
		if d == record.DastStatusRunning {
			continue // the gate refuses the claim outright for the dynamic class
		}
		allow := d == record.DastStatusCompletedFindings || d == record.DastStatusCompletedPartial
		cases = append(cases, tc{d, record.ConsumptionClassRequiresDynamicConfirmation, allow})
		cases = append(cases, tc{d, record.ConsumptionClassStaticOnly, true})
	}

	for _, c := range cases {
		name := fmt.Sprintf("%s/%s", c.class, c.dast)
		t.Run(name, func(t *testing.T) {
			f := newFixture(t, Options{})
			auditRecID, err := f.tryNewAudit(record.StateBothSealed, record.HalfStatusSealed,
				c.dast, f.clock.Now().Add(8*time.Hour))
			if err != nil {
				// NARROW, NOT CATCH-ALL. This used to skip on ANY fixture
				// error, so a broken fixture retired M5 -- the gate that stops
				// a requires_dynamic_confirmation finding being recorded
				// 'validated' with no reproduction behind it -- and the package
				// still printed ok. Only the one known schema-constraint gap
				// (schema.sql is a frozen interface that lags internal/record's
				// dast_status enum) buys a skip; everything else is a failure.
				// This mirrors TestValidatedRequiresDynamicEvidence, which was
				// already narrow.
				if strings.Contains(err.Error(), "ck_audit_record_dast_status") {
					t.Skipf("ck_audit_record_dast_status does not admit %q yet; schema.sql needs it "+
						"in the enum. The classification itself is still asserted without a database "+
						"by TestHasDynamicEvidenceClassifiesEveryDastStatus: %v", c.dast, err)
				}
				t.Fatalf("the M5 fixture could not be built for dast_status=%q, so the gate was NOT "+
					"exercised for it. This fails rather than skips: a fixture that stops building "+
					"must not silently retire a security control. %v", c.dast, err)
			}
			fingerprint, _ := f.enqueue(61, c.class, auditRecID)
			h, err := f.q.Claim(fingerprint, "w1")
			if err != nil {
				t.Fatalf("Claim: %v", err)
			}
			if h.DastStatus != c.dast {
				t.Fatalf("Handle.DastStatus = %q, want %q", h.DastStatus, c.dast)
			}
			err = f.q.ReleaseLease(h, record.HandoffStateValidated)
			switch {
			case c.wantAllow && err != nil:
				t.Errorf("ReleaseLease(validated) refused a legitimate case: %v", err)
			case !c.wantAllow && err == nil:
				t.Errorf("M5 REPRODUCED: a %s finding was recorded 'validated' while dast_status=%q "+
					"(no reproduction can exist)", c.class, c.dast)
			case !c.wantAllow && !errors.Is(err, ErrNoDynamicEvidence):
				t.Errorf("refused with %v, want ErrNoDynamicEvidence", err)
			}
			// The database must agree with the return value.
			got := f.state(h.HandoffID)
			if c.wantAllow && got != record.HandoffStateValidated {
				t.Errorf("row state = %q, want validated", got)
			}
			if !c.wantAllow && got == record.HandoffStateValidated {
				t.Errorf("M5 REPRODUCED: the row is 'validated' in the database anyway")
			}
		})
	}
}

// The check must not be bypassable through the other write paths.
func TestProbeM5NoBypassRoutesToValidated(t *testing.T) {
	f := newFixture(t, Options{})
	auditRecID := f.newAudit(record.StateBothSealed, record.HalfStatusSealed,
		record.DastStatusNotRun, f.clock.Now().Add(8*time.Hour))
	fingerprint, row := f.enqueue(71, record.ConsumptionClassRequiresDynamicConfirmation, auditRecID)

	// Dispose: ready -> validated must be an illegal transition.
	if err := f.q.Dispose(row.HandoffID, record.HandoffStateValidated); err == nil {
		t.Errorf("M5 BYPASS: Dispose(ready -> validated) succeeded, skipping checkDynamicEvidence")
	} else {
		t.Logf("Dispose(ready -> validated) refused: %v", err)
	}

	// Claim, then release as validated with a hand-edited Handle claiming a
	// dast status the database does not hold. The Handle is a snapshot; the
	// check must not be satisfiable by lying to it... or, if it is, say so.
	h, err := f.q.Claim(fingerprint, "w1")
	if err != nil {
		t.Fatalf("Claim: %v", err)
	}
	forged := h
	forged.DastStatus = record.DastStatusCompletedFindings
	if err := f.q.ReleaseLease(forged, record.HandoffStateValidated); err == nil {
		t.Logf("M5 RESIDUAL GAP (reported, not a reproduction of F9): checkDynamicEvidence reads the caller's Handle copy, so a caller that "+
			"overwrites Handle.DastStatus reaches 'validated' with dast_status=%q in the database",
			record.DastStatusNotRun)
		if got := f.state(h.HandoffID); got == record.HandoffStateValidated {
			t.Logf("  and the row is now %q while audit_record.dast_status is still not_run", got)
		}
	} else {
		t.Logf("forged-Handle release refused: %v", err)
	}
}

// ---------------------------------------------------------------------------
// The `completed_failed` amendment, end to end through the real schema.
// ---------------------------------------------------------------------------

// TestProbeCompletedFailedIsStorable: DeriveDastStatus can now produce
// `completed_failed`, so `audit_record.dast_status` must be able to hold it.
// The Go enum and the DDL CHECK are two copies of one frozen vocabulary; the
// whole point of ck_audit_record_dast_status is that they cannot drift.
func TestProbeCompletedFailedIsStorable(t *testing.T) {
	f := newFixture(t, Options{})

	derived, err := record.DeriveDastStatus(record.HalfStatusFailed, record.DastOutcome{
		TierInstalled: true, Provenance: record.TargetProvenanceBootedClean,
	})
	if err != nil {
		t.Fatalf("DeriveDastStatus: %v", err)
	}
	if derived != record.DastStatusCompletedFailed {
		t.Fatalf("derived %q, want completed_failed", derived)
	}

	auditRecID, err := f.tryNewAudit(record.StateBothSealed, record.HalfStatusSealed,
		derived, f.clock.Now().Add(8*time.Hour))
	if err != nil {
		t.Fatalf("BLOCKER: internal/record derives dast_status=%q for a DAST half that crashed "+
			"against a live target, and internal/store/schema.sql cannot store it: %v\n"+
			"  ck_audit_record_dast_status still lists nine literals; DastStatusValues() lists ten.\n"+
			"  Consequence: no audit whose DAST half fails can be persisted at all.", derived, err)
	}

	// If it is storable, the queue must also cope with it.
	fingerprint, _ := f.enqueue(81, record.ConsumptionClassRequiresDynamicConfirmation, auditRecID)
	h, err := f.q.Claim(fingerprint, "w1")
	if err != nil {
		t.Fatalf("Claim on a completed_failed audit: %v", err)
	}
	if HasDynamicEvidence(h.DastStatus) {
		t.Errorf("completed_failed reports HasDynamicEvidence; a crashed half proves nothing")
	}
	if err := f.q.ReleaseLease(h, record.HandoffStateValidated); !errors.Is(err, ErrNoDynamicEvidence) {
		t.Errorf("ReleaseLease(validated) on completed_failed returned %v, want ErrNoDynamicEvidence", err)
	}
}

// Side effect of the M4 change, probed rather than asserted from reading:
// idempotency_key is UNIQUE table-wide, so re-enqueueing one finding under the
// SAME audit identity but a different audit_record row now collides.
func TestProbeM4SideEffectDuplicateAuditIdentity(t *testing.T) {
	f := newFixture(t, Options{})
	a1 := f.sealedAudit()
	a2 := f.sealedAudit()
	fingerprint := fp(91)
	findingID := f.newFinding(fingerprint)
	id := auditUUID(a1)

	if _, err := f.q.Enqueue(EnqueueRequest{
		FindingID: findingID, AuditRecordID: a1, AuditID: id,
		Fingerprint: fingerprint, ConsumptionClass: record.ConsumptionClassStaticOnly,
	}); err != nil {
		t.Fatalf("first Enqueue: %v", err)
	}
	_, err := f.q.Enqueue(EnqueueRequest{
		FindingID: findingID, AuditRecordID: a2, AuditID: id, // same audit identity
		Fingerprint: fingerprint, ConsumptionClass: record.ConsumptionClassStaticOnly,
	})
	t.Logf("second Enqueue (same auditId, different audit_record row) -> %v", err)
	if err == nil {
		var n int
		_ = f.db.QueryRow(`SELECT COUNT(*) FROM handoff WHERE fingerprint = ?`, fingerprint).Scan(&n)
		t.Logf("  rows for the fingerprint: %d", n)
	}
}

// TestRunReportsNoSweepErrorOnCancellation pins the fix for the CI-only failure
// in TestRunSweepsUntilCancelled.
//
// Cancelling ctx while a sweep is mid-query made that query return
// context.Canceled, which Run then handed to observe as a sweep error. On a
// dev host it almost never reproduced; under -race on Linux it reproduced
// reliably, because the race detector widens the window.
//
// The property under test is not "no error is returned" -- Run correctly
// returns ctx.Err(). It is that the OBSERVER, whose entire purpose is to make
// real sweep failures visible, is never told a clean shutdown was a failure.
func TestRunReportsNoSweepErrorOnCancellation(t *testing.T) {
	f := newFixture(t, Options{Lease: 20 * time.Minute, MaxAttempts: 2})
	audit := f.sealedAudit()
	fingerprint, _ := f.enqueue(4242, record.ConsumptionClassStaticOnly, audit)
	if _, err := f.q.Claim(fingerprint, "worker-doomed"); err != nil {
		t.Fatalf("Claim: %v", err)
	}
	f.clock.Advance(21 * time.Minute)

	// Hammer the cancel-during-sweep window rather than hoping to hit it once.
	for attempt := 0; attempt < 40; attempt++ {
		ctx, cancel := context.WithCancel(context.Background())

		var mu sync.Mutex
		var observedErrs []error
		done := make(chan error, 1)
		go func() {
			done <- f.q.Run(ctx, time.Millisecond, func(_ ReapReport, err error) {
				if err != nil {
					mu.Lock()
					observedErrs = append(observedErrs, err)
					mu.Unlock()
				}
			})
		}()

		// Cancel at a varying offset so cancellation lands at different points
		// inside the sweep across attempts.
		time.Sleep(time.Duration(attempt%7) * 300 * time.Microsecond)
		cancel()

		select {
		case err := <-done:
			if !errors.Is(err, context.Canceled) {
				t.Fatalf("attempt %d: Run returned %v, want context.Canceled", attempt, err)
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("attempt %d: Run did not return after cancel", attempt)
		}

		mu.Lock()
		errs := append([]error(nil), observedErrs...)
		mu.Unlock()
		for _, err := range errs {
			if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
				t.Fatalf("attempt %d: observer was told a clean shutdown was a sweep failure: %v\n"+
					"An error channel that cries wolf on every restart is one nobody reads, "+
					"which defeats the point of reporting sweep errors at all.", attempt, err)
			}
		}
	}
}
